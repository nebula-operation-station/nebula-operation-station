// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrypull"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Private image transfer (ADR 0006, container update plan cu06 part 3,
// Q6 profile (a)).
//
// For a container update member whose binding names a private registry
// (`registry`), the host has no credential, so the executor does phases 2
// and 3 itself before the durable job is handed to the host:
//
//   - phase 2 (resolve): every entry's new tag is read over the private
//     read path (the same registry read grant, record and credential
//     identity as ReadPrivateRegistry) and must still name the bound index
//     or platform digest;
//   - phase 3 (transfer): registrypull fetches the bound digest with the
//     vault credential, verifies every manifest and blob, and its archive
//     is streamed over the member's authenticated SSH session into
//     `docker load` on the target. The target gets image bytes on stdin:
//     no credential, no token, no `docker login`, no Docker config, no
//     X-Registry-Auth, no environment and no argument derived from them.
//
// The registry record digest, the credential's random identity and its
// version are those of the binding, and they are rechecked, together with
// the vault lock generation, the credential expiry and every read grant
// claim, before the transfer and after it. Any change stops the member;
// nothing is retried. A lock during the stream also cuts the stream at the
// next write, so `docker load` never sees manifest.json.
//
// `docker load` records no repository digest, so the evidence that the
// loaded image is the approved one is defined per image store
// (imageStoreEvidence) and checked over SSH after the load. The host job
// later resolves the image as `repository@platform-digest` (phase 3
// verification), as `repository:tag@digest` with `--pull never` (phase 5)
// and by its repository digests (phase 1's current-digest check of the next
// update and retained_reference of a rollback). A store whose evidence
// cannot serve all three keeps private images unavailable, and the member
// is refused before any byte leaves the registry.

// Transfer limits.
const (
	// privateTransferTimeout bounds the whole transfer of one member
	// (resolve, every image's stream and verification).
	privateTransferTimeout = 30 * time.Minute
	// transferHostCommandTimeout bounds one read-only host command
	// (`docker info`, `docker image inspect`).
	transferHostCommandTimeout = 2 * time.Minute
	// maxTransferHostOutput bounds what is read from a host command's
	// stdout; the rest is discarded and the output is refused.
	maxTransferHostOutput = 64 << 10
	// maxTransferLoadOutput bounds what is kept of `docker load` output.
	// It is never parsed, logged or returned: only the exit status counts.
	maxTransferLoadOutput = 4 << 10
	// maxTransferImages bounds the distinct images of one member.
	maxTransferImages = 16
	// transferTagPrefix names the tag the archive records. It never is an
	// operator tag, so a load cannot move one (the old image keeps its
	// tag until phase 5 recreates the container).
	transferTagPrefix = "nos-transfer-"
)

// Image stores a target's Docker engine may use.
const (
	// imageStoreClassic is the graph-driver store (overlay2 and similar).
	imageStoreClassic = "classic"
	// imageStoreContainerd is the containerd image store (snapshotter).
	imageStoreContainerd = "containerd"
)

// containerdDriverType is the DriverStatus entry `docker info` reports for
// the containerd image store.
const containerdDriverType = "io.containerd.snapshotter.v1"

// Transfer errors. Messages carry no registry text, URL, credential or
// host output.
var (
	// errTransferBinding: the registry record or credential is not the one
	// the member binds, or it changed during the transfer.
	errTransferBinding = errors.New("private transfer: the registry record or credential differs from the approved binding")
	// errTransferLocked: the vault is locked, or was locked during the
	// transfer.
	errTransferLocked = errors.New("private transfer: the executor vault is locked or was locked during the transfer")
	// errTransferExpired: the bound credential has expired.
	errTransferExpired = errors.New("private transfer: the registry credential expired; rotate it")
	// errTransferGrant: no read grant covers the resolve read, or a claim
	// stopped covering it.
	errTransferGrant = errors.New("private transfer: no read grant covers the resolve read")
	// errTransferScope: an image is not in the registry's approved scope
	// or the binding is not a private update.
	errTransferScope = errors.New("private transfer: the image is outside the approved registry scope")
	// errTransferTagMoved: a new tag no longer names the bound digest.
	errTransferTagMoved = errors.New("private transfer: tag_moved")
	// errTransferResolve: the resolve read failed.
	errTransferResolve = errors.New("private transfer: tag_unresolved")
	// errTransferStore: the target's image store has no shown evidence for
	// loaded images, or could not be determined.
	errTransferStore = errors.New("private transfer: private images are unavailable on this image store")
	// errTransferPull: the registry fetch or its verification failed.
	errTransferPull = errors.New("private transfer: the registry fetch failed verification")
	// errTransferLoad: `docker load` failed or the stream broke.
	errTransferLoad = errors.New("private transfer: docker load failed")
	// errTransferEvidence: after the load the target does not show the
	// approved image by the store's evidence.
	errTransferEvidence = errors.New("private transfer: the loaded image does not match the approved digest")
)

// transferRepoRe bounds a repository reference that is interpolated into a
// host command (single-quoted, so this also excludes quotes).
var transferRepoRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.:-]*(/[a-z0-9][a-z0-9._-]*)+$`)

// transferDigestRe is the only digest form a host command carries.
var transferDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// storeEvidence is what proves, per image store, that a loaded image is the
// approved one, and whether that evidence is shown to serve the host job.
type storeEvidence struct {
	// available: the evidence serves phase 1's current-digest check,
	// retained_reference and `repository:tag@digest` with `--pull never`.
	available bool
	// why explains an unavailable store (fixed text).
	why string
	// ref is the reference the evidence inspects.
	ref func(img transferImage) string
	// verify checks the inspected image against the approved one.
	verify func(img transferImage, res registrypull.Result, got inspectedImage) error
}

// imageStoreEvidence defines the evidence per store:
//
//   - containerd: the image store keeps the imported manifest as the
//     image's target, so `docker image inspect repository@platform-digest`
//     must find an image whose Id is the bound platform digest, whose
//     RepoDigests list repository@platform-digest, whose RepoTags hold the
//     transfer tag and whose platform is the bound one. That reference is
//     exactly what `repository:tag@digest` with `--pull never`, phase 1's
//     digest check and a retained reference resolve, so the store is
//     available. The check fails closed when the engine rewrote the
//     manifest on import (a docker-archive without the registry manifest):
//     the image is then not found by digest, or has another Id.
//   - classic: `docker load` records no digest reference, and no command
//     can add one, so `repository@digest` and `repository:tag@digest` are
//     never found with `--pull never`. The evidence is the image Id, which
//     the classic store derives from the configuration: it must equal the
//     configuration digest of the verified manifest, under the transfer
//     tag. It proves the bytes but cannot serve the host job, so the store
//     stays unavailable and the member is refused before the transfer.
var imageStoreEvidence = map[string]storeEvidence{
	imageStoreContainerd: {
		available: true,
		ref:       func(img transferImage) string { return img.repository + "@" + img.platformDigest },
		verify:    verifyContainerdEvidence,
	},
	imageStoreClassic: {
		available: false,
		why:       "the classic image store records no repository digest for a loaded image, so repository:tag@digest is never found with --pull never",
		ref:       func(img transferImage) string { return img.repository + ":" + img.transferTag() },
		verify:    verifyClassicEvidence,
	},
}

// inspectedImage is the part of `docker image inspect` the evidence reads.
type inspectedImage struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	RepoDigests  []string `json:"RepoDigests"`
	OS           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Variant      string   `json:"Variant"`
}

func (got inspectedImage) platformIs(p registrypull.Platform) bool {
	return got.OS == p.OS && got.Architecture == p.Architecture && got.Variant == p.Variant
}

func verifyContainerdEvidence(img transferImage, _ registrypull.Result, got inspectedImage) error {
	if got.ID != img.platformDigest || !slices.Contains(got.RepoDigests, img.repository+"@"+img.platformDigest) ||
		!slices.Contains(got.RepoTags, img.repository+":"+img.transferTag()) || !got.platformIs(img.platform) {
		return errTransferEvidence
	}
	return nil
}

func verifyClassicEvidence(img transferImage, res registrypull.Result, got inspectedImage) error {
	if res.ImageID == "" || got.ID != res.ImageID || !slices.Contains(got.RepoTags, img.repository+":"+img.transferTag()) ||
		!got.platformIs(img.platform) {
		return errTransferEvidence
	}
	return nil
}

// transferImage is one distinct image of a member.
type transferImage struct {
	repository     string // host[:port]/path, as bound
	path           string // repository path in the registry
	newTag         string
	indexDigest    string
	platformDigest string
	platform       registrypull.Platform
}

// transferTag is the tag the archive records for img.
func (img transferImage) transferTag() string {
	return transferTagPrefix + strings.TrimPrefix(img.platformDigest, "sha256:")
}

// TransferredImage is the evidence of one loaded image. It holds no
// credential.
type TransferredImage struct {
	Repository     string
	PlatformDigest string
	ImageID        string
	Store          string
	BlobBytes      int64
}

// transferHooks lets tests observe the points between transfer steps.
type transferHooks struct {
	// afterResolve runs after phase 2, before the pre-transfer recheck.
	afterResolve func()
	// duringStream runs once after the first archive bytes reached the
	// target.
	duringStream func()
}

// transferState is the Service's private transfer configuration.
type transferState struct {
	mu sync.Mutex
	// tempDir holds registrypull's unlinked layer spool (empty: os.TempDir).
	tempDir string
	hooks   transferHooks
}

// SetPrivateTransferTempDir sets the directory for the transfer's layer
// spool. It bounds the executor's disk use to one layer
// (registrypull.MaxBlobBytes) per concurrent transfer.
func (s *Service) SetPrivateTransferTempDir(dir string) {
	s.transfer.mu.Lock()
	s.transfer.tempDir = dir
	s.transfer.mu.Unlock()
}

// parseTransferPlatform splits a bound "os/arch[/variant]".
func parseTransferPlatform(p string) (registrypull.Platform, bool) {
	parts := strings.Split(p, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return registrypull.Platform{}, false
	}
	out := registrypull.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		out.Variant = parts[2]
	}
	return out, out.OS != "" && out.Architecture != ""
}

// transferImages returns the distinct images of u in the registry l.
func transferImages(u canonical.BatchContainerUpdate, l *loadedRegistry) ([]transferImage, error) {
	host, err := registryHost(l.rec.Registry)
	if err != nil {
		return nil, errTransferScope
	}
	var out []transferImage
	for _, img := range u.Images {
		path, ok := strings.CutPrefix(img.Repository, host+"/")
		if !ok || !transferRepoRe.MatchString(img.Repository) || !slices.Contains(l.rec.Repositories, path) {
			return nil, errTransferScope
		}
		pl, ok := parseTransferPlatform(img.Platform)
		if !ok || !transferDigestRe.MatchString(img.NewPlatformDigest) ||
			(img.NewIndexDigest != "" && !transferDigestRe.MatchString(img.NewIndexDigest)) || !registrymeta.ValidTag(img.NewTag) {
			return nil, errTransferScope
		}
		t := transferImage{repository: img.Repository, path: path, newTag: img.NewTag, indexDigest: img.NewIndexDigest,
			platformDigest: img.NewPlatformDigest, platform: pl}
		if i := slices.IndexFunc(out, func(o transferImage) bool {
			return o.repository == t.repository && o.platformDigest == t.platformDigest
		}); i >= 0 {
			// The same image for two services: one transfer, but both
			// tags must resolve and the bindings must agree.
			if out[i].indexDigest != t.indexDigest || out[i].platform != t.platform {
				return nil, errTransferScope
			}
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 || len(out) > maxTransferImages {
		return nil, errTransferScope
	}
	return out, nil
}

// registryHost is the lower-case host[:port] of an approved origin.
func registryHost(origin string) (string, error) {
	h, ok := strings.CutPrefix(origin, "https://")
	if !ok || h == "" || strings.ContainsAny(h, "/?#@") || h != strings.ToLower(h) {
		return "", errors.New("invalid registry origin")
	}
	return h, nil
}

// openTransferRegistry opens the bound registry and checks it against the
// binding: vault unlocked at epoch, record digest, credential identity and
// version equal, credential not expired. The caller must wipe the result.
func (s *Service) openTransferRegistry(epoch uint64, b canonical.ContainerUpdateRegistry) (*loadedRegistry, error) {
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked || s.vault.LockGeneration() != epoch {
		return nil, errTransferLocked
	}
	l, err := s.loadRegistry(b.RegistryID)
	switch {
	case errors.Is(err, vault.ErrLocked):
		return nil, errTransferLocked
	case err != nil:
		return nil, errTransferBinding
	}
	if l.configDigest != b.RecordDigest || l.cred.ID != b.CredentialID || l.credVersion <= 0 ||
		uint64(l.credVersion) != b.CredentialVersion {
		l.wipe()
		return nil, errTransferBinding
	}
	if !s.clock().Before(time.Unix(l.cred.ExpiresUnix, 0)) {
		l.wipe()
		return nil, errTransferExpired
	}
	if s.vault.LockGeneration() != epoch {
		l.wipe()
		return nil, errTransferLocked
	}
	return l, nil
}

// recheckTransfer re-verifies everything the transfer depends on: lock
// generation, the stored record and credential identity (re-opened, so a
// removed and re-added registry never matches), expiry and every claim.
func (s *Service) recheckTransfer(ctx context.Context, epoch uint64, l *loadedRegistry, b canonical.ContainerUpdateRegistry, claims []RegistryReadClaim) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("private transfer: %w", err)
	}
	now, err := s.openTransferRegistry(epoch, b)
	if err != nil {
		return err
	}
	same := now.configVersion == l.configVersion && now.configDigest == l.configDigest &&
		now.credVersion == l.credVersion && now.cred.ID == l.cred.ID
	now.wipe()
	if !same {
		return errTransferBinding
	}
	for _, c := range claims {
		if c.Check() != nil {
			return errTransferGrant
		}
	}
	return nil
}

// transferPrivateImages runs phases 2 and 3 of a private update member u
// against the target behind client and returns the evidence of every
// loaded image. On error nothing has been dispatched; an image that was
// already loaded stays on the target (no cleanup, plan non-goals) and the
// member stops without a retry.
func (s *Service) transferPrivateImages(ctx context.Context, client *ssh.Client, u canonical.BatchContainerUpdate) ([]TransferredImage, error) {
	if u.Registry == nil || u.Kind != canonical.ContainerUpdateKindUpdate {
		return nil, errTransferScope
	}
	b := *u.Registry
	ctx, cancel := context.WithTimeout(ctx, privateTransferTimeout)
	defer cancel()
	epoch := s.vault.LockGeneration()
	l, err := s.openTransferRegistry(epoch, b)
	if err != nil {
		return nil, err
	}
	defer l.wipe()
	images, err := transferImages(u, l)
	if err != nil {
		return nil, err
	}

	// Phase 2 over the private read path.
	claims, err := s.resolvePrivateTags(ctx, l, u)
	if err != nil {
		return nil, err
	}
	s.transfer.mu.Lock()
	hooks, tempDir := s.transfer.hooks, s.transfer.tempDir
	s.transfer.mu.Unlock()
	if hooks.afterResolve != nil {
		hooks.afterResolve()
	}

	// The store decides before any blob is fetched.
	store, err := detectImageStore(ctx, client, s.jobs.Sudo)
	if err != nil {
		return nil, err
	}
	ev := imageStoreEvidence[store]
	if !ev.available {
		s.log.Warn("audit", "kind", "private_transfer_refused", "registry", l.rec.ID, "store", store, "detail", ev.why)
		return nil, fmt.Errorf("%w (%s): %s", errTransferStore, store, ev.why)
	}

	if err := s.recheckTransfer(ctx, epoch, l, b, claims); err != nil {
		return nil, err
	}
	puller, err := registrypull.New(registrypull.Options{Registry: l.rec.meta(), RootCAs: l.roots, TempDir: tempDir,
		AllowLoopback: s.registry.allowLoopback})
	if err != nil {
		return nil, errTransferPull
	}
	cred := registrymeta.Credential{Username: l.cred.Username, Secret: l.cred.Secret}
	var out []TransferredImage
	for _, img := range images {
		req := registrypull.Request{Repository: img.path, Digest: img.platformDigest, Tag: img.transferTag(), Platform: img.platform}
		if img.indexDigest != "" {
			req.Digest = img.indexDigest
		}
		res, err := s.loadOverSSH(ctx, client, puller, cred, req, epoch, hooks.duringStream)
		// Recheck after every stream, also a failed one: a change during
		// the transfer is reported as that change.
		if rerr := s.recheckTransfer(ctx, epoch, l, b, claims); rerr != nil {
			s.log.Warn("audit", "kind", "private_transfer_stopped", "registry", l.rec.ID, "repository", img.path, "detail", rerr.Error())
			return nil, rerr
		}
		if err != nil {
			s.log.Warn("audit", "kind", "private_transfer_failed", "registry", l.rec.ID, "repository", img.path, "detail", err.Error())
			return nil, err
		}
		if res.ManifestDigest != img.platformDigest || (img.indexDigest != "" && res.IndexDigest != img.indexDigest) {
			return nil, errTransferEvidence
		}
		got, err := inspectLoadedImage(ctx, client, s.jobs.Sudo, ev.ref(img))
		if err != nil {
			return nil, err
		}
		if err := ev.verify(img, res, got); err != nil {
			s.log.Warn("audit", "kind", "private_transfer_mismatch", "registry", l.rec.ID, "repository", img.path,
				"want", img.platformDigest, "store", store)
			return nil, err
		}
		out = append(out, TransferredImage{Repository: img.repository, PlatformDigest: img.platformDigest, ImageID: got.ID,
			Store: store, BlobBytes: res.BlobBytes})
		s.log.Info("audit", "kind", "private_image_transferred", "registry", l.rec.ID, "repository", img.path,
			"digest", img.platformDigest, "store", store, "bytes", res.BlobBytes, "credential_version", l.credVersion)
	}
	return out, nil
}

// resolvePrivateTags is phase 2 in the executor: each entry's new tag is
// read with a reserved read-grant claim, and must name the bound index
// digest (or the platform digest when no index is bound).
func (s *Service) resolvePrivateTags(ctx context.Context, l *loadedRegistry, u canonical.BatchContainerUpdate) ([]RegistryReadClaim, error) {
	client, err := s.registryClient(l)
	if err != nil {
		return nil, errTransferResolve
	}
	host, _ := registryHost(l.rec.Registry)
	cred := registrymeta.Credential{Username: l.cred.Username, Secret: l.cred.Secret}
	scope := l.rec.ID + "/" + l.configDigest + "/" + l.cred.ID + "/v" + strconv.FormatInt(l.credVersion, 10)
	var claims []RegistryReadClaim
	seen := map[string]bool{}
	for _, img := range u.Images {
		path := strings.TrimPrefix(img.Repository, host+"/")
		key := path + ":" + img.NewTag
		if seen[key] {
			continue
		}
		seen[key] = true
		claim, err := s.registryAuthorizer().AuthorizeRegistryRead(RegistryRead{RegistryID: l.rec.ID, Method: RegistryMethodTagDigest,
			Repository: path, ConfigDigest: l.configDigest, ConfigVersion: l.configVersion, CredentialVersion: l.credVersion,
			CredentialID: l.cred.ID, Reference: img.NewTag})
		if err != nil {
			return nil, errTransferGrant
		}
		claims = append(claims, claim)
		if claim.Check() != nil {
			return nil, errTransferGrant
		}
		res, err := client.TagDigest(ctx, registrymeta.Ref{Registry: l.rec.Registry, Repository: path, Tag: img.NewTag}, cred, scope)
		if err != nil || !registrymeta.ValidDigest(res.Digest) {
			return nil, errTransferResolve
		}
		want := img.NewIndexDigest
		if want == "" {
			want = img.NewPlatformDigest
		}
		if res.Digest != want {
			return nil, errTransferTagMoved
		}
	}
	return claims, nil
}

// hostCommand runs one fixed command on the target with stdin and returns
// at most limit bytes of stdout. Stderr is discarded.
func hostCommand(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader, limit int) ([]byte, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open session: %w", err)
	}
	defer sess.Close()
	out := &cappedWriter{limit: limit}
	sess.Stdout = out
	sess.Stderr = io.Discard
	if stdin != nil {
		sess.Stdin = stdin
	}
	if err := sess.Start(cmd); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Close()
		<-done
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if out.over {
		return nil, errors.New("output exceeds its limit")
	}
	return out.buf.Bytes(), nil
}

// cappedWriter keeps the first limit bytes and notes whether more came.
type cappedWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
	over  bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - w.buf.Len(); room < len(p) {
		w.over = true
		if room > 0 {
			w.buf.Write(p[:room])
		}
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

func sudoPrefix(sudo bool) string {
	if sudo {
		return "sudo -n "
	}
	return ""
}

// detectImageStore reads the target engine's image store from `docker
// info`. The output is untrusted: bounded, UTF-8 and JSON-checked.
func detectImageStore(ctx context.Context, client *ssh.Client, sudo bool) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, transferHostCommandTimeout)
	defer cancel()
	out, err := hostCommand(cctx, client, sudoPrefix(sudo)+"docker info --format '{{json .DriverStatus}}'", nil, maxTransferHostOutput)
	if err != nil || !utf8.Valid(out) {
		return "", fmt.Errorf("%w: the image store could not be determined", errTransferStore)
	}
	var status [][]string
	if err := json.Unmarshal(bytes.TrimSpace(out), &status); err != nil {
		return "", fmt.Errorf("%w: the image store could not be determined", errTransferStore)
	}
	for _, kv := range status {
		if len(kv) == 2 && kv[0] == "driver-type" && kv[1] == containerdDriverType {
			return imageStoreContainerd, nil
		}
	}
	return imageStoreClassic, nil
}

// inspectLoadedImage inspects ref on the target. ref is built from bound,
// validated values only and single-quoted.
func inspectLoadedImage(ctx context.Context, client *ssh.Client, sudo bool, ref string) (inspectedImage, error) {
	repo, rest, _ := strings.Cut(ref, "@")
	if strings.Contains(ref, "@") {
		if !transferDigestRe.MatchString(rest) {
			return inspectedImage{}, errTransferEvidence
		}
	} else {
		i := strings.LastIndex(ref, ":")
		if i < 0 || !registrymeta.ValidTag(ref[i+1:]) {
			return inspectedImage{}, errTransferEvidence
		}
		repo = ref[:i]
	}
	if !transferRepoRe.MatchString(repo) {
		return inspectedImage{}, errTransferEvidence
	}
	cctx, cancel := context.WithTimeout(ctx, transferHostCommandTimeout)
	defer cancel()
	out, err := hostCommand(cctx, client, sudoPrefix(sudo)+"docker image inspect --format '{{json .}}' -- '"+ref+"'", nil, maxTransferHostOutput)
	if err != nil || !utf8.Valid(out) {
		return inspectedImage{}, errTransferEvidence
	}
	var got inspectedImage
	if err := json.Unmarshal(bytes.TrimSpace(out), &got); err != nil || len(got.RepoTags) > 256 || len(got.RepoDigests) > 256 {
		return inspectedImage{}, errTransferEvidence
	}
	return got, nil
}

// lockGuard cuts the stream at the next write once the vault is locked or
// its lock generation moved, so the target never gets a complete archive
// across a lock. hook runs once after the first write.
type lockGuard struct {
	w     io.Writer
	s     *Service
	epoch uint64
	hook  func()
	once  sync.Once
}

func (g *lockGuard) Write(p []byte) (int, error) {
	if st, err := g.s.vault.State(); err != nil || st != vault.StateUnlocked || g.s.vault.LockGeneration() != g.epoch {
		return 0, errTransferLocked
	}
	n, err := g.w.Write(p)
	if g.hook != nil {
		g.once.Do(g.hook)
	}
	return n, err
}

// loadOverSSH streams one verified archive into `docker load` on the
// target. The session gets the archive on stdin and nothing else; the
// command is fixed. Success needs both a complete, verified pull and exit
// status 0 of `docker load`.
func (s *Service) loadOverSSH(ctx context.Context, client *ssh.Client, puller *registrypull.Puller, cred registrymeta.Credential,
	req registrypull.Request, epoch uint64, hook func()) (registrypull.Result, error) {
	sess, err := client.NewSession()
	if err != nil {
		return registrypull.Result{}, errTransferLoad
	}
	defer sess.Close()
	pr, pw := io.Pipe()
	sess.Stdin = pr
	out := &cappedWriter{limit: maxTransferLoadOutput}
	sess.Stdout, sess.Stderr = out, out
	if err := sess.Start(sudoPrefix(s.jobs.Sudo) + "docker load -q"); err != nil {
		_ = pr.Close()
		return registrypull.Result{}, errTransferLoad
	}
	type pulled struct {
		res registrypull.Result
		err error
	}
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	pullDone := make(chan pulled, 1)
	go func() {
		res, err := puller.Pull(pctx, cred, req, &lockGuard{w: pw, s: s, epoch: epoch, hook: hook})
		if err != nil {
			// Without manifest.json and trailer `docker load` refuses the
			// stream; it never held an unverified byte.
			pw.CloseWithError(err)
		} else {
			_ = pw.Close()
		}
		pullDone <- pulled{res, err}
	}()
	waitDone := make(chan error, 1)
	go func() { waitDone <- sess.Wait() }()
	var werr error
	select {
	case werr = <-waitDone:
	case <-ctx.Done():
		_ = sess.Close()
		werr = <-waitDone
		if werr == nil {
			werr = ctx.Err()
		}
	}
	// The load ended: a pull still writing must not block on the pipe.
	_ = pr.CloseWithError(errTransferLoad)
	p := <-pullDone
	switch {
	case errors.Is(p.err, errTransferLocked):
		return registrypull.Result{}, errTransferLocked
	case p.err != nil:
		return registrypull.Result{}, fmt.Errorf("%w: %s", errTransferPull, pullReason(p.err))
	case werr != nil:
		return registrypull.Result{}, errTransferLoad
	}
	return p.res, nil
}

// pullReason maps a registrypull error to a fixed reason: no registry
// text, URL, credential or token.
func pullReason(err error) string {
	for _, r := range []struct {
		err    error
		reason string
	}{
		{registrypull.ErrDigestMismatch, "digest mismatch"},
		{registrypull.ErrSizeMismatch, "size mismatch"},
		{registrypull.ErrTooLarge, "content too large"},
		{registrypull.ErrOutOfScope, "repository out of scope"},
		{registrypull.ErrCredentialRejected, "credential rejected"},
		{registrypull.ErrRealmNotApproved, "unapproved auth realm"},
		{registrypull.ErrRedirectNotAllowed, "redirect not allowed"},
		{registrypull.ErrRequestNotAllowed, "request not allowed"},
		{registrypull.ErrPrivateAddress, "refused address"},
		{registrypull.ErrPlatform, "platform mismatch"},
		{registrypull.ErrNotFound, "not found"},
		{registrypull.ErrRateLimited, "rate limited"},
		{registrypull.ErrUnsupported, "unsupported content"},
		{registrypull.ErrBadResponse, "malformed response"},
	} {
		if errors.Is(err, r.err) {
			return r.reason
		}
	}
	return "registry unreachable"
}
