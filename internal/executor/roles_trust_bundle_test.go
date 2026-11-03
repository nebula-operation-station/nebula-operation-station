// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

// bundleSK is a software stand-in for the FIDO release root, test-only.
type bundleSK struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newBundleSK(t *testing.T) *bundleSK {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, release.Application}))
	if err != nil {
		t.Fatal(err)
	}
	return &bundleSK{priv: priv, pub: k}
}

func (k *bundleSK) anchors() []release.Anchor {
	return []release.Anchor{{ID: "root-1", Key: k.pub}, {ID: "root-2"}}
}

func (k *bundleSK) sign(msg []byte) []byte {
	h := sha512.Sum512(msg)
	var m [6]byte
	copy(m[:], "SSHSIG")
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{m, release.Namespace, "", "sha512", h[:]})
	app := sha256.Sum256([]byte(release.Application))
	data := sha256.Sum256(signed)
	fido := ssh.Marshal(struct {
		App     []byte `ssh:"rest"`
		Flags   byte
		Counter uint32
		Data    []byte `ssh:"rest"`
	}{app[:], 1, 0, data[:]})
	sig := ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(k.priv, fido),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{1, 0})}
	raw := ssh.Marshal(struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}{m, 1, k.pub.Marshal(), release.Namespace, "", "sha512", ssh.Marshal(sig)})
	return []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END SSH SIGNATURE-----\n")
}

func bundleCanon(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	c, err := jcs.Transform(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func bundleSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func bundleTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, n := range names {
		if err := w.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(files[n]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// writeDockerBundle writes a signed release bundle with one built-in
// module "docker" at moduleVersion (one LOW action) into dir.
func writeDockerBundle(t *testing.T, k *bundleSK, dir, releaseVersion, moduleVersion, script string) {
	t.Helper()
	l := modulelock.Lock{Format: modulelock.Format, Name: "docker", Version: moduleVersion, Title: "Built-in",
		Actions: map[string]modulelock.Action{"restart": {Title: "restart", Script: "actions/restart.sh", SHA256: bundleSum([]byte(script)),
			Risk: "LOW", TimeoutS: 60, Params: []prelude.Param{}, Secrets: []string{}, Declares: []string{}}}}
	mod := bundleTar(t, map[string][]byte{"actions/restart.sh": []byte(script), release.LockFile: bundleCanon(t, l)})
	modPath := "modules/docker/" + moduleVersion + ".tar"
	bundle := bundleTar(t, map[string][]byte{modPath: mod})
	man := bundleCanon(t, map[string]any{"format": release.ManifestFormat, "release_version": releaseVersion,
		"artifacts": []any{map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": bundleSum(bundle)}},
		"modules":   []any{map[string]any{"name": "docker", "version": moduleVersion, "size": len(mod), "sha256": bundleSum(mod)}}})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{release.ManifestFile: man, release.SignatureFile: k.sign(man), release.BundleArtifact: bundle} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// listTree returns every path under dir with its size and mtime.
func listTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		out[p] = fmt.Sprintf("%v %d %d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type bundleEnv struct {
	k                   *bundleSK
	storeDir, bundleDir string
	now                 func() time.Time
	bt                  *dirBuiltinTrust
}

func newBundleEnv(t *testing.T) *bundleEnv {
	t.Helper()
	dir := t.TempDir()
	e := &bundleEnv{k: newBundleSK(t), storeDir: filepath.Join(dir, "trust"), bundleDir: filepath.Join(dir, "bundle"),
		now: func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }}
	writeDockerBundle(t, e.k, e.bundleDir, "2026.11.0", "1.0.0", "echo restart\n")
	bt, err := NewDirBuiltinTrust(e.storeDir, e.bundleDir, e.k.anchors(), e.now)
	if err != nil {
		t.Fatal(err)
	}
	e.bt = bt.(*dirBuiltinTrust)
	return e
}

// review runs an admin review and confirms it delivered, as the
// ReviewBuiltinTrust handler does.
func (e *bundleEnv) review(t *testing.T) (trust.BulkAdmitResult, error) {
	t.Helper()
	res, err := e.bt.Review(context.Background())
	if err == nil {
		e.bt.ConfirmReview(context.Background(), res.ManifestDigest, res.Review.Generation)
	}
	return res, err
}

// The server's status path never bootstraps or rewrites trust state: with
// index.json deleted after construction (and no objects), status reports
// UNAVAILABLE and nothing is written; an admin review does not either.
func TestBuiltinTrustStatusNeverBootstraps(t *testing.T) {
	e := newBundleEnv(t)
	if err := os.Remove(filepath.Join(e.storeDir, "index.json")); err != nil {
		t.Fatal(err)
	}
	before := listTree(t, e.storeDir)
	s := &Service{}
	s.SetBuiltinTrust(e.bt)
	out, err := callAs(t, trustTestServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName, &pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE {
		t.Fatalf("status = %+v, want UNAVAILABLE", out)
	}
	if _, err := e.bt.Review(context.Background()); !errors.Is(err, trust.ErrStateMissing) {
		t.Fatalf("review err = %v, want ErrStateMissing", err)
	}
	if _, err := os.Stat(filepath.Join(e.storeDir, "index.json")); !os.IsNotExist(err) {
		t.Fatalf("index.json was recreated: %v", err)
	}
	after := listTree(t, e.storeDir)
	if len(after) != len(before) {
		t.Fatalf("store tree changed: before %v, after %v", before, after)
	}
	for p, v := range before {
		if after[p] != v {
			t.Fatalf("store entry %s changed: %q -> %q", p, v, after[p])
		}
	}
}

// A real bundle commits through the directory-backed transaction: the
// commit returns the new store generation, a second commit of the same
// review is stale, and a store changed by a concurrent commit since the
// admin's review rejects the commit as stale.
func TestDirBuiltinTrustCommitRealBundle(t *testing.T) {
	e := newBundleEnv(t)
	ctx := context.Background()
	rev, err := e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if !rev.NeedsConfirmation || rev.Review.Generation != 0 || len(rev.OldVersions) != 0 {
		t.Fatalf("review = %+v", rev)
	}
	res, gen, err := e.bt.Commit(ctx, rev.ManifestDigest, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Committed || gen != 1 {
		t.Fatalf("commit = %+v, generation %d; want committed at 1", res, gen)
	}
	st, err := trust.OpenExisting(e.storeDir, e.now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation() != gen {
		t.Fatalf("durable generation %d, commit returned %d", st.Generation(), gen)
	}
	// The review was consumed: committing it again is stale.
	if _, _, err := e.bt.Commit(ctx, rev.ManifestDigest, nil, nil, 0); !errors.Is(err, trust.ErrStale) {
		t.Fatalf("recommit err = %v, want ErrStale", err)
	}

	// A new release; the admin reviews it at generation 1.
	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	rev, err = e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Review.Generation != 1 || len(rev.OldVersions) != 1 || rev.OldVersions[0] != "docker@1.0.0" {
		t.Fatalf("review = %+v", rev)
	}
	// Meanwhile another local writer commits to the same store.
	other, err := trust.Open(e.storeDir, e.k.anchors(), e.now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := release.ReadBundleDir(e.bundleDir, other.Roots())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.BulkAdmit(c, trust.BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest, Retired: []string{"docker@1.0.0"}}); err != nil {
		t.Fatal(err)
	}
	// The admin's commit of the generation-1 review is now stale.
	if _, _, err := e.bt.Commit(ctx, rev.ManifestDigest, nil, []string{"docker@1.0.0"}, 0); !errors.Is(err, trust.ErrStale) {
		t.Fatalf("stale commit err = %v, want ErrStale", err)
	}
	if st, err := trust.OpenExisting(e.storeDir, e.now); err != nil || st.Generation() != 2 {
		t.Fatalf("store after stale commit: %v, %v", st, err)
	}
}

// The status dry run is cached while the store generation and the bundle
// are unchanged, and recomputed after a commit or a bundle change.
func TestDirBuiltinTrustStatusIsCached(t *testing.T) {
	e := newBundleEnv(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		res, err := e.bt.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !res.NeedsConfirmation || res.Review.Generation != 0 {
			t.Fatalf("status = %+v", res)
		}
	}
	if e.bt.statusRuns != 1 {
		t.Fatalf("status dry runs = %d, want 1", e.bt.statusRuns)
	}
	rev, err := e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.bt.Commit(ctx, rev.ManifestDigest, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	res, err := e.bt.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.NeedsConfirmation || res.Review.Generation != 1 || e.bt.statusRuns != 2 {
		t.Fatalf("status after commit = %+v, runs %d", res, e.bt.statusRuns)
	}
	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	res, err = e.bt.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsConfirmation || res.Review.ReleaseVersion != "2026.12.0" || e.bt.statusRuns != 3 {
		t.Fatalf("status after bundle change = %+v, runs %d", res, e.bt.statusRuns)
	}
	if _, err := e.bt.Status(ctx); err != nil || e.bt.statusRuns != 3 {
		t.Fatalf("cached status: %v, runs %d", err, e.bt.statusRuns)
	}
}

// storeGeneration reads the durable store generation.
func (e *bundleEnv) storeGeneration(t *testing.T) int64 {
	t.Helper()
	st, err := trust.OpenExisting(e.storeDir, e.now)
	if err != nil {
		t.Fatal(err)
	}
	return st.Generation()
}

// adminCommit commits digest through the handler as the local admin.
func adminCommit(t *testing.T, s *Service, digest string) error {
	t.Helper()
	_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName,
		&pb.CommitBuiltinTrustRequest{ManifestDigest: digest}, s.CommitBuiltinTrust)
	return err
}

// serverStatus reads the trust status through the handler as the server.
func serverStatus(t *testing.T, s *Service) *pb.GetBuiltinTrustStatusResponse {
	t.Helper()
	out, err := callAs(t, trustTestServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName,
		&pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// inflatingTrust inflates the real review past the response limit.
type inflatingTrust struct{ *dirBuiltinTrust }

func (i inflatingTrust) Review(ctx context.Context) (trust.BulkAdmitResult, error) {
	res, err := i.dirBuiltinTrust.Review(ctx)
	if err != nil {
		return res, err
	}
	big := strings.Repeat("x", 1<<20)
	lines := make([]textdiff.Line, MaxResponseSize/(1<<20)+1)
	for j := range lines {
		lines[j] = textdiff.Line{Op: textdiff.Insert, Text: big}
	}
	res.Review.Modules[0].Actions[0].Diff = lines
	return res, nil
}

// A review refused for its size never reached the admin, so it leaves no
// commit binding: a commit of the (status-visible) digest is Aborted.
func TestBuiltinTrustOversizeReviewIsNotCommittable(t *testing.T) {
	e := newBundleEnv(t)
	s := &Service{}
	s.SetBuiltinTrust(inflatingTrust{e.bt})
	_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("review err = %v, want ResourceExhausted", err)
	}
	if e.bt.reviewed != nil {
		t.Fatal("refused review left a commit binding")
	}
	digest := serverStatus(t, s).ManifestDigest
	if err := adminCommit(t, s, digest); status.Code(err) != codes.Aborted {
		t.Fatalf("commit err = %v, want Aborted", err)
	}
	if g := e.storeGeneration(t); g != 0 {
		t.Fatalf("store generation %d, want 0", g)
	}
}

// A commit is bound to the reviewed manifest digest: reviewing bundle A
// and then committing bundle B swapped in at the same generation is
// Aborted and leaves the store unchanged.
func TestBuiltinTrustCommitRequiresReviewedDigest(t *testing.T) {
	e := newBundleEnv(t)
	s := &Service{}
	s.SetBuiltinTrust(e.bt)
	if _, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust); err != nil {
		t.Fatal(err)
	}
	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo swapped\n")
	b := serverStatus(t, s)
	if b.ReleaseVersion != "2026.12.0" || b.Generation != 0 {
		t.Fatalf("status of B = %+v", b)
	}
	before := listTree(t, e.storeDir)
	if err := adminCommit(t, s, b.ManifestDigest); status.Code(err) != codes.Aborted {
		t.Fatalf("commit of unreviewed B: %v, want Aborted", err)
	}
	after := listTree(t, e.storeDir)
	if len(after) != len(before) {
		t.Fatalf("store tree changed: before %v, after %v", before, after)
	}
	for p, v := range before {
		if after[p] != v {
			t.Fatalf("store entry %s changed: %q -> %q", p, v, after[p])
		}
	}
}

// The server's status never creates a commit binding.
func TestBuiltinTrustStatusCreatesNoBinding(t *testing.T) {
	e := newBundleEnv(t)
	s := &Service{}
	s.SetBuiltinTrust(e.bt)
	digest := serverStatus(t, s).ManifestDigest
	if e.bt.reviewed != nil || e.bt.pending != nil {
		t.Fatal("status created a commit binding")
	}
	if err := adminCommit(t, s, digest); status.Code(err) != codes.Aborted {
		t.Fatalf("commit after status only: %v, want Aborted", err)
	}
	if g := e.storeGeneration(t); g != 0 {
		t.Fatalf("store generation %d, want 0", g)
	}
}

// A failed review clears an earlier binding, even when the same bundle
// comes back unchanged.
func TestBuiltinTrustFailedReviewClearsBinding(t *testing.T) {
	e := newBundleEnv(t)
	s := &Service{}
	s.SetBuiltinTrust(e.bt)
	rev, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if err != nil {
		t.Fatal(err)
	}
	away := e.bundleDir + ".away"
	if err := os.Rename(e.bundleDir, away); err != nil {
		t.Fatal(err)
	}
	if _, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust); err == nil {
		t.Fatal("review without a bundle succeeded")
	}
	if err := os.Rename(away, e.bundleDir); err != nil {
		t.Fatal(err)
	}
	if err := adminCommit(t, s, rev.ManifestDigest); status.Code(err) != codes.Aborted {
		t.Fatalf("commit after a failed review: %v, want Aborted", err)
	}
	if g := e.storeGeneration(t); g != 0 {
		t.Fatalf("store generation %d, want 0", g)
	}
}
