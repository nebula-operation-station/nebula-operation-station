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
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
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
	// The manifest must list installed-files.json (spec 10). ReadBundleDir
	// does not read it from dir, so only its digest is needed here.
	list := []byte("placeholder")
	man := bundleCanon(t, map[string]any{"format": release.ManifestFormat, "release_version": releaseVersion,
		"artifacts": []any{
			map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": bundleSum(bundle)},
			map[string]any{"name": release.InstalledFilesArtifact, "size": len(list), "sha256": bundleSum(list)},
		},
		"modules": []any{map[string]any{"name": "docker", "version": moduleVersion, "size": len(mod), "sha256": bundleSum(mod)}}})
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
	// db holds the executor's artifact trust (the risk authority).
	db *executordb.DB
}

func newBundleEnv(t *testing.T) *bundleEnv {
	t.Helper()
	dir := t.TempDir()
	e := &bundleEnv{k: newBundleSK(t), storeDir: filepath.Join(dir, "trust"), bundleDir: filepath.Join(dir, "bundle"),
		now: func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }}
	e.db = openTrustTestDB(t)
	writeDockerBundle(t, e.k, e.bundleDir, "2026.11.0", "1.0.0", "echo restart\n")
	bt, err := NewDirBuiltinTrust(e.storeDir, e.bundleDir, e.k.anchors(), e.now, e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.bt = bt.(*dirBuiltinTrust)
	return e
}

// service returns a Service wired to the directory-backed transaction.
func (e *bundleEnv) service() *Service {
	s := &Service{}
	s.SetBuiltinTrust(e.bt)
	return s
}

// adminReview runs the ReviewBuiltinTrust handler as the local admin. Only
// the handler confirms the review, so a handler that does not confirm, or
// confirms another digest or generation, leaves nothing committable.
func adminReview(t *testing.T, s *Service) (*pb.ReviewBuiltinTrustResponse, error) {
	t.Helper()
	return callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName, &pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
}

// adminCommitReq runs the CommitBuiltinTrust handler as the local admin.
func adminCommitReq(t *testing.T, s *Service, req *pb.CommitBuiltinTrustRequest) (*pb.CommitBuiltinTrustResponse, error) {
	t.Helper()
	return callAs(t, trustTestAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName, req, s.CommitBuiltinTrust)
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

// A real bundle commits through the handlers and the directory-backed
// transaction: the commit returns the new store generation, a second
// commit of the same review is stale, and a store changed by a concurrent
// commit since the admin's review rejects the commit as stale.
func TestDirBuiltinTrustCommitRealBundle(t *testing.T) {
	e := newBundleEnv(t)
	s := e.service()
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if !rev.NeedsConfirmation || rev.Generation != 0 || len(rev.OldVersions) != 0 {
		t.Fatalf("review = %+v", rev)
	}
	out, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	if out.Generation != 1 || out.ManifestDigest != rev.ManifestDigest || out.AdminUid != trustTestAdminUID {
		t.Fatalf("commit = %+v; want committed at 1", out)
	}
	if g := e.storeGeneration(t); g != out.Generation {
		t.Fatalf("durable generation %d, commit returned %d", g, out.Generation)
	}
	// The review was consumed: committing it again is stale.
	if err := adminCommit(t, s, rev.ManifestDigest); status.Code(err) != codes.Aborted {
		t.Fatalf("recommit err = %v, want Aborted", err)
	}

	// A new release; the admin reviews it at generation 1.
	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	rev, err = adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Generation != 1 || len(rev.OldVersions) != 1 || rev.OldVersions[0] != "docker@1.0.0" {
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
	_, err = adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest, Retire: []string{"docker@1.0.0"}})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("stale commit err = %v, want Aborted", err)
	}
	if g := e.storeGeneration(t); g != 2 {
		t.Fatalf("store generation after stale commit %d, want 2", g)
	}
}

// The second release commits through the handlers with its old version
// retired, at the generation the review showed.
func TestDirBuiltinTrustCommitRealBundleUpgrade(t *testing.T) {
	e := newBundleEnv(t)
	s := e.service()
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest}); err != nil {
		t.Fatal(err)
	}
	writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
	rev, err = adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest, Retire: []string{"docker@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Generation != 2 || len(out.Retired) != 1 || out.Retired[0] != "docker@1.0.0" {
		t.Fatalf("commit = %+v", out)
	}
	if st := serverStatus(t, s); st.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED || st.ReleaseVersion != "2026.12.0" {
		t.Fatalf("status after upgrade = %+v", st)
	}
}

// ConfirmReview with another digest or generation than the pending review
// binds nothing and drops the pending review, so even a later matching
// confirm cannot revive it and the commit is stale.
func TestDirBuiltinTrustConfirmMismatchBindsNothing(t *testing.T) {
	const otherDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cases := map[string]func(digest string, gen int64) (string, int64){
		"other digest":     func(_ string, gen int64) (string, int64) { return otherDigest, gen },
		"other generation": func(d string, gen int64) (string, int64) { return d, gen + 1 },
		"older generation": func(d string, gen int64) (string, int64) { return d, gen - 1 },
		"empty digest":     func(_ string, gen int64) (string, int64) { return "", gen },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newBundleEnv(t)
			ctx := context.Background()
			rev, err := e.bt.Review(ctx)
			if err != nil {
				t.Fatal(err)
			}
			d, g := mutate(rev.ManifestDigest, rev.Review.Generation)
			e.bt.ConfirmReview(ctx, d, g)
			if e.bt.reviewed != nil || e.bt.pending != nil {
				t.Fatalf("mismatched confirm: reviewed=%+v pending=%+v", e.bt.reviewed, e.bt.pending)
			}
			// The pending review is gone: a matching confirm now binds nothing.
			e.bt.ConfirmReview(ctx, rev.ManifestDigest, rev.Review.Generation)
			if e.bt.reviewed != nil {
				t.Fatal("matching confirm after a mismatch revived the review")
			}
			if _, _, err := e.bt.Commit(ctx, rev.ManifestDigest, nil, nil, 0); !errors.Is(err, trust.ErrStale) {
				t.Fatalf("commit err = %v, want ErrStale", err)
			}
			if g := e.storeGeneration(t); g != 0 {
				t.Fatalf("store generation %d, want 0", g)
			}
		})
	}
	// Control: the matching confirm binds the review.
	e := newBundleEnv(t)
	rev, err := e.bt.Review(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.bt.ConfirmReview(context.Background(), rev.ManifestDigest, rev.Review.Generation)
	if b := e.bt.reviewed; b == nil || b.digest != rev.ManifestDigest || b.generation != rev.Review.Generation {
		t.Fatalf("matching confirm bound %+v", b)
	}
}

// Every commit attempt consumes the review, also one that fails: a commit
// rejected inside the trust store (an old version neither retained nor
// retired) or one that cannot read the bundle leaves nothing to retry, and
// the corrected commit needs a fresh review.
func TestBuiltinTrustFailedCommitConsumesReview(t *testing.T) {
	cases := map[string]func(t *testing.T, e *bundleEnv, s *Service, digest string) codes.Code{
		"undecided old version": func(t *testing.T, _ *bundleEnv, s *Service, digest string) codes.Code {
			_, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: digest})
			return status.Code(err)
		},
		"unknown retired version": func(t *testing.T, _ *bundleEnv, s *Service, digest string) codes.Code {
			_, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: digest, Retire: []string{"docker@1.0.0", "nope@9.9.9"}})
			return status.Code(err)
		},
		"bundle unreadable": func(t *testing.T, e *bundleEnv, s *Service, digest string) codes.Code {
			away := e.bundleDir + ".away"
			if err := os.Rename(e.bundleDir, away); err != nil {
				t.Fatal(err)
			}
			_, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: digest, Retire: []string{"docker@1.0.0"}})
			if err := os.Rename(away, e.bundleDir); err != nil {
				t.Fatal(err)
			}
			return status.Code(err)
		},
	}
	for name, fail := range cases {
		t.Run(name, func(t *testing.T) {
			e := newBundleEnv(t)
			s := e.service()
			rev, err := adminReview(t, s)
			if err != nil {
				t.Fatal(err)
			}
			if err := adminCommit(t, s, rev.ManifestDigest); err != nil {
				t.Fatal(err)
			}
			writeDockerBundle(t, e.k, e.bundleDir, "2026.12.0", "1.1.0", "echo restart v2\n")
			rev, err = adminReview(t, s)
			if err != nil {
				t.Fatal(err)
			}
			if code := fail(t, e, s, rev.ManifestDigest); code != codes.FailedPrecondition {
				t.Fatalf("failing commit: %v, want FailedPrecondition", code)
			}
			if e.bt.reviewed != nil || e.bt.pending != nil {
				t.Fatal("failed commit left a commit binding")
			}
			good := &pb.CommitBuiltinTrustRequest{ManifestDigest: rev.ManifestDigest, Retire: []string{"docker@1.0.0"}}
			if _, err := adminCommitReq(t, s, good); status.Code(err) != codes.Aborted {
				t.Fatalf("retry without a new review: %v, want Aborted", err)
			}
			if g := e.storeGeneration(t); g != 1 {
				t.Fatalf("store generation %d, want 1", g)
			}
			// A fresh review makes the corrected commit possible.
			if _, err := adminReview(t, s); err != nil {
				t.Fatal(err)
			}
			if out, err := adminCommitReq(t, s, good); err != nil || out.Generation != 2 {
				t.Fatalf("commit after a fresh review: %+v, %v", out, err)
			}
		})
	}
}

// copyStoreTree replaces dst with a copy of the directory tree src (only
// directories and regular files), keeping permission bits.
func copyStoreTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.RemoveAll(dst); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case fi.IsDir():
			if err := os.Mkdir(target, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, fi.Mode().Perm())
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, b, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, fi.Mode().Perm())
		default:
			return fmt.Errorf("unexpected store entry %s (%v)", p, fi.Mode())
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A commit rejected by the binding checks themselves (a digest other than
// the reviewed one, or a store generation other than the reviewed one)
// also consumes the review: committing the reviewed digest afterwards, at
// the reviewed generation, is still stale. Clearing the binding only after
// those checks would leave the review committable here.
func TestBuiltinTrustRejectedCommitConsumesReview(t *testing.T) {
	const otherDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cases := map[string]func(t *testing.T, e *bundleEnv, s *Service, digest string){
		"other digest": func(t *testing.T, _ *bundleEnv, s *Service, _ string) {
			if err := adminCommit(t, s, otherDigest); status.Code(err) != codes.Aborted {
				t.Fatalf("commit of another digest: %v, want Aborted", err)
			}
		},
		"other generation": func(t *testing.T, e *bundleEnv, s *Service, digest string) {
			// Another local writer commits after the review, the admin's
			// commit is stale, and then the store returns to the reviewed
			// generation (restored from a copy taken at review time).
			snap := filepath.Join(t.TempDir(), "snap")
			copyStoreTree(t, e.storeDir, snap)
			other, err := trust.Open(e.storeDir, e.k.anchors(), e.now)
			if err != nil {
				t.Fatal(err)
			}
			c, err := release.ReadBundleDir(e.bundleDir, other.Roots())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := other.BulkAdmit(c, trust.BulkAdmitOpts{ConfirmedDigest: c.Manifest.Digest}); err != nil {
				t.Fatal(err)
			}
			if err := adminCommit(t, s, digest); status.Code(err) != codes.Aborted {
				t.Fatalf("commit at a changed generation: %v, want Aborted", err)
			}
			copyStoreTree(t, snap, e.storeDir)
			if g := e.storeGeneration(t); g != 0 {
				t.Fatalf("restored store generation %d, want 0", g)
			}
		},
	}
	for name, reject := range cases {
		t.Run(name, func(t *testing.T) {
			e := newBundleEnv(t)
			s := e.service()
			rev, err := adminReview(t, s)
			if err != nil {
				t.Fatal(err)
			}
			if e.bt.reviewed == nil {
				t.Fatal("delivered review not bound")
			}
			reject(t, e, s, rev.ManifestDigest)
			if e.bt.reviewed != nil || e.bt.pending != nil {
				t.Fatal("rejected commit left a commit binding")
			}
			if err := adminCommit(t, s, rev.ManifestDigest); status.Code(err) != codes.Aborted {
				t.Fatalf("commit of the reviewed digest after a rejected commit: %v, want Aborted", err)
			}
			if g := e.storeGeneration(t); g != 0 {
				t.Fatalf("store generation %d, want 0", g)
			}
			// A fresh review makes the commit possible again.
			if _, err := adminReview(t, s); err != nil {
				t.Fatal(err)
			}
			if err := adminCommit(t, s, rev.ManifestDigest); err != nil {
				t.Fatalf("commit after a fresh review: %v", err)
			}
		})
	}
}

// confirmSwappingTrust is a handler-side wiring bug: it forwards every call
// but confirms the review with a different generation.
type confirmSwappingTrust struct{ *dirBuiltinTrust }

func (c confirmSwappingTrust) ConfirmReview(ctx context.Context, digest string, generation int64) {
	c.dirBuiltinTrust.ConfirmReview(ctx, digest, generation+1)
}

// A review confirmed with the wrong generation binds nothing, so the
// handler-driven commit is Aborted. The wrapper shifts the generation
// itself, so this re-tests ConfirmReview's mismatch check end to end; it does
// not detect a handler that confirms the wrong generation. That handler-level
// detection comes from TestReviewBuiltinTrustConfirmsDeliveredReview.
func TestBuiltinTrustWrongGenerationConfirmIsNotCommittable(t *testing.T) {
	e := newBundleEnv(t)
	s := &Service{}
	s.SetBuiltinTrust(confirmSwappingTrust{e.bt})
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if e.bt.reviewed != nil || e.bt.pending != nil {
		t.Fatal("mismatched confirm left a binding")
	}
	if err := adminCommit(t, s, rev.ManifestDigest); status.Code(err) != codes.Aborted {
		t.Fatalf("commit err = %v, want Aborted", err)
	}
	if g := e.storeGeneration(t); g != 0 {
		t.Fatalf("store generation %d, want 0", g)
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
	s := e.service()
	rev, err := adminReview(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminCommit(t, s, rev.ManifestDigest); err != nil {
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

// The status cache key covers the bundle directory listing: an extra entry,
// which ReadBundleDir rejects, invalidates a cached status even though the
// three bundle files are untouched. Removing it again recomputes the status.
func TestDirBuiltinTrustStatusCacheCoversDirListing(t *testing.T) {
	for _, extra := range []string{"extra", "manifest.json.bak", ".hidden"} {
		t.Run(extra, func(t *testing.T) {
			e := newBundleEnv(t)
			ctx := context.Background()
			if _, err := e.bt.Status(ctx); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(e.bundleDir, extra)
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := e.bt.Status(ctx); !errors.Is(err, release.ErrBundle) {
				t.Fatalf("status with an extra entry: %v, want ErrBundle", err)
			}
			if e.bt.status != nil {
				t.Fatal("rejected bundle left a cached status")
			}
			s := e.service()
			if st := serverStatus(t, s); st.State != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE {
				t.Fatalf("server status = %+v, want UNAVAILABLE", st)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			runs := e.bt.statusRuns
			if res, err := e.bt.Status(ctx); err != nil || !res.NeedsConfirmation {
				t.Fatalf("status after removal: %+v, %v", res, err)
			}
			if e.bt.statusRuns != runs+1 {
				t.Fatalf("status after removal not recomputed: runs %d -> %d", runs, e.bt.statusRuns)
			}
		})
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
	_, err := adminCommitReq(t, s, &pb.CommitBuiltinTrustRequest{ManifestDigest: digest})
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
