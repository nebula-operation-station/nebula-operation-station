// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// rotationDoc returns a canonical root-rotation.json.
func rotationDoc(t *testing.T, seq int64, previous string, add map[string]*bundleSK, revoke ...string) []byte {
	t.Helper()
	ids := make([]string, 0, len(add))
	for id := range add {
		ids = append(ids, id)
	}
	// Root IDs in this file sort correctly as strings (root-2..root-9).
	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[j] < ids[i] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	adds := []any{}
	for _, id := range ids {
		adds = append(adds, map[string]any{"id": id, "public_key": release.FormatRootKey(add[id].pub)})
	}
	revs := []any{}
	for _, id := range revoke {
		revs = append(revs, id)
	}
	return bundleCanon(t, map[string]any{"format": release.RotationFormat, "sequence": seq,
		"previous_sha256": previous, "add": adds, "revoke": revs})
}

// writeRotation places a rotation and its signature in the rotation
// directory beside the release dir bundleDir.
func writeRotation(t *testing.T, bundleDir string, doc, sig []byte) {
	t.Helper()
	dir := rotationDir(bundleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, RootRotationFile), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, RootRotationSignatureFile), sig, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rotationEnv is a bundle env whose Service audits into a buffer.
type rotationEnv struct {
	*bundleEnv
	s     *Service
	audit *bytes.Buffer
}

func newRotationEnv(t *testing.T) *rotationEnv {
	t.Helper()
	e := newBundleEnv(t)
	buf := &bytes.Buffer{}
	s := &Service{log: slog.New(slog.NewJSONHandler(buf, nil))}
	s.SetBuiltinTrust(e.bt)
	return &rotationEnv{bundleEnv: e, s: s, audit: buf}
}

func (e *rotationEnv) review(t *testing.T) (*pb.ReviewRootRotationResponse, error) {
	t.Helper()
	return callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewRootRotation_FullMethodName, &pb.ReviewRootRotationRequest{}, e.s.ReviewRootRotation)
}

func (e *rotationEnv) commit(t *testing.T, digest string) (*pb.CommitRootRotationResponse, error) {
	t.Helper()
	return callAs(t, trustTestAdminUID, pb.ExecutorService_CommitRootRotation_FullMethodName,
		&pb.CommitRootRotationRequest{RotationDigest: digest}, e.s.CommitRootRotation)
}

// rootState reads the durable root state from disk.
func (e *rotationEnv) rootState(t *testing.T) release.RootState {
	t.Helper()
	st, err := trust.OpenExisting(e.storeDir, e.now)
	if err != nil {
		t.Fatal(err)
	}
	return st.RootState()
}

func rootIDs(rs []*pb.ReleaseRoot) []string {
	var out []string
	for _, r := range rs {
		s := r.GetId()
		if r.GetRevokedSequence() != 0 {
			s += "(revoked)"
		}
		out = append(out, s)
	}
	return out
}

// A valid rotation signed by the trusted root is reviewed with old and
// new roots and their fingerprints, and is applied only after the
// digest-bound commit; the durable state then holds the new root.
func TestRootRotationValidIsReviewedThenCommitted(t *testing.T) {
	e := newRotationEnv(t)
	k2 := newBundleSK(t)
	doc := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2})
	writeRotation(t, e.bundleDir, doc, e.k.sign(doc))

	rev, err := e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	wantFP1 := release.Root{ID: "root-1", Key: e.k.pub}.Fingerprint()
	wantFP2 := release.Root{ID: "root-2", Key: k2.pub}.Fingerprint()
	if rev.RotationDigest != bundleSum(doc) || rev.Sequence != 1 || rev.CurrentSequence != 0 || rev.Generation != 0 {
		t.Fatalf("review = %+v", rev)
	}
	if rev.SignedBy.GetId() != "root-1" || rev.SignedBy.GetFingerprint() != wantFP1 {
		t.Fatalf("signed by %+v, want root-1 %s", rev.SignedBy, wantFP1)
	}
	if got := strings.Join(rootIDs(rev.OldRoots), ","); got != "root-1" {
		t.Fatalf("old roots %s", got)
	}
	if got := strings.Join(rootIDs(rev.NewRoots), ","); got != "root-1,root-2" {
		t.Fatalf("new roots %s", got)
	}
	if len(rev.Added) != 1 || rev.Added[0].GetFingerprint() != wantFP2 || rev.Added[0].GetAddedSequence() != 1 {
		t.Fatalf("added %+v", rev.Added)
	}
	// Review commits nothing.
	if s := e.rootState(t); s.Sequence != 0 || len(s.Active()) != 1 {
		t.Fatalf("review changed root state: %+v", s)
	}

	out, err := e.commit(t, rev.RotationDigest)
	if err != nil {
		t.Fatal(err)
	}
	if out.Sequence != 1 || out.Generation != 1 || out.AdminUid != trustTestAdminUID || out.RotationDigest != rev.RotationDigest {
		t.Fatalf("commit = %+v", out)
	}
	s := e.rootState(t)
	if s.Sequence != 1 || s.Digest != bundleSum(doc) || len(s.Active()) != 2 {
		t.Fatalf("durable state %+v", s)
	}
	// The new root now verifies releases: a bundle signed by root-2 reads.
	writeDockerBundle(t, k2, e.bundleDir, "2026.12.0", "1.1.0", "echo v2\n")
	if _, err := adminReview(t, e.s); err != nil {
		t.Fatalf("built-in review under root-2: %v", err)
	}
}

// Without a confirmed review, with another digest, or after the store
// changed, nothing is applied.
func TestRootRotationCommitIsDigestBound(t *testing.T) {
	e := newRotationEnv(t)
	k2 := newBundleSK(t)
	doc := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2})
	writeRotation(t, e.bundleDir, doc, e.k.sign(doc))

	if _, err := e.commit(t, bundleSum(doc)); status.Code(err) != codes.Aborted {
		t.Fatalf("commit without review: %v, want Aborted", err)
	}
	if _, err := e.review(t); err != nil {
		t.Fatal(err)
	}
	if _, err := e.commit(t, strings.Repeat("b", 64)); status.Code(err) != codes.Aborted {
		t.Fatalf("commit of other digest: %v, want Aborted", err)
	}
	// The failed commit consumed the review.
	if _, err := e.commit(t, bundleSum(doc)); status.Code(err) != codes.Aborted {
		t.Fatalf("commit after consumed review: %v, want Aborted", err)
	}
	// The file is swapped after the review: the reviewed digest no longer
	// matches the bytes on disk.
	if _, err := e.review(t); err != nil {
		t.Fatal(err)
	}
	k3 := newBundleSK(t)
	other := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-3": k3})
	writeRotation(t, e.bundleDir, other, e.k.sign(other))
	if _, err := e.commit(t, bundleSum(doc)); status.Code(err) != codes.Aborted {
		t.Fatalf("commit after swap: %v, want Aborted", err)
	}
	if s := e.rootState(t); s.Sequence != 0 || len(s.Roots) != 1 {
		t.Fatalf("root state changed: %+v", s)
	}
	if _, err := e.commit(t, ""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty digest: %v, want InvalidArgument", err)
	}
}

// Rejected rotations change nothing: a wrong signature, a signature by a
// root the durable state has revoked, a fifth active root and a replay of
// the applied rotation.
func TestRootRotationRejections(t *testing.T) {
	e := newRotationEnv(t)
	k2 := newBundleSK(t)
	// Rotation 1: root-1 enrolls root-2 and revokes itself.
	doc1 := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2}, "root-1")
	writeRotation(t, e.bundleDir, doc1, e.k.sign(doc1))

	// Wrong signature: root-1's signature over other bytes, then a
	// signature by a key the executor never trusted.
	writeRotation(t, e.bundleDir, doc1, e.k.sign([]byte("other")))
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("wrong signature: %v, want FailedPrecondition", err)
	}
	writeRotation(t, e.bundleDir, doc1, k2.sign(doc1))
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("self-signed new root: %v, want FailedPrecondition", err)
	}

	writeRotation(t, e.bundleDir, doc1, e.k.sign(doc1))
	rev, err := e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rootIDs(rev.NewRoots), ","); got != "root-1(revoked),root-2" || len(rev.Revoked) != 1 {
		t.Fatalf("new roots %s revoked %v", got, rev.Revoked)
	}
	if _, err := e.commit(t, rev.RotationDigest); err != nil {
		t.Fatal(err)
	}
	applied := e.rootState(t)

	// Replay of the applied rotation: the review refuses it, and a commit
	// of its digest finds nothing to commit.
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "already applied") {
		t.Fatalf("replay review: %v, want FailedPrecondition already applied", err)
	}
	if _, err := e.commit(t, rev.RotationDigest); status.Code(err) != codes.Aborted {
		t.Fatalf("replay commit: %v, want Aborted", err)
	}

	// Signature by the revoked root-1 on an otherwise valid next rotation.
	k3 := newBundleSK(t)
	doc2 := rotationDoc(t, 2, bundleSum(doc1), map[string]*bundleSK{"root-3": k3})
	writeRotation(t, e.bundleDir, doc2, e.k.sign(doc2))
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("revoked signer: %v, want FailedPrecondition", err)
	}

	// A fifth active root: root-2 plus four added.
	add := map[string]*bundleSK{}
	for _, id := range []string{"root-3", "root-4", "root-5", "root-6"} {
		add[id] = newBundleSK(t)
	}
	doc5 := rotationDoc(t, 2, bundleSum(doc1), add)
	writeRotation(t, e.bundleDir, doc5, k2.sign(doc5))
	_, err = e.review(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "active roots") {
		t.Fatalf("fifth active root: %v, want FailedPrecondition on active roots", err)
	}
	if _, err := e.commit(t, bundleSum(doc5)); status.Code(err) != codes.Aborted {
		t.Fatalf("fifth active root commit: %v, want Aborted", err)
	}

	if s := e.rootState(t); s.Sequence != applied.Sequence || s.Digest != applied.Digest || len(s.Roots) != len(applied.Roots) {
		t.Fatalf("a rejected rotation changed the root state: %+v, want %+v", s, applied)
	}
	// Still valid: root-2 signs the next rotation with three new roots
	// (four active).
	delete(add, "root-6")
	doc4 := rotationDoc(t, 2, bundleSum(doc1), add)
	writeRotation(t, e.bundleDir, doc4, k2.sign(doc4))
	rev, err = e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.commit(t, rev.RotationDigest); err != nil {
		t.Fatal(err)
	}
	if s := e.rootState(t); s.Sequence != 2 || len(s.Active()) != 4 {
		t.Fatalf("state %+v, want 4 active roots at sequence 2", s)
	}
}

// A missing rotation, or a symlinked one, is refused before verification.
func TestRootRotationMissingOrSymlinkRefused(t *testing.T) {
	e := newRotationEnv(t)
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), RootRotationFile) {
		t.Fatalf("missing rotation: %v", err)
	}
	k2 := newBundleSK(t)
	doc := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2})
	outside := filepath.Join(t.TempDir(), "doc")
	if err := os.WriteFile(outside, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	// Rotation files in the release directory itself are not read.
	if err := os.WriteFile(filepath.Join(e.bundleDir, RootRotationFile), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), RootRotationDirName) {
		t.Fatalf("rotation in release dir: %v", err)
	}
	if err := os.Remove(filepath.Join(e.bundleDir, RootRotationFile)); err != nil {
		t.Fatal(err)
	}
	rdir := rotationDir(e.bundleDir)
	if err := os.MkdirAll(rdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rdir, RootRotationFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rdir, RootRotationSignatureFile), e.k.sign(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("symlinked rotation: %v, want FailedPrecondition", err)
	}
	// An oversize document is refused by size.
	if err := os.Remove(filepath.Join(rdir, RootRotationFile)); err != nil {
		t.Fatal(err)
	}
	writeRotation(t, e.bundleDir, bytes.Repeat([]byte(" "), release.MaxRotation+1), e.k.sign(doc))
	if _, err := e.review(t); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("oversize rotation: %v, want FailedPrecondition", err)
	}
}

// The server role reaches neither method; the store is not touched.
func TestRootRotationServerRoleDenied(t *testing.T) {
	e := newRotationEnv(t)
	k2 := newBundleSK(t)
	doc := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2})
	writeRotation(t, e.bundleDir, doc, e.k.sign(doc))
	if got := MethodRoles()[pb.ExecutorService_ReviewRootRotation_FullMethodName]; len(got) != 1 || got[0] != peercred.RoleAdmin {
		t.Fatalf("review roles %v", got)
	}
	if got := MethodRoles()[pb.ExecutorService_CommitRootRotation_FullMethodName]; len(got) != 1 || got[0] != peercred.RoleAdmin {
		t.Fatalf("commit roles %v", got)
	}
	_, err := callAs(t, trustTestServerUID, pb.ExecutorService_ReviewRootRotation_FullMethodName, &pb.ReviewRootRotationRequest{}, e.s.ReviewRootRotation)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server review: %v", err)
	}
	_, err = callAs(t, trustTestServerUID, pb.ExecutorService_CommitRootRotation_FullMethodName,
		&pb.CommitRootRotationRequest{RotationDigest: bundleSum(doc)}, e.s.CommitRootRotation)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server commit: %v", err)
	}
	// Defense in depth: the handlers refuse a non-admin caller even past
	// the role table.
	wide := MethodRoles()
	wide[pb.ExecutorService_ReviewRootRotation_FullMethodName] = []peercred.Role{peercred.RoleServer}
	wide[pb.ExecutorService_CommitRootRotation_FullMethodName] = []peercred.Role{peercred.RoleServer}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{trustTestServerUID: {peercred.RoleServer}}, wide)
	ctx := peer.NewContext(t.Context(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: trustTestServerUID}})
	for _, m := range []string{pb.ExecutorService_ReviewRootRotation_FullMethodName, pb.ExecutorService_CommitRootRotation_FullMethodName} {
		_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: m}, func(ctx context.Context, _ any) (any, error) {
			if m == pb.ExecutorService_CommitRootRotation_FullMethodName {
				return e.s.CommitRootRotation(ctx, &pb.CommitRootRotationRequest{RotationDigest: bundleSum(doc)})
			}
			return e.s.ReviewRootRotation(ctx, &pb.ReviewRootRotationRequest{})
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s as server past the table: %v, want PermissionDenied", m, err)
		}
	}
	if _, err := e.s.ReviewRootRotation(t.Context(), &pb.ReviewRootRotationRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no caller: %v", err)
	}
	if s := e.rootState(t); s.Sequence != 0 || len(s.Roots) != 1 {
		t.Fatalf("root state changed: %+v", s)
	}
}

// Without a configured release directory the methods are Unimplemented.
func TestRootRotationUnconfigured(t *testing.T) {
	s := &Service{}
	_, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ReviewRootRotation_FullMethodName, &pb.ReviewRootRotationRequest{}, s.ReviewRootRotation)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("review: %v", err)
	}
	_, err = callAs(t, trustTestAdminUID, pb.ExecutorService_CommitRootRotation_FullMethodName,
		&pb.CommitRootRotationRequest{RotationDigest: trustTestDigest}, s.CommitRootRotation)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("commit: %v", err)
	}
}

// The applied and the rejected commit are audited with the admin UID,
// digest, sequence and fingerprints, never with key or signature bytes.
func TestRootRotationAuditHasNoKeyMaterial(t *testing.T) {
	e := newRotationEnv(t)
	k2 := newBundleSK(t)
	doc := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2})
	sig := e.k.sign(doc)
	writeRotation(t, e.bundleDir, doc, sig)
	rev, err := e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.commit(t, rev.RotationDigest); err != nil {
		t.Fatal(err)
	}
	// A rejected commit is audited too.
	if _, err := e.commit(t, rev.RotationDigest); err == nil {
		t.Fatal("replayed commit accepted")
	}
	log := e.audit.String()
	for _, want := range []string{`"kind":"root_rotation_applied"`, `"kind":"root_rotation_rejected"`, `"admin_uid":0`,
		rev.RotationDigest, release.Root{ID: "root-2", Key: k2.pub}.Fingerprint(), release.Root{ID: "root-1", Key: e.k.pub}.Fingerprint()} {
		if !strings.Contains(log, want) {
			t.Errorf("audit lacks %s:\n%s", want, log)
		}
	}
	forbidden := []string{
		base64.StdEncoding.EncodeToString(k2.pub.Marshal()),
		base64.StdEncoding.EncodeToString(e.k.pub.Marshal()),
		base64.StdEncoding.EncodeToString(k2.pub.Marshal())[:24],
		"SSH SIGNATURE",
		strings.Split(string(sig), "\n")[1][:24],
		"sk-ssh-ed25519@openssh.com AAAA",
	}
	for _, f := range forbidden {
		if strings.Contains(log, f) {
			t.Errorf("audit contains key or signature material %q", f)
		}
	}
}

// An interrupted built-in trust commit blocks the rotation commit: the
// pending record's recovery depends on the store generation.
func TestRootRotationRefusedWhileBuiltinCommitPending(t *testing.T) {
	e := newRotationEnv(t)
	k2 := newBundleSK(t)
	doc := rotationDoc(t, 1, release.ZeroDigest, map[string]*bundleSK{"root-2": k2})
	writeRotation(t, e.bundleDir, doc, e.k.sign(doc))
	rev, err := e.review(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.WritePending(e.storeDir, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.commit(t, rev.RotationDigest); status.Code(err) != codes.Aborted {
		t.Fatalf("commit with pending record: %v, want Aborted", err)
	}
	if s := e.rootState(t); s.Sequence != 0 {
		t.Fatalf("root state changed: %+v", s)
	}
}
