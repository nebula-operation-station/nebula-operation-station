// SPDX-License-Identifier: AGPL-3.0-or-later

package main

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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	wireServerUID = 101
	wireAdminUID  = 1000
)

// testRoot is a software stand-in for the FIDO release root, test-only.
type testRoot struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newTestRoot(t *testing.T) *testRoot {
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
	return &testRoot{priv: priv, pub: k}
}

func (k *testRoot) anchors() []release.Anchor {
	return []release.Anchor{{ID: "root-1", Key: k.pub}, {ID: "root-2"}}
}

// sign produces an SSHSIG over msg as the FIDO release root would.
func (k *testRoot) sign(msg []byte) []byte {
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

func canon(t *testing.T, v any) []byte {
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

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func tarOf(t *testing.T, files map[string][]byte) []byte {
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

// writeBundle writes a signed release bundle with one built-in module
// "docker" 1.0.0 holding one LOW action into dir.
func writeBundle(t *testing.T, k *testRoot, dir string) {
	t.Helper()
	script := []byte("echo restart\n")
	l := modulelock.Lock{Format: modulelock.Format, Name: "docker", Version: "1.0.0", Title: "Built-in",
		Actions: map[string]modulelock.Action{"restart": {Title: "restart", Script: "actions/restart.sh", SHA256: sum(script),
			Risk: "LOW", TimeoutS: 60, Params: []prelude.Param{}, Secrets: []string{}, Declares: []string{}}}}
	mod := tarOf(t, map[string][]byte{"actions/restart.sh": script, release.LockFile: canon(t, l)})
	bundle := tarOf(t, map[string][]byte{"modules/docker/1.0.0.tar": mod})
	man := canon(t, map[string]any{"format": release.ManifestFormat, "release_version": "2026.11.0",
		"artifacts": []any{map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": sum(bundle)}},
		"modules":   []any{map[string]any{"name": "docker", "version": "1.0.0", "size": len(mod), "sha256": sum(mod)}}})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{release.ManifestFile: man, release.SignatureFile: k.sign(man), release.BundleArtifact: bundle} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openDB(t *testing.T, dir string) *executordb.DB {
	t.Helper()
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// call runs h through the executor's real peercred role table as uid.
func call[Req, Resp any](t *testing.T, uid uint32, method string, req Req, h func(context.Context, Req) (Resp, error)) (Resp, error) {
	t.Helper()
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		wireServerUID: {peercred.RoleServer},
		wireAdminUID:  {peercred.RoleAdmin},
	}, executor.MethodRoles())
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
	var zero Resp
	out, err := policy.UnaryInterceptor(nil)(ctx, req, &grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, r any) (any, error) { return h(ctx, r.(Req)) })
	if err != nil {
		return zero, err
	}
	return out.(Resp), nil
}

func trustStatus(t *testing.T, s *executor.Service) pb.BuiltinTrustState {
	t.Helper()
	out, err := call(t, wireServerUID, pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName,
		&pb.GetBuiltinTrustStatusRequest{}, s.GetBuiltinTrustStatus)
	if err != nil {
		t.Fatal(err)
	}
	return out.GetState()
}

// Without wiring the status RPC always answers UNAVAILABLE (the web
// banner's "unreachable"); that was production before this change.
func TestUnwiredBuiltinTrustIsUnavailable(t *testing.T) {
	if got := trustStatus(t, &executor.Service{}); got != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE {
		t.Fatalf("status = %v", got)
	}
}

// Wired with the executor's store, bundle directory and executor.db, the
// server sees UNTRUSTED for a fresh release, the admin can review and
// commit it, the server then sees TRUSTED, and the committed built-in
// counts for the executor's risk policy.
func TestWireBuiltinTrustServesStatusAndRisk(t *testing.T) {
	dir := privateTempDir(t)
	k := newTestRoot(t)
	bundleDir := filepath.Join(t.TempDir(), "release")
	writeBundle(t, k, bundleDir)
	db := openDB(t, dir)
	const host, fp = "web-1", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := db.SetHostCriticality(host, fp, canonical.RiskLow, "admin:uid1000"); err != nil {
		t.Fatal(err)
	}
	s := &executor.Service{}
	now := func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }
	if err := wireBuiltinTrust(s, filepath.Join(dir, builtinTrustDirName), bundleDir, k.anchors(), now, db); err != nil {
		t.Fatal(err)
	}
	if got := trustStatus(t, s); got != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED {
		t.Fatalf("status before commit = %v, want UNTRUSTED", got)
	}
	rev, err := call(t, wireAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName,
		&pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if err != nil {
		t.Fatal(err)
	}
	art := rev.GetModules()[0].GetActions()[0].GetNewArtifactSha256()
	policy, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	req := canonical.Request{ActionID: "docker.restart", ModuleVersion: "1.0.0", ArtifactSHA256: art}
	targets := []canonical.Target{{HostID: host, HostKeyFingerprint: fp}}
	if r, _, err := policy.MinimumRisk(req, targets); err != nil || r != canonical.RiskHigh {
		t.Fatalf("floor before commit = %v, %v; want HIGH", r, err)
	}
	if _, err := call(t, wireAdminUID, pb.ExecutorService_CommitBuiltinTrust_FullMethodName,
		&pb.CommitBuiltinTrustRequest{ManifestDigest: rev.GetManifestDigest()}, s.CommitBuiltinTrust); err != nil {
		t.Fatal(err)
	}
	if got := trustStatus(t, s); got != pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED {
		t.Fatalf("status after commit = %v, want TRUSTED", got)
	}
	if r, _, err := policy.MinimumRisk(req, targets); err != nil || r != canonical.RiskLow {
		t.Fatalf("floor after commit = %v, %v; want LOW", r, err)
	}
}

// Production setup uses <data-dir>/trust by default and the compiled
// release anchors: the store is bootstrapped at startup and the admin
// review reaches the transaction (a missing bundle is a precondition
// failure, not "not configured").
func TestSetupBuiltinTrustDefaultStore(t *testing.T) {
	dir := privateTempDir(t)
	s := &executor.Service{}
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	setupBuiltinTrust(s, dir, "", filepath.Join(t.TempDir(), "no-bundle"), openDB(t, dir), log)
	if _, err := os.Stat(filepath.Join(dir, builtinTrustDirName, "index.json")); err != nil {
		t.Fatalf("store not bootstrapped under the data dir: %v", err)
	}
	_, err := call(t, wireAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName,
		&pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("review err = %v, want FailedPrecondition (wired, bundle missing)", err)
	}
}

// A store that cannot be opened leaves built-in trust unwired and the
// executor running; the failure is logged.
func TestSetupBuiltinTrustFailureIsLoggedNotFatal(t *testing.T) {
	dir := privateTempDir(t)
	store := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(store, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	s := &executor.Service{}
	setupBuiltinTrust(s, dir, store, filepath.Join(dir, "bundle"), openDB(t, dir), slog.New(slog.NewJSONHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("built-in trust unavailable")) {
		t.Fatalf("no warning logged: %s", buf.String())
	}
	_, err := call(t, wireAdminUID, pb.ExecutorService_ReviewBuiltinTrust_FullMethodName,
		&pb.ReviewBuiltinTrustRequest{}, s.ReviewBuiltinTrust)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("review err = %v, want Unimplemented", err)
	}
}
