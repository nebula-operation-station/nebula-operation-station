// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the executor client: harness (in-process executor on a real
// Unix socket, pattern copied from test/security/harness_test.go which is
// protected and must not be imported) plus the acceptance tests for the
// verified dialing (AC1) and the per-call timeouts (AC2). The error-mapping
// and end-to-end typed-error tests live in client_errors_test.go.

package executorclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	rpID       = "nebula.example.org"
	origin     = "https://nebula.example.org"
	passphrase = "a generated passphrase of at least 32 characters"
	credRef    = "nebula-default"
	fpA        = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB        = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	// unknownDigest is a parseable digest with no permit behind it.
	unknownDigest = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	script = []byte("#!/bin/sh\nset -eu\napt-get install --only-upgrade -y openssl\n")
	params = []byte(`{"packages":["openssl"]}`)
)

// harness runs the real executor service in-process on a real Unix socket
// with the real method-role table.
type harness struct {
	t      *testing.T
	socket string
	rp     virtualwebauthn.RelyingParty
	dev    virtualwebauthn.Authenticator
	cred   virtualwebauthn.Credential
}

type harnessOptions struct {
	uidRoles map[uint32][]peercred.Role
}

// newHarness starts an executor in-process. By default the test's own UID
// holds both roles so that the full flow can be driven from one process.
func newHarness(t *testing.T, o harnessOptions) *harness {
	t.Helper()
	if o.uidRoles == nil {
		o.uidRoles = map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer, peercred.RoleAdmin}}
	}
	h := &harness{
		t:    t,
		rp:   virtualwebauthn.RelyingParty{Name: "Nebula", ID: rpID, Origin: origin},
		dev:  virtualwebauthn.NewAuthenticator(),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	h.dev.AddCredential(h.cred)

	keysDir := t.TempDir()
	if err := os.Chmod(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeEncryptedKey(t, keysDir, credRef)

	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: db},
		[]webauthnverify.Credential{{ID: h.cred.ID, PublicKey: h.cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	// The executor's own risk data: the test script is trusted as LOW and
	// both hosts are LOW, so the proposed risk_class decides the approval
	// path as in Milestone 0. test/security covers the risk floor itself.
	trustForTests(t, db)
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: verifier, Store: db, RiskPolicy: risk})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: rpID, Origins: []string{origin}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, discardLogger())

	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.socket = filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: h.socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(o.uidRoles, executor.MethodRoles())
	srv := executor.NewGRPCServer(svc, policy, discardLogger())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return h
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func trustForTests(t *testing.T, db *executordb.DB) {
	t.Helper()
	sum := sha256.Sum256(script)
	if err := db.TrustArtifact(executordb.TrustedArtifact{
		SHA256: hex.EncodeToString(sum[:]), ActionID: "patching.install_security", ModuleVersion: "1.0.0",
		Risk: canonical.RiskLow, TrustedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	for h, fp := range map[string]string{"dockerflux": fpA, "strompi": fpB} {
		if err := db.SetHostCriticality(h, fp, canonical.RiskLow, "test"); err != nil {
			t.Fatal(err)
		}
	}
}

func writeEncryptedKey(t *testing.T, dir, ref string) {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(k, ref, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ref+".key"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

// client creates a verified client for the harness socket.
func (h *harness) client(mut ...func(*Options)) *Client {
	h.t.Helper()
	o := Options{SocketPath: h.socket, ExecutorUser: currentUser(h.t)}
	for _, m := range mut {
		m(&o)
	}
	c, err := New(h.ctx(), o)
	if err != nil {
		h.t.Fatalf("new client: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func (h *harness) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	h.t.Cleanup(cancel)
	return c
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// currentUser returns a user name that resolves to the test's own UID.
func currentUser(t *testing.T) string {
	t.Helper()
	if u, err := user.Current(); err == nil && u.Username != "" {
		if _, err := peercred.LookupUID(u.Username); err == nil {
			return u.Username
		}
	}
	return strconv.Itoa(os.Getuid())
}

// otherUser returns a user name that is guaranteed not to be the test's own.
func otherUser(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		return "root"
	}
	return "daemon"
}

func (h *harness) sign(challenge []byte) []byte {
	return []byte(virtualwebauthn.CreateAssertionResponse(h.rp, h.dev, h.cred,
		virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: rpID}))
}

func (h *harness) unlock(c *Client) {
	h.t.Helper()
	if _, err := c.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
		h.t.Fatalf("unlock: %v", err)
	}
}

func (h *harness) openSession(c *Client) {
	h.t.Helper()
	b, err := c.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := c.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: h.sign(b.GetChallenge())}); err != nil {
		h.t.Fatalf("open session: %v", err)
	}
}

var execCounter atomic.Int64

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func (h *harness) request(risk pb.RiskClass) *pb.ExecutionRequest {
	h.t.Helper()
	ph, err := canonical.HashParameters(params)
	if err != nil {
		h.t.Fatal(err)
	}
	return &pb.ExecutionRequest{
		ExecutionId:    fmt.Sprintf("00000000-0000-4000-8000-%012d", execCounter.Add(1)),
		ActionId:       "patching.install_security",
		ModuleVersion:  "1.0.0",
		ArtifactSha256: hexSum(script),
		ParametersHash: ph,
		CredentialRefs: []string{credRef},
		RiskClass:      risk,
		StagePlanHash:  strings.Repeat("c", 64),
		ExpiryUnix:     time.Now().Add(time.Hour).Unix(),
		ResolvedTargets: []*pb.Target{
			{HostId: "dockerflux", HostKeyFingerprint: fpA},
			{HostId: "strompi", HostKeyFingerprint: fpB},
		},
	}
}

func (h *harness) propose(c *Client, r *pb.ExecutionRequest) (*pb.ProposeExecutionResponse, error) {
	return c.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: params})
}

func run(digest, host, fp string) *pb.AuthorizeRunRequest {
	return &pb.AuthorizeRunRequest{
		ExecutionDigest: digest, HostId: host, HostKeyFingerprint: fp,
		ActionId: "patching.install_security", ModuleVersion: "1.0.0",
		Artifact: script, ParametersJson: params, CredentialRef: credRef,
	}
}

// --- Acceptance criterion 1: the client implements the generated
// interface and dials only through the verified peercred path. ---

func TestImplementsGeneratedInterface(t *testing.T) {
	var _ pb.ExecutorServiceClient = (*Client)(nil)
}

func TestNewDialsVerifiedSocket(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	st, err := c.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	if st.GetUnlocked() {
		t.Fatal("executor should start locked")
	}
}

func TestForeignSocketRefused(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	o := Options{SocketPath: h.socket, ExecutorUser: otherUser(t)}
	_, err := New(h.ctx(), o)
	if err == nil {
		t.Fatal("new client succeeded against a socket served by the wrong user")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestNewRefusesMissingSocket(t *testing.T) {
	o := Options{SocketPath: filepath.Join(t.TempDir(), "nope.sock"), ExecutorUser: currentUser(t)}
	_, err := New(testCtx(t), o)
	if err == nil {
		t.Fatal("new client succeeded against a missing socket")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestNewRequiresValidOptions(t *testing.T) {
	u := currentUser(t)
	for name, o := range map[string]Options{
		"empty socket":    {ExecutorUser: u},
		"relative socket": {SocketPath: "executor.sock", ExecutorUser: u},
		"empty user":      {SocketPath: "/tmp/executor.sock"},
		"unknown user":    {SocketPath: "/tmp/executor.sock", ExecutorUser: "no-such-user-424242"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(testCtx(t), o); err == nil {
				t.Fatal("new client succeeded with invalid options")
			}
		})
	}
}

// --- Acceptance criterion 2: per-call timeouts. ---

func TestDefaultTimeoutConstants(t *testing.T) {
	if DefaultCallTimeout != 10*time.Second {
		t.Errorf("DefaultCallTimeout = %v, want 10s", DefaultCallTimeout)
	}
	if AuthorizeRunCallTimeout != 60*time.Second {
		t.Errorf("AuthorizeRunCallTimeout = %v, want 60s", AuthorizeRunCallTimeout)
	}
}

// sleepingService is a fake executor that answers GetStatus immediately and
// delays the other methods, to exercise the client's per-call timeouts.
type sleepingService struct {
	pb.UnimplementedExecutorServiceServer
	proposeDelay   time.Duration
	authorizeDelay time.Duration
}

func (s *sleepingService) GetStatus(ctx context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, ctx.Err()
}

func (s *sleepingService) ProposeExecution(ctx context.Context, _ *pb.ProposeExecutionRequest) (*pb.ProposeExecutionResponse, error) {
	if err := waitDelay(ctx, s.proposeDelay); err != nil {
		return nil, err
	}
	return &pb.ProposeExecutionResponse{}, nil
}

func (s *sleepingService) AuthorizeRun(ctx context.Context, _ *pb.AuthorizeRunRequest) (*pb.AuthorizeRunResponse, error) {
	if err := waitDelay(ctx, s.authorizeDelay); err != nil {
		return nil, err
	}
	return &pb.AuthorizeRunResponse{Authorized: true}, nil
}

func waitDelay(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startFake serves svc on a real peercred socket with the real role table.
func startFake(t *testing.T, svc pb.ExecutorServiceServer) string {
	t.Helper()
	uidRoles := map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer, peercred.RoleAdmin}}
	policy := peercred.NewPolicy(uidRoles, executor.MethodRoles())
	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(peercred.Credentials{Policy: policy}),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(nil)),
		grpc.StreamInterceptor(policy.StreamInterceptor(nil)),
	)
	pb.RegisterExecutorServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return socket
}

func TestPerCallTimeoutFires(t *testing.T) {
	socket := startFake(t, &sleepingService{proposeDelay: 500 * time.Millisecond})
	c, err := New(testCtx(t), Options{SocketPath: socket, ExecutorUser: currentUser(t), DefaultTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()
	start := time.Now()
	_, err = c.ProposeExecution(testCtx(t), &pb.ProposeExecutionRequest{})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("want ErrDeadlineExceeded, got %v", err)
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("call took %v; the 100ms per-call timeout did not fire", elapsed)
	}
}

func TestAuthorizeRunUsesLongerTimeout(t *testing.T) {
	socket := startFake(t, &sleepingService{authorizeDelay: 300 * time.Millisecond})
	u := currentUser(t)

	long, err := New(testCtx(t), Options{SocketPath: socket, ExecutorUser: u, DefaultTimeout: 100 * time.Millisecond, AuthorizeRunTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer long.Close()
	if _, err := long.AuthorizeRun(testCtx(t), &pb.AuthorizeRunRequest{}); err != nil {
		t.Fatalf("authorize run within its 2s timeout: %v", err)
	}

	short, err := New(testCtx(t), Options{SocketPath: socket, ExecutorUser: u, DefaultTimeout: 100 * time.Millisecond, AuthorizeRunTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer short.Close()
	if _, err := short.AuthorizeRun(testCtx(t), &pb.AuthorizeRunRequest{}); !errors.Is(err, ErrDeadlineExceeded) {
		t.Fatalf("want ErrDeadlineExceeded, got %v", err)
	}
}

func TestDefaultAuthorizeRunTimeout(t *testing.T) {
	socket := startFake(t, &sleepingService{authorizeDelay: 200 * time.Millisecond})
	c, err := New(testCtx(t), Options{SocketPath: socket, ExecutorUser: currentUser(t)})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer c.Close()
	if _, err := c.AuthorizeRun(testCtx(t), &pb.AuthorizeRunRequest{}); err != nil {
		t.Fatalf("authorize run within the default 10s timeout: %v", err)
	}
}
