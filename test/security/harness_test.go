// SPDX-License-Identifier: AGPL-3.0-or-later

// Package security holds the acceptance tests for the security milestones.
// They run the real executor service over a real Unix socket with the real
// method-role table. These tests are protected: a change that weakens or
// deletes one needs human review (see AGENTS.md).
package security

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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
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

	testAction  = "patching.install_security"
	testVersion = "1.0.0"
)

var (
	script = []byte("#!/bin/sh\nset -eu\napt-get install --only-upgrade -y openssl\n")
	params = []byte(`{"packages":["openssl"]}`)
)

type harness struct {
	t        *testing.T
	logs     *syncBuffer
	socket   string
	client   pb.ExecutorServiceClient
	rp       virtualwebauthn.RelyingParty
	id       *identity
	db       *executordb.DB
	verifier *webauthnverify.Verifier
	svc      *executor.Service
	userKey  ssh.PublicKey // public half of the credRef key (H05)
	dataDir  string        // executor data directory, for restarts
	stopFn   func()
	once     sync.Once
}

// stop shuts the executor down and releases executor.db. It is safe to call
// more than once; tests call it explicitly before a simulated restart.
func (h *harness) stop() { h.once.Do(h.stopFn) }

type harnessOptions struct {
	uidRoles map[uint32][]peercred.Role
	mode     permit.Mode
	// dataDir holds executor.db. Empty means a fresh private directory; a
	// test simulates a restart by starting a second harness on the same
	// directory after stopping the first.
	dataDir string
	// identity reuses an authenticator and credential across a restart.
	identity *identity
	// untrusted skips the default risk data. By default the test script is
	// trusted as LOW for its action and both test hosts are LOW, so that the
	// proposed risk_class alone selects the approval path (the Milestone 0
	// tests rely on that). H01 tests set up their own risk data.
	untrusted bool
	// noCredential starts without the harness identity registered (H03).
	noCredential bool
}

// identity is a virtual authenticator with one registered credential.
type identity struct {
	dev  virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func newIdentity() *identity {
	id := &identity{dev: virtualwebauthn.NewAuthenticator(), cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)}
	id.dev.AddCredential(id.cred)
	return id
}

// privateDir returns a fresh 0700 directory, as the executor requires.
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// newHarness starts an executor in-process. By default the test's own UID
// holds both roles so that the full flow can be driven from one process; the
// production binary refuses that configuration (cmd/nebula-executor).
func newHarness(t *testing.T, o harnessOptions) *harness {
	t.Helper()
	if o.uidRoles == nil {
		o.uidRoles = map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer, peercred.RoleAdmin}}
	}
	if o.identity == nil {
		o.identity = newIdentity()
	}
	if o.dataDir == "" {
		o.dataDir = privateDir(t)
	}
	h := &harness{
		dataDir: o.dataDir,
		t:       t,
		rp:      virtualwebauthn.RelyingParty{Name: "Nebula", ID: rpID, Origin: origin},
		id:      o.identity,
	}

	db, err := executordb.Open(o.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	h.db = db

	// The SSH key lives with the data directory, so a restarted harness
	// (same dataDir) is the same Nebula instance to the test hosts.
	keysDir := filepath.Join(o.dataDir, "testkeys")
	if pemBytes, err := os.ReadFile(filepath.Join(keysDir, credRef+".key")); err == nil {
		k, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		h.userKey = signer.PublicKey()
	} else {
		if err := os.Mkdir(keysDir, 0o700); err != nil {
			t.Fatal(err)
		}
		h.userKey = writeEncryptedKey(t, keysDir, credRef)
	}

	h.logs = &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(h.logs, nil))
	// The harness identity is registered as if through H03 (unless a test
	// starts without credentials); credentials are then loaded from
	// executor.db exactly as the executor does.
	if !o.noCredential {
		err := db.AddWebAuthnCredential(executordb.WebAuthnCredential{
			ID: h.id.cred.ID, PublicKey: h.id.cred.Key.AttestationData(), UserName: "admin", CreatedBy: "test-harness",
		})
		if err != nil && !errors.Is(err, executordb.ErrCredentialExists) {
			t.Fatal(err)
		}
	}
	creds, err := executor.LoadCredentials(db, o.dataDir, log)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: db}, creds)
	if err != nil {
		t.Fatal(err)
	}
	if !o.untrusted {
		trustDefaults(t, db)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Mode: o.mode, Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db, Audit: executor.AuditLogger(log)})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{
		RPID: rpID, Origins: []string{origin}, Audit: executor.RegistrationAuditLogger(log),
	}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	h.verifier = verifier
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, log)
	svc.SetVaultParams(vault.Params{Time: 1, MemoryKiB: 64, Threads: 1})
	// Durable jobs on the test hosts (local processes) go below the data
	// directory, without sudo and systemd.
	svc.SetJobConfig(hostrun.JobConfig{JobRoot: filepath.Join(o.dataDir, "remote", "jobs"), RunRoot: filepath.Join(o.dataDir, "remote", "run")})
	h.svc = svc
	policy := peercred.NewPolicy(o.uidRoles, executor.MethodRoles())

	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.socket = filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: h.socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	srv := executor.NewGRPCServer(svc, policy, log)
	go func() { _ = srv.Serve(lis) }()
	h.stopFn = func() { srv.Stop(); _ = db.Close() }
	t.Cleanup(h.stop)

	conn, err := grpc.NewClient("unix://"+h.socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(executor.MaxMessageSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	h.client = pb.NewExecutorServiceClient(conn)
	return h
}

// trustDefaults writes the default risk data directly into executor.db.
func trustDefaults(t *testing.T, db *executordb.DB) {
	t.Helper()
	if err := db.TrustArtifact(executordb.TrustedArtifact{
		SHA256: hexSum(script), ActionID: testAction, ModuleVersion: testVersion,
		Risk: canonical.RiskLow, TrustedBy: "test-harness",
	}); err != nil {
		t.Fatal(err)
	}
	for h, fp := range map[string]string{"dockerflux": fpA, "strompi": fpB} {
		if _, err := db.SetHostCriticality(h, fp, canonical.RiskLow, "test-harness"); err != nil {
			t.Fatal(err)
		}
	}
}

func writeEncryptedKey(t *testing.T, dir, ref string) ssh.PublicKey {
	t.Helper()
	pub, k, err := ed25519.GenerateKey(rand.Reader)
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
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func (h *harness) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	h.t.Cleanup(cancel)
	return c
}

func (h *harness) sign(challenge []byte) []byte {
	return []byte(virtualwebauthn.CreateAssertionResponse(h.rp, h.id.dev, h.id.cred,
		virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: rpID}))
}

func (h *harness) unlock() {
	h.t.Helper()
	if _, err := h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)}); err != nil {
		h.t.Fatalf("unlock: %v", err)
	}
}

func (h *harness) openSession() {
	h.t.Helper()
	b, err := h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: h.sign(b.GetChallenge())}); err != nil {
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
		ActionId:       testAction,
		ModuleVersion:  testVersion,
		ArtifactSha256: hexSum(script),
		ParametersHash: ph,
		CredentialRefs: []string{credRef},
		RiskClass:      risk,
		StagePlanHash:  stageplan.SingleStageHash,
		ExpiryUnix:     time.Now().Add(time.Hour).Unix(),
		ResolvedTargets: []*pb.Target{
			{HostId: "dockerflux", HostKeyFingerprint: fpA},
			{HostId: "strompi", HostKeyFingerprint: fpB},
		},
	}
}

func (h *harness) propose(r *pb.ExecutionRequest) *pb.ProposeExecutionResponse {
	h.t.Helper()
	resp, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: params})
	if err != nil {
		h.t.Fatalf("propose: %v", err)
	}
	return resp
}

// approvedMedium proposes a MEDIUM request and approves it in the browser
// path (privileged session + WebAuthn assertion).
func (h *harness) approvedMedium() *pb.ProposeExecutionResponse {
	h.t.Helper()
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: p.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge()),
	}); err != nil {
		h.t.Fatalf("approve: %v", err)
	}
	return p
}

func run(digest, host, fp string) *pb.AuthorizeRunRequest {
	return &pb.AuthorizeRunRequest{
		ExecutionDigest: digest, HostId: host, HostKeyFingerprint: fp,
		ActionId: testAction, ModuleVersion: testVersion,
		Artifact: script, ParametersJson: params, CredentialRef: credRef,
	}
}

// syncBuffer collects executor log lines for assertions.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// requireHandshakeRejection asserts that the executor itself logged the
// rejection, so the test cannot pass on an unrelated connection failure.
func (h *harness) requireHandshakeRejection(uid uint32) {
	h.t.Helper()
	want := fmt.Sprintf(`"kind":"connection_rejected","uid":%d`, uid)
	if !strings.Contains(h.logs.String(), want) {
		h.t.Fatalf("executor did not log a handshake rejection for uid %d; log:\n%s", uid, h.logs.String())
	}
}

// wantRejectedPeer accepts both ways an unauthorized UID is turned away:
// closed during the handshake (Unavailable) or denied per method.
func wantRejectedPeer(t *testing.T, err error) {
	t.Helper()
	if c := status.Code(err); c != codes.Unavailable && c != codes.PermissionDenied {
		t.Fatalf("want connection rejected or permission denied, got %v", err)
	}
}

func wantCode(t *testing.T, err error, c codes.Code, contains string) {
	t.Helper()
	if status.Code(err) != c {
		t.Fatalf("want %v, got %v", c, err)
	}
	if contains != "" && !strings.Contains(status.Convert(err).Message(), contains) {
		t.Fatalf("want message containing %q, got %q", contains, status.Convert(err).Message())
	}
}
