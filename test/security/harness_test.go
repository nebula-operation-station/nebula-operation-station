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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	rpID       = "nebula.example.org"
	origin     = "https://nebula.example.org"
	passphrase = "a generated passphrase of at least 32 characters"
	credRef    = "nebula-default"
	fpA        = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB        = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

var (
	script = []byte("#!/bin/sh\nset -eu\napt-get install --only-upgrade -y openssl\n")
	params = []byte(`{"packages":["openssl"]}`)
)

type harness struct {
	t      *testing.T
	socket string
	client pb.ExecutorServiceClient
	rp     virtualwebauthn.RelyingParty
	dev    virtualwebauthn.Authenticator
	cred   virtualwebauthn.Credential
}

type harnessOptions struct {
	uidRoles map[uint32][]peercred.Role
	mode     permit.Mode
}

// newHarness starts an executor in-process. By default the test's own UID
// holds both roles so that the full flow can be driven from one process; the
// production binary refuses that configuration (cmd/nebula-executor).
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

	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}},
		[]webauthnverify.Credential{{ID: h.cred.ID, PublicKey: h.cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auth, err := permit.New(permit.Options{Mode: o.mode, Verifier: verifier, Audit: executor.AuditLogger(log)})
	if err != nil {
		t.Fatal(err)
	}
	svc := executor.NewService(auth, keyring.New(keysDir), log)
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
	t.Cleanup(srv.Stop)

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

func (h *harness) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	h.t.Cleanup(cancel)
	return c
}

func (h *harness) sign(challenge []byte) []byte {
	return []byte(virtualwebauthn.CreateAssertionResponse(h.rp, h.dev, h.cred,
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
		ActionId: "patching.install_security", ModuleVersion: "1.0.0",
		Artifact: script, ParametersJson: params, CredentialRef: credRef,
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
