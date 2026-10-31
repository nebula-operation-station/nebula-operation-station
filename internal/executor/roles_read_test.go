// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

func TestReadGrantMethodRoles(t *testing.T) {
	methods := map[string][]peercred.Role{
		pb.ExecutorService_ProposeReadGrant_FullMethodName:      {peercred.RoleServer},
		pb.ExecutorService_CommitReadGrant_FullMethodName:       {peercred.RoleServer},
		pb.ExecutorService_ListPendingReadGrants_FullMethodName: {peercred.RoleAdmin},
		pb.ExecutorService_ApproveReadGrantCLI_FullMethodName:   {peercred.RoleAdmin},
		pb.ExecutorService_ListReadGrants_FullMethodName:        {peercred.RoleServer, peercred.RoleAdmin},
		pb.ExecutorService_RevokeReadGrant_FullMethodName:       {peercred.RoleServer, peercred.RoleAdmin},
		pb.ExecutorService_RunReadGrant_FullMethodName:          {peercred.RoleServer},
	}
	roles := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector, peercred.Role("discovery")}
	uids := map[uint32][]peercred.Role{}
	for i, r := range roles {
		uids[uint32(i+1)] = []peercred.Role{r}
	}
	policy := peercred.NewPolicy(uids, MethodRoles())
	for method, want := range methods {
		t.Run(method, func(t *testing.T) {
			got := MethodRoles()[method]
			if len(got) != len(want) {
				t.Errorf("roles = %v, want %v", got, want)
			}
			for i, role := range roles {
				allowed := false
				for _, r := range want {
					allowed = allowed || r == role
				}
				if _, ok := policy.Allowed(uint32(i+1), method); ok != allowed {
					t.Errorf("role %s allowed=%v, want %v", role, ok, allowed)
				}
			}
			if _, ok := policy.Allowed(999, method); ok {
				t.Error("unknown UID allowed")
			}
		})
	}
}

func validReadRPCRequest() *pb.RunReadGrantRequest {
	return &pb.RunReadGrantRequest{
		GrantId:   "00000000-0000-4000-8000-0000000000aa",
		Trigger:   pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND,
		Run:       &pb.AuthorizeRunRequest{HostId: "host", HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), ActionId: "core.facts", ModuleVersion: "1.0.0", Artifact: []byte("#!/bin/sh\necho ok\n"), ParametersJson: []byte(`{}`), CredentialRef: "cred"},
		Endpoints: []string{"127.0.0.1:22"}, TimeoutSeconds: 1,
	}
}

func TestRunReadGrantRejectsMalformedBeforeAuthority(t *testing.T) {
	tests := map[string]func(*pb.RunReadGrantRequest){
		"missing grant":       func(r *pb.RunReadGrantRequest) { r.GrantId = "" },
		"invalid grant":       func(r *pb.RunReadGrantRequest) { r.GrantId = "../grant" },
		"oversize grant":      func(r *pb.RunReadGrantRequest) { r.GrantId = strings.Repeat("a", 1000) },
		"unspecified trigger": func(r *pb.RunReadGrantRequest) { r.Trigger = 0 },
		"unknown trigger":     func(r *pb.RunReadGrantRequest) { r.Trigger = 99 },
		"missing run":         func(r *pb.RunReadGrantRequest) { r.Run = nil },
		"permit digest":       func(r *pb.RunReadGrantRequest) { r.Run.ExecutionDigest = strings.Repeat("0", 64) },
		"bad host":            func(r *pb.RunReadGrantRequest) { r.Run.HostId = "bad host" },
		"bad pin":             func(r *pb.RunReadGrantRequest) { r.Run.HostKeyFingerprint = "SHA256:short" },
		"bad action":          func(r *pb.RunReadGrantRequest) { r.Run.ActionId = "shell" },
		"bad version":         func(r *pb.RunReadGrantRequest) { r.Run.ModuleVersion = "latest" },
		"bad credential":      func(r *pb.RunReadGrantRequest) { r.Run.CredentialRef = "../cred" },
		"missing artifact":    func(r *pb.RunReadGrantRequest) { r.Run.Artifact = nil },
		"oversize artifact":   func(r *pb.RunReadGrantRequest) { r.Run.Artifact = make([]byte, permit.MaxArtifactSize+1) },
		"bad parameters":      func(r *pb.RunReadGrantRequest) { r.Run.ParametersJson = []byte(`{"a":1,"a":2}`) },
		"invalid UTF8": func(r *pb.RunReadGrantRequest) {
			r.Run.ParametersJson = []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
		},
		"oversize parameters": func(r *pb.RunReadGrantRequest) { r.Run.ParametersJson = make([]byte, canonical.MaxParametersSize+1) },
		"missing endpoints":   func(r *pb.RunReadGrantRequest) { r.Endpoints = nil },
		"too many endpoints":  func(r *pb.RunReadGrantRequest) { r.Endpoints = make([]string, sshtransport.MaxEndpoints+1) },
		"bad endpoint":        func(r *pb.RunReadGrantRequest) { r.Endpoints = []string{"bad endpoint"} },
		"oversize endpoint":   func(r *pb.RunReadGrantRequest) { r.Endpoints = []string{strings.Repeat("a", 1025)} },
		"oversize timeout":    func(r *pb.RunReadGrantRequest) { r.TimeoutSeconds = 601 },
	}
	s := &Service{} // Validation must finish before touching authority, keys or storage.
	if _, err := s.RunReadGrant(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil: %v", err)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := validReadRPCRequest()
			mutate(r)
			_, err := s.RunReadGrant(context.Background(), r)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("want InvalidArgument, got %v", err)
			}
		})
	}
}

func TestReadGrantRejectsMalformedApprovalAndRevocation(t *testing.T) {
	s := &Service{}
	ctx := context.Background()
	digest := strings.Repeat("a", 64)
	for _, r := range []*pb.CommitReadGrantRequest{nil, {}, {GrantDigest: "bad", AssertionJson: []byte(`{}`)}, {GrantDigest: digest}, {GrantDigest: digest, AssertionJson: []byte(`broken`)}, {GrantDigest: digest, AssertionJson: []byte{0xff}}, {GrantDigest: digest, AssertionJson: make([]byte, webauthnverify.MaxAssertionSize+1)}} {
		if _, err := s.CommitReadGrant(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("approval: %v", err)
		}
	}
	for _, r := range []*pb.ApproveReadGrantCLIRequest{nil, {}, {GrantDigest: strings.Repeat("A", 64)}, {GrantDigest: strings.Repeat("a", 65)}} {
		if _, err := s.ApproveReadGrantCLI(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("CLI approval: %v", err)
		}
	}
	for _, r := range []*pb.RevokeReadGrantRequest{nil, {}, {GrantId: "../grant"}, {GrantId: strings.Repeat("a", 1000)}} {
		if _, err := s.RevokeReadGrant(ctx, r); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("revocation: %v", err)
		}
	}
}

func TestReadGrantRejectsMalformedProposalBeforeStorage(t *testing.T) {
	s := &Service{}
	for name, raw := range map[string][]byte{"empty": nil, "bad JSON": []byte(`broken`), "invalid UTF8": {0xff}, "unknown fields": []byte(`{"unknown":true}`), "duplicate fields": []byte(`{"grant":"read-grant-v2","grant":"read-grant-v2"}`), "oversize": make([]byte, permit.MaxReadGrantDocSize+1)} {
		t.Run(name, func(t *testing.T) {
			_, err := s.ProposeReadGrant(context.Background(), &pb.ProposeReadGrantRequest{GrantJson: raw})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("want InvalidArgument, got %v", err)
			}
		})
	}
	if _, err := s.ProposeReadGrant(context.Background(), nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil: %v", err)
	}
}

func TestReadGrantUnknownFieldsAreBounded(t *testing.T) {
	r := &pb.ListReadGrantsRequest{}
	// Unknown protobuf fields are covered by the same transport bound.
	r.ProtoReflect().SetUnknown(append([]byte{0x0a, 0x00}, make([]byte, MaxMessageSize)...))
	s := &Service{}
	if _, err := s.ListReadGrants(context.Background(), r); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversize: %v", err)
	}
}

// readRPCEnv uses real durable storage, risk policy and WebAuthn verification.
func readRPCEnv(t *testing.T, mode permit.Mode) (*reconcileEnv, func([]byte, bool) []byte, []byte) {
	t.Helper()
	e := newReconcileEnv(t)
	e.pin(mustReadSigner(t))
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	dev := virtualwebauthn.NewAuthenticator()
	dev.AddCredential(cred)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, []webauthnverify.Credential{{ID: cred.ID, PublicKey: cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{Mode: mode, Verifier: v, Store: e.db, RiskPolicy: risk, Schedules: e.db, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.reg, err = webauthnreg.New(webauthnreg.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Now: e.clock.Now}, v, e.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("#!/bin/sh\necho ok\n")
	sum := sha256.Sum256(artifact)
	if err := e.db.TrustArtifact(executordb.TrustedArtifact{SHA256: hex.EncodeToString(sum[:]), ActionID: "core.facts", ModuleVersion: "1.0.0", Risk: canonical.RiskLow, TrustedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.SetHostCriticality(e.host, e.fp, canonical.RiskLow, "test"); err != nil {
		t.Fatal(err)
	}
	ph, err := canonical.HashParameters([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	doc := permit.ReadGrantDoc{Grant: permit.ReadGrantFormat, ID: validReadRPCRequest().GrantId, Issuer: "test", CreatedUnix: e.clock.Now().Unix(), ExpiryUnix: e.clock.Now().Add(7 * 24 * time.Hour).Unix(), Trigger: permit.TriggerBoth, RateProfile: "ordinary", MinIntervalS: 900, RunBudget: 2,
		Actions: []permit.ReadGrantAction{{ActionID: "core.facts", ModuleVersion: "1.0.0", ArtifactSHA256: hex.EncodeToString(sum[:]), ParametersHash: ph}},
		Targets: []canonical.Target{{HostID: e.host, HostKeyFingerprint: e.fp}}, Credentials: []permit.ReadGrantCredential{{HostID: e.host, CredentialRef: "cred", CredentialVersion: ssh.FingerprintSHA256(e.userPub)}}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(challenge []byte, uv bool) []byte {
		dev.Options.UserNotVerified = !uv
		return []byte(virtualwebauthn.CreateAssertionResponse(virtualwebauthn.RelyingParty{Name: "Nebula", ID: "reconcile.test", Origin: "https://reconcile.test"}, dev, cred, virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: "reconcile.test"}))
	}
	return e, sign, raw
}

func mustReadSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func readRPCClient(t *testing.T, s *Service, role peercred.Role) pb.ExecutorServiceClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "read.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {role}}, MethodRoles())
	srv := NewGRPCServer(s, policy, s.log)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Stop(); _ = ln.Close() })
	conn, err := grpc.NewClient("passthrough:///executor", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return peercred.DialVerified(ctx, sock, uint32(os.Getuid()))
	}), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(MaxMessageSize+1024), grpc.MaxCallRecvMsgSize(MaxResponseSize)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewExecutorServiceClient(conn)
}

func TestReadGrantRPCRequiresUserVerification(t *testing.T) {
	for _, uv := range []bool{false, true} {
		t.Run(fmt.Sprint("UV=", uv), func(t *testing.T) {
			e, sign, raw := readRPCEnv(t, permit.ModeStandard)
			client := readRPCClient(t, e.svc, peercred.RoleServer)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pg, err := client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
			if err != nil {
				t.Fatal(err)
			}
			if pg.ApprovalRequirement != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED || len(pg.Challenge) == 0 || len(pg.RequestOptionsJson) == 0 || !bytes.Equal(pg.CanonicalGrant, e.svc.auth.PendingReadGrants()[0].Canonical) {
				t.Fatalf("incomplete approval: %v", pg)
			}
			if _, err := client.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: pg.GrantDigest}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("server approved: %v", err)
			}
			if _, err := client.ListPendingReadGrants(ctx, &pb.ListPendingReadGrantsRequest{}); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("server accessed local review: %v", err)
			}
			approval := &pb.CommitReadGrantRequest{GrantDigest: pg.GrantDigest, AssertionJson: sign(pg.Challenge, uv)}
			g, err := client.CommitReadGrant(ctx, approval)
			if uv {
				if err != nil || g.GetGrant().GetGrantDigest() != pg.GrantDigest {
					t.Fatalf("verified approval: %v %v", g, err)
				}
			} else if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("missing UV: %v", err)
			}
			if _, err := client.CommitReadGrant(ctx, approval); status.Code(err) != codes.NotFound {
				t.Fatalf("replayed approval: %v", err)
			}
			grants, err := client.ListReadGrants(ctx, &pb.ListReadGrantsRequest{})
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if uv {
				want = 1
			}
			if len(grants.Grants) != want {
				t.Fatalf("grants = %d, want %d", len(grants.Grants), want)
			}
			if active, _ := e.svc.auth.Session(); active {
				t.Fatal("grant approval opened a privileged session")
			}
		})
	}
}

func TestReadGrantRPCHardenedApprovalIsAdminOnly(t *testing.T) {
	e, _, raw := readRPCEnv(t, permit.ModeHardened)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := readRPCClient(t, e.svc, peercred.RoleServer)
	admin := readRPCClient(t, e.svc, peercred.RoleAdmin)
	pg, err := server.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		t.Fatal(err)
	}
	if pg.ApprovalRequirement != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY || len(pg.Challenge) != 0 {
		t.Fatalf("hardened challenge: %v", pg)
	}
	if _, err := server.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: pg.GrantDigest, AssertionJson: []byte(`{}`)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("browser approved hardened grant: %v", err)
	}
	pending, err := admin.ListPendingReadGrants(ctx, &pb.ListPendingReadGrantsRequest{})
	if err != nil || len(pending.GetGrants()) != 1 || !bytes.Equal(pending.Grants[0].CanonicalGrant, pg.CanonicalGrant) {
		t.Fatalf("admin review: %v %v", pending, err)
	}
	approved, err := admin.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: pg.GrantDigest})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(approved.Grant.ApprovedBy, "cli:") {
		t.Fatal("missing local approver")
	}
	if _, err := admin.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin proposal: %v", err)
	}
	if _, err := admin.RunReadGrant(ctx, validReadRPCRequest()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("admin read dispatch: %v", err)
	}
	if _, err := admin.RevokeReadGrant(ctx, &pb.RevokeReadGrantRequest{GrantId: approved.Grant.GrantId}); err != nil {
		t.Fatal(err)
	}
}

func TestReadGrantRPCTriggersShareBudgetAndRevocation(t *testing.T) {
	for _, first := range []pb.ReadGrantTrigger{pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED, pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND} {
		t.Run(first.String(), func(t *testing.T) {
			e, sign, raw := readRPCEnv(t, permit.ModeStandard)
			client := readRPCClient(t, e.svc, peercred.RoleServer)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pg, err := client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: pg.GrantDigest, AssertionJson: sign(pg.Challenge, true)}); err != nil {
				t.Fatal(err)
			}
			r := validReadRPCRequest()
			r.Run.HostId = e.host
			r.Run.HostKeyFingerprint = e.fp
			r.Endpoints = []string{closedAddr(t)}
			r.Trigger = first
			// A failed connection consumes a reservation; the other trigger cannot retry for free.
			one, err := client.RunReadGrant(ctx, r)
			if err != nil || one.GetExecutionId() == "" || one.GetResult().GetClass() != classNetworkUnreachable {
				t.Fatalf("first read: %v %v", one, err)
			}
			other := pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED
			if first == other {
				other = pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND
			}
			r.Trigger = other
			if _, err := client.RunReadGrant(ctx, r); status.Code(err) != codes.ResourceExhausted || !strings.HasPrefix(status.Convert(err).Message(), string(permit.CodeLeaseBudget)) {
				t.Fatalf("trigger bypassed interval: %v", err)
			}
			e.clock.Add(15 * time.Minute)
			two, err := client.RunReadGrant(ctx, r)
			if err != nil || two.GetExecutionId() == one.GetExecutionId() {
				t.Fatalf("second read: %v %v", two, err)
			}
			e.clock.Add(15 * time.Minute)
			if _, err := client.RunReadGrant(ctx, r); status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("trigger bypassed shared hourly budget: %v", err)
			}
			if _, err := client.RevokeReadGrant(ctx, &pb.RevokeReadGrantRequest{GrantId: r.GrantId}); err != nil {
				t.Fatal(err)
			}
			for _, trigger := range []pb.ReadGrantTrigger{first, other} {
				r.Trigger = trigger
				if _, err := client.RunReadGrant(ctx, r); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("revocation ignored: %v", err)
				}
			}
			gs, err := client.ListReadGrants(ctx, &pb.ListReadGrantsRequest{})
			if err != nil || len(gs.GetGrants()) != 1 || gs.Grants[0].RevokedUnix == 0 {
				t.Fatalf("revocation listing: %v %v", gs, err)
			}
		})
	}
}

func TestReadGrantRPCRejectsScopeSubstitution(t *testing.T) {
	e, sign, raw := readRPCEnv(t, permit.ModeStandard)
	client := readRPCClient(t, e.svc, peercred.RoleServer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pg, err := client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: pg.GrantDigest, AssertionJson: sign(pg.Challenge, true)}); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []pb.ReadGrantTrigger{pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED, pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND} {
		for name, mutate := range map[string]func(*pb.AuthorizeRunRequest){
			"artifact":   func(r *pb.AuthorizeRunRequest) { r.Artifact = []byte("#!/bin/sh\necho changed\n") },
			"parameters": func(r *pb.AuthorizeRunRequest) { r.ParametersJson = []byte(`{"changed":true}`) },
			"version":    func(r *pb.AuthorizeRunRequest) { r.ModuleVersion = "2.0.0" },
			"action":     func(r *pb.AuthorizeRunRequest) { r.ActionId = "service.list" },
			"pin":        func(r *pb.AuthorizeRunRequest) { r.HostKeyFingerprint = "SHA256:" + strings.Repeat("B", 43) },
			"credential": func(r *pb.AuthorizeRunRequest) { r.CredentialRef = "other" },
		} {
			t.Run(trigger.String()+"/"+name, func(t *testing.T) {
				r := validReadRPCRequest()
				r.Trigger = trigger
				r.Run.HostId = e.host
				r.Run.HostKeyFingerprint = e.fp
				r.Endpoints = []string{closedAddr(t)}
				mutate(r.Run)
				if _, err := client.RunReadGrant(ctx, r); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("scope substitution accepted: %v", err)
				}
			})
		}
	}
}

func TestReadGrantRPCEnforcesApprovedTrigger(t *testing.T) {
	for _, trigger := range []string{permit.TriggerScheduled, permit.TriggerOnDemand} {
		t.Run(trigger, func(t *testing.T) {
			e, sign, raw := readRPCEnv(t, permit.ModeStandard)
			var doc permit.ReadGrantDoc
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			doc.Trigger = trigger
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			client := readRPCClient(t, e.svc, peercred.RoleServer)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pg, err := client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: pg.GrantDigest, AssertionJson: sign(pg.Challenge, true)}); err != nil {
				t.Fatal(err)
			}
			r := validReadRPCRequest()
			r.Run.HostId = e.host
			r.Run.HostKeyFingerprint = e.fp
			r.Endpoints = []string{closedAddr(t)}
			if trigger == permit.TriggerOnDemand {
				r.Trigger = pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED
			}
			if _, err := client.RunReadGrant(ctx, r); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("unapproved trigger accepted: %v", err)
			}
		})
	}
}

type readListStore struct {
	permit.ReadGrantStore
	rows []permit.StoredReadGrant
	err  error
}

func (s readListStore) ReadGrants() ([]permit.StoredReadGrant, error) { return s.rows, s.err }

func TestReadGrantRPCListBoundsAndStorageFailure(t *testing.T) {
	e := newReconcileEnv(t)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	rows := make([]permit.StoredReadGrant, MaxResponseSize/permit.MaxReadGrantDocSize+1)
	document := make([]byte, permit.MaxReadGrantDocSize)
	for i := range rows {
		rows[i] = permit.StoredReadGrant{ID: validReadRPCRequest().GrantId, Digest: strings.Repeat("a", 64), Doc: document}
	}
	for _, tc := range []struct {
		name  string
		store permit.ReadGrantStore
		want  codes.Code
	}{
		{"oversize complete list", readListStore{ReadGrantStore: e.db, rows: rows}, codes.ResourceExhausted},
		{"storage failure", readListStore{ReadGrantStore: e.db, err: errors.New("private storage diagnostic")}, codes.Unavailable},
		{"disabled", nil, codes.Unimplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.svc.auth, err = permit.New(permit.Options{Verifier: v, Store: e.db, RiskPolicy: risk, Leases: tc.store})
			if err != nil {
				t.Fatal(err)
			}
			out, err := e.svc.ListReadGrants(context.Background(), &pb.ListReadGrantsRequest{})
			if status.Code(err) != tc.want || out != nil {
				t.Fatalf("list: %v %v", out, err)
			}
			if strings.Contains(err.Error(), "private storage diagnostic") {
				t.Fatal("storage diagnostic leaked")
			}
		})
	}
}

func TestReadGrantRPCTransportBounds(t *testing.T) {
	e, _, _ := readRPCEnv(t, permit.ModeStandard)
	client := readRPCClient(t, e.svc, peercred.RoleServer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: make([]byte, permit.MaxReadGrantDocSize+1)})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("document limit: %v", err)
	}
	unknown := protowire.AppendTag(nil, 100, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, make([]byte, MaxMessageSize))
	req := &pb.ListReadGrantsRequest{}
	req.ProtoReflect().SetUnknown(unknown)
	if _, err := client.ListReadGrants(ctx, req); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("transport limit: %v", err)
	}
}

func TestReadGrantProposalRequiresPinnedTargets(t *testing.T) {
	e, _, raw := readRPCEnv(t, permit.ModeStandard)
	var doc permit.ReadGrantDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unpinned", "changed key", "legacy format"} {
		t.Run(name, func(t *testing.T) {
			changed := doc
			changed.Targets = slices.Clone(doc.Targets)
			changed.Credentials = slices.Clone(doc.Credentials)
			switch name {
			case "unpinned":
				changed.Targets[0].HostID = "other"
				changed.Credentials[0].HostID = "other"
			case "changed key":
				changed.Targets[0].HostKeyFingerprint = "SHA256:" + strings.Repeat("B", 43)
			case "legacy format":
				changed.Grant = "read-schedule-v1"
			}
			raw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.ProposeReadGrant(context.Background(), &pb.ProposeReadGrantRequest{GrantJson: raw}); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("invalid target/format accepted: %v", err)
			}
			if len(e.svc.auth.PendingReadGrants()) != 0 {
				t.Fatal("rejected proposal consumed pending capacity")
			}
		})
	}
}

func TestReadGrantRPCLockPausesBothTriggers(t *testing.T) {
	e, sign, raw := readRPCEnv(t, permit.ModeStandard)
	client := readRPCClient(t, e.svc, peercred.RoleServer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pg, err := client.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: pg.GrantDigest, AssertionJson: sign(pg.Challenge, true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lock(ctx, &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []pb.ReadGrantTrigger{pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED, pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND} {
		r := validReadRPCRequest()
		r.Trigger = trigger
		r.Run.HostId = e.host
		r.Run.HostKeyFingerprint = e.fp
		if _, err := client.RunReadGrant(ctx, r); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("locked read: %v", err)
		}
	}
	gs, err := client.ListReadGrants(ctx, &pb.ListReadGrantsRequest{})
	if err != nil || len(gs.GetGrants()) != 1 || gs.Grants[0].RevokedUnix != 0 {
		t.Fatalf("lock changed durable approval: %v %v", gs, err)
	}
}
