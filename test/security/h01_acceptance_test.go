// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// H01 acceptance: the executor derives the minimum risk class from its own
// data and never trusts the server's risk_class below it.

const (
	riskLow      = pb.RiskClass_RISK_CLASS_LOW
	riskMedium   = pb.RiskClass_RISK_CLASS_MEDIUM
	riskHigh     = pb.RiskClass_RISK_CLASS_HIGH
	riskCritical = pb.RiskClass_RISK_CLASS_CRITICAL
)

var hostKeys = map[string]string{"dockerflux": fpA, "strompi": fpB}

func (h *harness) trust(risk pb.RiskClass) string {
	h.t.Helper()
	resp, err := h.client.TrustArtifact(h.ctx(), &pb.TrustArtifactRequest{
		ActionId: testAction, ModuleVersion: testVersion, RiskClass: risk, Artifact: script, Label: "h01 test",
		ExpectedSha256: hexSum(script),
	})
	if err != nil {
		h.t.Fatalf("trust artifact: %v", err)
	}
	return resp.GetArtifactSha256()
}

func (h *harness) setCriticality(host string, c pb.RiskClass) {
	h.t.Helper()
	if _, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{
		HostId: host, HostKeyFingerprint: hostKeys[host], Criticality: c,
	}); err != nil {
		h.t.Fatalf("set criticality %s: %v", host, err)
	}
}

func (h *harness) proposeReq(r *pb.ExecutionRequest) error {
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: params})
	return err
}

func (h *harness) proposeErr(risk pb.RiskClass) error { return h.proposeReq(h.request(risk)) }

// requireAudit asserts that the executor logged a line containing all parts.
func (h *harness) requireAudit(parts ...string) {
	h.t.Helper()
	for _, line := range strings.Split(h.logs.String(), "\n") {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(line, p)
		}
		if ok {
			return
		}
	}
	h.t.Fatalf("no audit line with %q; log:\n%s", parts, h.logs.String())
}

// The acceptance criterion of the issue: a compromised server proposes a
// HIGH action as LOW inside an active privileged session.
func TestH01_HighActionProposedAsLowIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.trust(riskHigh)
	h.setCriticality("dockerflux", riskLow)
	h.setCriticality("strompi", riskLow)
	h.openSession()

	err := h.proposeErr(riskLow)
	wantCode(t, err, codes.InvalidArgument, string(permit.CodeInvalidRequest)+": risk_class LOW is below the executor's minimum HIGH")
	wantCode(t, h.proposeErr(riskMedium), codes.InvalidArgument, string(permit.CodeInvalidRequest))
	h.requireAudit(`"kind":"rejected"`, "below executor minimum HIGH", "trusted as HIGH")

	st, err := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetApprovedPermits() != 0 || st.GetPendingPermits() != 0 {
		t.Fatalf("permit issued below the floor: %d approved, %d pending", st.GetApprovedPermits(), st.GetPendingPermits())
	}
	// Proposed honestly, the same action needs a user-verified assertion.
	p := h.propose(h.request(riskHigh))
	if p.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("HIGH proposal: requirement %v", p.GetApprovalRequirement())
	}
}

// Nothing trusted: every artifact is at least HIGH, so a LOW label never
// gets an automatic permit.
func TestH01_UntrustedArtifactIsAtLeastHigh(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.openSession()
	wantCode(t, h.proposeErr(riskLow), codes.InvalidArgument, "below the executor's minimum HIGH")
	h.requireAudit("artifact is not trusted on the executor")

	// Trust is bound to the bytes the executor hashed itself: trusting
	// other bytes under the same action does not help.
	if _, err := h.client.TrustArtifact(h.ctx(), &pb.TrustArtifactRequest{
		ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow, Artifact: []byte("#!/bin/sh\ntrue\n"),
	}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, h.proposeErr(riskLow), codes.InvalidArgument, "below the executor's minimum HIGH")
}

// The reviewer's attack: the server addresses the CRITICAL host's key under
// the name of a LOW host. A record counts only for its own key.
func TestH01_RelabelledCriticalHostIsNotLow(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.trust(riskMedium)
	h.setCriticality("dockerflux", riskLow)
	h.setCriticality("strompi", riskCritical)

	r := h.request(riskMedium)
	r.ResolvedTargets = []*pb.Target{{HostId: "dockerflux", HostKeyFingerprint: fpB}}
	wantCode(t, h.proposeReq(r), codes.InvalidArgument, "below the executor's minimum CRITICAL")
	h.requireAudit("host dockerflux (" + fpB + ") has no matching criticality record, but its host ID or key is recorded as CRITICAL")

	// Nor can it present the CRITICAL host under another of its keys.
	r = h.request(riskHigh)
	r.ResolvedTargets = []*pb.Target{{HostId: "strompi", HostKeyFingerprint: "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}}
	wantCode(t, h.proposeReq(r), codes.InvalidArgument, "below the executor's minimum CRITICAL")

	// The admin cannot record strompi's key under a second name either.
	_, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: "strompi-alias", HostKeyFingerprint: fpB, Criticality: riskLow})
	wantCode(t, err, codes.InvalidArgument, "already recorded for host strompi")
}

func TestH01_HostCriticalityRaisesTheFloor(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.trust(riskMedium)
	h.setCriticality("dockerflux", riskLow)
	// strompi has no record: HIGH.
	wantCode(t, h.proposeErr(riskMedium), codes.InvalidArgument, "below the executor's minimum HIGH")
	h.requireAudit("host strompi (" + fpB + ") has no matching criticality record")

	h.setCriticality("strompi", riskCritical)
	wantCode(t, h.proposeErr(riskHigh), codes.InvalidArgument, "below the executor's minimum CRITICAL")
	h.propose(h.request(riskCritical))
}

// LOW (read-only) actions stay LOW on recorded LOW..HIGH hosts and need a
// WebAuthn tap on CRITICAL hosts.
func TestH01_ReadOnlyActionsOnCriticalHostsNeedMedium(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	h.trust(riskLow)
	h.setCriticality("dockerflux", riskHigh)
	h.setCriticality("strompi", riskLow)
	h.openSession()
	if p := h.propose(h.request(riskLow)); p.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		t.Fatalf("trusted LOW action on HIGH and LOW hosts: state %v", p.GetState())
	}
	h.setCriticality("strompi", riskCritical)
	wantCode(t, h.proposeErr(riskLow), codes.InvalidArgument, "below the executor's minimum MEDIUM")
	h.propose(h.request(riskMedium))
}

// Trust withdrawn after approval stops the next host run.
func TestH01_WithdrawnTrustStopsApprovedRuns(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	sum := h.trust(riskMedium)
	h.setCriticality("dockerflux", riskLow)
	h.setCriticality("strompi", riskLow)
	h.unlock()
	h.openSession()
	p := h.approvedMedium()

	resp, err := h.client.UntrustArtifact(h.ctx(), &pb.UntrustArtifactRequest{ArtifactSha256: sum, ActionId: testAction, ModuleVersion: testVersion})
	if err != nil || !resp.GetRemoved() {
		t.Fatalf("untrust: %v %v", resp, err)
	}
	_, err = h.client.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "dockerflux", fpA))
	wantCode(t, err, codes.PermissionDenied, string(permit.CodeRiskAboveApproval)+": approved as MEDIUM, executor minimum for this host is now HIGH")

	// Raising a host's criticality has the same effect, for that host only.
	h.trust(riskMedium)
	h.setCriticality("strompi", riskHigh)
	_, err = h.client.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "strompi", fpB))
	wantCode(t, err, codes.PermissionDenied, string(permit.CodeRiskAboveApproval))
	h.requireAudit(`"kind":"denied"`, `"host":"strompi"`, "is HIGH")
	if _, err := h.client.AuthorizeRun(h.ctx(), run(p.GetExecutionDigest(), "dockerflux", fpA)); err != nil {
		t.Fatalf("dockerflux after re-trust: %v", err)
	}
}

// The server cannot read or change the executor's risk data.
func TestH01_ServerRoleCannotChangeRiskData(t *testing.T) {
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}})
	_, err := h.client.TrustArtifact(h.ctx(), &pb.TrustArtifactRequest{ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow, Artifact: script})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.UntrustArtifact(h.ctx(), &pb.UntrustArtifactRequest{ArtifactSha256: hexSum(script), ActionId: testAction, ModuleVersion: testVersion})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: "dockerflux", HostKeyFingerprint: fpA, Criticality: riskLow})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.ListTrustedArtifacts(h.ctx(), &pb.ListTrustedArtifactsRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.ListHostCriticality(h.ctx(), &pb.ListHostCriticalityRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}

func TestH01_RiskDataSurvivesRestartAndIsAudited(t *testing.T) {
	dir, id := privateDir(t), newIdentity()
	h1 := newHarness(t, harnessOptions{dataDir: dir, identity: id, untrusted: true})
	sum := h1.trust(riskMedium)
	h1.setCriticality("strompi", riskCritical)
	h1.setCriticality("dockerflux", riskLow)
	h1.requireAudit(`"kind":"artifact_trusted"`, sum, `"risk":"MEDIUM"`)
	h1.requireAudit(`"kind":"host_criticality_set"`, `"host":"strompi"`, fpB, `"criticality":"CRITICAL"`)
	h1.stop()

	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: id, untrusted: true})
	arts, err := h2.client.ListTrustedArtifacts(h2.ctx(), &pb.ListTrustedArtifactsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(arts.GetArtifacts()) != 1 || arts.GetArtifacts()[0].GetArtifactSha256() != sum || arts.GetArtifacts()[0].GetRiskClass() != riskMedium {
		t.Fatalf("trusted artifacts after restart: %v", arts.GetArtifacts())
	}
	wantCode(t, h2.proposeErr(riskHigh), codes.InvalidArgument, "below the executor's minimum CRITICAL")

	// Clearing a record makes the host unrecorded (HIGH) again.
	resp, err := h2.client.SetHostCriticality(h2.ctx(), &pb.SetHostCriticalityRequest{HostId: "strompi", Clear: true})
	if err != nil || !resp.GetChanged() {
		t.Fatalf("clear: %v %v", resp, err)
	}
	wantCode(t, h2.proposeErr(riskMedium), codes.InvalidArgument, "below the executor's minimum HIGH")
	h2.propose(h2.request(riskHigh))
}

func TestH01_AdminInputIsValidated(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	for name, req := range map[string]*pb.TrustArtifactRequest{
		"no risk":      {ActionId: testAction, ModuleVersion: testVersion, Artifact: script},
		"empty":        {ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow},
		"bad action":   {ActionId: "INSTALL", ModuleVersion: testVersion, RiskClass: riskLow, Artifact: script},
		"escape label": {ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow, Artifact: script, Label: "\x1b]0;pwned\x07"},
		"hash differs": {ActionId: testAction, ModuleVersion: testVersion, RiskClass: riskLow, Artifact: script, ExpectedSha256: strings.Repeat("0", 64)},
	} {
		_, err := h.client.TrustArtifact(h.ctx(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument, got %v", name, err)
		}
	}
	arts, err := h.client.ListTrustedArtifacts(h.ctx(), &pb.ListTrustedArtifactsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(arts.GetArtifacts()) != 0 {
		t.Fatalf("invalid entries stored: %v", arts.GetArtifacts())
	}
	for name, req := range map[string]*pb.SetHostCriticalityRequest{
		"bad host":           {HostId: "../etc", HostKeyFingerprint: fpA, Criticality: riskLow},
		"no fingerprint":     {HostId: "dockerflux", Criticality: riskLow},
		"no criticality":     {HostId: "dockerflux", HostKeyFingerprint: fpA},
		"clear with a level": {HostId: "dockerflux", Clear: true, Criticality: riskLow},
	} {
		_, err := h.client.SetHostCriticality(h.ctx(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument, got %v", name, err)
		}
	}
}
