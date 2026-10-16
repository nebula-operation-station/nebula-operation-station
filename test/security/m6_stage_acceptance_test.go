// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

// stagedRequest is a HIGH request for script on hosts with the given plan.
func (h *harness) stagedRequest(hosts []runHost, script []byte, plan []stageplan.Stage) (*pb.ExecutionRequest, []byte) {
	h.t.Helper()
	ph, err := canonical.HashParameters(runParamsProposed)
	if err != nil {
		h.t.Fatal(err)
	}
	doc, err := stageplan.Encode(plan)
	if err != nil {
		h.t.Fatal(err)
	}
	sh, err := canonical.HashParameters(doc)
	if err != nil {
		h.t.Fatal(err)
	}
	req := &pb.ExecutionRequest{
		ExecutionId: fmt.Sprintf("00000000-0000-4000-8000-%012d", execCounter.Add(1)),
		ActionId:    "test.run", ModuleVersion: "1.0.0", ArtifactSha256: hexSum(script), ParametersHash: ph,
		CredentialRefs: []string{credRef}, RiskClass: pb.RiskClass_RISK_CLASS_HIGH, StagePlanHash: sh,
		ExpiryUnix: time.Now().Add(time.Hour).Unix(),
	}
	for _, x := range hosts {
		req.ResolvedTargets = append(req.ResolvedTargets, &pb.Target{HostId: x.id, HostKeyFingerprint: x.fp})
	}
	return req, doc
}

// approvedStaged proposes and approves a staged HIGH rollout.
func (h *harness) approvedStaged(hosts []runHost, script []byte, plan []stageplan.Stage) *pb.ProposeExecutionResponse {
	h.t.Helper()
	req, doc := h.stagedRequest(hosts, script, plan)
	h.openSession()
	p, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req, ParametersJson: runParamsProposed, StagePlanJson: doc})
	if err != nil {
		h.t.Fatalf("propose: %v", err)
	}
	if _, err := h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: p.GetExecutionDigest(), AssertionJson: h.sign(p.GetChallenge()),
	}); err != nil {
		h.t.Fatalf("approve: %v", err)
	}
	return p
}

func manualStage(name string, hosts ...runHost) stageplan.Stage {
	st := stageplan.Stage{Name: name, Continue: stageplan.ContinueManual, TimeoutS: 600}
	for _, x := range hosts {
		st.Hosts = append(st.Hosts, x.id)
	}
	return st
}

var open2 = &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: 2}

// Spec 16, Milestone 6: a failing canary stops the rollout. The executor
// refuses the later hosts on its own record of the canary's run; nothing
// reaches them.
func TestM6_FailingCanaryStopsTheRollout(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	canary, rest := h.pinnedRunHost("canary"), h.pinnedRunHost("rest")
	failing := []byte("exit 3\n")
	p := h.approvedStaged([]runHost{canary, rest}, failing, []stageplan.Stage{manualStage("canary", canary), manualStage("rest", rest)})
	d := p.GetExecutionDigest()

	_, err := h.client.RunAttached(h.ctx(), runReq(d, rest, failing, credRef))
	wantCode(t, err, codes.PermissionDenied, "stage_not_open")
	r, err := h.client.RunAttached(h.ctx(), runReq(d, canary, failing, credRef))
	if err != nil || r.GetClass() != "script_failed" {
		t.Fatalf("%v %v", r, err)
	}
	_, err = h.client.RunAttached(h.ctx(), runReq(d, rest, failing, credRef))
	wantCode(t, err, codes.PermissionDenied, "rollout_stopped")
	_, err = h.client.BeginGate(h.ctx(), &pb.BeginGateRequest{ExecutionDigest: d, Gate: open2})
	wantCode(t, err, codes.PermissionDenied, "rollout_stopped")
	ro, err := h.client.GetRollout(h.ctx(), &pb.GetRolloutRequest{ExecutionDigest: d})
	if err != nil || ro.GetRollout().GetStopped() == "" || ro.GetRollout().GetOpenStage() != 1 {
		t.Fatalf("%v %v", ro, err)
	}
	if n := len(rest.srv.Commands()); n != 0 {
		t.Fatalf("%d commands reached the stopped stage", n)
	}
	h.requireAudit("stage_failed", "")
}

// Spec 16, Milestone 6: a HIGH gate demands a fresh assertion, bound to
// this rollout and this stage.
func TestM6_HighGateDemandsAFreshAssertion(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	a, b := h.pinnedRunHost("a"), h.pinnedRunHost("b")
	p := h.approvedStaged([]runHost{a, b}, runScript, []stageplan.Stage{manualStage("one", a), manualStage("two", b)})
	d := p.GetExecutionDigest()
	if r, err := h.client.RunAttached(h.ctx(), runReq(d, a, runScript, credRef)); err != nil || r.GetClass() != "success" {
		t.Fatalf("%v %v", r, err)
	}
	_, err := h.client.RunAttached(h.ctx(), runReq(d, b, runScript, credRef))
	wantCode(t, err, codes.PermissionDenied, "stage_not_open")

	// The privileged session alone does not open a HIGH gate.
	_, err = h.client.CommitGate(h.ctx(), &pb.CommitGateRequest{ExecutionDigest: d, Gate: open2})
	wantCode(t, err, codes.FailedPrecondition, "")
	// The approval assertion of the rollout is not a gate assertion.
	g, err := h.client.BeginGate(h.ctx(), &pb.BeginGateRequest{ExecutionDigest: d, Gate: open2})
	if err != nil || g.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED || len(g.GetChallenge()) != 32 {
		t.Fatalf("%v %v", g, err)
	}
	_, err = h.client.CommitGate(h.ctx(), &pb.CommitGateRequest{ExecutionDigest: d, Gate: open2, AssertionJson: h.sign(p.GetChallenge())})
	wantCode(t, err, codes.PermissionDenied, "")
	// Used once: the same challenge does not work after a failed attempt.
	_, err = h.client.CommitGate(h.ctx(), &pb.CommitGateRequest{ExecutionDigest: d, Gate: open2, AssertionJson: h.sign(g.GetChallenge())})
	wantCode(t, err, codes.FailedPrecondition, "")

	g, err = h.client.BeginGate(h.ctx(), &pb.BeginGateRequest{ExecutionDigest: d, Gate: open2})
	if err != nil {
		t.Fatal(err)
	}
	c, err := h.client.CommitGate(h.ctx(), &pb.CommitGateRequest{ExecutionDigest: d, Gate: open2, AssertionJson: h.sign(g.GetChallenge())})
	if err != nil || c.GetRollout().GetOpenStage() != 2 {
		t.Fatalf("%v %v", c, err)
	}
	if r, err := h.client.RunAttached(h.ctx(), runReq(d, b, runScript, credRef)); err != nil || r.GetClass() != "success" {
		t.Fatalf("%v %v", r, err)
	}
	h.requireAudit("stage_opened", "")
}

// The approved stage plan is what the executor enforces: a plan that does
// not hash to stage_plan_hash, or a request without a plan that does not
// carry the single-stage hash, is refused; so is automatic continue on a
// HIGH rollout.
func TestM6_StagePlanIsPartOfTheApproval(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession()
	a, b := h.pinnedRunHost("a"), h.pinnedRunHost("b")
	req, _ := h.stagedRequest([]runHost{a, b}, runScript, []stageplan.Stage{manualStage("one", a), manualStage("two", b)})
	_, other := h.stagedRequest([]runHost{a, b}, runScript, []stageplan.Stage{manualStage("one", a, b)})
	_, err := h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req, ParametersJson: runParamsProposed, StagePlanJson: other})
	wantCode(t, err, codes.InvalidArgument, "stage_plan")
	_, err = h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req, ParametersJson: runParamsProposed})
	wantCode(t, err, codes.InvalidArgument, "stage_plan")
	auto := manualStage("one", a)
	auto.Continue = stageplan.ContinueAuto
	req, doc := h.stagedRequest([]runHost{a, b}, runScript, []stageplan.Stage{auto, manualStage("two", b)})
	_, err = h.client.ProposeExecution(h.ctx(), &pb.ProposeExecutionRequest{Request: req, ParametersJson: runParamsProposed, StagePlanJson: doc})
	wantCode(t, err, codes.InvalidArgument, "manually")
}

// Abort takes permission away without an approval; the server role may do
// it, the hosts that did not run stay untouched.
func TestM6_AbortStopsTheRollout(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	a, b := h.pinnedRunHost("a"), h.pinnedRunHost("b")
	p := h.approvedStaged([]runHost{a, b}, runScript, []stageplan.Stage{manualStage("all", a, b)})
	d := p.GetExecutionDigest()
	if _, err := h.client.AbortRollout(h.ctx(), &pb.AbortRolloutRequest{ExecutionDigest: d}); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.RunAttached(h.ctx(), runReq(d, a, runScript, credRef))
	wantCode(t, err, codes.PermissionDenied, "rollout_aborted")
	if n := len(a.srv.Commands()); n != 0 {
		t.Fatalf("%d commands after abort", n)
	}
}
