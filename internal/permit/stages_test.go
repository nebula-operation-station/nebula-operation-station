// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

const fpC = "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

var fps = map[string]string{"dockerflux": fpA, "strompi": fpB, "web": fpC}

// staged proposes and approves a three-host request with the given
// stages and returns the permit.
func (e *env) staged(risk canonical.Risk, st ...stageplan.Stage) Permit {
	e.t.Helper()
	r := e.request(risk)
	r.ResolvedTargets = append(r.ResolvedTargets, canonical.Target{HostID: "web", HostKeyFingerprint: fpC})
	plan, err := stageplan.Encode(st)
	if err != nil {
		e.t.Fatal(err)
	}
	r.StagePlanHash, _ = canonical.HashParameters(plan)
	res, err := e.auth.ProposeStaged(r, params, plan, false)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	p := res.Permit
	if p.State == StatePending {
		if p.Requirement == RequireCLI {
			if _, err := e.auth.ApproveCLI(p.Digest, 0, "test"); err != nil {
				e.t.Fatal(err)
			}
		} else if _, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 3); err != nil {
			e.t.Fatal(err)
		}
	}
	return p
}

func stg(name string, maxFailed, maxUnreachable int, cont string, hosts ...string) stageplan.Stage {
	return stageplan.Stage{Name: name, Hosts: hosts, MaxFailed: maxFailed, MaxUnreachable: maxUnreachable, Continue: cont, TimeoutS: 600}
}

// run authorizes host and records the executor's outcome.
func (e *env) run(p Permit, host string, o Outcome) {
	e.t.Helper()
	if _, err := e.auth.AuthorizeGrant(p.Digest, goodRun(host, fps[host])); err != nil {
		e.t.Fatalf("authorize %s: %v", host, err)
	}
	e.auth.RecordOutcome(p.Request.ExecutionID, host, o)
}

func (e *env) authorize(p Permit, host string) error {
	_, err := e.auth.AuthorizeGrant(p.Digest, goodRun(host, fps[host]))
	return err
}

// Spec 16, Milestone 6: a failing canary stops the rollout. The executor
// refuses every later host, whatever the server asks.
func TestFailingCanaryStopsTheRollout(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskMedium, stg("canary", 0, 0, stageplan.ContinueAuto, "dockerflux"), stg("rest", 1, 1, stageplan.ContinueManual, "strompi", "web"))

	wantCode(t, e.authorize(p, "strompi"), CodeStageNotOpen)
	e.run(p, "dockerflux", OutcomeFailed)
	wantCode(t, e.authorize(p, "strompi"), CodeRolloutStopped)
	_, err := e.auth.BeginGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 2})
	wantCode(t, err, CodeRolloutStopped)
	wantCode(t, e.auth.CommitGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 2}, nil), CodeRolloutStopped)
	r, err := e.auth.Rollout(p.Digest)
	if err != nil || r.Stopped == "" || r.Open != 0 || r.Stages[0].Outcomes["dockerflux"] != OutcomeFailed {
		t.Fatalf("%+v %v", r, err)
	}
	// A failed outcome is final: the executor's record cannot be replaced.
	e.auth.RecordOutcome(p.Request.ExecutionID, "dockerflux", OutcomeSucceeded)
	wantCode(t, e.authorize(p, "web"), CodeRolloutStopped)
}

// A passing stage with continue auto opens the next one by itself (LOW
// and MEDIUM only); thresholds let exactly max_failed failures through.
func TestAutoContinueAndThresholds(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskMedium, stg("first", 1, 0, stageplan.ContinueAuto, "dockerflux", "strompi"), stg("last", 0, 0, stageplan.ContinueManual, "web"))
	e.run(p, "dockerflux", OutcomeFailed)
	wantCode(t, e.authorize(p, "web"), CodeStageNotOpen) // stage 1 not complete yet
	e.run(p, "strompi", OutcomeSucceeded)
	e.run(p, "web", OutcomeSucceeded) // opened automatically
	r, _ := e.auth.Rollout(p.Digest)
	if r.Open != 1 || r.Stopped != "" || !r.Stages[0].Passed || !r.Stages[1].Passed {
		t.Fatalf("%+v", r)
	}
}

// Spec 16, Milestone 6: a HIGH gate demands a fresh user-verified
// assertion bound to the digest and the stage.
func TestHighGateNeedsAFreshAssertionForThatStage(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskHigh, stg("one", 0, 0, stageplan.ContinueManual, "dockerflux"), stg("two", 0, 0, stageplan.ContinueManual, "strompi"), stg("three", 0, 0, stageplan.ContinueManual, "web"))
	open2 := Gate{Kind: GateOpenStage, Stage: 2}

	_, err := e.auth.BeginGate(p.Digest, open2)
	wantCode(t, err, CodeStageNotDone)
	e.run(p, "dockerflux", OutcomeSucceeded)
	wantCode(t, e.authorize(p, "strompi"), CodeStageNotOpen) // manual: waits at the gate

	// No challenge yet; the session alone is not enough for HIGH.
	wantCode(t, e.auth.CommitGate(p.Digest, open2, nil), CodeNoChallenge)
	// Stage 3 cannot be opened before stage 2.
	_, err = e.auth.BeginGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 3})
	wantCode(t, err, CodeGateInvalid)

	gc, err := e.auth.BeginGate(p.Digest, open2)
	if err != nil || gc.Requirement != RequireAssertionVerified || len(gc.Challenge) != 32 {
		t.Fatalf("%+v %v", gc, err)
	}
	// The permit's own approval challenge does not open a gate.
	wantCode(t, e.auth.CommitGate(p.Digest, open2, e.sign(p.Challenge)), CodeAssertionRejected)
	// The challenge was consumed by that attempt: a fresh one is needed,
	// and an assertion over an older gate challenge is refused.
	gc, _ = e.auth.BeginGate(p.Digest, open2)
	old := gc.Challenge
	gc, _ = e.auth.BeginGate(p.Digest, open2)
	wantCode(t, e.auth.CommitGate(p.Digest, open2, e.sign(old)), CodeAssertionRejected)
	// Without user verification it is refused.
	gc, _ = e.auth.BeginGate(p.Digest, open2)
	e.dev.Options.UserNotVerified = true
	wantCode(t, e.auth.CommitGate(p.Digest, open2, e.sign(gc.Challenge)), CodeAssertionRejected)
	e.dev.Options.UserNotVerified = false
	// An assertion for this gate does not open the same gate of another
	// rollout.
	q := e.staged(canonical.RiskHigh, stg("one", 0, 0, stageplan.ContinueManual, "dockerflux"), stg("two", 0, 0, stageplan.ContinueManual, "strompi", "web"))
	e.run(q, "dockerflux", OutcomeSucceeded)
	gc, _ = e.auth.BeginGate(p.Digest, open2)
	if _, err := e.auth.BeginGate(q.Digest, open2); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.auth.CommitGate(q.Digest, open2, e.sign(gc.Challenge)), CodeAssertionRejected)
	gc, _ = e.auth.BeginGate(p.Digest, open2)
	if err := e.auth.CommitGate(p.Digest, open2, e.sign(gc.Challenge)); err != nil {
		t.Fatal(err)
	}
	e.run(p, "strompi", OutcomeSucceeded)
	wantCode(t, e.authorize(p, "web"), CodeStageNotOpen)
}

// HIGH and CRITICAL rollouts never continue on their own (decision 2).
func TestHighRolloutCannotContinueAutomatically(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	for _, risk := range []canonical.Risk{canonical.RiskHigh, canonical.RiskCritical} {
		r := e.request(risk)
		r.ResolvedTargets = append(r.ResolvedTargets, canonical.Target{HostID: "web", HostKeyFingerprint: fpC})
		plan, _ := stageplan.Encode([]stageplan.Stage{stg("a", 0, 0, stageplan.ContinueAuto, "dockerflux"), stg("b", 0, 0, stageplan.ContinueManual, "strompi", "web")})
		r.StagePlanHash, _ = canonical.HashParameters(plan)
		_, err := e.auth.ProposeStaged(r, params, plan, false)
		wantCode(t, err, CodeStagePlan)
	}
	// Raising the risk to the executor's minimum applies too.
	e.risk.set(canonical.RiskHigh)
	r := e.request(canonical.RiskMedium)
	r.ResolvedTargets = append(r.ResolvedTargets, canonical.Target{HostID: "web", HostKeyFingerprint: fpC})
	plan, _ := stageplan.Encode([]stageplan.Stage{stg("a", 0, 0, stageplan.ContinueAuto, "dockerflux"), stg("b", 0, 0, stageplan.ContinueManual, "strompi", "web")})
	r.StagePlanHash, _ = canonical.HashParameters(plan)
	_, err := e.auth.ProposeStaged(r, params, plan, true)
	wantCode(t, err, CodeStagePlan)
}

func TestStagePlanMustBeTheApprovedOne(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	r := e.request(canonical.RiskMedium)
	plan, _ := stageplan.Encode([]stageplan.Stage{stg("a", 0, 0, stageplan.ContinueManual, "dockerflux"), stg("b", 0, 0, stageplan.ContinueManual, "strompi")})
	other, _ := stageplan.Encode([]stageplan.Stage{stg("a", 0, 0, stageplan.ContinueManual, "dockerflux", "strompi")})
	r.StagePlanHash, _ = canonical.HashParameters(other)
	_, err := e.auth.ProposeStaged(r, params, plan, false)
	wantCode(t, err, CodeStagePlan)
	// A plan that leaves out a target.
	missing, _ := stageplan.Encode([]stageplan.Stage{stg("a", 0, 0, stageplan.ContinueManual, "dockerflux")})
	r.StagePlanHash, _ = canonical.HashParameters(missing)
	_, err = e.auth.ProposeStaged(r, params, missing, false)
	wantCode(t, err, CodeStagePlan)
	_, err = e.auth.ProposeStaged(r, params, nil, false)
	wantCode(t, err, CodeStagePlan)
}

// Retry: an unreachable host (released, nothing ran) runs again in its
// stage. Skip: a gate decision, audited, that counts the host as neither
// failed nor done; a host that ran cannot be skipped.
func TestUnreachableHostsAreRetriedOrSkipped(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskMedium, stg("one", 0, 0, stageplan.ContinueManual, "dockerflux", "strompi"), stg("two", 0, 0, stageplan.ContinueManual, "web"))
	open2 := Gate{Kind: GateOpenStage, Stage: 2}

	// dockerflux unreachable, then retried successfully.
	if err := e.authorize(p, "dockerflux"); err != nil {
		t.Fatal(err)
	}
	if !e.auth.ReleaseHost(p.Digest, "dockerflux") {
		t.Fatal("not released")
	}
	e.auth.RecordOutcome(p.Request.ExecutionID, "dockerflux", OutcomeUnreachable)
	e.run(p, "dockerflux", OutcomeSucceeded)

	// strompi unreachable: stage one is over its threshold until it is
	// retried or skipped.
	if err := e.authorize(p, "strompi"); err != nil {
		t.Fatal(err)
	}
	e.auth.ReleaseHost(p.Digest, "strompi")
	e.auth.RecordOutcome(p.Request.ExecutionID, "strompi", OutcomeUnreachable)
	_, err := e.auth.BeginGate(p.Digest, open2)
	wantCode(t, err, CodeStageNotDone)

	// Skip needs the gate's approval: the session for MEDIUM.
	skip := Gate{Kind: GateSkipHost, Host: "strompi"}
	wantCode(t, e.auth.CommitGate(p.Digest, Gate{Kind: GateSkipHost, Host: "dockerflux"}, nil), CodeGateInvalid) // ran already
	wantCode(t, e.auth.CommitGate(p.Digest, Gate{Kind: GateSkipHost, Host: "web"}, nil), CodeStageNotOpen)
	wantCode(t, e.auth.CommitGate(p.Digest, Gate{Kind: GateSkipHost, Host: "nope"}, nil), CodeGateInvalid)
	e.auth.Lock("test") // ends the session and every permit
	wantCode(t, e.auth.CommitGate(p.Digest, skip, nil), CodeNotFound)

	e = newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p = e.staged(canonical.RiskMedium, stg("one", 0, 0, stageplan.ContinueManual, "dockerflux", "strompi"), stg("two", 0, 0, stageplan.ContinueManual, "web"))
	e.run(p, "dockerflux", OutcomeSucceeded)
	if err := e.authorize(p, "strompi"); err != nil {
		t.Fatal(err)
	}
	// strompi is running: it cannot be skipped.
	wantCode(t, e.auth.CommitGate(p.Digest, skip, nil), CodeGateInvalid)
	e.auth.ReleaseHost(p.Digest, "strompi")
	e.auth.RecordOutcome(p.Request.ExecutionID, "strompi", OutcomeUnreachable)
	e.clk.Add(DefaultSessionLength) // session over
	wantCode(t, e.auth.CommitGate(p.Digest, skip, nil), CodeSessionRequired)
	e.openSession()
	if err := e.auth.CommitGate(p.Digest, skip, nil); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.authorize(p, "strompi"), CodeHostAlreadyRun)
	if e.auth.ReleaseHost(p.Digest, "strompi") {
		t.Fatal("a skipped host was released")
	}
	if err := e.auth.CommitGate(p.Digest, open2, nil); err != nil {
		t.Fatal(err)
	}
	// web: a durable job that could not be dispatched stays used but
	// unreachable; it can be skipped, not run again.
	if err := e.authorize(p, "web"); err != nil {
		t.Fatal(err)
	}
	e.auth.RecordOutcome(p.Request.ExecutionID, "web", OutcomeUnreachable)
	wantCode(t, e.authorize(p, "web"), CodeHostAlreadyRun)
	if err := e.auth.CommitGate(p.Digest, Gate{Kind: GateSkipHost, Host: "web"}, nil); err != nil {
		t.Fatal(err)
	}
	if !e.hasEvent("host_skipped", "strompi") || !e.hasEvent("stage_opened", "") {
		t.Fatal("skip or gate not audited")
	}
}

func TestAbortStopsEveryRemainingHost(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskLow, stg("all", 3, 3, stageplan.ContinueManual, "dockerflux", "strompi", "web"))
	e.run(p, "dockerflux", OutcomeSucceeded)
	if err := e.auth.Abort(p.Digest, "test"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.authorize(p, "strompi"), CodeRolloutAborted)
	_, err := e.auth.BeginGate(p.Digest, Gate{Kind: GateSkipHost, Host: "web"})
	wantCode(t, err, CodeRolloutAborted)
}

func TestHardenedModeGatesNeedTheCLI(t *testing.T) {
	e := newEnv(t, ModeHardened, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskHigh, stg("one", 0, 0, stageplan.ContinueManual, "dockerflux"), stg("two", 0, 0, stageplan.ContinueManual, "strompi", "web"))
	e.run(p, "dockerflux", OutcomeSucceeded)
	open2 := Gate{Kind: GateOpenStage, Stage: 2}
	gc, err := e.auth.BeginGate(p.Digest, open2)
	if err != nil || gc.Requirement != RequireCLI || gc.Challenge != nil {
		t.Fatalf("%+v %v", gc, err)
	}
	wantCode(t, e.auth.CommitGate(p.Digest, open2, nil), CodeCLIRequired)
	if err := e.auth.ApproveGateCLI(p.Digest, open2, "root"); err != nil {
		t.Fatal(err)
	}
	if err := e.authorize(p, "strompi"); err != nil {
		t.Fatal(err)
	}
}

// A request without stages behaves as before: one stage, every host may
// run once approved, failures do not stop the others.
func TestRequestWithoutStagesIsOneStage(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.propose(e.request(canonical.RiskLow))
	e.run(p, "dockerflux", OutcomeFailed)
	if err := e.authorize(p, "strompi"); err != nil {
		t.Fatal(err)
	}
	if len(p.Plan) != 1 || len(p.Plan[0].Hosts) != 2 {
		t.Fatalf("%+v", p.Plan)
	}
}

func (e *env) hasEvent(kind, host string) bool {
	e.evtMu.Lock()
	defer e.evtMu.Unlock()
	for _, ev := range e.evts {
		if ev.Kind == kind && (host == "" || ev.Host == host) {
			return true
		}
	}
	return false
}

// A host of a passed stage that is retried and fails afterwards still
// stops the rollout (Hermes review of #34, finding 1).
func TestRetriedHostOfAPassedStageStillStopsTheRollout(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskMedium, stg("canary", 0, 1, stageplan.ContinueAuto, "dockerflux"), stg("rest", 2, 2, stageplan.ContinueManual, "strompi", "web"))
	if err := e.authorize(p, "dockerflux"); err != nil {
		t.Fatal(err)
	}
	if !e.auth.ReleaseUnreachable(p.Digest, "dockerflux") {
		t.Fatal("not released")
	}
	// Stage 1 passed with one unreachable host; stage 2 opened by itself.
	if err := e.authorize(p, "strompi"); err != nil {
		t.Fatal(err)
	}
	e.run(p, "dockerflux", OutcomeFailed)
	wantCode(t, e.authorize(p, "web"), CodeRolloutStopped)
}

// Release and outcome happen together: once released, the host is
// unreachable in the rollout at the same moment (finding 2).
func TestReleaseUnreachableRecordsTheOutcome(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskMedium, stg("one", 0, 0, stageplan.ContinueManual, "dockerflux", "strompi"), stg("two", 0, 0, stageplan.ContinueManual, "web"))
	if err := e.authorize(p, "dockerflux"); err != nil {
		t.Fatal(err)
	}
	if !e.auth.ReleaseUnreachable(p.Digest, "dockerflux") {
		t.Fatal("not released")
	}
	r, _ := e.auth.Rollout(p.Digest)
	if r.Stages[0].Outcomes["dockerflux"] != OutcomeUnreachable {
		t.Fatalf("%+v", r.Stages[0].Outcomes)
	}
	if e.auth.ReleaseUnreachable(p.Digest, "dockerflux") {
		t.Fatal("released twice")
	}
}

// Review m62b L1: the AuthorizeRun RPC reserves a host and nothing records
// its outcome, so for a staged permit it would hold the stage open with a
// host that no Skip can clear. Staged permits refuse it; the host stays
// runnable and skippable.
func TestAuthorizeRPCRefusesStagedPermits(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	e.openSession()
	p := e.staged(canonical.RiskLow, stg("one", 0, 1, stageplan.ContinueManual, "dockerflux", "strompi"), stg("two", 0, 0, stageplan.ContinueManual, "web"))
	wantCode(t, e.auth.Authorize(p.Digest, goodRun("dockerflux", fpA)), CodeStagePlan)
	if err := e.auth.CommitGate(p.Digest, Gate{Kind: GateSkipHost, Host: "dockerflux"}, nil); err != nil {
		t.Fatalf("skip after a refused AuthorizeRun: %v", err)
	}
	e.run(p, "strompi", OutcomeSucceeded)
	if _, err := e.auth.BeginGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 2}); err != nil {
		t.Fatalf("stage one should have passed: %v", err)
	}

	// A permit without stages keeps the M0 behaviour: authorize and reserve.
	q := e.propose(e.request(canonical.RiskLow))
	if err := e.auth.Authorize(q.Digest, goodRun("dockerflux", fpA)); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.auth.Authorize(q.Digest, goodRun("dockerflux", fpA)), CodeHostAlreadyRun)
}
