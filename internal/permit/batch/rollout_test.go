// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// isCode reports whether err carries the given permit code.
func isCode(err error, code permit.Code) bool {
	return permit.CodeOf(err) == code
}

// specMember is one member of a test batch plan.
type specMember struct {
	id       string
	host     string
	risk     canonical.Risk
	stage    int
	action   string
	provider *canonical.BatchProviderTarget
}

// specStage is one stage of a test batch plan.
type specStage struct {
	id            string
	gate          string
	postchecks    []string
	failThresh    int
	unreachThresh int
}

// planSpec is a test batch plan: stages, members and dependencies.
type planSpec struct {
	batchID string
	stages  []specStage
	members []specMember
	deps    []canonical.BatchDependency
}

// buildPlan builds a canonical batch from a spec and returns it with the
// member inputs needed to propose it.
func buildPlan(t *testing.T, e *environment, spec planSpec) (canonical.Batch, []MemberInput) {
	t.Helper()
	b := canonical.Batch{
		BatchVersion: canonical.BatchVersion,
		BatchID:      spec.batchID,
		ExpiryUnix:   e.unix.Load() + 3600,
		StagePlan: canonical.BatchStagePlan{
			Stages:       make([]canonical.BatchStage, len(spec.stages)),
			Dependencies: spec.deps,
		},
	}
	if b.StagePlan.Dependencies == nil {
		b.StagePlan.Dependencies = []canonical.BatchDependency{}
	}
	for i, ss := range spec.stages {
		pc := ss.postchecks
		if pc == nil {
			pc = []string{}
		}
		b.StagePlan.Stages[i] = canonical.BatchStage{
			StageID:              ss.id,
			Gate:                 ss.gate,
			RequiredPostchecks:   pc,
			FailureThreshold:     ss.failThresh,
			UnreachableThreshold: ss.unreachThresh,
		}
	}
	var inputs []MemberInput
	for i, ms := range spec.members {
		art := []byte("#!/bin/sh\necho ready\n")
		params := []byte(`{"approved":true}`)
		ph, err := canonical.HashParameters(params)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(art)
		action := ms.action
		if action == "" {
			action = "package.upgrade"
		}
		m := canonical.BatchMember{
			MemberID: ms.id,
			Request: canonical.Request{
				RequestVersion: canonical.RequestVersion,
				ExecutionID:    fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10),
				ActionID:       action,
				ModuleVersion:  "1.0.0",
				ArtifactSHA256: canonical.Digest(h).String(),
				ParametersHash: ph,
				CredentialRefs: []string{"admin-key"},
				RiskClass:      ms.risk,
				ExpiryUnix:     b.ExpiryUnix,
			},
			CredentialVersions: []canonical.CredentialVersion{{Reference: "admin-key", Version: 1}},
			PreconditionHashes: []string{},
		}
		if ms.provider != nil {
			m.ProviderTarget = ms.provider
			m.Request.ResolvedTargets = []canonical.Target{}
		} else {
			m.Request.ResolvedTargets = []canonical.Target{{HostID: ms.host, HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
		}
		b.Members = append(b.Members, m)
		b.StagePlan.Stages[ms.stage].MemberIDs = append(b.StagePlan.Stages[ms.stage].MemberIDs, ms.id)
		inputs = append(inputs, MemberInput{MemberID: ms.id, Artifact: art, ParametersJSON: params})
		e.policy.set(ms.id, Snapshot{Risk: ms.risk, Trust: sha256.Sum256([]byte(ms.id))})
	}
	h, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = h.String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = h.String()
	}
	return b, inputs
}

// proposePlan builds and proposes a batch from a spec.
func proposePlan(t *testing.T, e *environment, spec planSpec) Approval {
	t.Helper()
	b, inputs := buildPlan(t, e, spec)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.a.Propose(ctx, raw, inputs)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A member in a stage that is not open yet is not claimable; once the open
// stage passes and its gate is automatic, the next stage opens and its member
// becomes claimable.
func TestMemberBehindUnopenedStageGateNotClaimable(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages: []specStage{
			{id: "first", gate: canonical.BatchGateAutomatic},
			{id: "second", gate: canonical.BatchGateManual},
		},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0},
			{id: "member-1", host: "host-1", risk: canonical.RiskLow, stage: 1},
		},
	}
	p := proposePlan(t, e, spec)
	if p.State != permit.StateApproved {
		t.Fatalf("state = %v, want approved", p.State)
	}
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeStageNotOpen)
	// member-0 succeeds; stage 0's gate is automatic, so stage 1 opens.
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after stage 1 opened: %v", err)
	}
}

// A member whose dependency has not succeeded is not claimable; once the
// dependency succeeds it becomes claimable.
func TestMemberWithUnfinishedDependencyNotClaimable(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual}},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0},
			{id: "member-1", host: "host-1", risk: canonical.RiskLow, stage: 0},
		},
		deps: []canonical.BatchDependency{{MemberID: "member-1", DependsOn: []string{"member-0"}}},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, CodeDependencyNotMet)
	// member-0 succeeds; member-1's dependency is satisfied.
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after dependency satisfied: %v", err)
	}
}

// A member on a host where another member is running is not claimable; once
// the first member finishes the host is free and the member becomes claimable.
func TestMemberOnBusyHostNotClaimable(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual}},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0, action: "package.upgrade"},
			{id: "member-1", host: "host-0", risk: canonical.RiskLow, stage: 0, action: "package.install"},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, CodeHostBusy)
	// member-0 succeeds; the host is free.
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after host free: %v", err)
	}
}

// Two provider members on the same node and VM never run at once; different
// VMs on the same node may.
func TestProviderMemberOnBusyVMNotClaimable(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	pin := canonical.Digest(sha256.Sum256([]byte("pin"))).String()
	prov := func() *canonical.BatchProviderTarget {
		return &canonical.BatchProviderTarget{
			RemoteID: "remote-1", Kind: "qemu", Node: "pve-1", VMID: 100,
			Generation: 1, Pin: pin, TrustGeneration: 1,
			APIEndpoints: []string{"https://pve-1.example.com"},
		}
	}
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual}},
		members: []specMember{
			{id: "member-0", risk: canonical.RiskLow, stage: 0, action: "package.upgrade", provider: prov()},
			{id: "member-1", risk: canonical.RiskLow, stage: 0, action: "package.install", provider: prov()},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, CodeHostBusy)
	// member-0 succeeds; the VM is free.
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after VM free: %v", err)
	}
}

// A stage is not passed until its required postchecks are recorded, so the
// next stage does not open and its member is not claimable.
func TestStagePostcheckRequiredBeforeNextStage(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	pc := canonical.Digest(sha256.Sum256([]byte("health"))).String()
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages: []specStage{
			{id: "first", gate: canonical.BatchGateAutomatic, postchecks: []string{pc}},
			{id: "second", gate: canonical.BatchGateManual},
		},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0},
			{id: "member-1", host: "host-1", risk: canonical.RiskLow, stage: 1},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	// member-0 succeeds but the postcheck is not recorded: stage 0 is not passed.
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeStageNotOpen)
	// Record the postcheck; stage 0 passes and its automatic gate opens stage 1.
	e.a.RecordPostcheck(p.Plan.Members[0].Request.ExecutionID, "member-0", pc)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after postcheck: %v", err)
	}
}

// When an open stage has more failures than its threshold allows, the rollout
// stops and no further member is claimable.
func TestRolloutStopsOnFailureThreshold(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual, failThresh: 0}},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0},
			{id: "member-1", host: "host-1", risk: canonical.RiskLow, stage: 0},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	// member-0 fails; the threshold is 0, so the rollout stops.
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeFailed)
	r, err := e.a.Rollout(p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if r.Stopped == "" {
		t.Fatal("rollout not stopped after failure beyond threshold")
	}
	_, err = e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeRolloutStopped)
}

// An unreachable member of the open stage can be skipped (audited); skipping
// records the skipped outcome and frees the host.
func TestSkipUnreachableMember(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual}},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeUnreachable)
	// Skipping a member that already has a final outcome is rejected.
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); !isCode(err, permit.CodeWrongState) {
		t.Fatalf("re-claim = %v, want already claimed", err)
	}
	// Skip member-0 (LOW gate: privileged session).
	if err := e.a.CommitGate(ctx, p.Digest, Gate{Kind: GateSkipMember, MemberID: "member-0"}, nil); err != nil {
		t.Fatalf("skip gate: %v", err)
	}
	r, err := e.a.Rollout(p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if r.Stages[0].Outcomes["member-0"] != permit.OutcomeSkipped {
		t.Fatalf("member-0 outcome = %s, want skipped", r.Stages[0].Outcomes["member-0"])
	}
}

// Aborting the rollout makes no further member claimable and no gate applies.
func TestAbortStopsClaims(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual}},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskLow, stage: 0},
		},
	}
	p := proposePlan(t, e, spec)
	if err := e.a.Abort(p.Digest, "operator"); err != nil {
		t.Fatalf("abort: %v", err)
	}
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
	wantCode(t, err, permit.CodeRolloutAborted)
	if _, err := e.a.BeginGate(p.Digest, Gate{Kind: GateSkipMember, MemberID: "member-0"}); !isCode(err, permit.CodeRolloutAborted) {
		t.Fatalf("gate after abort = %v, want aborted", err)
	}
}

// A HIGH batch gate needs a fresh WebAuthn assertion bound to the batch digest
// and stage number; committing without the assertion is rejected.
func TestHighGateRequiresFreshUV(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages: []specStage{
			{id: "first", gate: canonical.BatchGateManual},
			{id: "second", gate: canonical.BatchGateManual},
		},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskHigh, stage: 0},
			{id: "member-1", host: "host-1", risk: canonical.RiskHigh, stage: 1},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	// Stage 0 passed but its manual gate waits: member-1 is not claimable.
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeStageNotOpen)
	// The HIGH gate needs a fresh UV assertion.
	ch, err := e.a.BeginGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 2})
	if err != nil {
		t.Fatalf("BeginGate: %v", err)
	}
	if ch.Requirement != permit.RequireAssertionVerified || len(ch.Challenge) == 0 {
		t.Fatalf("gate = %+v, want assertion challenge", ch)
	}
	// Committing without the assertion is rejected.
	if err := e.a.CommitGate(ctx, p.Digest, Gate{Kind: GateOpenStage, Stage: 2}, nil); !isCode(err, permit.CodeAssertionRejected) {
		t.Fatalf("commit without assertion = %v, want rejected", err)
	}
	// A fresh challenge is needed after a failed commit.
	ch, err = e.a.BeginGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 2})
	if err != nil {
		t.Fatalf("BeginGate retry: %v", err)
	}
	if err := e.a.CommitGate(ctx, p.Digest, Gate{Kind: GateOpenStage, Stage: 2}, e.sign(ch.Challenge)); err != nil {
		t.Fatalf("CommitGate: %v", err)
	}
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after gate: %v", err)
	}
}

// In hardened mode a HIGH batch gate is committed only by the local admin via
// the CLI; the web commit is rejected.
func TestHighGateHardenedRequiresCLI(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages: []specStage{
			{id: "first", gate: canonical.BatchGateManual},
			{id: "second", gate: canonical.BatchGateManual},
		},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskHigh, stage: 0},
			{id: "member-1", host: "host-1", risk: canonical.RiskHigh, stage: 1},
		},
	}
	p := proposePlan(t, e, spec)
	if p.Requirement != permit.RequireCLI {
		t.Fatalf("requirement = %s, want CLI", p.Requirement)
	}
	if _, err := e.a.ApproveCLI(ctx, p.Digest, 1000); err != nil {
		t.Fatalf("ApproveCLI: %v", err)
	}
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatalf("member-0 claim: %v", err)
	}
	e.a.RecordOutcome(p.Plan.Members[0].Request.ExecutionID, "member-0", permit.OutcomeSucceeded)
	_, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeStageNotOpen)
	ch, err := e.a.BeginGate(p.Digest, Gate{Kind: GateOpenStage, Stage: 2})
	if err != nil {
		t.Fatalf("BeginGate: %v", err)
	}
	if ch.Requirement != permit.RequireCLI {
		t.Fatalf("gate requirement = %s, want CLI", ch.Requirement)
	}
	// The web commit is rejected in hardened mode.
	if err := e.a.CommitGate(ctx, p.Digest, Gate{Kind: GateOpenStage, Stage: 2}, nil); !isCode(err, permit.CodeCLIRequired) {
		t.Fatalf("web commit = %v, want CLI required", err)
	}
	// The local admin opens the stage via the CLI.
	if err := e.a.ApproveGateCLI(p.Digest, Gate{Kind: GateOpenStage, Stage: 2}, 1000); err != nil {
		t.Fatalf("ApproveGateCLI: %v", err)
	}
	if _, err := e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1]); err != nil {
		t.Fatalf("member-1 claim after CLI gate: %v", err)
	}
}

// A non-admin cannot open a batch gate via the CLI.
func TestGateCLIRequiresAdmin(t *testing.T) {
	e := setup(t, permit.ModeHardened)
	spec := planSpec{
		batchID: "00000000-0000-4000-8000-000000000001",
		stages:  []specStage{{id: "first", gate: canonical.BatchGateManual}},
		members: []specMember{
			{id: "member-0", host: "host-0", risk: canonical.RiskHigh, stage: 0},
		},
	}
	p := proposePlan(t, e, spec)
	if _, err := e.a.ApproveCLI(ctx, p.Digest, 1000); err != nil {
		t.Fatalf("ApproveCLI: %v", err)
	}
	if err := e.a.ApproveGateCLI(p.Digest, Gate{Kind: GateOpenStage, Stage: 2}, 1001); !errors.Is(err, ErrAdminRequired) {
		t.Fatalf("non-admin gate = %v, want admin required", err)
	}
}
