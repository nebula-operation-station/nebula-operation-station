// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeBatch is the executor as the admin CLI sees it: a complete review, a
// CLI approval and the gate methods, each call recorded.
type fakeBatch struct {
	pb.ExecutorServiceClient
	review   *pb.ReviewBatchResponse
	pending  []*pb.PendingPermit
	rollout  *pb.Rollout
	approved []string
	gates    []*pb.ApproveGateCLIRequest
	gateErr  error
}

func (f *fakeBatch) ListPending(context.Context, *pb.ListPendingRequest, ...grpc.CallOption) (*pb.ListPendingResponse, error) {
	return &pb.ListPendingResponse{Permits: f.pending}, nil
}

func (f *fakeBatch) ReviewBatch(_ context.Context, in *pb.ReviewBatchRequest, _ ...grpc.CallOption) (*pb.ReviewBatchResponse, error) {
	if f.review == nil || in.GetBatchDigest() != f.review.GetBatchDigest() {
		return nil, grpcstatus.Error(codes.NotFound, "batch approval not found")
	}
	return f.review, nil
}

func (f *fakeBatch) ApproveBatchCLI(_ context.Context, in *pb.ApproveBatchCLIRequest, _ ...grpc.CallOption) (*pb.ApproveBatchCLIResponse, error) {
	f.approved = append(f.approved, in.GetBatchDigest())
	return &pb.ApproveBatchCLIResponse{State: pb.PermitState_PERMIT_STATE_APPROVED, ApprovedBy: "cli:1000"}, nil
}

func (f *fakeBatch) GetRollout(context.Context, *pb.GetRolloutRequest, ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	if f.rollout == nil {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "batch approval is in the wrong state")
	}
	return &pb.GetRolloutResponse{Rollout: f.rollout}, nil
}

func (f *fakeBatch) ApproveGateCLI(_ context.Context, in *pb.ApproveGateCLIRequest, _ ...grpc.CallOption) (*pb.ApproveGateCLIResponse, error) {
	if f.gateErr != nil {
		return nil, f.gateErr
	}
	f.gates = append(f.gates, in)
	return &pb.ApproveGateCLIResponse{Rollout: f.rollout}, nil
}

var protoRisk = map[canonical.Risk]pb.RiskClass{
	canonical.RiskLow: pb.RiskClass_RISK_CLASS_LOW, canonical.RiskMedium: pb.RiskClass_RISK_CLASS_MEDIUM,
	canonical.RiskHigh: pb.RiskClass_RISK_CLASS_HIGH, canonical.RiskCritical: pb.RiskClass_RISK_CLASS_CRITICAL,
}

// batchReview builds the executor's review of a canonical plan with n
// members, members 0..n-2 in stage "canary" and the last one in "rest"
// depending on member-0, exactly as ReviewBatch returns it.
func batchReview(t *testing.T, n int, risk canonical.Risk) *pb.ReviewBatchResponse {
	t.Helper()
	expiry := time.Now().Add(time.Hour).Unix()
	b := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: "00000000-0000-4000-8000-000000000001", ExpiryUnix: expiry,
		StagePlan: canonical.BatchStagePlan{Stages: []canonical.BatchStage{
			{StageID: "canary", Gate: canonical.BatchGateManual, RequiredPostchecks: []string{}},
			{StageID: "rest", Gate: canonical.BatchGateManual, FailureThreshold: 1, RequiredPostchecks: []string{strings.Repeat("e", 64)}},
		}, Dependencies: []canonical.BatchDependency{}}}
	rev := &pb.ReviewBatchResponse{Risk: protoRisk[risk], State: pb.PermitState_PERMIT_STATE_PENDING, ApprovalExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}
	for i := range n {
		id := fmt.Sprintf("member-%d", i)
		params := []byte(fmt.Sprintf(`{"package":"pkg-%d"}`, i))
		ph, err := canonical.HashParameters(params)
		if err != nil {
			t.Fatal(err)
		}
		art := sha256.Sum256([]byte(id))
		b.Members = append(b.Members, canonical.BatchMember{MemberID: id, Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10), ActionID: "package.upgrade", ModuleVersion: "1.0.0",
			ArtifactSHA256: canonical.Digest(art).String(), ParametersHash: ph, CredentialRefs: []string{"admin-key"}, RiskClass: risk, ExpiryUnix: expiry,
			ResolvedTargets: []canonical.Target{{HostID: fmt.Sprintf("host-%03d", i), HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)}}},
			CredentialVersions: []canonical.CredentialVersion{{Reference: "admin-key", Version: 7}}, PreconditionHashes: []string{}})
		stage := 0
		if i == n-1 && n > 1 {
			stage = 1
			b.StagePlan.Dependencies = append(b.StagePlan.Dependencies, canonical.BatchDependency{MemberID: id, DependsOn: []string{"member-0"}})
		}
		b.StagePlan.Stages[stage].MemberIDs = append(b.StagePlan.Stages[stage].MemberIDs, id)
		rev.MemberParameters = append(rev.MemberParameters, params)
		rev.MemberFindings = append(rev.MemberFindings, &pb.BatchMemberFindings{})
	}
	if n == 1 {
		b.StagePlan.Stages = b.StagePlan.Stages[:1]
	}
	h, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = h.String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = h.String()
	}
	plan, raw, d, err := canonical.CanonicalizeBatch(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rev.BatchDigest, rev.CanonicalBatch = d.String(), raw
	rev.Plan = &pb.BatchPlan{BatchId: plan.BatchID, BatchVersion: plan.BatchVersion, ExpiryUnix: plan.ExpiryUnix, StagePlanHash: plan.StagePlanHash}
	for _, m := range plan.Members {
		rev.Plan.Members = append(rev.Plan.Members, &pb.BatchMember{MemberId: m.MemberID, ActionId: m.Request.ActionID, ModuleVersion: m.Request.ModuleVersion,
			Risk: protoRisk[m.Request.RiskClass], ExecutionId: m.Request.ExecutionID, ArtifactSha256: m.Request.ArtifactSHA256, ParametersHash: m.Request.ParametersHash,
			StagePlanHash: m.Request.StagePlanHash, HostIds: []string{m.Request.ResolvedTargets[0].HostID}, CredentialRefs: m.Request.CredentialRefs})
	}
	return rev
}

// The local approval shows every member of a full-size batch with its exact
// target, executor risk, parameters, credential versions and the stage graph,
// then approves the digest once.
func TestBatchApproveShowsEveryMember(t *testing.T) {
	rev := batchReview(t, canonical.MaxBatchMembers, canonical.RiskHigh)
	rev.MemberFindings[42].Findings = []*pb.BatchFinding{{Category: "curl-pipe", Risk: pb.RiskClass_RISK_CLASS_HIGH, Line: 4, Excerpt: "curl x | sh"}}
	f := &fakeBatch{review: rev}
	var out bytes.Buffer
	if err := runBatch(f, []string{"approve", rev.GetBatchDigest()}, "yes\n", &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(f.approved) != 1 || f.approved[0] != rev.GetBatchDigest() {
		t.Fatalf("approved %v", f.approved)
	}
	s := out.String()
	for i := range canonical.MaxBatchMembers {
		for _, want := range []string{
			fmt.Sprintf("member %d/%d  member-%d\n", i+1, canonical.MaxBatchMembers, i),
			fmt.Sprintf("host-%03d  SHA256:%s", i, strings.Repeat("A", 43)),
			fmt.Sprintf(`{"package":"pkg-%d"}`, i),
			fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10),
		} {
			if !strings.Contains(s, want) {
				t.Fatalf("output misses %q", want)
			}
		}
	}
	for _, want := range []string{
		"risk           HIGH (executor)",
		"100 members, 2 stages, 1 dependencies, 100 hosts",
		"admin-key v7",
		"curl-pipe (HIGH) at line 4: curl x | sh",
		"stage 2/2 rest  gate manual, max failed 1, max unreachable 0",
		"postcheck " + strings.Repeat("e", 64),
		"member-99 after member-0",
		"approved by cli:1000",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output misses %q", want)
		}
	}
	if strings.Count(s, "safety scanner no findings") != canonical.MaxBatchMembers-1 {
		t.Errorf("scanner verdict missing for some members")
	}
}

// `nebula approve <batch digest>` (ADR 0007) reaches the batch when no
// pending single permit has that digest; a short prefix never selects a batch.
func TestApproveFullDigestFallsBackToBatch(t *testing.T) {
	rev := batchReview(t, 2, canonical.RiskHigh)
	f := &fakeBatch{review: rev}
	var out bytes.Buffer
	if err := approve(context.Background(), f, rev.GetBatchDigest(), strings.NewReader("yes\n"), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(f.approved) != 1 {
		t.Fatalf("batch not approved: %v", f.approved)
	}
	f.approved = nil
	if err := approve(context.Background(), f, rev.GetBatchDigest()[:16], strings.NewReader("yes\n"), &bytes.Buffer{}); err == nil || len(f.approved) != 0 {
		t.Fatalf("prefix approved a batch: %v %v", err, f.approved)
	}
}

// Nothing is approved without the typed confirmation, for a plan that is not
// pending, or when the executor's view is not complete and self-consistent.
func TestBatchApproveRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate  func(*pb.ReviewBatchResponse)
		answer  string
		wantErr string
	}{
		"no confirmation":  {answer: "y\n", wantErr: "not approved"},
		"empty input":      {answer: "", wantErr: "not approved"},
		"already approved": {mutate: func(r *pb.ReviewBatchResponse) { r.State = pb.PermitState_PERMIT_STATE_APPROVED }, answer: "yes\n", wantErr: "not pending"},
		"critical":         {mutate: func(r *pb.ReviewBatchResponse) { r.Risk = pb.RiskClass_RISK_CLASS_CRITICAL }, answer: "yes\n", wantErr: "CRITICAL"},
		"digest mismatch": {mutate: func(r *pb.ReviewBatchResponse) {
			r.CanonicalBatch = batchReview(t, 3, canonical.RiskHigh).GetCanonicalBatch()
		}, answer: "yes\n", wantErr: "does not match"},
		"missing parameters":   {mutate: func(r *pb.ReviewBatchResponse) { r.MemberParameters = r.MemberParameters[:1] }, answer: "yes\n", wantErr: "incomplete"},
		"missing findings":     {mutate: func(r *pb.ReviewBatchResponse) { r.MemberFindings = nil }, answer: "yes\n", wantErr: "incomplete"},
		"truncated typed plan": {mutate: func(r *pb.ReviewBatchResponse) { r.Plan.Members = r.Plan.Members[:1] }, answer: "yes\n", wantErr: "incomplete"},
		"reordered typed plan": {mutate: func(r *pb.ReviewBatchResponse) {
			r.Plan.Members[0], r.Plan.Members[1] = r.Plan.Members[1], r.Plan.Members[0]
		}, answer: "yes\n", wantErr: "does not match"},
		"parameters differ from hash": {mutate: func(r *pb.ReviewBatchResponse) { r.MemberParameters[1] = []byte(`{"package":"evil"}`) }, answer: "yes\n", wantErr: "parameters"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rev := batchReview(t, 2, canonical.RiskHigh)
			if tc.mutate != nil {
				tc.mutate(rev)
			}
			f := &fakeBatch{review: rev}
			err := runBatch(f, []string{"approve", rev.GetBatchDigest()}, tc.answer, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if len(f.approved) != 0 {
				t.Fatal("approved despite refusal")
			}
		})
	}
	for _, args := range [][]string{{"approve"}, {"approve", "abc"}, {"approve", strings.Repeat("A", 64)}, {"frobnicate", strings.Repeat("a", 64)}} {
		if err := runBatch(&fakeBatch{}, args, "yes\n", &bytes.Buffer{}); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// Host-author and proposer text is shown escaped: no terminal control or
// bidi override reaches the approval screen.
func TestBatchReviewEscapesUntrustedText(t *testing.T) {
	rev := batchReview(t, 2, canonical.RiskMedium)
	rev.MemberFindings[0].Findings = []*pb.BatchFinding{{Category: "x\x1b[2J", Line: 1, Excerpt: "rm\u202e -rf"}}
	f := &fakeBatch{review: rev}
	var out bytes.Buffer
	if err := runBatch(f, []string{"review", rev.GetBatchDigest()}, "", &out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\u202e") {
		t.Fatalf("raw control text on screen: %q", out.String())
	}
	if len(f.approved) != 0 {
		t.Fatal("review approved")
	}
}

// Stage gates go through the admin-only CLI gate method with the exact batch
// digest after showing the executor's rollout; a skip names a member.
func TestBatchStageGates(t *testing.T) {
	rev := batchReview(t, 3, canonical.RiskHigh)
	rev.State = pb.PermitState_PERMIT_STATE_APPROVED
	ro := &pb.Rollout{OpenStage: 1, GateRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY, Stages: []*pb.StageStatus{
		{Open: true, Stage: &pb.PlanStage{Name: "canary", HostIds: []string{"member-0", "member-1"}, ContinueMode: "manual"},
			Outcomes: []*pb.HostOutcome{{HostId: "member-0", Outcome: "succeeded"}}},
		{Stage: &pb.PlanStage{Name: "rest", HostIds: []string{"member-2"}, MaxFailed: 1, ContinueMode: "manual"}},
	}}
	f := &fakeBatch{review: rev, rollout: ro}
	d := rev.GetBatchDigest()
	var out bytes.Buffer
	if err := runBatch(f, []string{"skip", "member-1", d}, "yes\n", &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if err := runBatch(f, []string{"stage", "2", d}, "yes\n", &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(f.gates) != 2 {
		t.Fatalf("gates %v", f.gates)
	}
	if g := f.gates[0]; g.GetExecutionDigest() != d || g.GetGate().GetKind() != pb.GateKind_GATE_KIND_SKIP_HOST || g.GetGate().GetHostId() != "member-1" || g.GetGate().GetStage() != 0 {
		t.Errorf("skip gate %+v", g)
	}
	if g := f.gates[1]; g.GetExecutionDigest() != d || g.GetGate().GetKind() != pb.GateKind_GATE_KIND_OPEN_STAGE || g.GetGate().GetStage() != 2 || g.GetGate().GetHostId() != "" {
		t.Errorf("stage gate %+v", g)
	}
	for _, want := range []string{"Skip member member-1", "Open stage 2", "canary", "member-0", "succeeded", "member-2"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output misses %q", want)
		}
	}

	// Refused locally: no confirmation, malformed input, a member not in the plan.
	refused := []struct {
		args   []string
		answer string
	}{
		{[]string{"stage", "2", d}, "no\n"},
		{[]string{"stage", "1", d}, "yes\n"},
		{[]string{"stage", "21", d}, "yes\n"},
		{[]string{"stage", "x", d}, "yes\n"},
		{[]string{"stage", "2", d[:16]}, "yes\n"},
		{[]string{"skip", "member-9", d}, "yes\n"},
		{[]string{"skip", "", d}, "yes\n"},
		{[]string{"skip", "member-1"}, "yes\n"},
	}
	for _, tc := range refused {
		f.gates = nil
		if err := runBatch(f, tc.args, tc.answer, &bytes.Buffer{}); err == nil || len(f.gates) != 0 {
			t.Errorf("%v %q: err %v gates %v", tc.args, tc.answer, err, f.gates)
		}
	}
	// The executor's refusal (e.g. another UID, a stage not passed) is returned.
	f.gateErr = grpcstatus.Error(codes.PermissionDenied, "batch approval requires the executor-local admin UID")
	if err := runBatch(f, []string{"stage", "2", d}, "yes\n", &bytes.Buffer{}); grpcstatus.Code(err) != codes.PermissionDenied {
		t.Fatalf("executor refusal: %v", err)
	}
}

// runBatch runs `nebula batch <args>` against a fake executor.
func runBatch(c pb.ExecutorServiceClient, args []string, answer string, out *bytes.Buffer) error {
	return batchCmd(context.Background(), c, args, strings.NewReader(answer), out)
}
