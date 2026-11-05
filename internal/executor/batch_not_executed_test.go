// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func notExecutedReq(digest string, i int, reason string) *pb.RunBatchMemberRequest {
	return &pb.RunBatchMemberRequest{BatchDigest: digest, MemberId: "member-" + string(rune('0'+i)), NotExecutedReason: reason}
}

// A member the server cannot hand over is reported: the executor spends it
// without running anything (no script, no run record), audits the reason,
// answers not executed, and the rollout applies the stop policy, so the
// next stage never opens. The member can never run afterwards.
func TestRunBatchMemberNotExecutedReportSpendsMember(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true,
		dispatchMember{host: "web-1"}, dispatchMember{host: "web-1", stage: 1})
	resp, err := e.server.RunBatchMember(ctx, notExecutedReq(d, 0, "the host has no endpoint"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED || resp.GetClass() != classBatchNotExecuted ||
		resp.GetExecutionId() != members[0].Request.ExecutionID || !strings.Contains(resp.GetDetail(), "the host has no endpoint") {
		t.Fatalf("report: %+v %v", resp, err)
	}
	if e.attached.count() != 0 {
		t.Fatal("a reported member ran")
	}
	if _, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err == nil {
		t.Fatal("a reported member left a run record")
	}
	if len(e.logs.find("batch_member_not_executed", members[0].Request.ExecutionID)) != 1 {
		t.Error("report not audited")
	}
	// Spent: the member never runs, nor is it reported twice.
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 0)
	if _, err := e.server.RunBatchMember(ctx, notExecutedReq(d, 0, "again")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second report: %v", err)
	}
	// The zero threshold stopped the rollout.
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 1, "web-1"))
	e.requireRefused(t, err, codes.PermissionDenied, members[1], 0)
}

// A malformed report is refused before anything is claimed: the member
// stays unspent and runs afterwards.
func TestRunBatchMemberNotExecutedReportRefusals(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	cases := []struct {
		name string
		mut  func(*pb.RunBatchMemberRequest)
		code codes.Code
	}{
		{"oversize reason", func(r *pb.RunBatchMemberRequest) {
			r.NotExecutedReason = strings.Repeat("x", maxBatchNotExecutedReason+1)
		}, codes.InvalidArgument},
		{"reason with a newline", func(r *pb.RunBatchMemberRequest) { r.NotExecutedReason = "x\naudit kind=forged" }, codes.InvalidArgument},
		{"reason with a control character", func(r *pb.RunBatchMemberRequest) { r.NotExecutedReason = "x\x1b[2J" }, codes.InvalidArgument},
		{"with an artifact", func(r *pb.RunBatchMemberRequest) { r.Artifact = dispatchArtifact(n, 0) }, codes.InvalidArgument},
		{"with endpoints", func(r *pb.RunBatchMemberRequest) { r.Endpoints = []string{e.ssh["web-1"].addr} }, codes.InvalidArgument},
		{"with a timeout", func(r *pb.RunBatchMemberRequest) { r.TimeoutSeconds = 60 }, codes.InvalidArgument},
		{"bad digest", func(r *pb.RunBatchMemberRequest) { r.BatchDigest = "x" }, codes.InvalidArgument},
		{"unknown batch", func(r *pb.RunBatchMemberRequest) { r.BatchDigest = strings.Repeat("0", 64) }, codes.NotFound},
		{"unknown member", func(r *pb.RunBatchMemberRequest) { r.MemberId = "member-9" }, codes.NotFound},
		{"no member", func(r *pb.RunBatchMemberRequest) { r.MemberId = "" }, codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := notExecutedReq(d, 0, "the host is not in the inventory")
			c.mut(req)
			_, err := e.server.RunBatchMember(ctx, req)
			e.requireRefused(t, err, c.code, members[0], 0)
		})
	}
	t.Run("reason not UTF-8", func(t *testing.T) {
		// gRPC refuses it on the wire; a direct call is refused too.
		_, err := e.svc.RunBatchMember(ctx, notExecutedReq(d, 0, "\xff"))
		e.requireRefused(t, err, codes.InvalidArgument, members[0], 0)
	})
	if len(e.logs.find("batch_member_not_executed", members[0].Request.ExecutionID)) != 0 {
		t.Fatal("a refused report was audited as not executed")
	}
	resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS || e.attached.count() != 1 {
		t.Fatalf("after refused reports: %+v %v", resp, err)
	}
}
