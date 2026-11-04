// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func (f *fakeBatchRPC) RunBatchMember(_ context.Context, in *pb.RunBatchMemberRequest, _ ...grpc.CallOption) (*pb.RunBatchMemberResponse, error) {
	f.mu.Lock()
	f.runs = append(f.runs, in)
	answer := f.answer
	f.mu.Unlock()
	if answer != nil {
		return answer(in)
	}
	return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS, Class: "success"}, nil
}

func (f *fakeBatchRPC) GetRollout(context.Context, *pb.GetRolloutRequest, ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &pb.GetRolloutResponse{Rollout: &pb.Rollout{OpenStage: f.openStage}}, nil
}

func (f *fakeBatchRPC) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

// approvedBatch proposes and approves a plan of one member per stage (the
// deployment plan's shape) on the wiring host with gate.
func approvedBatch(t *testing.T, b deployBatches, gate string, actionIDs ...string) executions.BatchView {
	t.Helper()
	ctx := context.Background()
	var req executions.BatchRequest
	for _, id := range actionIDs {
		req.Stages = append(req.Stages, executions.BatchStageSpec{Gate: gate, Members: []executions.BatchMemberSpec{{ActionID: id, HostID: wiringHost}}})
	}
	c, err := b.ProposeBatch(ctx, "alice", req)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ApproveBatch(ctx, "alice", c.ID, []byte(`{"id":"x"}`)); err != nil {
		t.Fatal(err)
	}
	v, err := b.Batch(ctx, c.ID)
	if err != nil || v.State != "approved" {
		t.Fatalf("batch %+v %v", v, err)
	}
	return v
}

func newRunner(f *fakeBatchRPC, b deployBatches) *batchRunner {
	return &batchRunner{batches: b.Batches, exec: serverBatchExecutor{client: func() batchRPC { return f }}, hosts: wiringHosts{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func script(t *testing.T, id string) []byte {
	t.Helper()
	a, ok := actions.Lookup(id)
	if !ok {
		t.Fatalf("no built-in %s", id)
	}
	return a.Script
}

// The runner hands an approved plan's members to the executor one at a
// time in plan order, each naming only the digest and member with the exact
// approved script and the host's endpoints; results are recorded and the
// batch completes. A finished batch is never handed over again.
func TestBatchRunnerRunsApprovedMembersInOrder(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh", "package.install_all")
	r := newRunner(f, b)
	// The executor opens stage 2 once stage 1 succeeded.
	f.answer = func(in *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
		f.mu.Lock()
		f.openStage = 2
		f.mu.Unlock()
		return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS, Class: "success"}, nil
	}
	ctx := context.Background()
	if n := r.runOnce(ctx); n != 2 {
		t.Fatalf("handed over %d members, want 2", n)
	}
	for i, id := range []string{"package.refresh", "package.install_all"} {
		got := f.runs[i]
		sum := sha256.Sum256(got.GetArtifact())
		if got.GetBatchDigest() != v.Digest || got.GetMemberId() != v.Members[i].MemberID || string(got.GetArtifact()) != string(script(t, id)) ||
			hex.EncodeToString(sum[:]) != v.Members[i].ArtifactSHA256 || len(got.GetEndpoints()) != 1 || got.GetEndpoints()[0] != "192.168.10.50:22" {
			t.Fatalf("run %d = %+v", i, got)
		}
	}
	after, err := b.Batch(ctx, v.ID)
	if err != nil || after.Counts.Success != 2 || after.Summary != "succeeded" {
		t.Fatalf("after: %+v %v", after.Counts, err)
	}
	if n := r.runOnce(ctx); n != 0 || f.runCount() != 2 {
		t.Fatalf("finished batch handed over again: %d", n)
	}
}

// A failed member stops the batch under the default zero threshold: the
// next member is never handed over and ends not executed.
func TestBatchRunnerFailureStops(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 2}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh", "package.install_all")
	f.answer = func(*pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
		return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE, Class: "script_failed", ExitCode: 1}, nil
	}
	r := newRunner(f, b)
	r.runOnce(context.Background())
	after, err := b.Batch(context.Background(), v.ID)
	if err != nil || f.runCount() != 1 || after.Members[0].Outcome != executions.OutcomeFailed || after.Members[1].Outcome != executions.OutcomeNotExecuted {
		t.Fatalf("after failure: %d runs, %+v %v", f.runCount(), after.Members, err)
	}
}

// The executor's answer decides the server's record: a refusal status means
// nothing ran (failed, "not executed"); a lost answer is unknown (never
// redispatched); a claimed but revoked member is not executed; an
// unreachable host is a failure counted as unreachable.
func TestBatchRunnerRecordsExecutorAnswers(t *testing.T) {
	for _, tc := range []struct {
		name        string
		resp        *pb.RunBatchMemberResponse
		err         error
		outcome     string
		unreachable bool
		detail      string
	}{
		{"refused", nil, status.Error(codes.PermissionDenied, "rollout_stopped: stage 1"), executions.OutcomeFailed, false, "not executed: the executor refused"},
		{"lost", nil, status.Error(codes.Unavailable, "connection reset"), executions.OutcomeUnknown, false, "never redispatched"},
		{"deadline", nil, status.Error(codes.DeadlineExceeded, "deadline"), executions.OutcomeUnknown, false, "never redispatched"},
		{"not executed", &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED, Class: "not_executed",
			Detail: "credential rotated"}, nil, executions.OutcomeFailed, false, "not executed: not_executed: credential rotated"},
		{"unknown", &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN, Class: "unknown"}, nil, executions.OutcomeUnknown, false, "unknown"},
		{"unreachable", &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE, Class: "network_unreachable",
			Unreachable: true}, nil, executions.OutcomeFailed, true, "network_unreachable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeBatchRPC{execution: true, openStage: 1}
			b, _ := newWiringBatches(t, f)
			v := approvedBatch(t, b, "automatic", "package.refresh")
			f.answer = func(*pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) { return tc.resp, tc.err }
			newRunner(f, b).runOnce(context.Background())
			after, err := b.Batch(context.Background(), v.ID)
			if err != nil {
				t.Fatal(err)
			}
			m := after.Members[0]
			if m.Outcome != tc.outcome || m.Unreachable != tc.unreachable || !strings.Contains(m.Detail, tc.detail) {
				t.Fatalf("member = %+v", m)
			}
		})
	}
}

// A member behind a closed manual gate waits: nothing is marked dispatched
// or handed over until the executor opens the stage.
func TestBatchRunnerWaitsForGate(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "manual", "package.refresh", "package.install_all")
	r := newRunner(f, b)
	ctx := context.Background()
	if n := r.runOnce(ctx); n != 1 {
		t.Fatalf("handed over %d, want only stage 1", n)
	}
	after, _ := b.Batch(ctx, v.ID)
	if after.Members[1].Outcome != executions.OutcomePlanned {
		t.Fatalf("gated member = %+v", after.Members[1])
	}
	f.mu.Lock()
	f.openStage = 2
	f.mu.Unlock()
	if n := r.runOnce(ctx); n != 1 || f.runCount() != 2 {
		t.Fatalf("after the gate opened: %d, %d runs", n, f.runCount())
	}
}

// Without an executor connection nothing is marked dispatched.
func TestBatchRunnerWithoutExecutor(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh")
	r := newRunner(f, b)
	r.exec = serverBatchExecutor{client: func() batchRPC { return nil }}
	if n := r.runOnce(context.Background()); n != 0 {
		t.Fatalf("handed over %d", n)
	}
	after, _ := b.Batch(context.Background(), v.ID)
	if after.Members[0].Outcome != executions.OutcomePlanned {
		t.Fatalf("member = %+v", after.Members[0])
	}
}

// A member whose script on this server no longer matches the approved
// artifact is never handed over: it fails closed as not executed.
func TestBatchRunnerRefusesChangedArtifact(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh")
	m := v.Members[0]
	m.ArtifactSHA256 = strings.Repeat("0", 64)
	if newRunner(f, b).runMember(context.Background(), v, m) {
		t.Fatal("the batch continues after a changed artifact")
	}
	after, _ := b.Batch(context.Background(), v.ID)
	if f.runCount() != 0 || after.Members[0].Outcome != executions.OutcomeFailed || !strings.Contains(after.Members[0].Detail, "not executed") {
		t.Fatalf("changed artifact: %d runs, %+v", f.runCount(), after.Members[0])
	}
}
