// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

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
	if in.GetNotExecutedReason() != "" {
		// A not-executed report is answered as the real executor does;
		// reportErr fails it instead.
		f.mu.Lock()
		err := f.reportErr
		f.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED, Class: "not_executed",
			Detail: "not executed: " + in.GetNotExecutedReason(), ExitCode: -1}, nil
	}
	if answer != nil {
		return answer(in)
	}
	return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS, Class: "success"}, nil
}

// reports are the not-executed reports among the RunBatchMember requests.
func (f *fakeBatchRPC) reports() []*pb.RunBatchMemberRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*pb.RunBatchMemberRequest
	for _, r := range f.runs {
		if r.GetNotExecutedReason() != "" {
			out = append(out, r)
		}
	}
	return out
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

// newRunner returns a runner that talks to f through the real executor
// client (gRPC over a Unix socket, with the client's error mapping).
func newRunner(t *testing.T, f *fakeBatchRPC, b deployBatches) *batchRunner {
	c := realClient(t, f)
	return &batchRunner{batches: b.Batches, exec: serverBatchExecutor{client: func() batchRPC { return c }}, hosts: wiringHosts{},
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
	r := newRunner(t, f, b)
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
	r := newRunner(t, f, b)
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
			newRunner(t, f, b).runOnce(context.Background())
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
	r := newRunner(t, f, b)
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
	r := newRunner(t, f, b)
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
// artifact is never handed over: it fails closed as not executed, and the
// executor is told so with a request that carries nothing that could run
// (no artifact, no endpoints), so its rollout does not stay open. If the
// executor cannot be told, the member still fails closed.
func TestBatchRunnerRefusesChangedArtifact(t *testing.T) {
	for _, reportErr := range []error{nil, status.Error(codes.Unavailable, "down")} {
		t.Run(fmt.Sprint(reportErr != nil), func(t *testing.T) {
			f := &fakeBatchRPC{execution: true, openStage: 1, reportErr: reportErr}
			b, _ := newWiringBatches(t, f)
			v := approvedBatch(t, b, "automatic", "package.refresh")
			m := v.Members[0]
			m.ArtifactSHA256 = strings.Repeat("0", 64)
			if newRunner(t, f, b).runMember(context.Background(), v, m) {
				t.Fatal("the batch continues after a changed artifact")
			}
			after, _ := b.Batch(context.Background(), v.ID)
			rep := f.reports()
			if f.runCount() != 1 || len(rep) != 1 || after.Members[0].Outcome != executions.OutcomeFailed ||
				!strings.Contains(after.Members[0].Detail, "not executed: the action's script differs") {
				t.Fatalf("changed artifact: %d runs, %d reports, %+v", f.runCount(), len(rep), after.Members[0])
			}
			if r := rep[0]; r.GetBatchDigest() != v.Digest || r.GetMemberId() != m.MemberID || len(r.GetArtifact()) != 0 ||
				len(r.GetEndpoints()) != 0 || r.GetTimeoutSeconds() != 0 || r.GetNotExecutedReason() != errBatchScriptChanged.Error() {
				t.Fatalf("report = %+v", r)
			}
		})
	}
}

// Every reason the server can give for a member it cannot hand over is
// one the executor accepts (printable, bounded).
func TestBatchNotExecutedReasonsAreValid(t *testing.T) {
	for _, err := range []error{errBatchActionMissing, errBatchVersionMissing, errBatchScriptChanged, errBatchHostMissing,
		errBatchHostNoEndpoint, errBatchTargetStaysBusy, errBatchHoldStoreDown} {
		r := err.Error()
		if r == "" || len(r) > 256 || strings.ContainsFunc(r, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			t.Errorf("reason %q", r)
		}
	}
}

// A member whose host is not in the inventory (or has no endpoint) is
// reported to the executor as not executed and stops the batch.
func TestBatchRunnerReportsMissingHost(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh", "package.install_all")
	r := newRunner(t, f, b)
	r.hosts = noHosts{}
	r.runOnce(context.Background())
	after, _ := b.Batch(context.Background(), v.ID)
	rep := f.reports()
	if f.runCount() != 1 || len(rep) != 1 || rep[0].GetNotExecutedReason() != errBatchHostMissing.Error() ||
		after.Members[0].Outcome != executions.OutcomeFailed || after.Members[1].Outcome != executions.OutcomeNotExecuted {
		t.Fatalf("missing host: %d runs, %v, %+v", f.runCount(), rep, after.Members)
	}
}

// busyErr is the executor's refusal of a member whose target runs another
// batch member (before the claim: nothing ran).
var busyErr = status.Error(codes.FailedPrecondition, "batch_host_busy: another batch member runs on the target")

// testClock is a settable clock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// A member whose target is busy with another batch member is not spent:
// it stays dispatched (so a server crash still ends it unknown, never
// redispatched) and is offered again after its backoff, not before; once
// the target is free it runs and the batch goes on.
func TestBatchRunnerRetriesBusyTarget(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 2}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh", "package.install_all")
	busy := 2
	f.answer = func(in *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if busy > 0 {
			busy--
			return nil, busyErr
		}
		return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS, Class: "success"}, nil
	}
	clk := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRunner(t, f, b)
	r.now = clk.now
	ctx := context.Background()

	if n := r.runOnce(ctx); n != 0 || f.runCount() != 1 {
		t.Fatalf("busy: %d handed over, %d calls", n, f.runCount())
	}
	mid, _ := b.Batch(ctx, v.ID)
	if mid.Members[0].Outcome != executions.OutcomeDispatched || mid.Members[1].Outcome != executions.OutcomePlanned {
		t.Fatalf("while waiting: %+v", mid.Members)
	}
	// Not before the backoff.
	clk.add(busyBackoff(1) - time.Second)
	if r.runOnce(ctx); f.runCount() != 1 {
		t.Fatalf("offered again before the backoff: %d calls", f.runCount())
	}
	clk.add(time.Second)
	if r.runOnce(ctx); f.runCount() != 2 {
		t.Fatalf("not offered again after the backoff: %d calls", f.runCount())
	}
	clk.add(busyBackoff(2))
	if n := r.runOnce(ctx); n != 2 || f.runCount() != 4 {
		t.Fatalf("after the target is free: %d handed over, %d calls", n, f.runCount())
	}
	after, _ := b.Batch(ctx, v.ID)
	if after.Counts.Success != 2 || len(f.reports()) != 0 || len(r.waiting) != 0 {
		t.Fatalf("after: %+v, %d reports, waiting %v", after.Members, len(f.reports()), r.waiting)
	}
	// Every offer of the member was the same approved request.
	for _, in := range f.runs[:3] {
		if in.GetMemberId() != v.Members[0].MemberID || in.GetBatchDigest() != v.Digest || len(in.GetArtifact()) == 0 {
			t.Fatalf("offer = %+v", in)
		}
	}
}

// The wait is bounded: a target that stays busy ends the member not
// executed after batchBusyAttempts offers, the executor is told, the stop
// policy applies, and nothing is offered again.
func TestBatchRunnerBusyTargetIsBounded(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 2}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh", "package.install_all")
	f.answer = func(*pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) { return nil, busyErr }
	clk := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRunner(t, f, b)
	r.now = clk.now
	ctx := context.Background()
	for range 3 * batchBusyAttempts {
		r.runOnce(ctx)
		clk.add(batchBusyMaxBackoff)
	}
	rep := f.reports()
	if f.runCount() != batchBusyAttempts+1 || len(rep) != 1 || rep[0].GetNotExecutedReason() != errBatchTargetStaysBusy.Error() {
		t.Fatalf("%d calls, %d reports; want %d offers and one report", f.runCount(), len(rep), batchBusyAttempts)
	}
	after, _ := b.Batch(ctx, v.ID)
	if after.Members[0].Outcome != executions.OutcomeFailed || !strings.Contains(after.Members[0].Detail, "not executed: the target stayed busy") ||
		after.Members[1].Outcome != executions.OutcomeNotExecuted || len(r.waiting) != 0 {
		t.Fatalf("after: %+v", after.Members)
	}
	// The backoff grows and is capped.
	if busyBackoff(1) != batchBusyBackoff || busyBackoff(2) != 2*batchBusyBackoff || busyBackoff(batchBusyAttempts) != batchBusyMaxBackoff {
		t.Fatalf("backoff %s %s %s", busyBackoff(1), busyBackoff(2), busyBackoff(batchBusyAttempts))
	}
}

// A batch waiting for a busy target does not hold up other batches.
func TestBatchRunnerBusyTargetDoesNotBlockOtherBatches(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	waiting := approvedBatch(t, b, "automatic", "package.refresh")
	other := approvedBatch(t, b, "automatic", "package.refresh")
	f.answer = func(in *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
		if in.GetBatchDigest() == waiting.Digest {
			return nil, busyErr
		}
		return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS, Class: "success"}, nil
	}
	r := newRunner(t, f, b)
	r.now = (&testClock{t: time.Unix(1_800_000_000, 0)}).now
	if n := r.runOnce(context.Background()); n != 1 {
		t.Fatalf("handed over %d, want the other batch's member", n)
	}
	o, _ := b.Batch(context.Background(), other.ID)
	w, _ := b.Batch(context.Background(), waiting.ID)
	if o.Counts.Success != 1 || w.Members[0].Outcome != executions.OutcomeDispatched {
		t.Fatalf("other %+v, waiting %+v", o.Members, w.Members)
	}
}

// Fail closed across a restart: a member that waited for its target when
// the server stopped is never offered again by a new runner, and the
// startup reconciliation ends it unknown.
func TestBatchRunnerBusyMemberAfterRestart(t *testing.T) {
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh")
	f.answer = func(*pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) { return nil, busyErr }
	ctx := context.Background()
	newRunner(t, f, b).runOnce(ctx)
	f.answer = nil
	if n := newRunner(t, f, b).runOnce(ctx); n != 0 || f.runCount() != 1 {
		t.Fatalf("a new runner offered the waiting member: %d, %d calls", n, f.runCount())
	}
	if _, err := b.ReconcileBatches(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := b.Batch(ctx, v.ID)
	if after.Members[0].Outcome != executions.OutcomeUnknown {
		t.Fatalf("after restart: %+v", after.Members[0])
	}
}

// Only the executor's batch_host_busy and batch_hold_store_unavailable
// refusals are offered again, raw or as the executor client maps them; any
// other refusal ends the member.
func TestWaitRefusalRecognizesOnlyTheWaitRefusals(t *testing.T) {
	store := status.Error(codes.FailedPrecondition, "batch_hold_store_unavailable: held batch targets cannot be persisted; see the executor log")
	for _, tc := range []struct {
		err  error
		want error
	}{
		{busyErr, errBatchTargetStaysBusy},
		{status.Error(codes.FailedPrecondition, "precondition_failed: batch_host_busy: another batch member runs on the target"), errBatchTargetStaysBusy},
		{store, errBatchHoldStoreDown},
		{status.Error(codes.FailedPrecondition, "precondition_failed: batch_hold_store_unavailable: x"), errBatchHoldStoreDown},
		{nil, nil},
		{status.Error(codes.FailedPrecondition, "credential_mismatch: batch_host_busy:"), nil},
		{status.Error(codes.PermissionDenied, "batch_host_busy: x"), nil},
		{status.Error(codes.Unavailable, "batch_hold_store_unavailable: x"), nil},
		{status.Error(codes.FailedPrecondition, "host_key_mismatch: blocked"), nil},
	} {
		if got := waitRefusal(tc.err); got != tc.want {
			t.Errorf("waitRefusal(%v) = %v", tc.err, got)
		}
	}
}

// A transient hold-store refusal waits like a busy target and the member
// runs once the store recovers; one that stays ends the member not
// executed after batchBusyAttempts offers, and the executor is told.
func TestBatchRunnerRetriesHoldStoreRefusal(t *testing.T) {
	storeErr := status.Error(codes.FailedPrecondition, "batch_hold_store_unavailable: held batch targets cannot be persisted; see the executor log")
	f := &fakeBatchRPC{execution: true, openStage: 1}
	b, _ := newWiringBatches(t, f)
	v := approvedBatch(t, b, "automatic", "package.refresh")
	down := 1
	f.answer = func(*pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if down > 0 {
			down--
			return nil, storeErr
		}
		return &pb.RunBatchMemberResponse{Outcome: pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS, Class: "success"}, nil
	}
	clk := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRunner(t, f, b)
	r.now = clk.now
	ctx := context.Background()
	r.runOnce(ctx)
	clk.add(busyBackoff(1))
	if n := r.runOnce(ctx); n != 1 || f.runCount() != 2 || len(f.reports()) != 0 {
		t.Fatalf("after the store recovered: %d handed over, %d calls, %d reports", n, f.runCount(), len(f.reports()))
	}
	if after, _ := b.Batch(ctx, v.ID); after.Counts.Success != 1 {
		t.Fatalf("after: %+v", after.Members)
	}

	f2 := &fakeBatchRPC{execution: true, openStage: 1}
	b2, _ := newWiringBatches(t, f2)
	v2 := approvedBatch(t, b2, "automatic", "package.refresh")
	f2.answer = func(*pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) { return nil, storeErr }
	r2 := newRunner(t, f2, b2)
	r2.now = clk.now
	for range 3 * batchBusyAttempts {
		r2.runOnce(ctx)
		clk.add(batchBusyMaxBackoff)
	}
	rep := f2.reports()
	if f2.runCount() != batchBusyAttempts+1 || len(rep) != 1 || rep[0].GetNotExecutedReason() != errBatchHoldStoreDown.Error() {
		t.Fatalf("%d calls, %d reports", f2.runCount(), len(rep))
	}
	if after, _ := b2.Batch(ctx, v2.ID); after.Members[0].Outcome != executions.OutcomeFailed {
		t.Fatalf("after: %+v", after.Members)
	}
}
