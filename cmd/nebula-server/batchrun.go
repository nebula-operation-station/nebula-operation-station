// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// batchRunInterval is how often the server hands the next approved batch
// members to the executor.
const batchRunInterval = 5 * time.Second

// A member whose target is busy with another batch member (the executor's
// batch_host_busy refusal, which comes before the claim, so nothing ran
// and the member is unspent there) waits and is offered again: after
// batchBusyBackoff, doubling up to batchBusyMaxBackoff, at most
// batchBusyAttempts offers in all (about 16 minutes, longer than one
// attached member run plus the executor's hold wait). After the last
// refusal it ends not executed, and the executor is told so.
const (
	batchBusyAttempts   = 12
	batchBusyBackoff    = 5 * time.Second
	batchBusyMaxBackoff = 2 * time.Minute
)

// batchHostBusyCode prefixes the executor's refusal of a member whose
// target runs (or may still run) another batch member.
const batchHostBusyCode = "batch_host_busy:"

// hostrunMaxAttached is the executor's limit for one member run (members
// run attached).
const hostrunMaxAttached = 10 * time.Minute

// batchRunner hands the members of approved batches to the executor one at
// a time (ADR 0007 E11/E13). It only decides when: the executor takes
// everything that runs from its frozen plan and enforces claims, stage
// gates, dependencies, same-host ordering, trust, risk and credential
// versions. Each member is recorded as dispatched before the first call
// and stays dispatched while it waits for a busy target, so a server crash
// leaves it unknown (ReconcileBatches), never redispatched; its result is
// recorded with the server's stop policy. One goroutine runs it, so at
// most one member is in flight from this server.
type batchRunner struct {
	batches *executions.Batches
	exec    serverBatchExecutor
	hosts   executions.Hosts
	actions executions.ActionResolver
	log     *slog.Logger
	// now is the clock of the busy-target backoff; nil means time.Now.
	now func() time.Time
	// waiting are the dispatched members whose target was busy, by batch
	// ID (at most one per batch: the batch waits with it). Only the
	// runner's goroutine uses it; a restart loses it, and the members stay
	// dispatched and end unknown (fail closed).
	waiting map[string]*busyMember
}

// busyMember is a dispatched member waiting for its target.
type busyMember struct {
	memberID string
	// attempts counts the busy refusals so far.
	attempts int
	// next is when the member is offered again.
	next time.Time
}

func (r *batchRunner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// busyBackoff is the wait after the n-th busy refusal (n >= 1).
func busyBackoff(n int) time.Duration {
	d := batchBusyBackoff
	for i := 1; i < n && d < batchBusyMaxBackoff; i++ {
		d *= 2
	}
	return min(d, batchBusyMaxBackoff)
}

// run hands members to the executor every interval until ctx ends.
func (r *batchRunner) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		r.runOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// runOnce offers the waiting members whose backoff is over again and
// advances every other approved batch with planned members as far as the
// executor allows now. It returns the number of members handed over.
func (r *batchRunner) runOnce(ctx context.Context) int {
	if r.exec.client() == nil {
		return 0
	}
	n := 0
	// Waiting members first, independent of the (bounded) batch list.
	for _, id := range slices.Sorted(maps.Keys(r.waiting)) {
		if ctx.Err() != nil {
			return n
		}
		n += r.retryWaiting(ctx, id)
	}
	list, err := r.batches.ListBatches(ctx)
	if err != nil {
		r.log.Error("batch runner: list batches", "error", err)
		return n
	}
	for _, b := range list {
		if ctx.Err() != nil {
			return n
		}
		if _, waits := r.waiting[b.ID]; waits || b.State != "approved" || b.Counts.Planned == 0 || b.Counts.Dispatched > 0 {
			continue
		}
		n += r.runBatch(ctx, b.ID)
	}
	return n
}

// retryWaiting offers the waiting member of batch id again once its
// backoff is over, then continues the batch if it may. A member that is no
// longer dispatched (ended elsewhere) stops waiting.
func (r *batchRunner) retryWaiting(ctx context.Context, id string) int {
	w := r.waiting[id]
	if r.clock().Before(w.next) {
		return 0
	}
	v, err := r.batches.Batch(ctx, id)
	if err != nil {
		if errors.Is(err, executions.ErrBatchNotFound) {
			delete(r.waiting, id)
		}
		r.log.Error("batch runner: read batch", "batch", id, "error", err)
		return 0
	}
	i := slices.IndexFunc(v.Members, func(m executions.BatchMemberView) bool { return m.MemberID == w.memberID })
	if i < 0 || v.Members[i].Outcome != executions.OutcomeDispatched {
		delete(r.waiting, id)
		return 0
	}
	if !r.handOver(ctx, v, v.Members[i], w.attempts) {
		if _, waits := r.waiting[id]; waits {
			return 0
		}
		return 1
	}
	return 1 + r.runBatch(ctx, id)
}

// runBatch hands the batch's planned members over in plan order until one
// must wait (a later stage, a closed gate, a busy target) or the batch
// stops.
func (r *batchRunner) runBatch(ctx context.Context, id string) int {
	n := 0
	for ctx.Err() == nil {
		v, err := r.batches.Batch(ctx, id)
		if err != nil {
			r.log.Error("batch runner: read batch", "batch", id, "error", err)
			return n
		}
		if v.State != "approved" || v.Counts.Dispatched > 0 {
			return n
		}
		i := slices.IndexFunc(v.Members, func(m executions.BatchMemberView) bool { return m.Outcome == executions.OutcomePlanned })
		if i < 0 {
			return n
		}
		m := v.Members[i]
		if !r.stageOpen(ctx, v, m) {
			return n
		}
		if !r.runMember(ctx, v, m) {
			return n
		}
		n++
	}
	return n
}

// stageOpen reports whether the executor has the member's stage open. The
// first stage is open from approval; a later stage behind an automatic
// gate opens as earlier stages complete (the executor's own rollout
// decides); a manual gate waits for the admin. Any doubt waits.
func (r *batchRunner) stageOpen(ctx context.Context, v executions.BatchView, m executions.BatchMemberView) bool {
	if m.Stage <= 1 {
		return true
	}
	cctx, cancel := context.WithTimeout(ctx, batchProbeTimeout)
	defer cancel()
	resp, err := r.exec.GetRollout(cctx, &pb.GetRolloutRequest{ExecutionDigest: v.Digest})
	if err != nil {
		r.log.Warn("batch runner: read rollout", "batch", v.ID, "error", err)
		return false
	}
	return int(resp.GetRollout().GetOpenStage()) >= m.Stage
}

// Reasons a member cannot be handed over as approved. They are fixed,
// secret-free texts the executor accepts as a not-executed reason.
var (
	errBatchActionMissing   = errors.New("the action is not available on this server")
	errBatchVersionMissing  = errors.New("the action at the approved version is not available on this server")
	errBatchScriptChanged   = errors.New("the action's script differs from the approved artifact")
	errBatchHostMissing     = errors.New("the host is not in the inventory")
	errBatchHostNoEndpoint  = errors.New("the host has no endpoint")
	errBatchTargetStaysBusy = errors.New("the target stayed busy with another batch member")
)

// memberInputs returns the exact script of a member, its run timeout and
// its host's endpoints; an error means the member cannot be handed over as
// approved.
func (r *batchRunner) memberInputs(ctx context.Context, m executions.BatchMemberView) (script []byte, timeout time.Duration, eps []string, err error) {
	a, ok := actions.Lookup(m.ActionID)
	if !ok || a.Version != m.ModuleVersion {
		if r.actions == nil {
			return nil, 0, nil, errBatchActionMissing
		}
		var found bool
		a, found, err = r.actions.Action(ctx, m.ActionID, m.ModuleVersion)
		if err != nil || !found || a.ID != m.ActionID || a.Version != m.ModuleVersion {
			return nil, 0, nil, errBatchVersionMissing
		}
	}
	if sum := sha256.Sum256(a.Script); hex.EncodeToString(sum[:]) != m.ArtifactSHA256 {
		return nil, 0, nil, errBatchScriptChanged
	}
	h, err := r.hosts.Get(ctx, m.HostID)
	if err != nil {
		return nil, 0, nil, errBatchHostMissing
	}
	for _, e := range h.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		eps = append(eps, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	if len(eps) == 0 {
		return nil, 0, nil, errBatchHostNoEndpoint
	}
	return a.Script, a.Timeout, eps, nil
}

// runMember marks the member dispatched and hands it to the executor. It
// reports whether the batch may continue now.
func (r *batchRunner) runMember(ctx context.Context, v executions.BatchView, m executions.BatchMemberView) bool {
	if err := r.batches.MarkDispatched(ctx, v.ID, m.MemberID); err != nil {
		if !errors.Is(err, executions.ErrBatchNotDispatchable) && !errors.Is(err, executions.ErrBatchMemberFinal) {
			r.log.Error("batch runner: mark dispatched", "batch", v.ID, "member", m.MemberID, "error", err)
		}
		return false
	}
	return r.handOver(ctx, v, m, 0)
}

// handOver offers a dispatched member to the executor (attempts busy
// refusals so far) and records its result. A busy target leaves the member
// dispatched and waiting (bounded by batchBusyAttempts); inputs the server
// cannot build end it not executed and are reported to the executor. It
// reports whether the batch may continue now.
func (r *batchRunner) handOver(ctx context.Context, v executions.BatchView, m executions.BatchMemberView, attempts int) bool {
	var res executions.MemberResult
	script, timeout, eps, inErr := r.memberInputs(ctx, m)
	if inErr != nil {
		// Nothing that could run reaches the executor: the member fails
		// closed, the executor spends it and the stop policy applies.
		res = r.reportNotExecuted(ctx, v, m, inErr)
	} else {
		secs := uint32(min(timeout, hostrunMaxAttached) / time.Second)
		// Shutdown cancels the run; its outcome is then unknown.
		resp, err := r.exec.RunBatchMember(ctx, &pb.RunBatchMemberRequest{BatchDigest: v.Digest, MemberId: m.MemberID,
			Endpoints: eps, TimeoutSeconds: secs, Artifact: script})
		switch {
		case hostBusy(err) && attempts+1 < batchBusyAttempts:
			next := r.clock().Add(busyBackoff(attempts + 1))
			if r.waiting == nil {
				r.waiting = map[string]*busyMember{}
			}
			r.waiting[v.ID] = &busyMember{memberID: m.MemberID, attempts: attempts + 1, next: next}
			r.log.Info("audit", "kind", "batch_member_waiting_for_target", "batch", v.ID, "member", m.MemberID,
				"attempt", attempts+1, "max_attempts", batchBusyAttempts, "next", next.UTC().Format(time.RFC3339))
			return false
		case hostBusy(err):
			res = r.reportNotExecuted(ctx, v, m, errBatchTargetStaysBusy)
		default:
			res = batchMemberResult(resp, err)
		}
	}
	delete(r.waiting, v.ID)
	if err := r.batches.RecordOutcome(context.WithoutCancel(ctx), v.ID, m.MemberID, res); err != nil {
		r.log.Error("batch runner: record outcome", "batch", v.ID, "member", m.MemberID, "error", err)
		return false
	}
	r.log.Info("audit", "kind", "batch_member_handed_over", "batch", v.ID, "member", m.MemberID, "outcome", res.Outcome,
		"unreachable", res.Unreachable)
	return res.Outcome == executions.OutcomeSuccess
}

// reportNotExecuted tells the executor that a dispatched member ends
// without running (RunBatchMemberRequest.not_executed_reason), so its
// rollout records the member failed instead of leaving it open, and
// returns the server's not-executed result. The result is the same if the
// executor cannot be told: nothing that could run was sent.
func (r *batchRunner) reportNotExecuted(ctx context.Context, v executions.BatchView, m executions.BatchMemberView, why error) executions.MemberResult {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), batchProbeTimeout)
	defer cancel()
	resp, err := r.exec.RunBatchMember(cctx, &pb.RunBatchMemberRequest{BatchDigest: v.Digest, MemberId: m.MemberID,
		NotExecutedReason: why.Error()})
	informed := err == nil && resp.GetOutcome() == pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED
	if !informed {
		r.log.Warn("batch runner: report a member not executed", "batch", v.ID, "member", m.MemberID, "error", err)
	}
	r.log.Warn("audit", "kind", "batch_member_not_executed", "batch", v.ID, "member", m.MemberID, "reason", why.Error(),
		"executor_informed", informed)
	return executions.MemberResult{Outcome: executions.OutcomeFailed, Detail: "not executed: " + why.Error()}
}

// hostBusy reports whether err is the executor's batch_host_busy refusal,
// as a raw status or mapped by the executor client (whose message is
// "precondition_failed: batch_host_busy: ..."). Only that refusal is
// offered again; every other refusal ends the member.
func hostBusy(err error) bool {
	if err == nil {
		return false
	}
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition {
		return false
	}
	return strings.HasPrefix(strings.TrimPrefix(st.Message(), "precondition_failed: "), batchHostBusyCode)
}

// batchMemberResult maps the executor's answer to the server's member
// result. A refusal status means nothing ran (the executor refuses only
// before the claim); a transport failure means the outcome is unknown.
func batchMemberResult(resp *pb.RunBatchMemberResponse, err error) executions.MemberResult {
	if err != nil {
		st := status.Convert(err)
		switch st.Code() {
		case codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition, codes.PermissionDenied, codes.Unimplemented,
			codes.AlreadyExists, codes.Unauthenticated, codes.ResourceExhausted, codes.OutOfRange:
			return executions.MemberResult{Outcome: executions.OutcomeFailed, Detail: "not executed: the executor refused: " + st.Message()}
		}
		return executions.MemberResult{Outcome: executions.OutcomeUnknown, Detail: "the executor's answer was lost; the member may have run and is never redispatched"}
	}
	detail := resp.GetClass()
	if d := resp.GetDetail(); d != "" {
		detail += ": " + d
	}
	switch resp.GetOutcome() {
	case pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS:
		return executions.MemberResult{Outcome: executions.OutcomeSuccess, Detail: detail}
	case pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE:
		return executions.MemberResult{Outcome: executions.OutcomeFailed, Unreachable: resp.GetUnreachable(), Detail: detail}
	case pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED:
		return executions.MemberResult{Outcome: executions.OutcomeFailed, Detail: "not executed: " + detail}
	}
	return executions.MemberResult{Outcome: executions.OutcomeUnknown, Detail: detail}
}
