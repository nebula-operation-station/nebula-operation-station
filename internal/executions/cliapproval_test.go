// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// TestCheckCLIApprovalsRecordsAndDispatches checks the core behaviour of
// issue #78: a pending execution whose permit the executor reports APPROVED
// (approved on the executor host with `nebula approve`) is recorded approved
// with a guarded update, audited as execution_approved_on_cli, and dispatched.
func TestCheckCLIApprovalsRecordsAndDispatches(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, db := setup(t, f)
	ctx := context.Background()
	now := time.Unix(1791960000, 0)
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A second execution that is not pending: it must be left alone.
	other, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET state = 'running' WHERE id = ?`, other.ID); err != nil {
		t.Fatal(err)
	}

	n, err := s.CheckCLIApprovals(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("recorded %d, want 1", n)
	}
	waitState(t, s, c.ID, "finished")
	if got := len(f.attached); got != 1 {
		t.Fatalf("dispatched %d times, want 1", got)
	}
	e, _ := s.Get(ctx, c.ID)
	if len(e.Options) != 0 {
		t.Fatalf("options not cleared: %s", e.Options)
	}
	// The non-pending execution was not asked about.
	if f.permitStateCalls != 1 {
		t.Fatalf("GetPermitState called %d times, want 1", f.permitStateCalls)
	}
}

// TestCheckCLIApprovalsIsAudited checks that recording a CLI approval logs an
// audit record of kind execution_approved_on_cli with the execution id.
func TestCheckCLIApprovalsIsAudited(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED,
		pins: []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:web", CredentialRef: "nebula-default"}}}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(ctx, f, db, fakeHosts{"web": {ID: "web", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}}}}, log)
	t.Cleanup(func() { cancel(); s.Wait() })
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckCLIApprovals(ctx, time.Unix(1791960000, 0)); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "execution_approved_on_cli") || !strings.Contains(got, "execution="+c.ID) {
		t.Fatalf("audit record missing: %s", got)
	}
}

// TestCheckCLIApprovalsConcurrentDispatchesOnce checks that two concurrent
// calls record the approval once and dispatch exactly once: only the call
// whose guarded UPDATE moved the row starts it.
func TestCheckCLIApprovalsConcurrentDispatchesOnce(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var recorded int
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := s.CheckCLIApprovals(ctx, time.Unix(1791960000, 0))
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			recorded += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	if recorded != 1 {
		t.Fatalf("recorded %d, want 1", recorded)
	}
	waitState(t, s, c.ID, "finished")
	if got := len(f.attached); got != 1 {
		t.Fatalf("dispatched %d times, want 1", got)
	}
}

// TestCheckCLIApprovalsLeavesUnapprovedAlone checks that a permit the
// executor does not report approved (PENDING, or no live permit) leaves the
// execution pending and undispached.
func TestCheckCLIApprovalsLeavesUnapprovedAlone(t *testing.T) {
	for name, state := range map[string]pb.PermitState{
		"pending":   pb.PermitState_PERMIT_STATE_PENDING,
		"no permit": pb.PermitState_PERMIT_STATE_UNSPECIFIED,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeExec{permitState: state}
			s, _ := setup(t, f)
			ctx := context.Background()
			c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			n, err := s.CheckCLIApprovals(ctx, time.Unix(1791960000, 0))
			if err != nil || n != 0 {
				t.Fatalf("n=%d err=%v", n, err)
			}
			e, _ := s.Get(ctx, c.ID)
			if e.State != "pending" || len(f.attached) != 0 {
				t.Fatalf("state %s attached %d", e.State, len(f.attached))
			}
		})
	}
}

// TestCheckCLIApprovalsExecutorErrorLeavesPending checks that an executor
// error leaves the execution pending and is returned (the server logs it and
// retries on the next tick).
func TestCheckCLIApprovalsExecutorErrorLeavesPending(t *testing.T) {
	f := &fakeExec{permitStateErr: status.Error(codes.Unavailable, "executor down")}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckCLIApprovals(ctx, time.Unix(1791960000, 0)); status.Code(err) != codes.Unavailable {
		t.Fatalf("err=%v", err)
	}
	e, _ := s.Get(ctx, c.ID)
	if e.State != "pending" || len(f.attached) != 0 {
		t.Fatalf("state %s attached %d", e.State, len(f.attached))
	}
}

// TestCheckCLIApprovalsWithoutPendingDoesNotCallTheExecutor checks that the
// periodic check does not contact the executor when no execution is pending.
func TestCheckCLIApprovalsWithoutPendingDoesNotCallTheExecutor(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(ctx, "axel", c.ID, []byte("good"), 0); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	if n, err := s.CheckCLIApprovals(ctx, time.Unix(1791960000, 0)); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if f.permitStateCalls != 0 {
		t.Fatalf("GetPermitState called %d times, want 0", f.permitStateCalls)
	}
}

// TestExpirePendingKeepsCLIApproved checks the sweep interaction from issue
// #78: a pending execution whose window has ended (beyond the grace) is not
// expired when the executor still reports its permit APPROVED. The check runs
// before the expiry, records the approval and dispatches it.
func TestExpirePendingKeepsCLIApproved(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, db := setup(t, f)
	ctx := context.Background()
	now := time.Unix(1791960000, 0)
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET approval_expiry = ? WHERE id = ?`, now.Unix()-int64(expireGrace/time.Second)-100, c.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpirePending(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expired %d, want 0 (the permit is approved)", n)
	}
	waitState(t, s, c.ID, "finished")
	if got := len(f.attached); got != 1 {
		t.Fatalf("dispatched %d times, want 1", got)
	}
}

// TestExpirePendingStillExpiresUnapproved checks the control case: when the
// executor does not report the permit approved, the overdue sweep expires as
// before.
func TestExpirePendingStillExpiresUnapproved(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_PENDING}
	s, db := setup(t, f)
	ctx := context.Background()
	now := time.Unix(1791960000, 0)
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET approval_expiry = ? WHERE id = ?`, now.Unix()-int64(expireGrace/time.Second)-100, c.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpirePending(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	e, _ := s.Get(ctx, c.ID)
	if e.State != "expired" || len(f.attached) != 0 {
		t.Fatalf("state %s attached %d", e.State, len(f.attached))
	}
}

// TestExpirePendingKeepsPendingWhenTheExecutorIsUnreachable checks that the
// sweep does not expire anything it could not verify: an executor error
// aborts the sweep with the error instead of expiring the overdue pending
// execution (nothing can run while the executor is down anyway).
func TestExpirePendingKeepsPendingWhenTheExecutorIsUnreachable(t *testing.T) {
	f := &fakeExec{permitStateErr: status.Error(codes.Unavailable, "executor down")}
	s, db := setup(t, f)
	ctx := context.Background()
	now := time.Unix(1791960000, 0)
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET approval_expiry = ? WHERE id = ?`, now.Unix()-int64(expireGrace/time.Second)-100, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExpirePending(ctx, now); status.Code(err) != codes.Unavailable {
		t.Fatalf("err=%v", err)
	}
	e, _ := s.Get(ctx, c.ID)
	if e.State != "pending" {
		t.Fatalf("state %s, want pending", e.State)
	}
}

// TestCheckCLIApprovalSingle checks the on-demand check used by the operation
// page: it returns the state after the check, approves a pending execution
// the executor reports approved, and passes not-found through.
func TestCheckCLIApprovalSingle(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.CheckCLIApproval(ctx, c.ID)
	// The dispatcher may already have moved it on: the fake executor
	// answers at once, so on a fast machine the run can even be finished.
	if err != nil || (state != "approved" && state != "running" && state != "finished") {
		t.Fatalf("state=%s err=%v", state, err)
	}
	waitState(t, s, c.ID, "finished")
	if got := len(f.attached); got != 1 {
		t.Fatalf("dispatched %d times, want 1", got)
	}
	if _, err := s.CheckCLIApproval(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

// TestCheckCLIApprovalLeavesNonPendingAlone checks that checking an execution
// that is no longer pending just returns its state without asking the
// executor.
func TestCheckCLIApprovalLeavesNonPendingAlone(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(ctx, "axel", c.ID, []byte("good"), 0); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	state, err := s.CheckCLIApproval(ctx, c.ID)
	if err != nil || state != "finished" {
		t.Fatalf("state=%s err=%v", state, err)
	}
	if f.permitStateCalls != 0 {
		t.Fatalf("GetPermitState called %d times, want 0", f.permitStateCalls)
	}
}

// TestCheckCLIApprovalsSkipsExecutionsWithoutADigest guards against a
// corrupted row: a pending execution without a digest cannot be checked and
// is skipped, not a server error.
func TestCheckCLIApprovalsSkipsExecutionsWithoutADigest(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_APPROVED}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET digest = '' WHERE id = ?`, c.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CheckCLIApprovals(ctx, time.Unix(1791960000, 0)); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	e, _ := s.Get(ctx, c.ID)
	if e.State != "pending" {
		t.Fatalf("state %s, want pending", e.State)
	}
}

// TestExpirePendingSkipsOnlyTheExecutionWhoseCheckFailed checks that one
// execution the executor refuses to check (here: an invalid digest) stays
// pending and is reported, while the other overdue execution still expires,
// so a single bad row cannot stop the sweep for good.
func TestExpirePendingSkipsOnlyTheExecutionWhoseCheckFailed(t *testing.T) {
	bad := strings.Repeat("b", 64)
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_PENDING,
		permitStateErrFor: map[string]error{bad: status.Error(codes.InvalidArgument, "bad digest")}}
	s, db := setup(t, f)
	ctx := context.Background()
	now := time.Unix(1791960000, 0)
	overdue := now.Unix() - int64(expireGrace/time.Second) - 100
	a, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET approval_expiry = ?`, overdue); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET digest = ? WHERE id = ?`, bad, b.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.ExpirePending(ctx, now)
	if n != 1 || status.Code(err) != codes.InvalidArgument {
		t.Fatalf("n=%d err=%v, want 1 and InvalidArgument", n, err)
	}
	if e, _ := s.Get(ctx, a.ID); e.State != "expired" {
		t.Fatalf("checked execution: state %s, want expired", e.State)
	}
	if e, _ := s.Get(ctx, b.ID); e.State != "pending" {
		t.Fatalf("unchecked execution: state %s, want pending", e.State)
	}
}
