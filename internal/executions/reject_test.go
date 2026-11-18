// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// hostState reads the state and class of the one host row of an execution.
func hostState(t *testing.T, s *Service, id string) (string, string) {
	t.Helper()
	var state, class string
	if err := s.db.QueryRow(`SELECT state, class FROM execution_hosts WHERE execution_id = ?`, id).Scan(&state, &class); err != nil {
		t.Fatal(err)
	}
	return state, class
}

// TestRejectRecordsRejectionAfterExecutorSuccess checks the happy path: the
// executor is asked with the digest, the relayed user and the reason; then the
// server moves the execution to rejected, its waiting host row to
// finished/not_executed, and nothing is dispatched.
func TestRejectRecordsRejectionAfterExecutorSuccess(t *testing.T) {
	f := &fakeExec{}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(ctx, "axel", c.ID, "wrong host"); err != nil {
		t.Fatal(err)
	}
	if len(f.rejects) != 1 {
		t.Fatalf("executor asked %d times, want 1", len(f.rejects))
	}
	got := f.rejects[0]
	e, _ := s.Get(ctx, c.ID)
	if got.GetDigest() != e.Digest || got.GetRelayedUser() != "axel" || got.GetReason() != "wrong host" {
		t.Fatalf("RPC request = %+v", got)
	}
	e, err = s.Get(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "rejected" {
		t.Fatalf("state = %s, want rejected", e.State)
	}
	if !strings.Contains(e.Detail, "wrong host") {
		t.Fatalf("detail %q does not carry the reason", e.Detail)
	}
	if st, class := hostState(t, s, c.ID); st != "finished" || class != "not_executed" {
		t.Fatalf("host row = %s/%s, want finished/not_executed", st, class)
	}
	if len(f.attached) != 0 {
		t.Fatalf("a rejected execution was dispatched %d times", len(f.attached))
	}
}

// TestRejectExecutorErrorLeavesServerStateUnchanged checks that an executor
// refusal is returned to the caller and the execution stays pending, with its
// host row waiting.
func TestRejectExecutorErrorLeavesServerStateUnchanged(t *testing.T) {
	f := &fakeExec{rejectErr: status.Error(codes.FailedPrecondition, "privileged session required")}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Reject(ctx, "axel", c.ID, "")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the executor's refusal", err)
	}
	e, _ := s.Get(ctx, c.ID)
	if e.State != "pending" {
		t.Fatalf("state = %s, want pending after an executor error", e.State)
	}
	if st, _ := hostState(t, s, c.ID); st != "waiting" {
		t.Fatalf("host row = %s, want waiting", st)
	}
}

// TestRejectRefusesBadInputBeforeTheExecutor checks that the reason and the
// user name are validated first: a refused input never reaches the executor.
func TestRejectRefusesBadInputBeforeTheExecutor(t *testing.T) {
	long := strings.Repeat("a", RejectReasonMaxRunes+1)
	multi := strings.Repeat("ä", RejectReasonMaxRunes) // 400 bytes, within the byte limit
	tooManyBytes := strings.Repeat("ö", 450)           // 900 bytes, over the byte limit
	cases := []struct {
		name, user, reason string
	}{
		{"reason over 200 characters", "axel", long},
		{"reason over 800 bytes", "axel", tooManyBytes},
		{"reason with newline", "axel", "two\nlines"},
		{"reason with NUL", "axel", "a\x00b"},
		{"reason with RLO", "axel", "a‮b"},
		{"reason with DEL", "axel", "a\x7fb"},
		{"user empty", "", ""},
		{"user with tab", "ax\tel", ""},
		{"user too long", strings.Repeat("u", relayedUserMaxBytes+1), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExec{}
			s, _ := setup(t, f)
			ctx := context.Background()
			c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = s.Reject(ctx, tc.user, c.ID, tc.reason)
			var pe *ParamError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want ParamError", err)
			}
			if len(f.rejects) != 0 {
				t.Fatalf("executor was asked %d times", len(f.rejects))
			}
		})
	}
	// The limits are inclusive: 200 characters of 2 bytes each is accepted,
	// and 200 characters of 4 bytes each is exactly the byte limit.
	if err := CheckRejectReason(multi); err != nil {
		t.Fatalf("200 characters of 2 bytes refused: %v", err)
	}
	if err := CheckRejectReason(strings.Repeat("😀", RejectReasonMaxRunes)); err != nil {
		t.Fatalf("200 characters of 4 bytes (800 bytes) refused: %v", err)
	}
}

// TestRejectNonPendingIsRefusedWithoutExecutorCall checks that only a pending
// execution can be rejected, and that the executor is not asked otherwise.
func TestRejectNonPendingIsRefusedWithoutExecutorCall(t *testing.T) {
	for _, state := range []string{"approved", "running", "finished", "failed", "expired", "rejected"} {
		t.Run(state, func(t *testing.T) {
			f := &fakeExec{}
			s, db := setup(t, f)
			ctx := context.Background()
			c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`UPDATE executions SET state = ? WHERE id = ?`, state, c.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.Reject(ctx, "axel", c.ID, ""); !errors.Is(err, ErrNotPending) {
				t.Fatalf("err = %v, want ErrNotPending", err)
			}
			if len(f.rejects) != 0 {
				t.Fatalf("executor was asked %d times", len(f.rejects))
			}
		})
	}
}

// TestRejectUnknownExecutionIsNotFound checks that an unknown ID is refused
// as not found, before the executor is asked.
func TestRejectUnknownExecutionIsNotFound(t *testing.T) {
	f := &fakeExec{}
	s, _ := setup(t, f)
	if err := s.Reject(context.Background(), "axel", "00000000-0000-0000-0000-000000000000", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if len(f.rejects) != 0 {
		t.Fatalf("executor was asked %d times", len(f.rejects))
	}
}

// TestRejectedByExecutorOnTheCLIIsRecorded checks that an execution the
// executor reports REJECTED (rejected with `nebula reject` on the executor
// host) is recorded rejected by the approval check, so the expiry sweep does
// not show it as expired, and that it is not dispatched.
func TestRejectedByExecutorOnTheCLIIsRecorded(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_REJECTED}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.CheckCLIApproval(ctx, c.ID)
	if err != nil || state != "rejected" {
		t.Fatalf("state=%s err=%v, want rejected", state, err)
	}
	// The sweep afterwards must leave the rejection alone.
	if _, err := s.ExpirePending(ctx, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e, _ := s.Get(ctx, c.ID)
	if e.State != "rejected" {
		t.Fatalf("sweep changed state to %s", e.State)
	}
	if len(f.attached) != 0 {
		t.Fatalf("a rejected execution was dispatched")
	}
}
