// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// intentRow is the rejection intent stored on a pending execution record.
type intentRow struct {
	state  string
	user   sql.NullString
	reason sql.NullString
	at     sql.NullInt64
}

// readIntent reads the state and the rejection intent columns of an execution.
func readIntent(t *testing.T, db *sql.DB, id string) intentRow {
	t.Helper()
	var r intentRow
	if err := db.QueryRow(`SELECT state, reject_user, reject_reason, reject_at FROM executions WHERE id = ?`, id).
		Scan(&r.state, &r.user, &r.reason, &r.at); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRejectStoresIntentBeforeTheExecutorCall checks spec 07 v29-07-01: the
// user, reason and time are in the pending record when the executor is asked,
// and the state is still pending at that point.
func TestRejectStoresIntentBeforeTheExecutorCall(t *testing.T) {
	f := &fakeExec{}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var seen intentRow
	f.beforeReject = func() { seen = readIntent(t, db, c.ID) }
	if err := s.Reject(ctx, "axel", c.ID, "wrong host"); err != nil {
		t.Fatal(err)
	}
	if seen.state != "pending" {
		t.Fatalf("state at the executor call = %s, want pending", seen.state)
	}
	if seen.user.String != "axel" || seen.reason.String != "wrong host" || !seen.at.Valid || seen.at.Int64 == 0 {
		t.Fatalf("intent at the executor call = user %v reason %v at %v, want axel / wrong host / a time", seen.user, seen.reason, seen.at)
	}
	if len(f.rejects) != 1 {
		t.Fatalf("executor asked %d times, want 1", len(f.rejects))
	}
	// The success keeps the intent as the record of who asked, and the state
	// is now rejected.
	after := readIntent(t, db, c.ID)
	if after.state != "rejected" || after.user.String != "axel" {
		t.Fatalf("after success: state %s user %v, want rejected with the intent kept", after.state, after.user)
	}
}

// TestRejectCrashBetweenIntentAndCallLeavesIntentPending simulates the server
// dying after the intent is stored and before RejectPending is sent. The
// record keeps the intent, the state stays pending, and the executor has not
// been asked.
func TestRejectCrashBetweenIntentAndCallLeavesIntentPending(t *testing.T) {
	f := &fakeExec{}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.beforeReject = func() { panic("simulated server crash") }
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Reject returned, want the simulated crash")
			}
		}()
		_ = s.Reject(ctx, "axel", c.ID, "stale host")
	}()
	if len(f.rejects) != 0 {
		t.Fatalf("executor was asked %d times before the crash point", len(f.rejects))
	}
	got := readIntent(t, db, c.ID)
	if got.state != "pending" {
		t.Fatalf("state = %s, want pending after the crash", got.state)
	}
	if got.user.String != "axel" || got.reason.String != "stale host" {
		t.Fatalf("intent = user %v reason %v, want the stored intent", got.user, got.reason)
	}
}

// TestRejectExecutorRefusalClearsIntent checks that a refused call (here a
// FailedPrecondition from the executor) clears the intent again and leaves the
// execution pending.
func TestRejectExecutorRefusalClearsIntent(t *testing.T) {
	f := &fakeExec{rejectErr: status.Error(codes.FailedPrecondition, "privileged session required")}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(ctx, "axel", c.ID, "wrong host"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v, want the executor's refusal", err)
	}
	got := readIntent(t, db, c.ID)
	if got.state != "pending" {
		t.Fatalf("state = %s, want pending", got.state)
	}
	if got.user.Valid || got.reason.Valid || got.at.Valid {
		t.Fatalf("intent kept after a refusal: user %v reason %v at %v", got.user, got.reason, got.at)
	}
}

// TestRejectLostAnswerKeepsIntent checks that when the answer is lost (the
// executor is unavailable), the outcome is open: the intent stays, the state
// stays pending, and the error reaches the caller.
func TestRejectLostAnswerKeepsIntent(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.DeadlineExceeded, codes.Canceled} {
		t.Run(code.String(), func(t *testing.T) {
			f := &fakeExec{rejectErr: status.Error(code, "no answer")}
			s, db := setup(t, f)
			ctx := context.Background()
			c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Reject(ctx, "axel", c.ID, "wrong host"); status.Code(err) != code {
				t.Fatalf("err = %v, want code %s", err, code)
			}
			got := readIntent(t, db, c.ID)
			if got.state != "pending" {
				t.Fatalf("state = %s, want pending", got.state)
			}
			if got.user.String != "axel" || got.reason.String != "wrong host" {
				t.Fatalf("intent = user %v reason %v, want it kept", got.user, got.reason)
			}
		})
	}
}

// TestRejectPlainErrorKeepsIntent checks that an error that carries no gRPC
// status is treated as a lost answer: the intent is kept.
func TestRejectPlainErrorKeepsIntent(t *testing.T) {
	f := &fakeExec{rejectErr: errors.New("connection reset")}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(ctx, "axel", c.ID, ""); err == nil {
		t.Fatal("Reject succeeded, want the executor error")
	}
	if got := readIntent(t, db, c.ID); got.state != "pending" || got.user.String != "axel" {
		t.Fatalf("state %s user %v, want pending with the intent kept", got.state, got.user)
	}
}

// TestAdminRejectionOnTheCLIDropsLeftoverIntent checks spec 07: a rejection
// the executor reports with role admin (nebula reject on the executor host)
// drops an intent left over from a server call that never reached the
// executor.
func TestAdminRejectionOnTheCLIDropsLeftoverIntent(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_REJECTED, rejectedBy: pb.RejectingRole_REJECTING_ROLE_ADMIN}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE executions SET reject_user = 'axel', reject_reason = 'old', reject_at = 1 WHERE id = ?`, c.ID); err != nil {
		t.Fatal(err)
	}
	state, err := s.CheckCLIApproval(ctx, c.ID)
	if err != nil || state != "rejected" {
		t.Fatalf("state=%s err=%v, want rejected", state, err)
	}
	got := readIntent(t, db, c.ID)
	if got.state != "rejected" || got.user.Valid || got.reason.Valid || got.at.Valid {
		t.Fatalf("after admin rejection: state %s, intent user %v reason %v at %v; want rejected and no intent", got.state, got.user, got.reason, got.at)
	}
}

// setIntent writes a rejection intent into a pending execution, as the server
// does before it calls RejectPending.
func setIntent(t *testing.T, db *sql.DB, id, user, reason string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE executions SET reject_user = ?, reject_reason = ?, reject_at = 1700000000 WHERE id = ?`, user, reason, id); err != nil {
		t.Fatal(err)
	}
}

// TestServerRejectionAfterLostAnswerIsRecordedWithTheIntent checks spec 07
// v29-07-01: the server stored the intent, the executor committed the
// rejection, and the answer was lost (or the server restarted). The approval
// check learns REJECTED with role server: the execution is recorded with the
// intent's user and reason, marked as recorded after restart, and not as a
// rejection on the executor host.
func TestServerRejectionAfterLostAnswerIsRecordedWithTheIntent(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_REJECTED, rejectedBy: pb.RejectingRole_REJECTING_ROLE_SERVER}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	setIntent(t, db, c.ID, "axel", "wrong host")
	state, err := s.CheckCLIApproval(ctx, c.ID)
	if err != nil || state != "rejected" {
		t.Fatalf("state=%s err=%v, want rejected", state, err)
	}
	e, _ := s.Get(ctx, c.ID)
	if !strings.Contains(e.Detail, "recorded after restart") || !strings.Contains(e.Detail, "wrong host") {
		t.Fatalf("detail %q, want the recorded-after-restart marker and the stored reason", e.Detail)
	}
	if strings.Contains(e.Detail, "executor host") {
		t.Fatalf("detail %q says the rejection was on the executor host", e.Detail)
	}
	got := readIntent(t, db, c.ID)
	if got.user.String != "axel" || got.reason.String != "wrong host" {
		t.Fatalf("intent after recording = user %v reason %v, want the stored intent kept", got.user, got.reason)
	}
	if st, class := hostState(t, s, c.ID); st != "finished" || class != "not_executed" {
		t.Fatalf("host row = %s/%s, want finished/not_executed", st, class)
	}
}

// TestServerRejectionWithoutIntentSaysUserNotRecorded checks spec 07 v29-07-01:
// role server with no intent (the server lost its record of the call) is shown
// as "Rejected in the web UI; user not recorded", and no intent is invented.
func TestServerRejectionWithoutIntentSaysUserNotRecorded(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_REJECTED, rejectedBy: pb.RejectingRole_REJECTING_ROLE_SERVER}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := s.CheckCLIApproval(ctx, c.ID); err != nil || state != "rejected" {
		t.Fatalf("state=%s err=%v, want rejected", state, err)
	}
	e, _ := s.Get(ctx, c.ID)
	if !strings.HasPrefix(e.Detail, "Rejected in the web UI; user not recorded") {
		t.Fatalf("detail %q, want the user-not-recorded text", e.Detail)
	}
	if got := readIntent(t, db, c.ID); got.user.Valid || got.reason.Valid || got.at.Valid {
		t.Fatalf("an intent appeared from nowhere: user %v reason %v at %v", got.user, got.reason, got.at)
	}
}

// TestAdminRejectionOnTheCLIIsSaidToBeOnTheExecutorHost checks the detail of a
// rejection with role admin, with or without a leftover intent: it is the
// executor-host text, and the intent is dropped.
func TestAdminRejectionOnTheCLIIsSaidToBeOnTheExecutorHost(t *testing.T) {
	for _, withIntent := range []bool{false, true} {
		name := "without intent"
		if withIntent {
			name = "with intent"
		}
		t.Run(name, func(t *testing.T) {
			f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_REJECTED, rejectedBy: pb.RejectingRole_REJECTING_ROLE_ADMIN}
			s, db := setup(t, f)
			ctx := context.Background()
			c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if withIntent {
				setIntent(t, db, c.ID, "axel", "old")
			}
			if state, err := s.CheckCLIApproval(ctx, c.ID); err != nil || state != "rejected" {
				t.Fatalf("state=%s err=%v, want rejected", state, err)
			}
			e, _ := s.Get(ctx, c.ID)
			if e.Detail != "rejected on the executor host; nothing was run" {
				t.Fatalf("detail = %q, want the executor-host text", e.Detail)
			}
			if got := readIntent(t, db, c.ID); got.user.Valid || got.reason.Valid || got.at.Valid {
				t.Fatalf("intent kept after an admin rejection: user %v", got.user)
			}
		})
	}
}

// TestConcurrentRejectionsKeepTheWinnersIntent checks that two web rejections
// of one execution at the same time cannot overwrite the winner's intent: the
// executor answers the first call slowly, the other caller must wait, and the
// execution is rejected once, with the intent of the call the executor accepted.
func TestConcurrentRejectionsKeepTheWinnersIntent(t *testing.T) {
	f := &fakeExec{}
	// Every caller gets past its own checks while the first call waits here.
	f.beforeReject = func() { time.Sleep(100 * time.Millisecond) }
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	users := []string{"u0", "u1", "u2", "u3"}
	errs := make([]error, len(users))
	var wg sync.WaitGroup
	for i, u := range users {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Reject(ctx, u, c.ID, "reason of "+u)
		}()
	}
	wg.Wait()
	winner := ""
	for i, err := range errs {
		switch {
		case err == nil:
			if winner != "" {
				t.Fatalf("two rejections succeeded: %s and %s", winner, users[i])
			}
			winner = users[i]
		case errors.Is(err, ErrNotPending):
		default:
			t.Fatalf("rejection by %s: err = %v, want nil or ErrNotPending", users[i], err)
		}
	}
	if winner == "" {
		t.Fatal("no rejection succeeded")
	}
	if len(f.rejects) != 1 {
		t.Fatalf("executor asked %d times, want 1", len(f.rejects))
	}
	got := readIntent(t, db, c.ID)
	if got.state != "rejected" || got.user.String != winner || got.reason.String != "reason of "+winner {
		t.Fatalf("state %s, intent user %v reason %v; want rejected with the winner %s's intent", got.state, got.user, got.reason, winner)
	}
}
