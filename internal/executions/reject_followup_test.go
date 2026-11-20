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

// TestRejectStorageRefusalClearsIntent checks that the executor's storage
// refusal (permit storage_error, rolled back: nothing was rejected) is a
// refusal, not a lost answer: the intent is cleared and the error is not the
// outcome-unknown error.
func TestRejectStorageRefusalClearsIntent(t *testing.T) {
	f := &fakeExec{rejectErr: status.Error(codes.Unavailable, "storage_error: executor state store unavailable")}
	s, db := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Reject(ctx, "axel", c.ID, "wrong host")
	if err == nil {
		t.Fatal("Reject succeeded, want the storage refusal")
	}
	if errors.Is(err, ErrRejectOutcomeUnknown) {
		t.Fatalf("storage refusal reported as a lost answer: %v", err)
	}
	got := readIntent(t, db, c.ID)
	if got.state != "pending" {
		t.Fatalf("state = %s, want pending", got.state)
	}
	if got.user.Valid || got.reason.Valid || got.at.Valid {
		t.Fatalf("intent kept after a storage refusal: user %v reason %v at %v", got.user, got.reason, got.at)
	}
}

// TestRejectLostAnswerIsOutcomeUnknown checks that a lost answer (timeout,
// cancellation, unreachable executor, an error without a status) is reported
// as ErrRejectOutcomeUnknown, so the caller does not say "nothing was
// rejected", and that the intent is kept for the next check.
func TestRejectLostAnswerIsOutcomeUnknown(t *testing.T) {
	cases := map[string]error{
		"unavailable":       status.Error(codes.Unavailable, "connection refused"),
		"deadline exceeded": status.Error(codes.DeadlineExceeded, "no answer"),
		"canceled":          status.Error(codes.Canceled, "no answer"),
		"plain error":       errors.New("connection reset"),
	}
	for name, rejectErr := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeExec{rejectErr: rejectErr}
			s, db := setup(t, f)
			ctx := context.Background()
			c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = s.Reject(ctx, "axel", c.ID, "wrong host")
			if !errors.Is(err, ErrRejectOutcomeUnknown) {
				t.Fatalf("err = %v, want ErrRejectOutcomeUnknown", err)
			}
			got := readIntent(t, db, c.ID)
			if got.state != "pending" || got.user.String != "axel" {
				t.Fatalf("state %s user %v, want pending with the intent kept", got.state, got.user)
			}
		})
	}
}

// TestRejectExecutorRefusalIsNotOutcomeUnknown checks that a refusal by the
// executor is not reported as a lost answer.
func TestRejectExecutorRefusalIsNotOutcomeUnknown(t *testing.T) {
	f := &fakeExec{rejectErr: status.Error(codes.FailedPrecondition, "privileged session required")}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reject(ctx, "axel", c.ID, ""); errors.Is(err, ErrRejectOutcomeUnknown) {
		t.Fatalf("refusal reported as a lost answer: %v", err)
	}
}

// TestSweepWaitsForAWebRejectionInFlight checks that the sweep does not record
// a rejection the executor reports while a web rejection of the same execution
// is still in flight. The executor has committed the rejection (the fake
// answers REJECTED from the moment RejectPending runs); the sweep starts in
// that window. It must wait for the web call to record the rejection, so the
// rejection keeps the web call's detail and is not recorded "after restart".
func TestSweepWaitsForAWebRejectionInFlight(t *testing.T) {
	f := &fakeExec{permitState: pb.PermitState_PERMIT_STATE_REJECTED, rejectedBy: pb.RejectingRole_REJECTING_ROLE_SERVER}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sweepDone := make(chan error, 1)
	f.beforeReject = func() {
		go func() {
			_, err := s.CheckCLIApproval(ctx, c.ID)
			sweepDone <- err
		}()
		// The sweep runs in this window, between the executor's commit and
		// the web call recording it.
		time.Sleep(100 * time.Millisecond)
	}
	if err := s.Reject(ctx, "axel", c.ID, "wrong host"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if err := <-sweepDone; err != nil {
		t.Fatalf("sweep: %v", err)
	}
	e, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "rejected" {
		t.Fatalf("state = %s, want rejected", e.State)
	}
	if want := rejectDetail("wrong host"); e.Detail != want {
		t.Fatalf("detail = %q, want the web rejection's detail %q", e.Detail, want)
	}
	if strings.Contains(e.Detail, "recorded after restart") {
		t.Fatalf("detail %q says the rejection was recorded after restart", e.Detail)
	}
}
