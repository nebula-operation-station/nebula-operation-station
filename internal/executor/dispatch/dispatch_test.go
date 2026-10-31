// SPDX-License-Identifier: AGPL-3.0-or-later

package dispatch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

var ctx = context.Background()

// fakeRecorder is a durable recorder test double: state survives being
// handed to a fresh Dispatcher, simulating an executor restart.
type fakeRecorder struct {
	mu          sync.Mutex
	intents     map[string]bool
	outcomes    map[string]Outcome
	failIntent  error
	failOutcome error
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{intents: map[string]bool{}, outcomes: map[string]Outcome{}}
}

func (r *fakeRecorder) RecordIntent(_ context.Context, run Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failIntent != nil {
		return r.failIntent
	}
	if r.intents[run.ExecutionID] {
		return fmt.Errorf("%w: %s", ErrIntentRecorded, run.ExecutionID)
	}
	r.intents[run.ExecutionID] = true
	return nil
}

func (r *fakeRecorder) RecordOutcome(_ context.Context, run Run, outcome Outcome) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failOutcome != nil {
		return r.failOutcome
	}
	if !r.intents[run.ExecutionID] {
		return errors.New("no intent recorded")
	}
	r.outcomes[run.ExecutionID] = outcome
	return nil
}

func (r *fakeRecorder) intentCount(id string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.intents[id] {
		return 1
	}
	return 0
}

func (r *fakeRecorder) outcome(id string) (Outcome, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.outcomes[id]
	return o, ok
}

func testRun(id string) Run {
	return Run{ParentDigest: "0000000000000000000000000000000000000000000000000000000000000001",
		MemberID: "member-0", ExecutionID: id, Target: "host-0", ActionID: "package.upgrade"}
}

func TestDispatchRunsOnce(t *testing.T) {
	rec := newFakeRecorder()
	var calls atomic.Int32
	d, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := testRun("00000000-0000-4000-8000-000000000001")
	outcome, err := d.Dispatch(ctx, run)
	if err != nil || outcome != OutcomeSuccess {
		t.Fatalf("first dispatch: %v %v", outcome, err)
	}
	outcome, err = d.Dispatch(ctx, run)
	if !errors.Is(err, ErrAlreadyDispatched) || outcome != OutcomeUnknown {
		t.Fatalf("second dispatch: %v %v", outcome, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
	if rec.intentCount(run.ExecutionID) != 1 {
		t.Fatal("intent not recorded exactly once")
	}
	if o, ok := rec.outcome(run.ExecutionID); !ok || o != OutcomeSuccess {
		t.Fatalf("outcome %q recorded=%v, want success", o, ok)
	}
}

func TestConcurrentDispatchIsSingleUse(t *testing.T) {
	for _, n := range []int{2, 8, 32} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			rec := newFakeRecorder()
			var calls atomic.Int32
			called := make(chan struct{})
			gate := make(chan struct{})
			d, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
				calls.Add(1)
				close(called)
				<-gate
				return OutcomeSuccess, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			run := testRun("00000000-0000-4000-8000-000000000007")
			var started, wg sync.WaitGroup
			started.Add(n)
			proceed := make(chan struct{})
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					started.Done()
					<-proceed
					_, _ = d.Dispatch(ctx, run)
				}()
			}
			started.Wait()
			close(proceed)
			<-called // exactly one dispatch reached the transport
			close(gate)
			wg.Wait()
			if calls.Load() != 1 {
				t.Fatalf("transport called %d times, want exactly 1", calls.Load())
			}
			if rec.intentCount(run.ExecutionID) != 1 {
				t.Fatal("intent recorded more than once")
			}
		})
	}
}

func TestDefinitiveFailureIsRecordedAndNotRetried(t *testing.T) {
	rec := newFakeRecorder()
	var calls atomic.Int32
	d, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeFailure, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := testRun("00000000-0000-4000-8000-000000000002")
	outcome, err := d.Dispatch(ctx, run)
	if err != nil || outcome != OutcomeFailure {
		t.Fatalf("dispatch: %v %v", outcome, err)
	}
	if _, err := d.Dispatch(ctx, run); !errors.Is(err, ErrAlreadyDispatched) {
		t.Fatalf("retry after failure: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
	if o, ok := rec.outcome(run.ExecutionID); !ok || o != OutcomeFailure {
		t.Fatalf("outcome %q recorded=%v, want failure", o, ok)
	}
}

func TestUncertainOutcomeIsNeverRedispatched(t *testing.T) {
	rec := newFakeRecorder()
	var calls atomic.Int32
	d, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeUnknown, errors.New("connection reset during dispatch")
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := testRun("00000000-0000-4000-8000-000000000003")
	outcome, err := d.Dispatch(ctx, run)
	if err == nil || outcome != OutcomeUnknown {
		t.Fatalf("dispatch: %v %v, want unknown outcome with error", outcome, err)
	}
	// The remote operation may have run: a retry must be refused, not
	// attempted.
	if _, err := d.Dispatch(ctx, run); !errors.Is(err, ErrAlreadyDispatched) {
		t.Fatalf("redispatch after uncertain outcome: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want exactly 1", calls.Load())
	}
	if o, ok := rec.outcome(run.ExecutionID); !ok || o != OutcomeUnknown {
		t.Fatalf("outcome %q recorded=%v, want unknown", o, ok)
	}
}

func TestRestartNeverRedispatchesRecordedIntent(t *testing.T) {
	rec := newFakeRecorder()
	run := testRun("00000000-0000-4000-8000-000000000004")
	// First process recorded the intent, then died before the transport
	// ran. The durable recorder is all that survives the restart.
	if err := rec.RecordIntent(ctx, run); err != nil {
		t.Fatal(err)
	}
	// Second process: same durable recorder, fresh Dispatcher.
	var calls atomic.Int32
	second, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := second.Dispatch(ctx, run)
	if !errors.Is(err, ErrAlreadyDispatched) || outcome != OutcomeUnknown {
		t.Fatalf("redispatch after restart: %v %v", outcome, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("transport called %d times after restart, want 0", calls.Load())
	}
}

func TestIntentStoreErrorIsRetryable(t *testing.T) {
	rec := newFakeRecorder()
	rec.failIntent = errors.New("recorder storage unavailable")
	var calls atomic.Int32
	d, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := testRun("00000000-0000-4000-8000-000000000005")
	if _, err := d.Dispatch(ctx, run); err == nil || errors.Is(err, ErrAlreadyDispatched) {
		t.Fatalf("storage error must not consume the run: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("transport ran although intent was not recorded")
	}
	rec.failIntent = nil
	outcome, err := d.Dispatch(ctx, run)
	if err != nil || outcome != OutcomeSuccess {
		t.Fatalf("retry after storage recovery: %v %v", outcome, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
}

func TestOutcomeStoreErrorStillConsumesRun(t *testing.T) {
	rec := newFakeRecorder()
	rec.failOutcome = errors.New("recorder storage unavailable")
	var calls atomic.Int32
	d, err := New(Options{Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := testRun("00000000-0000-4000-8000-000000000006")
	if _, err := d.Dispatch(ctx, run); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The remote operation ran; losing the outcome record must not make
	// the run dispatchable again.
	if _, err := d.Dispatch(ctx, run); !errors.Is(err, ErrAlreadyDispatched) {
		t.Fatalf("redispatch after outcome store error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
}

func TestDispatchRequiresExecutionID(t *testing.T) {
	rec := newFakeRecorder()
	d, err := New(Options{Recorder: rec, Transport: func(context.Context, Run) (Outcome, error) {
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := testRun("")
	if _, err := d.Dispatch(ctx, run); err == nil {
		t.Fatal("empty execution ID accepted")
	}
	if rec.intentCount("") != 0 {
		t.Fatal("empty execution ID recorded")
	}
}
