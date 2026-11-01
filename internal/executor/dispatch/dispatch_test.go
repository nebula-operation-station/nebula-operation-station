// SPDX-License-Identifier: AGPL-3.0-or-later

package dispatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
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

// fakePermits is the batch authority's claimed-permit view: tests claim
// members into it and revoke them, as Lock or expiry would.
type fakePermits struct {
	mu      sync.Mutex
	permits map[string]batch.MemberPermit
	// onLookup runs on every lookup (before the result is read).
	onLookup func(n int)
	lookups  int
}

func newFakePermits() *fakePermits { return &fakePermits{permits: map[string]batch.MemberPermit{}} }

func permitKey(parent canonical.Digest, memberID string) string {
	return parent.String() + "/" + memberID
}

func (f *fakePermits) Member(parent canonical.Digest, memberID string) (batch.MemberPermit, bool) {
	f.mu.Lock()
	f.lookups++
	n, hook := f.lookups, f.onLookup
	f.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	mp, ok := f.permits[permitKey(parent, memberID)]
	return mp, ok
}

func (f *fakePermits) revoke(c claimed) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.permits, permitKey(c.parent, c.member))
}

// claimed names one claimed member and the run Dispatch derives from it.
type claimed struct {
	parent      canonical.Digest
	member      string
	ExecutionID string
	run         Run
}

var testParent = canonical.Digest{1}

// claim stores a member permit for execution ID id, as ClaimMember would.
func (f *fakePermits) claim(id string) claimed {
	mp := batch.MemberPermit{
		ParentDigest: testParent, Index: 0,
		Member: canonical.BatchMember{MemberID: "member-" + id, Request: canonical.Request{
			ExecutionID: id, ActionID: "package.upgrade", ArtifactSHA256: strings.Repeat("a", 64),
			ResolvedTargets: []canonical.Target{{HostID: "host-0"}},
		}},
		Parameters: []byte(`{"packages":"all"}`),
		Expiry:     time.Unix(1<<40, 0),
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.permits[permitKey(testParent, mp.Member.MemberID)] = mp
	return claimed{parent: testParent, member: mp.Member.MemberID, ExecutionID: id, run: runFrom(mp)}
}

func TestDispatchRunsOnce(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := perms.claim("00000000-0000-4000-8000-000000000001")
	outcome, err := d.Dispatch(ctx, run.parent, run.member)
	if err != nil || outcome != OutcomeSuccess {
		t.Fatalf("first dispatch: %v %v", outcome, err)
	}
	outcome, err = d.Dispatch(ctx, run.parent, run.member)
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
			perms := newFakePermits()
			var calls atomic.Int32
			called := make(chan struct{})
			gate := make(chan struct{})
			d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
				calls.Add(1)
				close(called)
				<-gate
				return OutcomeSuccess, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			run := perms.claim("00000000-0000-4000-8000-000000000007")
			var started, wg sync.WaitGroup
			started.Add(n)
			proceed := make(chan struct{})
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					started.Done()
					<-proceed
					_, _ = d.Dispatch(ctx, run.parent, run.member)
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
	perms := newFakePermits()
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeFailure, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := perms.claim("00000000-0000-4000-8000-000000000002")
	outcome, err := d.Dispatch(ctx, run.parent, run.member)
	if err != nil || outcome != OutcomeFailure {
		t.Fatalf("dispatch: %v %v", outcome, err)
	}
	if _, err := d.Dispatch(ctx, run.parent, run.member); !errors.Is(err, ErrAlreadyDispatched) {
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
	perms := newFakePermits()
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeUnknown, errors.New("connection reset during dispatch")
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := perms.claim("00000000-0000-4000-8000-000000000003")
	outcome, err := d.Dispatch(ctx, run.parent, run.member)
	if err == nil || outcome != OutcomeUnknown {
		t.Fatalf("dispatch: %v %v, want unknown outcome with error", outcome, err)
	}
	// The remote operation may have run: a retry must be refused, not
	// attempted.
	if _, err := d.Dispatch(ctx, run.parent, run.member); !errors.Is(err, ErrAlreadyDispatched) {
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
	perms := newFakePermits()
	run := perms.claim("00000000-0000-4000-8000-000000000004")
	// First process recorded the intent, then died before the transport
	// ran. The durable recorder is all that survives the restart.
	if err := rec.RecordIntent(ctx, run.run); err != nil {
		t.Fatal(err)
	}
	// Second process: same durable recorder, fresh Dispatcher.
	var calls atomic.Int32
	second, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := second.Dispatch(ctx, run.parent, run.member)
	if !errors.Is(err, ErrAlreadyDispatched) || outcome != OutcomeUnknown {
		t.Fatalf("redispatch after restart: %v %v", outcome, err)
	}
	if calls.Load() != 0 {
		t.Fatalf("transport called %d times after restart, want 0", calls.Load())
	}
}

func TestIntentStoreErrorIsRetryable(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	rec.failIntent = errors.New("recorder storage unavailable")
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := perms.claim("00000000-0000-4000-8000-000000000005")
	if _, err := d.Dispatch(ctx, run.parent, run.member); err == nil || errors.Is(err, ErrAlreadyDispatched) {
		t.Fatalf("storage error must not consume the run: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("transport ran although intent was not recorded")
	}
	rec.failIntent = nil
	outcome, err := d.Dispatch(ctx, run.parent, run.member)
	if err != nil || outcome != OutcomeSuccess {
		t.Fatalf("retry after storage recovery: %v %v", outcome, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
}

func TestOutcomeStoreErrorStillConsumesRun(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	rec.failOutcome = errors.New("recorder storage unavailable")
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, _ Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := perms.claim("00000000-0000-4000-8000-000000000006")
	if _, err := d.Dispatch(ctx, run.parent, run.member); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// The remote operation ran; losing the outcome record must not make
	// the run dispatchable again.
	if _, err := d.Dispatch(ctx, run.parent, run.member); !errors.Is(err, ErrAlreadyDispatched) {
		t.Fatalf("redispatch after outcome store error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
}

func TestDispatchRequiresExecutionID(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(context.Context, Run) (Outcome, error) {
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := perms.claim("")
	if _, err := d.Dispatch(ctx, run.parent, run.member); err == nil {
		t.Fatal("empty execution ID accepted")
	}
	if rec.intentCount("") != 0 {
		t.Fatal("empty execution ID recorded")
	}
}

// Only a live claimed member permit can be dispatched; a member that was
// never claimed records nothing and reaches no target.
func TestDispatchRefusesUnclaimedMember(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(context.Context, Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := d.Dispatch(ctx, testParent, "member-never-claimed")
	if !errors.Is(err, ErrNotClaimed) || outcome != OutcomeNotExecuted {
		t.Fatalf("dispatch = %v %v, want not claimed", outcome, err)
	}
	if calls.Load() != 0 || len(rec.intents) != 0 {
		t.Fatal("an unclaimed member was recorded or dispatched")
	}
}

// The transport receives exactly the frozen member and parameters from
// the permit.
func TestRunIsBuiltFromThePermit(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	var got Run
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(_ context.Context, run Run) (Outcome, error) {
		got = run
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := perms.claim("00000000-0000-4000-8000-000000000020")
	if _, err := d.Dispatch(ctx, c.parent, c.member); err != nil {
		t.Fatal(err)
	}
	if got.ExecutionID != c.ExecutionID || got.ActionID != "package.upgrade" || got.ParentDigest != testParent.String() ||
		got.Member.Request.ResolvedTargets[0].HostID != "host-0" || string(got.Parameters) != `{"packages":"all"}` {
		t.Fatalf("run = %+v", got)
	}
}

// A lock (or expiry or invalidation) after the intent is durable but
// before the transport ends the run as not executed: nothing reaches the
// target and the run is never dispatched afterwards.
func TestRevocationBeforeTransportIsNotExecuted(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	var calls atomic.Int32
	d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(context.Context, Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := perms.claim("00000000-0000-4000-8000-000000000021")
	perms.onLookup = func(n int) {
		if n == 2 { // the recheck after the intent was recorded
			perms.revoke(c)
		}
	}
	outcome, err := d.Dispatch(ctx, c.parent, c.member)
	if !errors.Is(err, ErrNotClaimed) || outcome != OutcomeNotExecuted {
		t.Fatalf("dispatch = %v %v, want not executed", outcome, err)
	}
	if calls.Load() != 0 {
		t.Fatal("a revoked permit reached the transport")
	}
	if o, ok := rec.outcome(c.ExecutionID); !ok || o != OutcomeNotExecuted {
		t.Fatalf("outcome %q recorded=%v, want not_executed", o, ok)
	}
}

// A transport that reports neither a definitive outcome nor an error is
// treated as uncertain, never as dispatched.
func TestNonDefinitiveTransportOutcomeIsUncertain(t *testing.T) {
	for _, reported := range []Outcome{"", OutcomeUnknown, "maybe", OutcomeNotExecuted} {
		t.Run(string(reported), func(t *testing.T) {
			rec := newFakeRecorder()
			perms := newFakePermits()
			d, err := New(Options{Permits: perms, Recorder: rec, Transport: func(context.Context, Run) (Outcome, error) {
				return reported, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			c := perms.claim("00000000-0000-4000-8000-000000000022")
			outcome, err := d.Dispatch(ctx, c.parent, c.member)
			if err == nil || outcome != OutcomeUnknown {
				t.Fatalf("dispatch = %v %v, want unknown with error", outcome, err)
			}
			if o, _ := rec.outcome(c.ExecutionID); o != OutcomeUnknown {
				t.Fatalf("recorded %q, want unknown", o)
			}
		})
	}
}

// ctxRecorder refuses to record with an ended context, like a real store.
type ctxRecorder struct{ *fakeRecorder }

func (r ctxRecorder) RecordOutcome(ctx context.Context, run Run, o Outcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.fakeRecorder.RecordOutcome(ctx, run, o)
}

// When the caller's context ends mid-dispatch (the uncertain case), the
// outcome is still recorded for reconciliation.
func TestOutcomeRecordedAfterCallerContextEnds(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	cctx, cancel := context.WithCancel(ctx)
	d, err := New(Options{Permits: perms, Recorder: ctxRecorder{rec}, Transport: func(context.Context, Run) (Outcome, error) {
		cancel()
		return OutcomeUnknown, context.Canceled
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := perms.claim("00000000-0000-4000-8000-000000000023")
	if _, err := d.Dispatch(cctx, c.parent, c.member); err == nil {
		t.Fatal("cancelled dispatch reported no error")
	}
	if o, ok := rec.outcome(c.ExecutionID); !ok || o != OutcomeUnknown {
		t.Fatalf("outcome %q recorded=%v, want unknown", o, ok)
	}
}

// Two dispatchers sharing one durable recorder (two goroutines of a
// restarted executor, or a stale and a fresh instance) still dispatch a
// member once.
func TestDispatchersSharingRecorderDispatchOnce(t *testing.T) {
	rec := newFakeRecorder()
	perms := newFakePermits()
	var calls atomic.Int32
	transport := func(context.Context, Run) (Outcome, error) {
		calls.Add(1)
		return OutcomeSuccess, nil
	}
	c := perms.claim("00000000-0000-4000-8000-000000000024")
	var wg sync.WaitGroup
	for range 8 {
		d, err := New(Options{Permits: perms, Recorder: rec, Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = d.Dispatch(ctx, c.parent, c.member)
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("transport called %d times, want 1", calls.Load())
	}
}
