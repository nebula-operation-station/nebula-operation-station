// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// cancelClassifier classifies every finding as class and calls cancel on
// call number after (1-based), so a Complete stops part-way through.
type cancelClassifier struct {
	mu     sync.Mutex
	class  Class
	calls  int
	after  int
	cancel context.CancelFunc
}

func (c *cancelClassifier) Classify(_ context.Context, _ Finding) (Class, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.cancel != nil && c.calls == c.after {
		c.cancel()
	}
	return c.class, nil
}

// arm makes the next Complete cancel ctx on its after-th classification.
func (c *cancelClassifier) arm(after int, cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls, c.after, c.cancel = 0, after, cancel
}

func (c *cancelClassifier) disarm() { c.arm(0, nil) }

func openStore(t *testing.T, db *sql.DB, clk *clock, cls Classifier) *Store {
	t.Helper()
	st, err := New(db, Config{Sources: testSources, Tier: testTier, Classifier: cls, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func newCancelEnv(t *testing.T, class Class) (*env, *cancelClassifier, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: t0}
	cls := &cancelClassifier{class: class}
	return &env{st: openStore(t, db, clk, cls), clk: clk, ctx: context.Background()}, cls, db
}

// atomicScenario seeds three hosts with five findings each and starts a run
// that covers all three and reports none of them: 15 closures over three
// subjects, below both guards.
func atomicScenario(t *testing.T, e *env) (Run, []vulnfinding.Key) {
	t.Helper()
	var keys []vulnfinding.Key
	hosts := []string{"app01", "db01", "web01"}
	for _, h := range hosts {
		for _, it := range e.seed(t, h, 5) {
			keys = append(keys, it.Finding.Key)
		}
	}
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("app01"), hostSubj("db01"), hostSubj("web01")})
	return r, keys
}

func states(t *testing.T, e *env, keys []vulnfinding.Key) []string {
	t.Helper()
	var out []string
	for _, k := range keys {
		f := e.get(t, k)
		out = append(out, fmt.Sprintf("%s/%s/%d/%d", f.State, f.ClosedBy, f.StateRunSeq, f.Rev))
	}
	return out
}

func TestCompleteCancelledPartWayAppliesNothingAndRetryFinishes(t *testing.T) {
	// Reference: the same scenario completed in one go.
	ref, _, _ := newCancelEnv(t, ClassUnconfirmed)
	refRun, refKeys := atomicScenario(t, ref)
	want := ref.complete(t, refRun)
	if want.ClosedUnconfirmed != 15 {
		t.Fatalf("reference completion = %+v", want)
	}
	wantStates := states(t, ref, refKeys)

	e, cls, _ := newCancelEnv(t, ClassUnconfirmed)
	r, keys := atomicScenario(t, e)
	before := states(t, e, keys)
	// Cancel on the 8th classification: the first subject is planned, the
	// second only half.
	ctx, cancel := context.WithCancel(context.Background())
	cls.arm(8, cancel)
	if _, err := e.st.Complete(ctx, r.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled complete: %v, want context.Canceled", err)
	}
	cls.disarm()
	if got := states(t, e, keys); !reflect.DeepEqual(got, before) {
		t.Fatalf("cancelled complete changed findings:\n got %v\nwant %v", got, before)
	}
	for _, h := range []string{"app01", "db01", "web01"} {
		wm, err := watermark(e.ctx, e.st.db, hostSubj(h).String())
		if err != nil || wm >= r.Seq {
			t.Fatalf("watermark of %s moved to %d (%v)", h, wm, err)
		}
	}
	if _, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("completion after cancel: %v, want ErrRunNotRunning", err)
	}

	// The retry runs on the untouched state and matches the reference.
	got := e.complete(t, r)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retried completion = %+v, want %+v", got, want)
	}
	if gotStates := states(t, e, keys); !reflect.DeepEqual(gotStates, wantStates) {
		t.Fatalf("final states differ:\n got %v\nwant %v", gotStates, wantStates)
	}
	saved, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln")
	if err != nil || !reflect.DeepEqual(saved, want) {
		t.Fatalf("saved completion = %+v, %v; want %+v", saved, err, want)
	}
	// A second complete changes nothing; the saved completion stays.
	if _, err := e.st.Complete(e.ctx, r.ID); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("second complete: %v, want ErrRunNotRunning", err)
	}
	if gotStates := states(t, e, keys); !reflect.DeepEqual(gotStates, wantStates) {
		t.Fatalf("second complete changed findings")
	}
}

// cutCtx is a context that is cancelled on the cut-th call of Done. The
// database layer calls Done for every statement, so a cut point picks a
// place in the sequence of statements of one Complete; cut 0 only counts.
type cutCtx struct {
	context.Context
	mu     sync.Mutex
	calls  int
	cut    int
	done   chan struct{}
	closed bool
}

func newCutCtx(cut int) *cutCtx {
	return &cutCtx{Context: context.Background(), cut: cut, done: make(chan struct{})}
}

func (c *cutCtx) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.cut > 0 && c.calls >= c.cut && !c.closed {
		close(c.done)
		c.closed = true
	}
	return c.done
}

func (c *cutCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return context.Canceled
	}
	return nil
}

// Cancelled at any point of a Complete, including while closures are being
// applied, nothing is applied; the retry matches an uninterrupted complete.
func TestCompleteCancelledAtAnyPointAppliesNothing(t *testing.T) {
	ref, _, _ := newCancelEnv(t, ClassUnconfirmed)
	refRun, refKeys := atomicScenario(t, ref)
	counter := newCutCtx(0)
	want, err := ref.st.Complete(counter, refRun.ID)
	if err != nil || want.ClosedUnconfirmed != 15 {
		t.Fatalf("reference completion = %+v, %v", want, err)
	}
	wantStates := states(t, ref, refKeys)
	total := counter.calls
	if total < 50 {
		t.Fatalf("only %d context checks in a complete; the cut points would not spread", total)
	}

	// Cut points from the start of planning to just before the commit; the
	// later ones fall into the apply phase.
	for _, pct := range []int{10, 50, 80, 90, 95, 99} {
		t.Run(fmt.Sprintf("cut%d", pct), func(t *testing.T) {
			e, _, _ := newCancelEnv(t, ClassUnconfirmed)
			r, keys := atomicScenario(t, e)
			before := states(t, e, keys)
			_, err := e.st.Complete(newCutCtx(total*pct/100), r.ID)
			if err == nil {
				t.Fatalf("complete cut at %d%% of %d succeeded", pct, total)
			}
			t.Logf("cut at %d of %d: %v", total*pct/100, total, err)
			if got := states(t, e, keys); !reflect.DeepEqual(got, before) {
				t.Fatalf("cut complete changed findings:\n got %v\nwant %v", got, before)
			}
			if _, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
				t.Fatalf("completion after cut: %v, want ErrRunNotRunning", err)
			}
			got := e.complete(t, r)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("retried completion = %+v, want %+v", got, want)
			}
			if gotStates := states(t, e, keys); !reflect.DeepEqual(gotStates, wantStates) {
				t.Fatalf("final states differ:\n got %v\nwant %v", gotStates, wantStates)
			}
		})
	}
}

func TestCompletionSurvivesARestart(t *testing.T) {
	e, _, db := newCancelEnv(t, ClassUnconfirmed)
	r, _ := atomicScenario(t, e)
	want := e.complete(t, r)

	// A new store on the same database (server restart).
	st2 := openStore(t, db, e.clk, &cancelClassifier{class: ClassUnconfirmed})
	got, err := st2.CompletionOf(e.ctx, r.ID, "hermes-vuln")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("completion after restart = %+v, %v; want %+v", got, err, want)
	}
	if _, err := st2.CompletionOf(e.ctx, r.ID, "other-token"); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("completion for another token: %v, want ErrRunNotFound", err)
	}
	if _, err := st2.CompletionOf(e.ctx, "00000000000000000000000000000000", "hermes-vuln"); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("completion of unknown run: %v, want ErrRunNotFound", err)
	}
	// Running and aborted runs have no completion.
	r2 := e.start(t)
	if _, err := st2.CompletionOf(e.ctx, r2.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("completion of running run: %v", err)
	}
	e.clk.Add(MaxRunDuration + time.Minute)
	if _, err := e.st.Complete(e.ctx, r2.ID); !errors.Is(err, ErrRunExpired) {
		t.Fatalf("late complete: %v", err)
	}
	if _, err := st2.CompletionOf(e.ctx, r2.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("completion of aborted run: %v", err)
	}
}

// largestRun starts a run covering MaxCoveredPerRun subjects, each with one
// open finding the run omits: MaxCoveredPerRun closures.
func largestRun(t *testing.T, e *env) (Run, []vulnfinding.Key) {
	t.Helper()
	subjects := make([]Subject, MaxCoveredPerRun)
	items := make([]Item, MaxCoveredPerRun)
	keys := make([]vulnfinding.Key, MaxCoveredPerRun)
	for i := range subjects {
		h := fmt.Sprintf("h%05d", i)
		subjects[i], items[i] = hostSubj(h), item(t, h, cve(0))
		keys[i] = items[i].Finding.Key
	}
	// The seed run opens the findings; it need not complete.
	seedRun := e.start(t)
	for b := 0; b < MaxCoveredPerRun/MaxCoveredPerBatch; b++ {
		lo, hi := b*MaxCoveredPerBatch, (b+1)*MaxCoveredPerBatch
		e.submit(t, seedRun, int64(b), nil, items[lo:hi]...)
	}
	r := e.start(t)
	for b := 0; b < MaxCoveredPerRun/MaxCoveredPerBatch; b++ {
		lo, hi := b*MaxCoveredPerBatch, (b+1)*MaxCoveredPerBatch
		e.submit(t, r, int64(b), subjects[lo:hi])
	}
	return r, keys
}

// The largest allowed run, cancelled one subject before the end, applies
// nothing; the retry closes everything and finishes well inside the API's
// complete budget.
func TestCompleteLargestRunIsAtomic(t *testing.T) {
	e, cls, _ := newCancelEnv(t, ClassEvidenced)
	r, keys := largestRun(t, e)

	ctx, cancel := context.WithCancel(context.Background())
	cls.arm(MaxCoveredPerRun-1, cancel)
	if _, err := e.st.Complete(ctx, r.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled complete: %v, want context.Canceled", err)
	}
	cls.disarm()
	for _, k := range []vulnfinding.Key{keys[0], keys[MaxCoveredPerRun/2], keys[MaxCoveredPerRun-1]} {
		e.wantState(t, k, StateOpen, "")
	}

	begin := time.Now()
	c := e.complete(t, r)
	took := time.Since(begin)
	t.Logf("complete of %d subjects took %v", MaxCoveredPerRun, took)
	if c.ClosedEvidenced != MaxCoveredPerRun || c.SubjectsBelowWatermark != 0 {
		t.Fatalf("completion = %+v", c)
	}
	for _, k := range []vulnfinding.Key{keys[0], keys[MaxCoveredPerRun/2], keys[MaxCoveredPerRun-1]} {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
	saved, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln")
	if err != nil || !reflect.DeepEqual(saved, c) {
		t.Fatalf("saved completion = %+v, %v", saved, err)
	}
}
