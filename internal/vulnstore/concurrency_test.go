// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// An older run that completes after a newer one never closes a finding the
// newer run opened or updated.
func TestOlderRunCompletingLateDoesNotCloseNewerWrites(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	older := e.start(t)
	newer := e.start(t)
	added := item(t, "web01", "CVE-2026-7777")
	e.submit(t, newer, 0, []Subject{hostSubj("web01")}, items[0], items[1], added)
	e.complete(t, newer)

	// The older run omits everything and completes last.
	e.submit(t, older, 0, []Subject{hostSubj("web01")})
	c := e.complete(t, older)
	if c.SubjectsBelowWatermark != 1 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("older completion = %+v", c)
	}
	for _, it := range append(items, added) {
		e.wantState(t, it.Finding.Key, StateOpen, "")
		if f := e.get(t, it.Finding.Key); f.StateRunSeq != newer.Seq {
			t.Fatalf("state_run_seq = %d, want newer run %d", f.StateRunSeq, newer.Seq)
		}
	}
}

// The state_run_seq check alone also protects a finding the newer run
// wrote when the newer run did not cover the subject (no watermark).
func TestOlderRunCannotCloseFindingNewerPartialRunUpdated(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	older := e.start(t)
	newer := e.start(t)
	e.submit(t, newer, 0, nil, items[0]) // partial: no coverage
	e.complete(t, newer)
	e.submit(t, older, 0, []Subject{hostSubj("web01")})
	c := e.complete(t, older)
	if c.ClosedUnconfirmed != 1 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, items[0].Finding.Key, StateOpen, "")
	e.wantState(t, items[1].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
}

// An older run never overwrites data a newer run wrote.
func TestOlderRunCannotOverwriteNewerData(t *testing.T) {
	e := newEnv(t)
	base := item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-2"))
	r0 := e.start(t)
	e.submit(t, r0, 0, nil, base)
	e.complete(t, r0)

	older := e.start(t)
	newer := e.start(t)
	e.submit(t, newer, 0, nil, item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-8"), withText("newer")))
	res := e.submit(t, older, 0, nil, item(t, "web01", "CVE-2026-0001", withFix(vulnfinding.FixFixed, "1.0-4"), withText("older")))
	if res.Superseded != 1 || res.Updated != 0 {
		t.Fatalf("older batch = %+v", res)
	}
	f := e.get(t, base.Finding.Key)
	if f.Record.Fix.Version != "1.0-8" || f.Record.Assessment.Text != "newer" || f.StateRunSeq != newer.Seq {
		t.Fatalf("finding = fix %s text %q seq %d", f.Record.Fix.Version, f.Record.Assessment.Text, f.StateRunSeq)
	}
}

// An older run never re-opens a finding a newer run closed.
func TestOlderRunCannotReopenNewerClosure(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1)
	older := e.start(t)
	newer := e.start(t)
	e.submit(t, newer, 0, []Subject{hostSubj("web01")})
	e.complete(t, newer)
	e.wantState(t, items[0].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)

	res := e.submit(t, older, 0, []Subject{hostSubj("web01")}, items[0])
	if res.Superseded != 1 || res.Reopened != 0 {
		t.Fatalf("older batch = %+v", res)
	}
	e.complete(t, older)
	e.wantState(t, items[0].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
}

// A run below the subject watermark creates no hold either.
func TestRunBelowWatermarkHoldsNothing(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1, withKEV("2026-01-01"))
	older := e.start(t)
	newer := e.start(t)
	e.submit(t, newer, 0, []Subject{hostSubj("web01")})
	if c := e.complete(t, newer); c.Held[HoldKEVOrCritical] != 1 {
		t.Fatalf("newer = %+v", c)
	}
	e.submit(t, older, 0, []Subject{hostSubj("web01")})
	if c := e.complete(t, older); len(c.Held) != 0 || c.SubjectsBelowWatermark != 1 {
		t.Fatalf("older = %+v", c)
	}
	h, _ := e.st.Holds(e.ctx, items[0].Finding.Key)
	if len(h) != 1 || h[0].RunID != newer.ID {
		t.Fatalf("holds = %+v", h)
	}
}

func TestInventoryGenerationMustNotDecrease(t *testing.T) {
	e := newEnv(t)
	start := func(gen int64) error {
		_, err := e.st.StartRun(e.ctx, StartRequest{TokenID: "tok", InventoryGeneration: gen, InventoryAt: e.clk.Now(),
			MatcherVersion: "1.0", Sources: []RunSource{e.src("osv")}})
		return err
	}
	if err := start(9); err != nil {
		t.Fatal(err)
	}
	if err := start(8); !errors.Is(err, ErrInventoryRegressed) {
		t.Fatalf("lower generation: %v", err)
	}
	if err := start(9); err != nil {
		t.Fatalf("equal generation: %v", err)
	}
	if err := start(10); !errors.Is(err, ErrTooManyRuns) {
		t.Fatalf("third concurrent run of one token: %v", err)
	}
}

func TestRunSeqStrictlyIncreasing(t *testing.T) {
	e := newEnv(t)
	var last int64
	for i := 0; i < 5; i++ {
		r := e.start(t)
		if r.Seq <= last {
			t.Fatalf("run_seq %d after %d", r.Seq, last)
		}
		last = r.Seq
		e.complete(t, r)
	}
}

// Two runs submitting and completing in parallel: no errors, and the
// ordering rule decides every overlapping finding (run with -race).
func TestConcurrentRunsInParallel(t *testing.T) {
	e := newEnv(t)
	shared := e.seed(t, "web01", 20)
	older := e.start(t)
	newer := e.start(t)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	submit := func(r Run, seq int64, items ...Item) {
		defer wg.Done()
		if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(seq, nil, items...)); err != nil {
			errs <- err
		}
	}
	for i := 0; i < 10; i++ {
		wg.Add(2)
		// newer reports all shared findings; older reports half of them
		// with other values.
		go submit(newer, int64(i), shared[2*i], shared[2*i+1])
		go submit(older, int64(i), item(t, "web01", cve(2*i), withFix(vulnfinding.FixFixed, "1.0-1~old")))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Coverage arrives in a last batch of each run; complete both at once.
	if _, err := e.st.SubmitBatch(e.ctx, newer.ID, batchOf(100, []Subject{hostSubj("web01")})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.SubmitBatch(e.ctx, older.ID, batchOf(100, []Subject{hostSubj("web01")})); err != nil {
		t.Fatal(err)
	}
	wg.Add(2)
	var cOld, cNew Completion
	var errOld, errNew error
	go func() { defer wg.Done(); cOld, errOld = e.st.Complete(e.ctx, older.ID) }()
	go func() { defer wg.Done(); cNew, errNew = e.st.Complete(e.ctx, newer.ID) }()
	wg.Wait()
	if errOld != nil || errNew != nil {
		t.Fatalf("complete: %v / %v", errOld, errNew)
	}
	if cNew.ClosedUnconfirmed != 0 || cOld.ClosedUnconfirmed != 0 {
		t.Fatalf("closures: older %+v newer %+v", cOld, cNew)
	}
	for _, it := range shared {
		f := e.get(t, it.Finding.Key)
		if f.State != StateOpen {
			t.Fatalf("%s closed", f.Record.Vuln.ID)
		}
		// Whatever order the batches ran in, a finding the newer run wrote
		// never carries the older run's values afterwards.
		if f.StateRunSeq == newer.Seq && f.Record.Fix.Version == "1.0-1~old" {
			t.Fatalf("%s: older values over newer write", f.Record.Vuln.ID)
		}
	}
	if wm, _ := watermark(e.ctx, e.st.db, hostSubj("web01").String()); wm != newer.Seq {
		t.Fatalf("watermark = %d, want %d", wm, newer.Seq)
	}
}
