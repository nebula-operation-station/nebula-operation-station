// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// windowLab seeds hosts h0..h19 with per findings each, then moves the
// clock past the window so the seed lies before it.
func windowLab(t *testing.T, e *env, per int) (items []Item, all []Subject) {
	t.Helper()
	for i := 0; i < 20; i++ {
		h := "h" + string(rune('a'+i))
		all = append(all, hostSubj(h))
		items = append(items, e.seed(t, h, per)...)
	}
	return items, all
}

func except(items []Item, drop map[vulnfinding.Key]bool) []Item {
	var out []Item
	for _, it := range items {
		if !drop[it.Finding.Key] {
			out = append(out, it)
		}
	}
	return out
}

// TestWindowGuardNotLaunderedByReopenAndReclose: closing a set X, having
// it re-reported and closing it again must not drop X from the baseline or
// from the applied count.
func TestWindowGuardNotLaunderedByReopenAndReclose(t *testing.T) {
	e := newEnv(t)
	items, all := windowLab(t, e, 5)
	e.clk.Add(25 * time.Hour)

	x := map[vulnfinding.Key]bool{}
	for i, it := range items {
		if i%5 < 2 {
			x[it.Finding.Key] = true // 40 of 100, 2 per host
		}
	}
	// Run 1 closes X.
	r1 := e.start(t)
	e.submit(t, r1, 0, all, except(items, x)...)
	if c := e.complete(t, r1); c.ClosedUnconfirmed != 40 || c.WindowGuard || c.RunGuard {
		t.Fatalf("run 1 = %+v", c)
	}
	// Run 2 re-reports everything: X re-opens inside the window.
	e.clk.Add(time.Hour)
	r2 := e.start(t)
	if res := e.submit(t, r2, 0, all, items...); res.Reopened != 40 {
		t.Fatalf("run 2 = %+v", res)
	}
	e.complete(t, r2)
	// Run 3 closes X again.
	e.clk.Add(time.Hour)
	r3 := e.start(t)
	e.submit(t, r3, 0, all, except(items, x)...)
	if c := e.complete(t, r3); c.ClosedUnconfirmed != 40 || c.WindowGuard {
		t.Fatalf("run 3 = %+v", c)
	}
	// Run 4 closes 29 of the other 60: 29 of 60 passes the run guard, but
	// 40 + 29 of the window baseline of 100 must trip the window guard.
	e.clk.Add(time.Hour)
	y := map[vulnfinding.Key]bool{}
	for k := range x {
		y[k] = true
	}
	n := 0
	for _, it := range items {
		if !x[it.Finding.Key] && n < 29 {
			y[it.Finding.Key] = true
			n++
		}
	}
	r4 := e.start(t)
	e.submit(t, r4, 0, all, except(items, y)...)
	c := e.complete(t, r4)
	if c.RunGuard || !c.WindowGuard || c.Held[HoldWindowGuard] != 29 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("run 4 = %+v", c)
	}
}

// TestWindowGuardReopenDoesNotUncountAppliedClosure: closing X, having X
// re-reported (and left open), then closing another set Y must still count
// the applied closure of X in the window. Counting only findings that are
// fixed right now would see Y alone and let Y through.
func TestWindowGuardReopenDoesNotUncountAppliedClosure(t *testing.T) {
	e := newEnv(t)
	items, all := windowLab(t, e, 5)
	e.clk.Add(25 * time.Hour)

	x := map[vulnfinding.Key]bool{}
	for i, it := range items {
		if i%5 < 2 {
			x[it.Finding.Key] = true // 40 of 100, 2 per host
		}
	}
	// Run 1 closes X.
	r1 := e.start(t)
	e.submit(t, r1, 0, all, except(items, x)...)
	if c := e.complete(t, r1); c.ClosedUnconfirmed != 40 || c.WindowGuard || c.RunGuard {
		t.Fatalf("run 1 = %+v", c)
	}
	// Run 2 re-reports everything: X re-opens inside the window and stays
	// open from here on.
	e.clk.Add(time.Hour)
	r2 := e.start(t)
	if res := e.submit(t, r2, 0, all, items...); res.Reopened != 40 {
		t.Fatalf("run 2 = %+v", res)
	}
	e.complete(t, r2)
	// Run 3 keeps reporting X and closes 29 of the other 60: 29 of 100
	// open passes the run guard, but the applied 40 plus 29 of the window
	// baseline of 100 must trip the window guard.
	e.clk.Add(time.Hour)
	y := map[vulnfinding.Key]bool{}
	for _, it := range items {
		if !x[it.Finding.Key] && len(y) < 29 {
			y[it.Finding.Key] = true
		}
	}
	r3 := e.start(t)
	e.submit(t, r3, 0, all, except(items, y)...)
	c := e.complete(t, r3)
	if c.RunGuard || !c.WindowGuard || c.Held[HoldWindowGuard] != 29 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("run 3 = %+v", c)
	}
	for k := range x {
		e.wantState(t, k, StateOpen, "")
	}
	for k := range y {
		e.wantState(t, k, StateOpen, "")
	}
}

// TestWindowGuardBaselineCountsOnlyOpenFindings: accepted_risk and
// false_positive findings at window start are not in the baseline.
func TestWindowGuardBaselineCountsOnlyOpenFindings(t *testing.T) {
	e := newEnv(t)
	items, all := windowLab(t, e, 5)
	accepted := map[vulnfinding.Key]bool{}
	for i, it := range items {
		if i%5 == 4 { // 1 per host: 20 accepted_risk, 80 open
			accepted[it.Finding.Key] = true
			if err := e.st.SetAcceptedRisk(e.ctx, it.Finding.Key, AcceptRisk{Approver: "admin", Reason: "r", BasisVersion: "1.0-1"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.clk.Add(25 * time.Hour)
	open := except(items, accepted)

	// Run 1 closes 1 per host (20 of 80).
	drop := map[vulnfinding.Key]bool{}
	for i, it := range open {
		if i%4 == 0 {
			drop[it.Finding.Key] = true
		}
	}
	r1 := e.start(t)
	e.submit(t, r1, 0, all, except(open, drop)...)
	if c := e.complete(t, r1); c.ClosedUnconfirmed != 20 || c.WindowGuard || c.RunGuard {
		t.Fatalf("run 1 = %+v", c)
	}
	// Run 2 closes 21 more: 41 of the 80 open at window start trips the
	// window guard (with the 20 accepted in the baseline it would not).
	e.clk.Add(time.Hour)
	n := 0
	for i, it := range open {
		if (i%4 == 1 || (i == 2)) && n < 21 {
			drop[it.Finding.Key] = true
			n++
		}
	}
	r2 := e.start(t)
	e.submit(t, r2, 0, all, except(open, drop)...)
	c := e.complete(t, r2)
	if c.RunGuard || !c.WindowGuard || c.Held[HoldWindowGuard] != 21 {
		t.Fatalf("run 2 = %+v", c)
	}
}

// TestFindingHistoryRecordsStateChanges: every state change and every
// dropped KEV flag or fallen tier lands in the finding history.
func TestFindingHistoryRecordsStateChanges(t *testing.T) {
	e := newEnv(t)
	it := e.seed(t, "web01", 1, withKEV("2026-01-01"))[0]
	// An accepted, dated source drops the KEV flag: applied, and recorded.
	r := e.start(t)
	e.submit(t, r, 0, nil, item(t, "web01", cve(0)))
	e.complete(t, r)
	h, err := e.st.History(e.ctx, it.Finding.Key)
	if err != nil {
		t.Fatal(err)
	}
	var got []HistoryEvent
	for _, ev := range h {
		got = append(got, ev.Event)
	}
	want := []HistoryEvent{EventOpened, EventKEVDropped, EventTierFell}
	if len(got) != len(want) {
		t.Fatalf("history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("history = %v, want %v", got, want)
		}
	}
	if h[1].RunSeq != r.Seq {
		t.Fatalf("kev_dropped run_seq = %d, want %d", h[1].RunSeq, r.Seq)
	}
}
