// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestCompleteRunClosesOmittedFindingsOfCoveredSubjects(t *testing.T) {
	e := newEnv(t)
	web := e.seed(t, "web01", 3)
	db := e.seed(t, "db01", 1)

	r := e.start(t)
	// web01 fully covered, reports only finding 0; db01 not covered.
	e.submit(t, r, 0, []Subject{hostSubj("web01")}, web[0])
	c := e.complete(t, r)
	if c.ClosedUnconfirmed != 2 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, web[0].Finding.Key, StateOpen, "")
	e.wantState(t, web[1].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
	e.wantState(t, web[2].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
	e.wantState(t, db[0].Finding.Key, StateOpen, "")
	if f := e.get(t, web[1].Finding.Key); f.StateRunSeq != r.Seq {
		t.Fatalf("closing run did not take state_run_seq: %d", f.StateRunSeq)
	}
}

func TestIncompleteOrAbortedRunClosesNothing(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)

	// Never completed and past 6 h: aborted, no closures.
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")}, item(t, "web01", cve(0), withFix(vulnfinding.FixNotAffected, "")))
	e.clk.Add(MaxRunDuration + time.Minute)
	if _, err := e.st.Complete(e.ctx, r.ID); !errors.Is(err, ErrRunExpired) {
		t.Fatalf("late complete: %v, want ErrRunExpired", err)
	}
	if _, err := e.st.Complete(e.ctx, r.ID); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("complete after abort: %v", err)
	}
	for _, it := range items {
		e.wantState(t, it.Finding.Key, StateOpen, "")
	}

	// AbortExpiredRuns aborts a forgotten run.
	r2 := e.start(t)
	e.clk.Add(MaxRunDuration + time.Minute)
	if n, err := e.st.AbortExpiredRuns(e.ctx); err != nil || n != 1 {
		t.Fatalf("abort expired = %d, %v", n, err)
	}
	if _, err := e.st.SubmitBatch(e.ctx, r2.ID, batchOf(0, nil)); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("batch to aborted run: %v", err)
	}
}

func TestNotAffectedClosesOnlyInCompleteRunOnCoveredSubject(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	na := item(t, "web01", cve(0), withFix(vulnfinding.FixNotAffected, ""))

	// Subject not covered: nothing closes.
	r1 := e.start(t)
	if res := e.submit(t, r1, 0, nil, na, items[1]); res.ClosureRequests != 1 {
		t.Fatalf("result = %+v", res)
	}
	e.complete(t, r1)
	e.wantState(t, items[0].Finding.Key, StateOpen, "")

	// Covered and completed: closes, counted as unevidenced.
	r2 := e.start(t)
	e.submit(t, r2, 0, []Subject{hostSubj("web01")}, na, items[1])
	c := e.complete(t, r2)
	if c.ClosedUnconfirmed != 1 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, items[0].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
	e.wantState(t, items[1].Finding.Key, StateOpen, "")

	// not_affected never opens a finding.
	r3 := e.start(t)
	fresh := item(t, "web01", "CVE-2026-9999", withFix(vulnfinding.FixNotAffected, ""))
	e.submit(t, r3, 0, nil, fresh)
	if _, err := e.st.Get(e.ctx, fresh.Finding.Key); !errors.Is(err, ErrFindingNotFound) {
		t.Fatal("not_affected record opened a finding")
	}
}

func TestRejectedRecordBlocksItsClosure(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	r := e.start(t)
	b := batchOf(0, []Subject{hostSubj("web01")})
	b.Rejected = []vulnfinding.Key{items[0].Finding.Key}
	if _, err := e.st.SubmitBatch(e.ctx, r.ID, b); err != nil {
		t.Fatal(err)
	}
	c := e.complete(t, r)
	if c.BlockedRejected != 1 || c.ClosedUnconfirmed != 1 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, items[0].Finding.Key, StateOpen, "")
	e.wantState(t, items[1].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
}

func TestWholeBatchRejectionBlocksAllClosures(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	e.cls.set(items[1].Finding.Key, ClassEvidenced)
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")})
	if err := e.st.RejectBatch(e.ctx, r.ID, 1, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	c := e.complete(t, r)
	if !c.BatchRejected || c.ClosedUnconfirmed+c.ClosedEvidenced != 0 {
		t.Fatalf("completion = %+v", c)
	}
	for _, it := range items {
		e.wantState(t, it.Finding.Key, StateOpen, "")
	}
}

func TestClosureNeedsEveryBasisSourceAcceptedAndFresh(t *testing.T) {
	cases := map[string]func(e *env) []RunSource{
		"omitted": func(e *env) []RunSource { return []RunSource{e.src("osv")} },
		"regressed": func(e *env) []RunSource {
			return []RunSource{e.src("osv"), e.srcAt("kev", e.clk.Now().Add(-81*time.Hour))}
		},
		"invalid": func(e *env) []RunSource { return []RunSource{e.src("osv"), e.srcAt("kev", e.clk.Now().Add(time.Hour))} },
		"stale": func(e *env) []RunSource {
			return []RunSource{e.src("osv"), e.srcAt("kev", e.clk.Now().Add(-73*time.Hour))}
		},
		"undated": func(e *env) []RunSource {
			return []RunSource{e.src("osv"), {ID: "kev", SnapshotID: "s", Integrity: vulnfinding.IntegrityNone, DateKind: DateKindNone}}
		},
	}
	for name, sources := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.clk.Add(24 * time.Hour)
			onKev := item(t, "web01", cve(0), withSources("osv", "kev"))
			onOSV := item(t, "web01", cve(1))
			// kev's mark lies 80 h back, so the stale case (73 h) is still
			// accepted and the regressed case (81 h) is below it.
			r0 := e.start(t, e.src("osv"), e.srcAt("kev", e.clk.Now().Add(-80*time.Hour)))
			e.submit(t, r0, 0, nil, onKev, onOSV)
			e.complete(t, r0)

			r := e.start(t, sources(e)...)
			e.submit(t, r, 0, []Subject{hostSubj("web01")})
			c := e.complete(t, r)
			if c.NotRequested != 1 || len(c.Held) != 0 {
				t.Fatalf("completion = %+v", c)
			}
			e.wantState(t, onKev.Finding.Key, StateOpen, "")
			// A finding on another, fresh source closes normally.
			e.wantState(t, onOSV.Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
		})
	}
}

func TestEvidencedRunClosureNeedsNoFreshSource(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1)
	e.cls.set(items[0].Finding.Key, ClassEvidenced)
	r := e.start(t, e.src("kev")) // osv omitted
	e.submit(t, r, 0, []Subject{hostSubj("web01")})
	if c := e.complete(t, r); c.ClosedEvidenced != 1 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, items[0].Finding.Key, StateFixed, ClosedByNOSInventory)
}

func TestContradictedAndKEVClosuresAreHeld(t *testing.T) {
	e := newEnv(t)
	contra := item(t, "web01", cve(0))
	kevDropped := item(t, "web01", cve(1), withKEV("2026-01-01"))
	critical := item(t, "web01", cve(2), withCVSS(9.9))
	failing := item(t, "web01", cve(3))
	r0 := e.start(t)
	e.submit(t, r0, 0, nil, contra, kevDropped, critical, failing)
	e.complete(t, r0)
	e.cls.set(contra.Finding.Key, ClassContradicted)
	e.cls.mu.Lock()
	e.cls.errs[failing.Finding.Key] = errors.New("inventory unavailable")
	e.cls.mu.Unlock()

	// Hermes first drops the KEV flag and lowers CVSS (accepted, dated)...
	r1 := e.start(t)
	e.submit(t, r1, 0, nil, item(t, "web01", cve(1)), item(t, "web01", cve(2), withCVSS(3.0)))
	e.complete(t, r1)
	// ...then omits all of them.
	r2 := e.start(t)
	e.submit(t, r2, 0, []Subject{hostSubj("web01")})
	c := e.complete(t, r2)
	if c.Held[HoldContradicted] != 1 || c.Held[HoldKEVOrCritical] != 2 || c.Held[HoldClassifyFailed] != 1 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("completion = %+v", c)
	}
	for _, it := range []Item{contra, kevDropped, critical, failing} {
		e.wantState(t, it.Finding.Key, StateOpen, "")
		if h, _ := e.st.Holds(e.ctx, it.Finding.Key); len(h) != 1 || h[0].RunID != r2.ID {
			t.Fatalf("holds = %+v", h)
		}
	}
}

func TestUnconfirmedUnchangedClosureIsLabelled(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1, withFix(vulnfinding.FixNoFixYet, ""))
	e.cls.set(items[0].Finding.Key, ClassUnconfirmedUnchanged)
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")})
	e.complete(t, r)
	if f := e.get(t, items[0].Finding.Key); f.ClosedBy != ClosedByHermesUnconfirmed || f.ClosedNote != NoteVersionUnchanged {
		t.Fatalf("closed = %s %q", f.ClosedBy, f.ClosedNote)
	}
}

func TestRunGuardHoldsBulkClosures(t *testing.T) {
	e := newEnv(t)
	var items []Item
	for h := 0; h < 5; h++ {
		host := []string{"h0", "h1", "h2", "h3", "h4"}[h]
		items = append(items, e.seed(t, host, 6)...)
	}
	// 30 open; a run omitting 4 of 6 on each host requests 20 closures:
	// > 50 % and >= 20.
	r := e.start(t)
	var covered []Subject
	var keep []Item
	for i, it := range items {
		if i%6 < 2 {
			keep = append(keep, it)
		}
	}
	for _, h := range []string{"h0", "h1", "h2", "h3", "h4"} {
		covered = append(covered, hostSubj(h))
	}
	e.submit(t, r, 0, covered, keep...)
	c := e.complete(t, r)
	if !c.RunGuard || c.Held[HoldRunGuard] != 20 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("completion = %+v", c)
	}
}

func TestRunGuardPerSubject(t *testing.T) {
	e := newEnv(t)
	big := e.seed(t, "big", 12)
	e.seed(t, "other", 30)
	// 11 of 12 on one subject: per-subject guard (> 50 %, >= 10), while
	// the overall count of 11 stays below the floor of 20.
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("big")}, big[0])
	c := e.complete(t, r)
	if !c.RunGuard || c.Held[HoldRunGuard] != 11 {
		t.Fatalf("completion = %+v", c)
	}
}

func TestRunGuardScopeExcludesFindingsTheRunOpened(t *testing.T) {
	e := newEnv(t)
	old := e.seed(t, "web01", 19)
	// A run that opens 100 findings does not widen its own guard scope.
	r := e.start(t)
	var fresh []Item
	for i := 0; i < 100; i++ {
		fresh = append(fresh, item(t, "web01", cve(500+i)))
	}
	e.submit(t, r, 0, []Subject{hostSubj("web01")}, fresh...)
	c := e.complete(t, r)
	// 19 closures of a scope of 19: per-subject guard trips (>= 10).
	if !c.RunGuard || c.Held[HoldRunGuard] != 19 {
		t.Fatalf("completion = %+v", c)
	}
	e.wantState(t, old[0].Finding.Key, StateOpen, "")
}

func TestWindowGuardStopsSecondRunWithinADay(t *testing.T) {
	e := newEnv(t)
	hosts := []string{}
	var items []Item
	for i := 0; i < 20; i++ {
		h := "h" + string(rune('a'+i))
		hosts = append(hosts, h)
		items = append(items, e.seed(t, h, 5)...)
	}
	e.clk.Add(25 * time.Hour) // the seed lies before the window
	all := func() []Subject {
		var s []Subject
		for _, h := range hosts {
			s = append(s, hostSubj(h))
		}
		return s
	}
	// Run 1 closes 40 of 100 (2 per host): below both guards.
	r1 := e.start(t)
	var keep1 []Item
	for i, it := range items {
		if i%5 >= 2 {
			keep1 = append(keep1, it)
		}
	}
	e.submit(t, r1, 0, all(), keep1...)
	if c := e.complete(t, r1); c.ClosedUnconfirmed != 40 || c.RunGuard || c.WindowGuard {
		t.Fatalf("run 1 = %+v", c)
	}
	// Run 2 closes 30 more of the 60 left: 50 % of its scope (no run guard),
	// but 70 of the window baseline of 100.
	e.clk.Add(time.Hour)
	r2 := e.start(t)
	var keep2 []Item
	n := 0
	for i, it := range items {
		if i%5 < 2 {
			continue
		}
		if n < 30 {
			n++
			continue
		}
		keep2 = append(keep2, it)
	}
	e.submit(t, r2, 0, all(), keep2...)
	c := e.complete(t, r2)
	if c.RunGuard || !c.WindowGuard || c.Held[HoldWindowGuard] != 30 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("run 2 = %+v", c)
	}
}

func TestWindowGuardBaselineIgnoresFindingsOpenedInWindow(t *testing.T) {
	e := newEnv(t)
	e.seed(t, "web01", 4)
	e.clk.Add(25 * time.Hour)
	// A run opens 100 findings inside the window; a later run closes 25 of
	// them and those don't count: they are not in the baseline.
	r1 := e.start(t)
	var fresh []Item
	for i := 0; i < 100; i++ {
		fresh = append(fresh, item(t, "web01", cve(500+i)))
	}
	e.submit(t, r1, 0, nil, fresh...)
	e.complete(t, r1)
	r2 := e.start(t)
	keep := append([]Item{}, e.seedItems(t, "web01", 4)...)
	keep = append(keep, fresh[25:]...)
	e.submit(t, r2, 0, []Subject{hostSubj("web01")}, keep...)
	c := e.complete(t, r2)
	if c.WindowGuard || c.RunGuard || c.ClosedUnconfirmed != 25 {
		t.Fatalf("completion = %+v", c)
	}
}

// seedItems rebuilds the items seed created (same keys).
func (e *env) seedItems(t *testing.T, host string, n int) []Item {
	items := make([]Item, n)
	for i := range items {
		items[i] = item(t, host, cve(i))
	}
	return items
}

func TestConfirmHeldClosure(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 3, withKEV("2026-01-01"))
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")})
	e.complete(t, r)

	// Unconfirmed → admin_confirmed.
	by, err := e.st.ConfirmHeld(e.ctx, r.ID, items[0].Finding.Key, "admin", "checked by hand")
	if err != nil || by != ClosedByAdminConfirmed {
		t.Fatalf("confirm = %s, %v", by, err)
	}
	f := e.get(t, items[0].Finding.Key)
	if f.ClosedAdmin != "admin" || f.ClosedReason != "checked by hand" {
		t.Fatalf("confirmation not recorded: %+v", f)
	}
	// Contradicted → never fixed.
	e.cls.set(items[1].Finding.Key, ClassContradicted)
	if _, err := e.st.ConfirmHeld(e.ctx, r.ID, items[1].Finding.Key, "admin", "x"); !errors.Is(err, ErrContradicted) {
		t.Fatalf("confirm contradicted: %v", err)
	}
	e.wantState(t, items[1].Finding.Key, StateOpen, "")
	// Discard (path 7).
	if err := e.st.DiscardHeld(e.ctx, r.ID, items[1].Finding.Key); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DiscardHeld(e.ctx, r.ID, items[1].Finding.Key); !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("second discard: %v", err)
	}
	// Bad input.
	if _, err := e.st.ConfirmHeld(e.ctx, r.ID, items[2].Finding.Key, "admin", ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty reason: %v", err)
	}
	if _, err := e.st.ConfirmHeld(e.ctx, r.ID, items[2].Finding.Key, "admin", string([]byte{0xff})); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid UTF-8 reason: %v", err)
	}
}

func TestConfirmHeldSupersededByNewerRun(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2, withKEV("2026-01-01"))
	r1 := e.start(t)
	e.submit(t, r1, 0, []Subject{hostSubj("web01")})
	e.complete(t, r1)
	// A newer run reports finding 0 (writes it) and covers the subject:
	// the older holds are superseded and dropped (path 7, automatic).
	r2 := e.start(t)
	e.submit(t, r2, 0, []Subject{hostSubj("web01")}, items[0], items[1])
	e.complete(t, r2)
	if _, err := e.st.ConfirmHeld(e.ctx, r1.ID, items[0].Finding.Key, "admin", "ok"); !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("confirm after newer run: %v", err)
	}
	e.wantState(t, items[0].Finding.Key, StateOpen, "")
}

func TestConfirmHeldSupersededWhenFindingWritten(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1, withKEV("2026-01-01"))
	r1 := e.start(t)
	e.submit(t, r1, 0, []Subject{hostSubj("web01")})
	e.complete(t, r1)
	// A newer, partial run updates the finding without covering the
	// subject: the watermark stays, but the finding changed.
	r2 := e.start(t)
	e.submit(t, r2, 0, nil, items[0])
	e.complete(t, r2)
	if _, err := e.st.ConfirmHeld(e.ctx, r1.ID, items[0].Finding.Key, "admin", "ok"); !errors.Is(err, ErrHoldSuperseded) {
		t.Fatalf("confirm after write: %v", err)
	}
	if h, _ := e.st.Holds(e.ctx, items[0].Finding.Key); len(h) != 0 {
		t.Fatal("superseded hold kept")
	}
	e.wantState(t, items[0].Finding.Key, StateOpen, "")
}

func TestInventoryClosePaths(t *testing.T) {
	e := newEnv(t)
	items := []Item{
		item(t, "web01", cve(0)),                                                            // installed 1.0-2 >= fixed 1.0-2: path 1
		item(t, "web01", cve(1), withPackage("zlib")),                                       // absent: path 2
		item(t, "web01", cve(2), withPackage("curl")),                                       // still below fixed
		item(t, "web01", cve(3), withPackage("linux")),                                      // kernel: never here
		item(t, "web01", cve(4), withFix(vulnfinding.FixNoFixYet, ""), withPackage("bash")), // no fixed version
	}
	r := e.start(t)
	e.submit(t, r, 0, nil, items...)
	e.complete(t, r)
	read := InventoryRead{Subject: hostSubj("web01"), ReadAt: e.clk.Now().Add(time.Second),
		SourceVersions: map[string]string{"openssl": "1.0-2", "curl": "1.0-1", "bash": "5.0-1"}}

	// A partial read closes nothing, and neither does a read older than the
	// last write.
	if k, err := e.st.CloseByInventory(e.ctx, read); err != nil || len(k) != 0 {
		t.Fatalf("partial read closed %d, %v", len(k), err)
	}
	read.Complete = true
	read.ReadAt = e.clk.Now().Add(-time.Second)
	if k, err := e.st.CloseByInventory(e.ctx, read); err != nil || len(k) != 0 {
		t.Fatalf("stale read closed %d, %v", len(k), err)
	}
	read.ReadAt = e.clk.Now().Add(time.Second)
	closed, err := e.st.CloseByInventory(e.ctx, read)
	if err != nil || len(closed) != 2 {
		t.Fatalf("complete read closed %d, %v", len(closed), err)
	}
	e.wantState(t, items[0].Finding.Key, StateFixed, ClosedByNOSInventory)
	e.wantState(t, items[1].Finding.Key, StateFixed, ClosedByNOSInventory)
	for _, it := range items[2:] {
		e.wantState(t, it.Finding.Key, StateOpen, "")
	}
}

func TestSubjectRemovedClosesEverything(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	other := e.seed(t, "db01", 1)
	if err := e.st.SetFalsePositive(e.ctx, items[1].Finding.Key, MarkFalsePositive{By: "admin", Category: CategoryOther, Reason: "r", BasisVersion: "1.0-1"}); err != nil {
		t.Fatal(err)
	}
	n, err := e.st.CloseSubjectRemoved(e.ctx, hostSubj("web01"))
	if err != nil || n != 2 {
		t.Fatalf("closed %d, %v", n, err)
	}
	for _, it := range items {
		e.wantState(t, it.Finding.Key, StateFixed, ClosedBySubjectRemoved)
	}
	e.wantState(t, other[0].Finding.Key, StateOpen, "")
}
