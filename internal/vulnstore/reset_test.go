// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// regressOSV seeds n findings on web01 (osv mark d = t0 - 1h) and starts
// and completes a run naming osv at reported (< d). It returns the seeded
// items, d and the regressed run.
func regressOSV(t *testing.T, e *env, n int, reported time.Time) ([]Item, time.Time, Run) {
	t.Helper()
	items := e.seed(t, "web01", n)
	d := e.clk.Now().Add(-time.Hour)
	r := e.start(t, e.srcAt("osv", reported))
	if r.Sources[0].Status != SourceRegressed {
		t.Fatalf("fixture: osv = %+v, want regressed", r.Sources[0])
	}
	e.complete(t, r)
	return items, d, r
}

func (e *env) reset(r Run, at time.Time) (MarkReset, error) {
	return e.st.ResetMark(e.ctx, MarkResetRequest{SourceID: "osv", RunID: r.ID, ContentDate: at, Admin: "admin", Reason: "provider re-dated data"})
}

func TestMarkResetLowersMarkAndReportsAuditFields(t *testing.T) {
	e := newEnv(t)
	_, d, r2 := regressOSV(t, e, 1, e.clk.Now().Add(-4*time.Hour))
	view, err := e.st.MarkResetCandidate(e.ctx, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if !view.MarkDate.Equal(d) || view.RunID != r2.ID || !view.ReportedDate.Equal(d.Add(-3*time.Hour)) || view.LastAcceptedSnapshot != "snap-osv" || view.Probation {
		t.Fatalf("view = %+v", view)
	}
	got, err := e.reset(r2, d.Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if got.SourceID != "osv" || got.Admin != "admin" || got.RunID != r2.ID || got.Reason != "provider re-dated data" ||
		!got.OldDate.Equal(d) || !got.NewDate.Equal(d.Add(-3*time.Hour)) || !got.PreResetDate.Equal(d) || !got.At.Equal(e.clk.Now()) {
		t.Fatalf("reset = %+v", got)
	}
	// A run naming osv above the reset value is accepted, on probation.
	r3 := e.start(t, e.srcAt("osv", d.Add(-2*time.Hour)))
	if v := r3.Sources[0]; v.Status != SourceAccepted || !v.Probation {
		t.Fatalf("after reset osv = %+v, want accepted on probation", v)
	}
}

func TestMarkResetRefusals(t *testing.T) {
	e := newEnv(t)
	_, d, r2 := regressOSV(t, e, 1, e.clk.Now().Add(-4*time.Hour))
	accepted := e.start(t, e.srcAt("osv", d)) // at the mark: accepted
	e.complete(t, accepted)
	r3 := e.start(t, e.srcAt("osv", d.Add(-90*time.Minute))) // a later regressed run
	e.complete(t, r3)
	good := MarkResetRequest{SourceID: "osv", RunID: r3.ID, ContentDate: d.Add(-90 * time.Minute), Admin: "admin", Reason: "why"}

	cases := []struct {
		name string
		mod  func(*MarkResetRequest)
		want error
	}{
		{"source not on the list", func(q *MarkResetRequest) { q.SourceID = "made-up" }, ErrResetRefused},
		{"run that did not regress the source", func(q *MarkResetRequest) { q.RunID = accepted.ID; q.ContentDate = d }, ErrResetRefused},
		{"unknown run", func(q *MarkResetRequest) { q.RunID = "nope" }, ErrResetRefused},
		{"older regressed run", func(q *MarkResetRequest) { q.RunID = r2.ID; q.ContentDate = d.Add(-3 * time.Hour) }, ErrResetRefused},
		{"value no run reported", func(q *MarkResetRequest) { q.ContentDate = d.Add(-80 * time.Minute) }, ErrResetRefused},
		{"sequence no run reported", func(q *MarkResetRequest) { v := int64(3); q.Sequence = &v }, ErrResetRefused},
		{"no reason", func(q *MarkResetRequest) { q.Reason = "" }, ErrInvalidInput},
		{"reason over 1 KiB", func(q *MarkResetRequest) { q.Reason = strings.Repeat("x", 1025) }, ErrInvalidInput},
		{"reason invalid UTF-8", func(q *MarkResetRequest) { q.Reason = "bad \xff" }, ErrInvalidInput},
		{"bad admin", func(q *MarkResetRequest) { q.Admin = "" }, ErrInvalidInput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := good
			c.mod(&q)
			if _, err := e.st.ResetMark(e.ctx, q); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	if _, err := e.st.ResetMark(e.ctx, good); err != nil {
		t.Fatalf("latest regressed run: %v", err)
	}
	// The mark is now at that value: a second reset to it lowers nothing.
	if _, err := e.st.ResetMark(e.ctx, good); !errors.Is(err, ErrResetRefused) {
		t.Fatalf("reset to the mark itself: %v, want ErrResetRefused", err)
	}
}

func TestMarkResetRefusesFutureValue(t *testing.T) {
	e := newEnv(t)
	_, _, r2 := regressOSV(t, e, 1, e.clk.Now().Add(-4*time.Hour))
	future := e.clk.Now().Add(MaxFutureSkew + time.Minute)
	if _, err := e.st.db.Exec(`UPDATE vuln_run_sources SET content_date = ? WHERE run_id = ? AND source_id = 'osv'`, unix(future), r2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reset(r2, future); !errors.Is(err, ErrResetRefused) {
		t.Fatalf("future value: %v, want ErrResetRefused", err)
	}
}

func TestRunStartedBeforeResetStaysFrozen(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1)
	d := e.clk.Now().Add(-time.Hour)
	r2 := e.start(t, e.srcAt("osv", d.Add(-3*time.Hour)))
	if _, err := e.reset(r2, d.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.submit(t, r2, 0, []Subject{hostSubj("web01")})
	if c := e.complete(t, r2); c.NotRequested != 1 || c.ClosedUnconfirmed != 0 {
		t.Fatalf("frozen run = %+v", c)
	}
	e.wantState(t, items[0].Finding.Key, StateOpen, "")
}

func TestProbationHoldsUnevidencedClosuresUntilAbovePreResetMark(t *testing.T) {
	e := newEnv(t)
	items, d, r2 := regressOSV(t, e, 2, e.clk.Now().Add(-4*time.Hour))
	a, b := items[0].Finding.Key, items[1].Finding.Key
	if _, err := e.reset(r2, d.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	e.cls.set(b, ClassEvidenced)
	web := []Subject{hostSubj("web01")}

	// Above the reset value, up to and including the pre-reset mark d: an
	// omitted A is held for an admin, whatever the guards say; the
	// evidenced B closes.
	for _, at := range []time.Time{d.Add(-3*time.Hour + time.Minute), d} {
		e.clk.Add(time.Minute)
		r := e.start(t, e.srcAt("osv", at))
		if !r.Sources[0].Probation {
			t.Fatalf("osv at %v not on probation", at)
		}
		e.submit(t, r, 0, web)
		c := e.complete(t, r)
		if c.Held[HoldProbation] != 1 || c.ClosedUnconfirmed != 0 {
			t.Fatalf("probation run at %v = %+v", at, c)
		}
		e.wantState(t, a, StateOpen, "")
	}
	e.wantState(t, b, StateFixed, ClosedByNOSInventory)

	// Strictly above d: probation ends and A closes normally.
	e.clk.Add(time.Minute)
	r := e.start(t, e.srcAt("osv", d.Add(time.Minute)))
	if r.Sources[0].Probation {
		t.Fatal("osv above the pre-reset mark still on probation")
	}
	e.submit(t, r, 0, web)
	if c := e.complete(t, r); c.ClosedUnconfirmed != 1 {
		t.Fatalf("after probation = %+v", c)
	}
	e.wantState(t, a, StateFixed, ClosedByHermesUnconfirmed)
	if view, err := e.st.MarkResetCandidate(e.ctx, "osv"); err != nil || view.Probation {
		t.Fatalf("view after probation = %+v, %v", view, err)
	}
}

func TestSecondResetDuringProbationKeepsHigherPreResetMark(t *testing.T) {
	e := newEnv(t)
	_, d, r2 := regressOSV(t, e, 1, e.clk.Now().Add(-4*time.Hour))
	if _, err := e.reset(r2, d.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// On probation the mark moves up with the run (to d - 2h) ...
	e.complete(t, e.start(t, e.srcAt("osv", d.Add(-2*time.Hour))))
	// ... a later run regresses below it and a second reset follows.
	r4 := e.start(t, e.srcAt("osv", d.Add(-150*time.Minute)))
	e.complete(t, r4)
	got, err := e.reset(r4, d.Add(-150*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !got.PreResetDate.Equal(d) {
		t.Fatalf("pre-reset mark = %v, want the first one %v", got.PreResetDate, d)
	}
	if r := e.start(t, e.srcAt("osv", d.Add(-time.Hour))); !r.Sources[0].Probation {
		t.Fatal("past the second reset's mark but not past d: probation ended")
	}
	if r := e.start(t, e.srcAt("osv", d.Add(time.Minute))); r.Sources[0].Probation {
		t.Fatal("past d: still on probation")
	}
}

func TestProbationSequenceMustPassPreResetSequence(t *testing.T) {
	e := newEnv(t)
	seq := func(v int64) *int64 { return &v }
	csaf := func(at time.Time, s int64) RunSource {
		r := e.srcAt("cisco-csaf", at)
		r.Sequence = seq(s)
		return r
	}
	now := e.clk.Now()
	e.complete(t, e.start(t, csaf(now.Add(-time.Hour), 10)))
	r2 := e.start(t, csaf(now.Add(-time.Hour), 3)) // operator restarted the sequence
	e.complete(t, r2)
	if _, err := e.st.ResetMark(e.ctx, MarkResetRequest{SourceID: "cisco-csaf", RunID: r2.ID, ContentDate: now.Add(-time.Hour), Sequence: seq(3),
		Admin: "admin", Reason: "new signing key"}); err != nil {
		t.Fatal(err)
	}
	// A newer date with a sequence not past 10 stays on probation.
	if r := e.start(t, csaf(now.Add(-time.Minute), 4)); !r.Sources[0].Probation {
		t.Fatal("sequence 4 after pre-reset 10 ended probation")
	}
	if r := e.start(t, csaf(now, 11)); r.Sources[0].Probation {
		t.Fatal("sequence 11 and newer date still on probation")
	}
}

func TestProbationUpdatesOnlyRaise(t *testing.T) {
	e := newEnv(t)
	_, d, r2 := regressOSV(t, e, 1, e.clk.Now().Add(-4*time.Hour))
	if _, err := e.reset(r2, d.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := e.start(t, e.srcAt("osv", d.Add(-2*time.Hour)))
	low := item(t, "web01", cve(0), withCVSS(3.0), withFix(vulnfinding.FixNoFixYet, ""), withText("rewritten"))
	res := e.submit(t, r, 0, nil, low)
	if len(res.Ignored) != 3 {
		t.Fatalf("ignored = %+v, want fix, cvss, assessment", res.Ignored)
	}
	f := e.get(t, low.Finding.Key)
	if f.Record.Scores.CVSS.BaseScore != 5.0 || f.Record.Fix.Version != "1.0-2" || f.Record.Assessment.Text != "assessment v1" {
		t.Fatalf("probation record lowered values: %+v", f.Record)
	}
	high := item(t, "web01", cve(0), withCVSS(8.0))
	e.submit(t, r, 1, nil, high)
	if f := e.get(t, low.Finding.Key); f.Record.Scores.CVSS.BaseScore != 8.0 || f.EpisodePeakTier != TierHigh {
		t.Fatalf("probation record did not raise: %+v", f)
	}
	e.complete(t, r)
	// After probation ends, a record resting on osv lowers as reported.
	r5 := e.start(t, e.srcAt("osv", d.Add(time.Minute)))
	e.submit(t, r5, 0, nil, low)
	if f := e.get(t, low.Finding.Key); f.Record.Scores.CVSS.BaseScore != 3.0 || f.Record.Assessment.Text != "rewritten" {
		t.Fatalf("after probation: %+v", f.Record)
	}
}
