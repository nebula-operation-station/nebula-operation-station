// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"errors"
	"testing"
	"time"
)

func TestRetention(t *testing.T) {
	e := newEnv(t)
	day := 24 * time.Hour
	old := e.seed(t, "web01", 2)  // closed at day 0
	stays := e.seed(t, "db01", 1) // stays open throughout
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")}, old[1])
	e.complete(t, r) // old[0] fixed now
	runID := r.ID

	e.clk.Add(91 * day)
	res, err := e.st.Prune(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Assessment text of the closed finding gone after 90 days; the finding
	// itself stays; runs older than 90 days are gone.
	if res.ClearedAssessment != 1 || res.DeletedFindings != 0 || res.DeletedRuns == 0 {
		t.Fatalf("prune at 91 d = %+v", res)
	}
	f := e.get(t, old[0].Finding.Key)
	if f.Record.Assessment.Text != "" || f.State != StateFixed {
		t.Fatalf("closed finding after 91 d: %+v", f)
	}
	if open := e.get(t, old[1].Finding.Key); open.Record.Assessment.Text == "" {
		t.Fatal("assessment of open finding removed")
	}
	if _, err := loadRun(e.ctx, e.st.db, runID); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("run after 91 d: %v", err)
	}

	e.clk.Add(273 * day) // day 364
	if res, _ := e.st.Prune(e.ctx); res.DeletedFindings != 0 {
		t.Fatalf("fixed finding deleted before 365 d: %+v", res)
	}
	e.clk.Add(2 * day) // day 366
	if res, _ := e.st.Prune(e.ctx); res.DeletedFindings != 1 {
		t.Fatalf("prune at 366 d = %+v", res)
	}
	if _, err := e.st.Get(e.ctx, old[0].Finding.Key); !errors.Is(err, ErrFindingNotFound) {
		t.Fatal("fixed finding kept past 365 d")
	}
	e.wantState(t, old[1].Finding.Key, StateOpen, "")
	e.wantState(t, stays[0].Finding.Key, StateOpen, "")
}

func TestPruneKeepsRunningRunsAndAbortsExpired(t *testing.T) {
	e := newEnv(t)
	r := e.start(t)
	e.clk.Add(MaxRunDuration + time.Minute)
	res, err := e.st.Prune(e.ctx)
	if err != nil || res.AbortedRuns != 1 || res.DeletedRuns != 0 {
		t.Fatalf("prune = %+v, %v", res, err)
	}
	if run, err := loadRun(e.ctx, e.st.db, r.ID); err != nil || run.state != "aborted" {
		t.Fatalf("run = %+v, %v", run, err)
	}
}

func TestStaleness(t *testing.T) {
	e := newEnv(t)
	st, err := e.st.SubjectStatus(e.ctx, hostSubj("web01"))
	if err != nil || st.Assessment != NotAssessed {
		t.Fatalf("before any run = %+v, %v", st, err)
	}
	if off, last, _ := e.st.HermesOffline(e.ctx); !off || !last.IsZero() {
		t.Fatal("no run yet must count as offline")
	}
	// A run that did not cover the subject does not assess it.
	r := e.start(t)
	e.submit(t, r, 0, nil, item(t, "web01", cve(0)))
	e.complete(t, r)
	if st, _ := e.st.SubjectStatus(e.ctx, hostSubj("web01")); st.Assessment != NotAssessed {
		t.Fatalf("partial run assessed the subject: %+v", st)
	}
	e.seed(t, "web01", 1)
	if st, _ := e.st.SubjectStatus(e.ctx, hostSubj("web01")); st.Assessment != Fresh || !st.LastComplete.Equal(t0) {
		t.Fatalf("after complete run = %+v", st)
	}
	e.clk.Add(StaleAfter)
	if st, _ := e.st.SubjectStatus(e.ctx, hostSubj("web01")); st.Assessment != Fresh {
		t.Fatal("stale at exactly 48 h")
	}
	if off, _, _ := e.st.HermesOffline(e.ctx); off {
		t.Fatal("offline at exactly 48 h")
	}
	e.clk.Add(time.Second)
	if st, _ := e.st.SubjectStatus(e.ctx, hostSubj("web01")); st.Assessment != Stale {
		t.Fatal("not stale after 48 h")
	}
	if off, last, _ := e.st.HermesOffline(e.ctx); !off || !last.Equal(t0) {
		t.Fatal("not offline after 48 h")
	}
}
