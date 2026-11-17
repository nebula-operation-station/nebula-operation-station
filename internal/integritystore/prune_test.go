// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"errors"
	"testing"
	"time"
)

func TestPruneKeepsResolvedFindingsAndRunsByRetention(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	a := obs(ClassEtcChanged, "/etc/a")
	b := obs(ClassEtcChanged, "/etc/b")

	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{a, b}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)
	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r2.ID, []Observation{a}); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r2.ID) // resolves b

	// After 100 days: b's record text is cleared (90 days after closing),
	// both runs are deleted (90 days after they ended), b is kept.
	clk.Add(100 * 24 * time.Hour)
	res, err := s.Prune(t.Context())
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if res.ClearedRecords != 1 || res.DeletedRuns != 2 || res.DeletedFindings != 0 {
		t.Fatalf("prune at 100 days = %+v", res)
	}
	fb, err := s.Get(t.Context(), keyOf(subj, b))
	if err != nil {
		t.Fatalf("resolved finding gone too early: %v", err)
	}
	if fb.NewRecord != "" || fb.State != StateResolved {
		t.Errorf("b after 90 days = record %q state %s", fb.NewRecord, fb.State)
	}
	if fa, err := s.Get(t.Context(), keyOf(subj, a)); err != nil || fa.State != StateOpen {
		t.Errorf("open finding a changed by prune: %v %+v", err, fa)
	}

	// 365 days after closing, the resolved finding is deleted.
	clk.Add(266 * 24 * time.Hour)
	res, err = s.Prune(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedFindings != 1 {
		t.Fatalf("prune at 366 days = %+v, want one finding deleted", res)
	}
	if _, err := s.Get(t.Context(), keyOf(subj, b)); !errors.Is(err, ErrFindingNotFound) {
		t.Errorf("b after retention: %v, want ErrFindingNotFound", err)
	}
}

func TestPruneAbortsOverdueRunAndClosesNothing(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	clk.Add(MaxRunDuration + time.Minute)
	res, err := s.Prune(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.AbortedRuns != 1 {
		t.Fatalf("AbortedRuns = %d, want 1", res.AbortedRuns)
	}
	if _, err := s.Finish(t.Context(), run.ID, true); !errors.Is(err, ErrRunNotRunning) {
		t.Errorf("Finish after abort: %v, want ErrRunNotRunning", err)
	}
	// The subject is free again for a new run.
	mustBegin(t, s, subj)
}
