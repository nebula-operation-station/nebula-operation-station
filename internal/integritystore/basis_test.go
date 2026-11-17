// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"errors"
	"testing"
	"time"
)

// fillFindings records n observations of class with unique paths, in
// batches of MaxObservationsPerBatch, in run, and fails on any error.
func fillFindings(t *testing.T, s *Store, runID string, class Class, start, n int) {
	t.Helper()
	for done := 0; done < n; done += MaxObservationsPerBatch {
		size := min(MaxObservationsPerBatch, n-done)
		batch := make([]Observation, 0, size)
		for i := start + done; i < start+done+size; i++ {
			batch = append(batch, Observation{Class: class, Path: sizedPath(i, 40)})
		}
		if _, err := s.Record(t.Context(), runID, batch); err != nil {
			t.Fatalf("fill %s at %d: %v", class, start+done, err)
		}
	}
}

// TestAcceptedFindingReopensWhenItsRecordsChange: an accepted finding keeps
// its state while the records it was accepted with are seen again, and
// reopens when either record differs (ADR 0011 D6 basis rule).
func TestAcceptedFindingReopensWhenItsRecordsChange(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Observation)
	}{
		{"new record", func(o *Observation) { o.NewRecord = "sha256=k2" }},
		{"old record", func(o *Observation) { o.OldRecord = "sha256=k0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := &clock{t: t0}
			s, _ := newTestStore(t, clk)
			subj := mustHost(t, "web-1")
			o := obs(ClassSSHKeyExtra, "/root/.ssh/authorized_keys")
			o.OldRecord = "sha256=k1"
			o.NewRecord = "sha256=k1-new"
			key := keyOf(subj, o)

			r1 := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), r1.ID, []Observation{o}); err != nil {
				t.Fatal(err)
			}
			if err := s.Accept(t.Context(), key, "admin"); err != nil {
				t.Fatalf("Accept: %v", err)
			}
			f, err := s.Get(t.Context(), key)
			if err != nil {
				t.Fatal(err)
			}
			if f.BasisOldRecord != "sha256=k1" || f.BasisNewRecord != "sha256=k1-new" {
				t.Fatalf("basis = %q / %q, want the accepted records", f.BasisOldRecord, f.BasisNewRecord)
			}
			if want := t0.Add(AcceptValidity); !f.ExpiresAt.Equal(want) {
				t.Fatalf("expires = %v, want %v", f.ExpiresAt, want)
			}
			finishComplete(t, s, r1.ID)

			// The same records seen again keep the acceptance.
			clk.Add(time.Hour)
			r2 := mustBegin(t, s, subj)
			res, err := s.Record(t.Context(), r2.ID, []Observation{o})
			if err != nil {
				t.Fatal(err)
			}
			if res.Reopened != 0 || res.Updated != 1 {
				t.Fatalf("same records: result = %+v, want one update", res)
			}
			if f, _ := s.Get(t.Context(), key); f.State != StateAccepted || f.StateBy != "admin" {
				t.Fatalf("same records: state = %s by %q, want accepted by admin", f.State, f.StateBy)
			}
			finishComplete(t, s, r2.ID)

			// A different record reopens it as an open finding of the new run.
			clk.Add(time.Hour)
			r3 := mustBegin(t, s, subj)
			changed := o
			tc.mutate(&changed)
			res, err = s.Record(t.Context(), r3.ID, []Observation{changed})
			if err != nil {
				t.Fatal(err)
			}
			if res.Reopened != 1 {
				t.Fatalf("changed records: result = %+v, want one reopened", res)
			}
			f, err = s.Get(t.Context(), key)
			if err != nil {
				t.Fatal(err)
			}
			if f.State != StateOpen || f.StateBy != "" || f.StateRunID != r3.ID {
				t.Errorf("state = %s by %q run %s, want open, no admin, run %s", f.State, f.StateBy, f.StateRunID, r3.ID)
			}
			if f.OldRecord != changed.OldRecord || f.NewRecord != changed.NewRecord {
				t.Errorf("records = %q / %q, want the changed ones", f.OldRecord, f.NewRecord)
			}
			if f.BasisOldRecord != "" || f.BasisNewRecord != "" || !f.ExpiresAt.IsZero() {
				t.Errorf("basis and expiry not cleared: %q / %q / %v", f.BasisOldRecord, f.BasisNewRecord, f.ExpiresAt)
			}
			if !f.FirstSeen.Equal(t0) {
				t.Errorf("first seen moved to %v; the finding was never closed", f.FirstSeen)
			}
		})
	}
}

// TestExpectedPendingFindingReopensWhenItsRecordsChange: an expected_pending
// finding is bound to the records it was marked with.
func TestExpectedPendingFindingReopensWhenItsRecordsChange(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	o := obs(ClassPkgUpdatedOutsideNOS, "/usr/bin/x")
	key := keyOf(subj, o)

	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{o}); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExpectedPending(t.Context(), r1.ID, key); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)

	clk.Add(time.Hour)
	r2 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r2.ID, []Observation{o}); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.Get(t.Context(), key); f.State != StateExpectedPending {
		t.Fatalf("same records: state = %s, want expected_pending", f.State)
	}
	changed := o
	changed.NewRecord = "sha256=other"
	res, err := s.Record(t.Context(), r2.ID, []Observation{changed})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reopened != 1 {
		t.Fatalf("changed records: result = %+v, want one reopened", res)
	}
	f, _ := s.Get(t.Context(), key)
	if f.State != StateOpen || f.BasisNewRecord != "" {
		t.Errorf("state = %s basis = %q, want open with no basis", f.State, f.BasisNewRecord)
	}
}

// TestAcceptanceExpiresAndReopens: an accepted finding re-opens once its
// acceptance has expired, even when its records did not change.
func TestAcceptanceExpiresAndReopens(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	o := obs(ClassEtcChanged, "/etc/motd")
	key := keyOf(subj, o)

	r1 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r1.ID, []Observation{o}); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(t.Context(), key, "admin"); err != nil {
		t.Fatal(err)
	}
	finishComplete(t, s, r1.ID)

	clk.Add(AcceptValidity - time.Minute)
	r2 := mustBegin(t, s, subj)
	if _, err := s.Record(t.Context(), r2.ID, []Observation{o}); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.Get(t.Context(), key); f.State != StateAccepted {
		t.Fatalf("before expiry: state = %s, want accepted", f.State)
	}
	finishComplete(t, s, r2.ID)

	clk.Add(time.Minute)
	r3 := mustBegin(t, s, subj)
	res, err := s.Record(t.Context(), r3.ID, []Observation{o})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reopened != 1 {
		t.Fatalf("after expiry: result = %+v, want one reopened", res)
	}
	if f, _ := s.Get(t.Context(), key); f.State != StateOpen || !f.ExpiresAt.IsZero() {
		t.Errorf("after expiry: state = %s expires %v, want open without expiry", f.State, f.ExpiresAt)
	}
}

// TestNonCriticalFindingsLeaveRoomForCriticalOnes: a subject flooded with
// high findings cannot keep critical findings out (D9 severity).
func TestNonCriticalFindingsLeaveRoomForCriticalOnes(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)

	fillFindings(t, s, run.ID, ClassEtcChanged, 0, MaxFindingsPerSubject-ReservedCriticalSlots)
	high := Observation{Class: ClassEtcChanged, Path: []byte("/etc/one-more-high")}
	res, err := s.Record(t.Context(), run.ID, []Observation{high})
	if err != nil {
		t.Fatal(err)
	}
	if res.OverLimit != 1 || res.Inserted != 0 {
		t.Fatalf("high over its share: %+v, want OverLimit 1", res)
	}

	crit := Observation{Class: ClassSSHKeyExtra, Path: []byte("/root/.ssh/authorized_keys")}
	res, err = s.Record(t.Context(), run.ID, []Observation{crit})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 1 || res.OverLimit != 0 {
		t.Fatalf("critical after high flood: %+v, want it stored", res)
	}

	fillFindings(t, s, run.ID, ClassSetIDNew, 0, ReservedCriticalSlots-1)
	if rowCount(t, db, subj) != MaxFindingsPerSubject {
		t.Fatalf("rows = %d, want %d", rowCount(t, db, subj), MaxFindingsPerSubject)
	}
	crit2 := Observation{Class: ClassNOSKeyMissing, Path: []byte("/root/.ssh/authorized_keys2")}
	res, err = s.Record(t.Context(), run.ID, []Observation{crit2})
	if err != nil {
		t.Fatal(err)
	}
	if res.OverLimit != 1 || res.Inserted != 0 {
		t.Fatalf("critical over the total limit: %+v, want OverLimit 1", res)
	}
	if fin := finishComplete(t, s, run.ID); fin.Outcome != OutcomeIncomplete || fin.Dropped != 2 {
		t.Fatalf("finish = %+v, want incomplete with two dropped", fin)
	}
}

// TestAcceptedFindingFreesItsSlot: an admin's Accept lowers the number of
// findings that count against the limit, so a subject at the limit can
// recover without database work.
func TestAcceptedFindingFreesItsSlot(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	fillFindings(t, s, run.ID, ClassCriticalPathChanged, 0, MaxFindingsPerSubject)

	extra := Observation{Class: ClassCriticalPathChanged, Path: []byte("/etc/new-critical")}
	res, err := s.Record(t.Context(), run.ID, []Observation{extra})
	if err != nil {
		t.Fatal(err)
	}
	if res.OverLimit != 1 {
		t.Fatalf("at the limit: %+v, want OverLimit 1", res)
	}
	if err := s.Accept(t.Context(), keyOf(subj, Observation{Class: ClassCriticalPathChanged, Path: sizedPath(0, 40)}), "admin"); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	res, err = s.Record(t.Context(), run.ID, []Observation{extra})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 1 || res.OverLimit != 0 {
		t.Fatalf("after Accept: %+v, want the finding stored", res)
	}
}

// TestRefusedBatchMarksRunDropped: a caller that ignores a refused batch
// cannot make the run close findings the batch would have seen.
func TestRefusedBatchMarksRunDropped(t *testing.T) {
	cases := []struct {
		name  string
		batch func() []Observation
	}{
		{"batch too large", func() []Observation {
			b := make([]Observation, MaxObservationsPerBatch+1)
			for i := range b {
				b[i] = Observation{Class: ClassEtcChanged, Path: sizedPath(i, 30)}
			}
			return b
		}},
		{"unknown class", func() []Observation {
			return []Observation{obs(ClassEtcChanged, "/etc/a"), obs(Class("made-up"), "/etc/b")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := &clock{t: t0}
			s, _ := newTestStore(t, clk)
			subj := mustHost(t, "web-1")
			keep := obs(ClassEtcChanged, "/etc/kept")
			r1 := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), r1.ID, []Observation{keep}); err != nil {
				t.Fatal(err)
			}
			finishComplete(t, s, r1.ID)

			clk.Add(time.Hour)
			r2 := mustBegin(t, s, subj)
			batch := tc.batch()
			if _, err := s.Record(t.Context(), r2.ID, batch); err == nil {
				t.Fatal("refused batch accepted")
			} else if !errors.Is(err, ErrBatchTooLarge) && !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("unexpected error: %v", err)
			}
			fin := finishComplete(t, s, r2.ID)
			if fin.Outcome != OutcomeIncomplete || fin.Closed != 0 || fin.Dropped != len(batch) {
				t.Fatalf("finish = %+v, want incomplete, nothing closed, %d dropped", fin, len(batch))
			}
			if f, _ := s.Get(t.Context(), keyOf(subj, keep)); f.State != StateOpen {
				t.Fatalf("finding closed by a run that refused its batch: %s", f.State)
			}
		})
	}
}

// TestResolvedFindingReopensAsNewEpisode: a resolved finding seen again is
// opened as a new episode with its own first_seen and opened run, and the
// closing fields are cleared.
func TestResolvedFindingReopensAsNewEpisode(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	a := obs(ClassEtcChanged, "/etc/a")
	b := obs(ClassEtcChanged, "/etc/b")
	kb := keyOf(subj, b)

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
	finishComplete(t, s, r2.ID)
	closed, _ := s.Get(t.Context(), kb)
	if closed.State != StateResolved || closed.ClosedRunID != r2.ID {
		t.Fatalf("b = %s closed by %q, want resolved by %s", closed.State, closed.ClosedRunID, r2.ID)
	}

	clk.Add(time.Hour)
	r3 := mustBegin(t, s, subj)
	res, err := s.Record(t.Context(), r3.ID, []Observation{b})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reopened != 1 || res.Inserted != 0 {
		t.Fatalf("result = %+v, want one reopened", res)
	}
	f, err := s.Get(t.Context(), kb)
	if err != nil {
		t.Fatal(err)
	}
	if f.State != StateOpen {
		t.Errorf("state = %s, want open", f.State)
	}
	if !f.FirstSeen.Equal(clk.Now()) {
		t.Errorf("first seen = %v, want the reopen time %v", f.FirstSeen, clk.Now())
	}
	if f.OpenedRunID != r3.ID || f.LastRunID != r3.ID {
		t.Errorf("opened=%s last=%s, want both %s", f.OpenedRunID, f.LastRunID, r3.ID)
	}
	if f.ClosedRunID != "" || !f.ClosedAt.IsZero() {
		t.Errorf("closing fields kept: run %q at %v", f.ClosedRunID, f.ClosedAt)
	}
}
