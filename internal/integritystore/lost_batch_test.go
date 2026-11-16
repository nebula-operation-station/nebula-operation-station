// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"context"
	"testing"
	"time"
)

// TestFailedRecordStopsRunFromClosingFindings: a Record that fails after its
// batch may have been lost (here: its context is cancelled before the
// write) marks the run as dropped, so a caller that still finishes the run
// as complete closes nothing that the lost batch would have refreshed.
func TestFailedRecordStopsRunFromClosingFindings(t *testing.T) {
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
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Record(ctx, r2.ID, []Observation{keep}); err == nil {
		t.Fatal("Record with a cancelled context succeeded")
	}
	fin, err := s.Finish(t.Context(), r2.ID, true)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if fin.Outcome != OutcomeIncomplete || fin.Closed != 0 || fin.Dropped < 1 {
		t.Fatalf("finish after a failed Record = %+v, want incomplete, nothing closed, something dropped", fin)
	}
	if f, _ := s.Get(t.Context(), keyOf(subj, keep)); f.State != StateOpen {
		t.Fatalf("finding closed by a run whose Record failed: %s", f.State)
	}
}

// TestRefusedRecordDoesNotDoubleCountDropped: a refused batch is counted once
// (ADR 0015 D9 dropped counter), not again as a lost batch.
func TestRefusedRecordDoesNotDoubleCountDropped(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	run := mustBegin(t, s, subj)
	batch := []Observation{obs(ClassEtcChanged, "/etc/a"), obs(Class("made-up"), "/etc/b")}
	if _, err := s.Record(t.Context(), run.ID, batch); err == nil {
		t.Fatal("refused batch accepted")
	}
	fin, err := s.Finish(t.Context(), run.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if fin.Dropped != len(batch) {
		t.Fatalf("Dropped = %d, want %d", fin.Dropped, len(batch))
	}
}
