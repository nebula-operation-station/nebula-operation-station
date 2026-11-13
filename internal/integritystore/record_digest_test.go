// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"strings"
	"testing"
	"time"
)

// TestDroppedRecordChangeReopensHumanState: an accepted or expected_pending
// finding whose record is too large to store keeps its state only while the
// same record is seen. Two different oversized records must not compare
// equal just because both are stored empty.
func TestDroppedRecordChangeReopensHumanState(t *testing.T) {
	big := func(c byte) string { return strings.Repeat(string(c), MaxRecordBytes+1) }
	withRecord := func(rec string) Observation {
		o := obs(ClassEtcChanged, "/etc/big")
		o.NewRecord = rec
		return o
	}

	for _, state := range []State{StateAccepted, StateExpectedPending} {
		t.Run(string(state), func(t *testing.T) {
			clk := &clock{t: t0}
			s, _ := newTestStore(t, clk)
			subj := mustHost(t, "web-1")
			first := withRecord(big('a'))
			key := keyOf(subj, first)

			r1 := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), r1.ID, []Observation{first}); err != nil {
				t.Fatal(err)
			}
			finishComplete(t, s, r1.ID)

			clk.Add(time.Hour)
			r2 := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), r2.ID, []Observation{first}); err != nil {
				t.Fatal(err)
			}
			if state == StateExpectedPending {
				if err := s.MarkExpectedPending(t.Context(), r2.ID, key); err != nil {
					t.Fatal(err)
				}
			}
			finishComplete(t, s, r2.ID)
			if state == StateAccepted {
				if err := s.Accept(t.Context(), key, "ops-admin"); err != nil {
					t.Fatal(err)
				}
			}

			// The same oversized record keeps the state.
			clk.Add(time.Hour)
			r3 := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), r3.ID, []Observation{first}); err != nil {
				t.Fatal(err)
			}
			finishComplete(t, s, r3.ID)
			if f, _ := s.Get(t.Context(), key); f.State != state {
				t.Fatalf("same oversized record: state %s, want %s", f.State, state)
			}

			// A different oversized record reopens it.
			clk.Add(time.Hour)
			r4 := mustBegin(t, s, subj)
			if _, err := s.Record(t.Context(), r4.ID, []Observation{withRecord(big('b'))}); err != nil {
				t.Fatal(err)
			}
			finishComplete(t, s, r4.ID)
			if f, _ := s.Get(t.Context(), key); f.State != StateOpen {
				t.Fatalf("different oversized record: state %s, want open", f.State)
			}
		})
	}
}
