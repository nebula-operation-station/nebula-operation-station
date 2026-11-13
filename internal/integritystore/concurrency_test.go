// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestConcurrentWritersOnDifferentSubjects runs several scans at once, one
// per subject, each recording and finishing in parallel. Every finding must
// land and every complete run must close only its own unseen findings.
func TestConcurrentWritersOnDifferentSubjects(t *testing.T) {
	clk := &clock{t: t0}
	s, db := newTestStore(t, clk)
	const writers = 6
	const perRun = 40
	var wg sync.WaitGroup
	errc := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			subj, err := HostSubject(fmt.Sprintf("h%d", w))
			if err != nil {
				errc <- err
				return
			}
			run, err := s.BeginRun(t.Context(), subj)
			if err != nil {
				errc <- fmt.Errorf("begin %s: %w", subj, err)
				return
			}
			batch := make([]Observation, 0, perRun)
			for i := 0; i < perRun; i++ {
				batch = append(batch, Observation{Class: ClassEtcChanged, Path: sizedPath(i, 24)})
			}
			res, err := s.Record(t.Context(), run.ID, batch)
			if err != nil {
				errc <- fmt.Errorf("record %s: %w", subj, err)
				return
			}
			if res.Inserted != perRun {
				errc <- fmt.Errorf("record %s: inserted %d, want %d", subj, res.Inserted, perRun)
				return
			}
			fin, err := s.Finish(t.Context(), run.ID, true)
			if err != nil {
				errc <- fmt.Errorf("finish %s: %w", subj, err)
				return
			}
			if fin.Outcome != OutcomeComplete || fin.Closed != 0 {
				errc <- fmt.Errorf("finish %s: %+v", subj, fin)
			}
		}(w)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	for w := 0; w < writers; w++ {
		subj, _ := HostSubject(fmt.Sprintf("h%d", w))
		if n := rowCount(t, db, subj); n != perRun {
			t.Errorf("%s: %d rows, want %d", subj, n, perRun)
		}
	}
}

// TestConcurrentBeginRunForOneSubjectAdmitsExactlyOne checks that the
// one-run-per-subject rule holds under races: exactly one BeginRun wins.
func TestConcurrentBeginRunForOneSubjectAdmitsExactlyOne(t *testing.T) {
	clk := &clock{t: t0}
	s, _ := newTestStore(t, clk)
	subj := mustHost(t, "web-1")
	const racers = 8
	var won, active atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.BeginRun(t.Context(), subj)
			switch {
			case err == nil:
				won.Add(1)
			case errors.Is(err, ErrRunActive):
				active.Add(1)
			default:
				t.Errorf("BeginRun: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 || active.Load() != racers-1 {
		t.Fatalf("won = %d, refused = %d; want 1 and %d", won.Load(), active.Load(), racers-1)
	}
}
