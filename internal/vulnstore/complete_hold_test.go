// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"fmt"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// fakeHold replaces the store's lock-hold clock and step hook by a fake
// clock that advances by step for every unit of apply work, so the wall
// clock limit on an apply transaction is tested without real sleeps. The
// unit of work is one statement group, as applyChunk counts them.
func fakeHold(st *Store, step time.Duration) func() time.Duration {
	base := time.Date(2026, 11, 20, 4, 0, 0, 0, time.UTC)
	var elapsed time.Duration
	st.holdClock = func() time.Time { return base.Add(elapsed) }
	st.applyStep = func() { elapsed += step }
	return func() time.Duration { return elapsed }
}

// TestApplyTransactionStopsAtWallClockHoldLimit: an apply transaction takes
// units of work until the lock has been held for maxApplyHold on the
// injected clock, then commits. A complete of many small transactions
// therefore holds the write lock for at most maxApplyHold plus one unit
// each time. Without the limit one transaction takes all of them (row
// budget only) and holds the lock for their whole sum.
func TestApplyTransactionStopsAtWallClockHoldLimit(t *testing.T) {
	const step = 300 * time.Millisecond
	const hosts = 20
	e, _, _ := newPathEnv(t, ClassEvidenced)
	var keys []vulnfinding.Key
	var covered []Subject
	for i := 0; i < hosts; i++ {
		h := fmt.Sprintf("w%03d", i)
		for _, it := range e.seed(t, h, 1) {
			keys = append(keys, it.Finding.Key)
		}
		covered = append(covered, hostSubj(h))
	}
	r := e.start(t)
	e.submit(t, r, 0, covered)
	fakeHold(e.st, step)

	stats := recordApplyTx(e.st)
	c, err := e.st.Complete(e.ctx, r.ID)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	txs := stats()
	if len(txs) < 2 {
		t.Fatalf("%d apply transactions, want the hold limit to split the complete", len(txs))
	}
	for i, s := range txs {
		if s.held > maxApplyHold+step {
			t.Errorf("apply transaction %d held the write lock %v, limit %v plus one unit %v", i, s.held, maxApplyHold, step)
		}
	}
	if c.ClosedEvidenced != hosts {
		t.Fatalf("completion = %+v", c)
	}
	for _, k := range keys {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}

// TestSlowApplyUnitKeepsLockWithinBusyTimeout: a slow statement group (1.5 s
// on the injected clock, as a loaded machine or a large statement could
// take) must not keep the write lock for the busy timeout of the other
// writers of server.db. The transaction ends after the unit that crosses
// the limit; a resumed subject's watermark re-check, which is not a change,
// may add one more unit, so the hold is at most maxApplyHold plus two slow
// units, 4 s, below the 5 s busy timeout. The complete still finishes with
// the same result.
func TestSlowApplyUnitKeepsLockWithinBusyTimeout(t *testing.T) {
	const slow = 1500 * time.Millisecond
	const hosts = 10
	e, _, _ := newPathEnv(t, ClassEvidenced)
	var keys []vulnfinding.Key
	var covered []Subject
	for i := 0; i < hosts; i++ {
		h := fmt.Sprintf("s%03d", i)
		for _, it := range e.seed(t, h, 1) {
			keys = append(keys, it.Finding.Key)
		}
		covered = append(covered, hostSubj(h))
	}
	r := e.start(t)
	e.submit(t, r, 0, covered)
	fakeHold(e.st, slow)

	stats := recordApplyTx(e.st)
	c, err := e.st.Complete(e.ctx, r.ID)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	txs := stats()
	if len(txs) < 2 {
		t.Fatalf("%d apply transactions, want the hold limit to split the complete", len(txs))
	}
	for i, s := range txs {
		if s.held >= serverdb.DefaultBusyTimeout {
			t.Errorf("apply transaction %d held the write lock %v, busy timeout %v", i, s.held, serverdb.DefaultBusyTimeout)
		}
		if s.held > maxApplyHold+2*slow {
			t.Errorf("apply transaction %d held the write lock %v, limit %v plus two units %v", i, s.held, maxApplyHold, 2*slow)
		}
	}
	if c.ClosedEvidenced != hosts {
		t.Fatalf("completion = %+v", c)
	}
	for _, k := range keys {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}
