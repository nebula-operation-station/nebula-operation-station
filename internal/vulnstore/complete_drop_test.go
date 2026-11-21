// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"testing"
	"time"
)

// TestHoldDropStatementsStayWithinHoldLimit: the superseded holds are
// dropped in statements of at most maxDropRows rows, and the hold limit is
// checked before each statement. A statement that drops the whole row budget
// of a transaction (1024 rows) holds the write lock for its whole duration,
// seconds under the race detector, past the limit. The injected clock counts
// one step per unit of apply work, so the number of units shows the statement
// size: 3072 holds need at least 3072/maxDropRows drop statements.
func TestHoldDropStatementsStayWithinHoldLimit(t *testing.T) {
	const step = 300 * time.Millisecond
	const holds = 3 * rowBudget
	e, _, _ := newPathEnv(t, ClassEvidenced)
	seedSupersededHolds(t, e, "big", holds)
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("big")})
	fakeHold(e.st, step)
	units := 0
	count := e.st.applyStep
	e.st.applyStep = func() { units++; count() }

	stats := recordApplyTx(e.st)
	if _, err := e.st.Complete(e.ctx, r.ID); err != nil {
		t.Fatalf("complete: %v", err)
	}
	for i, s := range stats() {
		if s.held > maxApplyHold+step {
			t.Errorf("apply transaction %d held the write lock %v, limit %v plus one unit %v", i, s.held, maxApplyHold, step)
		}
	}
	if want := holds / maxDropRows; units < want {
		t.Errorf("%d units of apply work for %d holds, want at least %d drop statements of at most %d rows", units, holds, want, maxDropRows)
	}
	if n := heldOn(t, e, "big"); n != 0 {
		t.Fatalf("%d superseded holds left", n)
	}
}
