// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"testing"
	"time"
)

// A held slot counts against the limit before the backend answers: reserve
// refuses once pending and held slots fill the table, and release gives a
// slot back.
func TestOpsAgentPendingReserveCountsHeldSlots(t *testing.T) {
	now := time.Unix(1791960000, 0)
	tab := newOpsAgentPendingTable()
	for i := 0; i < maxOpsAgentPending; i++ {
		if !tab.reserve(now) {
			t.Fatalf("reserve %d refused below the limit", i)
		}
	}
	if tab.reserve(now) {
		t.Fatal("reserve beyond the limit with all slots held")
	}
	tab.release()
	if !tab.reserve(now) {
		t.Fatal("a released slot was not free again")
	}
}

// settle turns a held slot into a pending change without exceeding the limit,
// and an expired pending change frees its slot.
func TestOpsAgentPendingSettleTurnsSlotIntoPendingChange(t *testing.T) {
	now := time.Unix(1791960000, 0)
	tab := newOpsAgentPendingTable()
	for i := 0; i < maxOpsAgentPending-1; i++ {
		if !begin(t, tab, "ops-challenge-live-"+string(rune('a'+i)), opsAgentPending{user: "alice", expires: now.Add(opsAgentPendingTTL)}, now) {
			t.Fatalf("begin %d refused", i)
		}
	}
	if !tab.reserve(now) {
		t.Fatal("reserve refused with one slot left")
	}
	if !tab.settle("ops-challenge-settled-000000000", opsAgentPending{user: "alice", expires: now.Add(opsAgentPendingTTL)}, now) {
		t.Fatal("settle refused the held slot")
	}
	if tab.reserve(now) {
		t.Fatal("the settled change did not take the last slot")
	}
	later := now.Add(opsAgentPendingTTL)
	if !tab.reserve(later) {
		t.Fatal("expired changes did not free their slots")
	}
}
