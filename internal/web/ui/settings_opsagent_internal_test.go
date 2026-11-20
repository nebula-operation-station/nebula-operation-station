// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"testing"
	"time"
)

// begin holds a slot and settles it under id, as the begin handler does.
func begin(t *testing.T, tab *opsAgentPendingTable, id string, p opsAgentPending, now time.Time) bool {
	t.Helper()
	if !tab.reserve(now) {
		return false
	}
	return tab.settle(id, p, now)
}

// A begun ops agent change can be taken only by the user who began it.
func TestOpsAgentPendingChangeIsBoundToItsUser(t *testing.T) {
	now := time.Unix(1791960000, 0)
	tab := newOpsAgentPendingTable()
	id := "ops-challenge-0000000001"
	if !begin(t, tab, id, opsAgentPending{user: "alice", change: OpsAgentChange{BaseVersion: 4}, expires: now.Add(opsAgentPendingTTL)}, now) {
		t.Fatal("begin refused on an empty table")
	}
	if _, ok := tab.take(id, "mallory", now); ok {
		t.Fatal("another user took the pending change")
	}
	c, ok := tab.take(id, "alice", now)
	if !ok || c.BaseVersion != 4 {
		t.Fatalf("owner could not take the change: ok=%v change=%+v", ok, c)
	}
	if _, ok := tab.take(id, "alice", now); ok {
		t.Fatal("a change was taken twice")
	}
}

// Another user's take also consumes nothing: the owner can still commit.
func TestOpsAgentForeignTakeKeepsChangeForOwner(t *testing.T) {
	now := time.Unix(1791960000, 0)
	tab := newOpsAgentPendingTable()
	id := "ops-challenge-0000000002"
	if !begin(t, tab, id, opsAgentPending{user: "alice", change: OpsAgentChange{BaseVersion: 7}, expires: now.Add(opsAgentPendingTTL)}, now) {
		t.Fatal("begin refused on an empty table")
	}
	tab.take(id, "mallory", now)
	if c, ok := tab.take(id, "alice", now); !ok || c.BaseVersion != 7 {
		t.Fatalf("owner lost the change after a foreign take: ok=%v", ok)
	}
}

// Expired challenges are refused and dropped; the table keeps its limit.
func TestOpsAgentPendingTableLimitAndTTL(t *testing.T) {
	now := time.Unix(1791960000, 0)
	tab := newOpsAgentPendingTable()
	for i := 0; i < maxOpsAgentPending; i++ {
		id := "ops-challenge-" + string(rune('a'+i)) + "000000000000000"
		if !begin(t, tab, id, opsAgentPending{user: "alice", expires: now.Add(opsAgentPendingTTL)}, now) {
			t.Fatalf("begin %d refused below the limit", i)
		}
	}
	if begin(t, tab, "ops-challenge-overflow0000000", opsAgentPending{user: "alice", expires: now.Add(opsAgentPendingTTL)}, now) {
		t.Fatal("begin accepted beyond the limit")
	}
	later := now.Add(opsAgentPendingTTL)
	if !begin(t, tab, "ops-challenge-after-ttl000000", opsAgentPending{user: "alice", expires: later.Add(opsAgentPendingTTL)}, later) {
		t.Fatal("expired entries still hold the limit")
	}
	if _, ok := tab.take("ops-challenge-a000000000000000", "alice", later); ok {
		t.Fatal("an expired challenge was taken")
	}
}
