// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

var readGrantID = "00000000-0000-4000-8000-000000000001"

func readGrantDoc(t *testing.T) permit.StoredReadGrant {
	t.Helper()
	return permit.StoredReadGrant{ID: readGrantID, Digest: strings.Repeat("a", 64), Doc: []byte(`{}`),
		ApprovedBy: "webauthn:x", CreatedAt: t0, ExpiresAt: t0.Add(7 * 24 * time.Hour)}
}

func TestReadGrantStoreRoundTrip(t *testing.T) {
	db := openT(t, privateDir(t))
	g := readGrantDoc(t)
	if err := db.SaveReadGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveReadGrant(g); err == nil {
		t.Fatal("grant stored twice")
	}
	got, ok, err := db.ReadGrant(g.ID)
	if err != nil || !ok || got.Digest != g.Digest || !got.RevokedAt.IsZero() || !got.ExpiresAt.Equal(g.ExpiresAt) {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if _, ok, _ := db.ReadGrant("00000000-0000-4000-8000-000000000002"); ok {
		t.Fatal("unknown grant found")
	}
	if ok, err := db.RevokeReadGrant(g.ID, t0); err != nil || !ok {
		t.Fatal(err, ok)
	}
	if ok, _ := db.RevokeReadGrant(g.ID, t0); ok {
		t.Fatal("revoked twice")
	}
	all, err := db.ReadGrants()
	if err != nil || len(all) != 1 || all[0].RevokedAt.IsZero() {
		t.Fatalf("%+v %v", all, err)
	}
}

// reserve reserves one run and fails the test on a storage error.
func (db *DB) reserveT(t *testing.T, grantID, action, host string, at time.Time, budget int, floor time.Duration) bool {
	t.Helper()
	ok, err := db.ReserveReadRun(grantID, action, host, at, budget, floor)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestReserveReadRunBudget(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	// Budget 2 per target per hour: the third reservation of the hour
	// denies, whatever the action.
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 2, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	if !db.reserveT(t, readGrantID, "docker.list", "web", t0.Add(16*time.Minute), 2, 15*time.Minute) {
		t.Fatal("second run denied")
	}
	if db.reserveT(t, readGrantID, "core.facts", "web", t0.Add(32*time.Minute), 2, 15*time.Minute) {
		t.Fatal("budget not enforced")
	}
	// Another host has its own budget.
	if !db.reserveT(t, readGrantID, "core.facts", "db", t0, 2, 15*time.Minute) {
		t.Fatal("other host shares the budget")
	}
}

// The 15-minute per-action floor applies per action on the host and is
// shared across grants.
func TestReserveReadRunActionFloor(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 24, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	if db.reserveT(t, readGrantID, "core.facts", "web", t0.Add(14*time.Minute), 24, 15*time.Minute) {
		t.Fatal("floor not enforced")
	}
	// A different action is not bound by the other action's floor.
	if !db.reserveT(t, readGrantID, "docker.list", "web", t0.Add(14*time.Minute), 24, 15*time.Minute) {
		t.Fatal("other action bound by the floor")
	}
	// The floor clears once the interval has passed.
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0.Add(31*time.Minute), 24, 15*time.Minute) {
		t.Fatal("floor does not clear")
	}
}

// The rolling hour refills once the window has passed.
func TestReserveReadRunWindowRefills(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 1, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	if db.reserveT(t, readGrantID, "docker.list", "web", t0.Add(59*time.Minute), 1, 15*time.Minute) {
		t.Fatal("budget refilled inside the window")
	}
	if !db.reserveT(t, readGrantID, "docker.list", "web", t0.Add(61*time.Minute), 1, 15*time.Minute) {
		t.Fatal("budget did not refill after the window")
	}
}

// A wall-clock rollback never refills the budget: the window is anchored
// to the latest time seen.
func TestReserveReadRunClockRollback(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 1, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	// Advance past the window so the budget legitimately refills.
	if !db.reserveT(t, readGrantID, "docker.list", "web", t0.Add(2*time.Hour), 1, 15*time.Minute) {
		t.Fatal("second run denied")
	}
	// Roll the clock back to before the first run: still denied.
	if db.reserveT(t, readGrantID, "core.facts", "web", t0.Add(-time.Hour), 1, 15*time.Minute) {
		t.Fatal("rollback refilled the budget")
	}
}

// Overlapping grants share the per-target ceiling: they cannot multiply it.
func TestReserveReadRunSharedAcrossGrants(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	g2 := readGrantDoc(t)
	g2.ID = "00000000-0000-4000-8000-000000000002"
	g2.Digest = strings.Repeat("b", 64)
	if err := db.SaveReadGrant(g2); err != nil {
		t.Fatal(err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 2, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	if !db.reserveT(t, readGrantID, "docker.list", "web", t0.Add(16*time.Minute), 2, 15*time.Minute) {
		t.Fatal("second run denied")
	}
	// The target has spent its shared ceiling; the other grant cannot add.
	if db.reserveT(t, g2.ID, "docker.list", "web", t0.Add(32*time.Minute), 2, 15*time.Minute) {
		t.Fatal("overlapping grant multiplied the ceiling")
	}
}

// Spent budgets survive a restart on the same database.
func TestReserveReadRunSurvivesRestart(t *testing.T) {
	dir := privateDir(t)
	db, err := open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 1, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// A restarted executor on the same data directory.
	db2, err := open(dir, func() time.Time { return t0.Add(30 * time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if db2.reserveT(t, readGrantID, "core.facts", "web", t0.Add(30*time.Minute), 1, 15*time.Minute) {
		t.Fatal("spent budget did not survive the restart")
	}
}

// A storage failure surfaces as an error, which the executor denies on.
func TestReserveReadRunStorageError(t *testing.T) {
	dir := privateDir(t)
	db, err := open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReserveReadRun(readGrantID, "core.facts", "web", t0, 1, 15*time.Minute); err == nil {
		t.Fatal("reservation on a closed store succeeded")
	}
}
