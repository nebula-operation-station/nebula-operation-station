// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

func TestReserveReadRunRejectsInactiveGrant(t *testing.T) {
	for _, state := range []string{"revoked", "expired", "unknown", "expired after rollback"} {
		t.Run(state, func(t *testing.T) {
			db := openT(t, privateDir(t))
			g := readGrantDoc(t)
			if state != "unknown" {
				if err := db.SaveReadGrant(g); err != nil {
					t.Fatal(err)
				}
			}
			at := t0
			switch state {
			case "revoked":
				if ok, err := db.RevokeReadGrant(g.ID, at); err != nil || !ok {
					t.Fatalf("revoke: %v, %v", ok, err)
				}
			case "expired":
				at = g.ExpiresAt
			case "expired after rollback":
				if _, err := db.sql.Exec(`UPDATE read_clock SET high_water = ?`, g.ExpiresAt.Unix()); err != nil {
					t.Fatal(err)
				}
			}
			if ok, err := db.ReserveReadRun(g.ID, "core.facts", "web", at, 1, 15*time.Minute); ok || !errors.Is(err, permit.ErrReadGrantInactive) {
				t.Fatalf("inactive grant reserved: %v, %v", ok, err)
			}
			var spent int
			if err := db.sql.QueryRow(`SELECT COUNT(*) FROM read_run_log`).Scan(&spent); err != nil || spent != 0 {
				t.Fatalf("inactive claim spent budget: %d, %v", spent, err)
			}
		})
	}
}

func TestLegacyScheduleMigrationPreservesApprovalAndClaims(t *testing.T) {
	dir := privateDir(t)
	ms := mustMigrations(t)
	shared := -1
	for i, m := range ms {
		if m.name == "0016_shared_read_grants.sql" {
			shared = i
		}
	}
	if shared < 1 {
		t.Fatal("shared grant migration missing")
	}
	if err := seedPrePveDatabase(t, dir, ms[:shared]); err != nil {
		t.Fatal(err)
	}
	old, err := sql.Open("sqlite", filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	const legacyID = "00000000-0000-4000-8000-000000000002"
	expires := t0.Add(90 * 24 * time.Hour)
	for _, row := range []struct {
		id, digest string
		revoked    any
	}{
		{legacyID, strings.Repeat("b", 64), nil},
		{"00000000-0000-4000-8000-000000000003", strings.Repeat("c", 64), t0.Unix()},
	} {
		if _, err := old.Exec(`INSERT INTO schedule_grants (id, digest, doc, approved_by, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.id, row.digest, []byte(`{"grant":"read-schedule-v1"}`), "webauthn:legacy", t0.Unix(), expires.Unix(), row.revoked); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := old.Exec(`INSERT INTO schedule_runs (grant_id, action_id, host_id, last_run) VALUES (?, 'core.facts', 'web', ?)`, legacyID, t0.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db := openT(t, dir)
	all, err := db.ReadGrants()
	if err != nil || len(all) != 2 {
		t.Fatalf("migrated approvals: %+v, %v", all, err)
	}
	g, ok, err := db.ScheduleGrant(legacyID)
	if err != nil || !ok || g.Digest != strings.Repeat("b", 64) || string(g.Doc) != `{"grant":"read-schedule-v1"}` || g.ApprovedBy != "webauthn:legacy" || !g.ExpiresAt.Equal(expires) {
		t.Fatalf("migration changed approval: %+v, %v, %v", g, ok, err)
	}
	revoked, ok, err := db.ReadGrant("00000000-0000-4000-8000-000000000003")
	if err != nil || !ok || !revoked.RevokedAt.Equal(t0) {
		t.Fatalf("migration lost revocation: %+v, %v", revoked, err)
	}
	if db.reserveT(t, legacyID, "docker.list", "web", t0, 1, 15*time.Minute) {
		t.Fatal("migration lost spent budget")
	}
	if db.reserveT(t, legacyID, "core.facts", "web", t0.Add(14*time.Minute), 2, 15*time.Minute) {
		t.Fatal("migration lost action floor")
	}
	if !db.reserveT(t, legacyID, "core.facts", "web", t0.Add(15*time.Minute), 2, 15*time.Minute) {
		t.Fatal("migrated action floor never clears")
	}
	var obsolete int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('schedule_grants', 'schedule_runs')`).Scan(&obsolete); err != nil || obsolete != 0 {
		t.Fatalf("migration duplicated authority: %d old tables, %v", obsolete, err)
	}
}

func TestLegacyScheduleSharesReadGrantAccounting(t *testing.T) {
	for _, first := range []string{"read", "schedule"} {
		t.Run(first, func(t *testing.T) {
			db := openT(t, privateDir(t))
			g := readGrantDoc(t)
			if err := db.SaveReadGrant(g); err != nil {
				t.Fatal(err)
			}
			s := permit.StoredGrant{ID: "00000000-0000-4000-8000-000000000002", Digest: strings.Repeat("b", 64), Doc: []byte(`{}`),
				ApprovedBy: g.ApprovedBy, CreatedAt: t0, ExpiresAt: t0.Add(90 * 24 * time.Hour)}
			if err := db.SaveScheduleGrant(s); err != nil {
				t.Fatal(err)
			}
			all, err := db.ReadGrants()
			if err != nil || len(all) != 2 {
				t.Fatalf("shared registry: %+v, %v", all, err)
			}
			claim := func(kind, action string) bool {
				t.Helper()
				var ok bool
				var err error
				if kind == "read" {
					ok, err = db.ReserveReadRun(g.ID, action, "web", t0, permit.GlobalRunBudget, 15*time.Minute)
				} else {
					ok, err = db.ClaimScheduleRun(s.ID, action, "web", t0, 15*time.Minute)
				}
				if err != nil {
					t.Fatal(err)
				}
				return ok
			}
			other := "schedule"
			if first == "schedule" {
				other = "read"
			}
			if !claim(first, "core.facts") {
				t.Fatal("first claim denied")
			}
			if claim(other, "core.facts") {
				t.Fatal("legacy schedule bypassed shared action floor")
			}
			for i := 1; i < permit.GlobalRunBudget; i++ {
				if !claim(first, fmt.Sprintf("action.%d", i)) {
					t.Fatalf("claim %d denied", i)
				}
			}
			if claim(other, "service.list") {
				t.Fatal("legacy schedule bypassed shared target ceiling")
			}
			stored, ok, err := db.ReadGrant(s.ID)
			if err != nil || !ok || !stored.ExpiresAt.Equal(s.ExpiresAt) || string(stored.Doc) != string(s.Doc) {
				t.Fatalf("legacy approval changed: %+v, %v, %v", stored, ok, err)
			}
			if ok, err := db.RevokeReadGrant(s.ID, t0); err != nil || !ok {
				t.Fatalf("shared revoke: %v, %v", ok, err)
			}
			legacy, ok, err := db.ScheduleGrant(s.ID)
			if err != nil || !ok || legacy.RevokedAt.IsZero() {
				t.Fatalf("legacy revoke diverged: %+v, %v", legacy, err)
			}
		})
	}
}

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

// Denied attempts still observe time. Losing that observation on rollback
// could resurrect an expired grant or move subsequent claims into the past.
func TestReadClockDenialsSurviveRollbackAndRestart(t *testing.T) {
	for _, denial := range []string{"expiry", "budget", "interval"} {
		t.Run(denial, func(t *testing.T) {
			dir := privateDir(t)
			db, err := open(dir, func() time.Time { return t0 })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			g := readGrantDoc(t)
			if denial == "expiry" {
				g.ExpiresAt = t0.Add(time.Hour)
			}
			if err := db.SaveReadGrant(g); err != nil {
				t.Fatal(err)
			}
			if !db.reserveT(t, g.ID, "core.facts", "web", t0, 1, 2*time.Hour) {
				t.Fatal("initial claim denied")
			}
			observed := t0.Add(30 * time.Minute)
			if denial != "budget" {
				observed = t0.Add(90 * time.Minute)
			}
			ok, err := db.ReserveReadRun(g.ID, "core.facts", "web", observed, 1, 2*time.Hour)
			if ok || (denial == "expiry" && !errors.Is(err, permit.ErrReadGrantInactive)) || (denial != "expiry" && err != nil) {
				t.Fatalf("denial: %v, %v", ok, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = open(dir, func() time.Time { return t0 })
			if err != nil {
				t.Fatal(err)
			}
			var high int64
			if err := db.sql.QueryRow(`SELECT high_water FROM read_clock WHERE id = 1`).Scan(&high); err != nil {
				t.Fatal(err)
			}
			if high != observed.Unix() {
				t.Fatalf("denied observation lost: got %d, want %d", high, observed.Unix())
			}
			if denial == "expiry" {
				if ok, err := db.ReserveReadRun(g.ID, "docker.list", "other", t0, 1, 15*time.Minute); ok || !errors.Is(err, permit.ErrReadGrantInactive) {
					t.Fatalf("expired grant resurrected after rollback: %v, %v", ok, err)
				}
			}
		})
	}
}

func TestReadGrantRecoveryStateIsCheckedInsideStorageMutation(t *testing.T) {
	db := openT(t, privateDir(t))
	g := readGrantDoc(t)
	if err := db.SaveReadGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := db.SetRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ReserveReadRun(g.ID, "core.facts", "web", t0, 1, 15*time.Minute); ok || !errors.Is(err, permit.ErrReadGrantInactive) {
		t.Fatalf("recovery claim: %v, %v", ok, err)
	}
	g.ID, g.Digest = "00000000-0000-4000-8000-000000000002", strings.Repeat("b", 64)
	if err := db.SaveReadGrant(g); err == nil {
		t.Fatal("grant created during recovery")
	}
}

func TestReadGrantConcurrentClaimsRespectSharedCeiling(t *testing.T) {
	db := openT(t, privateDir(t))
	for i := 1; i <= 2; i++ {
		g := readGrantDoc(t)
		g.ID, g.Digest = fmt.Sprintf("00000000-0000-4000-8000-%012d", i), strings.Repeat(fmt.Sprint(i), 64)
		if err := db.SaveReadGrant(g); err != nil {
			t.Fatal(err)
		}
	}
	const budget, contenders = 3, 24
	start, result := make(chan struct{}), make(chan bool, contenders)
	errs := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		go func() {
			<-start
			ok, err := db.ReserveReadRun(fmt.Sprintf("00000000-0000-4000-8000-%012d", i%2+1), fmt.Sprintf("action.%d", i), "web", t0, budget, 15*time.Minute)
			result <- ok
			errs <- err
		}()
	}
	close(start)
	accepted := 0
	for i := 0; i < contenders; i++ {
		if <-result {
			accepted++
		}
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if accepted != budget {
		t.Fatalf("accepted %d claims, want %d", accepted, budget)
	}
}

// Interval rows older than the longest approvable interval are pruned, so
// per-guest and per-target interval keys cannot grow without bound.
func TestReserveReadRunPrunesStaleIntervalRows(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	old := t0.Add(-schedgrant.MaxInterval).Unix()
	for _, action := range []string{"pve.snapshots:100", "pve.snapshots:101"} {
		if _, err := db.sql.Exec(`INSERT INTO read_action_last (action_id, host_id, last_run) VALUES (?, ?, ?)`, action, "pve:pve-1", old); err != nil {
			t.Fatal(err)
		}
	}
	recent := t0.Add(-time.Minute).Unix()
	if _, err := db.sql.Exec(`INSERT INTO read_action_last (action_id, host_id, last_run) VALUES (?, ?, ?)`, "pve.snapshots:102", "pve:pve-1", recent); err != nil {
		t.Fatal(err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 24, 15*time.Minute) {
		t.Fatal("run denied")
	}
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM read_action_last`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("read_action_last has %d rows, want 2 (the recent one and the new run)", n)
	}
	// A recent row still enforces its interval.
	if db.reserveT(t, readGrantID, "pve.snapshots:102", "pve:pve-1", t0, 24, 15*time.Minute) {
		t.Fatal("recent interval row was pruned")
	}
}

// An interval longer than the retention would outlive its own row.
func TestReserveReadRunRejectsIntervalAboveRetention(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReserveReadRun(readGrantID, "core.facts", "web", t0, 24, schedgrant.MaxInterval+time.Second); err == nil {
		t.Fatal("interval above retention accepted")
	}
}
