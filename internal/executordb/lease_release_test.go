// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"testing"
	"time"
)

// TestReadActionLastRunSurvivesRestart: the interval counter is read from
// the store, before and after a reopen, and reading never reserves.
func TestReadActionLastRunSurvivesRestart(t *testing.T) {
	dir := privateDir(t)
	db, err := open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.ReadActionLastRun("core.facts", "web"); err != nil || ok {
		t.Fatalf("before any run: %v %v", ok, err)
	}
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 2, 15*time.Minute) {
		t.Fatal("run denied")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	last, ok, err := db.ReadActionLastRun("core.facts", "web")
	if err != nil || !ok || !last.Equal(t0) {
		t.Fatalf("after reopen: %v %v %v", last, ok, err)
	}
	if !db.reserveT(t, readGrantID, "docker.list", "web", t0, 2, 15*time.Minute) {
		t.Fatal("reading the counter spent budget")
	}
}

// TestReleaseReadRunRestoresBudgetAndInterval: a released reservation
// gives back its budget unit and restores the previous interval row; a
// second release, or one whose reservation was superseded, does nothing.
func TestReleaseReadRunRestoresBudgetAndInterval(t *testing.T) {
	db := openT(t, privateDir(t))
	if err := db.SaveReadGrant(readGrantDoc(t)); err != nil {
		t.Fatal(err)
	}
	// No earlier run: the interval row goes away.
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 2, 15*time.Minute) {
		t.Fatal("first run denied")
	}
	if ok, err := db.ReleaseReadRun(readGrantID, "core.facts", "web", time.Time{}, false); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	if _, ok, err := db.ReadActionLastRun("core.facts", "web"); err != nil || ok {
		t.Fatalf("interval row kept: %v %v", ok, err)
	}
	if ok, err := db.ReleaseReadRun(readGrantID, "core.facts", "web", time.Time{}, false); err != nil || ok {
		t.Fatalf("second release: %v %v", ok, err)
	}
	// An earlier run stays: the interval row goes back to it.
	if !db.reserveT(t, readGrantID, "core.facts", "web", t0, 2, 15*time.Minute) {
		t.Fatal("run after release denied")
	}
	at := t0.Add(20 * time.Minute)
	if !db.reserveT(t, readGrantID, "core.facts", "web", at, 2, 15*time.Minute) {
		t.Fatal("second run denied")
	}
	if ok, err := db.ReleaseReadRun(readGrantID, "core.facts", "web", t0, true); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	if last, ok, err := db.ReadActionLastRun("core.facts", "web"); err != nil || !ok || !last.Equal(t0) {
		t.Fatalf("interval row %v %v %v, want %v", last, ok, err, t0)
	}
	// Budget 2: one unit is spent (t0), the released one is free again.
	if !db.reserveT(t, readGrantID, "docker.list", "web", at, 2, 15*time.Minute) {
		t.Fatal("released budget unit not returned")
	}
	if db.reserveT(t, readGrantID, "core.version", "web", at, 2, 15*time.Minute) {
		t.Fatal("budget over-returned")
	}
	// The interval row still holds the earlier run: nothing to release.
	if ok, err := db.ReleaseReadRun(readGrantID, "core.facts", "web", t0, true); err != nil || ok {
		t.Fatalf("release of a superseded reservation: %v %v", ok, err)
	}
}
