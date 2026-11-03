// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for OpenAt: a test-only helper that leaves a database at a
// historical schema version so tests can exercise the migrations from that
// point on without hand-rolled schema rollbacks.

package serverdb

import (
	"path/filepath"
	"testing"
)

// TestOpenAtStopsAtRequestedVersion opens at version 1, checks that only
// migration 1 was applied, then checks that a normal Open completes to head.
func TestOpenAtStopsAtRequestedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := OpenAt(path, 1)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path)
	if err != nil {
		t.Fatalf("Open after OpenAt: %v", err)
	}
	defer migrated.Close()
	latest, err := LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err := migrated.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != latest {
		t.Errorf("schema version = %d, want %d", version, latest)
	}

	// Reopening a database that is already at a newer version must be
	// refused, not silently left behind.
	if _, err := OpenAt(path, 1); err == nil {
		t.Error("OpenAt accepted a database newer than the requested version")
	}
}
