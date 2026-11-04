// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMigration0033DropsOrphanOverridesAndCascades seeds asset icon
// overrides on the 0032 schema (one for an existing asset, one for an
// asset that was already deleted), applies 0033 and checks that the
// orphan is gone but recorded, the valid override stays, and deleting
// the asset now removes its override and records that.
func TestMigration0033DropsOrphanOverridesAndCascades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	if err := migrateUpTo(db, now, 32); err != nil {
		t.Fatalf("migrate to 0032: %v", err)
	}
	sha := strings.Repeat("a", 64)
	for _, q := range []string{
		`INSERT INTO assets (id, name, kind, updated_at) VALUES ('nas-1', 'NAS', 'nas', 1)`,
		`INSERT INTO software_icons (sha, source_kind, added_by, added_at) VALUES ('` + sha + `', 'upload', 'alice', 1)`,
		`INSERT INTO asset_icon_overrides (asset_id, icon_sha, updated_by, updated_at) VALUES ('nas-1', '` + sha + `', 'alice', 1)`,
		`INSERT INTO asset_icon_overrides (asset_id, icon_sha, updated_by, updated_at) VALUES ('gone-1', '` + sha + `', 'alice', 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if err := migrateUpTo(db, now, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ids := func() string {
		t.Helper()
		rows, err := db.Query(`SELECT asset_id FROM asset_icon_overrides ORDER BY asset_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return strings.Join(out, ",")
	}
	if got := ids(); got != "nas-1" {
		t.Fatalf("overrides after 0033 = %q, want nas-1", got)
	}
	// The dropped orphan is recorded like an asset delete.
	recorded := func(id string) string {
		t.Helper()
		var hist, audit string
		if err := db.QueryRow(`SELECT COALESCE(icon_sha, 'none') || ' ' || prev_sha || ' ' || rollback_of || ' ' || changed_by
			FROM software_icon_history WHERE subject_kind = 'asset' AND subject_id = ?`, id).Scan(&hist); err != nil {
			t.Fatalf("history of %s: %v", id, err)
		}
		if err := db.QueryRow(`SELECT action || ' ' || actor || ' ' || detail
			FROM software_catalog_audit WHERE subject = ?`, id).Scan(&audit); err != nil {
			t.Fatalf("audit of %s: %v", id, err)
		}
		return hist + " | " + audit
	}
	want := "none " + sha + " -1 system | asset_icon_clear system " + sha + " -> none (asset deleted)"
	if got := recorded("gone-1"); got != want {
		t.Fatalf("orphan record %q", got)
	}
	var n int
	if err := db.QueryRow(`SELECT (SELECT COUNT(*) FROM software_icon_history) + (SELECT COUNT(*) FROM software_catalog_audit)`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("records after 0033: %d %v", n, err)
	}
	if _, err := db.Exec(`INSERT INTO asset_icon_overrides (asset_id, icon_sha, updated_by, updated_at) VALUES ('nope', ?, 'alice', 1)`, sha); err == nil {
		t.Fatal("override for a missing asset was accepted")
	}
	if _, err := db.Exec(`DELETE FROM assets WHERE id = 'nas-1'`); err != nil {
		t.Fatal(err)
	}
	if got := ids(); got != "" {
		t.Fatalf("overrides after asset delete = %q, want none", got)
	}
	if got := recorded("nas-1"); got != want {
		t.Fatalf("delete record %q", got)
	}
}
