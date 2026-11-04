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

// TestMigration0033MarksDeletedAssetHistory seeds icon history on the
// 0032 schema and checks that 0033 ends the history of every asset that
// no longer exists, also when its override was cleared before the
// delete, and leaves existing assets, already ended histories and
// catalog keys alone.
func TestMigration0033MarksDeletedAssetHistory(t *testing.T) {
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
	hist := `INSERT INTO software_icon_history (subject_kind, subject_id, icon_sha, prev_sha, rollback_of, changed_by, changed_at) VALUES `
	for _, q := range []string{
		`INSERT INTO assets (id, name, kind, updated_at) VALUES ('live-1', 'Live', 'nas', 1)`,
		`INSERT INTO software_icons (sha, source_kind, added_by, added_at) VALUES ('` + sha + `', 'upload', 'alice', 1)`,
		// live-1 exists: set, then cleared.
		hist + `('asset', 'live-1', '` + sha + `', NULL, 0, 'alice', 1)`,
		hist + `('asset', 'live-1', NULL, '` + sha + `', 0, 'alice', 2)`,
		// gone-2 was deleted after its override was cleared.
		hist + `('asset', 'gone-2', '` + sha + `', NULL, 0, 'alice', 3)`,
		hist + `('asset', 'gone-2', NULL, '` + sha + `', 0, 'alice', 4)`,
		// gone-3's history already ends with the marker.
		hist + `('asset', 'gone-3', '` + sha + `', NULL, 0, 'alice', 5)`,
		hist + `('asset', 'gone-3', NULL, '` + sha + `', -1, 'system', 6)`,
		// A catalog key is no asset.
		hist + `('catalog', 'widgetd', '` + sha + `', NULL, 0, 'alice', 7)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if err := migrateUpTo(db, now, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	history := func(kind, id string) string {
		t.Helper()
		rows, err := db.Query(`SELECT COALESCE(icon_sha, 'none') || ' ' || COALESCE(prev_sha, 'none') || ' ' || rollback_of || ' ' || changed_by
			FROM software_icon_history WHERE subject_kind = ? AND subject_id = ? ORDER BY id`, kind, id)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return strings.Join(out, "; ")
	}
	set, clr := sha+" none 0 alice", "none "+sha+" 0 alice"
	for _, c := range []struct{ kind, id, want string }{
		{"asset", "live-1", set + "; " + clr},
		{"asset", "gone-2", set + "; " + clr + "; none none -1 system"},
		{"asset", "gone-3", set + "; none " + sha + " -1 system"},
		{"catalog", "widgetd", set},
	} {
		if got := history(c.kind, c.id); got != c.want {
			t.Fatalf("history of %s %s = %q, want %q", c.kind, c.id, got, c.want)
		}
	}
	// Nothing was removed, so nothing is audited.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM software_catalog_audit`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit rows after 0033: %d %v", n, err)
	}
	// Deleting live-1 ends its history without an audit row (it has no
	// override); deleting it again after recreating it adds nothing.
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`DELETE FROM assets WHERE id = 'live-1'`); err != nil {
			t.Fatal(err)
		}
		if got, want := history("asset", "live-1"), set+"; "+clr+"; none none -1 system"; got != want {
			t.Fatalf("history of live-1 after delete %d = %q, want %q", i+1, got, want)
		}
		if _, err := db.Exec(`INSERT INTO assets (id, name, kind, updated_at) VALUES ('live-1', 'Live', 'nas', 1)`); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM software_catalog_audit`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit rows after deletes: %d %v", n, err)
	}
}
