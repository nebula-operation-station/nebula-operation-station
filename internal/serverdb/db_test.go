// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the server database: Open pragmas (acceptance criterion 1),
// embedded migrations applied in order and recorded in schema_migrations
// (criterion 2), a failing migration rolling back completely (criterion 3),
// a newer database version being refused (criterion 4), and the first
// migration's schema (criterion 5). All tests use t.TempDir().

package serverdb

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// openTemp opens a fresh database in a temp dir and closes it on cleanup.
func openTemp(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func openTempWithOptions(t *testing.T, opts Options) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := OpenWithOptions(path, opts)
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// rawOpen opens the SQLite file directly, bypassing the migration engine.
func rawOpen(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	return n > 0
}

// --- Acceptance criterion 1: Open sets WAL, foreign keys, busy timeout. ---

func TestOpenPragmas(t *testing.T) {
	db := openTemp(t)

	var jm string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil {
		t.Fatal(err)
	}
	if jm != "wal" {
		t.Errorf("journal_mode = %q, want wal", jm)
	}

	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}

	var bt int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&bt); err != nil {
		t.Fatal(err)
	}
	if bt != int(DefaultBusyTimeout.Milliseconds()) {
		t.Errorf("busy_timeout = %d, want %d", bt, int(DefaultBusyTimeout.Milliseconds()))
	}
}

func TestOpenBusyTimeoutConfigurable(t *testing.T) {
	db := openTempWithOptions(t, Options{BusyTimeout: time.Second})
	var bt int
	if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&bt); err != nil {
		t.Fatal(err)
	}
	if bt != 1000 {
		t.Errorf("busy_timeout = %d, want 1000", bt)
	}
}

// A path containing '?' or '#' would be mis-parsed as DSN query/fragment
// once the pragmas are appended, so Open must reject it up front.
func TestOpenRejectsPathWithQueryOrFragment(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"nebula?x.db", "nebula#x.db", "nebula?#x.db"} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(filepath.Join(dir, name)); err == nil {
				t.Fatal("Open accepted a path containing '?' or '#'")
			}
		})
	}
}

// TestForeignKeysEnforced proves foreign_keys holds on the connections the
// pool actually uses, by violating a constraint.
func TestForeignKeysEnforced(t *testing.T) {
	db := openTemp(t)
	if _, err := db.Exec(`INSERT INTO host_endpoints (host_id, address, created_at) VALUES (999, '10.0.0.1', '2026-01-01T00:00:00Z')`); err == nil {
		t.Error("inserting an endpoint for a missing host succeeded; foreign keys are not enforced")
	}
}

// --- Acceptance criterion 2: migrations recorded, in order, idempotent. ---

func TestMigrationsRecorded(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	db := openTempWithOptions(t, Options{Now: func() time.Time { return fixed }})

	var version int
	var appliedAt string
	if err := db.QueryRow(`SELECT version, applied_at FROM schema_migrations`).Scan(&version, &appliedAt); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
	if want := fixed.Format(time.RFC3339); appliedAt != want {
		t.Errorf("applied_at = %q, want %q", appliedAt, want)
	}
}

func TestReopenIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Opening again must apply nothing and not error.
	db, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	// One row per shipped migration, none applied twice.
	shipped, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if n != len(shipped) {
		t.Errorf("schema_migrations rows = %d, want %d", n, len(shipped))
	}
}

// TestMigrationsAppliedInOrder applies two migrations where the second
// depends on the first; out-of-order application would fail.
func TestMigrationsAppliedInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "order.db")
	db := rawOpen(t, path)
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	migs := []migration{
		{version: 1, name: "0001_a.sql", sql: `CREATE TABLE a (x INTEGER PRIMARY KEY);`},
		{version: 2, name: "0002_b.sql", sql: `CREATE TABLE b (a_id INTEGER NOT NULL REFERENCES a(x));`},
	}
	if err := migrateWith(db, migs, now); err != nil {
		t.Fatalf("migrateWith: %v", err)
	}
	if !tableExists(t, db, "a") || !tableExists(t, db, "b") {
		t.Fatal("expected tables a and b")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("schema_migrations rows = %d, want 2", n)
	}
}

// --- Acceptance criterion 3: a failing migration rolls back completely. ---

func TestFailingMigrationRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fail.db")
	db := rawOpen(t, path)
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	migs := []migration{
		// Version 1 succeeds and commits.
		{version: 1, name: "0001_ok.sql", sql: `CREATE TABLE ok (x INTEGER);`},
		// Version 2 creates a table then fails; the table must not survive.
		{version: 2, name: "0002_bad.sql", sql: `CREATE TABLE bad (x INTEGER); INSERT INTO no_such_table VALUES (1);`},
	}
	err := migrateWith(db, migs, now)
	if err == nil {
		t.Fatal("migrateWith succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "0002") {
		t.Errorf("error %q does not name the failing version 0002", err)
	}
	// The failed migration's own DDL must be rolled back.
	if tableExists(t, db, "bad") {
		t.Error("table from the failed migration survived the rollback")
	}
	// The earlier successful migration must persist.
	if !tableExists(t, db, "ok") {
		t.Error("table from the earlier migration was lost")
	}
	// The failed migration must not be recorded.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 2`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("failed migration was recorded in schema_migrations")
	}
}

// --- Acceptance criterion 4: a newer database version is refused. ---

func TestNewerVersionRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Simulate a newer binary having applied version 99.
	db = rawOpen(t, path)
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (99, '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = Open(path)
	if err == nil {
		t.Fatal("Open succeeded on a database newer than the binary")
	}
	if !strings.Contains(err.Error(), "newer") {
		t.Errorf("error %q does not explain the version mismatch", err)
	}
}

// --- Acceptance criterion 5: the first migration's schema. ---

var initTables = []string{
	"users", "hosts", "host_endpoints", "groups", "host_groups", "tags", "host_tags", "audit_events",
}

// secretish are column-name fragments that must never appear: the server
// database holds credential references, never credential material.
var secretish = []string{
	"password", "passphrase", "secret", "token", "private_key", "plaintext",
}

func TestInitSchemaTables(t *testing.T) {
	db := openTemp(t)
	for _, name := range initTables {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
}

func TestInitSchemaNoCredentialMaterial(t *testing.T) {
	db := openTemp(t)
	for _, table := range initTables {
		rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			t.Fatalf("table_info %s: %v", table, err)
		}
		for rows.Next() {
			var (
				cid, notnull, pk int
				name             string
				colType          string
				dflt             sql.NullString
			)
			if err := rows.Scan(&cid, &name, &colType, &notnull, &dflt, &pk); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			lower := strings.ToLower(name)
			for _, s := range secretish {
				if strings.Contains(lower, s) {
					t.Errorf("table %s has column %q holding credential material", table, name)
				}
			}
		}
		rows.Close()
	}
}

func TestHostsHaveCredentialRef(t *testing.T) {
	db := openTemp(t)
	var colType string
	err := db.QueryRow(`SELECT type FROM pragma_table_info('hosts') WHERE name = 'credential_ref'`).Scan(&colType)
	if err != nil {
		t.Fatalf("hosts.credential_ref missing: %v", err)
	}
	if !strings.EqualFold(colType, "TEXT") {
		t.Errorf("hosts.credential_ref type = %q, want TEXT", colType)
	}
}

// --- more tests below ---

// A .sql file in migrations/ that does not match NNNN_name.sql must be an
// error, not silently ignored: an ignored file would be applied by no
// binary while still sitting in the release tree.
func TestLoadMigrationsRejectsNonConformingName(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/0001_ok.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE a (x INTEGER);`)},
		"migrations/notes.sql":   &fstest.MapFile{Data: []byte("-- notes")},
	}
	if _, err := loadMigrationsFrom(fsys, "migrations"); err == nil {
		t.Fatal("loadMigrations accepted a non-conforming .sql file")
	}
}

func TestLoadMigrationsRejectsDuplicateVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/0001_a.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE a (x INTEGER);`)},
		"migrations/0001_b.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE b (x INTEGER);`)},
	}
	if _, err := loadMigrationsFrom(fsys, "migrations"); err == nil {
		t.Fatal("loadMigrations accepted duplicate migration versions")
	}
}

// host_tags links hosts to tags with ON DELETE CASCADE on both sides and a
// composite primary key.
func TestHostTagsSchema(t *testing.T) {
	db := openTemp(t)
	const ts = "2026-01-01T00:00:00Z"
	mustExec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	mustExec(`INSERT INTO hosts (name, created_at, updated_at) VALUES ('h1', ?, ?)`, ts, ts)
	mustExec(`INSERT INTO tags (name, created_at) VALUES ('t1', ?)`, ts)
	var hostID, tagID int
	if err := db.QueryRow(`SELECT id FROM hosts WHERE name = 'h1'`).Scan(&hostID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT id FROM tags WHERE name = 't1'`).Scan(&tagID); err != nil {
		t.Fatal(err)
	}

	mustExec(`INSERT INTO host_tags (host_id, tag_id) VALUES (?, ?)`, hostID, tagID)
	if _, err := db.Exec(`INSERT INTO host_tags (host_id, tag_id) VALUES (?, ?)`, hostID, tagID); err == nil {
		t.Error("duplicate host_tags row was accepted; composite primary key is missing")
	}
	if _, err := db.Exec(`INSERT INTO host_tags (host_id, tag_id) VALUES (9999, ?)`, tagID); err == nil {
		t.Error("host_tags row for a missing host was accepted; foreign keys are not enforced")
	}
	if _, err := db.Exec(`INSERT INTO host_tags (host_id, tag_id) VALUES (?, 9999)`, hostID); err == nil {
		t.Error("host_tags row for a missing tag was accepted; foreign keys are not enforced")
	}

	// ON DELETE CASCADE: deleting the host removes the tag link.
	mustExec(`DELETE FROM hosts WHERE id = ?`, hostID)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_tags WHERE tag_id = ?`, tagID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("host_tags row survived host deletion; ON DELETE CASCADE is missing")
	}

	// ON DELETE CASCADE: deleting the tag removes the tag link.
	mustExec(`INSERT INTO hosts (name, created_at, updated_at) VALUES ('h2', ?, ?)`, ts, ts)
	if err := db.QueryRow(`SELECT id FROM hosts WHERE name = 'h2'`).Scan(&hostID); err != nil {
		t.Fatal(err)
	}
	mustExec(`INSERT INTO host_tags (host_id, tag_id) VALUES (?, ?)`, hostID, tagID)
	mustExec(`DELETE FROM tags WHERE id = ?`, tagID)
	if err := db.QueryRow(`SELECT COUNT(*) FROM host_tags WHERE host_id = ?`, hostID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("host_tags row survived tag deletion; ON DELETE CASCADE is missing")
	}
}
