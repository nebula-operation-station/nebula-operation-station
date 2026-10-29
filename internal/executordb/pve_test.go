// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// pinOf derives a well-formed 64-char lowercase hex trust pin from s.
func pinOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestPveMigrationUpOnExistingDatabase applies the PVE registry migration
// on top of a database that an older binary left behind (all migrations
// before the PVE one), and checks the new schema is usable.
func TestPveMigrationUpOnExistingDatabase(t *testing.T) {
	dir := privateDir(t)
	ms := mustMigrations(t)
	if len(ms) < 2 {
		t.Fatal("no migrations shipped")
	}
	newest := ms[len(ms)-1].version

	db := openT(t, dir)
	// Simulate a database from a binary without the PVE registry: drop the
	// PVE objects and unrecord the newest migration.
	for _, stmt := range []string{
		`DROP TABLE pve_remote_changes`,
		`DROP TABLE pve_remote_endpoints`,
		`DROP INDEX pve_remote_trust_pin_idx`,
		`DROP TABLE pve_remotes`,
	} {
		if _, err := db.sql.Exec(stmt); err != nil {
			t.Fatalf("simulate old database: %v", err)
		}
	}
	if _, err := db.sql.Exec(`DELETE FROM schema_migrations WHERE version = ?`, newest); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Reopening must apply the PVE migration on the existing schema.
	db2 := openT(t, dir)
	var n int
	if err := db2.sql.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, newest).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("PVE migration not recorded after reopen")
	}
	for _, table := range []string{"pve_remotes", "pve_remote_endpoints", "pve_remote_changes"} {
		if err := db2.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("table %s missing after migration up", table)
		}
	}
	// The schema is usable end to end.
	if _, err := db2.sql.Exec(`INSERT INTO pve_remotes (remote_id, name, kind, trust_pin_kind, trust_pin, trust_generation, state,
		read_credential_ref, read_credential_version, action_credential_ref, action_credential_version,
		created_at, updated_at, updated_by)
		VALUES ('migr', '', 'cluster', 'ca', ?, 1, 'active', '', 0, '', 0, 0, 0, 'admin')`, pinOf("migr")); err != nil {
		t.Fatalf("insert into pve_remotes: %v", err)
	}
	if _, err := db2.sql.Exec(`INSERT INTO pve_remote_endpoints (remote_id, seq, host, port) VALUES ('migr', 1, 'pve1', 8006)`); err != nil {
		t.Fatalf("insert into pve_remote_endpoints: %v", err)
	}
	if _, err := db2.sql.Exec(`INSERT INTO pve_remote_changes (remote_id, change_type, detail, actor, at) VALUES ('migr', 'created', '', 'admin', 0)`); err != nil {
		t.Fatalf("insert into pve_remote_changes: %v", err)
	}
}

// TestPveMigrationUniquePinIndex checks the database-level guard against
// registering the same trust identity for a second remote, bypassing any
// Go-level check.
func TestPveMigrationUniquePinIndex(t *testing.T) {
	db := openT(t, privateDir(t))
	insert := func(id, pin string) error {
		_, err := db.sql.Exec(`INSERT INTO pve_remotes (remote_id, name, kind, trust_pin_kind, trust_pin, trust_generation, state,
			read_credential_ref, read_credential_version, action_credential_ref, action_credential_version,
			created_at, updated_at, updated_by)
			VALUES (?, '', 'cluster', 'ca', ?, 1, 'active', '', 0, '', 0, 0, 0, 'admin')`, id, pin)
		return err
	}
	if err := insert("a", pinOf("a")); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := insert("b", pinOf("a")); err == nil {
		t.Fatal("second remote with the same trust pin accepted at the database level")
	}
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM pve_remotes`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("duplicate pin left a row behind")
	}
}
