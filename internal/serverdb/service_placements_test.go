// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"path/filepath"
	"testing"
	"time"
)

func TestServicePlacementMigrationFromPreviousSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db := rawOpen(t, path)
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC) }
	var previous []migration
	for _, m := range migrations {
		if m.version < 25 {
			previous = append(previous, m)
		}
	}
	if err := migrateWith(db, previous, now); err != nil {
		t.Fatal(err)
	}
	if tableExists(t, db, "pve_service_placements") {
		t.Fatal("test must start before placement schema")
	}
	if _, err := db.Exec(`INSERT INTO hosts(name,created_at,updated_at) VALUES ('preserved','2026-10-30T00:00:00Z','2026-10-30T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !tableExists(t, db, "pve_service_placements") {
		t.Fatal("migration missing")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE name='preserved'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("existing data lost: %d %v", n, err)
	}
}

func TestServicePlacementSchemaEnforcesOneActivePlacementAndCheckShape(t *testing.T) {
	db := openTemp(t)
	insert := `INSERT INTO pve_service_placements(service_name,kind,host_id,check_protocol,check_destination,check_port,check_internal,source,recorded_by,recorded_at) VALUES (?,?,?,?,?,?,?,'manual','alice','2026-10-30T00:00:00Z')`
	if _, err := db.Exec(insert, "api", "host", "web1", "http", "127.0.0.1", 80, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insert, "api", "host", "web2", "", "", 0, 0); err == nil {
		t.Fatal("duplicate active placement accepted")
	}
	if _, err := db.Exec(`UPDATE pve_service_placements SET removed_at='2026-10-30T01:00:00Z' WHERE service_name='api'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insert, "api", "host", "web2", "", "", 0, 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, protocol, destination string
		port, internal              int
	}{
		{"partial", "http", "", 0, 0}, {"port", "tcp", "web1", 65536, 0}, {"approval", "", "", 0, 1}, {"boolean", "http", "web1", 80, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(insert, tc.name, "host", "web1", tc.protocol, tc.destination, tc.port, tc.internal); err == nil {
				t.Fatal("invalid check accepted")
			}
		})
	}
}

func TestHostDeletionTombstonesPlacementsAfterSchemaUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	db := rawOpen(t, path)
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var previous []migration
	for _, m := range migrations {
		if m.version <= 25 {
			previous = append(previous, m)
		}
	}
	if err := migrateWith(db, previous, time.Now); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`INSERT INTO hosts(name,created_at,updated_at) VALUES ('web1','2026-10-30T00:00:00Z','2026-10-30T00:00:00Z')`,
		`INSERT INTO pve_service_placements(service_name,kind,host_id,source,recorded_by,recorded_at)
		 VALUES ('api','host','web1','manual','alice','2026-10-30T00:00:00Z')`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The tombstone and host deletion must share a transaction.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM hosts WHERE name='web1'`); err != nil {
		t.Fatal(err)
	}
	var removedAt string
	if err := tx.QueryRow(`SELECT removed_at FROM pve_service_placements WHERE service_name='api'`).Scan(&removedAt); err != nil || removedAt == "" {
		t.Fatalf("placement not tombstoned during deletion: %q %v", removedAt, err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT removed_at FROM pve_service_placements WHERE service_name='api'`).Scan(&removedAt); err != nil || removedAt != "" {
		t.Fatalf("rollback failed to restore placement: %q %v", removedAt, err)
	}
	if _, err := db.Exec(`DELETE FROM hosts WHERE name='web1'`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT removed_at FROM pve_service_placements WHERE service_name='api'`).Scan(&removedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, removedAt); err != nil {
		t.Fatalf("invalid tombstone time %q: %v", removedAt, err)
	}
}
