// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"strings"
	"testing"
	"time"
)

const netdevMigration = "0024_netdev_devices.sql"

var ndT0 = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

func ndDB(t *testing.T) *DB {
	t.Helper()
	return openAtT(t, privateDir(t), ndT0)
}

// rawInsertNetDevice writes a device row directly, bypassing the Go-level
// checks, to exercise the database-level guards.
func rawInsertNetDevice(db *DB, id, family, pinKind, pin string) error {
	_, err := db.sql.Exec(`INSERT INTO netdev_devices (id, family, endpoint_ip, port, pin_kind, pin_value,
		digest_key_ref, fingerprint_key_ref, created_at, updated_at)
		VALUES (?, ?, '10.0.0.1', 22, ?, ?, ?, ?, 0, 0)`,
		id, family, pinKind, pin, "nd-"+id+"-digest", "nd-"+id+"-fp")
	return err
}

func TestNetdevMigrationIsNewest(t *testing.T) {
	ms := mustMigrations(t)
	last := ms[len(ms)-1]
	if last.name != netdevMigration {
		t.Fatalf("newest migration is %s, want %s", last.name, netdevMigration)
	}
	if prev := ms[len(ms)-2]; prev.version != last.version-1 {
		t.Fatalf("netdev migration %d does not directly follow %d", last.version, prev.version)
	}
}

func TestNetdevMigrationAppliesOnEmptyDatabase(t *testing.T) {
	db := ndDB(t)
	assertNetdevSchema(t, db)
}

// TestNetdevMigrationUpFromPreviousVersion opens a database that a binary
// without the netdev registry left behind and checks the migration applies
// on top of it without touching existing data.
func TestNetdevMigrationUpFromPreviousVersion(t *testing.T) {
	dir := privateDir(t)
	ms := mustMigrations(t)
	idx := -1
	for i, m := range ms {
		if m.name == netdevMigration {
			idx = i
		}
	}
	if idx < 1 {
		t.Fatal("netdev migration not shipped")
	}
	if err := seedPrePveDatabase(t, dir, ms[:idx]); err != nil {
		t.Fatal(err)
	}
	db := openAtT(t, dir, ndT0)
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, ms[idx].version).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("netdev migration not recorded after reopen")
	}
	assertNetdevSchema(t, db)
}

func assertNetdevSchema(t *testing.T, db *DB) {
	t.Helper()
	for _, obj := range []string{
		"netdev_devices", "netdev_tombstones", "netdev_devices_trust_identity_idx",
		"netdev_devices_no_tombstoned_id", "netdev_devices_tombstone_frozen", "netdev_devices_no_delete",
		"netdev_tombstones_no_update", "netdev_tombstones_no_delete",
	} {
		var n int
		if err := db.sql.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, obj).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("schema object %s missing", obj)
		}
	}
	if err := rawInsertNetDevice(db, "sw-schema", "cbs", "ssh-host-key", pinOf("schema")); err != nil {
		t.Fatalf("schema not usable: %v", err)
	}
}

// TestNetdevSchemaGuards checks the database-level constraints directly,
// independent of the Go store.
func TestNetdevSchemaGuards(t *testing.T) {
	db := ndDB(t)
	if err := rawInsertNetDevice(db, "sw-a", "cbs", "ssh-host-key", pinOf("a")); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	refused := []struct {
		name string
		do   func() error
	}{
		{"duplicate live trust identity", func() error { return rawInsertNetDevice(db, "sw-b", "cbs", "ssh-host-key", pinOf("a")) }},
		{"bad id", func() error { return rawInsertNetDevice(db, "SW_A", "cbs", "ssh-host-key", pinOf("c")) }},
		{"leading hyphen", func() error { return rawInsertNetDevice(db, "-a", "cbs", "ssh-host-key", pinOf("c")) }},
		{"unknown family", func() error { return rawInsertNetDevice(db, "x", "pfsense", "tls-leaf", pinOf("c")) }},
		{"family/pin mismatch", func() error { return rawInsertNetDevice(db, "x", "cbs", "tls-leaf", pinOf("c")) }},
		{"short pin", func() error { return rawInsertNetDevice(db, "x", "cbs", "ssh-host-key", "abc") }},
		{"uppercase pin", func() error {
			return rawInsertNetDevice(db, "x", "cbs", "ssh-host-key", strings.ToUpper(pinOf("c")))
		}},
		{"zone in endpoint", func() error {
			_, err := db.sql.Exec(`INSERT INTO netdev_devices (id, family, endpoint_ip, port, pin_kind, pin_value,
				digest_key_ref, fingerprint_key_ref, created_at, updated_at)
				VALUES ('x', 'cbs', 'fd00::1%eth0', 22, 'ssh-host-key', ?, 'd', 'f', 0, 0)`, pinOf("c"))
			return err
		}},
		{"same key ref twice", func() error {
			_, err := db.sql.Exec(`INSERT INTO netdev_devices (id, family, endpoint_ip, port, pin_kind, pin_value,
				digest_key_ref, fingerprint_key_ref, created_at, updated_at)
				VALUES ('x', 'cbs', '10.0.0.2', 22, 'ssh-host-key', ?, 'k', 'k', 0, 0)`, pinOf("c"))
			return err
		}},
		{"blocked without reason", func() error {
			_, err := db.sql.Exec(`UPDATE netdev_devices SET blocked = 1 WHERE id = 'sw-a'`)
			return err
		}},
		{"delete device row", func() error {
			_, err := db.sql.Exec(`DELETE FROM netdev_devices WHERE id = 'sw-a'`)
			return err
		}},
	}
	for _, r := range refused {
		if err := r.do(); err == nil {
			t.Errorf("%s: accepted at the database level", r.name)
		}
	}

	// Tombstone sw-a at the database level.
	if _, err := db.sql.Exec(`UPDATE netdev_devices SET tombstoned_at = 1 WHERE id = 'sw-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`INSERT INTO netdev_tombstones (id, tombstoned_at) VALUES ('sw-a', 1)`); err != nil {
		t.Fatal(err)
	}
	afterTombstone := []struct {
		name string
		do   func() error
	}{
		{"revive tombstoned row", func() error {
			_, err := db.sql.Exec(`UPDATE netdev_devices SET tombstoned_at = NULL WHERE id = 'sw-a'`)
			return err
		}},
		{"delete tombstone", func() error {
			_, err := db.sql.Exec(`DELETE FROM netdev_tombstones WHERE id = 'sw-a'`)
			return err
		}},
		{"rename tombstone", func() error {
			_, err := db.sql.Exec(`UPDATE netdev_tombstones SET id = 'sw-z' WHERE id = 'sw-a'`)
			return err
		}},
	}
	for _, r := range afterTombstone {
		if err := r.do(); err == nil {
			t.Errorf("%s: accepted at the database level", r.name)
		}
	}
	// The trust identity of a tombstoned device is free for a new id.
	if err := rawInsertNetDevice(db, "sw-b", "cbs", "ssh-host-key", pinOf("a")); err != nil {
		t.Fatalf("trust identity of a tombstoned device not released: %v", err)
	}
	// A tombstoned id is refused even if its device row were gone.
	if _, err := db.sql.Exec(`INSERT INTO netdev_tombstones (id, tombstoned_at) VALUES ('sw-gone', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := rawInsertNetDevice(db, "sw-gone", "cbs", "ssh-host-key", pinOf("gone")); err == nil {
		t.Fatal("tombstoned id re-inserted at the database level")
	}
}
