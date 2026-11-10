// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
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

// TestNetdevMigrationShippedInOrder checks that 0024 is shipped exactly
// once, at version 24, directly after 0023; it keeps passing when later
// migrations are added.
func TestNetdevMigrationShippedInOrder(t *testing.T) {
	ms := mustMigrations(t)
	idx := -1
	for i, m := range ms {
		if m.name == netdevMigration {
			if idx != -1 {
				t.Fatal("netdev migration shipped twice")
			}
			idx = i
		}
	}
	if idx < 1 {
		t.Fatal("netdev migration not shipped")
	}
	if ms[idx].version != 24 {
		t.Fatalf("netdev migration has version %d, want 24", ms[idx].version)
	}
	if prev := ms[idx-1]; prev.version != 23 {
		t.Fatalf("netdev migration follows version %d, want 23", prev.version)
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].version != ms[i-1].version+1 {
			t.Fatalf("migration %s does not directly follow %s", ms[i].name, ms[i-1].name)
		}
	}
	db := ndDB(t)
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 24`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("netdev migration not applied")
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
		"netdev_devices_credential_ref_idx", "netdev_devices_digest_key_ref_idx", "netdev_devices_fingerprint_key_ref_idx",
		"netdev_devices_vault_ref_insert", "netdev_devices_vault_ref_update",
		"netdev_devices_id_immutable", "netdev_tombstones_id_immutable",
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

// --- store ------------------------------------------------------------------

func cbsDevice(id, pin string) NetDevice {
	return NetDevice{
		ID: id, Family: netdevcontract.FamilyCBS, Label: "Switch " + id,
		EndpointIP: "10.0.0.2", Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, PinValue: pin,
		CredentialRef:     "nd-" + id + "-read",
		DigestKeyRef:      "nd-" + id + "-digest",
		FingerprintKeyRef: "nd-" + id + "-fp",
	}
}

func panosDevice(id, pin string) NetDevice {
	return NetDevice{
		ID: id, Family: netdevcontract.FamilyPANOS, Label: "fw " + id,
		EndpointIP: "fd00:10::1", Port: 443,
		PinKind: netdevcontract.PinTLSLeaf, PinValue: pin,
		DigestKeyRef:      "nd-" + id + "-digest",
		FingerprintKeyRef: "nd-" + id + "-fp",
	}
}

func insertND(t *testing.T, db *DB, d NetDevice) NetDevice {
	t.Helper()
	got, err := db.InsertNetDevice(d)
	if err != nil {
		t.Fatalf("insert %s: %v", d.ID, err)
	}
	return got
}

func ndCanon(d NetDevice) NetDevice {
	d.CreatedAt = d.CreatedAt.UTC()
	d.UpdatedAt = d.UpdatedAt.UTC()
	if d.TombstonedAt != nil {
		at := d.TombstonedAt.UTC()
		d.TombstonedAt = &at
	}
	return d
}

func TestNetDeviceInsertGetList(t *testing.T) {
	db := ndDB(t)
	b := insertND(t, db, panosDevice("fw-b", pinOf("b")))
	a := insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	if a.TrustGeneration != 1 || a.Blocked || a.TombstonedAt != nil {
		t.Fatalf("new device state: %+v", a)
	}
	if !a.CreatedAt.Equal(ndT0) || !a.UpdatedAt.Equal(ndT0) {
		t.Fatalf("timestamps not from the injected clock: %+v", a)
	}
	got, ok, err := db.GetNetDevice("sw-a")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(ndCanon(got), ndCanon(a)) {
		t.Fatalf("stored record differs:\nreturned %+v\nstored   %+v", a, got)
	}
	if _, ok, err := db.GetNetDevice("nope"); ok || err != nil {
		t.Fatalf("missing device: ok=%v err=%v", ok, err)
	}
	list, err := db.ListNetDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != b.ID || list[1].ID != a.ID {
		t.Fatalf("list not in stable id order: %+v", list)
	}
}

func TestNetDeviceInsertRejectsInvalid(t *testing.T) {
	db := ndDB(t)
	cases := map[string]func(d *NetDevice){
		"bad id":               func(d *NetDevice) { d.ID = "Sw_A" },
		"empty id":             func(d *NetDevice) { d.ID = "" },
		"long id":              func(d *NetDevice) { d.ID = strings.Repeat("a", 65) },
		"unknown family":       func(d *NetDevice) { d.Family = "pfsense" },
		"cbs with tls pin":     func(d *NetDevice) { d.PinKind = netdevcontract.PinTLSLeaf },
		"bad pin":              func(d *NetDevice) { d.PinValue = "zz" },
		"uppercase pin":        func(d *NetDevice) { d.PinValue = strings.ToUpper(pinOf("x")) },
		"host name endpoint":   func(d *NetDevice) { d.EndpointIP = "switch.lab" },
		"zone":                 func(d *NetDevice) { d.EndpointIP = "fd00::1%eth0" },
		"public address":       func(d *NetDevice) { d.EndpointIP = "8.8.8.8" },
		"loopback":             func(d *NetDevice) { d.EndpointIP = "127.0.0.1" },
		"link-local":           func(d *NetDevice) { d.EndpointIP = "169.254.1.1" },
		"multicast":            func(d *NetDevice) { d.EndpointIP = "ff02::1" },
		"unspecified":          func(d *NetDevice) { d.EndpointIP = "0.0.0.0" },
		"non-canonical ip":     func(d *NetDevice) { d.EndpointIP = "FD00::1" },
		"mapped ipv4":          func(d *NetDevice) { d.EndpointIP = "::ffff:10.0.0.2" },
		"port zero":            func(d *NetDevice) { d.Port = 0 },
		"label control char":   func(d *NetDevice) { d.Label = "a\x1bb" },
		"label invalid utf8":   func(d *NetDevice) { d.Label = "a\xffb" },
		"long label":           func(d *NetDevice) { d.Label = strings.Repeat("x", 256) },
		"bad credential ref":   func(d *NetDevice) { d.CredentialRef = "Secret Value!" },
		"missing digest ref":   func(d *NetDevice) { d.DigestKeyRef = "" },
		"missing fp ref":       func(d *NetDevice) { d.FingerprintKeyRef = "" },
		"same key refs":        func(d *NetDevice) { d.FingerprintKeyRef = d.DigestKeyRef },
		"bad digest ref":       func(d *NetDevice) { d.DigestKeyRef = "a/b" },
		"generation not 1":     func(d *NetDevice) { d.TrustGeneration = 2 },
		"inserted as blocked":  func(d *NetDevice) { d.Blocked = true; d.BlockReason = "x" },
		"inserted with reason": func(d *NetDevice) { d.BlockReason = "x" },
		"inserted tombstoned":  func(d *NetDevice) { at := ndT0; d.TombstonedAt = &at },
	}
	for name, mutate := range cases {
		d := cbsDevice("sw-a", pinOf("a"))
		mutate(&d)
		if _, err := db.InsertNetDevice(d); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if list, err := db.ListNetDevices(); err != nil || len(list) != 0 {
		t.Fatalf("rejected inserts left rows: %v %v", list, err)
	}
}

func TestNetDeviceDuplicateIDAndPinRefused(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	if _, err := db.InsertNetDevice(cbsDevice("sw-a", pinOf("other"))); !errors.Is(err, ErrNetDeviceExists) {
		t.Fatalf("duplicate id: err = %v", err)
	}
	if _, err := db.InsertNetDevice(cbsDevice("sw-b", pinOf("a"))); !errors.Is(err, ErrNetTrustIdentityInUse) {
		t.Fatalf("duplicate pin: err = %v", err)
	}
	list, err := db.ListNetDevices()
	if err != nil || len(list) != 1 {
		t.Fatalf("refused inserts changed the registry: %v %v", list, err)
	}
}

func TestNetDeviceTombstonedIDNeverReused(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	ts, err := db.TombstoneNetDevice("sw-a")
	if err != nil {
		t.Fatal(err)
	}
	if ts.TombstonedAt == nil || !ts.TombstonedAt.Equal(ndT0) {
		t.Fatalf("tombstone time: %+v", ts)
	}
	// The id is reserved in netdev_tombstones, not only on the device row.
	var tombAt int64
	if err := db.sql.QueryRow(`SELECT tombstoned_at FROM netdev_tombstones WHERE id = 'sw-a'`).Scan(&tombAt); err != nil {
		t.Fatalf("no netdev_tombstones row after TombstoneNetDevice: %v", err)
	}
	if tombAt != ndT0.Unix() {
		t.Fatalf("netdev_tombstones time = %d, want %d", tombAt, ndT0.Unix())
	}
	// Same id, same or a different pin: always refused.
	for _, pin := range []string{pinOf("a"), pinOf("new")} {
		if _, err := db.InsertNetDevice(cbsDevice("sw-a", pin)); !errors.Is(err, ErrNetDeviceTombstoned) {
			t.Fatalf("re-insert of tombstoned id: err = %v", err)
		}
	}
	// Tombstoned devices are not listed but stay readable.
	list, err := db.ListNetDevices()
	if err != nil || len(list) != 0 {
		t.Fatalf("tombstoned device listed: %v %v", list, err)
	}
	got, ok, err := db.GetNetDevice("sw-a")
	if err != nil || !ok || got.TombstonedAt == nil {
		t.Fatalf("tombstoned device not readable: %+v ok=%v err=%v", got, ok, err)
	}
	// Every mutation of a tombstoned device is refused.
	if _, err := db.TombstoneNetDevice("sw-a"); !errors.Is(err, ErrNetDeviceTombstoned) {
		t.Fatalf("second tombstone: err = %v", err)
	}
	if _, err := db.BlockNetDevice("sw-a", "x"); !errors.Is(err, ErrNetDeviceTombstoned) {
		t.Fatalf("block tombstoned: err = %v", err)
	}
	if _, err := db.UnblockNetDevice("sw-a"); !errors.Is(err, ErrNetDeviceTombstoned) {
		t.Fatalf("unblock tombstoned: err = %v", err)
	}
	if _, err := db.BumpTrustGeneration("sw-a", pinOf("z")); !errors.Is(err, ErrNetDeviceTombstoned) {
		t.Fatalf("bump tombstoned: err = %v", err)
	}
	// The trust identity of the removed device may be enrolled under a new id.
	insertND(t, db, cbsDevice("sw-a2", pinOf("a")))
	if _, err := db.TombstoneNetDevice("missing"); !errors.Is(err, ErrNetDeviceNotFound) {
		t.Fatalf("tombstone missing: err = %v", err)
	}
}

func TestNetDeviceTrustGenerationIncrements(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	insertND(t, db, cbsDevice("sw-b", pinOf("b")))
	later := ndT0.Add(time.Hour)
	db.now = func() time.Time { return later }
	d, err := db.BumpTrustGeneration("sw-a", pinOf("a2"))
	if err != nil {
		t.Fatal(err)
	}
	if d.TrustGeneration != 2 || d.PinValue != pinOf("a2") || !d.UpdatedAt.Equal(later) || !d.CreatedAt.Equal(ndT0) {
		t.Fatalf("after bump: %+v", d)
	}
	d, err = db.BumpTrustGeneration("sw-a", pinOf("a3"))
	if err != nil || d.TrustGeneration != 3 {
		t.Fatalf("second bump: %+v %v", d, err)
	}
	refused := map[string]struct {
		id, pin string
		want    error
	}{
		"same pin":       {"sw-a", pinOf("a3"), ErrInvalid},
		"malformed pin":  {"sw-a", "abc", ErrInvalid},
		"pin of another": {"sw-a", pinOf("b"), ErrNetTrustIdentityInUse},
		"missing device": {"nope", pinOf("q"), ErrNetDeviceNotFound},
	}
	for name, c := range refused {
		if _, err := db.BumpTrustGeneration(c.id, c.pin); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	got, _, err := db.GetNetDevice("sw-a")
	if err != nil || got.TrustGeneration != 3 || got.PinValue != pinOf("a3") {
		t.Fatalf("refused bumps changed the device: %+v %v", got, err)
	}
	// The old pin is released for other devices.
	insertND(t, db, cbsDevice("sw-c", pinOf("a")))
}

func TestNetDeviceTrustGenerationOverflowRefused(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	if _, err := db.sql.Exec(`UPDATE netdev_devices SET trust_generation = ? WHERE id = 'sw-a'`, int64(netdevcontract.MaxTrustGeneration)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.BumpTrustGeneration("sw-a", pinOf("b")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overflow bump: err = %v", err)
	}
}

func TestNetDeviceBlockedListedWithFlag(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	insertND(t, db, panosDevice("fw-b", pinOf("b")))
	d, err := db.BlockNetDevice("sw-a", "host key mismatch")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Blocked || d.BlockReason != "host key mismatch" {
		t.Fatalf("after block: %+v", d)
	}
	list, err := db.ListNetDevices()
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %v", list, err)
	}
	if list[1].ID != "sw-a" || !list[1].Blocked || list[1].BlockReason != "host key mismatch" || list[0].Blocked {
		t.Fatalf("blocked flag not listed: %+v", list)
	}
	// A block is kept until explicitly unblocked, also across a re-pin.
	if _, err := db.BlockNetDevice("sw-a", "again"); !errors.Is(err, ErrNetDeviceState) {
		t.Fatalf("double block: err = %v", err)
	}
	if d, err := db.BumpTrustGeneration("sw-a", pinOf("a2")); err != nil || !d.Blocked {
		t.Fatalf("re-pin cleared the block: %+v %v", d, err)
	}
	for _, reason := range []string{"", strings.Repeat("r", 513), "bad\x00reason"} {
		if _, err := db.BlockNetDevice("fw-b", reason); !errors.Is(err, ErrInvalid) {
			t.Errorf("reason %q: err = %v", reason, err)
		}
	}
	d, err = db.UnblockNetDevice("sw-a")
	if err != nil || d.Blocked || d.BlockReason != "" {
		t.Fatalf("after unblock: %+v %v", d, err)
	}
	if _, err := db.UnblockNetDevice("sw-a"); !errors.Is(err, ErrNetDeviceState) {
		t.Fatalf("double unblock: err = %v", err)
	}
	if _, err := db.BlockNetDevice("nope", "x"); !errors.Is(err, ErrNetDeviceNotFound) {
		t.Fatalf("block missing: err = %v", err)
	}
	if _, err := db.UnblockNetDevice("nope"); !errors.Is(err, ErrNetDeviceNotFound) {
		t.Fatalf("unblock missing: err = %v", err)
	}
}

func TestNetDeviceClosedDBFailsClosed(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	checks := map[string]func() error{
		"InsertNetDevice": func() error { _, err := db.InsertNetDevice(cbsDevice("sw-b", pinOf("b"))); return err },
		"GetNetDevice": func() error {
			d, ok, err := db.GetNetDevice("sw-a")
			if ok || d.ID != "" {
				t.Errorf("GetNetDevice returned a partial result")
			}
			return err
		},
		"ListNetDevices": func() error {
			l, err := db.ListNetDevices()
			if l != nil {
				t.Errorf("ListNetDevices returned a partial result")
			}
			return err
		},
		"BumpTrustGeneration": func() error { _, err := db.BumpTrustGeneration("sw-a", pinOf("c")); return err },
		"BlockNetDevice":      func() error { _, err := db.BlockNetDevice("sw-a", "x"); return err },
		"UnblockNetDevice":    func() error { _, err := db.UnblockNetDevice("sw-a"); return err },
		"TombstoneNetDevice":  func() error { _, err := db.TombstoneNetDevice("sw-a"); return err },
	}
	for name, call := range checks {
		if err := call(); err == nil {
			t.Errorf("%s on a closed database returned nil", name)
		}
	}
}

// TestNetDeviceCorruptRowFailsClosed checks that a row violating the
// store's invariants (an endpoint that is no longer an approved IP
// literal) is never returned, by Get, List or a mutation.
func TestNetDeviceCorruptRowFailsClosed(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	insertND(t, db, cbsDevice("sw-b", pinOf("b")))
	if _, err := db.sql.Exec(`UPDATE netdev_devices SET endpoint_ip = '8.8.8.8' WHERE id = 'sw-b'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.GetNetDevice("sw-b"); err == nil {
		t.Fatal("corrupt row returned by GetNetDevice")
	}
	if l, err := db.ListNetDevices(); err == nil || l != nil {
		t.Fatalf("corrupt row: list = %v, err = %v", l, err)
	}
	if _, err := db.BlockNetDevice("sw-b", "x"); err == nil {
		t.Fatal("corrupt row mutated")
	}
}

// TestNetDeviceStoresNoSecrets checks that the registry schema has no
// column that could hold a secret value: key columns are vault references.
func TestNetDeviceStoresNoSecrets(t *testing.T) {
	db := ndDB(t)
	rows, err := db.sql.Query(`SELECT name FROM pragma_table_info('netdev_devices')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		n++
		lower := strings.ToLower(name)
		for _, bad := range []string{"secret", "password", "community", "psk", "token"} {
			if strings.Contains(lower, bad) {
				t.Errorf("column %s looks like it stores a secret", name)
			}
		}
		if strings.Contains(lower, "key") && !strings.HasSuffix(lower, "_ref") {
			t.Errorf("key column %s is not a vault reference", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("netdev_devices has no columns")
	}
}

// --- vault references, id immutability, constraint mapping -----------------

// TestNetDeviceVaultRefsUniqueAcrossDevices checks that no vault reference
// is shared between devices, in any role, and that a tombstoned device's
// references are never reused.
func TestNetDeviceVaultRefsUniqueAcrossDevices(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	insertND(t, db, panosDevice("fw-t", pinOf("t")))
	if _, err := db.TombstoneNetDevice("fw-t"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(d *NetDevice){
		"same digest ref":                  func(d *NetDevice) { d.DigestKeyRef = "nd-sw-a-digest" },
		"same fingerprint ref":             func(d *NetDevice) { d.FingerprintKeyRef = "nd-sw-a-fp" },
		"same credential ref":              func(d *NetDevice) { d.CredentialRef = "nd-sw-a-read" },
		"digest ref is other's fp ref":     func(d *NetDevice) { d.DigestKeyRef = "nd-sw-a-fp" },
		"fp ref is other's digest ref":     func(d *NetDevice) { d.FingerprintKeyRef = "nd-sw-a-digest" },
		"credential is other's digest ref": func(d *NetDevice) { d.CredentialRef = "nd-sw-a-digest" },
		"digest ref is other's credential": func(d *NetDevice) { d.DigestKeyRef = "nd-sw-a-read" },
		"tombstoned digest ref":            func(d *NetDevice) { d.DigestKeyRef = "nd-fw-t-digest" },
		"tombstoned fingerprint ref":       func(d *NetDevice) { d.FingerprintKeyRef = "nd-fw-t-fp" },
	}
	for name, mutate := range cases {
		d := cbsDevice("sw-b", pinOf("b"))
		mutate(&d)
		if _, err := db.InsertNetDevice(d); !errors.Is(err, ErrNetVaultRefInUse) {
			t.Errorf("%s: err = %v, want ErrNetVaultRefInUse", name, err)
		}
	}
	list, err := db.ListNetDevices()
	if err != nil || len(list) != 1 {
		t.Fatalf("refused inserts changed the registry: %v %v", list, err)
	}
	// A device with fresh references is still accepted.
	insertND(t, db, cbsDevice("sw-b", pinOf("b")))
}

// TestNetDeviceVaultRefsDistinctPerDevice checks that one device never uses
// the same vault entry in two roles.
func TestNetDeviceVaultRefsDistinctPerDevice(t *testing.T) {
	db := ndDB(t)
	cases := map[string]func(d *NetDevice){
		"digest = fingerprint": func(d *NetDevice) { d.FingerprintKeyRef = d.DigestKeyRef },
		"credential = digest":  func(d *NetDevice) { d.CredentialRef = d.DigestKeyRef },
		"credential = fp":      func(d *NetDevice) { d.CredentialRef = d.FingerprintKeyRef },
	}
	for name, mutate := range cases {
		d := cbsDevice("sw-a", pinOf("a"))
		mutate(&d)
		if _, err := db.InsertNetDevice(d); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	// The same rules hold at the database level.
	raw := map[string][3]any{
		"digest = fingerprint": {nil, "k", "k"},
		"credential = digest":  {"k", "k", "f"},
		"credential = fp":      {"k", "d", "k"},
	}
	for name, refs := range raw {
		if err := rawInsertNetDeviceRefs(db, "x", pinOf("x"), refs[0], refs[1].(string), refs[2].(string)); err == nil {
			t.Errorf("%s: accepted at the database level", name)
		}
	}
}

// rawInsertNetDeviceRefs writes a device row with explicit vault references.
func rawInsertNetDeviceRefs(db *DB, id, pin string, cred any, digest, fp string) error {
	_, err := db.sql.Exec(`INSERT INTO netdev_devices (id, family, endpoint_ip, port, pin_kind, pin_value,
		credential_ref, digest_key_ref, fingerprint_key_ref, created_at, updated_at)
		VALUES (?, 'cbs', '10.0.0.1', 22, 'ssh-host-key', ?, ?, ?, ?, 0, 0)`, id, pin, cred, digest, fp)
	return err
}

// TestNetdevSchemaVaultRefGuards checks the database-level uniqueness of
// vault references, independent of the Go store, including tombstoned rows
// and updates of the reference columns.
func TestNetdevSchemaVaultRefGuards(t *testing.T) {
	db := ndDB(t)
	if err := rawInsertNetDeviceRefs(db, "sw-a", pinOf("a"), "c-a", "d-a", "f-a"); err != nil {
		t.Fatal(err)
	}
	if err := rawInsertNetDeviceRefs(db, "sw-n", pinOf("n"), nil, "d-n", "f-n"); err != nil {
		t.Fatal(err)
	}
	// Two devices without a credential are fine: NULL is not a reference.
	if err := rawInsertNetDeviceRefs(db, "sw-m", pinOf("m"), nil, "d-m", "f-m"); err != nil {
		t.Fatalf("second device without credential refused: %v", err)
	}
	refused := map[string]func() error{
		"insert same digest":       func() error { return rawInsertNetDeviceRefs(db, "x", pinOf("x"), nil, "d-a", "f-x") },
		"insert same fp":           func() error { return rawInsertNetDeviceRefs(db, "x", pinOf("x"), nil, "d-x", "f-a") },
		"insert same credential":   func() error { return rawInsertNetDeviceRefs(db, "x", pinOf("x"), "c-a", "d-x", "f-x") },
		"insert cross-role digest": func() error { return rawInsertNetDeviceRefs(db, "x", pinOf("x"), nil, "f-a", "f-x") },
		"insert cross-role cred":   func() error { return rawInsertNetDeviceRefs(db, "x", pinOf("x"), "d-a", "d-x", "f-x") },
		"update to other's digest": func() error {
			_, err := db.sql.Exec(`UPDATE netdev_devices SET digest_key_ref = 'd-a' WHERE id = 'sw-n'`)
			return err
		},
		"update to other's fp as digest": func() error {
			_, err := db.sql.Exec(`UPDATE netdev_devices SET digest_key_ref = 'f-a' WHERE id = 'sw-n'`)
			return err
		},
		"update credential to other's": func() error {
			_, err := db.sql.Exec(`UPDATE netdev_devices SET credential_ref = 'c-a' WHERE id = 'sw-n'`)
			return err
		},
	}
	for name, do := range refused {
		if err := do(); err == nil {
			t.Errorf("%s: accepted at the database level", name)
		}
	}
	// Tombstone sw-a; its references stay reserved.
	if _, err := db.sql.Exec(`UPDATE netdev_devices SET tombstoned_at = 1 WHERE id = 'sw-a'`); err != nil {
		t.Fatal(err)
	}
	for name, do := range map[string]func() error{
		"reuse tombstoned digest":     func() error { return rawInsertNetDeviceRefs(db, "y", pinOf("y"), nil, "d-a", "f-y") },
		"reuse tombstoned fp":         func() error { return rawInsertNetDeviceRefs(db, "y", pinOf("y"), nil, "d-y", "f-a") },
		"reuse tombstoned credential": func() error { return rawInsertNetDeviceRefs(db, "y", pinOf("y"), "c-a", "d-y", "f-y") },
	} {
		if err := do(); err == nil {
			t.Errorf("%s: accepted at the database level", name)
		}
	}
}

// TestNetdevSchemaIDImmutable checks that a raw UPDATE can never change a
// device id or a tombstone id.
func TestNetdevSchemaIDImmutable(t *testing.T) {
	db := ndDB(t)
	insertND(t, db, cbsDevice("sw-a", pinOf("a")))
	insertND(t, db, cbsDevice("sw-t", pinOf("t")))
	if _, err := db.TombstoneNetDevice("sw-t"); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"rename live device":               `UPDATE netdev_devices SET id = 'sw-b' WHERE id = 'sw-a'`,
		"rename live device to tombstoned": `UPDATE netdev_devices SET id = 'sw-t' WHERE id = 'sw-a'`,
		"rename tombstone":                 `UPDATE netdev_tombstones SET id = 'sw-z' WHERE id = 'sw-t'`,
	} {
		if _, err := db.sql.Exec(q); err == nil {
			t.Errorf("%s: accepted at the database level", name)
		}
	}
	if _, ok, err := db.GetNetDevice("sw-a"); err != nil || !ok {
		t.Fatalf("device lost: ok=%v err=%v", ok, err)
	}
	if _, ok, err := db.GetNetDevice("sw-b"); err != nil || ok {
		t.Fatalf("device renamed: ok=%v err=%v", ok, err)
	}
}

// TestNetConstraintErrorsMapped provokes each database constraint with a
// direct insert, as a concurrent writer that passed the Go pre-checks
// would, and checks the error maps to the typed error callers branch on.
func TestNetConstraintErrorsMapped(t *testing.T) {
	db := ndDB(t)
	if err := rawInsertNetDeviceRefs(db, "sw-a", pinOf("a"), "c-a", "d-a", "f-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`INSERT INTO netdev_tombstones (id, tombstoned_at) VALUES ('sw-gone', 1)`); err != nil {
		t.Fatal(err)
	}
	insertTomb := func() error {
		_, err := db.sql.Exec(`INSERT INTO netdev_tombstones (id, tombstoned_at) VALUES ('sw-gone', 2)`)
		return err
	}
	cases := []struct {
		name string
		do   func() error
		want error
	}{
		{"duplicate id", func() error { return rawInsertNetDeviceRefs(db, "sw-a", pinOf("x"), nil, "d-x", "f-x") }, ErrNetDeviceExists},
		{"tombstoned id", func() error { return rawInsertNetDeviceRefs(db, "sw-gone", pinOf("x"), nil, "d-x", "f-x") }, ErrNetDeviceTombstoned},
		{"duplicate tombstone", insertTomb, ErrNetDeviceTombstoned},
		{"duplicate trust identity", func() error { return rawInsertNetDeviceRefs(db, "sw-b", pinOf("a"), nil, "d-x", "f-x") }, ErrNetTrustIdentityInUse},
		{"duplicate digest ref", func() error { return rawInsertNetDeviceRefs(db, "sw-b", pinOf("x"), nil, "d-a", "f-x") }, ErrNetVaultRefInUse},
		{"duplicate fingerprint ref", func() error { return rawInsertNetDeviceRefs(db, "sw-b", pinOf("x"), nil, "d-x", "f-a") }, ErrNetVaultRefInUse},
		{"duplicate credential ref", func() error { return rawInsertNetDeviceRefs(db, "sw-b", pinOf("x"), "c-a", "d-x", "f-x") }, ErrNetVaultRefInUse},
		{"cross-role ref", func() error { return rawInsertNetDeviceRefs(db, "sw-b", pinOf("x"), nil, "c-a", "f-x") }, ErrNetVaultRefInUse},
	}
	for _, c := range cases {
		raw := c.do()
		if raw == nil {
			t.Errorf("%s: not refused", c.name)
			continue
		}
		if got := mapNetConstraintErr(raw); !errors.Is(got, c.want) {
			t.Errorf("%s: mapped %v to %v, want %v", c.name, raw, got, c.want)
		}
	}
	// Errors that are not registry uniqueness constraints are not mapped.
	other := errors.New("disk on fire")
	if got := mapNetConstraintErr(other); got != other {
		t.Fatalf("unrelated error rewritten: %v", got)
	}
	chk := rawInsertNetDeviceRefs(db, "BAD", pinOf("y"), nil, "d-y", "f-y")
	if chk == nil {
		t.Fatal("bad id accepted")
	}
	for _, typed := range []error{ErrNetDeviceExists, ErrNetDeviceTombstoned, ErrNetTrustIdentityInUse, ErrNetVaultRefInUse} {
		if errors.Is(mapNetConstraintErr(chk), typed) {
			t.Fatalf("CHECK failure mapped to %v", typed)
		}
	}
}
