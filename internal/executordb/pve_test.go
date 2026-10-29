// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// pinOf derives a well-formed 64-char lowercase hex trust pin from s.
func pinOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var pveT0 = time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)

func pveDB(t *testing.T) *DB {
	t.Helper()
	return openAtT(t, privateDir(t), pveT0)
}

func pveClusterRemote(id, pin string) pvecontract.Remote {
	return pvecontract.Remote{
		RemoteID: id, Name: id, Kind: pvecontract.KindCluster,
		Endpoints: []pvecontract.Endpoint{
			{Host: "pve1.example.lan", Port: 8006},
			{Host: "pve2.example.lan", Port: 8006},
		},
		TrustPin: pin, TrustGeneration: 1,
	}
}

func pveStandaloneRemote(id, pin string) pvecontract.Remote {
	return pvecontract.Remote{
		RemoteID: id, Name: id, Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "solo.example.lan", Port: 8006}},
		TrustPin:  pin, TrustGeneration: 1,
	}
}

func addPveRemote(t *testing.T, db *DB, r pvecontract.Remote) PveRemote {
	t.Helper()
	rm, err := db.AddRemote(r, PveRemoteCredentials{ReadRef: "pve-" + r.RemoteID + "-read", ReadVersion: 1}, "admin")
	if err != nil {
		t.Fatalf("add %s: %v", r.RemoteID, err)
	}
	return rm
}

func TestPveRemoteCreateListGet(t *testing.T) {
	db := pveDB(t)
	rm := addPveRemote(t, db, pveClusterRemote("pve-main", pinOf("ca-main")))
	if rm.State != StateActive || rm.TrustPinKind != PinKindCA || rm.TrustGeneration != 1 {
		t.Fatalf("new remote: state=%s pinkind=%s gen=%d", rm.State, rm.TrustPinKind, rm.TrustGeneration)
	}
	if !rm.CreatedAt.Equal(pveT0) || !rm.UpdatedAt.Equal(pveT0) || rm.UpdatedBy != "admin" {
		t.Fatalf("timestamps: created=%v updated=%v by=%s", rm.CreatedAt, rm.UpdatedAt, rm.UpdatedBy)
	}
	if len(rm.Endpoints) != 2 || rm.Endpoints[0].Host != "pve1.example.lan" || rm.Endpoints[1].Port != 8006 {
		t.Fatalf("endpoints out of order: %v", rm.Endpoints)
	}
	if rm.Credentials.ReadRef != "pve-pve-main-read" || rm.Credentials.ReadVersion != 1 {
		t.Fatalf("credentials: %+v", rm.Credentials)
	}

	solo := addPveRemote(t, db, pveStandaloneRemote("pve-solo", pinOf("leaf-solo")))
	if solo.TrustPinKind != PinKindLeaf {
		t.Fatalf("standalone pin kind %s, want leaf", solo.TrustPinKind)
	}

	got, ok, err := db.GetRemote("pve-main")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.TrustPin != rm.TrustPin || len(got.Endpoints) != 2 {
		t.Fatalf("get returned %q with %d endpoints", got.TrustPin, len(got.Endpoints))
	}
	if _, ok, err := db.GetRemote("nope"); err != nil || ok {
		t.Fatalf("get missing: ok=%v err=%v", ok, err)
	}

	all, err := db.ListRemotes()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].RemoteID != "pve-main" || all[1].RemoteID != "pve-solo" {
		t.Fatalf("list: %v", all)
	}

	byPin, ok, err := db.RemoteByTrustPin(pinOf("leaf-solo"))
	if err != nil || !ok || byPin.RemoteID != "pve-solo" {
		t.Fatalf("by pin: ok=%v id=%q err=%v", ok, byPin.RemoteID, err)
	}
	if _, ok, err := db.RemoteByTrustPin(pinOf("unknown")); err != nil || ok {
		t.Fatalf("by unknown pin: ok=%v err=%v", ok, err)
	}
}

func TestPveRemoteCreateRejectsInvalid(t *testing.T) {
	db := pveDB(t)
	base := pveClusterRemote("pve-main", pinOf("ca-main"))
	creds := PveRemoteCredentials{ReadRef: "pve-main-read", ReadVersion: 1}
	many := make([]pvecontract.Endpoint, pvecontract.MaxEndpointsPerRemote+1)
	for i := range many {
		many[i] = pvecontract.Endpoint{Host: "n1.example.lan", Port: 8006}
	}
	longName := strings.Repeat("n", pvecontract.MaxLabelBytes+1)
	longRef := strings.Repeat("r", 65)
	cases := map[string]func(r *pvecontract.Remote, c *PveRemoteCredentials, by *string){
		"bad remote id upper":     func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.RemoteID = "PVE" },
		"bad remote id leading -": func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.RemoteID = "-pve" },
		"remote id too long":      func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.RemoteID = strings.Repeat("a", 65) },
		"pin uppercase": func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) {
			r.TrustPin = strings.ToUpper(pinOf("x"))
		},
		"pin too short":       func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.TrustPin = pinOf("x")[:63] },
		"pin non-hex":         func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.TrustPin = strings.Repeat("g", 64) },
		"no endpoints":        func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Endpoints = nil },
		"too many endpoints":  func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Endpoints = many },
		"duplicate endpoints": func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Endpoints[1] = r.Endpoints[0] },
		"endpoint port zero":  func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Endpoints[0].Port = 0 },
		"endpoint bad host":   func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Endpoints[0].Host = "bad_host" },
		"standalone two endpoints": func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) {
			r.Kind = pvecontract.KindStandalone
			r.Endpoints = append(r.Endpoints, pvecontract.Endpoint{Host: "n3.example.lan", Port: 8006})
		},
		"unknown kind":        func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Kind = "vmware" },
		"generation zero":     func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.TrustGeneration = 0 },
		"generation not one":  func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.TrustGeneration = 2 },
		"name too long":       func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Name = longName },
		"name control char":   func(r *pvecontract.Remote, _ *PveRemoteCredentials, _ *string) { r.Name = "bad\x1b[31m" },
		"read version no ref": func(_ *pvecontract.Remote, c *PveRemoteCredentials, _ *string) { c.ReadRef, c.ReadVersion = "", 1 },
		"read ref no version": func(_ *pvecontract.Remote, c *PveRemoteCredentials, _ *string) {
			c.ReadRef, c.ReadVersion = "pve-main-read", 0
		},
		"read ref malformed":    func(_ *pvecontract.Remote, c *PveRemoteCredentials, _ *string) { c.ReadRef = "Bad_Ref" },
		"read ref too long":     func(_ *pvecontract.Remote, c *PveRemoteCredentials, _ *string) { c.ReadRef = longRef },
		"action version no ref": func(_ *pvecontract.Remote, c *PveRemoteCredentials, _ *string) { c.ActionRef, c.ActionVersion = "", 3 },
		"empty actor":           func(_ *pvecontract.Remote, _ *PveRemoteCredentials, by *string) { *by = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, c, by := base, creds, "admin"
			mutate(&r, &c, &by)
			if _, err := db.AddRemote(r, c, by); err == nil {
				t.Fatal("accepted")
			}
			all, err := db.ListRemotes()
			if err != nil {
				t.Fatal(err)
			}
			if len(all) != 0 {
				t.Fatalf("rejected add left %d rows behind", len(all))
			}
		})
	}
}

func TestPveRemoteDuplicateTrustPin(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-a", pinOf("shared-ca")))
	_, err := db.AddRemote(pveClusterRemote("pve-b", pinOf("shared-ca")), PveRemoteCredentials{}, "admin")
	if !errors.Is(err, ErrTrustPinInUse) {
		t.Fatalf("duplicate pin: %v", err)
	}
	if !strings.Contains(err.Error(), "pve-a") {
		t.Fatalf("error does not name the owning remote: %v", err)
	}
	all, err := db.ListRemotes()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("duplicate add left rows behind: %v", all)
	}
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM pve_remote_endpoints WHERE remote_id = 'pve-b'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rejected add left %d endpoint rows", n)
	}
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM pve_remote_changes WHERE remote_id = 'pve-b'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rejected add left %d change rows", n)
	}
}

func TestPveRemoteBlockUnblock(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-a", pinOf("ca-a")))

	rm, err := db.BlockRemote("pve-a", "pin mismatch at pve1.example.lan", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rm.State != StateBlocked || !rm.BlockedAt.Equal(pveT0) || rm.BlockedBy != "admin" || rm.BlockedReason == "" {
		t.Fatalf("blocked record: %+v", rm)
	}
	if _, err := db.BlockRemote("pve-a", "again", "admin"); !errors.Is(err, ErrRemoteState) {
		t.Fatalf("second block: %v", err)
	}
	if _, err := db.BlockRemote("nope", "r", "admin"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("block missing: %v", err)
	}
	if _, err := db.BlockRemote("pve-a", "\x1b[31m", "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control-char reason: %v", err)
	}
	if _, err := db.BlockRemote("pve-a", "", "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty reason: %v", err)
	}

	rm, err = db.UnblockRemote("pve-a", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rm.State != StateActive || rm.BlockedAt != nil || rm.BlockedReason != "" {
		t.Fatalf("unblocked record: %+v", rm)
	}
	if _, err := db.UnblockRemote("pve-a", "admin"); !errors.Is(err, ErrRemoteState) {
		t.Fatalf("unblock active: %v", err)
	}
	if _, err := db.UnblockRemote("nope", "admin"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("unblock missing: %v", err)
	}

	changes, err := db.RemoteChanges("pve-a")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, c := range changes {
		types = append(types, c.ChangeType)
	}
	if len(types) != 3 || types[0] != ChangeCreated || types[1] != ChangeBlocked || types[2] != ChangeUnblocked {
		t.Fatalf("change trail: %v", types)
	}
}

func TestPveRemoteRemoveTombstoneAndReadd(t *testing.T) {
	db := pveDB(t)
	pin := pinOf("ca-a")
	addPveRemote(t, db, pveClusterRemote("pve-a", pin))

	rm, err := db.RemoveRemote("pve-a", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rm.State != StateRemoved || !rm.RemovedAt.Equal(pveT0) {
		t.Fatalf("removed record: %+v", rm)
	}
	if _, err := db.RemoveRemote("pve-a", "admin"); !errors.Is(err, ErrRemoteState) {
		t.Fatalf("second remove: %v", err)
	}
	if _, err := db.RemoveRemote("nope", "admin"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("remove missing: %v", err)
	}

	// The tombstone stays: id and trust identity are still reserved.
	tomb, ok, err := db.GetRemote("pve-a")
	if err != nil || !ok || tomb.State != StateRemoved {
		t.Fatalf("tombstone: ok=%v state=%q err=%v", ok, tomb.State, err)
	}
	if len(tomb.Endpoints) != 2 {
		t.Fatalf("tombstone lost endpoints: %v", tomb.Endpoints)
	}
	byPin, ok, err := db.RemoteByTrustPin(pin)
	if err != nil || !ok || byPin.RemoteID != "pve-a" || byPin.State != StateRemoved {
		t.Fatalf("pin of tombstone: ok=%v err=%v", ok, err)
	}

	// A different id with the tombstoned pin is refused.
	if _, err := db.AddRemote(pveClusterRemote("pve-b", pin), PveRemoteCredentials{}, "admin"); !errors.Is(err, ErrTrustPinInUse) {
		t.Fatalf("new id with tombstoned pin: %v", err)
	}

	// Re-add under a different trust identity is refused.
	rmB := addPveRemote(t, db, pveClusterRemote("pve-b", pinOf("ca-b")))
	if _, err := db.RemoveRemote("pve-b", "admin"); err != nil {
		t.Fatal(err)
	}
	_ = rmB
	if _, err := db.AddRemote(pveClusterRemote("pve-b", pinOf("ca-b-other")), PveRemoteCredentials{}, "admin"); !errors.Is(err, ErrRemoteTombstoned) {
		t.Fatalf("re-add with different pin: %v", err)
	}

	// Explicit re-add: same id, same trust identity. It continues the
	// trust generation and returns the remote to active.
	rm, err = db.AddRemote(pveClusterRemote("pve-a", pin), PveRemoteCredentials{ReadRef: "pve-a-read", ReadVersion: 2}, "admin")
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if rm.State != StateActive || rm.TrustGeneration != 2 || rm.RemovedAt != nil {
		t.Fatalf("re-added record: %+v", rm)
	}
	got, ok, err := db.GetRemote("pve-a")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if !got.CreatedAt.Equal(pveT0) {
		t.Fatalf("re-add changed created_at to %v", got.CreatedAt)
	}
	changes, err := db.RemoteChanges("pve-a")
	if err != nil {
		t.Fatal(err)
	}
	var last string
	for _, c := range changes {
		last = c.ChangeType
	}
	if last != ChangeReAdded {
		t.Fatalf("change trail ends with %q, want %q", last, ChangeReAdded)
	}
}

func TestPveRemoteRepin(t *testing.T) {
	db := pveDB(t)
	p1, p2 := pinOf("ca-1"), pinOf("ca-2")
	addPveRemote(t, db, pveClusterRemote("pve-a", p1))

	rm, err := db.RepinRemote("pve-a", p1, p2, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rm.TrustPin != p2 || rm.TrustGeneration != 2 || rm.State != StateActive {
		t.Fatalf("re-pinned record: %+v", rm)
	}
	if _, ok, _ := db.RemoteByTrustPin(p2); !ok {
		t.Fatal("new pin not resolvable")
	}
	if _, ok, _ := db.RemoteByTrustPin(p1); ok {
		t.Fatal("old pin still resolvable after re-pin")
	}

	// The released pin may be registered for another remote.
	if _, err := db.AddRemote(pveClusterRemote("pve-b", p1), PveRemoteCredentials{}, "admin"); err != nil {
		t.Fatalf("released pin re-registered: %v", err)
	}
	// But a pin in use by another remote is refused.
	if _, err := db.RepinRemote("pve-a", p2, p1, "admin"); !errors.Is(err, ErrTrustPinInUse) {
		t.Fatalf("repin to pin in use: %v", err)
	}

	if _, err := db.RepinRemote("pve-a", p1, p2, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale old pin: %v", err)
	}
	if _, err := db.RepinRemote("pve-a", p2, p2, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("repin to same pin: %v", err)
	}
	if _, err := db.RepinRemote("pve-a", p2, "nothex", "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed new pin: %v", err)
	}
	if _, err := db.RepinRemote("nope", p2, p1, "admin"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("repin missing: %v", err)
	}

	// Re-pin is the recovery path for a blocked remote: it clears the
	// block and bumps the generation.
	if _, err := db.BlockRemote("pve-a", "mismatch", "admin"); err != nil {
		t.Fatal(err)
	}
	p3 := pinOf("ca-3")
	rm, err = db.RepinRemote("pve-a", p2, p3, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rm.State != StateActive || rm.TrustGeneration != 3 || rm.BlockedAt != nil {
		t.Fatalf("re-pin of blocked remote: %+v", rm)
	}

	// A tombstoned remote cannot be re-pinned.
	if _, err := db.RemoveRemote("pve-b", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RepinRemote("pve-b", p1, p3, "admin"); !errors.Is(err, ErrRemoteState) {
		t.Fatalf("repin removed: %v", err)
	}
}

func TestPveRemoteEndpointChange(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-a", pinOf("ca-a")))
	newEps := []pvecontract.Endpoint{
		{Host: "pve3.example.lan", Port: 8006},
		{Host: "pve1.example.lan", Port: 8443},
	}
	rm, err := db.SetEndpoints("pve-a", newEps, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(rm.Endpoints) != 2 || rm.Endpoints[0].Host != "pve3.example.lan" || rm.Endpoints[1].Port != 8443 {
		t.Fatalf("endpoints: %v", rm.Endpoints)
	}
	changes, err := db.RemoteChanges("pve-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[1].ChangeType != ChangeEndpointChange {
		t.Fatalf("change trail: %+v", changes)
	}

	// Contract validation applies to the new set, against the kind.
	if _, err := db.SetEndpoints("pve-a", nil, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero endpoints: %v", err)
	}
	if _, err := db.SetEndpoints("pve-a", append(newEps, newEps[0]), "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate endpoint: %v", err)
	}
	addPveRemote(t, db, pveStandaloneRemote("pve-solo", pinOf("leaf-solo")))
	if _, err := db.SetEndpoints("pve-solo", newEps, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("standalone with two endpoints: %v", err)
	}

	if _, err := db.SetEndpoints("nope", newEps, "admin"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("missing remote: %v", err)
	}
	if _, err := db.BlockRemote("pve-a", "mismatch", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetEndpoints("pve-a", newEps, "admin"); !errors.Is(err, ErrRemoteState) {
		t.Fatalf("blocked remote: %v", err)
	}
}

func TestPveRemoteCredentialsRotation(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-a", pinOf("ca-a")))

	rm, err := db.SetRemoteCredentials("pve-a", PveRemoteCredentials{
		ReadRef: "pve-a-read", ReadVersion: 2,
		ActionRef: "pve-a-action", ActionVersion: 1,
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rm.Credentials.ReadVersion != 2 || rm.Credentials.ActionRef != "pve-a-action" || rm.Credentials.ActionVersion != 1 {
		t.Fatalf("credentials: %+v", rm.Credentials)
	}
	changes, err := db.RemoteChanges("pve-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[1].ChangeType != ChangeCredentials {
		t.Fatalf("change trail: %+v", changes)
	}

	if _, err := db.SetRemoteCredentials("pve-a", PveRemoteCredentials{ReadVersion: 3}, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("version without ref: %v", err)
	}
	if _, err := db.SetRemoteCredentials("nope", PveRemoteCredentials{}, "admin"); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("missing remote: %v", err)
	}
	if _, err := db.BlockRemote("pve-a", "mismatch", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetRemoteCredentials("pve-a", PveRemoteCredentials{ReadRef: "pve-a-read", ReadVersion: 3}, "admin"); !errors.Is(err, ErrRemoteState) {
		t.Fatalf("blocked remote: %v", err)
	}
}

func TestPveClosedDBFailsClosed(t *testing.T) {
	db := pveDB(t)
	addPveRemote(t, db, pveClusterRemote("pve-a", pinOf("ca-a")))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	eps := []pvecontract.Endpoint{{Host: "pve1.example.lan", Port: 8006}}
	creds := PveRemoteCredentials{ReadRef: "pve-a-read", ReadVersion: 1}
	checks := []struct {
		name string
		call func() error
	}{
		{"AddRemote", func() error {
			_, err := db.AddRemote(pveClusterRemote("pve-b", pinOf("b")), creds, "admin")
			return err
		}},
		{"GetRemote", func() error { _, _, err := db.GetRemote("pve-a"); return err }},
		{"ListRemotes", func() error { _, err := db.ListRemotes(); return err }},
		{"RemoteByTrustPin", func() error { _, _, err := db.RemoteByTrustPin(pinOf("ca-a")); return err }},
		{"BlockRemote", func() error { _, err := db.BlockRemote("pve-a", "r", "admin"); return err }},
		{"UnblockRemote", func() error { _, err := db.UnblockRemote("pve-a", "admin"); return err }},
		{"RepinRemote", func() error { _, err := db.RepinRemote("pve-a", pinOf("ca-a"), pinOf("x"), "admin"); return err }},
		{"SetEndpoints", func() error { _, err := db.SetEndpoints("pve-a", eps, "admin"); return err }},
		{"RemoveRemote", func() error { _, err := db.RemoveRemote("pve-a", "admin"); return err }},
		{"SetRemoteCredentials", func() error { _, err := db.SetRemoteCredentials("pve-a", creds, "admin"); return err }},
		{"RemoteChanges", func() error { _, err := db.RemoteChanges("pve-a"); return err }},
	}
	for _, c := range checks {
		if err := c.call(); err == nil {
			t.Errorf("%s on a closed database returned nil", c.name)
		}
	}
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
