// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the netdev inventory store (ND-16): atomic dataset replace,
// out-of-order refusal, absent and partial handling, stale marking and
// hostile device text.

package netdevinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var testBase = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func newTestStore(t *testing.T) (*Store, *sql.DB, *time.Time) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	now := testBase
	s := NewWithNow(db, func() time.Time { return now })
	return s, db, &now
}

func cbsDevice() netdevcontract.Device {
	return netdevcontract.Device{
		DeviceID:        "sw-core",
		Name:            "Core switch",
		Family:          netdevcontract.FamilyCBS,
		Endpoints:       []netdevcontract.Endpoint{{Address: "192.168.1.2", Port: 22}},
		PinKind:         netdevcontract.PinSSHHostKey,
		TrustPin:        strings.Repeat("a", 64),
		TrustGeneration: 2,
	}
}

func panosDevice() netdevcontract.Device {
	return netdevcontract.Device{
		DeviceID:        "fw-edge",
		Name:            "Edge firewall",
		Family:          netdevcontract.FamilyPANOS,
		Endpoints:       []netdevcontract.Endpoint{{Address: "192.168.1.1", Port: 443}},
		PinKind:         netdevcontract.PinTLSLeaf,
		TrustPin:        strings.Repeat("b", 64),
		TrustGeneration: 1,
	}
}

func addDevice(t *testing.T, s *Store, d netdevcontract.Device) {
	t.Helper()
	if err := s.UpsertDevice(context.Background(), d); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
}

func mustReplace(t *testing.T, s *Store, dev string, read Read, at time.Time, incomplete bool, rows Rows) ReplaceResult {
	t.Helper()
	res, err := s.ReplaceDataset(context.Background(), dev, read, at, incomplete, rows)
	if err != nil {
		t.Fatalf("ReplaceDataset %s at %s: %v", read, at, err)
	}
	return res
}

func mac(n byte) netdevcontract.MACEntry {
	return netdevcontract.MACEntry{VLAN: 10, MAC: "aa:bb:cc:dd:ee:0" + string('0'+n), Port: "gi1/0/1", Type: netdevcontract.MACDynamic}
}

// storedRow is one row of a typed table as the tests inspect it.
type storedRow struct {
	key    string
	seq    sql.NullInt64
	seenAt sql.NullInt64
	absent bool
}

func rowsOf(t *testing.T, db *sql.DB, table string, datasetID int64) []storedRow {
	t.Helper()
	rs, err := db.Query(`SELECT row_key, seq, seen_at, absent FROM `+table+` WHERE dataset_id = ? ORDER BY row_key`, datasetID)
	if err != nil {
		t.Fatalf("query %s: %v", table, err)
	}
	defer rs.Close()
	var out []storedRow
	for rs.Next() {
		var r storedRow
		var absent int
		if err := rs.Scan(&r.key, &r.seq, &r.seenAt, &absent); err != nil {
			t.Fatalf("scan %s: %v", table, err)
		}
		r.absent = absent == 1
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatalf("rows %s: %v", table, err)
	}
	return out
}

func countRows(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func TestReplaceStoresFreshDataset(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	at := testBase.Add(-time.Minute)
	res := mustReplace(t, s, "sw-core", ReadVLANs, at, false, VLANRows{{ID: 1, Name: "default"}, {ID: 20, Name: "iot"}})

	d, err := s.GetDataset(context.Background(), "sw-core", ReadVLANs)
	if err != nil {
		t.Fatalf("GetDataset: %v", err)
	}
	if d.ID != res.DatasetID || d.State != StateFresh || d.Incomplete || d.RowCount != 2 || !d.ObservedAt.Equal(at) || !d.Current {
		t.Fatalf("dataset = %+v", d)
	}
	if len(d.PayloadSHA256) != 64 {
		t.Fatalf("payload digest %q", d.PayloadSHA256)
	}
	got := rowsOf(t, db, "netdev_vlans", d.ID)
	if len(got) != 2 || got[0].key != "1" || got[1].key != "20" || got[0].seenAt.Valid || got[0].absent {
		t.Fatalf("rows = %+v", got)
	}
	dev, err := s.GetDevice(context.Background(), "sw-core")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !dev.LastSeen.Equal(at) || dev.State != DeviceFresh || dev.Label != "Core switch" || dev.TrustGeneration != 2 {
		t.Fatalf("device = %+v", dev)
	}
}

func TestReplaceEmptyCompleteReadIsFreshAndMarksAllAbsent(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	mustReplace(t, s, "sw-core", ReadMACTable, testBase.Add(-2*time.Minute), false, MACRows{mac(1)})
	res := mustReplace(t, s, "sw-core", ReadMACTable, testBase.Add(-time.Minute), false, MACRows(nil))
	d, _ := s.GetDataset(context.Background(), "sw-core", ReadMACTable)
	if d.State != StateFresh || d.RowCount != 0 {
		t.Fatalf("dataset = %+v", d)
	}
	got := rowsOf(t, db, "netdev_mac_entries", res.DatasetID)
	if len(got) != 1 || !got[0].absent {
		t.Fatalf("rows = %+v", got)
	}
}

func TestReplaceFailureMidwayKeepsOldDataset(t *testing.T) {
	stages := []string{"dataset", "rows:netdev_fw_rules", "rows:netdev_nat_rules", "rows:netdev_objects", "commit"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			addDevice(t, s, panosDevice())
			old := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(-time.Hour), false, policy("allow-dns", "allow-web"))
			before, _ := s.GetDataset(context.Background(), "fw-edge", ReadFirewallPolicy)
			devBefore, _ := s.GetDevice(context.Background(), "fw-edge")

			boom := errors.New("injected failure")
			s.hook = func(st string) error {
				if st == stage {
					return boom
				}
				return nil
			}
			_, err := s.ReplaceDataset(context.Background(), "fw-edge", ReadFirewallPolicy, testBase, false, policy("deny-all"))
			if !errors.Is(err, boom) {
				t.Fatalf("err = %v, want injected failure", err)
			}
			s.hook = nil

			after, err := s.GetDataset(context.Background(), "fw-edge", ReadFirewallPolicy)
			if err != nil {
				t.Fatalf("GetDataset: %v", err)
			}
			if after != before || after.ID != old.DatasetID {
				t.Fatalf("dataset changed: before %+v after %+v", before, after)
			}
			if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets`); n != 1 {
				t.Fatalf("datasets = %d, want 1", n)
			}
			rules := rowsOf(t, db, "netdev_fw_rules", old.DatasetID)
			if len(rules) != 2 || rules[0].key != "allow-dns" || rules[1].key != "allow-web" {
				t.Fatalf("old rules = %+v", rules)
			}
			for _, tbl := range []string{"netdev_fw_rules", "netdev_nat_rules", "netdev_objects", "netdev_interfaces"} {
				if n := countRows(t, db, `SELECT count(*) FROM `+tbl+` WHERE dataset_id <> ?`, old.DatasetID); n != 0 {
					t.Fatalf("%s has %d rows of a rolled-back dataset", tbl, n)
				}
			}
			devAfter, _ := s.GetDevice(context.Background(), "fw-edge")
			if devAfter != devBefore {
				t.Fatalf("device changed: before %+v after %+v", devBefore, devAfter)
			}
		})
	}
}

func policy(rules ...string) PolicyRows {
	var p netdevcontract.FirewallPolicy
	for _, r := range rules {
		p.SecurityRules = append(p.SecurityRules, netdevcontract.SecurityRule{
			Name: r, From: []string{"trust"}, To: []string{"untrust"}, Source: []string{"any"},
			Destination: []string{"any"}, Application: []string{"any"}, Service: []string{"application-default"},
			Action: netdevcontract.ActionAllow,
		})
	}
	p.NATRules = []netdevcontract.NATRule{{Name: "outbound", From: []string{"trust"}, To: []string{"untrust"},
		SourceTranslation: "dynamic-ip-and-port ethernet1/1"}}
	p.Addresses = []netdevcontract.AddressObject{{Name: "lan", Type: netdevcontract.AddressNetmask, Value: "192.168.1.0/24"}}
	p.AddressGroups = []netdevcontract.Group{{Name: "internal", Static: []string{"lan"}}}
	p.Services = []netdevcontract.ServiceObject{{Name: "web", Protocol: "tcp", Port: "80,443"}}
	p.Zones = []netdevcontract.Zone{{Name: "trust", Interfaces: []string{"ethernet1/2"}}}
	tag := uint16(20)
	p.Interfaces = []netdevcontract.FirewallInterface{{Name: "ethernet1/2", VLANTag: &tag, Addresses: []string{"192.168.1.1/24"}, Zone: "trust"}}
	return PolicyRows{Policy: p}
}

func TestReplaceRefusesOutOfOrder(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	at := testBase.Add(-10 * time.Minute)
	first := mustReplace(t, s, "sw-core", ReadVLANs, at, false, VLANRows{{ID: 1}})

	cases := []struct {
		name string
		at   time.Time
		rows VLANRows
	}{
		{"older", at.Add(-time.Microsecond), VLANRows{{ID: 1}, {ID: 2}}},
		{"older identical", at.Add(-time.Hour), VLANRows{{ID: 1}}},
		{"same time other content", at, VLANRows{{ID: 3}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.ReplaceDataset(context.Background(), "sw-core", ReadVLANs, c.at, false, c.rows)
			if !errors.Is(err, ErrOutOfOrder) {
				t.Fatalf("err = %v, want ErrOutOfOrder", err)
			}
			d, _ := s.GetDataset(context.Background(), "sw-core", ReadVLANs)
			if d.ID != first.DatasetID || !d.ObservedAt.Equal(at) {
				t.Fatalf("dataset rolled back: %+v", d)
			}
			if got := rowsOf(t, db, "netdev_vlans", first.DatasetID); len(got) != 1 || got[0].key != "1" {
				t.Fatalf("rows = %+v", got)
			}
		})
	}

	// The same dataset delivered again (spool replay) is an idempotent no-op.
	res, err := s.ReplaceDataset(context.Background(), "sw-core", ReadVLANs, at, false, VLANRows{{ID: 1}})
	if err != nil || !res.Unchanged || res.DatasetID != first.DatasetID {
		t.Fatalf("replay = %+v, %v", res, err)
	}
	// A same-content replay that differs only in completeness is refused.
	if _, err := s.ReplaceDataset(context.Background(), "sw-core", ReadVLANs, at, true, VLANRows{{ID: 1}}); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("partial replay err = %v", err)
	}
}

func TestReplaceRefusesFutureObservation(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	if _, err := s.ReplaceDataset(context.Background(), "sw-core", ReadVLANs, testBase.Add(MaxFutureSkew+time.Second), false, VLANRows{{ID: 1}}); !errors.Is(err, ErrFutureObservation) {
		t.Fatalf("err = %v, want ErrFutureObservation", err)
	}
	mustReplace(t, s, "sw-core", ReadVLANs, testBase.Add(MaxFutureSkew), false, VLANRows{{ID: 1}})
}

func TestReplaceIdenticalPayloadOnlyAdvancesObservedAt(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	t1 := testBase.Add(-time.Hour)
	first := mustReplace(t, s, "sw-core", ReadVLANs, t1, false, VLANRows{{ID: 1, Name: "default"}})
	*now = testBase.Add(2 * time.Hour)
	if _, err := s.MarkStale(context.Background()); err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	t2 := testBase.Add(time.Hour + 59*time.Minute)
	res := mustReplace(t, s, "sw-core", ReadVLANs, t2, false, VLANRows{{ID: 1, Name: "default"}})
	if !res.Unchanged || res.DatasetID != first.DatasetID {
		t.Fatalf("result = %+v", res)
	}
	d, _ := s.GetDataset(context.Background(), "sw-core", ReadVLANs)
	if !d.ObservedAt.Equal(t2) || d.State != StateFresh {
		t.Fatalf("dataset = %+v", d)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets`); n != 1 {
		t.Fatalf("datasets = %d, want 1", n)
	}
}

func TestCompleteReadMarksMissingRowsAbsentAndKeepsHistory(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	t1 := testBase.Add(-30 * time.Minute)
	t2 := testBase.Add(-15 * time.Minute)
	t3 := testBase
	first := mustReplace(t, s, "sw-core", ReadMACTable, t1, false, MACRows{mac(1), mac(2)})
	second := mustReplace(t, s, "sw-core", ReadMACTable, t2, false, MACRows{mac(1)})
	if second.Carried != 1 {
		t.Fatalf("carried = %d, want 1", second.Carried)
	}
	got := rowsOf(t, db, "netdev_mac_entries", second.DatasetID)
	want := []storedRow{
		{key: "10/aa:bb:cc:dd:ee:01", seq: sql.NullInt64{Int64: 0, Valid: true}},
		{key: "10/aa:bb:cc:dd:ee:02", seenAt: sql.NullInt64{Int64: micros(t1), Valid: true}, absent: true},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
	// The absent row keeps its original last-seen time in the next dataset.
	third := mustReplace(t, s, "sw-core", ReadMACTable, t3, false, MACRows{mac(1), mac(3)})
	got = rowsOf(t, db, "netdev_mac_entries", third.DatasetID)
	if len(got) != 3 || !got[1].absent || got[1].seenAt.Int64 != micros(t1) {
		t.Fatalf("rows = %+v", got)
	}
	// History is kept: the first dataset and its rows are still stored.
	if n := len(rowsOf(t, db, "netdev_mac_entries", first.DatasetID)); n != 2 {
		t.Fatalf("history rows = %d, want 2", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE current = 1`); n != 1 {
		t.Fatalf("current datasets = %d", n)
	}
}

func TestPartialReadCarriesUncoveredRowsWithoutMarkingAbsent(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	t1 := testBase.Add(-15 * time.Minute)
	mustReplace(t, s, "sw-core", ReadMACTable, t1, false, MACRows{mac(1), mac(2)})
	res := mustReplace(t, s, "sw-core", ReadMACTable, testBase, true, MACRows{mac(1)})
	d, _ := s.GetDataset(context.Background(), "sw-core", ReadMACTable)
	if d.State != StatePartial || !d.Incomplete || d.RowCount != 1 {
		t.Fatalf("dataset = %+v", d)
	}
	got := rowsOf(t, db, "netdev_mac_entries", res.DatasetID)
	if len(got) != 2 || got[1].absent || got[1].seenAt.Int64 != micros(t1) || got[1].seq.Valid {
		t.Fatalf("rows = %+v", got)
	}
}

func TestFirewallPolicyStoredInTypedTables(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	res := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, policy("b-rule", "a-rule"))

	var seqA, seqB int
	if err := db.QueryRow(`SELECT seq FROM netdev_fw_rules WHERE dataset_id = ? AND name = 'a-rule'`, res.DatasetID).Scan(&seqA); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT seq FROM netdev_fw_rules WHERE dataset_id = ? AND name = 'b-rule'`, res.DatasetID).Scan(&seqB); err != nil {
		t.Fatal(err)
	}
	if seqB != 0 || seqA != 1 {
		t.Fatalf("rule order lost: b=%d a=%d", seqB, seqA)
	}
	var from, action string
	if err := db.QueryRow(`SELECT from_zones, action FROM netdev_fw_rules WHERE dataset_id = ? AND name = 'a-rule'`, res.DatasetID).Scan(&from, &action); err != nil {
		t.Fatal(err)
	}
	if from != `["trust"]` || action != "allow" {
		t.Fatalf("rule columns %q %q", from, action)
	}
	kinds := map[string]int{}
	rs, err := db.Query(`SELECT kind FROM netdev_objects WHERE dataset_id = ?`, res.DatasetID)
	if err != nil {
		t.Fatal(err)
	}
	for rs.Next() {
		var k string
		if err := rs.Scan(&k); err != nil {
			t.Fatal(err)
		}
		kinds[k]++
	}
	rs.Close()
	if kinds["address"] != 1 || kinds["address_group"] != 1 || kinds["service"] != 1 || kinds["zone"] != 1 {
		t.Fatalf("object kinds = %v", kinds)
	}
	var kind string
	var tag int
	if err := db.QueryRow(`SELECT kind, vlan_tag FROM netdev_interfaces WHERE dataset_id = ?`, res.DatasetID).Scan(&kind, &tag); err != nil {
		t.Fatal(err)
	}
	if kind != "firewall" || tag != 20 {
		t.Fatalf("interface %q %d", kind, tag)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_nat_rules WHERE dataset_id = ?`, res.DatasetID); n != 1 {
		t.Fatalf("nat rules = %d", n)
	}

	// A rule removed on the device stays visible as absent.
	next := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(time.Minute), false, policy("b-rule"))
	var absent int
	var seq sql.NullInt64
	if err := db.QueryRow(`SELECT absent, seq FROM netdev_fw_rules WHERE dataset_id = ? AND name = 'a-rule'`, next.DatasetID).Scan(&absent, &seq); err != nil {
		t.Fatalf("removed rule not carried: %v", err)
	}
	if absent != 1 || seq.Valid {
		t.Fatalf("removed rule absent=%d seq=%v", absent, seq)
	}
}

func TestHitCountsAndFactsStored(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	first := testBase.Add(-48 * time.Hour).In(time.FixedZone("CET", 3600))
	last := testBase.Add(-time.Hour)
	res := mustReplace(t, s, "fw-edge", ReadHitCounts, testBase, false, HitCountRows{
		{RuleName: "allow-dns", Hits: 42, FirstHit: &first, LastHit: &last},
		{RuleName: "unused"},
	})
	var hits, fh int64
	if err := db.QueryRow(`SELECT hits, first_hit FROM netdev_rule_hits WHERE dataset_id = ? AND rule_name = 'allow-dns'`, res.DatasetID).Scan(&hits, &fh); err != nil {
		t.Fatal(err)
	}
	if hits != 42 || fh != micros(first) {
		t.Fatalf("hits=%d first=%d", hits, fh)
	}

	up := uint64(3600)
	mustReplace(t, s, "fw-edge", ReadFacts, testBase, false, FactsRows{Facts: netdevcontract.Facts{
		Model: "PA-440", FirmwareVersion: "11.1.4", UptimeSeconds: &up, ManagementAddresses: []string{"192.168.1.1"}}})
	var model, addrs string
	if err := db.QueryRow(`SELECT model, management_addresses FROM netdev_facts`).Scan(&model, &addrs); err != nil {
		t.Fatal(err)
	}
	if model != "PA-440" || addrs != `["192.168.1.1"]` {
		t.Fatalf("facts %q %q", model, addrs)
	}
}

func TestReplaceRejectsBadInput(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())
	big := uint64(1) << 63
	cases := []struct {
		name string
		dev  string
		read Read
		inc  bool
		rows Rows
		want error
	}{
		{"unknown device", "sw-other", ReadVLANs, false, VLANRows{{ID: 1}}, ErrDeviceNotFound},
		{"malformed device id", "SW CORE", ReadVLANs, false, VLANRows{{ID: 1}}, ErrDeviceNotFound},
		{"unknown read", "sw-core", Read("running_config"), false, VLANRows{{ID: 1}}, ErrUnknownRead},
		{"rows of other read", "sw-core", ReadPorts, false, VLANRows{{ID: 1}}, ErrRowsMismatch},
		{"nil rows", "sw-core", ReadVLANs, false, nil, ErrRowsMismatch},
		{"cbs read on panos", "fw-edge", ReadVLANs, false, VLANRows{{ID: 1}}, ErrWrongFamily},
		{"panos read on cbs", "sw-core", ReadHitCounts, false, HitCountRows{}, ErrWrongFamily},
		{"vlan out of range", "sw-core", ReadVLANs, false, VLANRows{{ID: 4095}}, ErrInvalidRows},
		{"duplicate vlan", "sw-core", ReadVLANs, false, VLANRows{{ID: 5}, {ID: 5}}, ErrInvalidRows},
		{"incomplete facts", "sw-core", ReadFacts, true, FactsRows{Facts: netdevcontract.Facts{Model: "m", FirmwareVersion: "f"}}, ErrInvalidRows},
		{"malformed mac", "sw-core", ReadMACTable, false, MACRows{{VLAN: 1, MAC: "AA:BB:CC:DD:EE:FF", Type: netdevcontract.MACDynamic}}, ErrInvalidRows},
		{"hits overflow", "fw-edge", ReadHitCounts, false, HitCountRows{{RuleName: "r", Hits: big}}, ErrInvalidRows},
		{"uptime overflow", "sw-core", ReadFacts, false, FactsRows{Facts: netdevcontract.Facts{Model: "m", FirmwareVersion: "f", UptimeSeconds: &big}}, ErrInvalidRows},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.ReplaceDataset(context.Background(), c.dev, c.read, testBase, c.inc, c.rows)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestHostileStringsStoredVerbatimWithinLimits(t *testing.T) {
	hostile := []string{
		"<script>alert(1)</script>",
		"'; DROP TABLE netdev_vlans; --",
		`"quoted" \backslash\ & ampersand`,
		"Ünïcødé ✓ 漢字",
		"{{.Secret}} ${HOME} %s %n",
		strings.Repeat("x", netdevcontract.MaxLabelBytes),
		strings.Repeat("é", netdevcontract.MaxLabelBytes/2),
	}
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	for i, h := range hostile {
		t.Run(fmt.Sprintf("stored-%d", i), func(t *testing.T) {
			at := testBase.Add(time.Duration(i-len(hostile)) * time.Minute)
			res := mustReplace(t, s, "sw-core", ReadVLANs, at, false, VLANRows{{ID: 7, Name: h}})
			var name string
			if err := db.QueryRow(`SELECT name FROM netdev_vlans WHERE dataset_id = ?`, res.DatasetID).Scan(&name); err != nil {
				t.Fatal(err)
			}
			if name != h {
				t.Fatalf("stored %q, want %q", name, h)
			}
			lres := mustReplace(t, s, "sw-core", ReadLLDPNeighbors, at, false, LLDPRows{{
				LocalPort: "gi1/0/1", ChassisID: h, PortID: h, SystemName: h}})
			var chassis, sys, key string
			if err := db.QueryRow(`SELECT chassis_id, system_name, row_key FROM netdev_lldp_neighbors WHERE dataset_id = ? AND seq IS NOT NULL`, lres.DatasetID).Scan(&chassis, &sys, &key); err != nil {
				t.Fatal(err)
			}
			if chassis != h || sys != h {
				t.Fatalf("stored %q %q", chassis, sys)
			}
		})
	}

	refused := []string{
		strings.Repeat("x", netdevcontract.MaxLabelBytes+1),
		"\x1b[31mred",
		"line\nbreak",
		"nul\x00byte",
		"bidi ‮ override",
		"bad utf8 \xff",
	}
	before, err := s.GetDataset(context.Background(), "sw-core", ReadVLANs)
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range refused {
		t.Run(fmt.Sprintf("refused-%d", i), func(t *testing.T) {
			_, err := s.ReplaceDataset(context.Background(), "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 7, Name: h}})
			if !errors.Is(err, ErrInvalidRows) {
				t.Fatalf("err = %v, want ErrInvalidRows", err)
			}
			_, err = s.ReplaceDataset(context.Background(), "sw-core", ReadLLDPNeighbors, testBase, false, LLDPRows{{
				LocalPort: "gi1/0/1", ChassisID: "c", PortID: "p", SystemName: h}})
			if !errors.Is(err, ErrInvalidRows) {
				t.Fatalf("lldp err = %v, want ErrInvalidRows", err)
			}
			if after, _ := s.GetDataset(context.Background(), "sw-core", ReadVLANs); after != before {
				t.Fatalf("dataset changed: %+v", after)
			}
		})
	}
}

func TestDuplicateLLDPNeighborsAreAllStored(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	n := netdevcontract.LLDPNeighbor{LocalPort: "gi1/0/1", ChassisID: "c", PortID: "p"}
	res := mustReplace(t, s, "sw-core", ReadLLDPNeighbors, testBase, false, LLDPRows{n, n, n})
	got := rowsOf(t, db, "netdev_lldp_neighbors", res.DatasetID)
	if len(got) != 3 {
		t.Fatalf("rows = %+v", got)
	}
	keys := []string{got[0].key, got[1].key, got[2].key}
	want := []string{`["gi1/0/1","c","p"]`, `["gi1/0/1","c","p"]#2`, `["gi1/0/1","c","p"]#3`}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys = %q, want %q", keys, want)
	}
}

func TestMarkStaleAfterThreeIntervalsNeverDeletes(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())
	mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1}})
	mustReplace(t, s, "fw-edge", ReadHitCounts, testBase, false, HitCountRows{{RuleName: "r"}})
	ctx := context.Background()

	// Exactly three switch intervals: not yet stale.
	*now = testBase.Add(StaleAfterIntervals * SwitchInterval)
	rep, err := s.MarkStale(ctx)
	if err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	if rep != (StaleReport{}) {
		t.Fatalf("report at boundary = %+v", rep)
	}
	if d, _ := s.GetDevice(ctx, "sw-core"); d.State != DeviceFresh {
		t.Fatalf("device at boundary = %+v", d)
	}

	// One microsecond later the switch and its VLAN dataset are stale; the
	// firewall (60-minute interval) is not.
	*now = testBase.Add(StaleAfterIntervals*SwitchInterval + time.Microsecond)
	if d, _ := s.GetDevice(ctx, "sw-core"); d.State != DeviceStale {
		t.Fatalf("device before MarkStale = %+v, want stale view", d)
	}
	rep, err = s.MarkStale(ctx)
	if err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	if rep.Devices != 1 || rep.Datasets != 1 {
		t.Fatalf("report = %+v", rep)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM netdev_devices_seen WHERE device_id = 'sw-core'`).Scan(&state); err != nil || state != "stale" {
		t.Fatalf("stored device state %q %v", state, err)
	}
	if d, _ := s.GetDataset(ctx, "sw-core", ReadVLANs); d.State != StateStale {
		t.Fatalf("dataset = %+v", d)
	}
	if d, _ := s.GetDevice(ctx, "fw-edge"); d.State != DeviceFresh {
		t.Fatalf("firewall = %+v", d)
	}

	// Long after: still stored, still stale, never deleted.
	*now = testBase.Add(365 * 24 * time.Hour)
	if _, err := s.MarkStale(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_devices_seen WHERE state = 'stale'`); n != 2 {
		t.Fatalf("stale devices = %d, want 2", n)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_vlans`); n != 1 {
		t.Fatalf("vlan rows = %d, want 1", n)
	}

	// A new read makes device and dataset fresh again.
	mustReplace(t, s, "sw-core", ReadVLANs, *now, false, VLANRows{{ID: 1}, {ID: 2}})
	if d, _ := s.GetDevice(ctx, "sw-core"); d.State != DeviceFresh {
		t.Fatalf("device after read = %+v", d)
	}
}

func TestMarkStaleCoversDeviceNeverRead(t *testing.T) {
	s, _, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	*now = testBase.Add(time.Hour)
	rep, err := s.MarkStale(context.Background())
	if err != nil || rep.Devices != 1 {
		t.Fatalf("report = %+v, %v", rep, err)
	}
}

func TestUpsertDeviceGuards(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	addDevice(t, s, cbsDevice())

	d := cbsDevice()
	d.TrustGeneration = 1
	if err := s.UpsertDevice(ctx, d); !errors.Is(err, ErrTrustGenerationRegressed) {
		t.Fatalf("regress err = %v", err)
	}
	p := panosDevice()
	p.DeviceID = "sw-core"
	if err := s.UpsertDevice(ctx, p); !errors.Is(err, ErrFamilyChanged) {
		t.Fatalf("family err = %v", err)
	}
	d = cbsDevice()
	d.Name = "<b>renamed</b>"
	d.TrustGeneration = 3
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetDevice(ctx, "sw-core")
	if got.Label != "<b>renamed</b>" || got.TrustGeneration != 3 {
		t.Fatalf("device = %+v", got)
	}
	d.Name = strings.Repeat("x", netdevcontract.MaxLabelBytes+1)
	if err := s.UpsertDevice(ctx, d); !errors.Is(err, netdevcontract.ErrInvalid) {
		t.Fatalf("long label err = %v", err)
	}
	if _, err := s.GetDevice(ctx, "nope"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("missing device err = %v", err)
	}
	if _, err := s.GetDataset(ctx, "sw-core", ReadVLANs); !errors.Is(err, ErrDatasetNotFound) {
		t.Fatalf("missing dataset err = %v", err)
	}
}
