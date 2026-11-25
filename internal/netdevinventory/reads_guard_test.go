// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// currentDatasetID returns the ID of the current dataset of (dev, read).
func currentDatasetID(t *testing.T, db *sql.DB, dev string, read Read) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(`SELECT id FROM netdev_datasets WHERE device_id = ? AND read = ? AND current = 1`,
		dev, string(read)).Scan(&id); err != nil {
		t.Fatalf("current dataset of %s %s: %v", dev, read, err)
	}
	return id
}

// plantStoredValue changes stored rows behind the write path's back. The
// schema CHECKs are switched off on the single connection so that the
// readers' own refusals (the second line of defence) are what gets tested.
func plantStoredValue(t *testing.T, db *sql.DB, stmt string) {
	t.Helper()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA ignore_check_constraints = ON`); err != nil {
		t.Fatalf("disable check constraints: %v", err)
	}
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("plant %q: %v", stmt, err)
	}
}

// TestCorruptedStoredRowsAreRefused: a stored value the readers cannot
// represent makes the read fail. It is never returned as a clean value, and
// never as an empty result.
func TestCorruptedStoredRowsAreRefused(t *testing.T) {
	ctx := context.Background()
	facts := FactsRows{Facts: netdevcontract.Facts{Model: "C9300-24P", FirmwareVersion: "17.9.4",
		UptimeSeconds: u64p(86400), ManagementAddresses: []string{"192.168.1.2"}}}
	port := PortRows{{Name: "Gi1/0/1", AdminState: netdevcontract.LinkUp, OperState: netdevcontract.LinkUp,
		SpeedMbps: u64p(1000), Mode: netdevcontract.ModeAccess, AccessVLAN: u16p(20)}}

	tests := []struct {
		name  string
		setup func(t *testing.T, s *Store, db *sql.DB)
		plant string
		probe func(s *Store) error
	}{
		{
			name: "vlan above uint16",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1, Name: "default"}})
			},
			plant: `UPDATE netdev_vlans SET vlan_id = 70000`,
			probe: func(s *Store) error { _, err := s.VLANs(ctx, "sw-core"); return err },
		},
		{
			name: "negative vlan",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1, Name: "default"}})
			},
			plant: `UPDATE netdev_vlans SET vlan_id = -1`,
			probe: func(s *Store) error { _, err := s.VLANs(ctx, "sw-core"); return err },
		},
		{
			name: "negative facts uptime",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadFacts, testBase, false, facts)
			},
			plant: `UPDATE netdev_facts SET uptime_seconds = -5`,
			probe: func(s *Store) error { _, err := s.Facts(ctx, "sw-core"); return err },
		},
		{
			name: "invalid JSON management addresses",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadFacts, testBase, false, facts)
			},
			plant: `UPDATE netdev_facts SET management_addresses = '{'`,
			probe: func(s *Store) error { _, err := s.Facts(ctx, "sw-core"); return err },
		},
		{
			name: "facts dataset without its row",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadFacts, testBase, false, facts)
			},
			plant: `DELETE FROM netdev_facts`,
			probe: func(s *Store) error { _, err := s.Facts(ctx, "sw-core"); return err },
		},
		{
			name: "negative port speed",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadPorts, testBase, false, port)
			},
			plant: `UPDATE netdev_interfaces SET speed_mbps = -1`,
			probe: func(s *Store) error { _, err := s.Ports(ctx, "sw-core"); return err },
		},
		{
			name: "invalid JSON allowed VLANs",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, cbsDevice())
				mustReplace(t, s, "sw-core", ReadPorts, testBase, false, port)
			},
			plant: `UPDATE netdev_interfaces SET allowed_vlans = '{'`,
			probe: func(s *Store) error { _, err := s.Ports(ctx, "sw-core"); return err },
		},
		{
			name: "unknown policy object kind",
			setup: func(t *testing.T, s *Store, _ *sql.DB) {
				addDevice(t, s, panosDevice())
				mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, policy("r1"))
			},
			plant: `UPDATE netdev_objects SET kind = 'bogus' WHERE kind = 'zone'`,
			probe: func(s *Store) error { _, err := s.FirewallPolicy(ctx, "fw-edge"); return err },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			tt.setup(t, s, db)
			plantStoredValue(t, db, tt.plant)
			if err := tt.probe(s); err == nil {
				t.Fatal("read of corrupted stored data succeeded, want an error")
			}
		})
	}
}

// TestPolicyKindCapHoldsForCarriedRows: each object kind is cut at its own
// contract maximum. Carried address rows of an incomplete read can push the
// addresses past their maximum; the cut must drop them, not a zone or the
// address the latest read stored.
func TestPolicyKindCapHoldsForCarriedRows(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	if _, err := replacePart(s, testBase, false, partRows(PolicyZones, "z")); err != nil {
		t.Fatal(err)
	}
	if _, err := replacePart(s, testBase.Add(time.Minute), false, partRows(PolicyObjects, "x")); err != nil {
		t.Fatal(err)
	}

	// Carried addresses, filling the address kind to its maximum on top of
	// the one the latest read stored: one more than the contract allows.
	id := currentDatasetID(t, db, "fw-edge", ReadFirewallPolicy)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO netdev_objects
		(dataset_id, row_key, seq, seen_at, absent, kind, name, address_type, value)
		VALUES (?, ?, NULL, 1, 0, 'address', ?, 'ip-netmask', '10.0.0.1/32')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := range netdevcontract.MaxAddressObjects {
		name := fmt.Sprintf("c-%05d", i)
		if _, err := stmt.ExecContext(ctx, id, "carried-"+name, name); err != nil {
			t.Fatal(err)
		}
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	got, err := s.FirewallPolicy(ctx, "fw-edge")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Addresses) != netdevcontract.MaxAddressObjects {
		t.Fatalf("addresses = %d, want the kind maximum %d", len(got.Addresses), netdevcontract.MaxAddressObjects)
	}
	if got.Addresses[0].Name != "a-x" {
		t.Fatalf("first address = %q, want the stored one a-x (carried rows sort last)", got.Addresses[0].Name)
	}
	if len(got.Zones) != 1 || got.Zones[0].Name != "z-z" {
		t.Fatalf("zones = %+v, want z-z kept although addresses are over their maximum", got.Zones)
	}
}

// TestFirewallPolicyRoundTripAllFields: every field of every policy part,
// including service groups, NAT translation fields and tags, comes back as
// it was written.
func TestFirewallPolicyRoundTripAllFields(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	want := netdevcontract.FirewallPolicy{
		SecurityRules: []netdevcontract.SecurityRule{{
			Name: "allow-web", UUID: "5f0c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f", From: []string{"trust"}, To: []string{"untrust"},
			Source: []string{"lan"}, Destination: []string{"any"}, SourceUser: []string{"alice"},
			Application: []string{"web-browsing"}, Service: []string{"application-default"},
			Category: []string{"business"}, Action: netdevcontract.ActionAllow, Disabled: true,
			Description: "web", Tags: []string{"t1"},
		}},
		NATRules: []netdevcontract.NATRule{{
			Name: "outbound", UUID: "6a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d", From: []string{"trust"}, To: []string{"untrust"},
			Source: []string{"lan"}, Destination: []string{"any"}, Service: "any",
			SourceTranslation: "dynamic-ip-and-port ethernet1/1", DestinationTranslation: "10.0.0.5",
			Disabled: true, Description: "nat", Tags: []string{"t2"},
		}},
		Addresses: []netdevcontract.AddressObject{{Name: "lan", Type: netdevcontract.AddressNetmask,
			Value: "192.168.1.0/24", Description: "lan", Tags: []string{"t3"}}},
		AddressGroups: []netdevcontract.Group{{Name: "internal", Static: []string{"lan"},
			DynamicFilter: "", Description: "g", Tags: []string{"t4"}}},
		Services: []netdevcontract.ServiceObject{{Name: "web", Protocol: "tcp", Port: "80,443",
			SourcePort: "1024", Description: "s", Tags: []string{"t5"}}},
		ServiceGroups: []netdevcontract.Group{{Name: "webs", Static: []string{"web"},
			Description: "sg", Tags: []string{"t6"}}},
		Zones: []netdevcontract.Zone{{Name: "trust", Interfaces: []string{"ethernet1/2"}}},
		Interfaces: []netdevcontract.FirewallInterface{{Name: "ethernet1/2", VLANTag: u16p(20),
			Addresses: []string{"192.168.1.1/24"}, Zone: "trust"}},
	}
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, PolicyRows{Policy: want})

	got, err := s.FirewallPolicy(ctx, "fw-edge")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy round trip differs:\n got %+v\nwant %+v", got, want)
	}
}

// TestCarriedPolicyRowsListAfterCurrentRows: an incomplete read keeps the
// rows it did not deliver after its own rows, in row-key order, and a
// complete read removes them again.
func TestCarriedPolicyRowsListAfterCurrentRows(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	rules := func(names ...string) PolicyPartRows {
		var p netdevcontract.FirewallPolicy
		for _, n := range names {
			p.SecurityRules = append(p.SecurityRules, netdevcontract.SecurityRule{Name: n, Action: netdevcontract.ActionAllow})
		}
		return PolicyPartRows{Part: PolicySecurityRules, Policy: p}
	}
	list := func() []string {
		t.Helper()
		got, err := s.FirewallPolicy(ctx, "fw-edge")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range got.SecurityRules {
			out = append(out, r.Name)
		}
		return out
	}

	if _, err := replacePart(s, testBase, false, rules("r-b", "r-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := replacePart(s, testBase.Add(time.Minute), true, rules("r-c")); err != nil {
		t.Fatal(err)
	}
	if got, want := list(), []string{"r-c", "r-a", "r-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after incomplete read: %v, want %v", got, want)
	}
	if _, err := replacePart(s, testBase.Add(2*time.Minute), false, rules("r-d")); err != nil {
		t.Fatal(err)
	}
	if got, want := list(), []string{"r-d"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after complete read: %v, want %v", got, want)
	}
}
