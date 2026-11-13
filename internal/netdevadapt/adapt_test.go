// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevadapt

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
)

var testBase = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// fixture is a real SQLite inventory store whose clock the test moves.
func fixture(t *testing.T) (*netdevinventory.Store, *time.Time) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	now := testBase
	return netdevinventory.NewWithNow(db, func() time.Time { return now }), &now
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// addSwitch registers a CBS switch whose endpoint address ends in n.
func addSwitch(t *testing.T, s *netdevinventory.Store, id string, n int) {
	t.Helper()
	must(t, s.UpsertDevice(context.Background(), netdevcontract.Device{
		DeviceID:        id,
		Name:            id,
		Family:          netdevcontract.FamilyCBS,
		Endpoints:       []netdevcontract.Endpoint{{Address: fmt.Sprintf("192.168.1.%d", n), Port: 22}},
		PinKind:         netdevcontract.PinSSHHostKey,
		TrustPin:        strings.Repeat("a", 64),
		TrustGeneration: 1,
	}))
}

func macRow(vlan uint16, mac, port string) netdevcontract.MACEntry {
	return netdevcontract.MACEntry{VLAN: vlan, MAC: mac, Port: port, Type: netdevcontract.MACDynamic}
}

func replaceMAC(t *testing.T, s *netdevinventory.Store, dev string, at time.Time, incomplete bool, rows netdevinventory.MACRows) {
	t.Helper()
	_, err := s.ReplaceDataset(context.Background(), dev, netdevinventory.ReadMACTable, 1, at, incomplete, rows)
	must(t, err)
}

func replaceVLAN(t *testing.T, s *netdevinventory.Store, dev string, at time.Time, incomplete bool, rows netdevinventory.VLANRows) {
	t.Helper()
	_, err := s.ReplaceDataset(context.Background(), dev, netdevinventory.ReadVLANs, 1, at, incomplete, rows)
	must(t, err)
}

func replaceLLDP(t *testing.T, s *netdevinventory.Store, dev string, at time.Time, incomplete bool, rows netdevinventory.LLDPRows) {
	t.Helper()
	_, err := s.ReplaceDataset(context.Background(), dev, netdevinventory.ReadLLDPNeighbors, 1, at, incomplete, rows)
	must(t, err)
}

func TestNewRefusesNilStore(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) returned no error")
	}
}

func TestEmptyInventoryGivesNoTables(t *testing.T) {
	s, _ := fixture(t)
	a, err := New(s)
	must(t, err)
	ctx := context.Background()
	for name, get := range map[string]func() (int, error){
		"mac":  func() (int, error) { v, err := a.MACTables(ctx); return len(v), err },
		"vlan": func() (int, error) { v, err := a.VLANTables(ctx); return len(v), err },
		"lldp": func() (int, error) { v, err := a.LLDPTables(ctx); return len(v), err },
	} {
		n, err := get()
		must(t, err)
		if n != 0 {
			t.Errorf("%s: empty inventory gave %d tables, want 0", name, n)
		}
	}
}

func TestMACTablesKeepStateOfCompleteIncompleteAndStaleDatasets(t *testing.T) {
	s, now := fixture(t)
	addSwitch(t, s, "sw-old", 1)
	replaceMAC(t, s, "sw-old", testBase, false, netdevinventory.MACRows{macRow(10, "02:00:00:00:00:01", "Gi1/0/1")})
	*now = testBase.Add(time.Hour) // sw-old is now stale (three 15 minute intervals)

	addSwitch(t, s, "sw-fresh", 2)
	replaceMAC(t, s, "sw-fresh", *now, false, netdevinventory.MACRows{macRow(10, "02:00:00:00:00:02", "Gi1/0/2")})
	addSwitch(t, s, "sw-partial", 3)
	replaceMAC(t, s, "sw-partial", *now, true, netdevinventory.MACRows{macRow(20, "02:00:00:00:00:03", "Gi1/0/3")})

	a, err := New(s)
	must(t, err)
	got, err := a.MACTables(context.Background())
	must(t, err)
	want := map[string]struct {
		state netdevinventory.DatasetState
		mac   string
		at    time.Time
	}{
		"sw-fresh":   {netdevinventory.StateFresh, "02:00:00:00:00:02", *now},
		"sw-old":     {netdevinventory.StateStale, "02:00:00:00:00:01", testBase},
		"sw-partial": {netdevinventory.StatePartial, "02:00:00:00:00:03", *now},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d tables, want %d: %+v", len(got), len(want), got)
	}
	for _, tb := range got {
		w, ok := want[tb.DeviceID]
		if !ok {
			t.Fatalf("unexpected table for %s", tb.DeviceID)
		}
		if tb.State != w.state {
			t.Errorf("%s: state %s, want %s", tb.DeviceID, tb.State, w.state)
		}
		if !tb.ObservedAt.Equal(w.at) {
			t.Errorf("%s: observed %v, want %v", tb.DeviceID, tb.ObservedAt, w.at)
		}
		if len(tb.Entries) != 1 || tb.Entries[0].MAC != w.mac {
			t.Errorf("%s: entries %+v, want one entry %s", tb.DeviceID, tb.Entries, w.mac)
		}
	}
}

func TestDeviceWithoutMACDatasetIsOmittedNotEmpty(t *testing.T) {
	s, _ := fixture(t)
	addSwitch(t, s, "sw-none", 4)
	addSwitch(t, s, "sw-empty", 5)
	replaceMAC(t, s, "sw-empty", testBase, false, nil)

	a, err := New(s)
	must(t, err)
	got, err := a.MACTables(context.Background())
	must(t, err)
	if len(got) != 1 || got[0].DeviceID != "sw-empty" {
		t.Fatalf("got %+v, want only sw-empty", got)
	}
	if got[0].State != netdevinventory.StateFresh || len(got[0].Entries) != 0 {
		t.Errorf("complete empty read: state %s entries %d, want fresh and none", got[0].State, len(got[0].Entries))
	}
	vl, err := a.VLANTables(context.Background())
	must(t, err)
	if len(vl) != 0 {
		t.Errorf("device without VLAN dataset appeared in VLANTables: %+v", vl)
	}
}

func TestVLANTablesKeepStateAndNames(t *testing.T) {
	s, now := fixture(t)
	addSwitch(t, s, "sw-old", 1)
	replaceVLAN(t, s, "sw-old", testBase, false, netdevinventory.VLANRows{{ID: 50, Name: "old"}})
	*now = testBase.Add(time.Hour)
	addSwitch(t, s, "sw-fresh", 2)
	replaceVLAN(t, s, "sw-fresh", *now, false, netdevinventory.VLANRows{{ID: 30, Name: "guest"}, {ID: 10, Name: "users"}})
	addSwitch(t, s, "sw-partial", 3)
	replaceVLAN(t, s, "sw-partial", *now, true, netdevinventory.VLANRows{{ID: 20, Name: "iot"}})
	addSwitch(t, s, "sw-empty", 4)
	replaceVLAN(t, s, "sw-empty", *now, false, nil)

	a, err := New(s)
	must(t, err)
	got, err := a.VLANTables(context.Background())
	must(t, err)
	states := map[string]netdevinventory.DatasetState{}
	for _, tb := range got {
		states[tb.DeviceID] = tb.State
		switch tb.DeviceID {
		case "sw-fresh":
			want := netdevinventory.VLANRows{{ID: 10, Name: "users"}, {ID: 30, Name: "guest"}}
			if !reflect.DeepEqual(tb.VLANs, want) {
				t.Errorf("sw-fresh VLANs %+v, want %+v (sorted by ID)", tb.VLANs, want)
			}
		case "sw-empty":
			if len(tb.VLANs) != 0 {
				t.Errorf("sw-empty VLANs %+v, want none", tb.VLANs)
			}
		}
	}
	want := map[string]netdevinventory.DatasetState{
		"sw-fresh":   netdevinventory.StateFresh,
		"sw-old":     netdevinventory.StateStale,
		"sw-partial": netdevinventory.StatePartial,
		"sw-empty":   netdevinventory.StateFresh,
	}
	if !reflect.DeepEqual(states, want) {
		t.Errorf("states %v, want %v", states, want)
	}
}

func TestRowsAbsentFromLatestCompleteReadAreNotReturned(t *testing.T) {
	s, now := fixture(t)
	addSwitch(t, s, "sw-1", 1)
	replaceMAC(t, s, "sw-1", testBase, false, netdevinventory.MACRows{
		macRow(10, "02:00:00:00:00:01", "Gi1/0/1"),
		macRow(10, "02:00:00:00:00:02", "Gi1/0/2"),
	})
	*now = testBase.Add(15 * time.Minute)
	replaceMAC(t, s, "sw-1", *now, false, netdevinventory.MACRows{macRow(10, "02:00:00:00:00:02", "Gi1/0/2")})

	a, err := New(s)
	must(t, err)
	got, err := a.MACTables(context.Background())
	must(t, err)
	if len(got) != 1 || len(got[0].Entries) != 1 || got[0].Entries[0].MAC != "02:00:00:00:00:02" {
		t.Fatalf("got %+v, want only the MAC of the latest complete read", got)
	}
}

func TestPartialReadKeepsCarriedRowsButMarksTablePartial(t *testing.T) {
	s, now := fixture(t)
	addSwitch(t, s, "sw-1", 1)
	replaceLLDP(t, s, "sw-1", testBase, false, netdevinventory.LLDPRows{
		{LocalPort: "Gi1/0/1", ChassisID: "ap-01", PortID: "eth0"},
	})
	*now = testBase.Add(15 * time.Minute)
	replaceLLDP(t, s, "sw-1", *now, true, netdevinventory.LLDPRows{
		{LocalPort: "Gi1/0/2", ChassisID: "sw-2", PortID: "Gi1/0/9"},
	})

	a, err := New(s)
	must(t, err)
	got, err := a.LLDPTables(context.Background())
	must(t, err)
	if len(got) != 1 || got[0].State != netdevinventory.StatePartial {
		t.Fatalf("got %+v, want one partial table", got)
	}
	if len(got[0].Neighbors) != 2 {
		t.Errorf("partial read: %d neighbors, want the new one plus the carried one", len(got[0].Neighbors))
	}
}

func TestLLDPNeighborsKeepDuplicatesAndHostileTextVerbatim(t *testing.T) {
	s, _ := fixture(t)
	addSwitch(t, s, "sw-1", 1)
	const hostile = "<script>alert(1)</script> &amp; evil"
	dup := netdevcontract.LLDPNeighbor{LocalPort: "Gi1/0/3", ChassisID: "ch", PortID: "p", SystemName: hostile,
		Capabilities: []netdevcontract.LLDPCapability{netdevcontract.CapBridge, netdevcontract.CapRouter}}
	replaceLLDP(t, s, "sw-1", testBase, false, netdevinventory.LLDPRows{dup, dup})

	a, err := New(s)
	must(t, err)
	got, err := a.LLDPTables(context.Background())
	must(t, err)
	if len(got) != 1 || len(got[0].Neighbors) != 2 {
		t.Fatalf("got %+v, want two neighbors (duplicates are not merged)", got)
	}
	for _, n := range got[0].Neighbors {
		if n.SystemName != hostile {
			t.Errorf("system name %q, want device text unchanged", n.SystemName)
		}
		if !reflect.DeepEqual(n.Capabilities, dup.Capabilities) {
			t.Errorf("capabilities %v, want %v", n.Capabilities, dup.Capabilities)
		}
	}
}

func TestTablesAreInDeterministicOrder(t *testing.T) {
	s, _ := fixture(t)
	addSwitch(t, s, "sw-b", 2)
	addSwitch(t, s, "sw-a", 1)
	replaceMAC(t, s, "sw-b", testBase, false, netdevinventory.MACRows{
		macRow(20, "02:00:00:00:00:03", "Gi1/0/3"), macRow(10, "02:00:00:00:00:02", "Gi1/0/2"),
	})
	replaceMAC(t, s, "sw-a", testBase, false, netdevinventory.MACRows{
		macRow(10, "02:00:00:00:00:09", "Gi1/0/9"), macRow(10, "02:00:00:00:00:01", "Gi1/0/1"),
	})
	a, err := New(s)
	must(t, err)
	ctx := context.Background()
	first, err := a.MACTables(ctx)
	must(t, err)
	second, err := a.MACTables(ctx)
	must(t, err)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("two reads of the same inventory differ")
	}
	if first[0].DeviceID != "sw-a" || first[1].DeviceID != "sw-b" {
		t.Fatalf("devices out of order: %s, %s", first[0].DeviceID, first[1].DeviceID)
	}
	if got := first[0].Entries[0].MAC + "," + first[0].Entries[1].MAC; got != "02:00:00:00:00:01,02:00:00:00:00:09" {
		t.Errorf("sw-a entries out of order: %s", got)
	}
}

func TestMACTableAboveLimitIsCappedAndPartial(t *testing.T) {
	s, now := fixture(t)
	addSwitch(t, s, "sw-1", 1)
	mk := func(from, n int) netdevinventory.MACRows {
		out := make(netdevinventory.MACRows, 0, n)
		for i := from; i < from+n; i++ {
			out = append(out, macRow(10, fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", i>>24&0xff, i>>16&0xff, i>>8&0xff, i&0xff), "Gi1/0/1"))
		}
		return out
	}
	limit := netdevcontract.MaxMACEntriesPerDevice
	replaceMAC(t, s, "sw-1", testBase, false, mk(0, limit))
	*now = testBase.Add(15 * time.Minute)
	// A partial read with other MACs carries the old ones: more rows than the limit.
	replaceMAC(t, s, "sw-1", *now, true, mk(limit, limit))

	a, err := New(s)
	must(t, err)
	got, err := a.MACTables(context.Background())
	must(t, err)
	if len(got) != 1 {
		t.Fatalf("got %d tables, want 1", len(got))
	}
	if len(got[0].Entries) > limit {
		t.Fatalf("%d entries, above the per-device limit %d", len(got[0].Entries), limit)
	}
	if got[0].State != netdevinventory.StatePartial {
		t.Errorf("state %s, want partial when rows were cut at the limit", got[0].State)
	}
}

// TestConsumersReceiveAdapterData runs the real consumer functions over the
// adapters: the IPAM VLAN hints and the traffic map switch endpoints.
func TestConsumersReceiveAdapterData(t *testing.T) {
	s, now := fixture(t)
	addSwitch(t, s, "sw-old", 2)
	replaceVLAN(t, s, "sw-old", testBase, false, netdevinventory.VLANRows{{ID: 50, Name: "old"}})
	replaceMAC(t, s, "sw-old", testBase, false, nil)
	*now = testBase.Add(time.Hour) // sw-old is stale now, sw-edge is written at this time

	addSwitch(t, s, "sw-edge", 1)
	replaceVLAN(t, s, "sw-edge", *now, false, netdevinventory.VLANRows{{ID: 10, Name: "users"}, {ID: 20, Name: "iot"}, {ID: 30, Name: "guest"}})
	replaceMAC(t, s, "sw-edge", *now, false, netdevinventory.MACRows{macRow(20, "aa:bb:cc:dd:ee:01", "Gi1/0/5")})
	replaceLLDP(t, s, "sw-edge", *now, false, netdevinventory.LLDPRows{{LocalPort: "Gi1/0/5", ChassisID: "ap-01", PortID: "eth0", SystemName: "ap"}})

	a, err := New(s)
	must(t, err)
	ctx := context.Background()
	im := fakeIPAM{
		assets: []ipam.Asset{{ID: "nas", MAC: "aa:bb:cc:dd:ee:01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.5")}}},
		nets: []ipam.Network{
			{ID: "net-users", VLAN: 10, Prefix: netip.MustParsePrefix("10.0.10.0/24")},
			{ID: "net-lab", VLAN: 40, Prefix: netip.MustParsePrefix("10.0.40.0/24")},
		},
	}
	hints, err := ipam.VLANHints(ctx, a, im)
	must(t, err)

	var asset, withoutNet, notOnSwitch []ipam.VLANHint
	for _, h := range hints {
		switch h.Kind {
		case ipam.HintAssetPortVLAN:
			asset = append(asset, h)
		case ipam.HintSwitchVLANWithoutNetwork:
			withoutNet = append(withoutNet, h)
		case ipam.HintNetworkVLANNotOnSwitch:
			notOnSwitch = append(notOnSwitch, h)
		}
	}
	if len(asset) != 1 || asset[0].AssetID != "nas" || asset[0].DeviceID != "sw-edge" ||
		asset[0].Port != "Gi1/0/5" || asset[0].SwitchVLAN != 20 || asset[0].State != netdevinventory.StateFresh {
		t.Errorf("asset hints %+v, want nas on sw-edge 1/0/5 VLAN 20 fresh", asset)
	}
	gotVLANs := map[string]netdevinventory.DatasetState{}
	for _, h := range withoutNet {
		gotVLANs[fmt.Sprintf("%s/%d/%s", h.DeviceID, h.SwitchVLAN, h.SwitchVLANName)] = h.State
	}
	wantVLANs := map[string]netdevinventory.DatasetState{
		"sw-edge/20/iot":   netdevinventory.StateFresh,
		"sw-edge/30/guest": netdevinventory.StateFresh,
		"sw-old/50/old":    netdevinventory.StateStale,
	}
	if !reflect.DeepEqual(gotVLANs, wantVLANs) {
		t.Errorf("switch VLANs without network %v, want %v", gotVLANs, wantVLANs)
	}
	if len(notOnSwitch) != 1 || notOnSwitch[0].NetworkID != "net-lab" || notOnSwitch[0].State != netdevinventory.StateStale {
		t.Errorf("network VLAN not on switch %+v, want net-lab with the stale state of the least fresh switch", notOnSwitch)
	}

	sm, err := trafficingest.SwitchEndpoints(ctx, a, nil)
	must(t, err)
	if len(sm.Endpoints) != 1 || sm.Endpoints[0].MAC != "aa:bb:cc:dd:ee:01" || sm.Endpoints[0].DeviceID != "sw-edge" ||
		sm.Endpoints[0].Port != "Gi1/0/5" || sm.Endpoints[0].VLAN != 20 || sm.Endpoints[0].State != netdevinventory.StateFresh {
		t.Errorf("switch endpoints %+v, want the MAC on sw-edge 1/0/5 VLAN 20", sm.Endpoints)
	}
	if len(sm.Links) != 1 || sm.Links[0].LocalPort != "Gi1/0/5" || sm.Links[0].RemoteChassisID != "ap-01" ||
		sm.Links[0].Source != trafficingest.SourceLLDP {
		t.Errorf("LLDP links %+v, want the ap-01 neighbor on 1/0/5", sm.Links)
	}
}

type fakeIPAM struct {
	assets []ipam.Asset
	nets   []ipam.Network
}

func (f fakeIPAM) Assets(context.Context) ([]ipam.Asset, error)     { return f.assets, nil }
func (f fakeIPAM) Networks(context.Context) ([]ipam.Network, error) { return f.nets, nil }
