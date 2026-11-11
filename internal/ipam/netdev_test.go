// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
)

// fakeSwitches is a read-only fake of the switch MAC tables.
type fakeSwitches struct {
	tables []MACTable
	err    error
}

func (f *fakeSwitches) MACTables(context.Context) ([]MACTable, error) { return f.tables, f.err }

// fakeIPAM is a read-only fake of the IPAM store. It has no write
// methods; VLANHints can only read it.
type fakeIPAM struct {
	assets   []Asset
	networks []Network
	err      error
}

func (f *fakeIPAM) Assets(context.Context) ([]Asset, error)     { return f.assets, f.err }
func (f *fakeIPAM) Networks(context.Context) ([]Network, error) { return f.networks, f.err }

var observed = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func macTable(device string, entries ...netdevcontract.MACEntry) MACTable {
	return MACTable{DeviceID: device, State: netdevinventory.StateFresh, ObservedAt: observed, Entries: entries}
}

func mac(vlan uint16, m, port string) netdevcontract.MACEntry {
	return netdevcontract.MACEntry{VLAN: vlan, MAC: m, Port: port, Type: netdevcontract.MACDynamic}
}

func labIPAM() *fakeIPAM {
	return &fakeIPAM{
		assets: []Asset{
			{ID: "nas", Name: "nas", Kind: KindNAS, MAC: "aa:bb:cc:00:00:01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.5")}},
			{ID: "printer", Name: "printer", Kind: KindPrinter, MAC: "aa:bb:cc:00:00:02", Addresses: []netip.Addr{netip.MustParseAddr("10.0.20.7")}},
			{ID: "nomac", Name: "nomac", Kind: KindIoT, Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.9")}},
		},
		networks: []Network{
			{ID: "lan", Name: "lan", Prefix: netip.MustParsePrefix("10.0.10.0/24"), VLAN: 10},
			{ID: "print", Name: "print", Prefix: netip.MustParsePrefix("10.0.20.0/24"), VLAN: 20},
		},
	}
}

func TestVLANHintsReportsMismatch(t *testing.T) {
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1",
		mac(30, "AA:BB:CC:00:00:01", "gi1/0/3"), // nas: IPAM says VLAN 10
		mac(20, "aa:bb:cc:00:00:02", "gi1/0/4"), // printer: matches
	)}}
	hints, err := VLANHints(context.Background(), sw, labIPAM())
	if err != nil {
		t.Fatal(err)
	}
	want := []VLANHint{{
		AssetID: "nas", MAC: "aa:bb:cc:00:00:01", Address: netip.MustParseAddr("10.0.10.5"),
		NetworkID: "lan", NetworkVLAN: 10,
		DeviceID: "cbs1", Port: "gi1/0/3", PortVLAN: 30,
		Source: SourceMACTable, State: netdevinventory.StateFresh, ObservedAt: observed,
	}}
	if !reflect.DeepEqual(hints, want) {
		t.Fatalf("hints = %+v\nwant %+v", hints, want)
	}
}

func TestVLANHintsNoHintWithoutIPAMData(t *testing.T) {
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	cases := map[string]*fakeIPAM{
		"no assets or networks": {},
		"no networks":           {assets: labIPAM().assets},
		"no assets":             {networks: labIPAM().networks},
		"network without vlan": {assets: labIPAM().assets, networks: []Network{
			{ID: "lan", Prefix: netip.MustParsePrefix("10.0.10.0/24")},
		}},
		"asset without mac": {assets: []Asset{{ID: "x", Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.5")}}}, networks: labIPAM().networks},
		"address outside networks": {assets: []Asset{{ID: "x", MAC: "aa:bb:cc:00:00:01",
			Addresses: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}}, networks: labIPAM().networks},
	}
	for name, im := range cases {
		t.Run(name, func(t *testing.T) {
			hints, err := VLANHints(context.Background(), sw, im)
			if err != nil {
				t.Fatal(err)
			}
			if len(hints) != 0 {
				t.Fatalf("hints = %+v, want none", hints)
			}
		})
	}
}

func TestVLANHintsNoHintWithoutSwitchData(t *testing.T) {
	hints, err := VLANHints(context.Background(), &fakeSwitches{}, labIPAM())
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 0 {
		t.Fatalf("hints = %+v, want none", hints)
	}
}

func TestVLANHintsExcludesUplinkAndLAGPorts(t *testing.T) {
	entries := []netdevcontract.MACEntry{
		mac(30, "aa:bb:cc:00:00:01", "gi1/0/24"), // nas MAC on a busy uplink
		mac(30, "aa:bb:cc:00:00:02", "Po1"),      // printer MAC on a LAG
		mac(30, "aa:bb:cc:00:00:02", "port-channel2"),
		mac(30, "aa:bb:cc:00:00:01", ""), // not bound to a front port
	}
	for i := range UplinkMACThreshold {
		entries = append(entries, mac(1, fmt.Sprintf("02:00:00:00:00:%02x", i), "gi1/0/24"))
	}
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1", entries...)}}
	hints, err := VLANHints(context.Background(), sw, labIPAM())
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 0 {
		t.Fatalf("hints = %+v, want none", hints)
	}
}

func TestUplinkPortsThreshold(t *testing.T) {
	var entries []netdevcontract.MACEntry
	for i := range UplinkMACThreshold {
		entries = append(entries, mac(10, fmt.Sprintf("02:00:00:00:00:%02x", i), "gi1/0/1"))
		// the same MAC in a second VLAN does not count twice
		entries = append(entries, mac(20, fmt.Sprintf("02:00:00:00:00:%02x", i), "gi1/0/1"))
	}
	entries = append(entries, mac(10, "02:00:00:00:01:00", "gi1/0/2"))
	up := UplinkPorts(entries)
	if up["gi1/0/1"] || up["gi1/0/2"] {
		t.Fatalf("uplinks = %v, want none at exactly the threshold", up)
	}
	entries = append(entries, mac(10, "02:00:00:00:02:00", "gi1/0/1"))
	if up := UplinkPorts(entries); !up["gi1/0/1"] || up["gi1/0/2"] {
		t.Fatalf("uplinks = %v, want only gi1/0/1", up)
	}
	if up := UplinkPorts([]netdevcontract.MACEntry{mac(1, "02:00:00:00:00:01", "Po3")}); !up["Po3"] {
		t.Fatalf("uplinks = %v, want the LAG Po3", up)
	}
}

func TestVLANHintsDoesNotWrite(t *testing.T) {
	im := labIPAM()
	before := labIPAM()
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	beforeSw := macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))
	if _, err := VLANHints(context.Background(), sw, im); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(im, before) {
		t.Fatal("VLANHints changed the IPAM data")
	}
	if !reflect.DeepEqual(sw.tables[0], beforeSw) {
		t.Fatal("VLANHints changed the switch data")
	}
}

func TestVLANHintsDoesNotWriteRealStore(t *testing.T) {
	s := newStore(t, nil)
	ctx := context.Background()
	if err := s.SaveNetwork(ctx, Network{ID: "lan", Name: "lan", Prefix: netip.MustParsePrefix("10.0.10.0/24"), VLAN: 10}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAsset(ctx, Asset{ID: "nas", Name: "nas", Kind: KindNAS, MAC: "aa:bb:cc:00:00:01",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.5")}}); err != nil {
		t.Fatal(err)
	}
	assets, _ := s.Assets(ctx)
	nets, _ := s.Networks(ctx)
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	hints, err := VLANHints(ctx, sw, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 {
		t.Fatalf("hints = %+v, want one", hints)
	}
	assets2, _ := s.Assets(ctx)
	nets2, _ := s.Networks(ctx)
	if !reflect.DeepEqual(assets, assets2) || !reflect.DeepEqual(nets, nets2) {
		t.Fatal("VLANHints changed the IPAM store")
	}
}

func TestVLANHintsMostSpecificNetwork(t *testing.T) {
	im := &fakeIPAM{
		assets: []Asset{{ID: "nas", MAC: "aa:bb:cc:00:00:01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.5")}}},
		networks: []Network{
			{ID: "wide", Prefix: netip.MustParsePrefix("10.0.0.0/16"), VLAN: 30},
			{ID: "lan", Prefix: netip.MustParsePrefix("10.0.10.0/24"), VLAN: 10},
		},
	}
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	hints, err := VLANHints(context.Background(), sw, im)
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 || hints[0].NetworkID != "lan" {
		t.Fatalf("hints = %+v, want one against lan", hints)
	}
}

func TestVLANHintsCarriesDatasetState(t *testing.T) {
	tb := macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))
	tb.State = netdevinventory.StateStale
	hints, err := VLANHints(context.Background(), &fakeSwitches{tables: []MACTable{tb}}, labIPAM())
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 || hints[0].State != netdevinventory.StateStale {
		t.Fatalf("hints = %+v, want one stale", hints)
	}
}

func TestVLANHintsReadErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := VLANHints(context.Background(), &fakeSwitches{err: boom}, labIPAM()); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	sw := &fakeSwitches{tables: []MACTable{macTable("cbs1", mac(30, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	if _, err := VLANHints(context.Background(), sw, &fakeIPAM{err: boom}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if _, err := VLANHints(context.Background(), nil, labIPAM()); err == nil {
		t.Fatal("nil switch reader accepted")
	}
}
