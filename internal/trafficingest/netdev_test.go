// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// fakeSwitchData is a read-only fake of the netdevinventory switch
// datasets.
type fakeSwitchData struct {
	macs    []ipam.MACTable
	lldp    []LLDPTable
	macErr  error
	lldpErr error
}

func (f *fakeSwitchData) MACTables(context.Context) ([]ipam.MACTable, error) { return f.macs, f.macErr }
func (f *fakeSwitchData) LLDPTables(context.Context) ([]LLDPTable, error)    { return f.lldp, f.lldpErr }

// fakeLinks maps MACs to endpoints with server-confirmed links.
type fakeLinks struct {
	byMAC  map[string]trafficstore.Endpoint
	err    error
	called []string
}

func (f *fakeLinks) LookupEndpoint(_ context.Context, mac string, _ netip.Addr) (trafficstore.Endpoint, bool, error) {
	f.called = append(f.called, mac)
	if f.err != nil {
		return trafficstore.Endpoint{}, false, f.err
	}
	e, ok := f.byMAC[mac]
	return e, ok, nil
}

var swObserved = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func swMAC(vlan uint16, m, port string) netdevcontract.MACEntry {
	return netdevcontract.MACEntry{VLAN: vlan, MAC: m, Port: port, Type: netdevcontract.MACDynamic}
}

func swTable(device string, entries ...netdevcontract.MACEntry) ipam.MACTable {
	return ipam.MACTable{DeviceID: device, State: netdevinventory.StateFresh, ObservedAt: swObserved, Entries: entries}
}

func TestSwitchEndpointsMapMACToPort(t *testing.T) {
	sw := &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1",
		swMAC(10, "AA:BB:CC:00:00:01", "gi1/0/3"),
		swMAC(10, "aa:bb:cc:00:00:02", "gi1/0/4"),
		swMAC(1, "aa:bb:cc:00:00:ff", ""), // the switch's own address
	)}}
	got, err := SwitchEndpoints(context.Background(), sw, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []SwitchEndpoint{
		{MAC: "aa:bb:cc:00:00:01", DeviceID: "cbs1", Port: "gi1/0/3", VLAN: 10, Tier: TierSwitch, Source: SourceMACTable,
			State: netdevinventory.StateFresh, ObservedAt: swObserved},
		{MAC: "aa:bb:cc:00:00:02", DeviceID: "cbs1", Port: "gi1/0/4", VLAN: 10, Tier: TierSwitch, Source: SourceMACTable,
			State: netdevinventory.StateFresh, ObservedAt: swObserved},
	}
	if !reflect.DeepEqual(got.Endpoints, want) {
		t.Fatalf("endpoints = %+v\nwant %+v", got.Endpoints, want)
	}
	for _, e := range got.Endpoints {
		if e.Tier != "switch" || e.Source != "cbs-mac-table" {
			t.Fatalf("endpoint %+v not labelled tier switch / cbs-mac-table", e)
		}
	}
}

func TestSwitchEndpointsExcludeUplinkAndLAGPorts(t *testing.T) {
	entries := []netdevcontract.MACEntry{
		swMAC(10, "aa:bb:cc:00:00:01", "gi1/0/3"),
		swMAC(10, "aa:bb:cc:00:00:02", "Po1"),
		swMAC(10, "aa:bb:cc:00:00:03", "port-channel2"),
	}
	for i := range ipam.UplinkMACThreshold + 1 {
		entries = append(entries, swMAC(10, fmt.Sprintf("02:00:00:00:00:%02x", i), "gi1/0/24"))
	}
	got, err := SwitchEndpoints(context.Background(), &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1", entries...)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].Port != "gi1/0/3" {
		t.Fatalf("endpoints = %+v, want only gi1/0/3", got.Endpoints)
	}
}

func TestSwitchEndpointsKeepPortAtThreshold(t *testing.T) {
	var entries []netdevcontract.MACEntry
	for i := range ipam.UplinkMACThreshold {
		entries = append(entries, swMAC(10, fmt.Sprintf("02:00:00:00:00:%02x", i), "gi1/0/5"))
	}
	got, err := SwitchEndpoints(context.Background(), &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1", entries...)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != ipam.UplinkMACThreshold {
		t.Fatalf("endpoints = %d, want %d", len(got.Endpoints), ipam.UplinkMACThreshold)
	}
}

func TestSwitchEndpointsLLDPLinksSourceLabelled(t *testing.T) {
	sw := &fakeSwitchData{lldp: []LLDPTable{{
		DeviceID: "cbs1", State: netdevinventory.StatePartial, ObservedAt: swObserved,
		Neighbors: netdevinventory.LLDPRows{{
			LocalPort: "gi1/0/24", ChassisID: "aa:bb:cc:dd:ee:ff", PortID: "gi1/0/1",
			SystemName: "core-switch", ManagementAddress: "10.0.0.2",
			Capabilities: []netdevcontract.LLDPCapability{netdevcontract.CapBridge},
		}},
	}}}
	got, err := SwitchEndpoints(context.Background(), sw, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []SwitchLink{{
		DeviceID: "cbs1", LocalPort: "gi1/0/24",
		RemoteChassisID: "aa:bb:cc:dd:ee:ff", RemotePortID: "gi1/0/1", RemoteSystemName: "core-switch",
		Source: SourceLLDP, State: netdevinventory.StatePartial, ObservedAt: swObserved,
	}}
	if !reflect.DeepEqual(got.Links, want) {
		t.Fatalf("links = %+v\nwant %+v", got.Links, want)
	}
	if got.Links[0].Source != "lldp" {
		t.Fatalf("source = %q, want lldp", got.Links[0].Source)
	}
	if len(got.Endpoints) != 0 {
		t.Fatalf("LLDP produced endpoints: %+v", got.Endpoints)
	}
}

func TestSwitchEndpointsLinkOnlyFromConfirmedMapping(t *testing.T) {
	sw := &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1",
		swMAC(10, "aa:bb:cc:00:00:01", "gi1/0/3"), // confirmed link
		swMAC(10, "aa:bb:cc:00:00:02", "gi1/0/4"), // known endpoint, no link
		swMAC(10, "aa:bb:cc:00:00:03", "gi1/0/5"), // unknown MAC
	)}}
	links := &fakeLinks{byMAC: map[string]trafficstore.Endpoint{
		"aa:bb:cc:00:00:01": {ID: "ep-1", MAC: "aa:bb:cc:00:00:01", IPAMAssetID: "nas", HostID: "host-a"},
		"aa:bb:cc:00:00:02": {ID: "ep-2", MAC: "aa:bb:cc:00:00:02", Hostname: "lies", Owner: ""},
	}}
	got, err := SwitchEndpoints(context.Background(), sw, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 3 {
		t.Fatalf("endpoints = %+v", got.Endpoints)
	}
	e1, e2, e3 := got.Endpoints[0], got.Endpoints[1], got.Endpoints[2]
	if e1.EndpointID != "ep-1" || e1.IPAMAssetID != "nas" || e1.HostID != "host-a" {
		t.Fatalf("confirmed endpoint = %+v", e1)
	}
	if e2.EndpointID != "ep-2" || e2.IPAMAssetID != "" || e2.HostID != "" {
		t.Fatalf("unlinked endpoint = %+v", e2)
	}
	if e3.EndpointID != "" || e3.IPAMAssetID != "" || e3.HostID != "" {
		t.Fatalf("unknown endpoint = %+v", e3)
	}
}

func TestSwitchEndpointsNeverLinkLLDPNames(t *testing.T) {
	// An LLDP neighbor naming itself after a managed host is shown with
	// its source only; nothing is looked up or linked for it.
	sw := &fakeSwitchData{lldp: []LLDPTable{{DeviceID: "cbs1", State: netdevinventory.StateFresh, ObservedAt: swObserved,
		Neighbors: netdevinventory.LLDPRows{{LocalPort: "gi1/0/7", ChassisID: "aa:bb:cc:00:00:01", PortID: "eth0", SystemName: "host-a"}}}}}
	links := &fakeLinks{byMAC: map[string]trafficstore.Endpoint{
		"aa:bb:cc:00:00:01": {ID: "ep-1", IPAMAssetID: "nas", HostID: "host-a"},
	}}
	got, err := SwitchEndpoints(context.Background(), sw, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(links.called) != 0 {
		t.Fatalf("LLDP data was looked up: %v", links.called)
	}
	if len(got.Links) != 1 || got.Links[0].Source != SourceLLDP {
		t.Fatalf("links = %+v", got.Links)
	}
}

func TestSwitchEndpointsReadErrors(t *testing.T) {
	boom := errors.New("boom")
	ctx := context.Background()
	if _, err := SwitchEndpoints(ctx, nil, nil); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := SwitchEndpoints(ctx, &fakeSwitchData{macErr: boom}, nil); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if _, err := SwitchEndpoints(ctx, &fakeSwitchData{lldpErr: boom}, nil); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	sw := &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1", swMAC(10, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	if _, err := SwitchEndpoints(ctx, sw, &fakeLinks{err: boom}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestSwitchEndpointsWriteNothing(t *testing.T) {
	ctx := context.Background()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ts := trafficstore.New(db)
	im := ipam.New(db, nil)
	if err := im.SaveAsset(ctx, ipam.Asset{ID: "nas", Name: "nas", Kind: ipam.KindNAS}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := ts.UpsertEndpoint(ctx, trafficstore.Endpoint{
		MAC: "aa:bb:cc:00:00:01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.10.5")},
		LastSeen: now, Tier: flowagg.TierSocket, Reporter: "host-b",
	}, trafficstore.Identity{}); err != nil {
		t.Fatal(err)
	}
	countEP, _ := ts.CountEndpoints(ctx)
	assets, _ := im.Assets(ctx)
	known, knownOK, err := ts.LookupEndpoint(ctx, "aa:bb:cc:00:00:01", netip.Addr{})
	if err != nil || !knownOK {
		t.Fatalf("seed endpoint: ok=%v err=%v", knownOK, err)
	}

	// newSwitchData builds the input afresh, so the copy compared below
	// shares no slice backing array with the one SwitchEndpoints reads.
	newSwitchData := func() *fakeSwitchData {
		return &fakeSwitchData{
			macs: []ipam.MACTable{swTable("cbs1",
				swMAC(10, "AA:BB:CC:00:00:01", "gi1/0/3"),
				swMAC(10, "aa:bb:cc:00:00:09", "gi1/0/4"))},
			lldp: []LLDPTable{{DeviceID: "cbs1", Neighbors: netdevinventory.LLDPRows{{LocalPort: "gi1/0/3", ChassisID: "x", PortID: "y", SystemName: "nas"}}}},
		}
	}
	sw, before := newSwitchData(), newSwitchData()
	got, err := SwitchEndpoints(ctx, sw, ts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 2 || got.Endpoints[0].EndpointID == "" || got.Endpoints[0].IPAMAssetID != "" {
		t.Fatalf("endpoints = %+v, want the known endpoint unlinked", got.Endpoints)
	}
	countEP2, _ := ts.CountEndpoints(ctx)
	assets2, _ := im.Assets(ctx)
	if countEP != countEP2 {
		t.Fatalf("endpoints %d -> %d: SwitchEndpoints wrote the traffic store", countEP, countEP2)
	}
	if !reflect.DeepEqual(assets, assets2) {
		t.Fatal("SwitchEndpoints changed IPAM assets")
	}
	known2, knownOK2, err := ts.LookupEndpoint(ctx, "aa:bb:cc:00:00:01", netip.Addr{})
	if err != nil || !knownOK2 || !reflect.DeepEqual(known, known2) {
		t.Fatalf("endpoint record changed: %+v -> %+v (ok=%v err=%v)", known, known2, knownOK2, err)
	}
	if known2.IPAMAssetID != "" || known2.HostID != "" {
		t.Fatalf("endpoint links written: %+v", known2)
	}
	if _, ok, err := ts.LookupEndpoint(ctx, "aa:bb:cc:00:00:09", netip.Addr{}); err != nil || ok {
		t.Fatalf("unknown MAC got a traffic store record: ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(before, sw) {
		t.Fatal("SwitchEndpoints changed the switch data")
	}
}

func TestSwitchEndpointsLookUpEachMACOnce(t *testing.T) {
	// Three switches see the same five MACs on edge ports, two of them in
	// two VLANs: five lookups, not twenty-one.
	var tables []ipam.MACTable
	for d := range 3 {
		var entries []netdevcontract.MACEntry
		for i := range 5 {
			entries = append(entries, swMAC(10, fmt.Sprintf("02:00:00:00:00:%02x", i), fmt.Sprintf("gi1/0/%d", i)))
		}
		entries = append(entries, swMAC(20, "02:00:00:00:00:00", "gi1/0/0"), swMAC(20, "02:00:00:00:00:01", "gi1/0/1"))
		tables = append(tables, swTable(fmt.Sprintf("cbs%d", d), entries...))
	}
	links := &fakeLinks{byMAC: map[string]trafficstore.Endpoint{"02:00:00:00:00:00": {ID: "ep-0", IPAMAssetID: "nas"}}}
	got, err := SwitchEndpoints(context.Background(), &fakeSwitchData{macs: tables}, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 21 {
		t.Fatalf("endpoints = %d, want 21", len(got.Endpoints))
	}
	if len(links.called) != 5 {
		t.Fatalf("lookups = %d (%v), want 5", len(links.called), links.called)
	}
	if got.LinkState != netdevinventory.StateFresh {
		t.Fatalf("link state = %q, want fresh", got.LinkState)
	}
	linked := 0
	for _, e := range got.Endpoints {
		if !e.LinkLookedUp {
			t.Fatalf("endpoint %+v not looked up", e)
		}
		if e.MAC == "02:00:00:00:00:00" {
			if e.EndpointID != "ep-0" || e.IPAMAssetID != "nas" {
				t.Fatalf("endpoint %+v missing its link", e)
			}
			linked++
		}
	}
	if linked != 6 {
		t.Fatalf("linked endpoints = %d, want 6 (3 switches x 2 VLANs)", linked)
	}
}

func TestSwitchEndpointsLookupCapMarksPartial(t *testing.T) {
	// Four switches each carry the same MaxSwitchEndpointLookups+100
	// distinct MACs on edge ports (UplinkMACThreshold per port).
	n := MaxSwitchEndpointLookups + 100
	var entries []netdevcontract.MACEntry
	for i := range n {
		entries = append(entries, swMAC(10, fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256),
			fmt.Sprintf("gi1/0/%d", i/ipam.UplinkMACThreshold)))
	}
	var tables []ipam.MACTable
	for d := range 4 {
		tables = append(tables, swTable(fmt.Sprintf("cbs%d", d), entries...))
	}
	links := &fakeLinks{}
	got, err := SwitchEndpoints(context.Background(), &fakeSwitchData{macs: tables}, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 4*n {
		t.Fatalf("endpoints = %d, want %d", len(got.Endpoints), 4*n)
	}
	if len(links.called) != MaxSwitchEndpointLookups {
		t.Fatalf("lookups = %d, want the cap %d", len(links.called), MaxSwitchEndpointLookups)
	}
	seen := map[string]bool{}
	for _, m := range links.called {
		if seen[m] {
			t.Fatalf("MAC %s looked up twice", m)
		}
		seen[m] = true
	}
	if got.LinkState != netdevinventory.StatePartial {
		t.Fatalf("link state = %q, want partial", got.LinkState)
	}
	notLooked := 0
	for _, e := range got.Endpoints {
		if e.LinkLookedUp != seen[e.MAC] {
			t.Fatalf("endpoint %+v: LinkLookedUp %v, looked up %v", e, e.LinkLookedUp, seen[e.MAC])
		}
		if !e.LinkLookedUp {
			notLooked++
		}
	}
	if notLooked != 4*100 {
		t.Fatalf("endpoints without lookup = %d, want %d", notLooked, 4*100)
	}
}

func TestSwitchEndpointsNoLinkStateWithoutLinks(t *testing.T) {
	sw := &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1", swMAC(10, "aa:bb:cc:00:00:01", "gi1/0/3"))}}
	got, err := SwitchEndpoints(context.Background(), sw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.LinkState != "" || got.Endpoints[0].LinkLookedUp {
		t.Fatalf("map = %+v, want no lookup state", got)
	}
}

func TestSwitchEndpointsIgnoreStaticAndOtherEntries(t *testing.T) {
	static := swMAC(10, "aa:bb:cc:00:00:01", "gi1/0/3")
	static.Type = netdevcontract.MACStatic
	other := swMAC(10, "aa:bb:cc:00:00:02", "gi1/0/4")
	other.Type = netdevcontract.MACOther
	sw := &fakeSwitchData{macs: []ipam.MACTable{swTable("cbs1", static, other, swMAC(10, "aa:bb:cc:00:00:03", "gi1/0/5"))}}
	links := &fakeLinks{}
	got, err := SwitchEndpoints(context.Background(), sw, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Endpoints) != 1 || got.Endpoints[0].MAC != "aa:bb:cc:00:00:03" {
		t.Fatalf("endpoints = %+v, want only the dynamic entry", got.Endpoints)
	}
	if !reflect.DeepEqual(links.called, []string{"aa:bb:cc:00:00:03"}) {
		t.Fatalf("lookups = %v, want only the dynamic MAC", links.called)
	}
}
