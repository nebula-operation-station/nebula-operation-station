// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func newStore(t *testing.T, hosts HostAddresses) *Store {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db, hosts)
	s.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return s
}

func lan(t *testing.T, s *Store) {
	t.Helper()
	n := Network{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("192.168.10.0/24"), VLAN: 10, Gateway: addr("192.168.10.1"),
		Pools: []Pool{{Name: "servers", First: addr("192.168.10.10"), Last: addr("192.168.10.19")}}}
	if err := s.SaveNetwork(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}

func statusOf(t *testing.T, s *Store, network string) map[string]AddressView {
	t.Helper()
	views, _, err := s.Status(context.Background(), network)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]AddressView{}
	for _, v := range views {
		out[v.Address.String()] = v
	}
	return out
}

func TestStatusRules(t *testing.T) {
	ctx := context.Background()
	hosts := func(context.Context) (map[netip.Addr][]string, error) {
		return map[netip.Addr][]string{addr("192.168.10.20"): {"web1"}, addr("192.168.10.21"): {"nas1"}}, nil
	}
	s := newStore(t, hosts)
	lan(t, s)
	for _, a := range []Asset{
		{ID: "printer", Name: "Printer", Kind: KindPrinter, MAC: "AA-BB-CC-DD-EE-01", Addresses: []netip.Addr{addr("192.168.10.30")}},
		{ID: "cam1", Name: "Cam", Kind: KindIoT, Addresses: []netip.Addr{addr("192.168.10.31")}},
		{ID: "cam2", Name: "Cam 2", Kind: KindIoT, Addresses: []netip.Addr{addr("192.168.10.31")}},
		{ID: "nas", Name: "NAS", Kind: KindNAS, HostID: "nas1", Addresses: []netip.Addr{addr("192.168.10.21")}},
		{ID: "other", Name: "Other", Kind: KindUnknown, Addresses: []netip.Addr{addr("192.168.10.20")}},
	} {
		if err := s.SaveAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetEntry(ctx, "admin", addr("192.168.10.40"), EntryReserved, "new switch"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEntry(ctx, "admin", addr("192.168.10.41"), EntryExcluded, "broken port"); err != nil {
		t.Fatal(err)
	}
	now := s.now().Unix()
	for _, d := range []struct {
		ad, mac string
		at      int64
	}{{"192.168.10.30", "aa:bb:cc:dd:ee:02", now}, {"192.168.10.50", "", now}, {"192.168.10.40", "", now}, {"192.168.10.60", "", now - 40*86400}} {
		if _, err := s.db.Exec(`INSERT INTO discovered_addresses (address, mac, hostname, seen_at) VALUES (?, ?, '', ?)`, d.ad, d.mac, d.at); err != nil {
			t.Fatal(err)
		}
	}
	st := statusOf(t, s, "lan")
	if len(st) != 256 {
		t.Fatalf("%d addresses", len(st))
	}
	want := map[string]Status{
		"192.168.10.0":   Excluded,   // network address
		"192.168.10.255": Excluded,   // broadcast
		"192.168.10.1":   Assigned,   // gateway
		"192.168.10.2":   Free,       //
		"192.168.10.20":  Conflict,   // host web1 and asset "other"
		"192.168.10.21":  Assigned,   // asset nas is host nas1: one owner
		"192.168.10.30":  Conflict,   // discovery saw another MAC
		"192.168.10.31":  Conflict,   // two assets
		"192.168.10.40":  Conflict,   // reserved but a device answered
		"192.168.10.41":  Excluded,   // exclusion
		"192.168.10.50":  Discovered, // seen, unclaimed
		"192.168.10.60":  Discovered, // seen long ago
	}
	for ad, w := range want {
		if st[ad].Status != w {
			t.Errorf("%s: %s (%s), want %s", ad, st[ad].Status, st[ad].Why, w)
		}
	}
	// The suggestion skips everything claimed and recent sightings, but
	// takes an address last seen more than 30 days ago.
	sug, err := s.Suggest(ctx, "lan", "", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(sug) != 5 || sug[0] != addr("192.168.10.2") {
		t.Fatalf("suggest %v", sug)
	}
	sug, err = s.Suggest(ctx, "lan", "servers", 20)
	if err != nil || len(sug) != 10 || sug[0] != addr("192.168.10.10") || sug[9] != addr("192.168.10.19") {
		t.Fatalf("pool suggest %v %v", sug, err)
	}
	if _, err := s.Suggest(ctx, "lan", "nope", 5); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.SetEntry(ctx, "admin", addr("192.168.10.40"), EntryReserved, "x"); err != nil {
		t.Fatal(err)
	}
	// An old sighting is suggestable.
	if err := s.SetEntry(ctx, "admin", addr("192.168.10.2"), EntryExcluded, ""); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Suggest(ctx, "lan", "", 20)
	found := false
	for _, a := range all {
		if a == addr("192.168.10.60") {
			found = true
		}
		if a == addr("192.168.10.50") || a == addr("192.168.10.2") || a == addr("192.168.10.1") {
			t.Fatalf("suggested %s", a)
		}
	}
	if !found && len(all) == 20 {
		// 60 is beyond the first 20 free addresses; ask from a pool around it.
		n, _ := s.Network(ctx, "lan")
		n.Pools = append(n.Pools, Pool{Name: "high", First: addr("192.168.10.60"), Last: addr("192.168.10.61")})
		if err := s.SaveNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
		high, _ := s.Suggest(ctx, "lan", "high", 5)
		if len(high) != 2 || high[0] != addr("192.168.10.60") {
			t.Fatalf("high %v", high)
		}
	}
	if err := s.ClearEntry(ctx, addr("192.168.10.2")); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearEntry(ctx, addr("192.168.10.2")); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestLargeNetworksListOnlyClaims(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	if err := s.SaveNetwork(ctx, Network{ID: "big", Name: "Big", Prefix: netip.MustParsePrefix("10.0.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNetwork(ctx, Network{ID: "v6", Name: "V6", Prefix: netip.MustParsePrefix("2001:db8::/64")}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAsset(ctx, Asset{ID: "a", Name: "A", Kind: KindServer, Addresses: []netip.Addr{addr("10.0.5.5"), addr("2001:db8::5")}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"big", "v6"} {
		views, listed, err := s.Status(ctx, id)
		if err != nil || listed || len(views) != 1 || views[0].Status != Assigned {
			t.Fatalf("%s: %v %v %v", id, views, listed, err)
		}
	}
	sug, err := s.Suggest(ctx, "v6", "", 3)
	if err != nil || len(sug) != 3 || sug[0] != addr("2001:db8::") {
		t.Fatalf("%v %v", sug, err)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	lan(t, s)
	bad := []Asset{
		{ID: "Bad", Name: "x", Kind: KindServer},
		{ID: "a", Name: "", Kind: KindServer},
		{ID: "a", Name: "x\u202ey", Kind: KindServer},
		{ID: "a", Name: "x", Kind: "toaster"},
		{ID: "a", Name: "x", Kind: KindServer, MAC: "zz"},
		{ID: "a", Name: "x", Kind: KindServer, Hostname: "-bad-"},
		{ID: "a", Name: "x", Kind: KindServer, Addresses: []netip.Addr{addr("10.0.0.1"), addr("10.0.0.1")}},
		{ID: "a", Name: "x", Kind: KindServer, Addresses: []netip.Addr{addr("fe80::1%eth0")}},
	}
	for i, a := range bad {
		var ve *ValidationError
		if err := s.SaveAsset(ctx, a); !errors.As(err, &ve) {
			t.Errorf("asset %d: %v", i, err)
		}
	}
	badNets := []Network{
		{ID: "x", Name: "X", Prefix: netip.MustParsePrefix("10.0.0.0/4")},
		{ID: "x", Name: "X", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Gateway: addr("10.0.1.1")},
		{ID: "x", Name: "X", Prefix: netip.MustParsePrefix("10.0.0.0/24"), VLAN: 4095},
		{ID: "x", Name: "X", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Pools: []Pool{{Name: "p", First: addr("10.0.0.9"), Last: addr("10.0.0.1")}}},
		{ID: "x", Name: "X", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Pools: []Pool{{Name: "p", First: addr("10.0.0.1"), Last: addr("10.0.1.1")}}},
		{ID: "x", Name: "X", Prefix: netip.MustParsePrefix("192.168.10.0/24")}, // same prefix as lan
	}
	for i, n := range badNets {
		var ve *ValidationError
		if err := s.SaveNetwork(ctx, n); !errors.As(err, &ve) {
			t.Errorf("network %d: %v", i, err)
		}
	}
	// A /25 inside the /24 is fine (a subnet), and a host bits prefix is
	// masked.
	if err := s.SaveNetwork(ctx, Network{ID: "half", Name: "Half", Prefix: netip.MustParsePrefix("192.168.10.130/25")}); err != nil {
		t.Fatal(err)
	}
	n, err := s.Network(ctx, "half")
	if err != nil || n.Prefix.String() != "192.168.10.128/25" {
		t.Fatal(n.Prefix, err)
	}
	if err := s.SetEntry(ctx, "admin", addr("10.0.0.1"), "assigned", ""); err == nil {
		t.Fatal("unknown entry kind accepted")
	}
	if err := s.SetEntry(ctx, "admin", addr("10.0.0.1"), EntryReserved, "a\nb"); err == nil {
		t.Fatal("multiline note accepted")
	}
}

func TestAssetLinkAndMAC(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, nil)
	if err := s.SaveAsset(ctx, Asset{ID: "nas", Name: "NAS", Kind: KindNAS, MAC: "AA:BB:CC:DD:EE:FF"}); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkHost(ctx, "nas", "nas1"); err != nil {
		t.Fatal(err)
	}
	// Saving the asset again keeps the link.
	if err := s.SaveAsset(ctx, Asset{ID: "nas", Name: "NAS 2", Kind: KindNAS}); err != nil {
		t.Fatal(err)
	}
	a, err := s.Asset(ctx, "nas")
	if err != nil || a.HostID != "nas1" || a.Name != "NAS 2" || a.MAC != "" {
		t.Fatalf("%+v %v", a, err)
	}
	if err := s.LinkHost(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(ctx, "nas"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(ctx, "nas"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if m, ok := NormalizeMAC("AA-BB-CC-DD-EE-FF"); !ok || m != "aa:bb:cc:dd:ee:ff" {
		t.Fatal(m)
	}
}

func TestFromInventory(t *testing.T) {
	list := func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{
			{ID: "a", Endpoints: []inventory.Endpoint{{Address: "10.0.0.1"}, {Address: "10.0.0.1", Port: 2222}, {Address: "a.example.org"}}},
			{ID: "b", Endpoints: []inventory.Endpoint{{Address: "2001:db8::1"}, {Address: "fe80::1%eth0"}}},
		}, nil
	}
	m, err := FromInventory(list)(context.Background())
	if err != nil || len(m) != 2 || len(m[addr("10.0.0.1")]) != 1 || m[addr("2001:db8::1")][0] != "b" {
		t.Fatalf("%v %v", m, err)
	}
}
