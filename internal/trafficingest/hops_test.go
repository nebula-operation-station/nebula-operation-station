// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"net/netip"
	"testing"

	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
)

func mustRoutes(t *testing.T, path string) []hostnet.Route {
	t.Helper()
	tab, err := hostnet.ParseRoutes(readFixture(t, path))
	if err != nil {
		t.Fatalf("parse routes %s: %v", path, err)
	}
	return tab.Entries
}

func mustNeigh(t *testing.T, path string) []hostnet.Neighbor {
	t.Helper()
	tab, err := hostnet.ParseNeigh(readFixture(t, path))
	if err != nil {
		t.Fatalf("parse neigh %s: %v", path, err)
	}
	return tab.Entries
}

func TestHopViaDefaultGatewayWithNeighborMAC(t *testing.T) {
	h := DeriveHostNet("host-a", mustRoutes(t, "host-a/route.json"), mustNeigh(t, "host-a/neigh.json"))
	if len(h.Defaults) != 1 {
		t.Fatalf("defaults = %+v, want one", h.Defaults)
	}
	gw := h.Defaults[0]
	if gw.Addr != netip.MustParseAddr("192.168.10.1") || gw.MAC != "52:54:00:00:10:01" || gw.Dev != "eth0" || !gw.Default {
		t.Fatalf("default gateway = %+v", gw)
	}
	tests := []struct {
		dst    string
		hop    bool
		hopVia string
	}{
		{"192.168.10.20", false, ""},                   // same subnet: direct
		{"192.168.20.30", true, "192.168.10.1"},        // other subnet: default gateway
		{"1.1.1.1", true, "192.168.10.1"},              // internet: default gateway
		{"10.99.0.5", true, "192.168.10.254"},          // more specific static route
		{"192.168.10.1", false, ""},                    // the gateway itself
		{"::ffff:192.168.20.30", true, "192.168.10.1"}, // mapped form
	}
	for _, tc := range tests {
		got, ok := h.Hop(netip.MustParseAddr(tc.dst))
		if ok != tc.hop {
			t.Errorf("Hop(%s) ok = %v, want %v", tc.dst, ok, tc.hop)
			continue
		}
		if ok && got.Addr.String() != tc.hopVia {
			t.Errorf("Hop(%s) = %s, want %s", tc.dst, got.Addr, tc.hopVia)
		}
	}
}

func TestHopGatewayMACOnlyFromRouteInterface(t *testing.T) {
	routes := []hostnet.Route{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}}
	neigh := []hostnet.Neighbor{
		// Same address on another interface: not the gateway's MAC.
		{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth1", MAC: mac(t, "02:00:00:00:00:99"), State: []string{"REACHABLE"}},
	}
	h := DeriveHostNet("h", routes, neigh)
	if h.Defaults[0].MAC != "" {
		t.Fatalf("MAC from other interface used: %+v", h.Defaults[0])
	}
}

func TestHopFailedNeighborHasNoMAC(t *testing.T) {
	routes := []hostnet.Route{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}}
	for _, state := range []string{"FAILED", "INCOMPLETE"} {
		neigh := []hostnet.Neighbor{{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", MAC: mac(t, "02:00:00:00:00:01"), State: []string{state}}}
		h := DeriveHostNet("h", routes, neigh)
		if h.Defaults[0].MAC != "" {
			t.Fatalf("%s neighbor gave gateway MAC %q", state, h.Defaults[0].MAC)
		}
	}
	// Broadcast/multicast and all-zero MACs are not a gateway identity.
	for _, m := range []string{"ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:00:00:00:00:00"} {
		neigh := []hostnet.Neighbor{{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", MAC: mac(t, m), State: []string{"REACHABLE"}}}
		if got := DeriveHostNet("h", routes, neigh).Defaults[0].MAC; got != "" {
			t.Fatalf("MAC %s accepted as gateway MAC %q", m, got)
		}
	}
}

func TestHopDefaultsOrderedByFamilyAndMetric(t *testing.T) {
	routes := []hostnet.Route{
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Dev: "eth0", Metric: 1},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.2"), Dev: "eth1", Metric: 200},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", Metric: 100},
	}
	h := DeriveHostNet("h", routes, nil)
	want := []string{"10.0.0.1", "10.0.0.2", "fe80::1"}
	if len(h.Defaults) != len(want) {
		t.Fatalf("defaults = %+v", h.Defaults)
	}
	for i, w := range want {
		if h.Defaults[i].Addr.String() != w {
			t.Fatalf("defaults[%d] = %s, want %s", i, h.Defaults[i].Addr, w)
		}
	}
	if gw, ok := h.Hop(netip.MustParseAddr("8.8.8.8")); !ok || gw.Addr.String() != "10.0.0.1" {
		t.Fatalf("Hop picks %v %v, want lowest metric 10.0.0.1", gw, ok)
	}
	if gw, ok := h.Hop(netip.MustParseAddr("2001:db8::1")); !ok || gw.Addr.String() != "fe80::1" {
		t.Fatalf("IPv6 hop = %v %v", gw, ok)
	}
}

func TestHopWithoutRoutes(t *testing.T) {
	h := DeriveHostNet("h", nil, nil)
	if _, ok := h.Hop(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("hop without routes")
	}
	if _, ok := h.Hop(netip.Addr{}); ok {
		t.Fatal("hop for invalid address")
	}
}

func TestHostNetRouteBound(t *testing.T) {
	routes := make([]hostnet.Route, MaxRoutes+50)
	for i := range routes {
		routes[i] = hostnet.Route{Dst: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24), Dev: "eth0"}
	}
	if h := DeriveHostNet("h", routes, nil); len(h.routes) != MaxRoutes {
		t.Fatalf("routes kept = %d, want %d", len(h.routes), MaxRoutes)
	}
}
