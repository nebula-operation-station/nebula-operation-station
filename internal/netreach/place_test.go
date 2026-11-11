// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"net/netip"
	"testing"
)

func mustPlacer(t *testing.T, s *Snapshot) *Placer {
	t.Helper()
	p, err := NewPlacer(s)
	if err != nil {
		t.Fatalf("NewPlacer: %v", err)
	}
	return p
}

func TestPlaceAddress(t *testing.T) {
	p := mustPlacer(t, labSnapshot())
	tests := []struct {
		name     string
		addr     string
		zone     string
		subnet   string // expected SubnetID; "-" for no segment
		segment  string // expected segment prefix when no subnet ID
		reason   string // expected reason when unknown
		viaRoute bool
	}{
		{name: "ipam subnet on interface", addr: "10.0.1.5", zone: "lan", subnet: "lan-a"},
		{name: "longest prefix ipam over interface", addr: "10.0.2.7", zone: "lan", subnet: "lan-b"},
		{name: "interface network without ipam", addr: "10.0.77.1", zone: "lan", segment: "10.0.0.0/16"},
		{name: "subinterface subnet", addr: "10.20.0.10", zone: "dmz", subnet: "dmz"},
		{name: "ipv6 subnet", addr: "2001:db8:20::10", zone: "dmz", subnet: "dmz6"},
		{name: "ipv6 interface network", addr: "fd00:10::1", zone: "lan", segment: "fd00:10::/64"},
		{name: "ipv4-mapped query is unmapped", addr: "::ffff:10.0.1.5", zone: "lan", subnet: "lan-a"},
		{name: "public via default route", addr: "8.8.8.8", zone: "wan", subnet: "-", viaRoute: true},
		{name: "public ipv6 via default route and interface zone", addr: "2a00:1450::1", zone: "wan", subnet: "-", viaRoute: true},
		{name: "cgnat via specific route", addr: "100.100.1.1", zone: "vpn", subnet: "-", viaRoute: true},
		{name: "subnet not on firewall interface", addr: "172.30.0.5", subnet: "lab-behind-host", reason: ReasonSubnetNoInterface},
		{name: "rfc1918 outside subnets never via default", addr: "192.168.50.1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "rfc1918 10/8 outside subnets", addr: "10.99.0.1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "ula outside subnets", addr: "fd12::1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "link-local v4", addr: "169.254.1.1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "link-local v6", addr: "fe80::1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "loopback", addr: "127.0.0.1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "multicast", addr: "239.1.1.1", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "unspecified v6", addr: "::", subnet: "-", reason: ReasonPrivateOutsideSubnets},
		{name: "zoned address", addr: "fe80::1%eth0", subnet: "-", reason: ReasonInvalidAddress},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Place(addr(tc.addr))
			if got.Zone != tc.zone {
				t.Errorf("zone = %q, want %q (reason %q)", got.Zone, tc.zone, got.Reason)
			}
			if got.Unknown != (tc.reason != "") || got.Reason != tc.reason {
				t.Errorf("unknown=%v reason=%q, want reason %q", got.Unknown, got.Reason, tc.reason)
			}
			switch {
			case tc.subnet == "-":
				if got.Segment != nil {
					t.Errorf("segment = %+v, want none", got.Segment)
				}
			case tc.subnet != "":
				if got.Segment == nil || got.Segment.SubnetID != tc.subnet {
					t.Errorf("segment = %+v, want subnet %s", got.Segment, tc.subnet)
				}
			case tc.segment != "":
				if got.Segment == nil || got.Segment.Prefix != pfx(tc.segment) || got.Segment.SubnetID != "" {
					t.Errorf("segment = %+v, want %s", got.Segment, tc.segment)
				}
			}
			if (got.Route != nil) != tc.viaRoute {
				t.Errorf("route = %+v, want via route %v", got.Route, tc.viaRoute)
			}
		})
	}
}

// TestPlaceSpecialRangeBySpecificRoute: a private range outside every
// subnet is placed by a specific route the data proves.
func TestPlaceSpecialRangeBySpecificRoute(t *testing.T) {
	s := labSnapshot()
	s.Routes = append(s.Routes, Route{Prefix: pfx("192.168.50.0/24"), Zone: "vpn"})
	p := mustPlacer(t, s)
	got := p.Place(addr("192.168.50.1"))
	if got.Unknown || got.Zone != "vpn" || got.Route == nil {
		t.Fatalf("got %+v, want zone vpn via route", got)
	}
}

func TestPlaceDocumentationRangeFollowsSpecificRoute(t *testing.T) {
	// 198.51.100.0/24 is special (documentation) and the fixture has a
	// specific route for it: placed in vpn, the default route is not used.
	p := mustPlacer(t, labSnapshot())
	got := p.Place(addr("198.51.100.7"))
	if got.Unknown || got.Zone != "vpn" {
		t.Fatalf("got %+v, want zone vpn", got)
	}
}

func TestPlacePublicWithoutRouteIsUnknown(t *testing.T) {
	s := labSnapshot()
	s.Routes = nil
	got := mustPlacer(t, s).Place(addr("8.8.8.8"))
	if !got.Unknown || got.Reason != ReasonNoRoute || got.Zone != "" {
		t.Fatalf("got %+v, want unknown %q", got, ReasonNoRoute)
	}
}

func TestPlaceAmbiguities(t *testing.T) {
	tests := []struct {
		name   string
		mod    func(*Snapshot)
		addr   string
		reason string
	}{
		{
			name:   "two ipam subnets same prefix",
			mod:    func(s *Snapshot) { s.Subnets = append(s.Subnets, Subnet{ID: "lan-a-dup", Prefix: pfx("10.0.1.0/24")}) },
			addr:   "10.0.1.5",
			reason: ReasonSubnetAmbiguous,
		},
		{
			name: "two interfaces own subnet",
			mod: func(s *Snapshot) {
				s.Interfaces = append(s.Interfaces, Interface{Name: "ethernet1/4", Zone: "dmz", Prefixes: []netip.Prefix{pfx("10.0.0.0/16")}})
			},
			addr:   "10.0.1.5",
			reason: ReasonInterfaceAmbiguous,
		},
		{
			name: "default routes to different zones",
			mod: func(s *Snapshot) {
				s.Routes = append(s.Routes, Route{Prefix: pfx("0.0.0.0/0"), Zone: "vpn"})
			},
			addr:   "8.8.8.8",
			reason: ReasonRouteAmbiguous,
		},
		{
			name: "route zone contradicts interface zone",
			mod: func(s *Snapshot) {
				s.Routes = []Route{{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "lan"}}
			},
			addr:   "8.8.8.8",
			reason: ReasonRouteAmbiguous,
		},
		{
			name:   "route without zone",
			mod:    func(s *Snapshot) { s.Routes = []Route{{Prefix: pfx("0.0.0.0/0"), Interface: "nope"}} },
			addr:   "8.8.8.8",
			reason: ReasonInterfaceNoZone,
		},
		{
			name: "interface without zone",
			mod: func(s *Snapshot) {
				s.Interfaces = append(s.Interfaces, Interface{Name: "ethernet1/5", Prefixes: []netip.Prefix{pfx("10.50.0.0/24")}})
			},
			addr:   "10.50.0.1",
			reason: ReasonInterfaceNoZone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s)
			got := mustPlacer(t, s).Place(addr(tc.addr))
			if !got.Unknown || got.Reason != tc.reason || got.Zone != "" {
				t.Fatalf("got %+v, want unknown %q", got, tc.reason)
			}
		})
	}
}

func TestPlaceUnfreshInputIsUnknown(t *testing.T) {
	for _, k := range []InputKind{InputInterfaces, InputIPAM} {
		for _, st := range []InputState{InputMissing, InputStale, InputIncomplete} {
			s := labSnapshot()
			s.Inputs[k] = Input{State: st}
			got := mustPlacer(t, s).Place(addr("10.0.1.5"))
			if !got.Unknown || got.Zone != "" {
				t.Errorf("%s %s: got %+v, want unknown", k, st, got)
			}
		}
	}
	// Routes matter only for placement by route.
	s := labSnapshot()
	delete(s.Inputs, InputRoutes)
	p := mustPlacer(t, s)
	if got := p.Place(addr("10.0.1.5")); got.Unknown {
		t.Errorf("subnet placement with missing routes: %+v", got)
	}
	if got := p.Place(addr("8.8.8.8")); !got.Unknown || got.Reason != "input routes missing" {
		t.Errorf("route placement with missing routes: %+v", got)
	}
}

func TestCrossingTest(t *testing.T) {
	p := mustPlacer(t, labSnapshot())
	tests := []struct {
		name     string
		src, dst string
		want     bool
		reason   string
	}{
		{"same ipam subnet", "10.0.1.5", "10.0.1.6", true, ReasonSameSegment},
		{"same vlan different subnet", "10.0.2.5", "10.0.3.5", true, ReasonSameVLAN},
		{"same subnet not on firewall", "172.30.0.5", "172.30.0.6", true, ReasonSameSegment},
		{"different subnets", "10.0.1.5", "10.20.0.10", false, ""},
		{"subnet vs interface network", "10.0.1.5", "10.0.77.1", false, ""},
		{"source without segment", "8.8.8.8", "10.0.1.5", false, ""},
		{"both private outside subnets", "192.168.50.1", "192.168.50.2", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CrossingTest(p.Place(addr(tc.src)), p.Place(addr(tc.dst)))
			if got.NotFiltered != tc.want || got.Reason != tc.reason {
				t.Fatalf("got %+v, want notFiltered=%v %q", got, tc.want, tc.reason)
			}
		})
	}
}

// TestCrossingVLANNeedsSameOwningInterface: equal VLAN tags give
// not_filtered only when the same firewall interface owns both segments
// or no firewall interface owns either. Tag 20 on ethernet1/2.20 (dmz)
// and on ethernet1/3.20 (mgmt) are two segments with a firewall
// interface between them.
func TestCrossingVLANNeedsSameOwningInterface(t *testing.T) {
	s := labSnapshot()
	s.Interfaces = append(s.Interfaces,
		Interface{Name: "ethernet1/3.20", Zone: "mgmt", VLAN: Collected(uint16(20)), Prefixes: []netip.Prefix{pfx("10.30.0.0/24")}},
		Interface{Name: "ethernet1/6", Zone: "lan", Prefixes: []netip.Prefix{pfx("10.60.0.0/24")}},
		Interface{Name: "ethernet1/7", Zone: "lan", Prefixes: []netip.Prefix{pfx("10.60.0.0/24")}},
	)
	s.Subnets = append(s.Subnets,
		Subnet{ID: "off-fw-a", Prefix: pfx("172.31.1.0/24"), VLAN: Collected(uint16(40))},
		Subnet{ID: "off-fw-b", Prefix: pfx("172.31.2.0/24"), VLAN: Collected(uint16(40))},
		Subnet{ID: "on-fw-40", Prefix: pfx("10.0.40.0/24"), VLAN: Collected(uint16(40))},
		Subnet{ID: "amb-a", Prefix: pfx("10.60.0.0/25"), VLAN: Collected(uint16(60))},
		Subnet{ID: "amb-b", Prefix: pfx("10.60.0.128/25"), VLAN: Collected(uint16(60))},
	)
	p := mustPlacer(t, s)
	tests := []struct {
		name     string
		src, dst string
		want     bool
		reason   string
	}{
		{"same tag on different subinterfaces", "10.20.0.10", "10.30.0.5", false, ""},
		{"same tag on different subinterfaces reversed", "10.30.0.5", "10.20.0.10", false, ""},
		{"same tag same owning interface", "10.0.2.5", "10.0.3.5", true, ReasonSameVLAN},
		{"same tag no firewall interface owns either", "172.31.1.5", "172.31.2.5", true, ReasonSameVLAN},
		{"same tag one owned one not", "10.0.40.5", "172.31.1.5", false, ""},
		{"same tag owner ambiguous", "10.60.0.5", "10.60.0.200", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CrossingTest(p.Place(addr(tc.src)), p.Place(addr(tc.dst)))
			if got.NotFiltered != tc.want || got.Reason != tc.reason {
				t.Fatalf("got %+v, want notFiltered=%v %q", got, tc.want, tc.reason)
			}
		})
	}
	// A segment without owner information never shares a VLAN.
	a := Placement{Segment: &Segment{Prefix: pfx("10.1.0.0/24"), VLAN: Collected(uint16(5))}}
	b := Placement{Segment: &Segment{Prefix: pfx("10.2.0.0/24"), VLAN: Collected(uint16(5))}}
	if got := CrossingTest(a, b); got.NotFiltered {
		t.Fatalf("segments without owner: %+v", got)
	}
}

// TestSameL2NotFilteredInFlatNetwork is the NS-05 flat-network fixture:
// one subnet, no firewall interface owns it, no IPAM VLAN.
func TestSameL2NotFilteredInFlatNetwork(t *testing.T) {
	s := &Snapshot{
		Inputs:  allFresh(),
		Vsys:    1,
		Subnets: []Subnet{{ID: "flat", Prefix: pfx("192.168.1.0/24")}},
	}
	p := mustPlacer(t, s)
	a, b := p.Place(addr("192.168.1.10")), p.Place(addr("192.168.1.20"))
	if !a.Unknown || a.Reason != ReasonSubnetNoInterface {
		t.Fatalf("placement %+v, want unknown zone", a)
	}
	if got := CrossingTest(a, b); !got.NotFiltered {
		t.Fatalf("crossing %+v, want not_filtered", got)
	}
}

func TestIsSpecialAddress(t *testing.T) {
	special := []string{
		"0.0.0.0", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.0.1",
		"172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.168.0.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fdff::1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1",
		"2002::1", "3fff::1", "64:ff9b::1", "::ffff:10.0.0.1",
		// IANA special-purpose registries (AS112, AMT, SRv6 SIDs)
		"192.31.196.1", "192.52.193.1", "192.175.48.1", "2620:4f:8000::1", "5f00::1",
		"192.0.0.9", "192.0.0.170", "100::1", "64:ff9b:1::1", "2001:1::1", "2001:20::1",
	}
	public := []string{
		"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.0", "172.32.0.1", "2a00:1450::1", "2606:4700::1111", "::ffff:8.8.8.8",
		"192.31.195.255", "192.31.197.0", "192.52.192.255", "192.175.49.0", "2620:4f:8001::1",
	}
	for _, s := range special {
		if !IsSpecialAddress(addr(s)) {
			t.Errorf("%s: not special", s)
		}
	}
	for _, s := range public {
		if IsSpecialAddress(addr(s)) {
			t.Errorf("%s: special", s)
		}
	}
	if !IsSpecialAddress(netip.Addr{}) {
		t.Error("invalid address not special")
	}
}

// FuzzPlace checks that placement never panics and never claims a zone
// it cannot prove: a placed address lies in its segment or route, a
// special address is never placed through a default route, and an
// unknown placement carries a reason and no zone.
func FuzzPlace(f *testing.F) {
	for _, s := range []string{"10.0.1.5", "8.8.8.8", "fd12::1", "172.30.0.5", "::ffff:10.0.1.5", "192.168.50.1", "fe80::1%x"} {
		f.Add(s)
	}
	p, err := NewPlacer(labSnapshot())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		got := p.Place(a)
		if got.Unknown {
			if got.Reason == "" || got.Zone != "" || got.Route != nil {
				t.Fatalf("unknown placement %+v", got)
			}
			return
		}
		if got.Zone == "" {
			t.Fatalf("placed without zone: %+v", got)
		}
		u := a.Unmap()
		switch {
		case got.Segment != nil:
			if !got.Segment.Prefix.Contains(u) {
				t.Fatalf("segment %v does not contain %v", got.Segment.Prefix, u)
			}
		case got.Route != nil:
			if !got.Route.Prefix.Contains(u) {
				t.Fatalf("route %v does not contain %v", got.Route.Prefix, u)
			}
			if IsSpecialAddress(u) && got.Route.Prefix.Bits() == 0 {
				t.Fatalf("special %v placed via default route", u)
			}
		default:
			t.Fatalf("placed without segment or route: %+v", got)
		}
	})
}
