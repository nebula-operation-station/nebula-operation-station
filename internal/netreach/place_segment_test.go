// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"net/netip"
	"testing"
)

// TestDifferentSubnetsOnOneFirewallInterfaceAreRouted: two IP subnets with
// the same VLAN that the same firewall L3 interface owns are routed
// through that interface. The crossing test decides nothing and both
// addresses keep their zone, so the policy (intrazone rule) is evaluated.
func TestDifferentSubnetsOnOneFirewallInterfaceAreRouted(t *testing.T) {
	p := mustPlacer(t, labSnapshot())
	a, b := p.Place(addr("10.0.2.5")), p.Place(addr("10.0.3.5"))
	for _, pl := range []Placement{a, b} {
		if pl.Unknown || pl.Zone != "lan" || pl.Interface != "ethernet1/2" || pl.Segment == nil || pl.Segment.Owner != "ethernet1/2" {
			t.Fatalf("placement %+v, want zone lan via ethernet1/2", pl)
		}
	}
	if got := CrossingTest(a, b); got.NotFiltered {
		t.Fatalf("crossing %+v, want no decision", got)
	}
	// Even with every proof set, a firewall owner rules out same VLAN.
	seg := func(p string) Placement {
		return Placement{Segment: &Segment{Prefix: pfx(p), VLAN: Collected(uint16(7)), Owner: "ethernet1/9", OwnerKnown: true, Unsplit: true, NoRoute: true}}
	}
	if got := CrossingTest(seg("10.9.1.0/24"), seg("10.9.2.0/24")); got.NotFiltered {
		t.Fatalf("hand-built segments on one firewall interface: %+v", got)
	}
}

// TestSegmentSplitByRouteOrNestedSubnet: a firewall route or an IPAM
// subnet strictly inside a segment splits it, and so does a routes input
// that is not fresh (no route inside can be ruled out). A split segment
// never gives not_filtered.
func TestSegmentSplitByRouteOrNestedSubnet(t *testing.T) {
	tests := []struct {
		name   string
		mod    func(*Snapshot)
		a, b   string
		want   bool
		reason string
	}{
		{"unowned subnet, covering default route only", func(*Snapshot) {}, "172.30.0.5", "172.30.0.6", true, ReasonSameSegment},
		{"unowned subnet, route equal to subnet", func(s *Snapshot) {
			s.Routes = append(s.Routes, Route{Prefix: pfx("172.30.0.0/24"), Interface: "ethernet1/2"})
		}, "172.30.0.5", "172.30.0.6", true, ReasonSameSegment},
		{"unowned subnet, route inside", func(s *Snapshot) {
			s.Routes = append(s.Routes, Route{Prefix: pfx("172.30.0.128/25"), Zone: "vpn"})
		}, "172.30.0.5", "172.30.0.6", false, ""},
		{"unowned subnet, host route inside", func(s *Snapshot) {
			s.Routes = append(s.Routes, Route{Prefix: pfx("172.30.0.77/32"), Interface: "tunnel.1"})
		}, "172.30.0.5", "172.30.0.6", false, ""},
		{"owned subnet, route inside", func(s *Snapshot) {
			s.Routes = append(s.Routes, Route{Prefix: pfx("10.0.1.64/26"), Interface: "tunnel.1"})
		}, "10.0.1.5", "10.0.1.6", false, ""},
		{"ipv6 subnet, route inside", func(s *Snapshot) {
			s.Routes = append(s.Routes, Route{Prefix: pfx("2001:db8:20::/96"), Interface: "tunnel.1"})
		}, "2001:db8:20::10", "2001:db8:20::1:10", false, ""},
		{"unowned container with child subnets, addresses in the gap", func(s *Snapshot) {
			s.Subnets = append(s.Subnets,
				Subnet{ID: "container", Prefix: pfx("172.28.0.0/16")},
				Subnet{ID: "child-1", Prefix: pfx("172.28.1.0/24")},
				Subnet{ID: "child-2", Prefix: pfx("172.28.2.0/24")},
			)
		}, "172.28.200.1", "172.28.201.1", false, ""},
		{"unowned container, addresses in one child", func(s *Snapshot) {
			s.Subnets = append(s.Subnets,
				Subnet{ID: "container", Prefix: pfx("172.28.0.0/16")},
				Subnet{ID: "child-1", Prefix: pfx("172.28.1.0/24")},
			)
		}, "172.28.1.5", "172.28.1.6", true, ReasonSameSegment},
		{"interface network with ipam subnets inside", func(*Snapshot) {}, "10.0.77.1", "10.0.77.2", false, ""},
		{"unowned subnet, routes missing", func(s *Snapshot) { delete(s.Inputs, InputRoutes) }, "172.30.0.5", "172.30.0.6", false, ""},
		{"owned subnet, routes stale", func(s *Snapshot) { s.Inputs[InputRoutes] = Input{State: InputStale} }, "10.0.1.5", "10.0.1.6", false, ""},
		{"owned subnet, routes fresh", func(*Snapshot) {}, "10.0.1.5", "10.0.1.6", true, ReasonSameSegment},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s)
			p := mustPlacer(t, s)
			pa, pb := p.Place(addr(tc.a)), p.Place(addr(tc.b))
			if pa.Segment == nil || pb.Segment == nil || pa.Segment.Prefix != pb.Segment.Prefix {
				t.Fatalf("fixture: placements %+v %+v do not share a prefix", pa, pb)
			}
			if pa.Segment.Unsplit != tc.want {
				t.Errorf("unsplit = %v, want %v", pa.Segment.Unsplit, tc.want)
			}
			got := CrossingTest(pa, pb)
			if got.NotFiltered != tc.want || got.Reason != tc.reason {
				t.Fatalf("got %+v, want notFiltered=%v %q", got, tc.want, tc.reason)
			}
		})
	}
}

// TestVLANConflictIsAmbiguous: an IPAM VLAN that differs from the VLAN of
// the owning firewall interface is contradictory data: the placement is
// unknown and the segment shares nothing.
func TestVLANConflictIsAmbiguous(t *testing.T) {
	tests := []struct {
		name     string
		ipamVLAN Field[uint16]
		ifVLAN   Field[uint16]
		wantVLAN Field[uint16]
		conflict bool
	}{
		{"ipam and interface agree", Collected(uint16(20)), Collected(uint16(20)), Collected(uint16(20)), false},
		{"only interface records vlan", Field[uint16]{}, Collected(uint16(20)), Collected(uint16(20)), false},
		{"only ipam records vlan", Collected(uint16(30)), Field[uint16]{}, Collected(uint16(30)), false},
		{"ipam and interface disagree", Collected(uint16(30)), Collected(uint16(20)), Field[uint16]{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			for i := range s.Subnets {
				if s.Subnets[i].ID == "dmz" {
					s.Subnets[i].VLAN = tc.ipamVLAN
				}
			}
			for i := range s.Interfaces {
				if s.Interfaces[i].Name == "ethernet1/2.20" {
					s.Interfaces[i].VLAN = tc.ifVLAN
				}
			}
			p := mustPlacer(t, s)
			a, b := p.Place(addr("10.20.0.10")), p.Place(addr("10.20.0.11"))
			if a.Segment == nil {
				t.Fatalf("placement %+v without segment", a)
			}
			if a.Segment.VLAN != tc.wantVLAN || a.Segment.VLANConflict != tc.conflict {
				t.Errorf("segment vlan %+v conflict %v, want %+v %v", a.Segment.VLAN, a.Segment.VLANConflict, tc.wantVLAN, tc.conflict)
			}
			got := CrossingTest(a, b)
			if tc.conflict {
				if !a.Unknown || a.Reason != ReasonVLANAmbiguous || a.Zone != "" {
					t.Errorf("placement %+v, want unknown %q", a, ReasonVLANAmbiguous)
				}
				if got.NotFiltered {
					t.Errorf("crossing %+v, want no decision", got)
				}
				return
			}
			if a.Unknown || a.Zone != "dmz" {
				t.Errorf("placement %+v, want zone dmz", a)
			}
			if !got.NotFiltered || got.Reason != ReasonSameSegment {
				t.Errorf("crossing %+v, want same segment", got)
			}
		})
	}
	// A conflict on an interface without zone is detected as well.
	s := labSnapshot()
	s.Interfaces = append(s.Interfaces, Interface{Name: "ethernet1/5.50", VLAN: Collected(uint16(50)), Prefixes: []netip.Prefix{pfx("10.50.0.0/24")}})
	s.Subnets = append(s.Subnets, Subnet{ID: "v51", Prefix: pfx("10.50.0.0/24"), VLAN: Collected(uint16(51))})
	got := mustPlacer(t, s).Place(addr("10.50.0.1"))
	if !got.Unknown || got.Reason != ReasonVLANAmbiguous || got.Segment == nil || !got.Segment.VLANConflict {
		t.Fatalf("placement %+v, want unknown %q", got, ReasonVLANAmbiguous)
	}
	// A hand-built conflicting segment never shares anything.
	c := Placement{Segment: &Segment{Prefix: pfx("10.1.0.0/24"), Owner: "e1", OwnerKnown: true, Unsplit: true, NoRoute: true, VLANConflict: true}}
	if got := CrossingTest(c, c); got.NotFiltered {
		t.Fatalf("conflicting segment: %+v", got)
	}
}

// TestEqualRoutesToDifferentInterfacesAreAmbiguous: equal-length routes
// into the same zone through different interfaces leave the egress
// interface open: the placement reports route ambiguity instead of an
// arbitrarily chosen interface. Duplicates of one route are not ambiguous.
func TestEqualRoutesToDifferentInterfacesAreAmbiguous(t *testing.T) {
	tests := []struct {
		name   string
		routes []Route
		iface  string
		reason string
	}{
		{"same zone, different interfaces", []Route{
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "wan"},
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/4", Zone: "wan"},
		}, "", ReasonRouteAmbiguous},
		{"same zone, interface and zone-only route", []Route{
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1"},
			{Prefix: pfx("0.0.0.0/0"), Zone: "wan"},
		}, "", ReasonRouteAmbiguous},
		{"duplicate route", []Route{
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "wan"},
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "wan"},
		}, "ethernet1/1", ""},
		{"longer route wins over ecmp default", []Route{
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/1", Zone: "wan"},
			{Prefix: pfx("0.0.0.0/0"), Interface: "ethernet1/4", Zone: "wan"},
			{Prefix: pfx("8.8.8.0/24"), Interface: "ethernet1/1"},
		}, "ethernet1/1", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			s.Interfaces = append(s.Interfaces, Interface{Name: "ethernet1/4", Zone: "wan", Prefixes: []netip.Prefix{pfx("198.18.0.0/30")}})
			s.Routes = tc.routes
			got := mustPlacer(t, s).Place(addr("8.8.8.8"))
			if tc.reason != "" {
				if !got.Unknown || got.Reason != tc.reason || got.Interface != "" || got.Zone != "" {
					t.Fatalf("got %+v, want unknown %q", got, tc.reason)
				}
				return
			}
			if got.Unknown || got.Zone != "wan" || got.Interface != tc.iface {
				t.Fatalf("got %+v, want zone wan via %s", got, tc.iface)
			}
		})
	}
}
