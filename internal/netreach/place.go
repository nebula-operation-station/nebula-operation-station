// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"fmt"
	"net/netip"
)

// Placement reasons (ADR 0012 D2 step 1). They are stable texts; callers
// may show them and tests compare them.
const (
	ReasonPrivateOutsideSubnets = "private address outside known subnets"
	ReasonSubnetNoInterface     = "subnet not on a firewall interface"
	ReasonNoRoute               = "no route to the address"
	ReasonRouteAmbiguous        = "route ambiguity"
	ReasonSubnetAmbiguous       = "subnet ambiguity"
	ReasonInterfaceAmbiguous    = "subnet on more than one firewall interface"
	ReasonInterfaceNoZone       = "firewall interface without zone"
	ReasonInvalidAddress        = "invalid address"
	ReasonSameSegment           = "same L2 segment"
	ReasonSameVLAN              = "same VLAN"
)

// Segment is the L2 segment an address lies in: an IPAM subnet (SubnetID
// set) or, without one, the connected network of a firewall interface.
// VLAN is set only when IPAM or the owning interface records it.
type Segment struct {
	Prefix   netip.Prefix
	SubnetID string
	VLAN     Field[uint16]
}

// Placement is the result of placing one address (ADR 0012 D2 step 1).
//
// Segment is non-nil when the address lies in a known segment; Zone is
// set only when the data proves the zone, through the interface that
// owns the segment (Interface) or through a route (Route). Unknown is set
// with a Reason whenever no zone is proven; a placement with a Segment but
// no zone still serves the crossing test (same segment → not_filtered).
type Placement struct {
	Addr      netip.Addr
	Segment   *Segment
	Interface string
	Route     *Route
	Zone      string
	Unknown   bool
	Reason    string
}

// Placer places addresses against the placement inputs of one snapshot.
// It is immutable and safe for concurrent use.
type Placer struct {
	interfaces []Interface
	subnets    []Subnet
	routes     []Route
	ifZone     map[string]string
	// notFresh holds, per placement input, the reason it is not fresh.
	notFresh map[InputKind]string
}

// NewPlacer checks the snapshot limits and returns a Placer. It fails
// with an error wrapping ErrLimitReached or ErrInvalidSnapshot.
func NewPlacer(s *Snapshot) (*Placer, error) {
	if err := CheckLimits(s); err != nil {
		return nil, fmt.Errorf("new placer: %w", err)
	}
	p := &Placer{
		interfaces: s.Interfaces,
		subnets:    s.Subnets,
		routes:     s.Routes,
		ifZone:     make(map[string]string, len(s.Interfaces)),
		notFresh:   map[InputKind]string{},
	}
	for _, in := range s.Interfaces {
		if _, dup := p.ifZone[in.Name]; dup {
			return nil, fmt.Errorf("new placer: %w: duplicate interface %q", ErrInvalidSnapshot, in.Name)
		}
		p.ifZone[in.Name] = in.Zone
	}
	for _, k := range []InputKind{InputInterfaces, InputIPAM, InputRoutes} {
		if st := s.Inputs[k].State; st != InputFresh {
			p.notFresh[k] = fmt.Sprintf("input %s %s", k, st)
		}
	}
	return p, nil
}

// Place maps addr to its segment and zone. It never guesses: whatever the
// data does not prove gives Unknown with a reason.
//
//   - The longest IPAM subnet or interface network containing addr is its
//     segment; the zone is that of the firewall interface whose network
//     contains the segment (longest prefix). No such interface →
//     ReasonSubnetNoInterface.
//   - An address in a private or special range outside every segment is
//     placed only by a specific, non-default route; otherwise
//     ReasonPrivateOutsideSubnets, never the default route.
//   - A public address outside every segment follows its longest-prefix
//     route, the default route included; none → ReasonNoRoute.
//   - Equal-length candidates with different results → ambiguity.
//   - Interfaces and IPAM must be fresh for any placement, routes for a
//     placement by route.
func (p *Placer) Place(addr netip.Addr) Placement {
	addr = addr.Unmap()
	pl := Placement{Addr: addr}
	if !addr.IsValid() || addr.Zone() != "" {
		return unknown(pl, ReasonInvalidAddress)
	}
	for _, k := range []InputKind{InputInterfaces, InputIPAM} {
		if r, bad := p.notFresh[k]; bad {
			return unknown(pl, r)
		}
	}
	seg, reason := p.segment(addr)
	if reason != "" {
		return unknown(pl, reason)
	}
	if seg != nil {
		pl.Segment = seg
		in, reason := p.owner(seg.Prefix)
		if reason != "" {
			return unknown(pl, reason)
		}
		pl.Interface = in.Name
		pl.Zone = in.Zone
		if !seg.VLAN.Collected && in.VLAN.Collected {
			pl.Segment.VLAN = in.VLAN
		}
		return pl
	}
	if r, bad := p.notFresh[InputRoutes]; bad {
		return unknown(pl, r)
	}
	special := IsSpecialAddress(addr)
	rt, reason := p.route(addr, special)
	if reason != "" {
		return unknown(pl, reason)
	}
	if rt == nil {
		if special {
			return unknown(pl, ReasonPrivateOutsideSubnets)
		}
		return unknown(pl, ReasonNoRoute)
	}
	zone, reason := p.routeZone(*rt)
	if reason != "" {
		return unknown(pl, reason)
	}
	r := *rt
	pl.Route = &r
	pl.Interface = rt.Interface
	pl.Zone = zone
	return pl
}

func unknown(pl Placement, reason string) Placement {
	pl.Unknown = true
	pl.Reason = reason
	pl.Zone = ""
	pl.Interface = ""
	pl.Route = nil
	return pl
}

// segment returns the longest IPAM subnet or interface network containing
// addr, nil if none. Two different IPAM subnets with the same prefix are
// ambiguous. An IPAM subnet wins over an interface network of the same
// prefix (it carries the subnet ID).
func (p *Placer) segment(addr netip.Addr) (*Segment, string) {
	best := -1
	var seg *Segment
	ambiguous := false
	for _, sn := range p.subnets {
		if !sn.Prefix.Contains(addr) {
			continue
		}
		switch b := sn.Prefix.Bits(); {
		case b > best:
			best, ambiguous = b, false
			seg = &Segment{Prefix: sn.Prefix, SubnetID: sn.ID, VLAN: sn.VLAN}
		case b == best && (sn.ID != seg.SubnetID || sn.VLAN != seg.VLAN):
			ambiguous = true
		}
	}
	for _, in := range p.interfaces {
		for _, pr := range in.Prefixes {
			if pr.Contains(addr) && pr.Bits() > best {
				best, ambiguous = pr.Bits(), false
				seg = &Segment{Prefix: pr}
			}
		}
	}
	if ambiguous {
		return nil, ReasonSubnetAmbiguous
	}
	return seg, ""
}

// owner returns the firewall interface whose network contains seg, the
// longest one. Several interfaces at that length are ambiguous; an
// interface without zone proves no zone.
func (p *Placer) owner(seg netip.Prefix) (Interface, string) {
	best := -1
	var found []Interface
	for _, in := range p.interfaces {
		for _, pr := range in.Prefixes {
			if pr.Bits() > seg.Bits() || !pr.Contains(seg.Addr()) {
				continue
			}
			switch {
			case pr.Bits() > best:
				best = pr.Bits()
				found = append(found[:0], in)
			case pr.Bits() == best && found[len(found)-1].Name != in.Name:
				found = append(found, in)
			}
		}
	}
	switch {
	case len(found) == 0:
		return Interface{}, ReasonSubnetNoInterface
	case len(found) > 1:
		return Interface{}, ReasonInterfaceAmbiguous
	case found[0].Zone == "":
		return Interface{}, ReasonInterfaceNoZone
	}
	return found[0], ""
}

// route returns the longest route containing addr; for a special address
// default routes are ignored. Equal-length routes leading to different
// zones are ambiguous.
func (p *Placer) route(addr netip.Addr, special bool) (*Route, string) {
	best := -1
	var rt *Route
	ambiguous := false
	for i := range p.routes {
		r := &p.routes[i]
		if !r.Prefix.Contains(addr) || (special && r.Prefix.Bits() == 0) {
			continue
		}
		switch b := r.Prefix.Bits(); {
		case b > best:
			best, rt, ambiguous = b, r, false
		case b == best:
			z1, _ := p.routeZone(*rt)
			z2, _ := p.routeZone(*r)
			if z1 == "" || z1 != z2 {
				ambiguous = true
			}
		}
	}
	if ambiguous {
		return nil, ReasonRouteAmbiguous
	}
	return rt, ""
}

// routeZone returns the zone of a route: its own zone, or that of its
// interface. Both set and different, or neither known, proves no zone.
func (p *Placer) routeZone(r Route) (string, string) {
	ifz := ""
	if r.Interface != "" {
		ifz = p.ifZone[r.Interface]
	}
	switch {
	case r.Zone != "" && ifz != "" && r.Zone != ifz:
		return "", ReasonRouteAmbiguous
	case r.Zone != "":
		return r.Zone, ""
	case ifz != "":
		return ifz, ""
	}
	return "", ReasonInterfaceNoZone
}

// Crossing is the result of the crossing test (ADR 0012 D2 step 2).
// NotFiltered is set when source and destination share an L2 segment, so
// the firewall is not on the path; otherwise the test decides nothing.
type Crossing struct {
	NotFiltered bool
	Reason      string
}

// CrossingTest compares two placements: the same segment (same prefix
// and subnet ID), or two segments whose collected VLANs are equal, give
// not_filtered. Host firewalls are not modelled in nr-v1. An address
// without a segment never shares one.
func CrossingTest(src, dst Placement) Crossing {
	a, b := src.Segment, dst.Segment
	if a == nil || b == nil {
		return Crossing{}
	}
	if a.Prefix == b.Prefix && a.SubnetID == b.SubnetID {
		return Crossing{NotFiltered: true, Reason: ReasonSameSegment}
	}
	if a.VLAN.Collected && b.VLAN.Collected && a.VLAN.Value == b.VLAN.Value {
		return Crossing{NotFiltered: true, Reason: ReasonSameVLAN}
	}
	return Crossing{}
}

// specialPrefixes are the private and special-purpose ranges of ADR 0012
// D2 (RFC 6890 and successors). An IPv6 address outside 2000::/3 is
// special as well (see IsSpecialAddress).
var specialPrefixes = mustPrefixes(
	// IPv4
	"0.0.0.0/8",       // this network, unspecified
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation
	"192.88.99.0/24",  // 6to4 relay anycast (deprecated)
	"192.168.0.0/16",  // RFC 1918
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, broadcast
	// IPv6 inside 2000::/3
	"2001::/23",     // IETF protocol assignments (Teredo, ORCHID, ...)
	"2001:db8::/32", // documentation
	"2002::/16",     // 6to4
	"3fff::/20",     // documentation (RFC 9637)
)

var globalUnicast6 = netip.MustParsePrefix("2000::/3")

// IsSpecialAddress reports whether addr is in a private or special range
// (RFC 1918, CGNAT, loopback, link-local, ULA, multicast, documentation,
// reserved, unspecified). Every IPv6 address outside the global unicast
// range 2000::/3 counts as special. An invalid address counts as special.
func IsSpecialAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.Is6() && !globalUnicast6.Contains(addr) {
		return true
	}
	for _, p := range specialPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
