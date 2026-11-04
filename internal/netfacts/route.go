// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// defaultRouteV4 and defaultRouteV6 are the "default" destinations of the
// IPv4 and IPv6 route tables.
var (
	defaultRouteV4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	defaultRouteV6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

// Route is one entry of the host's route table.
type Route struct {
	// Dst is the destination prefix. A "default" route is 0.0.0.0/0 or
	// ::/0; see ParseRoutes for how the family is determined. A host
	// route, which iproute2 prints as a bare address, is a /32 or /128.
	Dst netip.Prefix
	// Gateway is the next-hop address; the zero address for direct routes.
	Gateway netip.Addr
	// Dev is the interface the route is installed on (a Linux interface
	// name, see validIfName).
	Dev string
	// Metric is the route metric; 0 when the host reported none.
	// iproute2 metrics are unsigned 32-bit values.
	Metric uint32
}

// routeDoc is the permissive shape of one `ip -j route` array element.
// Unknown fields are dropped (spec 09).
type routeDoc struct {
	Dst      string       `json:"dst"`
	Gateway  string       `json:"gateway"`
	Via      *viaDoc      `json:"via"`
	Dev      string       `json:"dev"`
	Metric   uint32       `json:"metric"`
	Nexthops []nexthopDoc `json:"nexthops"`
}

// viaDoc is the permissive shape of an RFC 5549 "via" field: a next hop
// of a different family than the destination (an IPv6 next hop for an
// IPv4 destination), which iproute2 prints as
// {"family": "inet6", "host": "fe80::1"}.
type viaDoc struct {
	Family string `json:"family"`
	Host   string `json:"host"`
}

// nexthopDoc is one element of the "nexthops" list of a multipath route
// (ECMP, or an IPv6 default learned from several routers).
type nexthopDoc struct {
	Gateway string  `json:"gateway"`
	Via     *viaDoc `json:"via"`
	Dev     string  `json:"dev"`
}

// RouteTable is the parsed route table of one `ip -j route` document.
type RouteTable struct {
	// Entries holds the valid routes in host order. A multipath route
	// contributes one entry per next hop, in host order.
	Entries []Route
	// Dropped counts array elements that were skipped as malformed or
	// ambiguous.
	Dropped int
	// Incomplete is true when Dropped > 0. An incomplete table must be
	// presented as such, never as the complete table (spec 09).
	Incomplete bool
}

// ParseRoutes parses the JSON array printed by `ip -j route` (IPv4) or
// `ip -6 -j route` (IPv6).
//
// A destination is "default", a prefix, or a bare address (a host route,
// stored as /32 or /128); an address destination never carries a zone. A
// "default" destination takes the family of the entry's gateway (or of
// its first next-hop gateway); without a gateway, the family of the first
// valid route in the document. An entry with no family signal is skipped,
// never guessed. A multipath route (a "nexthops" list and no top-level
// gateway or device) is expanded into one Route per next hop. Entries
// with an invalid destination, gateway (including an IPv6 zone that is
// not a short interface name, or a gateway whose family differs from the
// destination's), device (not a Linux interface name), metric, or
// next-hop list are skipped and counted in Dropped, as are entries that
// would grow the table beyond maxEntries routes. Input above
// maxInputSize, a document that is not a JSON array, or an array with
// more than maxEntries elements is an error. One bad entry never discards
// the rest of the table.
//
// An RFC 5549 next hop (an IPv6 next hop for an IPv4 destination) is
// printed by iproute2 as a "via" object, top-level and inside a
// "nexthops" list. A "via" goes through the same strict host-address
// rules as a gateway, and the IPv6-gateway-for-IPv4-destination
// combination is accepted only from a "via". An entry whose "via" cannot
// be parsed is skipped with the rest of the entry, never kept as a
// direct route (that would silently lose the gateway).
func ParseRoutes(raw []byte) (RouteTable, error) {
	if len(raw) > maxInputSize {
		return RouteTable{}, fmt.Errorf("route document exceeds %d bytes", maxInputSize)
	}
	elems, err := unmarshalArray(raw, "routes")
	if err != nil {
		return RouteTable{}, err
	}
	if len(elems) > maxEntries {
		return RouteTable{}, fmt.Errorf("route list exceeds %d entries", maxEntries)
	}
	docs := make([]routeDoc, 0, len(elems))
	t := RouteTable{Entries: make([]Route, 0, len(elems))}
	for _, e := range elems {
		var d routeDoc
		if err := json.Unmarshal(e, &d); err != nil {
			t.Dropped++
			continue
		}
		docs = append(docs, d)
	}
	docFamily, hasFamily := documentFamily(docs)
	for _, d := range docs {
		rs, ok := parseRouteEntry(d, docFamily, hasFamily)
		if !ok || len(t.Entries)+len(rs) > maxEntries {
			t.Dropped++
			continue
		}
		t.Entries = append(t.Entries, rs...)
	}
	t.Incomplete = t.Dropped > 0
	return t, nil
}

// hop is one validated next hop of a route element.
type hop struct {
	gw netip.Addr
	// via is true when the gateway came from an RFC 5549 "via" field;
	// only such a hop may carry an IPv6 gateway for an IPv4
	// destination.
	via bool
	dev string
}

// parseHops returns the validated next hops of d: the top-level gateway
// or "via" and device, or the "nexthops" list of a multipath route. ok
// is false for an invalid gateway or device, an empty or oversize
// next-hop list, or an element that mixes a top-level gateway, via, or
// device with a next-hop list (ambiguous).
func parseHops(d routeDoc) ([]hop, bool) {
	if d.Nexthops == nil {
		h, ok := parseHop(d.Gateway, d.Via, d.Dev)
		return []hop{h}, ok
	}
	if d.Gateway != "" || d.Via != nil || d.Dev != "" || len(d.Nexthops) == 0 || len(d.Nexthops) > maxNexthops {
		return nil, false
	}
	hops := make([]hop, 0, len(d.Nexthops))
	for _, n := range d.Nexthops {
		h, ok := parseHop(n.Gateway, n.Via, n.Dev)
		if !ok {
			return nil, false
		}
		hops = append(hops, h)
	}
	return hops, true
}

// parseHop validates one next hop: a "gateway" address or an RFC 5549
// "via" next hop, plus the device. ok is false for a malformed address
// or device, or when both a gateway and a via are present (ambiguous).
func parseHop(gateway string, via *viaDoc, dev string) (hop, bool) {
	var h hop
	switch {
	case gateway != "" && via != nil:
		return hop{}, false
	case gateway != "":
		a, ok := parseHostAddr(gateway)
		if !ok {
			return hop{}, false
		}
		h.gw = a
	case via != nil:
		a, ok := parseVia(via)
		if !ok {
			return hop{}, false
		}
		h.gw = a
		h.via = true
	}
	if !validIfName(dev) {
		return hop{}, false
	}
	h.dev = dev
	return h, true
}

// parseVia parses one RFC 5549 "via" next hop. The host goes through the
// same strict parseHostAddr/zone rules as a gateway; the family must be
// a known family name ("inet" or "inet6") and must match the host's
// family.
func parseVia(v *viaDoc) (netip.Addr, bool) {
	var fam int
	switch v.Family {
	case "inet":
		fam = 4
	case "inet6":
		fam = 6
	default:
		return netip.Addr{}, false
	}
	a, ok := parseHostAddr(v.Host)
	if !ok {
		return netip.Addr{}, false
	}
	if f, _ := familyOf(a); f != fam {
		return netip.Addr{}, false
	}
	return a, true
}

// parseDst parses a non-"default" destination: a prefix or a bare address
// (a host route, which iproute2 prints without a prefix length). The
// address goes through the same strict validation as every host address,
// and a zone is rejected: a route destination names a network, not an
// interface-scoped address, and iproute2 never prints one.
func parseDst(s string) (netip.Prefix, bool) {
	if s == "" || len(s) > maxAddrLen {
		return netip.Prefix{}, false
	}
	if !strings.Contains(s, "/") {
		a, ok := parseHostAddr(s)
		if !ok || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// parseRouteEntry parses one route element into one Route per next hop.
// ok is false for entries that are skipped (invalid or ambiguous fields),
// never an error: one bad entry must not discard the rest of the table.
func parseRouteEntry(d routeDoc, docFamily int, hasFamily bool) ([]Route, bool) {
	hops, ok := parseHops(d)
	if !ok {
		return nil, false
	}
	var dst netip.Prefix
	if d.Dst == "default" {
		fam, ok := 0, false
		for _, h := range hops {
			if f, ok2 := familyOf(h.gw); ok2 {
				fam, ok = f, true
				if h.via {
					// RFC 5549: a "via" next hop has the other
					// family than the destination: an IPv6 next
					// hop means an IPv4 destination.
					if f == 6 {
						fam = 4
					} else {
						fam = 6
					}
				}
				break
			}
		}
		if !ok && hasFamily {
			fam, ok = docFamily, true
		}
		if !ok {
			return nil, false
		}
		if fam == 4 {
			dst = defaultRouteV4
		} else {
			dst = defaultRouteV6
		}
	} else {
		p, ok := parseDst(d.Dst)
		if !ok {
			return nil, false
		}
		dst = p
	}
	dstFam, _ := familyOf(dst.Addr())
	routes := make([]Route, 0, len(hops))
	for _, h := range hops {
		if h.gw.IsValid() {
			gwFam, _ := familyOf(h.gw)
			if gwFam != dstFam && !(h.via && gwFam == 6 && dstFam == 4) {
				return nil, false
			}
		}
		routes = append(routes, Route{Dst: dst, Gateway: h.gw, Dev: h.dev, Metric: d.Metric})
	}
	return routes, true
}

// familyOf returns 4 or 6 for a valid address and ok=false for the zero
// address.
func familyOf(a netip.Addr) (int, bool) {
	if !a.IsValid() {
		return 0, false
	}
	if a.Is4() {
		return 4, true
	}
	return 6, true
}

// documentFamily returns the family of the first entry that is a valid
// route on its own (a prefix or address destination, or a "default"
// destination with a gateway), and ok=false when no entry provides one.
// Entries that are later skipped as invalid never decide the family.
func documentFamily(docs []routeDoc) (int, bool) {
	for _, d := range docs {
		if rs, ok := parseRouteEntry(d, 0, false); ok && len(rs) > 0 {
			return familyOf(rs[0].Dst.Addr())
		}
	}
	return 0, false
}

// DefaultGateways returns the default routes (0.0.0.0/0 or ::/0) that have
// a gateway, in input order. These are the hops the traffic map derives
// cross-subnet traffic through (ADR 0009 D3).
func DefaultGateways(routes []Route) []Route {
	out := make([]Route, 0, len(routes))
	for _, r := range routes {
		if r.Dst.IsValid() && r.Dst.Bits() == 0 && r.Gateway.IsValid() {
			out = append(out, r)
		}
	}
	return out
}
