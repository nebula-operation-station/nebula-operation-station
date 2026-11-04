// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"net/netip"
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
	// ::/0; see ParseRoutes for how the family is determined.
	Dst netip.Prefix
	// Gateway is the next-hop address; the zero address for direct routes.
	Gateway netip.Addr
	// Dev is the interface the route is installed on.
	Dev string
	// Metric is the route metric; 0 when the host reported none.
	// iproute2 metrics are unsigned 32-bit values.
	Metric uint32
}

// routeDoc is the permissive shape of one `ip -j route` array element.
// Unknown fields are dropped (spec 09).
type routeDoc struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Metric  uint32 `json:"metric"`
}

// RouteTable is the parsed route table of one `ip -j route` document.
type RouteTable struct {
	// Entries holds the valid routes in host order.
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
// A "default" destination takes the family of the entry's gateway; without
// a gateway, the family of the first valid route in the document. An
// entry with no family signal is skipped, never guessed. Entries with an
// invalid destination, gateway (including an IPv6 zone that is not a
// short interface name, or a gateway whose family differs from the
// destination's), device, or metric are skipped and counted in Dropped.
// Input above maxInputSize, a document that is not a JSON array, or an
// array with more than maxEntries elements is an error. One bad entry
// never discards the rest of the table.
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
		r, ok := parseRouteEntry(d, docFamily, hasFamily)
		if !ok {
			t.Dropped++
			continue
		}
		t.Entries = append(t.Entries, r)
	}
	t.Incomplete = t.Dropped > 0
	return t, nil
}

// parseRouteEntry parses one route element. ok is false for entries that
// are skipped (invalid or ambiguous fields), never an error: one bad entry
// must not discard the rest of the table.
func parseRouteEntry(d routeDoc, docFamily int, hasFamily bool) (Route, bool) {
	var gw netip.Addr
	if d.Gateway != "" {
		a, ok := parseHostAddr(d.Gateway)
		if !ok {
			return Route{}, false
		}
		gw = a
	}
	var dst netip.Prefix
	if d.Dst == "default" {
		fam, ok := familyOf(gw)
		if !ok && hasFamily {
			fam, ok = docFamily, true
		}
		if !ok {
			return Route{}, false
		}
		if fam == 4 {
			dst = defaultRouteV4
		} else {
			dst = defaultRouteV6
		}
	} else {
		if len(d.Dst) > maxAddrLen {
			return Route{}, false
		}
		p, err := netip.ParsePrefix(d.Dst)
		if err != nil {
			return Route{}, false
		}
		dst = p
	}
	if gw.IsValid() {
		gwFam, _ := familyOf(gw)
		dstFam, _ := familyOf(dst.Addr())
		if gwFam != dstFam {
			return Route{}, false
		}
	}
	if !printable(d.Dev, maxStringLen) {
		return Route{}, false
	}
	return Route{Dst: dst, Gateway: gw, Dev: d.Dev, Metric: d.Metric}, true
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
// route on its own (a prefix destination, or a "default" destination with
// a gateway), and ok=false when no entry provides one. Entries that are
// later skipped as invalid never decide the family.
func documentFamily(docs []routeDoc) (int, bool) {
	for _, d := range docs {
		if r, ok := parseRouteEntry(d, 0, false); ok {
			return familyOf(r.Dst.Addr())
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
