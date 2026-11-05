// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
)

// MaxRoutes bounds the routes kept per host for hop derivation. netfacts
// already bounds its tables; this keeps the per-host state small even if
// that bound changes.
const MaxRoutes = 1024

// Gateway is a next hop of one reporting host, derived from its route
// table and neighbor table (ADR 0009 D3). Everything in it is the host's
// own claim: it is labeled with the reporter and never used to decide
// ownership or identity.
type Gateway struct {
	// Addr is the next-hop address from the route.
	Addr netip.Addr
	// MAC is the gateway's link-layer address from the host's neighbor
	// table on Dev (lowercase aa:bb:cc:dd:ee:ff), "" when the table has
	// no usable entry (INCOMPLETE, FAILED, missing).
	MAC string
	// Dev is the interface the route uses.
	Dev string
	// Metric is the route metric.
	Metric uint32
	// Default is set when the route is the default route (0.0.0.0/0 or
	// ::/0).
	Default bool
}

// HostNet is the routing view of one reporting host at one snapshot,
// used to derive the hop of a flow (A → gateway → B).
type HostNet struct {
	// Reporter is the server's host ID of the reporting host.
	Reporter string
	// Defaults holds the host's default gateways, the lowest metric
	// first, IPv4 before IPv6.
	Defaults []Gateway
	// routes are the usable routes, most specific first.
	routes []hostnet.Route
	// neigh maps (dev, gateway address) to the gateway MAC.
	neigh map[neighKey]string
}

type neighKey struct {
	dev  string
	addr netip.Addr
}

// usableMAC returns the lowercase form of a 6-byte unicast MAC, or "".
func usableMAC(m net.HardwareAddr) string {
	if len(m) != 6 || m[0]&1 == 1 {
		return ""
	}
	allZero := true
	for _, b := range m {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return strings.ToLower(m.String())
}

// usableNeighbor reports whether a neighbor entry describes a reachable
// link-layer peer: it has a MAC and is not FAILED or INCOMPLETE.
func usableNeighbor(n hostnet.Neighbor) bool {
	if usableMAC(n.MAC) == "" {
		return false
	}
	for _, s := range n.State {
		if s == "FAILED" || s == "INCOMPLETE" {
			return false
		}
	}
	return true
}

// DeriveHostNet builds the routing view of reporter from its route and
// neighbor tables (IPv4 and IPv6). The gateway MAC is taken only from a
// neighbor entry on the route's interface.
func DeriveHostNet(reporter string, routes []hostnet.Route, neigh []hostnet.Neighbor) HostNet {
	h := HostNet{Reporter: reporter, neigh: map[neighKey]string{}}
	for _, n := range neigh {
		if !usableNeighbor(n) {
			continue
		}
		k := neighKey{dev: n.Dev, addr: n.IP.WithZone("").Unmap()}
		if _, dup := h.neigh[k]; !dup {
			h.neigh[k] = usableMAC(n.MAC)
		}
	}
	for _, r := range routes {
		if len(h.routes) >= MaxRoutes {
			break
		}
		if !r.Dst.IsValid() {
			continue
		}
		r.Dst = r.Dst.Masked()
		r.Gateway = r.Gateway.WithZone("").Unmap()
		h.routes = append(h.routes, r)
	}
	// Most specific first; on equal length the lower metric first; the
	// sort is stable so host order breaks the remaining ties.
	slices.SortStableFunc(h.routes, func(a, b hostnet.Route) int {
		if a.Dst.Bits() != b.Dst.Bits() {
			return b.Dst.Bits() - a.Dst.Bits()
		}
		switch {
		case a.Metric < b.Metric:
			return -1
		case a.Metric > b.Metric:
			return 1
		}
		return 0
	})
	for _, r := range hostnet.DefaultGateways(h.routes) {
		h.Defaults = append(h.Defaults, h.gateway(r))
	}
	slices.SortStableFunc(h.Defaults, func(a, b Gateway) int {
		if a.Addr.Is4() != b.Addr.Is4() {
			if a.Addr.Is4() {
				return -1
			}
			return 1
		}
		switch {
		case a.Metric < b.Metric:
			return -1
		case a.Metric > b.Metric:
			return 1
		}
		return 0
	})
	return h
}

func (h *HostNet) gateway(r hostnet.Route) Gateway {
	return Gateway{
		Addr:    r.Gateway,
		MAC:     h.neigh[neighKey{dev: r.Dev, addr: r.Gateway}],
		Dev:     r.Dev,
		Metric:  r.Metric,
		Default: r.Dst.Bits() == 0,
	}
}

// Hop returns the gateway that traffic from the host to dst passes, by
// longest-prefix match over the host's routes: a destination on a
// directly connected subnet (the best route has no gateway) has no hop;
// a destination in another subnet goes through the matching route's
// gateway, which for anything without a more specific route is the
// default gateway. ok is false when there is no hop or no route matches.
func (h HostNet) Hop(dst netip.Addr) (Gateway, bool) {
	dst = dst.WithZone("").Unmap()
	if !dst.IsValid() {
		return Gateway{}, false
	}
	for _, r := range h.routes {
		if r.Dst.Addr().Is4() != dst.Is4() || !r.Dst.Contains(dst) {
			continue
		}
		if !r.Gateway.IsValid() || r.Gateway == dst {
			return Gateway{}, false
		}
		return h.gateway(r), true
	}
	return Gateway{}, false
}
