// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// normalizeMAC returns the lowercase aa:bb:cc:dd:ee:ff form of a 6-byte
// MAC, or "" for anything else.
func normalizeMAC(s string) string {
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return ""
	}
	return strings.ToLower(m.String())
}

// normalizeOwnAddr returns the unmapped, zone-free form of a, or the zero
// address for an address that cannot identify a host.
func normalizeOwnAddr(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return netip.Addr{}
	}
	return a
}

// Exclusive returns the identities of records with every MAC and address
// removed that more than one host claims, normalized (lowercase MACs,
// unmapped zone-free addresses), deduplicated, sorted and bounded
// (trafficstore.MaxIdentityMACs, flowagg.MaxHostAddrs).
//
// records must come from the server's own records of the managed hosts
// (inventory endpoints, registered interfaces, IPAM assignments), never
// from host output: own addresses decide which flow ends and endpoints a
// host may speak for. A value two hosts claim belongs to neither, so a
// host cannot take over another host's flow ends or endpoints by having
// the same address recorded. Malformed values are dropped. Every host of
// records is in the result, possibly with an empty Identity.
func Exclusive(records map[string]trafficstore.Identity) map[string]trafficstore.Identity {
	macOwners := map[string]map[string]struct{}{}
	addrOwners := map[netip.Addr]map[string]struct{}{}
	claim := func(m map[string]struct{}, host string) map[string]struct{} {
		if m == nil {
			m = map[string]struct{}{}
		}
		m[host] = struct{}{}
		return m
	}
	for host, id := range records {
		for _, s := range id.MACs {
			if m := normalizeMAC(s); m != "" {
				macOwners[m] = claim(macOwners[m], host)
			}
		}
		for _, a := range id.Addrs {
			if a = normalizeOwnAddr(a); a.IsValid() {
				addrOwners[a] = claim(addrOwners[a], host)
			}
		}
	}
	out := make(map[string]trafficstore.Identity, len(records))
	for host, id := range records {
		var res trafficstore.Identity
		for _, s := range id.MACs {
			m := normalizeMAC(s)
			if m == "" || len(macOwners[m]) != 1 || slices.Contains(res.MACs, m) {
				continue
			}
			res.MACs = append(res.MACs, m)
		}
		for _, a := range id.Addrs {
			a = normalizeOwnAddr(a)
			if !a.IsValid() || len(addrOwners[a]) != 1 || slices.Contains(res.Addrs, a) {
				continue
			}
			res.Addrs = append(res.Addrs, a)
		}
		slices.Sort(res.MACs)
		slices.SortFunc(res.Addrs, netip.Addr.Compare)
		if len(res.MACs) > trafficstore.MaxIdentityMACs {
			res.MACs = res.MACs[:trafficstore.MaxIdentityMACs]
		}
		if len(res.Addrs) > flowagg.MaxHostAddrs {
			res.Addrs = res.Addrs[:flowagg.MaxHostAddrs]
		}
		out[host] = res
	}
	return out
}

// identitiesEqual reports whether two identity maps are the same.
func identitiesEqual(a, b map[string]trafficstore.Identity) bool {
	if len(a) != len(b) {
		return false
	}
	for host, x := range a {
		y, ok := b[host]
		if !ok || !slices.Equal(x.MACs, y.MACs) || !slices.Equal(x.Addrs, y.Addrs) {
			return false
		}
	}
	return true
}
