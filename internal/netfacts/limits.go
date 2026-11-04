// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import "net/netip"

// Shared limits for host network facts (ADR 0009 D1, spec 09). Every value
// read from a managed host is untrusted: bounded size, bounded count, and
// text fields only from a strict alphabet (interface names, NUD state
// names, IP addresses).
const (
	// maxInputSize bounds the raw size of one `ip -j ...` JSON document in
	// bytes (spec 09: "1 MiB decoded per response/spool page").
	maxInputSize = 1 << 20
	// maxEntries bounds the number of array elements one document may
	// contain (spec 09: "1,000 objects/page"; the limits "also apply to
	// the new SSH observation contracts"). One `ip -j` document is one
	// page.
	maxEntries = 1000
	// maxStates bounds the state list of one neighbor entry. iproute2
	// prints a combination of the NUD state names in nudStates.
	maxStates = 8
	// maxIfNameLen bounds an interface name (a route or neighbor device,
	// or an IPv6 zone): Linux interface names are at most IFNAMSIZ-1 = 15
	// bytes.
	maxIfNameLen = 15
	// maxZoneLen bounds an IPv6 zone, which names an interface.
	maxZoneLen = maxIfNameLen
	// maxNexthops bounds the "nexthops" list of one multipath route.
	maxNexthops = 64
	// maxAddrLen bounds the text of one host-provided IP address: the
	// longest IPv6 form (45 bytes), "%" and a maxZoneLen zone, rounded
	// up. Longer text is rejected before it is parsed.
	maxAddrLen = 64
)

// validIfName reports whether s is an acceptable interface name: 1..
// maxIfNameLen bytes from [A-Za-z0-9._@-]. Device fields and IPv6 zones
// from host data must pass this check before they are stored.
func validIfName(s string) bool {
	if s == "" || len(s) > maxIfNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '@':
		default:
			return false
		}
	}
	return true
}

// validZone reports whether z is an acceptable IPv6 zone: a short
// interface name (validIfName). netip accepts zones of any content and
// length, so every zone from host data must pass this check before the
// address is stored.
func validZone(z string) bool {
	return len(z) <= maxZoneLen && validIfName(z)
}

// parseHostAddr parses s as an IP address from host data. Text longer
// than maxAddrLen is rejected before parsing, and a zoned IPv6 address is
// accepted only when its zone passes validZone.
func parseHostAddr(s string) (netip.Addr, bool) {
	if s == "" || len(s) > maxAddrLen {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	if z := a.Zone(); z != "" && !validZone(z) {
		return netip.Addr{}, false
	}
	return a, true
}
