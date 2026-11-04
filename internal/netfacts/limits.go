// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"net"
	"net/netip"
)

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
	// maxAddrsPerIf bounds the "addr_info" list of one interface in an
	// `ip -j addr` document. A single interface carrying more than this
	// many addresses is truncated and the table is marked incomplete.
	maxAddrsPerIf = 1000
	// minVLANID and maxVLANID bound an 802.1Q VLAN id of a vlan device or
	// a bridge port. The tag field is 12 bits, but 0 (priority tag) and
	// 4095 are reserved: the kernel rejects them for vlan devices and the
	// bridge carries 1..4094. Host data outside this range is dropped.
	minVLANID = 1
	maxVLANID = 4094
	// maxVLANsPerDoc bounds the distinct (port, VLAN id) pairs one
	// `bridge -j vlan` document may expand to. iproute2 prints ranges
	// ("vlan" plus "vlanEnd"), so a small document can describe millions
	// of pairs (1000 ports x 4094 ids); the budget caps the allocations a
	// hostile document can force. It holds 64 ports carrying the full
	// 1..4094 range (a Proxmox VLAN-aware bridge defaults to 2-4094 on
	// every port). Pairs beyond the budget are dropped and the table is
	// marked incomplete.
	maxVLANsPerDoc = 64 * maxVLANID
	// maxVLANWorkPerDoc bounds the VLAN ids one `bridge -j vlan` document
	// may make the parser visit while expanding ranges, duplicates and
	// overlaps included. It bounds the CPU a document of repeated full
	// ranges can force once maxVLANsPerDoc no longer limits it. Expansion
	// stops at the budget and the table is marked incomplete.
	maxVLANWorkPerDoc = 4 * maxVLANsPerDoc
	// maxKindLen bounds the link kind string from `ip -j -d link`
	// (linkinfo.info_kind). Known kinds (vlan, bridge, veth, wireguard,
	// macvlan, openvswitch, ...) are short; a longer string is not a
	// real kind name and is dropped.
	maxKindLen = 32
	// maxLinkAddrLen bounds a link-layer address in bytes (MAX_ADDR_LEN in
	// the kernel).
	maxLinkAddrLen = 32
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

// parseLinkLayerAddr classifies the link-layer address text iproute2
// prints for an interface (ll_addr_n2a). mac is set for a 6-byte Ethernet
// MAC, the only kind kept. known is true when the text is either such a
// MAC or another well-formed link-layer address iproute2 prints: an IP
// literal for tunnel devices (sit/ipip/gre "0.0.0.0", ip6tnl "::") or
// colon-separated hex bytes of another length (e.g. a 20-byte InfiniBand
// address), at most maxLinkAddrLen bytes. A known non-Ethernet address is
// not kept but is not a loss either; anything else is malformed.
//
// linkType is the "link_type" iproute2 prints next to the address. For
// "ether" only a 6-byte MAC is well-formed, so a host cannot hide an
// Ethernet interface's MAC behind an IP literal or other hex bytes.
func parseLinkLayerAddr(s, linkType string) (mac net.HardwareAddr, known bool) {
	if hw, err := net.ParseMAC(s); err == nil && len(hw) == 6 {
		return hw, true
	}
	if linkType == "ether" {
		return nil, false
	}
	if _, ok := parseHostAddr(s); ok {
		return nil, true
	}
	return nil, isHexBytes(s)
}

// validKind reports whether s is a link kind from `ip -j -d link`
// ("vlan", "bridge", "vxlan", "ip6tnl", ...): 1..maxKindLen bytes of
// [a-z0-9_-]. Anything else (control bytes, upper case, non-ASCII) is
// dropped as a loss.
func validKind(s string) bool {
	if len(s) == 0 || len(s) > maxKindLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// isHexBytes reports whether s is 1..maxLinkAddrLen two-digit hex bytes
// separated by colons, the form iproute2 prints for a link-layer address
// of a non-tunnel type.
func isHexBytes(s string) bool {
	if len(s) < 2 || len(s) > 3*maxLinkAddrLen-1 || len(s)%3 != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
