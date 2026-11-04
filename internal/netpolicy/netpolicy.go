// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netpolicy holds the address and host name rules shared by the
// packages that connect to operator- or user-supplied destinations
// (internal/executions/servicecheck, internal/iconfetch). Keeping them in
// one place means a fix to a range or to the host name grammar reaches
// every caller.
package netpolicy

import (
	"net/netip"
	"regexp"
)

// hostnameRe is a strict RFC 1123 host name: ASCII labels of 1-63
// characters of [A-Za-z0-9-], starting and ending with [A-Za-z0-9], no
// trailing dot. It is deliberately narrower than what a resolver accepts:
// callers embed the name in a URL, so it must stay a bare name.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// numericHostRe matches legacy inet_aton forms (decimal, octal, hex, short
// dotted) that a resolver could reinterpret as an IPv4 address.
var numericHostRe = regexp.MustCompile(`(?i)^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$`)

// IsHostname reports whether s is a strict RFC 1123 host name that no
// resolver can reinterpret as a numeric IPv4 address. It does not check
// the overall length; callers bound that themselves.
func IsHostname(s string) bool {
	return hostnameRe.MatchString(s) && !numericHostRe.MatchString(s)
}

// Reserved reports whether addr is an internal address that a connection
// to an operator-supplied destination must not reach without explicit
// approval, with a fixed reason. IPv4-mapped IPv6 addresses are judged by
// their IPv4 part; every other IPv6 address is reserved, because IPv6 has
// too many ranges that embed or route to IPv4 (NAT64, 6to4, Teredo) or are
// internal (loopback, link-local, unique local, multicast). The invalid
// zero Addr is reserved too.
func Reserved(addr netip.Addr) (string, bool) {
	if !addr.IsValid() {
		return "invalid address", true
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.Is4() {
		return "IPv6 literal", true
	}
	o := addr.As4()
	switch {
	case o[0] == 0:
		return "0.0.0.0/8 (this network)", true
	case o[0] == 10:
		return "10.0.0.0/8 (private)", true
	case o[0] == 127:
		return "127.0.0.0/8 (loopback)", true
	case o[0] == 169 && o[1] == 254:
		return "169.254.0.0/16 (link-local, incl. 169.254.169.254 metadata)", true
	case o[0] == 100 && o[1] >= 64 && o[1] <= 127:
		return "100.64.0.0/10 (CGNAT)", true
	case o[0] == 172 && o[1] >= 16 && o[1] <= 31:
		return "172.16.0.0/12 (private)", true
	case o[0] == 192 && o[1] == 168:
		return "192.168.0.0/16 (private)", true
	case o[0] >= 224:
		return "224.0.0.0/4 (multicast/reserved)", true
	}
	return "", false
}

// specialPurpose are IANA special-purpose IPv4 ranges outside Reserved
// that a host on the public Internet never uses. Reserved leaves them out
// because an operator may legitimately probe them (lab and benchmarking
// networks); NonPublic adds them.
var specialPurpose = []struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("192.0.0.0/24"), "192.0.0.0/24 (IETF protocol assignments)"},
	{netip.MustParsePrefix("192.0.2.0/24"), "192.0.2.0/24 (documentation)"},
	{netip.MustParsePrefix("192.88.99.0/24"), "192.88.99.0/24 (deprecated 6to4 relay anycast)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "198.18.0.0/15 (benchmarking)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "198.51.100.0/24 (documentation)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "203.0.113.0/24 (documentation)"},
}

// NonPublic reports whether addr is not a public unicast IPv4 address:
// everything Reserved refuses plus the IANA special-purpose ranges that
// never host a public service. It is a strict superset of Reserved.
func NonPublic(addr netip.Addr) (string, bool) {
	if reason, bad := Reserved(addr); bad {
		return reason, true
	}
	addr = addr.Unmap()
	for _, r := range specialPurpose {
		if r.prefix.Contains(addr) {
			return r.reason, true
		}
	}
	return "", false
}
