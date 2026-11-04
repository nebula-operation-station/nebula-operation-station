// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"net/netip"
	"unicode"
	"unicode/utf8"
)

// Shared limits for host network facts (ADR 0009 D1, spec 09). Every value
// read from a managed host is untrusted: bounded size, bounded count,
// printable UTF-8 text only.
const (
	// maxInputSize bounds the raw size of one `ip -j ...` JSON document in
	// bytes (spec 09: "1 MiB decoded per response/spool page").
	maxInputSize = 1 << 20
	// maxEntries bounds the number of array elements one document may
	// contain (spec 09: "1,000 objects/page"; the limits "also apply to
	// the new SSH observation contracts"). One `ip -j` document is one
	// page.
	maxEntries = 1000
	// maxStringLen bounds any host-provided string field in bytes.
	maxStringLen = 253
	// maxStates bounds the state list of one neighbor entry. iproute2
	// reports at most one of the eight NUD states per entry.
	maxStates = 8
	// maxZoneLen bounds an IPv6 zone. A zone names an interface, and
	// Linux interface names are at most IFNAMSIZ-1 = 15 bytes.
	maxZoneLen = 15
	// maxAddrLen bounds the text of one host-provided IP address: the
	// longest IPv6 form (45 bytes), "%" and a maxZoneLen zone, rounded
	// up. Longer text is rejected before it is parsed.
	maxAddrLen = 64
)

// printable reports whether s is non-empty printable UTF-8 text within
// limit bytes: valid UTF-8, no control characters (C0, DEL, C1), no
// format characters (bidi overrides, zero-width characters), no line or
// paragraph separators. Host-provided text that fails this check is
// dropped, never rendered (spec 09).
func printable(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

// unsafeRune reports whether r must not appear in host-provided text.
func unsafeRune(r rune) bool {
	switch {
	case r == utf8.RuneError || !utf8.ValidRune(r):
		return true
	case unicode.Is(unicode.Cc, r): // C0, DEL, C1, including \t \n \r
		return true
	case unicode.Is(unicode.Cf, r): // bidi controls, zero-width, BOM
		return true
	case unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r):
		return true
	}
	return false
}

// validZone reports whether z is an acceptable IPv6 zone: a short
// interface name of 1..maxZoneLen bytes from [A-Za-z0-9._@-]. netip
// accepts zones of any content and length, so every zone from host data
// must pass this check before the address is stored.
func validZone(z string) bool {
	if z == "" || len(z) > maxZoneLen {
		return false
	}
	for i := 0; i < len(z); i++ {
		c := z[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '@':
		default:
			return false
		}
	}
	return true
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
