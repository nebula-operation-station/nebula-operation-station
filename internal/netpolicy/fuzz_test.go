// SPDX-License-Identifier: AGPL-3.0-or-later

package netpolicy

import (
	"net/netip"
	"strings"
	"testing"
)

// The oracles below are written by hand and deliberately share no code or
// regular expressions with netpolicy.go: they walk bytes and labels, and
// they compare IPv4 addresses as uint32 against CIDR blocks.

// maxHostLabel is the RFC 1123 limit for one label of a host name.
const maxHostLabel = 63

// isLabelByte reports whether c is an ASCII letter, digit or hyphen.
func isLabelByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-'
}

// numericLabel reports whether one dot-separated label is a number that a
// resolver reads as part of a legacy inet_aton address: decimal digits, or
// "0x"/"0X" followed by at least one hex digit.
func numericLabel(l string) bool {
	if len(l) > 2 && l[0] == '0' && (l[1] == 'x' || l[1] == 'X') {
		for i := 2; i < len(l); i++ {
			c := l[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return decimalOnly(l)
			}
		}
		return true
	}
	return decimalOnly(l)
}

// decimalOnly reports whether l is one or more ASCII decimal digits.
func decimalOnly(l string) bool {
	if l == "" {
		return false
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

// hostnameOracle is the expected result of IsHostname: a name is accepted
// only if every label is 1 to 63 ASCII bytes from [A-Za-z0-9-] without a
// leading or trailing hyphen (so an empty label, from a leading, trailing
// or doubled dot, is refused), and the name is not entirely numeric in
// one of the legacy IPv4 forms.
func hostnameOracle(s string) bool {
	if s == "" {
		return false
	}
	numeric := true
	for _, l := range strings.Split(s, ".") {
		if len(l) < 1 || len(l) > maxHostLabel {
			return false
		}
		for i := 0; i < len(l); i++ {
			if !isLabelByte(l[i]) {
				return false
			}
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		if !numericLabel(l) {
			numeric = false
		}
	}
	return !numeric
}

// seedHostnames covers the accepted and refused classes: the length limit
// on both sides, every numeric form, bad separators and non-ASCII input.
var seedHostnames = []string{
	"a", "example.com", "a-b.c-d.e", "0x", "0xg", "0x7f.example", "1a.example",
	"127.0.0.1", "2130706433", "0x7f000001", "0X7F.1", "017700000001", "089", "1.2.3",
	"", ".", "a.", ".a", "a..b", "-a", "a-", "a.-b", "a_b", "a b", "a\x00b", "é.example",
	strings.Repeat("a", maxHostLabel) + ".example",
	strings.Repeat("a", maxHostLabel+1) + ".example",
	strings.Repeat("a.", 200) + "a",
}

// FuzzIsHostname checks IsHostname against hostnameOracle for arbitrary
// strings, and checks that an accepted name is not an address that
// netip.ParseAddr reads, so the name cannot be taken for an IP literal.
func FuzzIsHostname(f *testing.F) {
	for _, s := range seedHostnames {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := IsHostname(s)
		want := hostnameOracle(s)
		if got != want {
			t.Fatalf("IsHostname(%q) = %v, oracle wants %v", s, got, want)
		}
		if got {
			if a, err := netip.ParseAddr(s); err == nil {
				t.Fatalf("IsHostname(%q) accepted a name that netip.ParseAddr reads as %v", s, a)
			}
		}
	})
}

// reservedRange is one CIDR block as a base address and a prefix length.
type reservedRange struct {
	base uint32
	bits uint
}

// v4 packs four octets into one uint32.
func v4(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

// inBlock reports whether v lies in the block base/bits.
func inBlock(v uint32, r reservedRange) bool {
	shift := 32 - r.bits
	return v>>shift == r.base>>shift
}

// oracleReserved are the IPv4 blocks that Reserved must refuse. 224/3 is
// written as in the existing tests, which refuse 240/4 and 255.255.255.255.
var oracleReserved = []reservedRange{
	{v4(0, 0, 0, 0), 8},      // this network, incl. 0.0.0.0
	{v4(10, 0, 0, 0), 8},     // private
	{v4(127, 0, 0, 0), 8},    // loopback
	{v4(169, 254, 0, 0), 16}, // link-local, incl. metadata
	{v4(100, 64, 0, 0), 10},  // CGNAT
	{v4(172, 16, 0, 0), 12},  // private
	{v4(192, 168, 0, 0), 16}, // private
	{v4(224, 0, 0, 0), 3},    // multicast, reserved, broadcast
}

// oracleSpecial are the IANA special-purpose blocks that NonPublic adds.
var oracleSpecial = []reservedRange{
	{v4(192, 0, 0, 0), 24},
	{v4(192, 0, 2, 0), 24},
	{v4(192, 88, 99, 0), 24},
	{v4(198, 18, 0, 0), 15},
	{v4(198, 51, 100, 0), 24},
	{v4(203, 0, 113, 0), 24},
}

// oracleInAny reports whether v lies in one of the blocks.
func oracleInAny(v uint32, blocks []reservedRange) bool {
	for _, r := range blocks {
		if inBlock(v, r) {
			return true
		}
	}
	return false
}

// isMappedRaw reports whether 16 bytes are an IPv4-mapped IPv6 address,
// ::ffff:a.b.c.d (ten zero bytes, then 0xff 0xff).
func isMappedRaw(raw [16]byte) bool {
	for i := 0; i < 10; i++ {
		if raw[i] != 0 {
			return false
		}
	}
	return raw[10] == 0xff && raw[11] == 0xff
}

// fuzzSeedAddrs are the starting points of the 16-byte corpus: IPv4, mapped
// IPv6 and plain IPv6 addresses from the boundaries of every block.
var fuzzSeedAddrs = []string{
	"0.0.0.0", "10.0.0.1", "100.63.255.255", "100.64.0.0", "127.0.0.1", "169.254.169.254",
	"172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0", "192.0.2.1", "192.167.255.255",
	"192.168.0.1", "192.169.0.0", "198.17.255.255", "198.18.0.1", "198.20.0.0", "223.255.255.255",
	"224.0.0.1", "240.0.0.1", "255.255.255.255", "8.8.8.8", "140.82.112.3",
	"::", "::1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "::ffff:192.0.2.1", "::ffff:0.0.0.0",
	"2606:4700::1111", "fe80::1", "64:ff9b::7f00:1", "::10.0.0.1",
}

// checkPolicy asserts Reserved and NonPublic on one address against the
// expected verdicts, that every refusal has a reason, and that NonPublic
// repeats Reserved's refusal with the same reason.
func checkPolicy(t *testing.T, a netip.Addr, wantReserved, wantNonPublic bool) (reason string) {
	t.Helper()
	reason, bad := Reserved(a)
	if bad != wantReserved {
		t.Fatalf("Reserved(%v) = %q, %v; oracle wants %v", a, reason, bad, wantReserved)
	}
	if bad != (reason != "") {
		t.Fatalf("Reserved(%v) = %q, %v: refusal and reason disagree", a, reason, bad)
	}
	npReason, npBad := NonPublic(a)
	if npBad != wantNonPublic {
		t.Fatalf("NonPublic(%v) = %q, %v; oracle wants %v", a, npReason, npBad, wantNonPublic)
	}
	if npBad != (npReason != "") {
		t.Fatalf("NonPublic(%v) = %q, %v: refusal and reason disagree", a, npReason, npBad)
	}
	if bad && (!npBad || npReason != reason) {
		t.Fatalf("NonPublic(%v) = %q, %v; must repeat Reserved reason %q", a, npReason, npBad, reason)
	}
	return reason
}

// FuzzReservedNonPublic reads 16 input bytes three ways: as a plain IPv4
// address (first four bytes), as an IPv4-mapped IPv6 address built from
// those four bytes, and as the full IPv6 address. It checks the verdict of
// Reserved and NonPublic against the oracles and that the functions do not
// panic.
func FuzzReservedNonPublic(f *testing.F) {
	for _, s := range fuzzSeedAddrs {
		a := netip.MustParseAddr(s)
		raw := a.As16()
		f.Add(raw[:])
		if a.Is4In6() {
			v4raw := a.Unmap().As4()
			prefixed := make([]byte, 16)
			copy(prefixed, v4raw[:])
			f.Add(prefixed)
		} else if a.Is4() {
			v4raw := a.As4()
			prefixed := make([]byte, 16)
			copy(prefixed, v4raw[:])
			f.Add(prefixed)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 16 {
			return
		}
		var raw [16]byte
		copy(raw[:], b[:16])

		// The IPv4 reading and the mapped reading of the first four bytes
		// must get the same verdict and the same reason.
		v4Bytes := [4]byte{raw[0], raw[1], raw[2], raw[3]}
		v4Addr := netip.AddrFrom4(v4Bytes)
		v := v4(v4Bytes[0], v4Bytes[1], v4Bytes[2], v4Bytes[3])
		wantRes := oracleInAny(v, oracleReserved)
		wantNP := wantRes || oracleInAny(v, oracleSpecial)
		v4Reason := checkPolicy(t, v4Addr, wantRes, wantNP)

		mappedRaw := [16]byte{10: 0xff, 11: 0xff}
		copy(mappedRaw[12:], v4Bytes[:])
		mapped := netip.AddrFrom16(mappedRaw)
		mappedReason := checkPolicy(t, mapped, wantRes, wantNP)
		if mappedReason != v4Reason {
			t.Fatalf("Reserved(%v) reason %q, IPv4 part %v reason %q", mapped, mappedReason, v4Addr, v4Reason)
		}

		// The full 16 bytes as IPv6: a mapped form is judged by its IPv4
		// part, every other IPv6 address is refused.
		v6 := netip.AddrFrom16(raw)
		if isMappedRaw(raw) {
			emb := v4(raw[12], raw[13], raw[14], raw[15])
			embRes := oracleInAny(emb, oracleReserved)
			checkPolicy(t, v6, embRes, embRes || oracleInAny(emb, oracleSpecial))
		} else {
			checkPolicy(t, v6, true, true)
		}
	})
}
