// SPDX-License-Identifier: AGPL-3.0-or-later

package netpolicy

import (
	"net/netip"
	"testing"
)

// reservedAddrs must be refused by Reserved (and therefore NonPublic).
var reservedAddrs = []string{
	"0.0.0.0", "0.1.2.3", // this network
	"10.0.0.1", "10.255.255.255", // private
	"127.0.0.1", "127.255.255.254", // loopback
	"169.254.169.254", "169.254.0.1", // link-local incl. metadata
	"100.64.0.1", "100.127.255.255", // CGNAT
	"172.16.0.1", "172.31.255.255", // private
	"192.168.0.1", "192.168.255.255", // private
	"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", // multicast / reserved / broadcast
	"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:224.0.0.1", // IPv4-mapped
	"::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", // IPv6 unspecified, loopback, link-local, ULA, multicast
	"::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001::1", "2001:db8::1", // IPv4-compatible, NAT64, 6to4, Teredo, documentation
	"2606:4700::1111", // public IPv6: every non-mapped IPv6 address is reserved
}

// specialAddrs are refused by NonPublic only.
var specialAddrs = []string{
	"192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1",
	"::ffff:192.0.2.1",
}

// publicAddrs are accepted by both, including the neighbours of every
// reserved range.
var publicAddrs = []string{
	"1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0", "126.255.255.255", "128.0.0.0",
	"100.63.255.255", "100.128.0.0", "169.253.255.255", "169.255.0.0",
	"172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0",
	"192.0.1.0", "192.88.98.255", "198.17.255.255", "198.20.0.0", "223.255.255.255",
	"140.82.112.3", "::ffff:140.82.112.3",
}

func TestReserved(t *testing.T) {
	for _, s := range reservedAddrs {
		if reason, bad := Reserved(netip.MustParseAddr(s)); !bad || reason == "" {
			t.Errorf("Reserved(%s) = %q, %v; want reserved with reason", s, reason, bad)
		}
	}
	for _, s := range append(append([]string(nil), specialAddrs...), publicAddrs...) {
		if reason, bad := Reserved(netip.MustParseAddr(s)); bad {
			t.Errorf("Reserved(%s) = %q, true; want not reserved", s, reason)
		}
	}
	if _, bad := Reserved(netip.Addr{}); !bad {
		t.Error("zero Addr must be reserved")
	}
}

func TestNonPublicIsSupersetOfReserved(t *testing.T) {
	for _, s := range append(append([]string(nil), reservedAddrs...), specialAddrs...) {
		if reason, bad := NonPublic(netip.MustParseAddr(s)); !bad || reason == "" {
			t.Errorf("NonPublic(%s) = %q, %v; want refused with reason", s, reason, bad)
		}
	}
	for _, s := range publicAddrs {
		if reason, bad := NonPublic(netip.MustParseAddr(s)); bad {
			t.Errorf("NonPublic(%s) = %q, true; want public", s, reason)
		}
	}
	if _, bad := NonPublic(netip.Addr{}); !bad {
		t.Error("zero Addr must be non-public")
	}
	// Reserved reasons pass through unchanged.
	for _, s := range reservedAddrs {
		a := netip.MustParseAddr(s)
		r1, _ := Reserved(a)
		r2, _ := NonPublic(a)
		if r1 != r2 {
			t.Errorf("%s: NonPublic reason %q, Reserved reason %q", s, r2, r1)
		}
	}
}

func TestIsHostname(t *testing.T) {
	for _, s := range []string{"a", "example.com", "Example.COM", "a-b.c-d.e", "x1.y2", "1a.example", "avatars.githubusercontent.com"} {
		if !IsHostname(s) {
			t.Errorf("IsHostname(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"", ".", "example.com.", ".example.com", "-a.example", "a-.example", "a..b",
		"exa_mple.com", "exa mple.com", "ex%41mple.com", "例え.jp", "a/b", "a:443",
		"127.0.0.1", "2130706433", "0x7f000001", "0x7f.1", "017700000001", "127.1", "1.2.3", // numeric forms
	} {
		if IsHostname(s) {
			t.Errorf("IsHostname(%q) = true, want false", s)
		}
	}
	long := ""
	for range 64 {
		long += "a"
	}
	if IsHostname(long + ".example") {
		t.Error("64-character label accepted")
	}
}
