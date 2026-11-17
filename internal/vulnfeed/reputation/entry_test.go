// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"errors"
	"net/netip"
	"testing"
)

// TestParseEntryNormalises checks the accepted entry spellings and their
// normal form: a bare address becomes a host prefix and host bits are
// masked, so every entry is the network it names.
func TestParseEntryNormalises(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"ipv4 prefix", "192.0.2.0/24", "192.0.2.0/24"},
		{"ipv4 bare address is host prefix", "192.0.2.7", "192.0.2.7/32"},
		{"ipv4 host bits masked", "192.0.2.7/24", "192.0.2.0/24"},
		{"ipv6 prefix", "2001:db8::/32", "2001:db8::/32"},
		{"ipv6 bare address is host prefix", "2001:db8::1", "2001:db8::1/128"},
		{"ipv6 upper case canonicalised", "2001:DB8:0:0::1", "2001:db8::1/128"},
		{"ipv6 host bits masked", "2001:db8::1/32", "2001:db8::/32"},
		{"surrounding blanks trimmed", " \t198.51.100.0/24 \t", "198.51.100.0/24"},
		{"shortest non default ipv4 prefix masked", "203.0.113.0/1", "128.0.0.0/1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEntry(tc.in)
			if err != nil {
				t.Fatalf("ParseEntry(%q): %v", tc.in, err)
			}
			if got.String() != tc.want {
				t.Errorf("ParseEntry(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseEntryRejects covers every malformed spelling that must stop a
// feed: it is untrusted input and each form below either has no single
// network meaning or would widen an entry past what the feed named.
func TestParseEntryRejects(t *testing.T) {
	for _, tc := range []struct {
		name, in string
	}{
		{"empty", ""},
		{"blank only", "   "},
		{"text", "not-an-address"},
		{"trailing text", "192.0.2.1 listed"},
		{"two slashes", "192.0.2.0/24/1"},
		{"empty length", "192.0.2.0/"},
		{"negative length", "192.0.2.0/-1"},
		{"ipv4 length too long", "192.0.2.0/33"},
		{"ipv6 length too long", "2001:db8::/129"},
		{"ipv4 default route", "0.0.0.0/0"},
		{"ipv6 default route", "::/0"},
		{"octet out of range", "192.0.2.256"},
		{"ipv4-mapped ipv6 form", "::ffff:192.0.2.1/120"},
		{"ipv6 zone", "fe80::1%eth0"},
		{"non ascii digits", "١٩٢.0.2.1"},
		{"embedded nul", "192.0.2.1\x00"},
		{"longer than any address prefix", "2001:0db8:0000:0000:0000:0000:0000:0001/128x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEntry(tc.in)
			if err == nil {
				t.Fatalf("ParseEntry(%q) = %s, want error", tc.in, got)
			}
			if !errors.Is(err, ErrMalformedEntry) {
				t.Errorf("ParseEntry(%q) error = %v, want ErrMalformedEntry", tc.in, err)
			}
		})
	}
}

// TestParseEntryTextLimit tests the text limit of one entry at the limit
// and one byte past it. An entry is at most one IPv6 prefix in full
// spelling plus the length, which is maxEntryTextBytes bytes.
func TestParseEntryTextLimit(t *testing.T) {
	atLimit := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
	if len(atLimit) != maxEntryTextBytes {
		t.Fatalf("test input is %d bytes, want %d", len(atLimit), maxEntryTextBytes)
	}
	if _, err := ParseEntry(atLimit); err != nil {
		t.Errorf("ParseEntry at the text limit: %v", err)
	}
	if _, err := ParseEntry(atLimit + "0"); !errors.Is(err, ErrMalformedEntry) {
		t.Errorf("ParseEntry one byte past the text limit: error %v, want ErrMalformedEntry", err)
	}
}

// TestParseEntryResultIsAlwaysNormal guards the invariant the matcher and
// the uploader rely on: a successful result is valid, masked and not an
// IPv4-mapped IPv6 address.
func TestParseEntryResultIsAlwaysNormal(t *testing.T) {
	for _, in := range []string{"192.0.2.9/31", "2001:db8:1::5/64", "198.51.100.200"} {
		p, err := ParseEntry(in)
		if err != nil {
			t.Fatalf("ParseEntry(%q): %v", in, err)
		}
		if !p.IsValid() || p.Masked() != p || p.Addr().Is4In6() {
			t.Errorf("ParseEntry(%q) = %s, not a normal prefix", in, p)
		}
	}
	var zero netip.Prefix
	if zero.IsValid() {
		t.Fatal("zero prefix unexpectedly valid")
	}
}
