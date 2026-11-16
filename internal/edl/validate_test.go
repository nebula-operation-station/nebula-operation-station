// SPDX-License-Identifier: AGPL-3.0-or-later

package edl

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// pfx parses a CIDR or a bare address (a host entry) for test tables.
// It panics on malformed test input; it is test-only.
func pfx(s string) netip.Prefix {
	if strings.Contains(s, "/") {
		return netip.MustParsePrefix(s)
	}
	a := netip.MustParseAddr(s)
	return netip.PrefixFrom(a, a.BitLen())
}

// testRefusals uses public test ranges so that only the injected sets decide.
func testRefusals() Refusals {
	return Refusals{
		IPAM:              []netip.Prefix{pfx("81.10.0.0/24")},
		NOSPath:           []netip.Prefix{pfx("81.20.0.5/32")},
		FirewallAddresses: []netip.Prefix{pfx("81.30.0.1/32")},
		ProtectedTargets:  []netip.Prefix{pfx("81.40.0.0/16")},
	}
}

// TestCheckRefusals covers every refusal reason with a case just inside and
// just outside the refused range, plus containment in both directions.
func TestCheckRefusals(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  error
	}{
		// Public space stays allowed.
		{"public v4 allowed", "80.255.255.255/32", nil},
		{"public v4 neighbour of IPAM allowed", "81.10.1.0/24", nil},
		{"public v6 allowed", "2606:4700::1111", nil},

		// Special and private ranges (table in validate.go).
		{"10/8 refused", "10.0.0.0/8", ErrSpecialRange},
		{"10/8 last address refused", "10.255.255.255", ErrSpecialRange},
		{"just below 10/8 allowed", "9.255.255.255", nil},
		{"just above 10/8 allowed", "11.0.0.0", nil},
		{"0.0.0.0/0 contains special refused", "0.0.0.0/0", ErrSpecialRange},
		{"CGNAT 100.64/10 refused", "100.64.0.0/10", ErrSpecialRange},
		{"just below CGNAT allowed", "100.63.255.255", nil},
		{"just above CGNAT allowed", "100.128.0.0", nil},
		{"172.16/12 first refused", "172.16.0.0", ErrSpecialRange},
		{"172.16/12 last refused", "172.31.255.255", ErrSpecialRange},
		{"just below 172.16/12 allowed", "172.15.255.255", nil},
		{"just above 172.16/12 allowed", "172.32.0.0", nil},
		{"192.168/16 refused", "192.168.7.0/24", ErrSpecialRange},
		{"just below 192.168/16 allowed", "192.167.255.255", nil},
		{"multicast 224/4 refused", "224.0.0.0", ErrSpecialRange},
		{"just below multicast allowed", "223.255.255.255", nil},
		{"reserved 240/4 refused", "240.0.0.0/4", ErrSpecialRange},
		{"broadcast refused", "255.255.255.255", ErrSpecialRange},
		{"IPv6 unspecified refused", "::", ErrSpecialRange},
		{"IPv6 loopback refused", "::1", ErrSpecialRange},
		{"IPv4-mapped refused", "::ffff:81.0.1.5", ErrSpecialRange},
		{"ULA fc00::/7 refused", "fd00::1", ErrSpecialRange},
		{"just below ULA allowed", "fbff::1", nil},
		{"just above ULA allowed", "fe00::1", nil},
		{"link-local fe80::/10 refused", "fe80::1", ErrSpecialRange},
		{"link-local last address refused", "febf::1", ErrSpecialRange},
		{"documentation 2001:db8::/32 refused", "2001:db8::1", ErrSpecialRange},
		{"2001:4860 allowed", "2001:4860::1", nil},
		{"ff00::/8 multicast refused", "ff02::1", ErrSpecialRange},

		// Overlap in both directions: entry contains a refused range, or lies inside it.
		{"IPAM: entry contains IPAM net refused", "81.10.0.0/16", ErrIPAMNetwork},
		{"IPAM: entry inside IPAM net refused", "81.10.0.128/25", ErrIPAMNetwork},
		{"IPAM: last address refused", "81.10.0.255", ErrIPAMNetwork},
		{"IPAM: just below allowed", "81.9.255.255", nil},
		{"IPAM: just above allowed", "81.10.1.0", nil},
		{"NOS path: entry contains address refused", "81.20.0.4/31", ErrNOSPath},
		{"NOS path: host refused", "81.20.0.5", ErrNOSPath},
		{"NOS path: neighbour allowed", "81.20.0.6", nil},
		{"firewall: containing /24 refused", "81.30.0.0/24", ErrFirewallAddress},
		{"firewall: host refused", "81.30.0.1", ErrFirewallAddress},
		{"firewall: neighbour allowed", "81.30.0.2", nil},
		{"protected: containing /15 refused", "81.40.0.0/15", ErrProtectedTarget},
		{"protected: inside /16 refused", "81.40.200.0/24", ErrProtectedTarget},
		{"protected: just below allowed", "81.39.255.255", nil},
		{"protected: just above allowed", "81.41.0.0/16", nil},

		// Malformed input is refused, never passed through.
		{"zero prefix invalid", "", ErrInvalidEntry},
	}
	r := testRefusals()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry netip.Prefix
			if tt.entry != "" {
				entry = pfx(tt.entry)
			}
			err := Check(entry, r)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("Check(%v) = %v, want nil", entry, err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Check(%v) = %v, want %v", entry, err, tt.want)
			}
		})
	}
}

// TestCheckRefusalOrderIsStable confirms an entry in several refused sets is
// reported with one reason, the special-range reason first.
func TestCheckRefusalOrderIsStable(t *testing.T) {
	r := Refusals{IPAM: []netip.Prefix{pfx("10.1.0.0/16")}}
	if err := Check(pfx("10.1.0.0/16"), r); !errors.Is(err, ErrSpecialRange) {
		t.Fatalf("Check = %v, want ErrSpecialRange first", err)
	}
}

// TestCheckFailsClosedOnInvalidRefusal ensures a broken refusal set cannot
// silently stop refusing anything.
func TestCheckFailsClosedOnInvalidRefusal(t *testing.T) {
	r := Refusals{ProtectedTargets: []netip.Prefix{{}}}
	if err := Check(pfx("80.0.0.1"), r); !errors.Is(err, ErrInvalidRefusal) {
		t.Fatalf("Check = %v, want ErrInvalidRefusal", err)
	}
}

// TestCheckMasksEntry confirms an entry with host bits set is judged by its
// network, so 81.10.0.9/24 is refused as part of the IPAM network.
func TestCheckMasksEntry(t *testing.T) {
	if err := Check(pfx("81.10.0.9/24"), testRefusals()); !errors.Is(err, ErrIPAMNetwork) {
		t.Fatalf("Check = %v, want ErrIPAMNetwork", err)
	}
}
