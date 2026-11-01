// SPDX-License-Identifier: AGPL-3.0-or-later

package invsort_test

import (
	"sort"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/invsort"
)

func TestLess(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool // Less(a, b)
	}{
		// Numeric per octet, not lexicographic.
		{"ipv4 octet", "192.168.0.25", "192.168.0.221", true},
		{"ipv4 octet reversed", "192.168.0.221", "192.168.0.25", false},
		{"ipv4 single vs double digit", "10.0.0.9", "10.0.0.10", true},
		{"ipv4 high octet", "10.0.0.200", "10.0.0.100", false},
		{"ipv4 first octet", "9.0.0.1", "10.0.0.1", true},
		// IPv6 compares numerically per group.
		{"ipv6 group", "2001:db8::1", "2001:db8::2", true},
		{"ipv6 group reversed", "2001:db8::2", "2001:db8::1", false},
		{"ipv6 wider group", "2001:db8::10", "2001:db8::f", false},
		{"ipv6 leading group", "2001:db8::1", "2001:db9::1", true},
		{"ipv6 case-insensitive", "2001:DB8::1", "2001:db8::1", false},
		{"ipv6 equal", "2001:db8::1", "2001:db8::1", false},
		// IPv4 before IPv6; IPs before non-IPs.
		{"ipv4 before ipv6", "10.0.0.1", "2001:db8::1", true},
		{"ipv6 after ipv4", "2001:db8::1", "10.0.0.1", false},
		{"ip before hostname", "10.0.0.1", "node1", true},
		{"hostname after ip", "node1", "10.0.0.1", false},
		// Natural order: digit runs as numbers, case-insensitive.
		{"natural node2 before node10", "node2", "node10", true},
		{"natural node10 after node2", "node10", "node2", false},
		{"natural case-insensitive", "Alpha", "beta", true},
		{"natural equal ignoring case", "alpha", "ALPHA", false},
		{"natural prefix first", "node", "node1", true},
		{"natural digit before letter", "node1", "nodea", true},
		{"natural leading zeros", "node007", "node8", true},
		{"natural equal digits", "node007", "node07", false},
		// Mixed comparisons.
		{"mixed ip natural", "192.168.0.25", "node10", true},
		{"mixed ipv6 natural", "2001:db8::1", "web-01", true},
		// Not IPs: ports and extra text stay in natural order.
		{"port is not an ip", "10.0.0.1:22", "10.0.0.2", false},
		{"ip with suffix is not an ip", "10.0.0.1x", "10.0.0.2", false},
		{"empty first", "", "node1", true},
		{"empty second", "node1", "", false},
		{"both empty", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := invsort.Less(tc.a, tc.b); got != tc.want {
				t.Errorf("Less(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestLessIsStrictWeakOrdering checks antisymmetry and the ordering
// properties on a mixed bag of names, so sort.Slice never sees a
// comparator it cannot handle.
func TestLessIsStrictWeakOrdering(t *testing.T) {
	names := []string{
		"192.168.0.25", "192.168.0.221", "10.0.0.9", "10.0.0.10",
		"2001:db8::1", "2001:db8::2", "2001:db9::1",
		"node2", "node10", "node002", "Alpha", "ALPHA", "alpha",
		"web-01", "web-1", "10.0.0.1:22", "", "0.0.0.0", "255.255.255.255",
		"::", "::1", "fe80::1", "172.16.0.1",
	}
	for _, a := range names {
		for _, b := range names {
			if invsort.Less(a, a) {
				t.Errorf("Less(%q, %q) must be false (irreflexivity)", a, a)
			}
			if invsort.Less(a, b) && invsort.Less(b, a) {
				t.Errorf("Less(%q, %q) and Less(%q, %q) both true (antisymmetry)", a, b, b, a)
			}
		}
	}
}

// TestSortInventoryNames checks the full ordering the inventory table
// gets: IPs numerically (IPv4 first), then hostnames naturally.
func TestSortInventoryNames(t *testing.T) {
	in := []string{
		"192.168.0.221", "node10", "192.168.0.25", "2001:db8::1",
		"node2", "10.0.0.9", "Alpha", "10.0.0.10", "192.168.1.5",
	}
	sort.SliceStable(in, func(i, j int) bool { return invsort.Less(in[i], in[j]) })
	want := []string{
		"10.0.0.9", "10.0.0.10", "192.168.0.25", "192.168.0.221",
		"192.168.1.5", "2001:db8::1", "Alpha", "node2", "node10",
	}
	for i := range want {
		if in[i] != want[i] {
			t.Fatalf("sorted[%d] = %q, want %q (full: %v)", i, in[i], want[i], in)
		}
	}
}
