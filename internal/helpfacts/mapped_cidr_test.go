// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"reflect"
	"testing"
)

// TestIPv4MappedCIDRCannotBypassTheMinimumPrefix covers IPv6 blocks that
// contain the IPv4-mapped range. net.IPNet treats ::ffff:0.0.0.0/96 as an
// IPv4 /0, so a 128-bit prefix check alone let it select every IPv4 host.
func TestIPv4MappedCIDRCannotBypassTheMinimumPrefix(t *testing.T) {
	for _, q := range []string{
		"::ffff:0.0.0.0/96",   // the whole mapped range: IPv4 /0
		"::ffff:0:0/80",       // covers the mapped range, broader than /96
		"::/32",               // an IPv6 block that contains every mapped address
		"::ffff:10.0.0.0/104", // IPv4 /8, below the IPv4 minimum of /16
	} {
		lits, truncated := parseLiterals("what about " + q + "?")
		for _, l := range lits {
			if l.kind == litCIDR || l.kind == litAddress {
				t.Fatalf("%s: broad block became literal %s", q, l.key())
			}
		}
		if !truncated {
			t.Fatalf("%s: truncated = false, want true", q)
		}
	}
}

// TestIPv4MappedCIDRSelectsItsIPv4Block checks that a mapped block that is
// narrow enough is read as the IPv4 block it names, and selects only the
// IPv4 hosts inside it.
func TestIPv4MappedCIDRSelectsItsIPv4Block(t *testing.T) {
	lits, truncated := parseLiterals("hosts in ::ffff:10.1.0.0/112?")
	if truncated {
		t.Fatal("narrow mapped block must not be refused")
	}
	var cidrs []string
	for _, l := range lits {
		if l.kind == litCIDR {
			cidrs = append(cidrs, l.network.String())
		}
	}
	if !reflect.DeepEqual(cidrs, []string{"10.1.0.0/16"}) {
		t.Fatalf("mapped block CIDR literals = %v, want [10.1.0.0/16]", cidrs)
	}

	src := fakeSource{hosts: []Record{
		baseRecord("lan-in", "lan-in", "10.1.5.5"),
		baseRecord("lan-out", "lan-out", "10.2.0.1"),
		baseRecord("lan-v6", "lan-v6", "2001:db8::1"),
	}}
	vis := visibleOnly("lan-in", "lan-out", "lan-v6")
	res := mustProject(t, request("hosts in ::ffff:10.1.0.0/112?", src, vis))
	if got := hostIDs(res); !reflect.DeepEqual(got, []string{"lan-in"}) {
		t.Fatalf("mapped block hosts = %v, want [lan-in]", got)
	}

	res = mustProject(t, request("which hosts are in ::ffff:0.0.0.0/96?", src, vis))
	if len(res.Hosts) != 0 || !res.Truncated {
		t.Fatalf("mapped all-hosts block projected %v (truncated=%v)", hostIDs(res), res.Truncated)
	}
}
