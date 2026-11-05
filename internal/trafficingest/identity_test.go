// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestExclusiveDropsValuesClaimedByTwoHosts(t *testing.T) {
	got := Exclusive(map[string]trafficstore.Identity{
		"a": {MACs: []string{"52:54:00:00:00:0A", "52:54:00:00:00:ff"}, Addrs: addrs("10.0.0.1", "10.0.0.99", "::ffff:10.0.0.11")},
		"b": {MACs: []string{"52:54:00:00:00:0b", "52:54:00:00:00:FF"}, Addrs: addrs("10.0.0.2", "10.0.0.99")},
		"c": {},
	})
	if a := got["a"]; !slices.Equal(a.MACs, []string{"52:54:00:00:00:0a"}) || !slices.Equal(a.Addrs, addrs("10.0.0.1", "10.0.0.11")) {
		t.Fatalf("a = %+v", a)
	}
	if b := got["b"]; !slices.Equal(b.MACs, []string{"52:54:00:00:00:0b"}) || !slices.Equal(b.Addrs, addrs("10.0.0.2")) {
		t.Fatalf("b = %+v", b)
	}
	if c, ok := got["c"]; !ok || len(c.MACs)+len(c.Addrs) != 0 {
		t.Fatalf("c = %+v %v", c, ok)
	}
}

func TestExclusiveDropsMalformedAndUnusable(t *testing.T) {
	got := Exclusive(map[string]trafficstore.Identity{
		"a": {
			MACs:  []string{"not-a-mac", "00:11:22:33:44:55:66:77", "52:54:00:00:00:0a", "52:54:00:00:00:0a"},
			Addrs: append(addrs("0.0.0.0", "127.0.0.1", "::1", "224.0.0.1", "fe80::1%eth0", "10.0.0.1", "10.0.0.1"), netip.Addr{}),
		},
	})["a"]
	if !slices.Equal(got.MACs, []string{"52:54:00:00:00:0a"}) {
		t.Fatalf("MACs = %v", got.MACs)
	}
	if !slices.Equal(got.Addrs, addrs("10.0.0.1", "fe80::1")) {
		t.Fatalf("Addrs = %v", got.Addrs)
	}
}

func TestExclusiveSameHostTwiceIsNotShared(t *testing.T) {
	// One host listing an address twice (two inventory endpoints) keeps it.
	got := Exclusive(map[string]trafficstore.Identity{"a": {Addrs: addrs("10.0.0.1", "10.0.0.1")}})
	if !slices.Equal(got["a"].Addrs, addrs("10.0.0.1")) {
		t.Fatalf("Addrs = %v", got["a"].Addrs)
	}
}
