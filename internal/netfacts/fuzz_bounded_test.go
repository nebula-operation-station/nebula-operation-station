// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// netfactsFuzzSeeds loads the named testdata fixtures as fuzz seeds so the
// corpus starts from realistic `ip -j ...` documents.
func netfactsFuzzSeeds(names ...string) [][]byte {
	seeds := make([][]byte, 0, len(names))
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			panic(err)
		}
		seeds = append(seeds, b)
	}
	return seeds
}

// FuzzParseNeighBounds checks the hard bounds of ParseNeigh on arbitrary
// input: no panic, bounded entry count, every returned field within its
// documented limits.
func FuzzParseNeighBounds(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("debian12-neigh.json", "ubuntu2404-neigh.json", "empty-neigh.json") {
		f.Add(s)
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[{"ip":"10.0.0.1","dev":"eth0"}]`))
	f.Add([]byte(`[{"ip":"fe80::1","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		ns, err := ParseNeigh(b)
		if err != nil {
			return
		}
		if len(ns) > maxEntries {
			t.Fatalf("neighbor list has %d entries, bound is %d", len(ns), maxEntries)
		}
		for _, n := range ns {
			if !n.IP.IsValid() {
				t.Fatalf("neighbor carries invalid IP %v", n.IP)
			}
			if !printable(n.Dev, maxStringLen) {
				t.Fatalf("neighbor dev %q violates its bounds", n.Dev)
			}
			if len(n.MAC) != 0 && len(n.MAC) != 6 {
				t.Fatalf("neighbor MAC has %d bytes, want 0 or 6", len(n.MAC))
			}
			if len(n.State) > maxStates {
				t.Fatalf("neighbor has %d states, bound is %d", len(n.State), maxStates)
			}
			for _, s := range n.State {
				if !printable(s, maxStringLen) {
					t.Fatalf("neighbor state %q violates its bounds", s)
				}
			}
		}
	})
}

// FuzzParseRoutesBounds checks the hard bounds of ParseRoutes on arbitrary
// input: no panic, bounded entry count, every returned field within its
// documented limits.
func FuzzParseRoutesBounds(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("debian12-route.json", "ubuntu2404-route.json", "ipv6-route.json", "empty-route.json") {
		f.Add(s)
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100}]`))
	f.Add([]byte(`[{"dst":"default","gateway":"fe80::1","dev":"eth0"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		rs, err := ParseRoutes(b)
		if err != nil {
			return
		}
		if len(rs) > maxEntries {
			t.Fatalf("route list has %d entries, bound is %d", len(rs), maxEntries)
		}
		for _, r := range rs {
			if !r.Dst.IsValid() {
				t.Fatalf("route carries invalid dst %v", r.Dst)
			}
			if !r.Gateway.IsValid() && r.Gateway != (netip.Addr{}) {
				t.Fatalf("route gateway %v is neither valid nor the zero address", r.Gateway)
			}
			if !printable(r.Dev, maxStringLen) {
				t.Fatalf("route dev %q violates its bounds", r.Dev)
			}
			if r.Metric < 0 || r.Metric > maxMetric {
				t.Fatalf("route metric %d outside [0, %d]", r.Metric, maxMetric)
			}
		}
	})
}
