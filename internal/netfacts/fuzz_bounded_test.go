// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// oracleAddr checks a stored address independently of parseHostAddr:
// valid, a zone only of [A-Za-z0-9._@-] and at most 15 bytes, and a
// bounded rendered length.
func oracleAddr(t *testing.T, what string, a netip.Addr) {
	t.Helper()
	z := a.Zone()
	if len(z) > 15 {
		t.Fatalf("%s zone is %d bytes", what, len(z))
	}
	for i := 0; i < len(z); i++ {
		c := z[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' || c == '@'
		if !ok {
			t.Fatalf("%s zone %q contains byte %#x", what, z, c)
		}
	}
	if n := len(a.String()); n > 64 {
		t.Fatalf("%s renders as %d bytes", what, n)
	}
}

// oracleIfName checks a stored device name independently of validIfName:
// 1..15 bytes from [A-Za-z0-9._@-].
func oracleIfName(t *testing.T, what, s string) {
	t.Helper()
	if s == "" || len(s) > 15 {
		t.Fatalf("%s %q has %d bytes", what, s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' || c == '@'
		if !ok {
			t.Fatalf("%s %q contains byte %#x", what, s, c)
		}
	}
}

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
	f.Add([]byte(`[{"dst":"10.0.0.1","dev":"eth0"}]`))
	f.Add([]byte(`[{"dst":"fe80::1","dev":"eth0","lladdr":"aa:bb:cc:dd:ee:ff","state":["REACHABLE"]}]`))
	f.Add([]byte(`[{"dst":"fe80::1%eth0","dev":"eth0"},{"dst":"fe80::2%\u001b[0m\n","dev":"eth0"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseNeigh(b)
		if err != nil {
			return
		}
		ns := res.Entries
		if len(ns) > 1000 {
			t.Fatalf("neighbor list has %d entries, bound is 1000", len(ns))
		}
		if res.Dropped < 0 || (res.Dropped > 0 && !res.Incomplete) {
			t.Fatalf("Dropped=%d with Incomplete=%v", res.Dropped, res.Incomplete)
		}
		for _, n := range ns {
			if !n.IP.IsValid() {
				t.Fatalf("neighbor carries invalid IP %v", n.IP)
			}
			oracleAddr(t, "neighbor IP", n.IP)
			oracleIfName(t, "neighbor dev", n.Dev)
			if len(n.MAC) != 0 && len(n.MAC) != 6 {
				t.Fatalf("neighbor MAC has %d bytes, want 0 or 6", len(n.MAC))
			}
			if len(n.State) > maxStates {
				t.Fatalf("neighbor has %d states, bound is %d", len(n.State), maxStates)
			}
			for _, s := range n.State {
				switch s {
				case "INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "NOARP", "PERMANENT", "NONE":
				default:
					t.Fatalf("neighbor state %q is not a NUD state name", s)
				}
			}
		}
	})
}

// oracleViaHosts returns the addresses named by a "via" host anywhere in
// the route document (top-level or inside a "nexthops" list), decoded
// independently of ParseRoutes. Only such an address may be an IPv6
// gateway of an IPv4 destination (RFC 5549).
func oracleViaHosts(b []byte) map[netip.Addr]bool {
	type via struct {
		Host string `json:"host"`
	}
	var elems []json.RawMessage
	if json.Unmarshal(b, &elems) != nil {
		return nil
	}
	hosts := map[netip.Addr]bool{}
	add := func(v *via) {
		if v == nil {
			return
		}
		if a, err := netip.ParseAddr(v.Host); err == nil {
			hosts[a] = true
		}
	}
	for _, e := range elems {
		var d struct {
			Via      *via `json:"via"`
			Nexthops []struct {
				Via *via `json:"via"`
			} `json:"nexthops"`
		}
		if json.Unmarshal(e, &d) != nil {
			continue
		}
		add(d.Via)
		for i := range d.Nexthops {
			add(d.Nexthops[i].Via)
		}
	}
	return hosts
}

// FuzzParseRoutesBounds checks the hard bounds of ParseRoutes on arbitrary
// input: no panic, bounded entry count, every returned field within its
// documented limits.
func FuzzParseRoutesBounds(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("debian12-route.json", "ubuntu2404-route.json", "ipv6-route.json", "ipv6-multipath-route.json", "rfc5549-route.json", "empty-route.json") {
		f.Add(s)
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[{"dst":"default","gateway":"10.0.0.1","dev":"eth0","metric":100}]`))
	f.Add([]byte(`[{"dst":"default","gateway":"fe80::1","dev":"eth0"}]`))
	f.Add([]byte(`[{"dst":"10.0.0.1","dev":"eth0"},{"dst":"fe80::1%eth0","dev":"eth0"}]`))
	f.Add([]byte(`[{"dst":"default","nexthops":[{"gateway":"fe80::1","dev":"eth0"},{"gateway":"fe80::2","dev":"eth1"}]}]`))
	f.Add([]byte(`[{"dst":"default","gateway":"fe80::1%eth0","dev":"eth0"},{"dst":"default","gateway":"fe80::2%\u202e","dev":"eth0"}]`))
	f.Add([]byte(`[{"dst":"10.0.0.0/24","dev":"eth0"},{"dst":"default","nexthops":[{"via":{"family":"inet6","host":"fe80::1%eth0"},"dev":"eth0"},{"gateway":"10.0.0.1","dev":"eth1"}]},{"dst":"10.1.0.0/24","via":{"family":"inet","host":"10.0.0.2"},"dev":"eth0"}]`))
	f.Add([]byte(`[{"dst":"2001:db8::/64","dev":"eth0"},{"dst":"default","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"},{"dst":"2001:db8:1::/48","via":{"family":"inet","host":"10.0.0.1"},"dev":"eth0"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseRoutes(b)
		if err != nil {
			return
		}
		rs := res.Entries
		var viaHosts map[netip.Addr]bool
		if len(rs) > 1000 {
			t.Fatalf("route list has %d entries, bound is 1000", len(rs))
		}
		if res.Dropped < 0 || res.Incomplete != (res.Dropped > 0) {
			t.Fatalf("Dropped=%d with Incomplete=%v", res.Dropped, res.Incomplete)
		}
		for _, r := range rs {
			if !r.Dst.IsValid() {
				t.Fatalf("route carries invalid dst %v", r.Dst)
			}
			if !r.Gateway.IsValid() && r.Gateway != (netip.Addr{}) {
				t.Fatalf("route gateway %v is neither valid nor the zero address", r.Gateway)
			}
			oracleAddr(t, "route gateway", r.Gateway)
			if r.Gateway.IsValid() && r.Gateway.Is4() != r.Dst.Addr().Is4() {
				// The only accepted family mix is RFC 5549: an IPv6
				// gateway for an IPv4 dst, and only from a "via".
				if r.Gateway.Is4() || !r.Dst.Addr().Is4() {
					t.Fatalf("route gateway %v family differs from dst %v", r.Gateway, r.Dst)
				}
				if viaHosts == nil {
					viaHosts = oracleViaHosts(b)
				}
				if !viaHosts[r.Gateway] {
					t.Fatalf("route gateway %v for IPv4 dst %v did not come from a via", r.Gateway, r.Dst)
				}
			}
			oracleIfName(t, "route dev", r.Dev)
			if z := r.Dst.Addr().Zone(); z != "" {
				t.Fatalf("route dst %v carries zone %q", r.Dst, z)
			}
		}
	})
}
