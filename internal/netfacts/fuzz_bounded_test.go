// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

// oracleRouteEntry is one route document element decoded independently
// of ParseRoutes: its raw "dst" text and the addresses named by a "via"
// host of that element (top-level or inside its "nexthops" list).
type oracleRouteEntry struct {
	dst string
	via map[netip.Addr]bool
}

// oracleRouteEntries decodes the route document element by element.
// Only an address from the element's own "via" fields may be an IPv6
// gateway of an IPv4 destination (RFC 5549); collecting the "via" hosts
// of the whole document would credit a plain "gateway" of one element
// from the "via" of another.
func oracleRouteEntries(b []byte) []oracleRouteEntry {
	var elems []json.RawMessage
	if json.Unmarshal(b, &elems) != nil {
		return nil
	}
	entries := make([]oracleRouteEntry, 0, len(elems))
	for _, e := range elems {
		var d struct {
			Dst string `json:"dst"`
			Via *struct {
				Host string `json:"host"`
			} `json:"via"`
			Nexthops []struct {
				Via *struct {
					Host string `json:"host"`
				} `json:"via"`
			} `json:"nexthops"`
		}
		if json.Unmarshal(e, &d) != nil {
			continue
		}
		oe := oracleRouteEntry{dst: d.Dst, via: map[netip.Addr]bool{}}
		add := func(h string) {
			if a, err := netip.ParseAddr(h); err == nil {
				oe.via[a] = true
			}
		}
		if d.Via != nil {
			add(d.Via.Host)
		}
		for i := range d.Nexthops {
			if d.Nexthops[i].Via != nil {
				add(d.Nexthops[i].Via.Host)
			}
		}
		entries = append(entries, oe)
	}
	return entries
}

// entryProducesDst reports whether a document element with the raw "dst"
// text s can produce the destination p, mirroring parseDst: "default"
// produces 0.0.0.0/0 or ::/0, an address its /32 or /128, and anything
// else must parse as that prefix.
func entryProducesDst(s string, p netip.Prefix) bool {
	if s == "default" {
		return p == defaultRouteV4 || p == defaultRouteV6
	}
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return false
		}
		return p == netip.PrefixFrom(a, a.BitLen())
	}
	q, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	return p == q
}

// entriesCreditGateway reports whether the gateway gw of a route to
// destination dst may have come from a "via" of an element that
// produces dst.
func entriesCreditGateway(entries []oracleRouteEntry, dst netip.Prefix, gw netip.Addr) bool {
	for _, e := range entries {
		if e.via[gw] && entryProducesDst(e.dst, dst) {
			return true
		}
	}
	return false
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
	f.Add([]byte(`[{"dst":"10.0.0.0/8","dev":"eth0"},{"dst":"default","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"},{"dst":"10.0.0.0/24","gateway":"fe80::1","dev":"eth0"}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseRoutes(b)
		if err != nil {
			return
		}
		rs := res.Entries
		var entries []oracleRouteEntry
		var haveEntries bool
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
				// The "via" must belong to the very element that
				// produced this route, not to another element of the
				// document.
				if !haveEntries {
					entries = oracleRouteEntries(b)
					haveEntries = true
				}
				if !entriesCreditGateway(entries, r.Dst, r.Gateway) {
					t.Fatalf("route gateway %v for IPv4 dst %v did not come from a via of its own element", r.Gateway, r.Dst)
				}
			}
			oracleIfName(t, "route dev", r.Dev)
			if z := r.Dst.Addr().Zone(); z != "" {
				t.Fatalf("route dst %v carries zone %q", r.Dst, z)
			}
		}
	})
}

// TestOracleViaHostsPerEntry pins the per-entry semantics of the fuzz
// oracle: an address named by a "via" of one element must not credit a
// plain "gateway" of another element with the same address.
func TestOracleViaHostsPerEntry(t *testing.T) {
	// Element 1 names fe80::1 as a "via" host; element 2 uses the same
	// address as a plain "gateway" for an IPv4 destination, which
	// ParseRoutes drops (RFC 5549 only from a "via").
	doc := []byte(`[{"dst":"default","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"},{"dst":"10.0.0.0/24","gateway":"fe80::1","dev":"eth0"}]`)
	entries := oracleRouteEntries(doc)
	if len(entries) != 2 {
		t.Fatalf("decoded %d elements, want 2", len(entries))
	}
	gw := netip.MustParseAddr("fe80::1")
	// The default route to 0.0.0.0/0 may carry the gateway: its own
	// element names it as a "via".
	if !entriesCreditGateway(entries, defaultRouteV4, gw) {
		t.Fatal("oracle does not credit the via of the default element itself")
	}
	// The 10.0.0.0/24 route may not: its element has no "via", and the
	// whole-document collection would have credited it wrongly.
	if entriesCreditGateway(entries, netip.MustParsePrefix("10.0.0.0/24"), gw) {
		t.Fatal("oracle credits a plain gateway from another element's via")
	}
	// A route to a destination no element produces is never credited.
	if entriesCreditGateway(entries, netip.MustParsePrefix("10.9.0.0/24"), gw) {
		t.Fatal("oracle credits a gateway for a destination no element produces")
	}
	// The multipath form: the via hosts of the nexthops of the element
	// itself count.
	doc2 := []byte(`[{"dst":"10.0.0.0/24","nexthops":[{"via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"},{"gateway":"10.0.0.1","dev":"eth1"}]}]`)
	entries2 := oracleRouteEntries(doc2)
	if !entriesCreditGateway(entries2, netip.MustParsePrefix("10.0.0.0/24"), gw) {
		t.Fatal("oracle does not credit a nexthop via of the element itself")
	}
}

// FuzzParseAddrsBounds checks the hard bounds of ParseAddrs on arbitrary
// input: no panic, bounded entry count, every returned field within its
// documented limits.
func FuzzParseAddrsBounds(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("proxmox-addr.json", "ubuntu-addr.json", "docker-addr.json", "malformed-addr.json") {
		f.Add(s)
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"ifname":"eth0","address":"bc:24:11:aa:bb:cc","operstate":"UP","addr_info":[{"family":"inet","local":"192.168.0.37","prefixlen":24}]}]`))
	f.Add([]byte(`[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64}]}]`))
	f.Add([]byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.0.37","prefixlen":33},{"family":"inet","local":"nope","prefixlen":24},{"family":"inets","local":"1.2.3.4","prefixlen":8}]}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseAddrs(b)
		if err != nil {
			return
		}
		if len(res.Entries) > maxEntries {
			t.Fatalf("addr list has %d entries, bound is %d", len(res.Entries), maxEntries)
		}
		if res.Dropped < 0 || (res.Dropped > 0 && !res.Incomplete) {
			t.Fatalf("Dropped=%d with Incomplete=%v", res.Dropped, res.Incomplete)
		}
		for _, a := range res.Entries {
			oracleIfName(t, "addr name", a.Name)
			if len(a.MAC) != 0 && len(a.MAC) != 6 {
				t.Fatalf("addr MAC has %d bytes, want 0 or 6", len(a.MAC))
			}
			if a.State != "" && !operStates[a.State] {
				t.Fatalf("addr state %q is not an operstate name", a.State)
			}
			if len(a.Addrs) > maxAddrsPerIf {
				t.Fatalf("interface %s has %d addrs, bound is %d", a.Name, len(a.Addrs), maxAddrsPerIf)
			}
			for _, p := range a.Addrs {
				if !p.IsValid() {
					t.Fatalf("addr carries invalid prefix %v", p)
				}
			}
		}
	})
}

// FuzzParseLinksBounds checks the hard bounds of ParseLinks on arbitrary
// input: no panic, bounded entry count, every returned field within its
// documented limits.
func FuzzParseLinksBounds(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("proxmox-link.json", "ubuntu-link.json", "docker-link.json", "malformed-link.json") {
		f.Add(s)
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"ifname":"eth0.100","address":"bc:24:11:aa:bb:cc","link":"eth0","linkinfo":{"info_kind":"vlan","info_data":{"id":100}}}]`))
	f.Add([]byte(`[{"ifname":"tap101","master":"vmbr0","linkinfo":{"info_kind":"tun"}}]`))
	f.Add([]byte(`[{"ifname":"eth0","linkinfo":{"info_kind":"vlan","info_data":{"id":99999}}}]`))
	f.Add([]byte(`[{"ifname":"vx0","linkinfo":{"info_kind":"vxlan","info_data":{"id":100}}},{"ifname":"sit0","address":"0.0.0.0"}]`))
	f.Add([]byte(fmt.Sprintf(`[{"ifname":"eth0","linkinfo":{"info_kind":"%s"}}]`, strings.Repeat("a", maxKindLen+1))))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseLinks(b)
		if err != nil {
			return
		}
		if len(res.Entries) > maxEntries {
			t.Fatalf("link list has %d entries, bound is %d", len(res.Entries), maxEntries)
		}
		if res.Dropped < 0 || (res.Dropped > 0 && !res.Incomplete) {
			t.Fatalf("Dropped=%d with Incomplete=%v", res.Dropped, res.Incomplete)
		}
		for _, l := range res.Entries {
			oracleIfName(t, "link name", l.Name)
			if len(l.MAC) != 0 && len(l.MAC) != 6 {
				t.Fatalf("link MAC has %d bytes, want 0 or 6", len(l.MAC))
			}
			if l.VLANID != nil && (*l.VLANID < minVLANID || *l.VLANID > maxVLANID) {
				t.Fatalf("link VLAN id %d out of range %d..%d", *l.VLANID, minVLANID, maxVLANID)
			}
			if l.VLANID != nil && l.Kind != "vlan" {
				t.Fatalf("link %s of kind %q has a VLAN id", l.Name, l.Kind)
			}
			if l.Parent != "" {
				oracleIfName(t, "link parent", l.Parent)
			}
			if l.Master != "" {
				oracleIfName(t, "link master", l.Master)
			}
			if len(l.Kind) > maxKindLen {
				t.Fatalf("link kind is %d bytes, bound is %d", len(l.Kind), maxKindLen)
			}
		}
	})
}

// FuzzParseBridgeVLANBounds checks the hard bounds of ParseBridgeVLAN on
// arbitrary input: no panic, bounded port and total VLAN counts, every
// returned field within its documented limits.
func FuzzParseBridgeVLANBounds(f *testing.F) {
	for _, s := range netfactsFuzzSeeds("proxmox-bridgevlan.json", "proxmox-bridgevlan-flat.json", "ubuntu-bridgevlan.json", "docker-bridgevlan.json", "malformed-bridgevlan.json") {
		f.Add(s)
	}
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"ifname":"eth0","vlans":[{"vlan":1,"flags":["PVID","Egress Untagged"]},{"vlan":100}]}]`))
	f.Add([]byte(`[{"ifname":"eth0","vlan":1,"flags":["PVID","Egress Untagged"]}]`))
	f.Add([]byte(`[{"ifname":"eth0","vlans":[{"vlan":4096},{"vlan":-1},{"vlan":100,"vlanEnd":50}]}]`))
	f.Add([]byte(`[{"ifname":"eth0","vlans":[{"flags":["PVID"]},{"vlan":0},{"vlan":1,"vlanEnd":4094}]}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		res, err := ParseBridgeVLAN(b)
		if err != nil {
			return
		}
		if len(res.Ports) > maxEntries {
			t.Fatalf("bridge vlan table has %d ports, bound is %d", len(res.Ports), maxEntries)
		}
		if res.Dropped < 0 || (res.Dropped > 0 && !res.Incomplete) {
			t.Fatalf("Dropped=%d with Incomplete=%v", res.Dropped, res.Incomplete)
		}
		total := 0
		for port, vlans := range res.Ports {
			oracleIfName(t, "bridge vlan port", port)
			total += len(vlans)
			for i, v := range vlans {
				if v.ID < minVLANID || v.ID > maxVLANID {
					t.Fatalf("port %s vlan has id %d out of range %d..%d", port, v.ID, minVLANID, maxVLANID)
				}
				if i > 0 && vlans[i-1].ID >= v.ID {
					t.Fatalf("port %s vlans not sorted by id: %d then %d", port, vlans[i-1].ID, v.ID)
				}
			}
		}
		if total > maxVLANsPerDoc {
			t.Fatalf("bridge vlan table has %d (port, vlan) pairs, bound is %d", total, maxVLANsPerDoc)
		}
	})
}
