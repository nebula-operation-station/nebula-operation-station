// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"testing"

	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
)

// Limits of the fuzz input. The input is a sequence of fixed-size records;
// a missing tail reads as zero bytes, so every byte string decodes.
const (
	fuzzMaxRoutes    = 32
	fuzzMaxNeighbors = 16
	fuzzRouteRec     = 36 // flags, bits, dev, metric, dst[16], gateway[16]
	fuzzNeighRec     = 24 // flags, dev, ip[16], mac[6]
)

// Flag bits of the fuzz records. They are independent of the code under
// test; the reference below works on the decoded hostnet values only.
const (
	fuzzDstV6     = 0x01 // query destination is IPv6
	fuzzDstZone   = 0x02 // query destination carries a zone
	fuzzDstMapped = 0x04 // query destination is an IPv4-mapped IPv6 address
	fuzzDstBad    = 0x08 // query destination is the zero (invalid) address

	fuzzRouteV6      = 0x01 // destination prefix is IPv6
	fuzzRouteHasGW   = 0x02 // route has a gateway
	fuzzRouteGWV6    = 0x04 // gateway is IPv6
	fuzzRouteGWZone  = 0x08 // gateway carries a zone
	fuzzRouteGWEqDst = 0x10 // gateway equals the query destination
	fuzzRouteGWMap   = 0x20 // gateway is an IPv4-mapped IPv6 address

	fuzzNeighV6         = 0x01 // neighbor IP is IPv6
	fuzzNeighShortMAC   = 0x02 // MAC has 5 bytes
	fuzzNeighNoMAC      = 0x04 // MAC is absent
	fuzzNeighFailed     = 0x08 // state FAILED
	fuzzNeighIncomplete = 0x10 // state INCOMPLETE
	fuzzNeighBadIP      = 0x20 // neighbor IP is the zero (invalid) address
	fuzzNeighZone       = 0x40 // neighbor IPv6 carries a zone
)

// fuzzDevs and fuzzMetrics are the value tables the record bytes index into.
var (
	fuzzDevs    = []string{"eth0", "eth1", "br0", ""}
	fuzzMetrics = []uint32{0, 1, 2, 100, 200, 4294967295}
)

// fuzzReader hands out consecutive slices of the fuzz input.
type fuzzReader struct{ b []byte }

func (r *fuzzReader) take(n int) []byte {
	out := make([]byte, n)
	k := copy(out, r.b)
	r.b = r.b[k:]
	return out
}

// fuzzAddr builds an address from a 16-byte field; IPv4 uses the first 4
// bytes. Zones are fixed to "eth0" so the encoder only needs a flag.
func fuzzAddr(v6 bool, b []byte, zone, mapped bool) netip.Addr {
	var a netip.Addr
	switch {
	case mapped:
		a = netip.AddrFrom16(netip.AddrFrom4([4]byte(b[:4])).As16())
	case v6:
		a = netip.AddrFrom16([16]byte(b[:16]))
	default:
		a = netip.AddrFrom4([4]byte(b[:4]))
	}
	if zone && a.Is6() {
		a = a.WithZone("eth0")
	}
	return a
}

// decodeFuzzInput turns fuzz bytes into a query destination, routes and
// neighbors. Routes may be invalid (bad prefix length, no destination) and
// so may neighbors (zero IP, short or missing MAC, odd states).
func decodeFuzzInput(data []byte) (netip.Addr, []hostnet.Route, []hostnet.Neighbor) {
	r := &fuzzReader{b: data}
	dh := r.take(1)[0]
	var dst netip.Addr
	if dh&fuzzDstBad == 0 {
		dst = fuzzAddr(dh&fuzzDstV6 != 0, r.take(16), dh&fuzzDstZone != 0, dh&fuzzDstMapped != 0)
	}

	nr := int(r.take(1)[0]) % (fuzzMaxRoutes + 1)
	routes := make([]hostnet.Route, 0, nr)
	for range nr {
		rec := r.take(fuzzRouteRec)
		fl := rec[0]
		rt := hostnet.Route{
			Dst:    netip.PrefixFrom(fuzzAddr(fl&fuzzRouteV6 != 0, rec[4:20], false, false), int(rec[1])),
			Dev:    fuzzDevs[int(rec[2])%len(fuzzDevs)],
			Metric: fuzzMetrics[int(rec[3])%len(fuzzMetrics)],
		}
		switch {
		case fl&fuzzRouteHasGW == 0:
		case fl&fuzzRouteGWEqDst != 0:
			rt.Gateway = dst
		default:
			rt.Gateway = fuzzAddr(fl&fuzzRouteGWV6 != 0, rec[20:36], fl&fuzzRouteGWZone != 0, fl&fuzzRouteGWMap != 0)
		}
		routes = append(routes, rt)
	}

	nn := int(r.take(1)[0]) % (fuzzMaxNeighbors + 1)
	neigh := make([]hostnet.Neighbor, 0, nn)
	for range nn {
		rec := r.take(fuzzNeighRec)
		fl := rec[0]
		var ip netip.Addr
		if fl&fuzzNeighBadIP == 0 {
			ip = fuzzAddr(fl&fuzzNeighV6 != 0, rec[2:18], fl&fuzzNeighZone != 0, false)
		}
		var mac net.HardwareAddr
		switch {
		case fl&fuzzNeighNoMAC != 0:
		case fl&fuzzNeighShortMAC != 0:
			mac = net.HardwareAddr(rec[18:23])
		default:
			mac = net.HardwareAddr(rec[18:24])
		}
		var state []string
		if fl&fuzzNeighFailed != 0 {
			state = append(state, "FAILED")
		}
		if fl&fuzzNeighIncomplete != 0 {
			state = append(state, "INCOMPLETE")
		}
		if len(state) == 0 {
			state = []string{"REACHABLE"}
		}
		neigh = append(neigh, hostnet.Neighbor{IP: ip, Dev: fuzzDevs[int(rec[1])%len(fuzzDevs)], MAC: mac, State: state})
	}
	return dst, routes, neigh
}

// fuzzAddrBytes writes an address into a 16-byte field in the layout
// fuzzAddr reads it back from.
func fuzzAddrBytes(a netip.Addr) (b [16]byte) {
	switch {
	case !a.IsValid():
	case a.Is4In6():
		v := a.Unmap().As4()
		copy(b[:], v[:])
	case a.Is4():
		v := a.As4()
		copy(b[:], v[:])
	default:
		b = a.As16()
	}
	return b
}

// encodeFuzzInput is the inverse of decodeFuzzInput for values it can
// express. It is used only to build seeds from the hops_test.go cases.
// Zones must be "eth0"; devices and metrics must come from the tables.
func encodeFuzzInput(dst netip.Addr, routes []hostnet.Route, neigh []hostnet.Neighbor) []byte {
	var dh byte
	switch {
	case !dst.IsValid():
		dh |= fuzzDstBad
	case dst.Is4In6():
		dh |= fuzzDstMapped | fuzzDstV6
	case dst.Is6():
		dh |= fuzzDstV6
	}
	if dst.Zone() != "" {
		dh |= fuzzDstZone
	}
	out := []byte{dh}
	fb := fuzzAddrBytes(dst)
	out = append(out, fb[:]...)

	out = append(out, byte(len(routes)))
	for _, r := range routes {
		var rec [fuzzRouteRec]byte
		var fl byte
		if r.Dst.Addr().Is6() {
			fl |= fuzzRouteV6
		}
		rec[1] = byte(r.Dst.Bits()) // -1 (invalid prefix) wraps to 255
		da := fuzzAddrBytes(r.Dst.Addr())
		copy(rec[4:20], da[:])
		if r.Gateway.IsValid() {
			fl |= fuzzRouteHasGW
			if r.Gateway == dst {
				fl |= fuzzRouteGWEqDst
			} else {
				if r.Gateway.Is6() {
					fl |= fuzzRouteGWV6
				}
				if r.Gateway.Is4In6() {
					fl |= fuzzRouteGWMap
				}
				if r.Gateway.Zone() != "" {
					fl |= fuzzRouteGWZone
				}
				ga := fuzzAddrBytes(r.Gateway)
				copy(rec[20:36], ga[:])
			}
		}
		rec[0] = fl
		rec[2] = byte(slices.Index(fuzzDevs, r.Dev))
		rec[3] = byte(slices.Index(fuzzMetrics, r.Metric))
		if rec[2] == 255 || rec[3] == 255 {
			panic(fmt.Sprintf("seed route uses a value outside the fuzz tables: %+v", r))
		}
		out = append(out, rec[:]...)
	}

	out = append(out, byte(len(neigh)))
	for _, n := range neigh {
		var rec [fuzzNeighRec]byte
		var fl byte
		switch {
		case !n.IP.IsValid():
			fl |= fuzzNeighBadIP
		case n.IP.Is6():
			fl |= fuzzNeighV6
		}
		if n.IP.Zone() != "" {
			fl |= fuzzNeighZone
		}
		switch len(n.MAC) {
		case 0:
			fl |= fuzzNeighNoMAC
		case 5:
			fl |= fuzzNeighShortMAC
		}
		for _, s := range n.State {
			switch s {
			case "FAILED":
				fl |= fuzzNeighFailed
			case "INCOMPLETE":
				fl |= fuzzNeighIncomplete
			}
		}
		copy(rec[18:24], n.MAC)
		ia := fuzzAddrBytes(n.IP)
		copy(rec[2:18], ia[:])
		rec[0] = fl
		rec[1] = byte(slices.Index(fuzzDevs, n.Dev))
		if rec[1] == 255 {
			panic(fmt.Sprintf("seed neighbor uses a dev outside the fuzz table: %+v", n))
		}
		out = append(out, rec[:]...)
	}
	return out
}

// refNorm is the address form Hop and DeriveHostNet compare by: zone
// removed, IPv4-mapped IPv6 unmapped.
func refNorm(a netip.Addr) netip.Addr {
	switch {
	case !a.IsValid():
		return a
	case a.Is4In6():
		return netip.AddrFrom4(a.As4())
	case a.Is6():
		return netip.AddrFrom16(a.As16())
	}
	return a
}

// refValidRoutes is the route list the rule works on: the first MaxRoutes
// routes with a valid destination prefix, in input order.
func refValidRoutes(routes []hostnet.Route) []hostnet.Route {
	var out []hostnet.Route
	for _, r := range routes {
		if len(out) == MaxRoutes {
			break
		}
		if r.Dst.IsValid() {
			out = append(out, r)
		}
	}
	return out
}

// refContains reports whether the first p.Bits() bits of a equal those of
// p's address, by comparing bits one at a time.
func refContains(p netip.Prefix, a netip.Addr) bool {
	pb, ab := p.Addr().AsSlice(), a.AsSlice()
	if len(pb) != len(ab) {
		return false
	}
	for i := range p.Bits() {
		if (pb[i/8]>>(7-i%8))&1 != (ab[i/8]>>(7-i%8))&1 {
			return false
		}
	}
	return true
}

// refUsable: a neighbor entry gives a gateway MAC only if it has a 6-byte
// unicast, non-zero MAC and is neither FAILED nor INCOMPLETE.
func refUsable(n hostnet.Neighbor) bool {
	if len(n.MAC) != 6 || n.MAC[0]&0x01 != 0 {
		return false
	}
	zero := true
	for _, b := range n.MAC {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return false
	}
	for _, s := range n.State {
		if s == "FAILED" || s == "INCOMPLETE" {
			return false
		}
	}
	return true
}

// refMAC returns the MAC of the first usable neighbor entry on dev for gw,
// lowercase, or "" if there is none.
func refMAC(neigh []hostnet.Neighbor, dev string, gw netip.Addr) string {
	for _, n := range neigh {
		if n.Dev != dev || refNorm(n.IP) != gw || !refUsable(n) {
			continue
		}
		m := n.MAC
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
	}
	return ""
}

// refGateway describes the hop a route gives: its normalized gateway, its
// interface and metric, whether it is a default, and the gateway MAC.
func refGateway(r hostnet.Route, neigh []hostnet.Neighbor) Gateway {
	gw := refNorm(r.Gateway)
	return Gateway{
		Addr:    gw,
		MAC:     refMAC(neigh, r.Dev, gw),
		Dev:     r.Dev,
		Metric:  r.Metric,
		Default: r.Dst.Bits() == 0,
	}
}

// refHop selects the hop for dst. Among the valid routes of dst's family
// that contain dst, the winner has the longest prefix; on equal length the
// lower metric; on equal metric the earlier route in input order. If the
// winner is directly connected (no gateway) or its gateway is dst itself,
// there is no hop, and no less specific route is consulted.
func refHop(routes []hostnet.Route, neigh []hostnet.Neighbor, dst netip.Addr) (Gateway, bool) {
	d := refNorm(dst)
	if !d.IsValid() {
		return Gateway{}, false
	}
	valid := refValidRoutes(routes)
	best := -1
	for i, r := range valid {
		if r.Dst.Addr().Is4() != d.Is4() || !refContains(r.Dst, d) {
			continue
		}
		if best < 0 ||
			r.Dst.Bits() > valid[best].Dst.Bits() ||
			(r.Dst.Bits() == valid[best].Dst.Bits() && r.Metric < valid[best].Metric) {
			best = i
		}
	}
	if best < 0 {
		return Gateway{}, false
	}
	r := valid[best]
	gw := refNorm(r.Gateway)
	if !gw.IsValid() || gw == d {
		return Gateway{}, false
	}
	return refGateway(r, neigh), true
}

// refDefaults lists the default routes with a gateway, IPv4 gateways
// before IPv6 ones, then by metric, then by input order.
func refDefaults(routes []hostnet.Route, neigh []hostnet.Neighbor) []Gateway {
	var out []Gateway
	for _, r := range refValidRoutes(routes) {
		if r.Dst.Bits() != 0 || !refNorm(r.Gateway).IsValid() {
			continue
		}
		out = append(out, refGateway(r, neigh))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a4, b4 := out[i].Addr.Is4(), out[j].Addr.Is4()
		if a4 != b4 {
			return a4
		}
		return out[i].Metric < out[j].Metric
	})
	return out
}

// checkGatewayMAC fails unless mac is "" or a lowercase, canonical,
// 6-byte unicast, non-zero address.
func checkGatewayMAC(t *testing.T, where, mac string) {
	t.Helper()
	if mac == "" {
		return
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 || hw[0]&0x01 != 0 || hw.String() != mac || mac == "00:00:00:00:00:00" {
		t.Fatalf("%s: MAC %q is not a lowercase unicast 6-byte address", where, mac)
	}
}

// fuzzSeed is one case of hops_test.go in the fuzz encoding.
type fuzzSeed struct {
	dst    netip.Addr
	routes []hostnet.Route
	neigh  []hostnet.Neighbor
}

func hwAddr(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// hopSeeds are the scenarios of hops_test.go, one seed per query.
func hopSeeds() []fuzzSeed {
	defaultEth0 := hostnet.Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.10.1"), Dev: "eth0"}
	connected := hostnet.Route{Dst: netip.MustParsePrefix("192.168.10.0/24"), Dev: "eth0"}
	static := hostnet.Route{Dst: netip.MustParsePrefix("10.99.0.0/16"), Gateway: netip.MustParseAddr("192.168.10.254"), Dev: "eth0"}
	gwNeigh := hostnet.Neighbor{IP: netip.MustParseAddr("192.168.10.1"), Dev: "eth0", MAC: hwAddr("52:54:00:00:10:01"), State: []string{"REACHABLE"}}
	host := []hostnet.Route{defaultEth0, connected, static}

	var seeds []fuzzSeed
	for _, d := range []string{"192.168.10.20", "192.168.20.30", "1.1.1.1", "10.99.0.5", "192.168.10.1", "::ffff:192.168.20.30"} {
		seeds = append(seeds, fuzzSeed{dst: netip.MustParseAddr(d), routes: host, neigh: []hostnet.Neighbor{gwNeigh}})
	}
	// Gateway MAC only from the route's own interface.
	seeds = append(seeds, fuzzSeed{
		dst:    netip.MustParseAddr("8.8.8.8"),
		routes: []hostnet.Route{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}},
		neigh:  []hostnet.Neighbor{{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth1", MAC: hwAddr("02:00:00:00:00:99"), State: []string{"REACHABLE"}}},
	})
	// FAILED, INCOMPLETE, broadcast, multicast and zero MACs.
	for _, n := range []hostnet.Neighbor{
		{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", MAC: hwAddr("02:00:00:00:00:01"), State: []string{"FAILED"}},
		{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", MAC: hwAddr("ff:ff:ff:ff:ff:ff"), State: []string{"REACHABLE"}},
		{IP: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", MAC: hwAddr("00:00:00:00:00:00"), State: []string{"REACHABLE"}},
	} {
		seeds = append(seeds, fuzzSeed{
			dst:    netip.MustParseAddr("8.8.8.8"),
			routes: []hostnet.Route{{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}},
			neigh:  []hostnet.Neighbor{n},
		})
	}
	// Default gateways ordered by family and metric; IPv6 query.
	seeds = append(seeds, fuzzSeed{
		dst: netip.MustParseAddr("8.8.8.8"),
		routes: []hostnet.Route{
			{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Dev: "eth0", Metric: 1},
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.2"), Dev: "eth1", Metric: 200},
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", Metric: 100},
		},
	})
	seeds = append(seeds, fuzzSeed{dst: netip.MustParseAddr("2001:db8::1"), routes: []hostnet.Route{
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Dev: "eth0", Metric: 1},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0", Metric: 100},
	}})
	// No routes; invalid query address.
	seeds = append(seeds, fuzzSeed{dst: netip.MustParseAddr("8.8.8.8")}, fuzzSeed{})
	// Equal prefix length: lower metric wins. Gateway equal to destination.
	seeds = append(seeds, fuzzSeed{dst: netip.MustParseAddr("10.1.2.3"), routes: []hostnet.Route{
		{Dst: netip.MustParsePrefix("10.1.0.0/16"), Gateway: netip.MustParseAddr("10.0.0.5"), Dev: "eth0", Metric: 100},
		{Dst: netip.MustParsePrefix("10.1.0.0/16"), Gateway: netip.MustParseAddr("10.0.0.6"), Dev: "eth0", Metric: 1},
	}})
	seeds = append(seeds, fuzzSeed{dst: netip.MustParseAddr("10.0.0.5"), routes: []hostnet.Route{
		{Dst: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("10.0.0.5"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"},
	}})
	return seeds
}

// FuzzHostNetHop compares DeriveHostNet and HostNet.Hop with a linear
// reference over the decoded routes and neighbors (ADR 0009 D3), and checks
// that nothing panics, that gateway MACs have the usableMAC form, that
// derivation is deterministic and that the default gateway order matches.
func FuzzHostNetHop(f *testing.F) {
	for _, s := range hopSeeds() {
		f.Add(encodeFuzzInput(s.dst, s.routes, s.neigh))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		dst, routes, neigh := decodeFuzzInput(data)
		h := DeriveHostNet("fuzz-host", routes, neigh)
		if again := DeriveHostNet("fuzz-host", routes, neigh); !reflect.DeepEqual(h, again) {
			t.Fatalf("DeriveHostNet not deterministic for routes %+v neighbors %+v", routes, neigh)
		}
		if len(h.routes) > MaxRoutes {
			t.Fatalf("routes kept = %d, above MaxRoutes %d", len(h.routes), MaxRoutes)
		}
		if len(h.Defaults) > len(routes) {
			t.Fatalf("defaults = %d for %d routes", len(h.Defaults), len(routes))
		}

		wantDefaults := refDefaults(routes, neigh)
		if !slices.Equal(h.Defaults, wantDefaults) {
			t.Fatalf("Defaults = %+v, want %+v (routes %+v)", h.Defaults, wantDefaults, routes)
		}
		for i, gw := range h.Defaults {
			checkGatewayMAC(t, fmt.Sprintf("Defaults[%d]", i), gw.MAC)
		}

		probes := []netip.Addr{dst}
		for _, r := range routes {
			probes = append(probes, r.Dst.Addr(), r.Gateway)
		}
		for _, p := range probes {
			got, ok := h.Hop(p)
			want, wantOK := refHop(routes, neigh, p)
			if ok != wantOK || (ok && got != want) {
				t.Fatalf("Hop(%v) = %+v, %v; want %+v, %v (routes %+v neighbors %+v)",
					p, got, ok, want, wantOK, routes, neigh)
			}
			if !ok && got != (Gateway{}) {
				t.Fatalf("Hop(%v) without hop returned %+v", p, got)
			}
			if ok {
				checkGatewayMAC(t, fmt.Sprintf("Hop(%v)", p), got.MAC)
			}
		}
	})
}

// TestHostNetCapKeepsFirstValidRoutes pins the MaxRoutes rule the fuzz
// inputs are too small to reach: invalid routes do not count, and only the
// first MaxRoutes valid routes are kept.
func TestHostNetCapKeepsFirstValidRoutes(t *testing.T) {
	def := hostnet.Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.0.0.1"), Dev: "eth0"}
	bogus := make([]hostnet.Route, 10) // zero Dst: invalid, not counted
	host := func(i int) hostnet.Route {
		return hostnet.Route{Dst: netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, byte(i >> 8), byte(i)}), 32), Dev: "eth0"}
	}
	cases := []struct {
		name         string
		routes       []hostnet.Route
		wantDefaults int
	}{
		{
			name:         "default is the last kept valid route",
			routes:       append(append(slices.Clone(bogus), hostsN(host, MaxRoutes-1)...), def, host(5000)),
			wantDefaults: 1,
		},
		{
			name:         "default after the cap is dropped",
			routes:       append(append(slices.Clone(bogus), hostsN(host, MaxRoutes)...), def),
			wantDefaults: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := DeriveHostNet("h", tc.routes, nil)
			if len(h.routes) != MaxRoutes {
				t.Fatalf("routes kept = %d, want %d", len(h.routes), MaxRoutes)
			}
			if len(h.Defaults) != tc.wantDefaults {
				t.Fatalf("defaults = %+v, want %d", h.Defaults, tc.wantDefaults)
			}
			if want := refDefaults(tc.routes, nil); !slices.Equal(h.Defaults, want) {
				t.Fatalf("Defaults = %+v, reference %+v", h.Defaults, want)
			}
		})
	}
}

// TestFuzzSeedsRoundTrip checks that the seed encoding decodes back to the
// hops_test.go scenarios, so the seeds exercise what they are meant to.
func TestFuzzSeedsRoundTrip(t *testing.T) {
	for i, s := range hopSeeds() {
		dst, routes, neigh := decodeFuzzInput(encodeFuzzInput(s.dst, s.routes, s.neigh))
		if dst != s.dst {
			t.Fatalf("seed %d: dst = %v, want %v", i, dst, s.dst)
		}
		if len(routes) != len(s.routes) || len(neigh) != len(s.neigh) {
			t.Fatalf("seed %d: got %d routes %d neighbors, want %d and %d", i, len(routes), len(neigh), len(s.routes), len(s.neigh))
		}
		for j := range routes {
			if !reflect.DeepEqual(routes[j], s.routes[j]) {
				t.Fatalf("seed %d route %d = %+v, want %+v", i, j, routes[j], s.routes[j])
			}
		}
		for j := range neigh {
			if !reflect.DeepEqual(neigh[j], s.neigh[j]) {
				t.Fatalf("seed %d neighbor %d = %+v, want %+v", i, j, neigh[j], s.neigh[j])
			}
		}
	}
}

// hostsN returns the first n routes made by host.
func hostsN(host func(int) hostnet.Route, n int) []hostnet.Route {
	out := make([]hostnet.Route, n)
	for i := range out {
		out[i] = host(i)
	}
	return out
}
