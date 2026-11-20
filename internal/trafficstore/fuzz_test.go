// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"math"
	"net/netip"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// The fuzz targets decode their bytes deterministically into flow keys:
// reads past the end yield zero, so every input decodes. A key built from
// hostile bytes is what a managed host can report, so the targets cover
// zones, IPv4-mapped addresses, unspecified and loopback addresses,
// unknown protocols, sides and tiers.
//
// Layout of one key (one byte per field unless noted):
//
//	address      mode: bit 0 set = IPv6 (16 bytes), clear = IPv4 (4 bytes);
//	             bit 1 = zone (one byte picks fuzzZones); bit 2 = IPv4 in
//	             IPv6 form (IPv4 only); bit 3 = preset (one byte picks
//	             fuzzAddrPresets)
//	end B        as end A
//	proto        bit 7 clear: TCP or UDP by bit 0; set: raw byte follows
//	port         two bytes, big endian
//	side         bit 7 clear: SideA or SideB by bit 0; set: raw byte follows
//	tier         bit 7 clear: index into fuzzTiers; set: length byte, then
//	             that many raw bytes
type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) next() byte {
	if r.i >= len(r.b) {
		return 0
	}
	v := r.b[r.i]
	r.i++
	return v
}

func (r *byteReader) u16() uint16 {
	return uint16(r.next())<<8 | uint16(r.next())
}

func (r *byteReader) u64() uint64 {
	var v uint64
	for range 8 {
		v = v<<8 | uint64(r.next())
	}
	return v
}

var (
	fuzzZones      = []string{"eth0", "lan1"}
	fuzzTiers      = []string{flowagg.TierSocket, flowagg.TierConntrack, flowagg.TierSensor, "", "Socket", "socket "}
	fuzzAddrPreset = []netip.Addr{
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("198.51.100.7"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("::ffff:192.0.2.1"),
	}
)

func (r *byteReader) addr() netip.Addr {
	mode := r.next()
	var a netip.Addr
	switch {
	case mode&8 != 0:
		a = fuzzAddrPreset[int(r.next())%len(fuzzAddrPreset)]
	case mode&1 == 0:
		v := [4]byte{r.next(), r.next(), r.next(), r.next()}
		if mode&4 != 0 {
			var raw [16]byte
			raw[10], raw[11] = 0xff, 0xff
			copy(raw[12:], v[:])
			a = netip.AddrFrom16(raw)
		} else {
			a = netip.AddrFrom4(v)
		}
	default:
		var raw [16]byte
		for i := range raw {
			raw[i] = r.next()
		}
		a = netip.AddrFrom16(raw)
	}
	if mode&2 != 0 {
		a = a.WithZone(fuzzZones[int(r.next())%len(fuzzZones)])
	}
	return a
}

func (r *byteReader) tier() string {
	t := r.next()
	if t&0x80 == 0 {
		return fuzzTiers[int(t)%len(fuzzTiers)]
	}
	buf := make([]byte, int(r.next()))
	for i := range buf {
		buf[i] = r.next()
	}
	return string(buf)
}

func (r *byteReader) key() flowagg.FlowKey {
	a := r.addr()
	b := r.addr()
	var proto flowagg.Proto
	if p := r.next(); p&0x80 == 0 {
		proto = []flowagg.Proto{flowagg.TCP, flowagg.UDP}[p&1]
	} else {
		proto = flowagg.Proto(r.next())
	}
	port := r.u16()
	var side flowagg.Side
	if s := r.next(); s&0x80 == 0 {
		side = flowagg.SideA + flowagg.Side(s&1)
	} else {
		side = flowagg.Side(r.next())
	}
	return flowagg.FlowKey{A: a, B: b, Proto: proto, ServerPort: port, Server: side, Tier: r.tier()}
}

// goodKey is a key that validKey accepts; the table tests start from it.
var goodKey = flowagg.FlowKey{
	A:          netip.MustParseAddr("192.0.2.1"),
	B:          netip.MustParseAddr("198.51.100.7"),
	Proto:      flowagg.TCP,
	ServerPort: 443,
	Server:     flowagg.SideB,
	Tier:       flowagg.TierSocket,
}

// checkAcceptedKey asserts the properties validKey promises for an
// accepted key.
func checkAcceptedKey(t *testing.T, k flowagg.FlowKey) {
	t.Helper()
	for _, a := range []netip.Addr{k.A, k.B} {
		switch {
		case !a.IsValid():
			t.Fatalf("accepted invalid endpoint %v", k)
		case a.Zone() != "":
			t.Fatalf("accepted endpoint with zone: %v", k)
		case a.Is4In6():
			t.Fatalf("accepted IPv4-mapped endpoint: %v", k)
		case a.IsUnspecified() || a.IsLoopback():
			t.Fatalf("accepted unspecified or loopback endpoint: %v", k)
		}
	}
	if k.A.Compare(k.B) >= 0 {
		t.Fatalf("accepted endpoints not in order: %v", k)
	}
	if k.Proto != flowagg.TCP && k.Proto != flowagg.UDP {
		t.Fatalf("accepted protocol %d", uint8(k.Proto))
	}
	if k.ServerPort == 0 {
		t.Fatalf("accepted server port 0: %v", k)
	}
	if k.Server != flowagg.SideA && k.Server != flowagg.SideB {
		t.Fatalf("accepted server side %d", uint8(k.Server))
	}
	if !validTier(k.Tier) {
		t.Fatalf("accepted tier %q", k.Tier)
	}
}

// checkRoundTrip asserts that the stored form of an accepted key, as
// UpsertBucket writes it, reads back as the same key.
func checkRoundTrip(t *testing.T, k flowagg.FlowKey) {
	t.Helper()
	got, err := storedTotal(k.A.String(), k.B.String(), k.Tier, int64(k.Proto), int64(k.ServerPort), int64(k.Server))
	if err != nil {
		t.Fatalf("stored form of accepted key %v rejected: %v", k, err)
	}
	if got.Key != k {
		t.Fatalf("round trip changed the key:\n got %v\nwant %v", got.Key, k)
	}
}

// FuzzValidKey checks that validKey accepts only keys in flowagg canonical
// form and that every accepted key is read back unchanged from its stored
// form.
func FuzzValidKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 192, 0, 2, 1, 0, 198, 51, 100, 7, 0x00, 0x01, 0xbb, 0x80})
	f.Add([]byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		k := (&byteReader{b: data}).key()
		// The error text of a rejected key is not bounded here: an unknown
		// tier is echoed in full (see the report, finding 1).
		if err := validKey(k); err != nil {
			return
		}
		checkAcceptedKey(t, k)
		checkRoundTrip(t, k)
	})
}

// FuzzStoredTotal checks that stored flow rows are decoded with the same
// checks as written keys: out-of-range numbers are refused rather than
// truncated, zones, IPv4-mapped forms and suffixes are refused, and an
// accepted row is a valid key.
func FuzzStoredTotal(f *testing.F) {
	const tier = flowagg.TierSocket
	seeds := []struct {
		a, b        string
		proto, port int64
		side        int64
	}{
		{"192.0.2.1", "198.51.100.7", 6, 443, 2},
		{"192.0.2.1", "198.51.100.7", 6, 65536, 2},
		{"192.0.2.1", "198.51.100.7", 6, -1, 2},
		{"192.0.2.1", "198.51.100.7", 6, math.MaxInt64, 2},
		{"fe80::1%eth0", "2001:db8::1", 6, 22, 1},
		{"::ffff:192.0.2.1", "2001:db8::1", 6, 22, 1},
		{"2001:db8::2", "2001:db8::1", 17, 53, 1},
		{"2001:db8::1", "2001:db8::1", 17, 53, 1},
	}
	for _, s := range seeds {
		f.Add(s.a, s.b, tier, s.proto, s.port, s.side)
	}
	f.Fuzz(func(t *testing.T, a, b, tier string, proto, port, side int64) {
		got, err := storedTotal(a, b, tier, proto, port, side)
		outOfRange := port < 1 || port > 65535 || proto < 0 || proto > 255 || side < 0 || side > 255
		if outOfRange && err == nil {
			t.Fatalf("accepted out-of-range proto %d, port %d or side %d", proto, port, side)
		}
		if err != nil {
			return
		}
		if err := validKey(got.Key); err != nil {
			t.Fatalf("accepted stored row fails validKey: %v", err)
		}
		if strings.ContainsRune(a, '%') || strings.ContainsRune(b, '%') {
			t.Fatalf("accepted zone in %q %q", a, b)
		}
		if got.Key.A.Is4In6() || got.Key.B.Is4In6() {
			t.Fatalf("accepted IPv4-mapped form in %q %q", a, b)
		}
		if int64(got.Key.Proto) != proto || int64(got.Key.ServerPort) != port || int64(got.Key.Server) != side {
			t.Fatalf("numbers truncated: got %v for proto %d port %d side %d", got.Key, proto, port, side)
		}
	})
}

// sign returns -1, 0 or +1 for c.
func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	}
	return 0
}

// forEachPerm calls fn with every permutation of 0..n-1. fn must not keep
// the slice.
func forEachPerm(n int, fn func([]int)) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	var rec func(k int)
	rec = func(k int) {
		if k == n {
			fn(p)
			return
		}
		for i := k; i < n; i++ {
			p[k], p[i] = p[i], p[k]
			rec(k + 1)
			p[k], p[i] = p[i], p[k]
		}
	}
	rec(0)
}

// checkSortedTotals asserts the order sortTotals promises: total bytes
// descending, ties by flow key.
func checkSortedTotals(t *testing.T, ts []flowagg.FlowTotal) {
	t.Helper()
	for i := 1; i < len(ts); i++ {
		prev, cur := ts[i-1], ts[i]
		if prev.Total() < cur.Total() {
			t.Fatalf("totals not descending at %d: %d before %d", i, prev.Total(), cur.Total())
		}
		if prev.Total() == cur.Total() && compareKey(prev.Key, cur.Key) > 0 {
			t.Fatalf("ties not ordered by key at %d", i)
		}
	}
}

// FuzzCompareKey checks that compareKey is an antisymmetric, transitive
// total order that is zero exactly for equal keys, and that sortTotals
// gives the same sequence for every permutation of the same totals.
func FuzzCompareKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &byteReader{b: data}
		var keys [3]flowagg.FlowKey
		var totals [3]flowagg.FlowTotal
		for i := range keys {
			keys[i] = r.key()
			totals[i] = flowagg.FlowTotal{Key: keys[i], BytesAB: r.u64(), BytesBA: r.u64()}
		}
		for i := range keys {
			for j := range keys {
				c, rev := compareKey(keys[i], keys[j]), compareKey(keys[j], keys[i])
				if sign(c) != -sign(rev) {
					t.Fatalf("not antisymmetric: %v vs %v", keys[i], keys[j])
				}
				if (c == 0) != (keys[i] == keys[j]) {
					t.Fatalf("zero compare differs from equality: %v vs %v", keys[i], keys[j])
				}
				for k := range keys {
					if compareKey(keys[i], keys[j]) <= 0 && compareKey(keys[j], keys[k]) <= 0 &&
						compareKey(keys[i], keys[k]) > 0 {
						t.Fatalf("not transitive: %v %v %v", keys[i], keys[j], keys[k])
					}
				}
			}
		}
		if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
			// Equal keys have no defined order between their totals; the
			// callers never pass duplicate keys (the store's query output
			// and the union map hold each key once).
			return
		}
		ref := append([]flowagg.FlowTotal(nil), totals[:]...)
		sortTotals(ref)
		checkSortedTotals(t, ref)
		forEachPerm(len(totals), func(p []int) {
			in := make([]flowagg.FlowTotal, len(totals))
			for i, j := range p {
				in[i] = totals[j]
			}
			sortTotals(in)
			for i := range in {
				if in[i] != ref[i] {
					t.Fatalf("permutation %v sorts differently at %d", p, i)
				}
			}
		})
	})
}

// TestStoredTotalBoundarySeeds runs the boundary values of FuzzStoredTotal
// and of the key checks without the fuzzer.
func TestStoredTotalBoundarySeeds(t *testing.T) {
	const tcp, udp = 6, 17
	tests := []struct {
		name        string
		a, b, tier  string
		proto, port int64
		side        int64
		ok          bool
	}{
		{"good key", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 443, 2, true},
		{"port 65535", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 65535, 2, true},
		{"port 65536", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 65536, 2, false},
		{"port -1", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, -1, 2, false},
		{"port MaxInt64", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, math.MaxInt64, 2, false},
		{"port 0", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 0, 2, false},
		{"proto 262 would truncate to 6", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp + 256, 443, 2, false},
		{"proto -1", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, -1, 443, 2, false},
		{"side 257 would truncate to 1", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 443, 257, false},
		{"side 0", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 443, 0, false},
		{"side 3", "192.0.2.1", "198.51.100.7", flowagg.TierSocket, tcp, 443, 3, false},
		{"zone on link-local", "fe80::1%eth0", "2001:db8::1", flowagg.TierSocket, tcp, 22, 1, false},
		{"IPv4-mapped end", "::ffff:192.0.2.1", "2001:db8::1", flowagg.TierSocket, tcp, 22, 1, false},
		{"suffix on address", "192.0.2.0/24", "198.51.100.7", flowagg.TierSocket, tcp, 22, 1, false},
		{"ends swapped", "198.51.100.7", "192.0.2.1", flowagg.TierSocket, tcp, 443, 2, false},
		{"same value at both ends", "2001:db8::1", "2001:db8::1", flowagg.TierSocket, udp, 53, 1, false},
		{"unspecified end", "0.0.0.0", "198.51.100.7", flowagg.TierSocket, tcp, 443, 2, false},
		{"loopback end", "127.0.0.1", "198.51.100.7", flowagg.TierSocket, tcp, 443, 2, false},
		{"empty tier", "192.0.2.1", "198.51.100.7", "", tcp, 443, 2, false},
		{"tier case", "192.0.2.1", "198.51.100.7", "Socket", tcp, 443, 2, false},
		{"udp ipv6 pair", "2001:db8::1", "2001:db8::2", flowagg.TierSensor, udp, 53, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := storedTotal(tt.a, tt.b, tt.tier, tt.proto, tt.port, tt.side)
			if (err == nil) != tt.ok {
				t.Fatalf("storedTotal error = %v, want accepted = %v", err, tt.ok)
			}
			if err == nil {
				checkAcceptedKey(t, got.Key)
			}
		})
	}
}

// TestValidKeyRoundTripsGoodKey checks the write form of the good key
// against storedTotal.
func TestValidKeyRoundTripsGoodKey(t *testing.T) {
	if err := validKey(goodKey); err != nil {
		t.Fatalf("good key rejected: %v", err)
	}
	checkRoundTrip(t, goodKey)
}

// TestCompareKeyOrderSeeds checks compareKey and sortTotals on boundary
// keys without the fuzzer.
func TestCompareKeyOrderSeeds(t *testing.T) {
	lo := goodKey
	hi := goodKey
	hi.ServerPort = 65535
	v6 := goodKey
	v6.A = netip.MustParseAddr("2001:db8::1")
	v6.B = netip.MustParseAddr("2001:db8::2")
	keys := []flowagg.FlowKey{v6, hi, lo}
	for i := range keys {
		for j := range keys {
			if sign(compareKey(keys[i], keys[j])) != -sign(compareKey(keys[j], keys[i])) {
				t.Fatalf("not antisymmetric: %v vs %v", keys[i], keys[j])
			}
		}
	}
	if compareKey(lo, lo) != 0 || compareKey(lo, hi) >= 0 || compareKey(hi, v6) >= 0 {
		t.Fatal("boundary keys not ordered by address, then port")
	}
	totals := []flowagg.FlowTotal{
		{Key: v6, BytesAB: math.MaxUint64, BytesBA: 1},
		{Key: hi, BytesAB: 5},
		{Key: lo, BytesAB: 5},
	}
	sortTotals(totals)
	checkSortedTotals(t, totals)
	if totals[0].Key != v6 || totals[1].Key != lo || totals[2].Key != hi {
		t.Fatalf("unexpected order %v", totals)
	}
}
