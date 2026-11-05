// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseRoutesDebian12(t *testing.T) {
	res, err := ParseRoutes(readFixture(t, "debian12-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	got := res.Entries
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Route{
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("192.168.178.1"),
			Dev:     "eth0",
			Metric:  100,
		},
		{Dst: netip.MustParsePrefix("192.168.178.0/24"), Dev: "eth0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseRoutesUbuntu2404(t *testing.T) {
	res, err := ParseRoutes(readFixture(t, "ubuntu2404-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	got := res.Entries
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	// systemd-networkd installs a DHCP host route to the gateway (and to
	// the DNS server), which iproute2 prints without a prefix length.
	want := []Route{
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("10.0.0.1"),
			Dev:     "ens18",
			Metric:  100,
		},
		{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "ens18", Metric: 100},
		{Dst: netip.MustParsePrefix("10.0.0.1/32"), Dev: "ens18", Metric: 100},
		{
			Dst:     netip.MustParsePrefix("10.0.0.53/32"),
			Gateway: netip.MustParseAddr("10.0.0.1"),
			Dev:     "ens18",
			Metric:  100,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseRoutesIPv6(t *testing.T) {
	res, err := ParseRoutes(readFixture(t, "ipv6-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	got := res.Entries
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Route{
		{
			Dst:     netip.MustParsePrefix("2001:db8:1::53/128"),
			Gateway: netip.MustParseAddr("fe80::1"),
			Dev:     "eth0",
			Metric:  1024,
		},
		{Dst: netip.MustParsePrefix("2001:db8:1::/64"), Dev: "eth0", Metric: 100},
		{Dst: netip.MustParsePrefix("fe80::/64"), Dev: "eth0", Metric: 256},
		{
			Dst:     netip.MustParsePrefix("::/0"),
			Gateway: netip.MustParseAddr("fe80::1"),
			Dev:     "eth0",
			Metric:  100,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseRoutesIPv6Multipath(t *testing.T) {
	res, err := ParseRoutes(readFixture(t, "ipv6-multipath-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	want := []Route{
		{Dst: netip.MustParsePrefix("2001:db8:1::/64"), Dev: "eth0", Metric: 1024},
		{Dst: netip.MustParsePrefix("fe80::/64"), Dev: "eth0", Metric: 256},
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Dev: "eth0", Metric: 1024},
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::2"), Dev: "eth0", Metric: 1024},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	if gws := DefaultGateways(res.Entries); len(gws) != 2 {
		t.Fatalf("got %d default gateways, want 2: %+v", len(gws), gws)
	}
}

func TestParseRoutesRFC5549(t *testing.T) {
	res, err := ParseRoutes(readFixture(t, "rfc5549-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if res.Incomplete || res.Dropped != 0 {
		t.Fatalf("complete fixture marked Incomplete=%v Dropped=%d", res.Incomplete, res.Dropped)
	}
	// RFC 5549: an IPv4 destination routed via an IPv6 next hop.
	// iproute2 prints such a next hop as a "via" object, top-level and
	// inside a multipath "nexthops" list.
	want := []Route{
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("fe80::1"),
			Dev:     "eth0",
			Metric:  100,
		},
		{Dst: netip.MustParsePrefix("192.168.178.0/24"), Dev: "eth0"},
		{
			Dst:     netip.MustParsePrefix("10.10.0.0/24"),
			Gateway: netip.MustParseAddr("fe80::2"),
			Dev:     "eth1",
			Metric:  50,
		},
		{
			Dst:     netip.MustParsePrefix("10.20.0.0/24"),
			Gateway: netip.MustParseAddr("fe80::3"),
			Dev:     "eth0",
			Metric:  75,
		},
		{
			Dst:     netip.MustParsePrefix("10.20.0.0/24"),
			Gateway: netip.MustParseAddr("fe80::4"),
			Dev:     "eth1",
			Metric:  75,
		},
	}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want %+v", res.Entries, want)
	}
	// The RFC 5549 default route must reach DefaultGateways.
	gws := DefaultGateways(res.Entries)
	if len(gws) != 1 || gws[0].Dst != netip.MustParsePrefix("0.0.0.0/0") ||
		gws[0].Gateway != netip.MustParseAddr("fe80::1") {
		t.Fatalf("got %+v, want the RFC 5549 default route", gws)
	}
}

func TestParseRoutesRFC5549ViaInNexthops(t *testing.T) {
	// A "via" next hop inside a multipath route goes through the same
	// strict parseHostAddr/zone rules as a top-level "via": a zoned next
	// hop is accepted only with a short interface-name zone.
	doc := `[{"dst":"10.30.0.0/24","nexthops":[` +
		`{"via":{"family":"inet6","host":"fe80::5"},"dev":"eth0"},` +
		`{"via":{"family":"inet6","host":"fe80::6%eth0.10"},"dev":"eth0.10"}]}]`
	res, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	want := []Route{
		{Dst: netip.MustParsePrefix("10.30.0.0/24"), Gateway: netip.MustParseAddr("fe80::5"), Dev: "eth0"},
		{
			Dst:     netip.MustParsePrefix("10.30.0.0/24"),
			Gateway: netip.MustParseAddr("fe80::6%eth0.10"),
			Dev:     "eth0.10",
		},
	}
	if !reflect.DeepEqual(res.Entries, want) || res.Incomplete {
		t.Fatalf("got %+v (Incomplete=%v), want %+v", res.Entries, res.Incomplete, want)
	}
}

func TestParseRoutesUnparseableViaNeverDirectRoute(t *testing.T) {
	// An entry whose "via" next hop cannot be parsed is dropped and the
	// table is Incomplete; it must never be kept as a direct route
	// (silent loss of the gateway).
	doc := `[{"dst":"10.1.0.0/24","via":{"family":"inet6","host":"nope"},"dev":"eth0"},` +
		`{"dst":"10.0.0.0/24","dev":"eth0"}]`
	res, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	want := []Route{{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"}}
	if !reflect.DeepEqual(res.Entries, want) {
		t.Fatalf("got %+v, want only the direct entry (the bad via entry is dropped, never demoted to a direct route)", res.Entries)
	}
	if !res.Incomplete || res.Dropped != 1 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
	}
}

func TestParseRoutesRFC5549MultipathDefault(t *testing.T) {
	// An RFC 5549 default route learned over several IPv6 next hops in an
	// IPv4 document: IPv6 "via" next hops fit an IPv4 and an IPv6
	// default, so the document family decides.
	doc := `[{"dst":"default","nexthops":[` +
		`{"via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"},` +
		`{"via":{"family":"inet6","host":"fe80::2"},"dev":"eth0"}]},` +
		`{"dst":"192.168.1.0/24","dev":"eth0"}]`
	res, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	want := []Route{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("fe80::1"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("fe80::2"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("192.168.1.0/24"), Dev: "eth0"},
	}
	if !reflect.DeepEqual(res.Entries, want) || res.Incomplete {
		t.Fatalf("got %+v (Incomplete=%v), want %+v", res.Entries, res.Incomplete, want)
	}
	if gws := DefaultGateways(res.Entries); len(gws) != 2 {
		t.Fatalf("got %d default gateways, want 2: %+v", len(gws), gws)
	}
}

func TestParseRoutesViaFamilies(t *testing.T) {
	// The family of a "via" next hop relative to the destination, for
	// "default" and prefix destinations, single and multipath. v4 and v6
	// are routes that set the document family.
	const (
		v4    = `{"dst":"192.168.1.0/24","dev":"eth0"}`
		v6    = `{"dst":"2001:db8::/64","dev":"eth0"}`
		via4  = `"via":{"family":"inet","host":"10.0.0.1"}`
		via6  = `"via":{"family":"inet6","host":"fe80::1"}`
		via6b = `"via":{"family":"inet6","host":"fe80::2"}`
	)
	v4Route := Route{Dst: netip.MustParsePrefix("192.168.1.0/24"), Dev: "eth0"}
	v6Route := Route{Dst: netip.MustParsePrefix("2001:db8::/64"), Dev: "eth0"}
	r := func(dst, gw string) Route {
		return Route{Dst: netip.MustParsePrefix(dst), Gateway: netip.MustParseAddr(gw), Dev: "eth0"}
	}
	cases := []struct {
		name    string
		doc     string
		want    []Route
		dropped int
	}{
		// default x same family
		{"default same-family inet via", `[{"dst":"default",` + via4 + `,"dev":"eth0"}]`,
			[]Route{r("0.0.0.0/0", "10.0.0.1")}, 0},
		{"default same-family inet via in ipv4 document", `[` + v4 + `,{"dst":"default",` + via4 + `,"dev":"eth0"}]`,
			[]Route{v4Route, r("0.0.0.0/0", "10.0.0.1")}, 0},
		{"default same-family inet6 via in ipv6 document", `[` + v6 + `,{"dst":"default",` + via6 + `,"dev":"eth0"}]`,
			[]Route{v6Route, r("::/0", "fe80::1")}, 0},
		{"default same-family inet6 via, document family after it", `[{"dst":"default",` + via6 + `,"dev":"eth0"},` + v6 + `]`,
			[]Route{r("::/0", "fe80::1"), v6Route}, 0},
		// default x cross family
		{"default rfc5549 inet6 via in ipv4 document", `[` + v4 + `,{"dst":"default",` + via6 + `,"dev":"eth0"}]`,
			[]Route{v4Route, r("0.0.0.0/0", "fe80::1")}, 0},
		{"default inet via in ipv6 document is an ipv4 default", `[` + v6 + `,{"dst":"default",` + via4 + `,"dev":"eth0"}]`,
			[]Route{v6Route, r("0.0.0.0/0", "10.0.0.1")}, 0},
		{"default inet6 via without family signal", `[{"dst":"default",` + via6 + `,"dev":"eth0"}]`,
			nil, 0},
		// A document that already contains a definite IPv4 default and a
		// definite IPv6 route mixes families, so it is not a real route
		// table; the later ambiguous default is dropped, not guessed as
		// RFC 5549 from the IPv4 default's family.
		{"default inet6 via in mixed-family document is dropped", `[{"dst":"default",` + via4 + `,"dev":"eth0"},` + v6 + `,{"dst":"default",` + via6 + `,"dev":"eth0"}]`,
			[]Route{r("0.0.0.0/0", "10.0.0.1"), v6Route}, 1},
		// The same guard for a "default" with no next hop at all: its
		// family comes only from the document, and a mixed document has
		// none.
		{"bare default in mixed-family document is dropped", `[` + v4 + `,` + v6 + `,{"dst":"default","dev":"eth0"}]`,
			[]Route{v4Route, v6Route}, 1},
		{"bare default in ipv4 document", `[` + v4 + `,{"dst":"default","dev":"eth0"}]`,
			[]Route{v4Route, {Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0"}}, 0},
		// prefix x same family
		{"prefix same-family inet via", `[{"dst":"10.1.0.0/24",` + via4 + `,"dev":"eth0"}]`,
			[]Route{r("10.1.0.0/24", "10.0.0.1")}, 0},
		{"prefix same-family inet6 via", `[{"dst":"2001:db8:1::/48",` + via6 + `,"dev":"eth0"}]`,
			[]Route{r("2001:db8:1::/48", "fe80::1")}, 0},
		// prefix x cross family
		{"prefix rfc5549 inet6 via", `[{"dst":"10.1.0.0/24",` + via6 + `,"dev":"eth0"}]`,
			[]Route{r("10.1.0.0/24", "fe80::1")}, 0},
		{"prefix inet via on ipv6 dst", `[{"dst":"2001:db8:1::/48",` + via4 + `,"dev":"eth0"}]`,
			nil, 0},
		// multipath
		{"multipath default inet6 vias in ipv6 document", `[` + v6 + `,{"dst":"default","nexthops":[{` + via6 + `,"dev":"eth0"},{` + via6b + `,"dev":"eth0"}]}]`,
			[]Route{v6Route, r("::/0", "fe80::1"), r("::/0", "fe80::2")}, 0},
		{"multipath default inet6 vias without family signal", `[{"dst":"default","nexthops":[{` + via6 + `,"dev":"eth0"},{` + via6b + `,"dev":"eth0"}]}]`,
			nil, 0},
		{"multipath default inet6 via then ipv4 gateway", `[{"dst":"default","nexthops":[{` + via6 + `,"dev":"eth0"},{"gateway":"10.0.0.1","dev":"eth0"}]}]`,
			[]Route{r("0.0.0.0/0", "fe80::1"), r("0.0.0.0/0", "10.0.0.1")}, 0},
		{"multipath default ipv4 gateway then inet6 via", `[{"dst":"default","nexthops":[{"gateway":"10.0.0.1","dev":"eth0"},{` + via6 + `,"dev":"eth0"}]}]`,
			[]Route{r("0.0.0.0/0", "10.0.0.1"), r("0.0.0.0/0", "fe80::1")}, 0},
		{"multipath default inet6 via then ipv6 gateway", `[{"dst":"default","nexthops":[{` + via6 + `,"dev":"eth0"},{"gateway":"fe80::2","dev":"eth0"}]}]`,
			[]Route{r("::/0", "fe80::1"), r("::/0", "fe80::2")}, 0},
		{"multipath default ipv6 gateway then inet6 via", `[{"dst":"default","nexthops":[{"gateway":"fe80::2","dev":"eth0"},{` + via6 + `,"dev":"eth0"}]}]`,
			[]Route{r("::/0", "fe80::2"), r("::/0", "fe80::1")}, 0},
		{"multipath default inet via and ipv6 gateway", `[{"dst":"default","nexthops":[{` + via4 + `,"dev":"eth0"},{"gateway":"fe80::2","dev":"eth0"}]}]`,
			nil, 0},
		{"multipath prefix inet via and inet6 via", `[{"dst":"10.1.0.0/24","nexthops":[{` + via4 + `,"dev":"eth0"},{` + via6 + `,"dev":"eth0"}]}]`,
			[]Route{r("10.1.0.0/24", "10.0.0.1"), r("10.1.0.0/24", "fe80::1")}, 0},
		{"multipath ipv6 prefix with inet via", `[{"dst":"2001:db8:1::/48","nexthops":[{` + via6 + `,"dev":"eth0"},{` + via4 + `,"dev":"eth0"}]}]`,
			nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseRoutes([]byte(tc.doc))
			if err != nil {
				t.Fatalf("ParseRoutes: %v", err)
			}
			if tc.want == nil {
				if len(res.Entries) != 0 || !res.Incomplete || res.Dropped != 1 {
					t.Fatalf("got %+v (Incomplete=%v Dropped=%d), want the entry dropped", res.Entries, res.Incomplete, res.Dropped)
				}
				return
			}
			if !reflect.DeepEqual(res.Entries, tc.want) || res.Incomplete != (tc.dropped > 0) || res.Dropped != tc.dropped {
				t.Fatalf("got %+v (Incomplete=%v Dropped=%d), want %+v (Dropped=%d)", res.Entries, res.Incomplete, res.Dropped, tc.want, tc.dropped)
			}
		})
	}
}

func TestParseRoutesViaHostBounds(t *testing.T) {
	maxZone := strings.Repeat("e", maxZoneLen)
	doc := `[{"dst":"10.1.0.0/24","via":{"family":"inet6","host":"fe80::1%` + maxZone + `"},"dev":"eth0"}]`
	res, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	want := []Route{{
		Dst:     netip.MustParsePrefix("10.1.0.0/24"),
		Gateway: netip.MustParseAddr("fe80::1%" + maxZone),
		Dev:     "eth0",
	}}
	if !reflect.DeepEqual(res.Entries, want) || res.Incomplete {
		t.Fatalf("zone of maxZoneLen bytes: got %+v (Incomplete=%v), want %+v", res.Entries, res.Incomplete, want)
	}

	rejected := map[string]string{
		"zone of maxZoneLen+1 bytes": "fe80::1%" + strings.Repeat("e", maxZoneLen+1),
		"host above maxAddrLen":      "fe80:" + strings.Repeat("0", maxAddrLen) + "::1",
	}
	for name, zone := range hostileZones() {
		rejected["hostile zone "+name] = "fe80::1%" + zone
	}
	for name, host := range rejected {
		t.Run(name, func(t *testing.T) {
			for _, entry := range []string{
				`{"dst":"10.1.0.0/24","via":{"family":"inet6","host":"` + host + `"},"dev":"eth0"}`,
				`{"dst":"10.1.0.0/24","nexthops":[{"via":{"family":"inet6","host":"` + host + `"},"dev":"eth0"}]}`,
			} {
				res, err := ParseRoutes([]byte(`[` + entry + `,{"dst":"10.0.0.0/24","dev":"eth0"}]`))
				if err != nil {
					t.Fatalf("ParseRoutes: %v", err)
				}
				want := []Route{{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"}}
				if !reflect.DeepEqual(res.Entries, want) || !res.Incomplete || res.Dropped != 1 {
					t.Fatalf("%s: got %+v (Incomplete=%v Dropped=%d), want only the direct entry", entry, res.Entries, res.Incomplete, res.Dropped)
				}
			}
		})
	}
}

func TestParseRoutesHostRoutes(t *testing.T) {
	cases := []struct {
		dst  string
		want netip.Prefix
	}{
		{"10.0.0.1", netip.MustParsePrefix("10.0.0.1/32")},
		{"10.0.0.1/32", netip.MustParsePrefix("10.0.0.1/32")},
		{"fe80::1", netip.MustParsePrefix("fe80::1/128")},
		{"2001:db8::53", netip.MustParsePrefix("2001:db8::53/128")},
	}
	for _, tc := range cases {
		t.Run(tc.dst, func(t *testing.T) {
			res, err := ParseRoutes([]byte(`[{"dst":"` + tc.dst + `","dev":"eth0","scope":"link","flags":[]}]`))
			if err != nil {
				t.Fatalf("ParseRoutes: %v", err)
			}
			want := []Route{{Dst: tc.want, Dev: "eth0"}}
			if !reflect.DeepEqual(res.Entries, want) || res.Incomplete {
				t.Fatalf("got %+v (Incomplete=%v), want %+v", res.Entries, res.Incomplete, want)
			}
		})
	}
}

func TestParseRoutesHostRouteDecidesDefaultFamily(t *testing.T) {
	res, err := ParseRoutes([]byte(`[{"dst":"fe80::1","dev":"eth0"},{"dst":"default","dev":"eth0"}]`))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(res.Entries) != 2 || res.Entries[1].Dst != netip.MustParsePrefix("::/0") {
		t.Fatalf("got %+v, want default route ::/0", res.Entries)
	}
}

func TestParseRoutesCapsExpandedEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries-1; i++ {
		fmt.Fprintf(&b, `{"dst":"10.%d.%d.0/24","dev":"eth0"},`, i/256, i%256)
	}
	b.WriteString(`{"dst":"default","nexthops":[{"gateway":"10.0.0.1","dev":"eth0"},{"gateway":"10.0.0.2","dev":"eth0"}]}]`)
	res, err := ParseRoutes([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(res.Entries) != maxEntries-1 || !res.Incomplete || res.Dropped != 1 {
		t.Fatalf("got %d entries Incomplete=%v Dropped=%d, want %d true 1",
			len(res.Entries), res.Incomplete, res.Dropped, maxEntries-1)
	}
}

func TestParseRoutesEmptyArray(t *testing.T) {
	res, err := ParseRoutes(readFixture(t, "empty-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	got := res.Entries
	if len(got) != 0 {
		t.Fatalf("got %d routes, want 0", len(got))
	}
}

func TestParseRoutesDefaultWithoutGatewayUsesDocumentFamily(t *testing.T) {
	doc := `[
		{"dst":"192.168.0.0/24","dev":"eth0"},
		{"dst":"default","dev":"eth0"}
	]`
	res, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	got := res.Entries
	if len(got) != 2 {
		t.Fatalf("got %d routes, want 2: %+v", len(got), got)
	}
	if got[1].Dst != (netip.MustParsePrefix("0.0.0.0/0")) {
		t.Fatalf("default route dst is %v, want 0.0.0.0/0", got[1].Dst)
	}
}

func TestParseRoutesDefaultWithoutFamilySignalSkipped(t *testing.T) {
	res, err := ParseRoutes([]byte(`[{"dst":"default","dev":"eth0"}]`))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	got := res.Entries
	if len(got) != 0 {
		t.Fatalf("got %d routes, want 0 (no family signal, never guessed): %+v", len(got), got)
	}
}

func TestParseRoutesSkipsInvalidEntries(t *testing.T) {
	good := `{"dst":"10.0.0.0/24","dev":"eth0"}`
	cases := []struct {
		name  string
		entry string
	}{
		{"missing dst", `{"dev":"eth0"}`},
		{"invalid dst", `{"dst":"not-a-prefix","dev":"eth0"}`},
		{"invalid gateway", `{"dst":"default","gateway":"nope","dev":"eth0"}`},
		{"invalid dev", `{"dst":"10.0.0.0/24","dev":"bad\u0001dev"}`},
		{"negative metric", `{"dst":"10.0.0.0/24","dev":"eth0","metric":-1}`},
		{"float metric", `{"dst":"10.0.0.0/24","dev":"eth0","metric":1.5}`},
		{"metric above bound", `{"dst":"10.0.0.0/24","dev":"eth0","metric":4294967296}`},
		{"non-object entry", `42`},
		{"null entry", `null`},
		{"gateway family differs from dst", `{"dst":"10.1.0.0/24","gateway":"fe80::1","dev":"eth0"}`},
		{"v4 gateway on v6 dst", `{"dst":"2001:db8::/32","gateway":"10.0.0.1","dev":"eth0"}`},
		{"zone in dst", `{"dst":"fe80::%eth0/64","dev":"eth0"}`},
		{"bidi override in dev", `{"dst":"10.0.0.0/24","dev":"eth\u202e0"}`},
		{"zone in host dst", `{"dst":"fe80::1%eth0","dev":"eth0"}`},
		{"hostile zone in host dst", `{"dst":"fe80::1%\u001b[0m","dev":"eth0"}`},
		{"oversize host dst", `{"dst":"` + strings.Repeat("1", maxAddrLen+1) + `","dev":"eth0"}`},
		{"non-canonical v4 host dst", `{"dst":"010.0.0.1","dev":"eth0"}`},
		{"missing dev", `{"dst":"10.0.0.0/24"}`},
		{"space in dev", `{"dst":"10.0.0.0/24","dev":"eth 0"}`},
		{"long dev", `{"dst":"10.0.0.0/24","dev":"` + strings.Repeat("e", maxIfNameLen+1) + `"}`},
		{"homoglyph dev", `{"dst":"10.0.0.0/24","dev":"\u0435th0"}`},
		{"multipath with top-level gateway", `{"dst":"default","gateway":"10.0.0.1","dev":"eth0","nexthops":[{"gateway":"10.0.0.2","dev":"eth0"}]}`},
		{"multipath empty", `{"dst":"default","nexthops":[]}`},
		{"multipath bad hop dev", `{"dst":"default","nexthops":[{"gateway":"10.0.0.1","dev":"eth0"},{"gateway":"10.0.0.2","dev":"e th"}]}`},
		{"multipath bad hop gateway", `{"dst":"default","nexthops":[{"gateway":"fe80::1%\u202e","dev":"eth0"}]}`},
		{"multipath mixed families", `{"dst":"default","nexthops":[{"gateway":"10.0.0.1","dev":"eth0"},{"gateway":"fe80::1","dev":"eth0"}]}`},
		{"multipath too many hops", `{"dst":"default","nexthops":[` + strings.TrimSuffix(strings.Repeat(`{"gateway":"10.0.0.1","dev":"eth0"},`, maxNexthops+1), ",") + `]}`},
		{"via bad host", `{"dst":"10.1.0.0/24","via":{"family":"inet6","host":"nope"},"dev":"eth0"}`},
		{"via hostile zone", `{"dst":"10.1.0.0/24","via":{"family":"inet6","host":"fe80::1%\u202e"},"dev":"eth0"}`},
		{"via family mismatch", `{"dst":"10.1.0.0/24","via":{"family":"inet","host":"fe80::1"},"dev":"eth0"}`},
		{"via unknown family", `{"dst":"10.1.0.0/24","via":{"family":"inets","host":"10.0.0.1"},"dev":"eth0"}`},
		{"via missing host", `{"dst":"10.1.0.0/24","via":{"family":"inet6"},"dev":"eth0"}`},
		{"via string not object", `{"dst":"10.1.0.0/24","via":"fe80::1","dev":"eth0"}`},
		{"via v4 on v6 dst", `{"dst":"2001:db8::/32","via":{"family":"inet","host":"10.0.0.1"},"dev":"eth0"}`},
		{"gateway and via both", `{"dst":"10.1.0.0/24","gateway":"10.0.0.1","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"}`},
		{"nexthop via bad host", `{"dst":"default","nexthops":[{"via":{"family":"inet6","host":"nope"},"dev":"eth0"}]}`},
		{"nexthop gateway and via", `{"dst":"default","nexthops":[{"gateway":"10.0.0.1","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0"}]}`},
		{"multipath with top-level via", `{"dst":"default","via":{"family":"inet6","host":"fe80::1"},"dev":"eth0","nexthops":[{"via":{"family":"inet6","host":"fe80::2"},"dev":"eth0"}]}`},
		{"C1 control in dev", `{"dst":"10.0.0.0/24","dev":"eth\u00850"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseRoutes([]byte("[" + tc.entry + "," + good + "]"))
			if err != nil {
				t.Fatalf("ParseRoutes: %v", err)
			}
			want := []Route{{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"}}
			if !reflect.DeepEqual(res.Entries, want) {
				t.Fatalf("got %+v, want only the good entry %+v", res.Entries, want)
			}
			if !res.Incomplete || res.Dropped != 1 {
				t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
			}
		})
	}
}

func TestParseRoutesAcceptsMaxNexthops(t *testing.T) {
	// Boundary: exactly maxNexthops next hops are accepted (the
	// maxNexthops+1 list is rejected by TestParseRoutesSkipsInvalidEntries).
	var b strings.Builder
	b.WriteString(`[{"dst":"default","nexthops":[`)
	for i := 0; i < maxNexthops; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"gateway":"10.0.%d.1","dev":"eth0"}`, i/256)
	}
	b.WriteString(`]}]`)
	res, err := ParseRoutes([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(res.Entries) != maxNexthops || res.Incomplete || res.Dropped != 0 {
		t.Fatalf("got %d entries (Incomplete=%v Dropped=%d), want %d false 0",
			len(res.Entries), res.Incomplete, res.Dropped, maxNexthops)
	}
}

func TestParseRoutesRejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxInputSize+1)
	copy(big, `[{"dst":"10.0.0.0/24","dev":"eth0"}]`)
	if _, err := ParseRoutes(big); err == nil {
		t.Fatal("expected error for input above the size limit")
	}
}

func TestParseRoutesRejectsNonArray(t *testing.T) {
	for name, doc := range map[string]string{
		"malformed": `{"dst":`,
		"object":    `{"dst":"default"}`,
		"null":      `null`,
		"string":    `"hello"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRoutes([]byte(doc)); err == nil {
				t.Fatal("expected error for non-array input")
			}
		})
	}
	t.Run("raw control byte", func(t *testing.T) {
		doc := `[{"dst":"10.0.0.0/24","dev":"eth` + "\x01" + `0"}]`
		if _, err := ParseRoutes([]byte(doc)); err == nil {
			t.Fatal("expected error for raw control byte in JSON text")
		}
	})
}

// hostileZones are IPv6 zone suffixes that netip.ParseAddr accepts but
// that must never reach a stored address. Control characters are JSON
// escapes, so the document stays valid JSON and reaches the zone check.
func hostileZones() map[string]string {
	return map[string]string{
		"control char": "eth\\u00010",
		"ANSI escape":  "\\u001b[31mred\\u001b[0m",
		"newline":      "eth0\\nforged line",
		"C1 control":   "eth\\u00850",
		"bidi":         "eth\\u202e0",
		"space":        "eth 0",
		"slash":        "eth/0",
		"too long":     strings.Repeat("e", maxZoneLen+1),
		"huge":         strings.Repeat("z", 512*1024),
	}
}

func TestParseRoutesRejectsHostileGatewayZone(t *testing.T) {
	for name, zone := range hostileZones() {
		t.Run(name, func(t *testing.T) {
			doc := `[{"dst":"default","gateway":"fe80::1%` + zone + `","dev":"eth0"},` +
				`{"dst":"10.0.0.0/24","dev":"eth0"}]`
			res, err := ParseRoutes([]byte(doc))
			if err != nil {
				t.Fatalf("ParseRoutes: %v", err)
			}
			want := []Route{{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"}}
			if !reflect.DeepEqual(res.Entries, want) {
				t.Fatalf("got %+v, want only the good entry", res.Entries)
			}
			if !res.Incomplete || res.Dropped != 1 {
				t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
			}
			if gws := DefaultGateways(res.Entries); len(gws) != 0 {
				t.Fatalf("hostile gateway reached DefaultGateways: %+v", gws)
			}
		})
	}
}

func TestParseRoutesAcceptsInterfaceZone(t *testing.T) {
	res, err := ParseRoutes([]byte(`[{"dst":"default","gateway":"fe80::1%eth0.10","dev":"eth0"}]`))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	want := []Route{{
		Dst:     netip.MustParsePrefix("::/0"),
		Gateway: netip.MustParseAddr("fe80::1%eth0.10"),
		Dev:     "eth0",
	}}
	if !reflect.DeepEqual(res.Entries, want) || res.Incomplete {
		t.Fatalf("got %+v (Incomplete=%v), want %+v", res.Entries, res.Incomplete, want)
	}
}

func TestParseRoutesInvalidEntryDoesNotDecideDefaultFamily(t *testing.T) {
	// The first entry has a parseable IPv6 dst but an invalid dev; it is
	// skipped and must not make the gateway-less default ::/0.
	doc := `[
		{"dst":"2001:db8::/32","dev":"bad\u0001dev"},
		{"dst":"192.168.0.0/24","dev":"eth0"},
		{"dst":"default","dev":"eth0"}
	]`
	res, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(res.Entries) != 2 || res.Entries[1].Dst != (netip.MustParsePrefix("0.0.0.0/0")) {
		t.Fatalf("got %+v, want default route 0.0.0.0/0", res.Entries)
	}
	if !res.Incomplete || res.Dropped != 1 {
		t.Fatalf("Incomplete=%v Dropped=%d, want true 1", res.Incomplete, res.Dropped)
	}
}

func TestParseRoutesAcceptsMaxEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"dst":"10.%d.%d.0/24","dev":"eth0"}`, i/256, i%256)
	}
	b.WriteByte(']')
	res, err := ParseRoutes([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(res.Entries) != maxEntries || res.Incomplete {
		t.Fatalf("got %d entries (Incomplete=%v), want %d", len(res.Entries), res.Incomplete, maxEntries)
	}
}

func TestParseRoutesRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"dst":"10.%d.%d.0/24","dev":"eth0"}`, i/256, i%256)
	}
	b.WriteByte(']')
	if _, err := ParseRoutes([]byte(b.String())); err == nil {
		t.Fatalf("expected error for %d entries", maxEntries+1)
	}
}

func TestDefaultGateways(t *testing.T) {
	routes := []Route{
		{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.178.1"), Dev: "eth0", Metric: 100},
		{Dst: netip.MustParsePrefix("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "eth0"},
	}
	got := DefaultGateways(routes)
	want := []Route{routes[1], routes[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDefaultGatewaysNone(t *testing.T) {
	if got := DefaultGateways(nil); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
	if got := DefaultGateways([]Route{{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"}}); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}
