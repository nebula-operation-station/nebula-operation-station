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
		{Dst: netip.MustParsePrefix("127.0.0.0/8"), Dev: "lo"},
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
	want := []Route{
		{
			Dst:     netip.MustParsePrefix("0.0.0.0/0"),
			Gateway: netip.MustParseAddr("10.0.0.1"),
			Dev:     "ens18",
			Metric:  100,
		},
		{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "ens18"},
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
	want := []Route{
		{
			Dst:     netip.MustParsePrefix("::/0"),
			Gateway: netip.MustParseAddr("fe80::1"),
			Dev:     "eth0",
			Metric:  100,
		},
		{Dst: netip.MustParsePrefix("fe80::/10"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("2001:db8::/32"), Dev: "eth0", Metric: 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
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
		{"oversize dev", `{"dst":"10.0.0.0/24","dev":"` + strings.Repeat("x", maxStringLen+1) + `"}`},
		{"negative metric", `{"dst":"10.0.0.0/24","dev":"eth0","metric":-1}`},
		{"float metric", `{"dst":"10.0.0.0/24","dev":"eth0","metric":1.5}`},
		{"metric above bound", `{"dst":"10.0.0.0/24","dev":"eth0","metric":4294967296}`},
		{"non-object entry", `42`},
		{"null entry", `null`},
		{"gateway family differs from dst", `{"dst":"10.1.0.0/24","gateway":"fe80::1","dev":"eth0"}`},
		{"v4 gateway on v6 dst", `{"dst":"2001:db8::/32","gateway":"10.0.0.1","dev":"eth0"}`},
		{"zone in dst", `{"dst":"fe80::%eth0/64","dev":"eth0"}`},
		{"bidi override in dev", `{"dst":"10.0.0.0/24","dev":"eth\u202e0"}`},
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
