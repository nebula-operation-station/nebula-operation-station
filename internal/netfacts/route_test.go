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
	got, err := ParseRoutes(readFixture(t, "debian12-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
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
	got, err := ParseRoutes(readFixture(t, "ubuntu2404-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
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
	got, err := ParseRoutes(readFixture(t, "ipv6-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
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
	got, err := ParseRoutes(readFixture(t, "empty-route.json"))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d routes, want 0", len(got))
	}
}

func TestParseRoutesDefaultWithoutGatewayUsesDocumentFamily(t *testing.T) {
	doc := `[
		{"dst":"192.168.0.0/24","dev":"eth0"},
		{"dst":"default","dev":"eth0"}
	]`
	got, err := ParseRoutes([]byte(doc))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d routes, want 2: %+v", len(got), got)
	}
	if got[1].Dst != (netip.MustParsePrefix("0.0.0.0/0")) {
		t.Fatalf("default route dst is %v, want 0.0.0.0/0", got[1].Dst)
	}
}

func TestParseRoutesDefaultWithoutFamilySignalSkipped(t *testing.T) {
	got, err := ParseRoutes([]byte(`[{"dst":"default","dev":"eth0"}]`))
	if err != nil {
		t.Fatalf("ParseRoutes: %v", err)
	}
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRoutes([]byte("[" + tc.entry + "," + good + "]"))
			if err != nil {
				t.Fatalf("ParseRoutes: %v", err)
			}
			want := []Route{{Dst: netip.MustParsePrefix("10.0.0.0/24"), Dev: "eth0"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want only the good entry %+v", got, want)
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
