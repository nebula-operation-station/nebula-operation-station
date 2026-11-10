// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

func TestParseZonesFixture(t *testing.T) {
	got, err := ParseZones(readFixture(t, "zones.xml"))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	want := ZoneSet{List: []Zone{
		{Name: "trust", Type: ZoneLayer3, Interfaces: []string{"ethernet1/2", "ethernet1/3.10"}},
		{Name: "untrust", Type: ZoneLayer3, Interfaces: []string{"ethernet1/1"}},
		{Name: "lab-l2", Type: ZoneLayer2, Interfaces: []string{"ethernet1/4"}},
		{Name: "vwire.zone", Type: ZoneVirtualWire, Interfaces: []string{"ethernet1/5", "ethernet1/6"}},
		{Name: "tap zone", Type: ZoneTap, Interfaces: []string{"ethernet1/7"}},
		{Name: "empty_zone", Type: ZoneLayer3},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseZones =\n%+v\nwant\n%+v", got, want)
	}
	// dropped elements (zone protection profile, user ACL) leave no trace
	if s := fmt.Sprintf("%+v", got); strings.Contains(s, "example-zpp") || strings.Contains(s, "192.0.2.0/24") {
		t.Fatalf("non-allowlisted zone content leaked: %s", s)
	}
}

func TestParseZonesFromVsysRead(t *testing.T) {
	got, err := ParseZones(readFixture(t, "objects.xml"))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	want := ZoneSet{List: []Zone{{Name: "trust", Type: ZoneLayer3, Interfaces: []string{"ethernet1/2"}}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseZones = %+v, want %+v", got, want)
	}
}

func TestParseZonesEmpty(t *testing.T) {
	for _, body := range []string{``, `<zone/>`} {
		got, err := ParseZones(wrapResult(body))
		if err != nil || len(got.List) != 0 || got.Incomplete {
			t.Fatalf("ParseZones(%q) = %+v, %v; want empty complete set", body, got, err)
		}
	}
}

func TestParseZonesUnknownTypeLeavesTypeEmpty(t *testing.T) {
	got, err := ParseZones(wrapResult(`<zone><entry name="t"><network><tunnel/></network></entry><entry name="n"/></zone>`))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	for _, z := range got.List {
		if z.Type != "" || len(z.Interfaces) != 0 {
			t.Fatalf("zone %+v: want no type and no interfaces", z)
		}
	}
}

func TestParseZonesRejectsInvalidContent(t *testing.T) {
	long := strings.Repeat("z", MaxNameLength+1)
	cases := map[string]string{
		"empty name":            `<zone><entry name=""/></zone>`,
		"missing name":          `<zone><entry/></zone>`,
		"name too long":         `<zone><entry name="` + long + `"/></zone>`,
		"name with quote":       `<zone><entry name="a&apos;b"/></zone>`,
		"name with slash":       `<zone><entry name="a/b"/></zone>`,
		"name with lt":          `<zone><entry name="a&lt;b"/></zone>`,
		"name non-ascii":        `<zone><entry name="zöne"/></zone>`,
		"name leading space":    `<zone><entry name=" z"/></zone>`,
		"duplicate zone":        `<zone><entry name="z"/><entry name="z"/></zone>`,
		"two types":             `<zone><entry name="z"><network><layer3/><layer2/></network></entry></zone>`,
		"two network elements":  `<zone><entry name="z"><network><layer3/></network><network><layer3/></network></entry></zone>`,
		"bad interface":         `<zone><entry name="z"><network><layer3><member>eth 1</member></layer3></network></entry></zone>`,
		"empty interface":       `<zone><entry name="z"><network><layer3><member></member></layer3></network></entry></zone>`,
		"duplicate interface":   `<zone><entry name="z"><network><layer3><member>ethernet1/1</member><member>ethernet1/1</member></layer3></network></entry></zone>`,
		"interface in two zone": `<zone><entry name="a"><network><layer3><member>ethernet1/1</member></layer3></network></entry><entry name="b"><network><layer2><member>ethernet1/1</member></layer2></network></entry></zone>`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseZones(wrapResult(body))
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestParseZonesOverLimitIsIncomplete(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<zone>`)
	for i := range netdevcontract.MaxZones + 5 {
		fmt.Fprintf(&b, `<entry name="z%d"/>`, i)
	}
	b.WriteString(`</zone>`)
	got, err := ParseZones(wrapResult(b.String()))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	if !got.Incomplete || len(got.List) != netdevcontract.MaxZones {
		t.Fatalf("got %d zones, incomplete %v; want %d, true", len(got.List), got.Incomplete, netdevcontract.MaxZones)
	}

	b.Reset()
	b.WriteString(`<zone><entry name="big"><network><layer3>`)
	for i := range netdevcontract.MaxFirewallInterfaces + 1 {
		fmt.Fprintf(&b, `<member>ethernet1/%d</member>`, i)
	}
	b.WriteString(`</layer3></network></entry></zone>`)
	got, err = ParseZones(wrapResult(b.String()))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	if !got.Incomplete || len(got.List[0].Interfaces) != netdevcontract.MaxFirewallInterfaces {
		t.Fatalf("got %d interfaces, incomplete %v", len(got.List[0].Interfaces), got.Incomplete)
	}
}

func TestParseZonesRefusesStatusError(t *testing.T) {
	if _, err := ParseZones(readFixture(t, "status-error.xml")); !errors.Is(err, ErrAPIStatus) {
		t.Fatalf("err = %v, want ErrAPIStatus", err)
	}
}

func TestParseZonesOutputPassesContract(t *testing.T) {
	got, err := ParseZones(readFixture(t, "zones.xml"))
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	validatePolicy(t, netdevcontract.FirewallPolicy{Zones: got.Contract()})
}
