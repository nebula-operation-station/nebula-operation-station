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
		"layer3 repeated":       `<zone><entry name="z"><network><layer3><member>ethernet1/1</member></layer3><layer3><member>ethernet1/2</member></layer3></network></entry></zone>`,
		"layer2 repeated":       `<zone><entry name="z"><network><layer2/><layer2><member>ethernet1/2</member></layer2></network></entry></zone>`,
		"virtual-wire repeated": `<zone><entry name="z"><network><virtual-wire/><virtual-wire/></network></entry></zone>`,
		"tap repeated":          `<zone><entry name="z"><network><tap/><tap/></network></entry></zone>`,
		"layer3 and layer2":     `<zone><entry name="z"><network><layer3><member>ethernet1/1</member></layer3><layer2><member>ethernet1/2</member></layer2></network></entry></zone>`,
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

// zonesSeedBody returns a <zone> body with n entries named z0..z(n-1), each
// with one interface.
func zonesSeedBody(n int) string {
	var b strings.Builder
	b.WriteString(`<zone>`)
	for i := range n {
		fmt.Fprintf(&b, `<entry name="z%d"><network><layer3><member>ethernet1/%d</member></layer3></network></entry>`, i, i+1)
	}
	b.WriteString(`</zone>`)
	return b.String()
}

func FuzzParseZones(f *testing.F) {
	f.Add(readFixture(f, "zones.xml"))
	f.Add(readFixture(f, "objects.xml"))
	f.Add(readFixture(f, "status-error.xml"))
	f.Add([]byte{})
	f.Add(wrapResult(``))
	f.Add(wrapResult(`<zone/>`))
	f.Add(wrapResult(zonesSeedBody(3)))
	f.Add(wrapResult(`<zone><entry name="` + strings.Repeat("z", MaxNameLength) + `"/></zone>`))
	f.Add(wrapResult(`<zone><entry name="` + strings.Repeat("z", MaxNameLength+1) + `"/></zone>`))
	f.Add(wrapResult("<zone><entry name=\"\xff\xfe\"/></zone>"))
	f.Add(wrapResult(`<zone><entry name="z"/><entry name="z"/></zone>`))
	f.Add(wrapResult(`<zone><entry name="z"><network><layer3/><layer3/></network></entry></zone>`))
	f.Add(wrapResult(`<zone><entry name="z"><network><layer3><member>ethernet1/1</member><member>ethernet1/1</member></layer3></network></entry></zone>`))
	f.Add(wrapResult(`<zone><entry name="z"><network><layer3/><tap/></network></entry></zone>`))
	f.Add(wrapResult(`<zone><entry name="z">` + strings.Repeat("<e>", 70) + strings.Repeat("</e>", 70) + `</entry></zone>`))
	f.Add(wrapResult(`<zone><entry name="z"><network><layer3><member>` + strings.Repeat("e", 2*MaxXMLTextBytes) + `</member></layer3></network></entry></zone>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseZones(data)
		if err != nil {
			if len(got.List) != 0 || got.Incomplete || got.List != nil {
				t.Fatalf("error with non-zero result: %v", err)
			}
			return
		}
		if len(got.List) > netdevcontract.MaxZones {
			t.Fatalf("%d zones over limit", len(got.List))
		}
		names := map[string]struct{}{}
		owner := map[string]struct{}{}
		for i, z := range got.List {
			if ValidateName(z.Name) != nil || len(z.Name) > MaxNameLength {
				t.Fatalf("zone %d has invalid name", i)
			}
			if _, dup := names[z.Name]; dup {
				t.Fatalf("zone %d duplicated", i)
			}
			names[z.Name] = struct{}{}
			switch z.Type {
			case "", ZoneLayer3, ZoneLayer2, ZoneVirtualWire, ZoneTap:
			default:
				t.Fatalf("zone %d has type %q", i, z.Type)
			}
			if z.Type == "" && len(z.Interfaces) != 0 {
				t.Fatalf("zone %d has interfaces without a type", i)
			}
			if len(z.Interfaces) > netdevcontract.MaxFirewallInterfaces {
				t.Fatalf("zone %d has %d interfaces over limit", i, len(z.Interfaces))
			}
			for _, itf := range z.Interfaces {
				if !netdevcontract.ValidInterfaceName(itf) {
					t.Fatalf("zone %d has invalid interface %q", i, itf)
				}
				if _, dup := owner[itf]; dup {
					t.Fatalf("interface %q in more than one zone", itf)
				}
				owner[itf] = struct{}{}
			}
		}
		// the contract form must pass the netdevcontract validator
		validatePolicy(t, netdevcontract.FirewallPolicy{Zones: got.Contract()})
	})
}
