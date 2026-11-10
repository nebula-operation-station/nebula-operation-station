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

// natBody wraps NAT rule entries in a direct rules subtree read.
func natBody(entries string) []byte {
	return wrapResult(`<rules>` + entries + `</rules>`)
}

// minimalNAT is a valid NAT rule without translation, with extra elements.
func minimalNAT(name, extra string) string {
	return `<entry name="` + name + `"><from><member>any</member></from><to><member>untrust</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<service>any</service>` + extra + `</entry>`
}

func natNames(rs []NATRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

func TestParseNATRulesFixture(t *testing.T) {
	got, err := ParseNATRules(readFixture(t, "nat.xml"))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	want := []NATRule{
		{
			Index: 0, Name: "outbound-pat", UUID: "00000000-0000-4000-8000-0000000000b1",
			From: []string{"trust"}, To: []string{"untrust"}, Source: []string{"lab-net"}, Destination: []string{"any"},
			Service: "any",
			SourceTranslation: SourceTranslation{
				Type: SourceDynamicIPAndPort, Interface: "ethernet1/1", InterfaceIP: "203.0.113.1/24",
			},
		},
		{
			Index: 1, Name: "web-dnat",
			From: []string{"untrust"}, To: []string{"untrust"}, Source: []string{"any"}, Destination: []string{"203.0.113.10"},
			Service:                "svc-http-alt",
			DestinationTranslation: DestinationTranslation{Enabled: true, TranslatedAddress: "web-1", TranslatedPort: "80"},
			Description:            "publish the example web server",
		},
		{
			Index: 2, Name: "static-bidir",
			From: []string{"dmz"}, To: []string{"untrust"}, Source: []string{"web-2"}, Destination: []string{"any"},
			Service: "any",
			SourceTranslation: SourceTranslation{
				Type: SourceStaticIP, TranslatedAddresses: []string{"203.0.113.11"}, BiDirectional: true,
			},
		},
		{
			Index: 3, Name: "a-disabled-pool",
			From: []string{"trust"}, To: []string{"untrust"}, Source: []string{"ghost-net"}, Destination: []string{"any"},
			Service: "any",
			SourceTranslation: SourceTranslation{
				Type: SourceDynamicIP, TranslatedAddresses: []string{"203.0.113.20-203.0.113.29", "pool-obj"},
			},
			Disabled: true, Tags: []string{"legacy"},
		},
	}
	if got.Incomplete {
		t.Fatal("fixture parsed as incomplete")
	}
	if len(got.Rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %q", len(got.Rules), len(want), natNames(got.Rules))
	}
	for i := range want {
		if !reflect.DeepEqual(got.Rules[i], want[i]) {
			t.Errorf("rule %d =\n%+v\nwant\n%+v", i, got.Rules[i], want[i])
		}
	}
}

func TestParseNATRulesFromWholeVsys(t *testing.T) {
	// rules.xml holds one NAT rule next to the security rulebase
	got, err := ParseNATRules(readFixture(t, "rules.xml"))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	if !reflect.DeepEqual(natNames(got.Rules), []string{"nat-not-read-here"}) || got.Rules[0].SourceTranslation.Type != SourceNone {
		t.Fatalf("got %+v", got)
	}
	// and the security parser does not read a NAT-only vsys
	sec, err := ParseSecurityRules(objectsBody(`<rulebase><nat><rules>` + minimalNAT("n", "") + `</rules></nat></rulebase>`))
	if err != nil || len(sec.Rules) != 0 {
		t.Fatalf("security from NAT-only vsys: %+v, %v", sec, err)
	}
}

func TestParseNATRulesOrderAndDisabled(t *testing.T) {
	names := []string{"z", "b", "a", "y y", "0"}
	var b strings.Builder
	for i, n := range names {
		extra := ""
		if i%2 == 1 {
			extra = "<disabled>yes</disabled>"
		}
		b.WriteString(minimalNAT(n, extra))
	}
	got, err := ParseNATRules(natBody(b.String()))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	if !reflect.DeepEqual(natNames(got.Rules), names) {
		t.Fatalf("order = %q", natNames(got.Rules))
	}
	for i, r := range got.Rules {
		if r.Index != i || r.Disabled != (i%2 == 1) {
			t.Fatalf("rule %d: index %d disabled %v", i, r.Index, r.Disabled)
		}
	}
}

func TestParseNATRulesOversizeIsIncomplete(t *testing.T) {
	var b strings.Builder
	for i := range netdevcontract.MaxNATRules + 1 {
		b.WriteString(minimalNAT(fmt.Sprintf("n%d", i), ""))
	}
	got, err := ParseNATRules(natBody(b.String()))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	if !got.Incomplete || len(got.Rules) != netdevcontract.MaxNATRules || got.Rules[0].Name != "n0" {
		t.Fatalf("got %d rules, incomplete %v", len(got.Rules), got.Incomplete)
	}

	b.Reset()
	b.WriteString(`<source-translation><dynamic-ip><translated-address>`)
	for i := range netdevcontract.MaxRuleMembers + 1 {
		fmt.Fprintf(&b, `<member>p%d</member>`, i)
	}
	b.WriteString(`</translated-address></dynamic-ip></source-translation>`)
	got, err = ParseNATRules(natBody(minimalNAT("n", b.String())))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	if !got.Incomplete || len(got.Rules[0].SourceTranslation.TranslatedAddresses) != netdevcontract.MaxRuleMembers {
		t.Fatalf("translated addresses over limit: incomplete %v", got.Incomplete)
	}
}

func TestParseNATRulesUnknownSourceTranslationIsIncomplete(t *testing.T) {
	// a translation type outside the allowlist must not read as "no NAT"
	got, err := ParseNATRules(natBody(minimalNAT("n", `<source-translation><future-nat><x/></future-nat></source-translation>`)))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	if !got.Incomplete || got.Rules[0].SourceTranslation.Type != SourceUnknown {
		t.Fatalf("got %+v", got)
	}
}

func TestParseNATRulesDynamicDestination(t *testing.T) {
	got, err := ParseNATRules(natBody(minimalNAT("n", `<dynamic-destination-translation><translated-address>web-servers</translated-address>`+
		`<translated-port>8080</translated-port><distribution>round-robin</distribution></dynamic-destination-translation>`)))
	if err != nil {
		t.Fatalf("ParseNATRules: %v", err)
	}
	want := DestinationTranslation{Enabled: true, Dynamic: true, TranslatedAddress: "web-servers", TranslatedPort: "8080"}
	if got.Rules[0].DestinationTranslation != want {
		t.Fatalf("got %+v", got.Rules[0].DestinationTranslation)
	}
}

func TestParseNATRulesRejectsInvalidContent(t *testing.T) {
	st := func(inner string) string { return `<source-translation>` + inner + `</source-translation>` }
	cases := []struct {
		name string
		data []byte
	}{
		{"duplicate name", natBody(minimalNAT("n", "") + minimalNAT("n", ""))},
		{"invalid name", natBody(minimalNAT("n&lt;x", ""))},
		{"bad uuid", natBody(strings.Replace(minimalNAT("n", ""), `name="n"`, `name="n" uuid="x"`, 1))},
		{"missing to", natBody(strings.Replace(minimalNAT("n", ""), `<to><member>untrust</member></to>`, ``, 1))},
		{"missing service", natBody(strings.Replace(minimalNAT("n", ""), `<service>any</service>`, ``, 1))},
		{"repeated service", natBody(minimalNAT("n", `<service>any</service>`))},
		{"invalid service", natBody(strings.Replace(minimalNAT("n", ""), `<service>any</service>`, `<service>a/b</service>`, 1))},
		{"bad disabled", natBody(minimalNAT("n", `<disabled>Y</disabled>`))},
		{"two source types", natBody(minimalNAT("n", st(`<dynamic-ip><translated-address><member>a</member></translated-address></dynamic-ip>`+
			`<static-ip><translated-address>b</translated-address></static-ip>`)))},
		{"repeated source translation", natBody(minimalNAT("n", st(`<static-ip><translated-address>b</translated-address></static-ip>`)+
			st(`<static-ip><translated-address>b</translated-address></static-ip>`)))},
		{"static without address", natBody(minimalNAT("n", st(`<static-ip><bi-directional>yes</bi-directional></static-ip>`)))},
		{"static bad bidir", natBody(minimalNAT("n", st(`<static-ip><translated-address>b</translated-address><bi-directional>1</bi-directional></static-ip>`)))},
		{"dynamic-ip without address", natBody(minimalNAT("n", st(`<dynamic-ip/>`)))},
		{"pat without address", natBody(minimalNAT("n", st(`<dynamic-ip-and-port/>`)))},
		{"pat with both forms", natBody(minimalNAT("n", st(`<dynamic-ip-and-port><translated-address><member>a</member></translated-address>`+
			`<interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port>`)))},
		{"pat bad interface", natBody(minimalNAT("n", st(`<dynamic-ip-and-port><interface-address><interface>eth 1;x</interface></interface-address></dynamic-ip-and-port>`)))},
		{"pat bad ip", natBody(minimalNAT("n", st(`<dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface><ip>1.2.3.4/99</ip></interface-address></dynamic-ip-and-port>`)))},
		{"bad translated member", natBody(minimalNAT("n", st(`<dynamic-ip><translated-address><member>a'b</member></translated-address></dynamic-ip>`)))},
		{"dst without address", natBody(minimalNAT("n", `<destination-translation><translated-port>80</translated-port></destination-translation>`))},
		{"dst bad port", natBody(minimalNAT("n", `<destination-translation><translated-address>a</translated-address><translated-port>70000</translated-port></destination-translation>`))},
		{"dst port range", natBody(minimalNAT("n", `<destination-translation><translated-address>a</translated-address><translated-port>80-81</translated-port></destination-translation>`))},
		{"dst bad address", natBody(minimalNAT("n", `<destination-translation><translated-address>a&amp;b</translated-address></destination-translation>`))},
		{"static and dynamic dst", natBody(minimalNAT("n", `<destination-translation><translated-address>a</translated-address></destination-translation>`+
			`<dynamic-destination-translation><translated-address>a</translated-address></dynamic-destination-translation>`))},
		{"hostile description", natBody(minimalNAT("n", "<description>a"+string(rune(0x202e))+"b</description>"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseNATRules(c.data); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestParseNATRulesRefusesMalformedAndOversize(t *testing.T) {
	if _, err := ParseNATRules(readFixture(t, "status-error.xml")); !errors.Is(err, ErrAPIStatus) {
		t.Fatalf("status error: %v", err)
	}
	if _, err := ParseNATRules([]byte(`<response status="success"><result><rules>`)); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := ParseNATRules(make([]byte, MaxParseResponseBytes+1)); !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("oversize: %v", err)
	}
	const marker = "SECRETMARKER"
	_, err := ParseNATRules(natBody(minimalNAT("n", `<destination-translation><translated-address>`+marker+`'</translated-address></destination-translation>`)))
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("error repeats device text or is nil: %v", err)
	}
}

func FuzzParseNATRules(f *testing.F) {
	f.Add(readFixture(f, "nat.xml"))
	f.Add(readFixture(f, "rules.xml"))
	f.Add(natBody(minimalNAT("n", "<disabled>yes</disabled>")))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseNATRules(data)
		if err != nil {
			if len(got.Rules) != 0 || got.Incomplete {
				t.Fatalf("error with non-zero result: %v", err)
			}
			return
		}
		if len(got.Rules) > netdevcontract.MaxNATRules {
			t.Fatalf("%d rules over limit", len(got.Rules))
		}
		for i, r := range got.Rules {
			if r.Index != i || ValidateName(r.Name) != nil || ValidateName(r.Service) != nil {
				t.Fatalf("rule %d invalid: %+v", i, r)
			}
		}
	})
}
