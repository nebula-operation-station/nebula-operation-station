// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// rulesBody wraps security rule entries in a vsys1 rulebase read.
func rulesBody(entries string) []byte {
	return objectsBody(`<rulebase><security><rules>` + entries + `</rules></security></rulebase>`)
}

// minimalRule is a valid allow-all rule with the given name and extra
// elements.
func minimalRule(name, extra string) string {
	return `<entry name="` + name + `"><from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<application><member>any</member></application><service><member>any</member></service>` +
		`<action>allow</action>` + extra + `</entry>`
}

func ruleNames(rs []Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

func TestParseSecurityRulesFixture(t *testing.T) {
	got, err := ParseSecurityRules(readFixture(t, "rules.xml"))
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	if got.Incomplete {
		t.Fatal("fixture parsed as incomplete")
	}
	wantOrder := []string{
		"zz-allow-mgmt", "allow-web", "old-ftp", "any-any-deny", "internal-dns", "unknown-ref",
		"dynamic-ref", "negated-src", "intrazone-dmz", "Allow Users", "disabled-deny", "hostile-text", "a-last",
	}
	if !reflect.DeepEqual(ruleNames(got.Rules), wantOrder) {
		t.Fatalf("order = %q, want %q", ruleNames(got.Rules), wantOrder)
	}
	for i, r := range got.Rules {
		if r.Index != i {
			t.Fatalf("rule %d has Index %d", i, r.Index)
		}
	}
	first := Rule{
		Index: 0, Name: "zz-allow-mgmt", UUID: "00000000-0000-4000-8000-0000000000a1", Type: RuleTypeUniversal,
		From: []string{"trust"}, To: []string{"mgmt"},
		Source: []string{"nos-host"}, Destination: []string{"any"},
		SourceUser: []string{"any"}, Category: []string{"any"},
		Application: []string{"ssh", "web-browsing"}, Service: []string{"application-default"},
		Action: netdevcontract.ActionAllow, LogStart: true, LogEnd: true,
		Description: "management from the NOS host", Tags: []string{"nos"},
	}
	if !reflect.DeepEqual(got.Rules[0], first) {
		t.Fatalf("rule 0 =\n%+v\nwant\n%+v", got.Rules[0], first)
	}
	// uuid is normalized to lower case
	if got.Rules[1].UUID != "00000000-0000-4000-8000-0000000000a2" {
		t.Fatalf("uuid = %q", got.Rules[1].UUID)
	}
	byName := map[string]Rule{}
	for _, r := range got.Rules {
		byName[r.Name] = r
	}
	for name, want := range map[string]bool{"old-ftp": true, "disabled-deny": true, "any-any-deny": false, "allow-web": false} {
		if byName[name].Disabled != want {
			t.Errorf("%s: Disabled = %v, want %v", name, byName[name].Disabled, want)
		}
	}
	if r := byName["any-any-deny"]; r.LogEnd || r.LogStart || r.Action != netdevcontract.ActionDeny {
		t.Errorf("any-any-deny: %+v", r)
	}
	if r := byName["negated-src"]; !r.NegateSource || r.NegateDestination || r.Action != netdevcontract.ActionResetClient {
		t.Errorf("negated-src: %+v", r)
	}
	if r := byName["intrazone-dmz"]; r.Type != RuleTypeIntrazone || r.Action != netdevcontract.ActionResetServer {
		t.Errorf("intrazone-dmz: %+v", r)
	}
	if r := byName["allow-web"]; r.Type != RuleTypeUniversal {
		t.Errorf("allow-web type = %q", r.Type)
	}
	if r := byName["Allow Users"]; !reflect.DeepEqual(r.SourceUser, []string{`example\alice`, "cn=bob,dc=example,dc=org"}) {
		t.Errorf("source users = %q", r.SourceUser)
	}
	// literals are kept, IPv6 in canonical form
	if r := byName["internal-dns"]; !reflect.DeepEqual(r.Destination, []string{"192.0.2.53", "2001:db8::53"}) {
		t.Errorf("internal-dns destination = %q", r.Destination)
	}
	if r := byName["a-last"]; !reflect.DeepEqual(r.Tags, []string{"cleanup", "nos"}) || r.Action != netdevcontract.ActionDeny {
		t.Errorf("a-last: %+v", r)
	}
}

func TestParseSecurityRulesDirectSubtreeForm(t *testing.T) {
	data := wrapResult(`<rules>` + minimalRule("b", "") + minimalRule("a", "<disabled>yes</disabled>") + `</rules>`)
	got, err := ParseSecurityRules(data)
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	if !reflect.DeepEqual(ruleNames(got.Rules), []string{"b", "a"}) || !got.Rules[1].Disabled || got.Incomplete {
		t.Fatalf("got %+v", got)
	}
}

func TestParseSecurityRulesOrderIsStable(t *testing.T) {
	// names chosen so that any sorting (by name, uuid or length) would
	// change the order
	names := []string{"m", "zz", "a", "Z", "b-2", "b-10", "0", "y y", "c"}
	var b strings.Builder
	for i, n := range names {
		fmt.Fprintf(&b, `<entry name=%q uuid="00000000-0000-4000-8000-%012d">`, n, len(names)-i)
		b.WriteString(strings.TrimPrefix(minimalRule("", ""), `<entry name="">`))
	}
	data := rulesBody(b.String())
	for range 20 {
		got, err := ParseSecurityRules(data)
		if err != nil {
			t.Fatalf("ParseSecurityRules: %v", err)
		}
		if !reflect.DeepEqual(ruleNames(got.Rules), names) {
			t.Fatalf("order = %q, want %q", ruleNames(got.Rules), names)
		}
	}
}

func TestParseSecurityRulesKeepsDisabledRulesInPlace(t *testing.T) {
	data := rulesBody(minimalRule("r1", "") + minimalRule("r2", "<disabled>yes</disabled>") + minimalRule("r3", "<disabled>no</disabled>"))
	got, err := ParseSecurityRules(data)
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	if len(got.Rules) != 3 || got.Rules[1].Name != "r2" || !got.Rules[1].Disabled || got.Rules[0].Disabled || got.Rules[2].Disabled {
		t.Fatalf("got %+v", got.Rules)
	}
}

func TestParseSecurityRulesEmptyAndIncomplete(t *testing.T) {
	cases := []struct {
		name       string
		data       []byte
		incomplete bool
	}{
		{"empty result", wrapResult(``), false},
		{"empty rules", wrapResult(`<rules/>`), false},
		{"vsys without rulebase", objectsBody(`<zone/>`), false},
		{"vsys without security", objectsBody(`<rulebase><nat><rules/></nat></rulebase>`), false},
		{"vsys without entry", wrapResult(`<vsys/>`), true},
		{"only foreign content", wrapResult(`<something-else/>`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseSecurityRules(c.data)
			if err != nil {
				t.Fatalf("ParseSecurityRules: %v", err)
			}
			if len(got.Rules) != 0 || got.Incomplete != c.incomplete {
				t.Fatalf("got %+v, want incomplete %v", got, c.incomplete)
			}
		})
	}
}

func TestParseSecurityRulesOversizeIsIncomplete(t *testing.T) {
	var b strings.Builder
	for i := range netdevcontract.MaxSecurityRules + 1 {
		b.WriteString(minimalRule(fmt.Sprintf("r%d", i), ""))
	}
	got, err := ParseSecurityRules(rulesBody(b.String()))
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	if !got.Incomplete || len(got.Rules) != netdevcontract.MaxSecurityRules {
		t.Fatalf("got %d rules, incomplete %v", len(got.Rules), got.Incomplete)
	}
	if got.Rules[0].Name != "r0" || got.Rules[netdevcontract.MaxSecurityRules-1].Name != fmt.Sprintf("r%d", netdevcontract.MaxSecurityRules-1) {
		t.Fatal("kept rules are not the first rules in document order")
	}

	// a member list over its limit is cut and marks the set incomplete
	b.Reset()
	b.WriteString(`<entry name="big"><from><member>any</member></from><to><member>any</member></to><source>`)
	for i := range netdevcontract.MaxRuleMembers + 1 {
		fmt.Fprintf(&b, `<member>h%d</member>`, i)
	}
	b.WriteString(`</source><destination><member>any</member></destination><application><member>any</member></application>` +
		`<service><member>any</member></service><action>allow</action></entry>`)
	got, err = ParseSecurityRules(rulesBody(b.String()))
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	if !got.Incomplete || len(got.Rules[0].Source) != netdevcontract.MaxRuleMembers {
		t.Fatalf("got %d sources, incomplete %v", len(got.Rules[0].Source), got.Incomplete)
	}

	// tags over the limit
	b.Reset()
	b.WriteString(`<tag>`)
	for i := range netdevcontract.MaxTagsPerObject + 1 {
		fmt.Fprintf(&b, `<member>t%d</member>`, i)
	}
	b.WriteString(`</tag>`)
	got, err = ParseSecurityRules(rulesBody(minimalRule("r", b.String())))
	if err != nil || !got.Incomplete || len(got.Rules[0].Tags) != netdevcontract.MaxTagsPerObject {
		t.Fatalf("tags over limit: incomplete %v, err %v", got.Incomplete, err)
	}
}

func TestParseSecurityRulesRefusesOversizeResponse(t *testing.T) {
	big := make([]byte, MaxParseResponseBytes+1)
	if _, err := ParseSecurityRules(big); !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("err = %v, want ErrXMLLimit", err)
	}
	deep := strings.Repeat("<a>", netdevcontract.MaxXMLDepth+1) + strings.Repeat("</a>", netdevcontract.MaxXMLDepth+1)
	if _, err := ParseSecurityRules(wrapResult(deep)); !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("deep: err = %v, want ErrXMLLimit", err)
	}
}

func TestParseSecurityRulesRefusesStatusErrorAndMalformedInput(t *testing.T) {
	if _, err := ParseSecurityRules(readFixture(t, "status-error.xml")); !errors.Is(err, ErrAPIStatus) {
		t.Fatalf("status error: err = %v", err)
	}
	for name, data := range map[string]string{
		"not xml":     `nope`,
		"no result":   `<response status="success"/>`,
		"truncated":   `<response status="success"><result><rules>`,
		"entity":      `<!DOCTYPE r [<!ENTITY x "y">]><response status="success"><result/></response>`,
		"wrong root":  `<reply status="success"><result/></reply>`,
		"bad charset": `<?xml version="1.0" encoding="ISO-8859-1"?><response status="success"><result/></response>`,
	} {
		if _, err := ParseSecurityRules([]byte(data)); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("%s: err = %v, want ErrMalformedResponse", name, err)
		}
	}
}

func TestParseSecurityRulesRejectsInvalidContent(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"repeated result", []byte(`<response status="success"><result/><result/></response>`)},
		{"repeated rules", wrapResult(`<rules/><rules/>`)},
		{"repeated vsys", wrapResult(`<vsys/><vsys/>`)},
		{"two vsys entries", wrapResult(`<vsys><entry name="vsys1"/><entry name="vsys2"/></vsys>`)},
		{"other vsys", wrapResult(`<vsys><entry name="vsys2"/></vsys>`)},
		{"vsys and direct rules", wrapResult(`<vsys><entry name="vsys1"/></vsys><rules/>`)},
		{"repeated rulebase", objectsBody(`<rulebase/><rulebase/>`)},
		{"repeated security", objectsBody(`<rulebase><security/><security/></rulebase>`)},
		{"repeated security rules", objectsBody(`<rulebase><security><rules/><rules/></security></rulebase>`)},
		{"duplicate rule name", rulesBody(minimalRule("r", "") + minimalRule("r", ""))},
		{"invalid rule name", rulesBody(minimalRule("bad/name", ""))},
		{"empty rule name", rulesBody(minimalRule("", ""))},
		{"long rule name", rulesBody(minimalRule(strings.Repeat("a", MaxNameLength+1), ""))},
		{"bad uuid", rulesBody(strings.Replace(minimalRule("r", ""), `name="r"`, `name="r" uuid="not-a-uuid"`, 1))},
		{"missing action", rulesBody(strings.Replace(minimalRule("r", ""), `<action>allow</action>`, ``, 1))},
		{"unknown action", rulesBody(strings.Replace(minimalRule("r", ""), `allow`, `permit`, 1))},
		{"repeated action", rulesBody(minimalRule("r", "<action>deny</action>"))},
		{"bad disabled", rulesBody(minimalRule("r", "<disabled>maybe</disabled>"))},
		{"repeated disabled", rulesBody(minimalRule("r", "<disabled>no</disabled><disabled>yes</disabled>"))},
		{"bad log-start", rulesBody(minimalRule("r", "<log-start>1</log-start>"))},
		{"bad negate", rulesBody(minimalRule("r", "<negate-source>true</negate-source>"))},
		{"unknown rule type", rulesBody(minimalRule("r", "<rule-type>sideways</rule-type>"))},
		{"missing from", rulesBody(strings.Replace(minimalRule("r", ""), `<from><member>any</member></from>`, ``, 1))},
		{"empty source", rulesBody(strings.Replace(minimalRule("r", ""), `<source><member>any</member></source>`, `<source/>`, 1))},
		{"missing service", rulesBody(strings.Replace(minimalRule("r", ""), `<service><member>any</member></service>`, ``, 1))},
		{"repeated from", rulesBody(minimalRule("r", "<from><member>any</member></from>"))},
		{"duplicate member", rulesBody(strings.Replace(minimalRule("r", ""), `<member>any</member></to>`, `<member>a</member><member>a</member></to>`, 1))},
		{"invalid zone", rulesBody(strings.Replace(minimalRule("r", ""), `<member>any</member></from>`, `<member>a/b</member></from>`, 1))},
		{"invalid address member", rulesBody(strings.Replace(minimalRule("r", ""), `<member>any</member></source>`, `<member>192.0.2.1/33</member></source>`, 1))},
		{"control in source user", rulesBody(minimalRule("r", "<source-user><member>a&#x9;b</member></source-user>"))},
		{"invalid application", rulesBody(strings.Replace(minimalRule("r", ""), `<member>any</member></application>`, `<member>app'x</member></application>`, 1))},
		{"invalid tag", rulesBody(minimalRule("r", "<tag><member>a&lt;b</member></tag>"))},
		{"repeated description", rulesBody(minimalRule("r", "<description>a</description><description>b</description>"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSecurityRules(c.data)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestParseSecurityRulesHostileDescription(t *testing.T) {
	// markup and SQL-looking text is kept verbatim as text; rendering
	// escapes it. Nothing in it is interpreted.
	got, err := ParseSecurityRules(readFixture(t, "rules.xml"))
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	var hostile Rule
	for _, r := range got.Rules {
		if r.Name == "hostile-text" {
			hostile = r
		}
	}
	want := `<script>alert(1)</script> & '"; DROP TABLE rules; --`
	if hostile.Description != want {
		t.Fatalf("description = %q, want %q", hostile.Description, want)
	}

	// text that could mislead a reader or a terminal is refused
	for name, desc := range map[string]string{
		"bidi override":  "allow " + string(rune(0x202e)) + "yna" + string(rune(0x202c)),
		"zero width":     "al" + string(rune(0x200b)) + "low",
		"newline":        "line one&#xA;line two",
		"escape":         "a\x1b[31mred",
		"replacement":    "a" + string(rune(0xfffd)) + "b",
		"line separator": "a" + string(rune(0x2028)) + "b",
		"oversize":       strings.Repeat("x", netdevcontract.MaxDescriptionBytes+1),
	} {
		_, err := ParseSecurityRules(rulesBody(minimalRule("r", "<description>"+desc+"</description>")))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), desc) || strings.Contains(err.Error(), "yna") {
			t.Errorf("%s: error repeats device text: %v", name, err)
		}
	}
	// the longest allowed description is accepted
	longest := strings.Repeat("x", netdevcontract.MaxDescriptionBytes)
	got, err = ParseSecurityRules(rulesBody(minimalRule("r", "<description>"+longest+"</description>")))
	if err != nil || got.Rules[0].Description != longest {
		t.Fatalf("max description: %v", err)
	}
}

func TestParseSecurityRulesErrorsNeverEchoDeviceText(t *testing.T) {
	const marker = "SECRETMARKER"
	for name, data := range map[string][]byte{
		"name":     rulesBody(minimalRule(marker+"/x", "")),
		"dup name": rulesBody(minimalRule(marker, "") + minimalRule(marker, "")),
		"action":   rulesBody(strings.Replace(minimalRule("r", ""), "allow", marker, 1)),
		"member":   rulesBody(strings.Replace(minimalRule("r", ""), `<member>any</member></source>`, `<member>`+marker+`'</member></source>`, 1)),
		"uuid":     rulesBody(strings.Replace(minimalRule("r", ""), `name="r"`, `name="r" uuid="`+marker+`"`, 1)),
	} {
		_, err := ParseSecurityRules(data)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: error repeats device text: %v", name, err)
		}
	}
}

func TestParseSecurityRulesIgnoresNATRulebase(t *testing.T) {
	data := objectsBody(`<rulebase><nat><rules>` + minimalRule("n", "") + `</rules></nat><security><rules>` +
		minimalRule("s", "") + `</rules></security></rulebase>`)
	got, err := ParseSecurityRules(data)
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	if !reflect.DeepEqual(ruleNames(got.Rules), []string{"s"}) {
		t.Fatalf("got %q", ruleNames(got.Rules))
	}
}

// fixtureRule returns the named rule of rules.xml and its objects.
func fixtureRule(t *testing.T, name string) (Rule, Objects) {
	t.Helper()
	data := readFixture(t, "rules.xml")
	rs, err := ParseSecurityRules(data)
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	o, err := ParseObjects(data)
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	for _, r := range rs.Rules {
		if r.Name == name {
			return r, o
		}
	}
	t.Fatalf("rule %s not in fixture", name)
	return Rule{}, Objects{}
}

func svcNames(ss []netdevcontract.ServiceObject) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Name)
	}
	return out
}

func TestResolveRuleExpandsGroups(t *testing.T) {
	r, o := fixtureRule(t, "internal-dns")
	got := ResolveRule(r, o)
	if len(got.Unresolved) != 0 || got.Incomplete {
		t.Fatalf("unexpected unresolved: %+v", got)
	}
	if !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"web-1", "web-2", "lab-net"}) || got.Source.Any {
		t.Fatalf("source = %+v", got.Source)
	}
	if !reflect.DeepEqual(got.Destination.Literals, []string{"192.0.2.53", "2001:db8::53"}) || len(got.Destination.Objects) != 0 {
		t.Fatalf("destination = %+v", got.Destination)
	}
	if !reflect.DeepEqual(svcNames(got.Service.Objects), []string{"svc-dns"}) {
		t.Fatalf("service = %+v", got.Service)
	}

	r, o = fixtureRule(t, "allow-web")
	got = ResolveRule(r, o)
	if !got.Source.Any || !reflect.DeepEqual(addrNames(got.Destination.Objects), []string{"web-1", "web-2"}) ||
		!reflect.DeepEqual(svcNames(got.Service.Objects), []string{"svc-http-alt"}) || len(got.Unresolved) != 0 {
		t.Fatalf("allow-web = %+v", got)
	}

	r, o = fixtureRule(t, "zz-allow-mgmt")
	got = ResolveRule(r, o)
	if !got.Service.ApplicationDefault || !got.Destination.Any || !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"nos-host"}) {
		t.Fatalf("zz-allow-mgmt = %+v", got)
	}

	r, o = fixtureRule(t, "any-any-deny")
	got = ResolveRule(r, o)
	if !got.Source.Any || !got.Destination.Any || !got.Service.Any || len(got.Unresolved) != 0 {
		t.Fatalf("any-any-deny = %+v", got)
	}
}

func TestResolveRuleKeepsUnknownMembers(t *testing.T) {
	r, o := fixtureRule(t, "unknown-ref")
	got := ResolveRule(r, o)
	want := []UnresolvedMember{
		{Field: FieldSource, Name: "ghost-host"},
		{Field: FieldService, Name: "service-http"},
	}
	if len(got.Unresolved) != len(want) {
		t.Fatalf("unresolved = %+v, want %+v", got.Unresolved, want)
	}
	for i, u := range got.Unresolved {
		if u.Field != want[i].Field || u.Name != want[i].Name || !errors.Is(u.Reason, ErrUnresolvedMember) {
			t.Fatalf("unresolved %d = %+v, want %+v (ErrUnresolvedMember)", i, u, want[i])
		}
	}
	// the known member next to the unknown one is still resolved
	if !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"web-1"}) {
		t.Fatalf("source = %+v", got.Source)
	}
	if !reflect.DeepEqual(got.Destination.Literals, []string{"198.51.100.0/25"}) {
		t.Fatalf("destination = %+v", got.Destination)
	}
	// the rule itself still lists every member
	if !reflect.DeepEqual(r.Source, []string{"ghost-host", "web-1"}) {
		t.Fatalf("rule source = %q", r.Source)
	}
}

func TestResolveRuleGroupFailuresAreUnresolved(t *testing.T) {
	r, o := fixtureRule(t, "dynamic-ref")
	got := ResolveRule(r, o)
	if len(got.Unresolved) != 1 || got.Unresolved[0].Name != "dyn-prod" || got.Unresolved[0].Field != FieldSource ||
		!errors.Is(got.Unresolved[0].Reason, ErrDynamicGroup) {
		t.Fatalf("unresolved = %+v", got.Unresolved)
	}
	if !reflect.DeepEqual(got.Destination.Literals, []string{"192.0.2.100-192.0.2.150"}) {
		t.Fatalf("destination = %+v", got.Destination)
	}

	// depth limit: a chain one deeper than allowed
	o, err := ParseObjects(objectsBody(groupChain(MaxGroupResolveDepth + 1)))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	rule := Rule{Source: []string{"g1"}, Destination: []string{"any"}, Service: []string{"any"}}
	got = ResolveRule(rule, o)
	if len(got.Unresolved) != 1 || !errors.Is(got.Unresolved[0].Reason, ErrGroupDepth) {
		t.Fatalf("depth: unresolved = %+v", got.Unresolved)
	}

	// cycle
	o, err = ParseObjects(objectsBody(`<address-group><entry name="x"><static><member>y</member></static></entry>` +
		`<entry name="y"><static><member>x</member></static></entry></address-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	got = ResolveRule(Rule{Destination: []string{"x"}}, o)
	if len(got.Unresolved) != 1 || got.Unresolved[0].Field != FieldDestination || !errors.Is(got.Unresolved[0].Reason, ErrGroupCycle) {
		t.Fatalf("cycle: unresolved = %+v", got.Unresolved)
	}

	// an unknown service group member
	o, err = ParseObjects(objectsBody(`<service-group><entry name="sg"><members><member>nope</member></members></entry></service-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	got = ResolveRule(Rule{Service: []string{"sg"}}, o)
	if len(got.Unresolved) != 1 || got.Unresolved[0].Field != FieldService || !errors.Is(got.Unresolved[0].Reason, ErrUnresolvedMember) {
		t.Fatalf("service group: unresolved = %+v", got.Unresolved)
	}
}

func TestResolveRuleIncompleteObjects(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<address>`)
	for i := range netdevcontract.MaxAddressObjects + 1 {
		fmt.Fprintf(&b, `<entry name="a%d"><ip-netmask>192.0.2.1</ip-netmask></entry>`, i)
	}
	b.WriteString(`</address>`)
	o, err := ParseObjects(objectsBody(b.String()))
	if err != nil || !o.Incomplete {
		t.Fatalf("ParseObjects: incomplete %v, err %v", o.Incomplete, err)
	}
	// a member that may have been cut away is incomplete, not unknown
	got := ResolveRule(Rule{Source: []string{"a0", fmt.Sprintf("a%d", netdevcontract.MaxAddressObjects)}}, o)
	if !got.Incomplete || len(got.Unresolved) != 1 || !errors.Is(got.Unresolved[0].Reason, ErrGroupIncomplete) {
		t.Fatalf("got %+v", got)
	}
	if !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"a0"}) {
		t.Fatalf("source = %+v", got.Source)
	}
}

func TestResolveRuleDeduplicatesObjects(t *testing.T) {
	r, o := fixtureRule(t, "internal-dns")
	r.Source = []string{"web-1", "web-servers", "all-internal"}
	got := ResolveRule(r, o)
	if !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"web-1", "web-2", "lab-net"}) {
		t.Fatalf("source = %q", addrNames(got.Source.Objects))
	}
}

func FuzzParseSecurityRules(f *testing.F) {
	f.Add(readFixture(f, "rules.xml"))
	f.Add(readFixture(f, "nat.xml"))
	f.Add(rulesBody(minimalRule("r", "<disabled>yes</disabled>")))
	f.Add(wrapResult(`<rules>` + minimalRule("r", "") + `</rules>`))
	f.Add(wrapResult(`<vsys/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseSecurityRules(data)
		if err != nil {
			if len(got.Rules) != 0 || got.Incomplete {
				t.Fatalf("error with non-zero result: %v", err)
			}
			return
		}
		if len(got.Rules) > netdevcontract.MaxSecurityRules {
			t.Fatalf("%d rules over limit", len(got.Rules))
		}
		seen := map[string]struct{}{}
		for i, r := range got.Rules {
			if r.Index != i {
				t.Fatalf("rule %d has index %d", i, r.Index)
			}
			if ValidateName(r.Name) != nil {
				t.Fatalf("rule %d has invalid name", i)
			}
			if _, dup := seen[r.Name]; dup {
				t.Fatalf("rule %d duplicated", i)
			}
			seen[r.Name] = struct{}{}
			if !validText(r.Description, netdevcontract.MaxDescriptionBytes) {
				t.Fatalf("rule %d has invalid description", i)
			}
			for _, f := range [][]string{r.From, r.To, r.Source, r.Destination, r.Application, r.Service} {
				if len(f) == 0 || len(f) > netdevcontract.MaxRuleMembers {
					t.Fatalf("rule %d has %d members", i, len(f))
				}
			}
			// resolution against no objects must not panic and must keep
			// every non-any, non-literal member as unresolved
			checkResolvedAgainstNoObjects(t, i, r, ResolveRule(r, Objects{}))
		}
	})
}

// checkResolvedAgainstNoObjects asserts that, with no objects, every
// source and destination member is "any", a literal or listed in
// Unresolved, and every service member is "any", "application-default"
// or listed in Unresolved, in field and member order.
func checkResolvedAgainstNoObjects(t *testing.T, i int, r Rule, got ResolvedRule) {
	t.Helper()
	var want []UnresolvedMember
	literals := map[RuleField]int{}
	for _, f := range []struct {
		field   RuleField
		members []string
	}{{FieldSource, r.Source}, {FieldDestination, r.Destination}} {
		for _, m := range f.members {
			if m == "any" {
				continue
			}
			if _, ok := addressLiteral(m); ok {
				literals[f.field]++
				continue
			}
			want = append(want, UnresolvedMember{Field: f.field, Name: m})
		}
	}
	for _, m := range r.Service {
		if m != "any" && m != "application-default" {
			want = append(want, UnresolvedMember{Field: FieldService, Name: m})
		}
	}
	if len(got.Unresolved) != len(want) {
		t.Fatalf("rule %d: %d unresolved, want %d", i, len(got.Unresolved), len(want))
	}
	for j, u := range got.Unresolved {
		if u.Field != want[j].Field || u.Name != want[j].Name || !errors.Is(u.Reason, ErrUnresolvedMember) {
			t.Fatalf("rule %d: unresolved %d = %+v, want %+v", i, j, u, want[j])
		}
	}
	if len(got.Source.Literals) != literals[FieldSource] || len(got.Destination.Literals) != literals[FieldDestination] {
		t.Fatalf("rule %d: literal count mismatch", i)
	}
	if len(got.Source.Objects)+len(got.Destination.Objects)+len(got.Service.Objects) != 0 {
		t.Fatalf("rule %d: objects resolved from no objects", i)
	}
}

// manyGroupObjects builds objects with nAddr address and service objects
// and nGroups address and service groups; group gI holds the objects
// a(2I), a(2I+1) and, for I > 0, the group g(I-1) (a shared nested chain
// is cut every 4 groups to stay under the depth limit).
func manyGroupObjects(nAddr, nGroups int) Objects {
	var o Objects
	for i := range nAddr {
		o.Addresses = append(o.Addresses, netdevcontract.AddressObject{
			Name: fmt.Sprintf("a%d", i), Type: netdevcontract.AddressNetmask, Value: "192.0.2.1"})
		o.Services = append(o.Services, netdevcontract.ServiceObject{
			Name: fmt.Sprintf("s%d", i), Protocol: "tcp", Port: "443"})
	}
	for i := range nGroups {
		ag := netdevcontract.Group{Name: fmt.Sprintf("g%d", i),
			Static: []string{fmt.Sprintf("a%d", (2*i)%nAddr), fmt.Sprintf("a%d", (2*i+1)%nAddr)}}
		sg := netdevcontract.Group{Name: fmt.Sprintf("sg%d", i),
			Static: []string{fmt.Sprintf("s%d", (2*i)%nAddr), fmt.Sprintf("s%d", (2*i+1)%nAddr)}}
		if i%4 != 0 {
			ag.Static = append(ag.Static, fmt.Sprintf("g%d", i-1))
			sg.Static = append(sg.Static, fmt.Sprintf("sg%d", i-1))
		}
		o.AddressGroups = append(o.AddressGroups, ag)
		o.ServiceGroups = append(o.ServiceGroups, sg)
	}
	return o
}

// manyGroupRule names every group of manyGroupObjects in source,
// destination and service.
func manyGroupRule(nGroups int) Rule {
	var r Rule
	for i := range nGroups {
		r.Source = append(r.Source, fmt.Sprintf("g%d", i))
		r.Service = append(r.Service, fmt.Sprintf("sg%d", i))
	}
	r.Destination = r.Source
	return r
}

func TestResolveRuleChecksEveryGroupOnce(t *testing.T) {
	const nAddr, nGroups = 4000, 1000
	o := manyGroupObjects(nAddr, nGroups)
	r := manyGroupRule(nGroups)

	got := ResolveRule(r, o)
	if len(got.Unresolved) != 0 || got.Incomplete {
		t.Fatalf("unexpected unresolved: %d", len(got.Unresolved))
	}
	// same result as expanding every member on its own, in first-seen order
	var wantAddr, wantSvc []string
	seenA, seenS := map[string]bool{}, map[string]bool{}
	for i := range nGroups {
		as, err := o.ResolveGroup(fmt.Sprintf("g%d", i))
		if err != nil {
			t.Fatalf("ResolveGroup: %v", err)
		}
		for _, n := range addrNames(as) {
			if !seenA[n] {
				seenA[n] = true
				wantAddr = append(wantAddr, n)
			}
		}
		ss, err := o.ResolveServiceGroup(fmt.Sprintf("sg%d", i))
		if err != nil {
			t.Fatalf("ResolveServiceGroup: %v", err)
		}
		for _, n := range svcNames(ss) {
			if !seenS[n] {
				seenS[n] = true
				wantSvc = append(wantSvc, n)
			}
		}
	}
	if !reflect.DeepEqual(addrNames(got.Source.Objects), wantAddr) || !reflect.DeepEqual(addrNames(got.Destination.Objects), wantAddr) {
		t.Fatalf("address expansion differs from ResolveGroup")
	}
	if !reflect.DeepEqual(svcNames(got.Service.Objects), wantSvc) {
		t.Fatalf("service expansion differs from ResolveServiceGroup")
	}

	// a RuleResolver checks every group once for any number of rules and
	// visits each group at most once per rule field
	rr := NewRuleResolver(o)
	for range 5 {
		before := rr.groupVisits.Load()
		if again := rr.Resolve(r); !reflect.DeepEqual(again, got) {
			t.Fatal("RuleResolver result differs from ResolveRule")
		}
		if n := rr.groupVisits.Load() - before; n > 3*nGroups {
			t.Fatalf("one rule visited groups %d times, want at most %d", n, 3*nGroups)
		}
	}
	if rr.groupChecks != 2*nGroups {
		t.Fatalf("groups checked %d times, want %d", rr.groupChecks, 2*nGroups)
	}
}

// sharedDeepGroupObjects builds the hostile shape of a shared group: a
// group "shared" that reaches nLeaves address objects through three
// nesting levels, and nParents groups p<i> that each hold only "shared".
func sharedDeepGroupObjects(nLeaves, nParents int) Objects {
	var o Objects
	for i := range nLeaves {
		o.Addresses = append(o.Addresses, netdevcontract.AddressObject{
			Name: fmt.Sprintf("a%d", i), Type: netdevcontract.AddressNetmask, Value: "192.0.2.1"})
	}
	var leafGroups []string
	for i := 0; i < nLeaves; i += netdevcontract.MaxGroupMembers {
		g := netdevcontract.Group{Name: fmt.Sprintf("leaf%d", len(leafGroups))}
		for j := i; j < min(i+netdevcontract.MaxGroupMembers, nLeaves); j++ {
			g.Static = append(g.Static, fmt.Sprintf("a%d", j))
		}
		o.AddressGroups = append(o.AddressGroups, g)
		leafGroups = append(leafGroups, g.Name)
	}
	o.AddressGroups = append(o.AddressGroups,
		netdevcontract.Group{Name: "d2", Static: leafGroups},
		netdevcontract.Group{Name: "d1", Static: []string{"d2"}},
		netdevcontract.Group{Name: "shared", Static: []string{"d1"}})
	for i := range nParents {
		o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{
			Name: fmt.Sprintf("p%d", i), Static: []string{"shared"}})
	}
	return o
}

func TestRuleResolverExpandsSharedDeepGroupOnce(t *testing.T) {
	// every parent re-expanding the shared subtree costs nParents x
	// nLeaves leaf visits per rule field (10^10 over the hostile rulebase);
	// a resolver checks each group once and visits the shared subtree once
	// per field
	const nLeaves, nParents, nRules = 20000, MaxRuleMembers, 10
	o := sharedDeepGroupObjects(nLeaves, nParents)
	nGroups := len(o.AddressGroups)
	var members []string
	for i := range nParents {
		members = append(members, fmt.Sprintf("p%d", i))
	}
	r := Rule{Source: members, Destination: members, Service: []string{"any"}}

	want, err := o.ResolveGroup("p0")
	if err != nil || len(want) != nLeaves {
		t.Fatalf("ResolveGroup: %d objects, %v", len(want), err)
	}
	// the output (two fields of nLeaves objects and their dedup sets) is
	// about 20 MiB per rule; expanding the shared group per parent
	// allocates over 1 MiB per member, gigabytes per rule
	const limit = nRules * (32 << 20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rr := NewRuleResolver(o)
	for i := range nRules {
		visits := rr.groupVisits.Load()
		got := rr.Resolve(r)
		if n := rr.groupVisits.Load() - visits; n > 2*int64(nGroups) {
			t.Fatalf("rule %d visited groups %d times, want at most %d", i, n, 2*nGroups)
		}
		if len(got.Unresolved) != 0 || !reflect.DeepEqual(got.Source.Objects, want) || !reflect.DeepEqual(got.Destination.Objects, want) {
			t.Fatalf("rule %d: %d unresolved, %d source objects", i, len(got.Unresolved), len(got.Source.Objects))
		}
	}
	runtime.ReadMemStats(&after)
	if rr.groupChecks != nGroups {
		t.Fatalf("groups checked %d times, want %d", rr.groupChecks, nGroups)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > limit {
		t.Fatalf("resolving %d rules allocated %d bytes, limit %d", nRules, n, limit)
	}
}

// sharedParentObjects builds the amplification shape of a shared parent:
// one group "big" that lists nAddr address objects, nMid groups m<i> that
// each hold "big" and one own address, and a diamond-shaped layer above
// them: h<j> holds m<j> and m<j+1>, t<k> holds h<k> and h<k+1>, so every
// m and h group is reached through two parents.
func sharedParentObjects(nAddr, nMid int) Objects {
	var o Objects
	for i := range nAddr + nMid {
		o.Addresses = append(o.Addresses, netdevcontract.AddressObject{
			Name: fmt.Sprintf("a%d", i), Type: netdevcontract.AddressNetmask, Value: "192.0.2.1"})
	}
	var big []string
	for i := range nAddr {
		big = append(big, fmt.Sprintf("a%d", i))
	}
	o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{Name: "big", Static: big})
	for i := range nMid {
		o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{
			Name: fmt.Sprintf("m%d", i), Static: []string{"big", fmt.Sprintf("a%d", nAddr+i)}})
	}
	for j := range nMid - 1 {
		o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{
			Name: fmt.Sprintf("h%d", j), Static: []string{fmt.Sprintf("m%d", j), fmt.Sprintf("m%d", j+1)}})
	}
	for k := range nMid - 2 {
		o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{
			Name: fmt.Sprintf("t%d", k), Static: []string{fmt.Sprintf("h%d", k), fmt.Sprintf("h%d", k+1)}})
	}
	return o
}

func TestRuleResolverGroupWalkIsBoundedAcrossRules(t *testing.T) {
	// re-walking the groups per rule iterates the 2,500 members of "big"
	// for every rule field (5*10^6 iterations for 1,000 rules); the memo
	// table walks each group once, so all rules together iterate at most
	// the total number of group members
	const nAddr, nMid, nRules = 2500, 150, 1000
	o := sharedParentObjects(nAddr, nMid)
	totalMembers := 0
	for _, g := range o.AddressGroups {
		totalMembers += len(g.Static)
	}
	want := map[string][]string{}
	expect := func(name string) []string {
		if w, ok := want[name]; ok {
			return w
		}
		objs, err := o.ResolveGroup(name)
		if err != nil {
			t.Fatalf("ResolveGroup(%s): %v", name, err)
		}
		want[name] = addrNames(objs)
		return want[name]
	}

	rr := NewRuleResolver(o)
	for i := range nRules {
		top := fmt.Sprintf("t%d", i%(nMid-2))
		mid := fmt.Sprintf("m%d", (i*7)%nMid)
		h := fmt.Sprintf("h%d", (i*13)%(nMid-1))
		got := rr.Resolve(Rule{Source: []string{top}, Destination: []string{mid, h}, Service: []string{"any"}})
		if len(got.Unresolved) != 0 {
			t.Fatalf("rule %d: unresolved %+v", i, got.Unresolved)
		}
		if !reflect.DeepEqual(addrNames(got.Source.Objects), expect(top)) {
			t.Fatalf("rule %d: source differs from ResolveGroup", i)
		}
		// first-seen order over the destination members
		var wantDst []string
		seen := map[string]bool{}
		for _, n := range append(append([]string{}, expect(mid)...), expect(h)...) {
			if !seen[n] {
				seen[n] = true
				wantDst = append(wantDst, n)
			}
		}
		if !reflect.DeepEqual(addrNames(got.Destination.Objects), wantDst) {
			t.Fatalf("rule %d: destination differs from ResolveGroup", i)
		}
	}
	if rr.memberIters > totalMembers {
		t.Fatalf("%d rules iterated %d group members, want at most the %d members of all groups", nRules, rr.memberIters, totalMembers)
	}
	if rr.groupChecks > len(o.AddressGroups) {
		t.Fatalf("groups entered %d times, want at most %d", rr.groupChecks, len(o.AddressGroups))
	}
	if n := rr.groupVisits.Load(); n != 3*nRules {
		t.Fatalf("memo lookups = %d, want one per direct group member (%d)", n, 3*nRules)
	}
}

func TestRuleResolverMemoizesFailures(t *testing.T) {
	// a failing group is walked once; later rules reuse the memoized error
	// and never iterate its members again
	o, err := ParseObjects(objectsBody(`<address><entry name="h"><ip-netmask>192.0.2.1</ip-netmask></entry></address>` +
		`<address-group><entry name="x"><static><member>h</member><member>y</member></static></entry>` +
		`<entry name="y"><static><member>x</member></static></entry>` +
		`<entry name="miss"><static><member>h</member><member>nothere</member></static></entry>` +
		`<entry name="dyn"><dynamic><filter>'t'</filter></dynamic></entry></address-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	rr := NewRuleResolver(o)
	r := Rule{Source: []string{"x", "y", "miss", "dyn"}, Destination: []string{"y"}}
	first := rr.Resolve(r)
	checks, iters, passes := rr.groupChecks, rr.memberIters, rr.reasonPasses
	if checks != len(o.AddressGroups) {
		t.Fatalf("groups entered %d times, want %d", checks, len(o.AddressGroups))
	}
	if passes != 4 {
		t.Fatalf("%d reason passes, want one per failing group (4)", passes)
	}
	for range 100 {
		if got := rr.Resolve(r); !reflect.DeepEqual(got, first) {
			t.Fatalf("result changed: %+v, want %+v", got, first)
		}
	}
	if rr.groupChecks != checks || rr.memberIters != iters || rr.reasonPasses != passes {
		t.Fatalf("repeated rules walked groups again: entered %d (was %d), members %d (was %d), reason passes %d (was %d)",
			rr.groupChecks, checks, rr.memberIters, iters, rr.reasonPasses, passes)
	}
	wantReasons := []error{ErrGroupCycle, ErrGroupCycle, ErrUnresolvedMember, ErrDynamicGroup, ErrGroupCycle}
	if len(first.Unresolved) != len(wantReasons) {
		t.Fatalf("unresolved = %+v", first.Unresolved)
	}
	for i, w := range wantReasons {
		if !errors.Is(first.Unresolved[i].Reason, w) {
			t.Fatalf("unresolved %d = %v, want %v", i, first.Unresolved[i].Reason, w)
		}
	}
}

func TestRuleResolverConcurrentUse(t *testing.T) {
	// the lazily filled memo table is shared by concurrent Resolve calls
	o := sharedParentObjects(200, 20)
	want := ResolveRule(Rule{Source: []string{"t0", "m5"}, Destination: []string{"h3"}, Service: []string{"any"}}, o)
	rr := NewRuleResolver(o)
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if got := rr.Resolve(Rule{Source: []string{"t0", "m5"}, Destination: []string{"h3"}, Service: []string{"any"}}); !reflect.DeepEqual(got, want) {
					errs <- "concurrent result differs"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestRuleResolverAgreesWithResolveGroup(t *testing.T) {
	// every group of a graph with cycles, too deep chains, dynamic, empty
	// and unresolved members: Resolve fails a member exactly when
	// ResolveGroup fails it, with the same reason when the group has a
	// single defect, and expands it to the same objects otherwise
	complete, err := ParseObjects(objectsBody(`<address><entry name="h1"><ip-netmask>192.0.2.1</ip-netmask></entry>` +
		`<entry name="h2"><ip-netmask>192.0.2.2</ip-netmask></entry></address>` +
		`<address-group>` +
		`<entry name="x"><static><member>h1</member><member>y</member></static></entry>` +
		`<entry name="y"><static><member>x</member></static></entry>` +
		`<entry name="nextToCycle"><static><member>h2</member><member>x</member></static></entry>` +
		`<entry name="ok"><static><member>h1</member><member>h2</member></static></entry>` +
		`<entry name="okParent"><static><member>ok</member><member>c1</member></static></entry>` +
		`<entry name="dyn"><dynamic><filter>'t'</filter></dynamic></entry>` +
		`<entry name="dynParent"><static><member>h1</member><member>dyn</member></static></entry>` +
		`<entry name="miss"><static><member>h1</member><member>nothere</member></static></entry>` +
		`<entry name="c1"><static><member>c2</member></static></entry>` +
		`<entry name="c2"><static><member>c3</member></static></entry>` +
		`<entry name="c3"><static><member>c4</member></static></entry>` +
		`<entry name="c4"><static><member>c5</member></static></entry>` +
		`<entry name="c5"><static><member>c6</member></static></entry>` +
		`<entry name="c6"><static><member>h2</member></static></entry>` +
		`<entry name="deep"><static><member>d1</member></static></entry>` +
		`<entry name="d1"><static><member>d2</member></static></entry>` +
		`<entry name="d2"><static><member>okParent</member></static></entry>` +
		// a cycle below a chain of MaxGroupResolveDepth groups: ResolveGroup
		// counts levels from the root and fails lc1..lc3 with ErrGroupDepth
		// before it reaches the cycle, lc4..lc8 with ErrGroupCycle
		`<entry name="lc1"><static><member>lc2</member></static></entry>` +
		`<entry name="lc2"><static><member>lc3</member></static></entry>` +
		`<entry name="lc3"><static><member>lc4</member></static></entry>` +
		`<entry name="lc4"><static><member>lc5</member></static></entry>` +
		`<entry name="lc5"><static><member>lc6</member></static></entry>` +
		`<entry name="lc6"><static><member>lc7</member></static></entry>` +
		`<entry name="lc7"><static><member>lc8</member></static></entry>` +
		`<entry name="lc8"><static><member>lx</member></static></entry>` +
		`<entry name="lx"><static><member>h1</member><member>ly</member></static></entry>` +
		`<entry name="ly"><static><member>lx</member></static></entry>` +
		// a group that expands (s, height 3) reached deep through a chain
		// k1..k6 whose end also holds an unknown member: from k1 ResolveGroup
		// enters s3 at level 9 (ErrGroupDepth); from r, which expanded s at
		// level 2 first, it skips s and reports the unknown member
		`<entry name="s"><static><member>s2</member></static></entry>` +
		`<entry name="s2"><static><member>s3</member></static></entry>` +
		`<entry name="s3"><static><member>h1</member></static></entry>` +
		`<entry name="k1"><static><member>k2</member></static></entry>` +
		`<entry name="k2"><static><member>k3</member></static></entry>` +
		`<entry name="k3"><static><member>k4</member></static></entry>` +
		`<entry name="k4"><static><member>k5</member></static></entry>` +
		`<entry name="k5"><static><member>k6</member></static></entry>` +
		`<entry name="k6"><static><member>s</member><member>nothere</member></static></entry>` +
		`<entry name="r"><static><member>s</member><member>k1</member></static></entry>` +
		`</address-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	// incomplete object data: an empty group (ErrGroupUnresolvable, and it
	// marks the objects incomplete), unknown members (ErrGroupIncomplete)
	// and a group cut at MaxGroupMembers (ErrGroupIncomplete)
	var long strings.Builder
	for i := range netdevcontract.MaxGroupMembers + 1 {
		fmt.Fprintf(&long, "<member>m%d</member>", i)
	}
	incomplete, err := ParseObjects(objectsBody(`<address><entry name="h1"><ip-netmask>192.0.2.1</ip-netmask></entry>` +
		`<entry name="h2"><ip-netmask>192.0.2.2</ip-netmask></entry></address>` +
		`<address-group>` +
		`<entry name="empty"><static/></entry>` +
		`<entry name="emptyParent"><static><member>h1</member><member>empty</member></static></entry>` +
		`<entry name="miss"><static><member>h1</member><member>nothere</member></static></entry>` +
		`<entry name="missParent"><static><member>h2</member><member>miss</member></static></entry>` +
		`<entry name="cut"><static>` + long.String() + `</static></entry>` +
		`<entry name="cutParent"><static><member>cut</member></static></entry>` +
		`<entry name="ok"><static><member>h1</member><member>h2</member></static></entry>` +
		`<entry name="okParent"><static><member>ok</member><member>h1</member></static></entry>` +
		`</address-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	if !incomplete.Incomplete {
		t.Fatal("fixture objects are complete, want incomplete")
	}

	sentinels := []error{ErrGroupCycle, ErrGroupDepth, ErrDynamicGroup, ErrUnresolvedMember, ErrGroupIncomplete, ErrGroupUnresolvable}
	covered := map[error]bool{}
	for _, o := range []Objects{complete, incomplete} {
		rr := NewRuleResolver(o)
		for _, g := range o.AddressGroups {
			want, wantErr := o.ResolveGroup(g.Name)
			for range 2 {
				got := rr.Resolve(Rule{Source: []string{g.Name}})
				if wantErr != nil {
					if len(got.Unresolved) != 1 || got.Unresolved[0].Name != g.Name || len(got.Source.Objects) != 0 {
						t.Fatalf("group %s: unresolved %+v, objects %d, want failure %v", g.Name, got.Unresolved, len(got.Source.Objects), wantErr)
					}
					for _, s := range sentinels {
						if errors.Is(wantErr, s) != errors.Is(got.Unresolved[0].Reason, s) {
							t.Fatalf("group %s: reason %v, want %v", g.Name, got.Unresolved[0].Reason, wantErr)
						}
						if errors.Is(wantErr, s) {
							covered[s] = true
						}
					}
					continue
				}
				if len(got.Unresolved) != 0 || !reflect.DeepEqual(got.Source.Objects, want) {
					t.Fatalf("group %s: unresolved %+v, objects %v, want %v", g.Name, got.Unresolved, addrNames(got.Source.Objects), addrNames(want))
				}
			}
		}
	}
	for _, s := range sentinels {
		if !covered[s] {
			t.Errorf("fixtures never fail a group with %v", s)
		}
	}
	// the reasons that depend on where ResolveGroup starts, pinned so the
	// fixtures keep exercising them; a fresh resolver per group and one
	// shared resolver whose memo was filled from other roots agree
	shared := NewRuleResolver(complete)
	for _, name := range []string{"k6", "s", "lc8", "lc4", "r", "k1", "lc1", "lc3"} {
		_ = shared.Resolve(Rule{Source: []string{name}})
	}
	for name, want := range map[string]error{
		"lc1": ErrGroupDepth, "lc3": ErrGroupDepth, "lc4": ErrGroupCycle, "lx": ErrGroupCycle,
		"k1": ErrGroupDepth, "k2": ErrUnresolvedMember, "r": ErrUnresolvedMember,
	} {
		if _, err := complete.ResolveGroup(name); !errors.Is(err, want) {
			t.Fatalf("fixture %s: ResolveGroup = %v, want %v", name, err, want)
		}
		for _, rr := range []*RuleResolver{NewRuleResolver(complete), shared} {
			got := rr.Resolve(Rule{Source: []string{name}})
			if len(got.Unresolved) != 1 || !errors.Is(got.Unresolved[0].Reason, want) {
				t.Fatalf("group %s: unresolved %+v, want %v", name, got.Unresolved, want)
			}
		}
	}
}

// randomGroupObjects builds a small random group graph over two address
// objects: members are objects, other groups (forward edges mostly, back
// edges for cycles) or unknown names; some groups are empty or dynamic.
func randomGroupObjects(rng *rand.Rand, nGroups int) Objects {
	o := Objects{Addresses: []netdevcontract.AddressObject{
		{Name: "h1", Type: netdevcontract.AddressNetmask, Value: "192.0.2.1"},
		{Name: "h2", Type: netdevcontract.AddressNetmask, Value: "192.0.2.2"},
	}}
	for i := range nGroups {
		g := netdevcontract.Group{Name: fmt.Sprintf("g%d", i)}
		switch rng.IntN(20) {
		case 0:
			o.AddressGroups = append(o.AddressGroups, g)
			continue
		case 1:
			g.DynamicFilter = "'t'"
			o.AddressGroups = append(o.AddressGroups, g)
			continue
		}
		for range 1 + rng.IntN(3) {
			switch r := rng.IntN(100); {
			case r < 30:
				g.Static = append(g.Static, fmt.Sprintf("h%d", 1+rng.IntN(2)))
			case r < 33:
				g.Static = append(g.Static, "nothere")
			case r < 38:
				g.Static = append(g.Static, fmt.Sprintf("g%d", rng.IntN(nGroups)))
			default:
				if i+1 < nGroups {
					g.Static = append(g.Static, fmt.Sprintf("g%d", i+1+rng.IntN(min(3, nGroups-i-1))))
				}
			}
		}
		o.AddressGroups = append(o.AddressGroups, g)
	}
	return o
}

func TestRuleResolverReasonMatchesResolveGroupOnRandomGraphs(t *testing.T) {
	// differential check of the reason pass: for every group of many random
	// graphs (cycles, chains over MaxGroupResolveDepth, shared subgroups,
	// unknown, empty and dynamic members), with a memo filled from random
	// roots first, Resolve reports exactly the reason of ResolveGroup
	rng := rand.New(rand.NewPCG(1, 2))
	for iter := range 400 {
		o := randomGroupObjects(rng, 6+rng.IntN(20))
		o.Incomplete = iter%5 == 0
		rr := NewRuleResolver(o)
		for range rng.IntN(4) {
			_ = rr.Resolve(Rule{Source: []string{o.AddressGroups[rng.IntN(len(o.AddressGroups))].Name}})
		}
		for _, g := range o.AddressGroups {
			want, wantErr := o.ResolveGroup(g.Name)
			got := rr.Resolve(Rule{Source: []string{g.Name}})
			if wantErr != nil {
				if len(got.Unresolved) != 1 || errors.Unwrap(got.Unresolved[0].Reason) != errors.Unwrap(wantErr) {
					t.Fatalf("graph %d group %s: unresolved %+v, want %v", iter, g.Name, got.Unresolved, wantErr)
				}
				continue
			}
			if len(got.Unresolved) != 0 || !reflect.DeepEqual(got.Source.Objects, want) {
				t.Fatalf("graph %d group %s: unresolved %+v, objects %v, want %v", iter, g.Name, got.Unresolved, addrNames(got.Source.Objects), addrNames(want))
			}
		}
	}
}

// addrObjects returns n address objects named <prefix>0 .. <prefix>(n-1).
func addrObjects(prefix string, n int) []netdevcontract.AddressObject {
	out := make([]netdevcontract.AddressObject, 0, n)
	for i := range n {
		out = append(out, netdevcontract.AddressObject{
			Name: fmt.Sprintf("%s%d", prefix, i), Type: netdevcontract.AddressNetmask, Value: "192.0.2.1"})
	}
	return out
}

// sharedWithOwnObjects builds the amplifying shape of the round-3 review:
// a group "shared" that reaches nShared address objects through leaf
// groups of MaxGroupMembers, and nGroups groups p<k> = {shared, o<k>}, each
// with its own object, so no two expansions are the same list.
func sharedWithOwnObjects(nShared, nGroups int) Objects {
	o := Objects{Addresses: append(addrObjects("a", nShared), addrObjects("o", nGroups)...)}
	var leafGroups []string
	for i := 0; i < nShared; i += netdevcontract.MaxGroupMembers {
		g := netdevcontract.Group{Name: fmt.Sprintf("leaf%d", len(leafGroups))}
		for j := i; j < min(i+netdevcontract.MaxGroupMembers, nShared); j++ {
			g.Static = append(g.Static, fmt.Sprintf("a%d", j))
		}
		o.AddressGroups = append(o.AddressGroups, g)
		leafGroups = append(leafGroups, g.Name)
	}
	o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{Name: "shared", Static: leafGroups})
	for k := range nGroups {
		o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{
			Name: fmt.Sprintf("p%d", k), Static: []string{"shared", fmt.Sprintf("o%d", k)}})
	}
	return o
}

// groupMembers is the total member count of groups.
func groupMembers(groups []netdevcontract.Group) int {
	n := 0
	for _, g := range groups {
		n += len(g.Static)
	}
	return n
}

func TestRuleResolverSharedGroupWithOwnMemberIsLinear(t *testing.T) {
	// round-3 HIGH: fields of MaxRuleMembers groups {shared 17,500-object
	// group, own object}. Merging every group's flattened expansion costs
	// about 4*10^7 leaf operations per field (10^12 over a rulebase); the
	// field merge enters "shared" once, so a rule costs O(groups + members)
	// and resolves completely
	const nShared, nGroups, nRules = 17500, MaxRuleMembers, 3
	o := sharedWithOwnObjects(nShared, nGroups)
	members := make([]string, 0, nGroups)
	for k := range nGroups {
		members = append(members, fmt.Sprintf("p%d", k))
	}
	r := Rule{Source: members, Destination: members, Service: []string{"any"}}
	var want []string
	for _, a := range o.Addresses {
		want = append(want, a.Name) // a0..a17499 through p0, then o0, o1, ...
	}
	total := groupMembers(o.AddressGroups)

	const allocLimit = 128 << 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rr := NewRuleResolver(o)
	for i := range nRules {
		ops := rr.leafOps.Load()
		got := rr.Resolve(r)
		if got.Incomplete || len(got.Unresolved) != 0 {
			t.Fatalf("rule %d: incomplete %v, unresolved %d", i, got.Incomplete, len(got.Unresolved))
		}
		if !reflect.DeepEqual(addrNames(got.Source.Objects), want) || !reflect.DeepEqual(addrNames(got.Destination.Objects), want) {
			t.Fatalf("rule %d: expansion differs from the first-seen order of ResolveGroup", i)
		}
		// a field iterates each reachable group's members once; the first
		// rule also walks every group once
		bound := int64(2 * total)
		if i == 0 {
			bound += int64(total)
		}
		if n := rr.leafOps.Load() - ops; n > bound {
			t.Fatalf("rule %d: %d leaf operations, want at most %d", i, n, bound)
		}
	}
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > allocLimit {
		t.Fatalf("resolving %d rules allocated %d bytes, limit %d", nRules, n, allocLimit)
	}
	if n := rr.resultLeaves.Load(); n != int64(nRules*2*len(want)) {
		t.Fatalf("result leaves charged %d, want %d", n, nRules*2*len(want))
	}
	if rr.memberIters != total {
		t.Fatalf("walk iterated %d members, want each of the %d once", rr.memberIters, total)
	}
	if objs, err := o.ResolveGroup("p1"); err != nil || len(objs) != nShared+1 || objs[nShared].Name != "o1" {
		t.Fatalf("ResolveGroup(p1): %d objects, %v", len(objs), err)
	}
}

func TestRuleResolverManySharingGroupsKeepNoLeafCopies(t *testing.T) {
	// round-3 MEDIUM: 4,990 groups {shared 15,000-object group, own object}
	// kept a flattened copy each (7.5*10^7 leaves, about 600 MB); the memo
	// keeps only the resolved member lists, as many entries as members
	const nShared, nGroups = 15000, 4990
	o := sharedWithOwnObjects(nShared, nGroups)
	var src, dst []string
	for k := range nGroups {
		if k%2 == 0 {
			src = append(src, fmt.Sprintf("p%d", k))
		} else {
			dst = append(dst, fmt.Sprintf("p%d", k))
		}
	}
	total := groupMembers(o.AddressGroups)

	const allocLimit = 128 << 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rr := NewRuleResolver(o)
	got := rr.Resolve(Rule{Source: src, Destination: dst, Service: []string{"any"}})
	runtime.ReadMemStats(&after)
	if got.Incomplete || len(got.Unresolved) != 0 || len(got.Source.Objects) != nShared+len(src) || len(got.Destination.Objects) != nShared+len(dst) {
		t.Fatalf("incomplete %v, unresolved %d, objects %d/%d", got.Incomplete, len(got.Unresolved), len(got.Source.Objects), len(got.Destination.Objects))
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > allocLimit {
		t.Fatalf("resolving allocated %d bytes, limit %d", n, allocLimit)
	}
	memo := 0
	for _, cs := range rr.addrs.codes {
		memo += len(cs)
	}
	if memo > total || rr.memberIters > total {
		t.Fatalf("memo holds %d entries after %d member iterations, want at most the %d group members", memo, rr.memberIters, total)
	}
	if n := rr.leafOps.Load(); n > int64(3*total) {
		t.Fatalf("%d leaf operations, want at most %d (walk plus two field merges)", n, 3*total)
	}
}

// duplicateGroupObjects builds nGroups groups that each list the same
// nAddr address objects: no nesting to share, so every field naming many
// of them iterates nGroups x nAddr members.
func duplicateGroupObjects(nAddr, nGroups int) Objects {
	o := Objects{Addresses: addrObjects("a", nAddr)}
	static := make([]string, 0, nAddr)
	for i := range nAddr {
		static = append(static, fmt.Sprintf("a%d", i))
	}
	for k := range nGroups {
		o.AddressGroups = append(o.AddressGroups, netdevcontract.Group{Name: fmt.Sprintf("g%d", k), Static: static})
	}
	return o
}

func TestRuleResolverLeafOpBudgetStopsAmplifyingRulebase(t *testing.T) {
	// fields of 2,000 groups that each list the same 2,000 objects cost
	// 4*10^6 operations per field, 8*10^10 over a 10,000-rule rulebase;
	// MaxResolveLeafOps stops the resolver after a few rules: every later
	// group member is ErrResolveBudget, the rules are Incomplete, and the
	// work done never exceeds the budget
	const nAddr, nGroups, nRules = 2000, 2000, 50
	o := duplicateGroupObjects(nAddr, nGroups)
	var members []string
	for k := range nGroups {
		members = append(members, fmt.Sprintf("g%d", k))
	}
	r := Rule{Source: members, Destination: members, Service: []string{"any"}}

	const allocLimit = 128 << 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rr := NewRuleResolver(o)
	complete, exhausted := 0, false
	for i := range nRules {
		got := rr.Resolve(r)
		if !got.Incomplete {
			if exhausted || len(got.Unresolved) != 0 || len(got.Source.Objects) != nAddr {
				t.Fatalf("rule %d: complete after exhaustion or wrong result", i)
			}
			complete++
			continue
		}
		exhausted = true
		if len(got.Unresolved) == 0 {
			t.Fatalf("rule %d: incomplete without unresolved members", i)
		}
		for _, u := range got.Unresolved {
			if !errors.Is(u.Reason, ErrResolveBudget) {
				t.Fatalf("rule %d: unresolved %+v, want ErrResolveBudget", i, u)
			}
		}
	}
	runtime.ReadMemStats(&after)
	if !exhausted {
		t.Fatalf("%d amplifying rules resolved without exhausting MaxResolveLeafOps", nRules)
	}
	// the walk (nGroups x nAddr) plus complete fields of nGroups x nAddr
	// each fit in the budget; one rule more does not
	perField := nGroups * nAddr
	if want := (MaxResolveLeafOps - perField) / (2 * perField); complete != want {
		t.Fatalf("%d rules resolved completely, want %d", complete, want)
	}
	// every charge is made before its work, so the work done is the charged
	// total minus the refused charges, each at most one group list
	if n := rr.leafOps.Load(); n <= MaxResolveLeafOps {
		t.Fatalf("leaf operations %d never exceeded the budget", n)
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > allocLimit {
		t.Fatalf("resolving %d rules allocated %d bytes, limit %d", nRules, n, allocLimit)
	}
}

func TestRuleResolverBudgetsAreChargedBeforeWork(t *testing.T) {
	o := sharedWithOwnObjects(10, 3)
	o.Services = []netdevcontract.ServiceObject{{Name: "s0", Protocol: "tcp", Port: "443"}}

	// result budget: three objects left, the group reaches eleven; the
	// field keeps the first three, the member is ErrResolveBudget, and every
	// later object member fails too
	rr := NewRuleResolver(o)
	rr.resultLeaves.Store(MaxResolveResultLeaves - 3)
	got := rr.Resolve(Rule{Source: []string{"p0", "a0"}, Destination: []string{"o2"}, Service: []string{"s0"}})
	if !got.Incomplete || !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"a0", "a1", "a2"}) {
		t.Fatalf("incomplete %v, source %v", got.Incomplete, addrNames(got.Source.Objects))
	}
	wantNames := []string{"p0", "o2", "s0"} // a0 is a duplicate and costs no result
	if len(got.Unresolved) != len(wantNames) {
		t.Fatalf("unresolved %+v", got.Unresolved)
	}
	for i, u := range got.Unresolved {
		if u.Name != wantNames[i] || !errors.Is(u.Reason, ErrResolveBudget) {
			t.Fatalf("unresolved %d = %+v, want %s with ErrResolveBudget", i, u, wantNames[i])
		}
	}

	// a group entered before the stop ("shared", through p0) is not taken as
	// merged when a later member names it
	rr = NewRuleResolver(o)
	rr.resultLeaves.Store(MaxResolveResultLeaves - 3)
	got = rr.Resolve(Rule{Source: []string{"p0", "shared"}})
	if !got.Incomplete || len(got.Unresolved) != 2 || got.Unresolved[1].Name != "shared" || !errors.Is(got.Unresolved[1].Reason, ErrResolveBudget) {
		t.Fatalf("incomplete %v, unresolved %+v", got.Incomplete, got.Unresolved)
	}

	// operation budget exhausted inside the walk: the walk stops, nothing
	// is memoized as a group failure, and the member is ErrResolveBudget
	rr = NewRuleResolver(o)
	rr.leafOps.Store(MaxResolveLeafOps - 2) // p0 (2 members) fits, shared does not
	got = rr.Resolve(Rule{Source: []string{"p0"}})
	if !got.Incomplete || len(got.Unresolved) != 1 || !errors.Is(got.Unresolved[0].Reason, ErrResolveBudget) {
		t.Fatalf("incomplete %v, unresolved %+v", got.Incomplete, got.Unresolved)
	}
	for gi, st := range rr.addrs.state {
		if st == walkVisiting || rr.addrs.err[gi] != nil {
			t.Fatalf("group %s left in state %d with error %v", o.AddressGroups[gi].Name, st, rr.addrs.err[gi])
		}
	}
	if len(rr.addrs.reason) != 0 {
		t.Fatalf("reasons memoized after a budget stop: %v", rr.addrs.reason)
	}
	// the budget stays exhausted
	if again := rr.Resolve(Rule{Source: []string{"a0"}}); !again.Incomplete || len(again.Source.Objects) != 0 {
		t.Fatalf("resolved after exhaustion: %+v", again)
	}

	// operation budget exhausted inside the reason pass of a failing group
	bad := sharedWithOwnObjects(10, 1)
	bad.AddressGroups = append(bad.AddressGroups, netdevcontract.Group{Name: "x", Static: []string{"p0", "nothere"}})
	rr = NewRuleResolver(bad)
	if err := rr.lookup(&rr.addrs, len(bad.AddressGroups)-1); !errors.Is(err, ErrUnresolvedMember) {
		t.Fatalf("lookup = %v", err)
	}
	rr = NewRuleResolver(bad)
	rr.mu.Lock()
	if err := rr.addrs.expand(len(bad.AddressGroups)-1, rr); !errors.Is(err, ErrUnresolvedMember) {
		t.Fatalf("expand = %v", err)
	}
	rr.mu.Unlock()
	rr.leafOps.Store(MaxResolveLeafOps)
	got = rr.Resolve(Rule{Source: []string{"x"}})
	if !got.Incomplete || len(got.Unresolved) != 1 || !errors.Is(got.Unresolved[0].Reason, ErrResolveBudget) || len(rr.addrs.reason) != 0 {
		t.Fatalf("incomplete %v, unresolved %+v, reasons %v", got.Incomplete, got.Unresolved, rr.addrs.reason)
	}
}

// mediumConfig builds a realistic medium configuration: 8,000 addresses,
// 1,500 address groups in three nesting levels with 20 widely shared
// groups of 400 objects, 300 services in 100 service groups, and 3,000
// rules with 1 to 8 source and destination members and 1 to 4 services.
func mediumConfig(rng *rand.Rand) (Objects, []Rule) {
	o := Objects{Addresses: addrObjects("a", 8000)}
	for i := range 300 {
		o.Services = append(o.Services, netdevcontract.ServiceObject{Name: fmt.Sprintf("s%d", i), Protocol: "tcp", Port: "443"})
	}
	pick := func(prefix string, n, from, to int) []string {
		seen := map[string]bool{}
		var out []string
		for range n {
			name := fmt.Sprintf("%s%d", prefix, from+rng.IntN(to-from))
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		return out
	}
	for i := range 1500 {
		g := netdevcontract.Group{Name: fmt.Sprintf("g%d", i)}
		switch {
		case i < 20:
			g.Static = pick("a", 400, 0, 8000)
		case i < 500:
			g.Static = pick("a", 2+rng.IntN(19), 0, 8000)
		case i < 1200:
			g.Static = append(pick("g", 1+rng.IntN(4), 20, 500), pick("a", rng.IntN(11), 0, 8000)...)
			if rng.IntN(10) < 3 {
				g.Static = append(g.Static, fmt.Sprintf("g%d", rng.IntN(20)))
			}
		default:
			g.Static = append(pick("g", 1+rng.IntN(3), 500, 1200), pick("a", rng.IntN(6), 0, 8000)...)
		}
		o.AddressGroups = append(o.AddressGroups, g)
	}
	for i := range 100 {
		g := netdevcontract.Group{Name: fmt.Sprintf("sg%d", i), Static: pick("s", 2+rng.IntN(9), 0, 300)}
		if i >= 50 {
			g.Static = append(g.Static, pick("sg", 1+rng.IntN(2), 0, 50)...)
		}
		o.ServiceGroups = append(o.ServiceGroups, g)
	}
	addrMembers := func() []string {
		var out []string
		for range 1 + rng.IntN(8) {
			switch r := rng.IntN(10); {
			case r < 4:
				out = append(out, fmt.Sprintf("a%d", rng.IntN(8000)))
			case r < 9:
				out = append(out, fmt.Sprintf("g%d", rng.IntN(1500)))
			default:
				out = append(out, fmt.Sprintf("10.%d.0.0/16", rng.IntN(256)))
			}
		}
		return out
	}
	var rules []Rule
	for range 3000 {
		r := Rule{Source: addrMembers(), Destination: addrMembers()}
		for range 1 + rng.IntN(4) {
			if rng.IntN(2) == 0 {
				r.Service = append(r.Service, fmt.Sprintf("s%d", rng.IntN(300)))
			} else {
				r.Service = append(r.Service, fmt.Sprintf("sg%d", rng.IntN(100)))
			}
		}
		rules = append(rules, r)
	}
	return o, rules
}

// expectAddrs is the reference expansion of address members: ResolveGroup
// per group member, merged in first-seen order.
func expectAddrs(t *testing.T, o Objects, members []string) []string {
	t.Helper()
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, m := range members {
		if strings.HasPrefix(m, "a") {
			add(m)
			continue
		}
		if !strings.HasPrefix(m, "g") {
			continue
		}
		objs, err := o.ResolveGroup(m)
		if err != nil {
			t.Fatalf("ResolveGroup(%s): %v", m, err)
		}
		for _, a := range objs {
			add(a.Name)
		}
	}
	return out
}

func TestRuleResolverResolvesRealisticConfigCompletely(t *testing.T) {
	// a realistic medium configuration resolves completely and uses a small
	// part of both budgets
	o, rules := mediumConfig(rand.New(rand.NewPCG(7, 11)))
	rr := NewRuleResolver(o)
	for i, r := range rules {
		got := rr.Resolve(r)
		if got.Incomplete || len(got.Unresolved) != 0 {
			t.Fatalf("rule %d: incomplete %v, unresolved %+v", i, got.Incomplete, got.Unresolved)
		}
		if i%60 == 0 {
			for _, f := range []struct {
				members []string
				objs    []netdevcontract.AddressObject
			}{{r.Source, got.Source.Objects}, {r.Destination, got.Destination.Objects}} {
				if g, w := addrNames(f.objs), expectAddrs(t, o, f.members); !slices.Equal(g, w) {
					t.Fatalf("rule %d: members %q expand to %d objects %q, ResolveGroup to %d %q", i, f.members, len(g), g, len(w), w)
				}
			}
		}
	}
	ops, results := rr.leafOps.Load(), rr.resultLeaves.Load()
	t.Logf("%d rules: %d leaf operations, %d result objects", len(rules), ops, results)
	if ops > MaxResolveLeafOps/8 || results > MaxResolveResultLeaves/8 {
		t.Fatalf("realistic config used %d of %d operations and %d of %d result objects, want under an eighth", ops, MaxResolveLeafOps, results, MaxResolveResultLeaves)
	}
}

func TestResolveRuleWorkDoesNotScaleWithMembersTimesObjects(t *testing.T) {
	// a rebuilt object index per group member (MaxRuleMembers members over
	// 20000 objects, three fields) allocates gigabytes; one index for the
	// rule stays at a few megabytes
	o := manyGroupObjects(20000, MaxRuleMembers)
	r := manyGroupRule(MaxRuleMembers)
	const limit = 64 << 20
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := ResolveRule(r, o)
	runtime.ReadMemStats(&after)
	if len(got.Unresolved) != 0 || len(got.Source.Objects) != 2*MaxRuleMembers {
		t.Fatalf("unexpected result: %d unresolved, %d source objects", len(got.Unresolved), len(got.Source.Objects))
	}
	if n := after.TotalAlloc - before.TotalAlloc; n > limit {
		t.Fatalf("ResolveRule allocated %d bytes, limit %d", n, limit)
	}
}

func TestRuleResolverKeepsFailureSemantics(t *testing.T) {
	// the shared index must not leak state between members: a failing
	// group (cycle) next to a good one is unresolved, the good one resolves
	o, err := ParseObjects(objectsBody(`<address><entry name="h"><ip-netmask>192.0.2.1</ip-netmask></entry></address>` +
		`<address-group><entry name="x"><static><member>y</member></static></entry>` +
		`<entry name="y"><static><member>x</member></static></entry>` +
		`<entry name="ok"><static><member>h</member></static></entry></address-group>`))
	if err != nil {
		t.Fatalf("ParseObjects: %v", err)
	}
	rr := NewRuleResolver(o)
	for range 2 {
		got := rr.Resolve(Rule{Source: []string{"x", "ok", "y"}, Destination: []string{"ok"}})
		if len(got.Unresolved) != 2 || !errors.Is(got.Unresolved[0].Reason, ErrGroupCycle) || got.Unresolved[0].Name != "x" ||
			!errors.Is(got.Unresolved[1].Reason, ErrGroupCycle) || got.Unresolved[1].Name != "y" {
			t.Fatalf("unresolved = %+v", got.Unresolved)
		}
		if !reflect.DeepEqual(addrNames(got.Source.Objects), []string{"h"}) || !reflect.DeepEqual(addrNames(got.Destination.Objects), []string{"h"}) {
			t.Fatalf("source %+v destination %+v", got.Source, got.Destination)
		}
	}
}

func TestRuleKeepsNameShapedLiteralsAsConfigured(t *testing.T) {
	// members that pass ValidateName are stored as configured, even when
	// they look like addresses; ResolveRule reads a valid one as literal
	// and reports an invalid one (descending range) as unresolved
	desc := "10.0.0.9-10.0.0.1"
	got, err := ParseSecurityRules(rulesBody(`<entry name="r"><from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>10.0.0.1</member><member>` + desc + `</member></source>` +
		`<destination><member>any</member></destination><application><member>any</member></application>` +
		`<service><member>any</member></service><action>allow</action></entry>`))
	if err != nil {
		t.Fatalf("ParseSecurityRules: %v", err)
	}
	r := got.Rules[0]
	if !reflect.DeepEqual(r.Source, []string{"10.0.0.1", desc}) {
		t.Fatalf("source = %q", r.Source)
	}
	res := ResolveRule(r, Objects{})
	if !reflect.DeepEqual(res.Source.Literals, []string{"10.0.0.1"}) {
		t.Fatalf("literals = %q", res.Source.Literals)
	}
	if len(res.Unresolved) != 1 || res.Unresolved[0].Name != desc || !errors.Is(res.Unresolved[0].Reason, ErrUnresolvedMember) {
		t.Fatalf("unresolved = %+v", res.Unresolved)
	}
}

func BenchmarkResolveRuleManyGroups(b *testing.B) {
	o := manyGroupObjects(20000, MaxRuleMembers)
	r := manyGroupRule(MaxRuleMembers)
	b.ResetTimer()
	for b.Loop() {
		_ = ResolveRule(r, o)
	}
}
