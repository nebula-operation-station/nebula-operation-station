// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
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

// countIndexBuilds installs the index build hook for the test.
func countIndexBuilds(t *testing.T) *int {
	t.Helper()
	n := new(int)
	resolveIndexHook = func() { *n++ }
	t.Cleanup(func() { resolveIndexHook = nil })
	return n
}

func TestResolveRuleBuildsObjectIndexOnce(t *testing.T) {
	const nAddr, nGroups = 4000, 1000
	o := manyGroupObjects(nAddr, nGroups)
	r := manyGroupRule(nGroups)
	builds := countIndexBuilds(t)

	got := ResolveRule(r, o)
	if *builds != 1 {
		t.Fatalf("object index built %d times for one rule, want 1", *builds)
	}
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

	// a RuleResolver builds the index once for any number of rules
	*builds = 0
	rr := NewRuleResolver(o)
	for range 5 {
		if again := rr.Resolve(r); !reflect.DeepEqual(again, got) {
			t.Fatal("RuleResolver result differs from ResolveRule")
		}
	}
	if *builds != 1 {
		t.Fatalf("object index built %d times for one RuleResolver, want 1", *builds)
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
