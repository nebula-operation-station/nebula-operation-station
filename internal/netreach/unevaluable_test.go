// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func mustIndex(t *testing.T, s *Snapshot) *Index {
	t.Helper()
	x, err := NewIndex(s)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	return x
}

func TestLabFixtureIsEvaluableAndComplete(t *testing.T) {
	x := mustIndex(t, labSnapshot())
	for _, v := range x.SecurityRules() {
		if !v.Evaluable() || v.Reason() != "" || len(v.Conditions) != 0 {
			t.Errorf("rule %s: %+v", v.Name, v)
		}
	}
	for _, v := range x.NATRules() {
		if !v.Evaluable() {
			t.Errorf("NAT rule %s: %s", v.Name, v.Reason())
		}
	}
	for _, intra := range []bool{true, false} {
		if d := x.DefaultRule(intra); !d.Evaluable() {
			t.Errorf("default rule %s: %s", d.Name, d.Reason())
		}
	}
	if c := x.PathCompleteness("wan", "dmz"); !c.Complete {
		t.Errorf("completeness: %v", c.Reasons)
	}
}

func TestExpansion(t *testing.T) {
	s := labSnapshot()
	s.SecurityRules = []SecurityRule{
		evaluableRule("r", ActionAllow, []string{"any"}, []string{"any"}, []string{"nested", "2001:db8::/126"}, []string{"10.0.0.1-10.0.0.3"}, []string{"web", "svc-dns"}),
	}
	v := mustIndex(t, s).SecurityRules()[0]
	if !v.Evaluable() {
		t.Fatalf("unevaluable: %s", v.Reason())
	}
	var src []string
	for _, r := range v.Source.Ranges {
		src = append(src, r.From.String()+"-"+r.To.String())
	}
	want := []string{"10.20.0.10-10.20.0.10", "10.0.1.10-10.0.1.20", "10.0.9.9-10.0.9.9", "10.0.0.0-10.0.255.255", "2001:db8::-2001:db8::3"}
	if !slices.Equal(src, want) {
		t.Errorf("source = %v, want %v", src, want)
	}
	if len(v.Destination.Ranges) != 1 || v.Destination.Ranges[0].To != addr("10.0.0.3") {
		t.Errorf("destination = %+v", v.Destination)
	}
	wantPorts := []PortRange{{"tcp", 443, 443}, {"tcp", 8000, 8080}, {"tcp", 9000, 9000}, {"udp", 53, 53}}
	if !slices.Equal(v.Service.Ports, wantPorts) {
		t.Errorf("ports = %v, want %v", v.Service.Ports, wantPorts)
	}
}

// TestUnevaluableSecurityRuleFailSafe covers ADR 0012 D2 "Required tests
// (NS-05)" item 1 for security rules: each case makes a deny rule
// unevaluable, with the reason "rule <name> unevaluable: <field or
// marker>", and the snapshot not complete for the path.
func TestUnevaluableSecurityRuleFailSafe(t *testing.T) {
	tests := []struct {
		name   string
		mod    func(s *Snapshot, r *SecurityRule)
		reason string
	}{
		{"rule-type intrazone", func(_ *Snapshot, r *SecurityRule) { r.Type = Collected(RuleTypeIntrazone) }, "rule-type: intrazone not modelled"},
		{"rule-type interzone", func(_ *Snapshot, r *SecurityRule) { r.Type = Collected(RuleTypeInterzone) }, "rule-type: interzone not modelled"},
		{"rule-type not collected", func(_ *Snapshot, r *SecurityRule) { r.Type = Field[RuleType]{} }, "rule-type: not collected"},
		{"source-hip set", func(_ *Snapshot, r *SecurityRule) { r.SourceHIP = list("corp-laptops") }, "source-hip: HIP profiles not modelled"},
		{"destination-hip set", func(_ *Snapshot, r *SecurityRule) { r.DestinationHIP = list("srv") }, "destination-hip: HIP profiles not modelled"},
		{"source-hip not collected", func(_ *Snapshot, r *SecurityRule) { r.SourceHIP = Field[[]string]{} }, "source-hip: not collected"},
		{"destination-hip not collected", func(_ *Snapshot, r *SecurityRule) { r.DestinationHIP = Field[[]string]{} }, "destination-hip: not collected"},
		{"negate-source not collected", func(_ *Snapshot, r *SecurityRule) { r.NegateSource = Field[bool]{} }, "negate-source: not collected"},
		{"negate-destination not collected", func(_ *Snapshot, r *SecurityRule) { r.NegateDestination = Field[bool]{} }, "negate-destination: not collected"},
		{"dropped marker on rule", func(_ *Snapshot, r *SecurityRule) { r.Dropped = []string{"<dropped:option>"} }, "<dropped:option>: rule"},
		{"dropped marker as member", func(_ *Snapshot, r *SecurityRule) { r.Destination = list("<dropped:member>") }, "<dropped:member>: destination"},
		{"dropped marker on object", func(s *Snapshot, _ *SecurityRule) { s.Addresses[2].Dropped = []string{"<dropped:value>"} }, "<dropped:value>: address lan-net"},
		{"dropped marker on nested group", func(s *Snapshot, r *SecurityRule) {
			r.Source = list("nested")
			s.AddressGroups[0].Dropped = []string{"<dropped:static>"}
		}, "<dropped:static>: group servers"},
		{"dropped marker on service", func(s *Snapshot, r *SecurityRule) {
			r.Service = list("svc-dns")
			s.Services[1].Dropped = []string{"<dropped:port>"}
		}, "<dropped:port>: service svc-dns"},
		{"field outside allowlist", func(_ *Snapshot, r *SecurityRule) { r.OutsideAllowlist = []string{"source-imei"} }, "source-imei: outside the collected allowlist"},
		{"disabled not collected", func(_ *Snapshot, r *SecurityRule) { r.Disabled = Field[bool]{} }, "disabled: not collected"},
		{"source not collected", func(_ *Snapshot, r *SecurityRule) { r.Source = Field[[]string]{} }, "source: not collected"},
		{"empty source never any", func(_ *Snapshot, r *SecurityRule) { r.Source = list() }, "source: empty"},
		{"unknown action", func(_ *Snapshot, r *SecurityRule) { r.Action = "continue" }, "action: unknown action"},
		{"zone not in snapshot", func(_ *Snapshot, r *SecurityRule) { r.To = list("mgmt", "vsys2-zone") }, "to: zone vsys2-zone not in snapshot"},
		{"fqdn object", func(_ *Snapshot, r *SecurityRule) { r.Destination = list("cloud") }, "destination: address cloud: type fqdn not evaluable"},
		{"wildcard object", func(s *Snapshot, r *SecurityRule) {
			s.Addresses = append(s.Addresses, AddressObject{Name: "wc", Type: AddressWildcard, Value: "10.0.0.1/0.0.255.0"})
			r.Destination = list("wc")
		}, "destination: address wc: type ip-wildcard not evaluable"},
		{"edl object", func(s *Snapshot, r *SecurityRule) {
			s.Addresses = append(s.Addresses, AddressObject{Name: "bad-ips", Type: AddressEDL})
			r.Source = list("bad-ips")
		}, "source: address bad-ips: type edl not evaluable"},
		{"region member", func(_ *Snapshot, r *SecurityRule) { r.Source = list("RU") }, "source: member RU: object not found"},
		{"dynamic group", func(_ *Snapshot, r *SecurityRule) { r.Source = list("dyn") }, "source: group dyn: dynamic members unknown"},
		{"empty static group", func(s *Snapshot, r *SecurityRule) {
			s.AddressGroups = append(s.AddressGroups, Group{Name: "empty"})
			r.Source = list("empty")
		}, "source: group empty: no members"},
		{"group cycle", func(s *Snapshot, r *SecurityRule) {
			s.AddressGroups = append(s.AddressGroups, Group{Name: "g1", Static: []string{"g2"}}, Group{Name: "g2", Static: []string{"g1"}})
			r.Source = list("g1")
		}, "source: group g1: cycle"},
		{"mapped literal", func(_ *Snapshot, r *SecurityRule) { r.Source = list("::ffff:10.0.0.1") }, "source: member ::ffff:10.0.0.1: object not found"},
		{"invalid netmask value", func(s *Snapshot, r *SecurityRule) {
			s.Addresses = append(s.Addresses, AddressObject{Name: "bad", Type: AddressNetmask, Value: "10.0.0.1-10.0.0.2"})
			r.Source = list("bad")
		}, "source: address bad: range in an ip-netmask object"},
		{"descending range", func(s *Snapshot, r *SecurityRule) {
			s.Addresses = append(s.Addresses, AddressObject{Name: "bad", Type: AddressRange, Value: "10.0.0.9-10.0.0.2"})
			r.Source = list("bad")
		}, "source: address bad: invalid range"},
		{"predefined service unknown", func(_ *Snapshot, r *SecurityRule) { r.Service = list("service-http") }, "service: member service-http: object not found"},
		{"service source-port not collected", func(s *Snapshot, r *SecurityRule) {
			s.Services[1].SourcePorts = Field[string]{}
			r.Service = list("svc-dns")
		}, "service: service svc-dns: source-port not collected"},
		{"service source-port condition", func(s *Snapshot, r *SecurityRule) {
			s.Services[1].SourcePorts = Collected("1024-65535")
			r.Service = list("svc-dns")
		}, "service: service svc-dns: source-port condition not modelled"},
		{"service invalid port", func(s *Snapshot, r *SecurityRule) {
			s.Services[1].Ports = "0"
			r.Service = list("svc-dns")
		}, "service: service svc-dns: invalid port"},
		{"service unknown protocol", func(s *Snapshot, r *SecurityRule) {
			s.Services[1].Protocol = "icmp"
			r.Service = list("svc-dns")
		}, "service: service svc-dns: protocol not evaluable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s, &s.SecurityRules[1])
			x := mustIndex(t, s)
			v := x.SecurityRules()[1]
			if v.Evaluable() {
				t.Fatalf("rule evaluable: %+v", v)
			}
			want := "rule deny-lan-mgmt unevaluable: " + tc.reason
			if v.Reason() != want {
				t.Fatalf("reason %q, want %q", v.Reason(), want)
			}
			if !x.SecurityRules()[0].Evaluable() {
				t.Errorf("other rule affected: %s", x.SecurityRules()[0].Reason())
			}
			c := x.PathCompleteness("lan", "mgmt")
			if c.Complete || !slices.Contains(c.Reasons, want) {
				t.Errorf("completeness %+v, want incomplete with %q", c, want)
			}
		})
	}
}

func TestDisabledRuleIsSkippedNotUnevaluable(t *testing.T) {
	s := labSnapshot()
	r := &s.SecurityRules[1]
	r.Disabled = Collected(true)
	r.Type = Field[RuleType]{}
	r.Dropped = []string{"<dropped:x>"}
	x := mustIndex(t, s)
	v := x.SecurityRules()[1]
	if !v.Disabled || !v.Evaluable() || v.Reason() != "" {
		t.Fatalf("disabled rule: %+v", v)
	}
	if c := x.PathCompleteness("lan", "mgmt"); !c.Complete {
		t.Fatalf("disabled rule makes path incomplete: %v", c.Reasons)
	}
}

// TestSnapshotWithoutQ11Fields is the "today" case of ADR 0012 Q11: no
// negation flags, rule types, HIP fields and default rules collected.
// Every rule and the default-rule step are unevaluable; no path is
// complete.
func TestSnapshotWithoutQ11Fields(t *testing.T) {
	s := labSnapshot()
	for i := range s.SecurityRules {
		r := &s.SecurityRules[i]
		r.NegateSource, r.NegateDestination = Field[bool]{}, Field[bool]{}
		r.Type = Field[RuleType]{}
		r.SourceHIP, r.DestinationHIP = Field[[]string]{}, Field[[]string]{}
	}
	s.DefaultRules = Field[DefaultRules]{}
	x := mustIndex(t, s)
	for _, v := range x.SecurityRules() {
		if v.Evaluable() || !strings.HasPrefix(v.Reason(), "rule "+v.Name+" unevaluable: negate-source") {
			t.Errorf("rule %s: %q", v.Name, v.Reason())
		}
	}
	for _, intra := range []bool{true, false} {
		d := x.DefaultRule(intra)
		want := "rule " + d.Name + " unevaluable: rulebase/default-security-rules: not collected"
		if d.Evaluable() || d.Reason() != want {
			t.Errorf("default %v: %q, want %q", intra, d.Reason(), want)
		}
	}
	for _, p := range [][2]string{{"wan", "dmz"}, {"lan", "lan"}, {"dmz", "mgmt"}} {
		if c := x.PathCompleteness(p[0], p[1]); c.Complete {
			t.Errorf("path %v complete", p)
		}
	}
}

func TestDefaultRulesUnevaluable(t *testing.T) {
	tests := []struct {
		name  string
		d     DefaultRules
		intra string
		inter string
	}{
		{"dropped marker", DefaultRules{Intrazone: ActionAllow, Interzone: ActionDeny, Dropped: []string{"<dropped:log-setting>"}},
			"rule intrazone-default unevaluable: <dropped:log-setting>: default rules", "rule interzone-default unevaluable: <dropped:log-setting>: default rules"},
		{"interzone action missing", DefaultRules{Intrazone: ActionAllow},
			"", "rule interzone-default unevaluable: action: unknown action"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			s.DefaultRules = Collected(tc.d)
			x := mustIndex(t, s)
			if got := x.DefaultRule(true).Reason(); got != tc.intra {
				t.Errorf("intrazone %q, want %q", got, tc.intra)
			}
			if got := x.DefaultRule(false).Reason(); got != tc.inter {
				t.Errorf("interzone %q, want %q", got, tc.inter)
			}
		})
	}
}

// TestUnevaluableNATRuleFailSafe covers item 1 for NAT rules: a NAT rule
// that cannot be evaluated makes every path incomplete, because the
// reverse-NAT lookup cannot exclude that it forwards to the destination.
func TestUnevaluableNATRuleFailSafe(t *testing.T) {
	tests := []struct {
		name   string
		mod    func(s *Snapshot, r *NATRule)
		reason string
	}{
		{"dropped translated address element", func(_ *Snapshot, r *NATRule) {
			r.DestinationTranslation = Collected(&DestinationTranslation{Address: "<dropped:translated-address>"})
		}, "<dropped:translated-address>: translated-address"},
		{"dropped marker on rule", func(_ *Snapshot, r *NATRule) { r.Dropped = []string{"<dropped:dynamic-destination-translation>"} }, "<dropped:dynamic-destination-translation>: NAT rule"},
		{"disabled outside allowlist", func(_ *Snapshot, r *NATRule) { r.OutsideAllowlist = []string{"disabled"} }, "disabled: outside the collected allowlist"},
		{"disabled not collected", func(_ *Snapshot, r *NATRule) { r.Disabled = Field[bool]{} }, "disabled: not collected"},
		{"translation not collected", func(_ *Snapshot, r *NATRule) { r.DestinationTranslation = Field[*DestinationTranslation]{} }, "destination-translation: not collected"},
		{"dynamic translation", func(_ *Snapshot, r *NATRule) {
			r.DestinationTranslation = Collected(&DestinationTranslation{Address: "web-server", Dynamic: true})
		}, "destination-translation: dynamic destination translation not modelled"},
		{"fqdn translated address", func(_ *Snapshot, r *NATRule) {
			r.DestinationTranslation = Collected(&DestinationTranslation{Address: "cloud"})
		}, "translated-address: address cloud: type fqdn not evaluable"},
		{"dropped marker on translated object", func(s *Snapshot, _ *NATRule) { s.Addresses[1].Dropped = []string{"<dropped:value>"} }, "<dropped:value>: address web-server"},
		{"fqdn original destination", func(_ *Snapshot, r *NATRule) { r.Destination = list("cloud") }, "destination: address cloud: type fqdn not evaluable"},
		{"to zone not collected", func(_ *Snapshot, r *NATRule) { r.To = Field[string]{} }, "to: not collected"},
		{"service not collected", func(_ *Snapshot, r *NATRule) { r.Service = Field[string]{} }, "service: not collected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s, &s.NATRules[0])
			x := mustIndex(t, s)
			v := x.NATRules()[0]
			want := "rule fwd-https unevaluable: " + tc.reason
			if v.Evaluable() || v.Reason() != want {
				t.Fatalf("reason %q, want %q", v.Reason(), want)
			}
			// Every path, also one the NAT rule's zones do not name.
			for _, p := range [][2]string{{"wan", "dmz"}, {"lan", "mgmt"}, {"mgmt", "mgmt"}} {
				c := x.PathCompleteness(p[0], p[1])
				if c.Complete || !slices.Contains(c.Reasons, want) {
					t.Errorf("path %v: %+v", p, c)
				}
			}
		})
	}
}

func TestNATRuleWithoutDestinationTranslation(t *testing.T) {
	s := labSnapshot()
	s.NATRules[0].DestinationTranslation = Collected[*DestinationTranslation](nil)
	v := mustIndex(t, s).NATRules()[0]
	if !v.Evaluable() || v.Translation != nil {
		t.Fatalf("got %+v", v)
	}
}

func TestRuleConditions(t *testing.T) {
	tests := []struct {
		name string
		mod  func(r *SecurityRule)
		want []string
	}{
		{"application", func(r *SecurityRule) { r.Application = list("ssh") }, []string{"application"}},
		{"source-user", func(r *SecurityRule) { r.SourceUser = list("corp\\admins") }, []string{"source-user"}},
		{"category", func(r *SecurityRule) { r.Category = list("social-networking") }, []string{"category"}},
		{"schedule", func(r *SecurityRule) { r.Schedule = Collected("office-hours") }, []string{"schedule"}},
		{"schedule not collected", func(r *SecurityRule) { r.Schedule = Field[string]{} }, []string{"schedule not collected"}},
		{"application-default", func(r *SecurityRule) { r.Service = list("application-default") }, []string{"service application-default"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(&s.SecurityRules[1])
			v := mustIndex(t, s).SecurityRules()[1]
			if !v.Evaluable() || !slices.Equal(v.Conditions, tc.want) {
				t.Fatalf("got %+v, want conditions %v", v, tc.want)
			}
		})
	}
}

func TestPathCompleteness(t *testing.T) {
	tests := []struct {
		name     string
		mod      func(*Snapshot)
		src, dst string
		reason   string // "" means complete
	}{
		{"complete", func(*Snapshot) {}, "lan", "mgmt", ""},
		{"stale input", func(s *Snapshot) { s.Inputs[InputSecurityRules] = Input{State: InputStale} }, "lan", "mgmt", "input security_rules stale"},
		{"incomplete input", func(s *Snapshot) { s.Inputs[InputObjects] = Input{State: InputIncomplete} }, "lan", "mgmt", "input objects incomplete"},
		{"missing input", func(s *Snapshot) { delete(s.Inputs, InputIPAM) }, "lan", "mgmt", "input ipam missing"},
		{"multi vsys", func(s *Snapshot) { s.Vsys = 2 }, "lan", "mgmt", "more than one vsys"},
		{"vsys not reported", func(s *Snapshot) { s.Vsys = 0 }, "lan", "mgmt", "vsys count not reported"},
		{"zone not proven", func(*Snapshot) {}, "", "mgmt", "zone not proven"},
		{"unevaluable rule on other path does not touch", func(s *Snapshot) { s.SecurityRules[1].Type = Field[RuleType]{} }, "wan", "dmz", ""},
		{"unevaluable rule with uncollected zones touches", func(s *Snapshot) {
			s.SecurityRules[1].Type = Field[RuleType]{}
			s.SecurityRules[1].From = Field[[]string]{}
		}, "wan", "mgmt", "rule deny-lan-mgmt unevaluable: from: not collected"},
		{"unevaluable rule touches unproven zone", func(s *Snapshot) { s.SecurityRules[1].Type = Field[RuleType]{} }, "lan", "", "rule deny-lan-mgmt unevaluable: rule-type: not collected"},
		{"limit reached rule touches", func(s *Snapshot) { s.SecurityRules[1].Source = list(deepGroups(s, MaxGroupDepth+1)) }, "lan", "mgmt", "rule deny-lan-mgmt: limit reached"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s)
			c := mustIndex(t, s).PathCompleteness(tc.src, tc.dst)
			if tc.reason == "" {
				if !c.Complete || len(c.Reasons) != 0 {
					t.Fatalf("got %+v, want complete", c)
				}
				return
			}
			if c.Complete || !slices.Contains(c.Reasons, tc.reason) {
				t.Fatalf("got %+v, want incomplete with %q", c, tc.reason)
			}
		})
	}
}

// deepGroups adds a chain of n nested groups ending in one object and
// returns the name of the outermost group (depth n).
func deepGroups(s *Snapshot, n int) string {
	member := "web-server"
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("deep%d", i)
		s.AddressGroups = append(s.AddressGroups, Group{Name: name, Static: []string{member}})
		member = name
	}
	return member
}

func TestGroupDepthLimit(t *testing.T) {
	for _, tc := range []struct {
		depth int
		limit bool
	}{{MaxGroupDepth, false}, {MaxGroupDepth + 1, true}} {
		s := labSnapshot()
		s.SecurityRules[1].Source = list(deepGroups(s, tc.depth))
		v := mustIndex(t, s).SecurityRules()[1]
		if v.LimitReached != tc.limit || v.Evaluable() == tc.limit {
			t.Errorf("depth %d: %+v", tc.depth, v)
		}
		if tc.limit && v.Reason() != "rule deny-lan-mgmt: limit reached" {
			t.Errorf("depth %d: reason %q", tc.depth, v.Reason())
		}
		if !tc.limit && (len(v.Source.Ranges) != 1 || v.Source.Ranges[0].From != addr("10.20.0.10")) {
			t.Errorf("depth %d: source %+v", tc.depth, v.Source)
		}
	}
}

func TestExpandedRangesPerFieldLimit(t *testing.T) {
	for _, tc := range []struct {
		n     int
		limit bool
	}{{MaxExpandedRangesPerField, false}, {MaxExpandedRangesPerField + 1, true}} {
		s := labSnapshot()
		var members []string
		for i := range tc.n {
			members = append(members, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
		}
		// Split over groups so no group exceeds MaxGroupMembers.
		var groups []string
		for i := 0; i < len(members); i += MaxGroupMembers {
			name := fmt.Sprintf("big%d", i)
			s.AddressGroups = append(s.AddressGroups, Group{Name: name, Static: members[i:min(i+MaxGroupMembers, len(members))]})
			groups = append(groups, name)
		}
		s.SecurityRules[1].Destination = list(groups...)
		v := mustIndex(t, s).SecurityRules()[1]
		if v.LimitReached != tc.limit {
			t.Errorf("n=%d: limit %v, want %v", tc.n, v.LimitReached, tc.limit)
		}
		if !tc.limit && len(v.Destination.Ranges) != tc.n {
			t.Errorf("n=%d: %d ranges", tc.n, len(v.Destination.Ranges))
		}
	}
}

func TestPortRangesPerFieldLimit(t *testing.T) {
	for _, tc := range []struct {
		n     int
		limit bool
	}{{MaxPortRangesPerField, false}, {MaxPortRangesPerField + 1, true}} {
		s := labSnapshot()
		var names []string
		for i := range tc.n {
			name := fmt.Sprintf("p%d", i)
			s.Services = append(s.Services, ServiceObject{Name: name, Protocol: "tcp", Ports: fmt.Sprint(i + 1), SourcePorts: Collected("")})
			names = append(names, name)
		}
		var groups []string
		for i := 0; i < len(names); i += MaxGroupMembers {
			name := fmt.Sprintf("pg%d", i)
			s.ServiceGroups = append(s.ServiceGroups, Group{Name: name, Static: names[i:min(i+MaxGroupMembers, len(names))]})
			groups = append(groups, name)
		}
		s.SecurityRules[1].Service = list(groups...)
		v := mustIndex(t, s).SecurityRules()[1]
		if v.LimitReached != tc.limit {
			t.Errorf("n=%d: limit %v, want %v", tc.n, v.LimitReached, tc.limit)
		}
		if !tc.limit && len(v.Service.Ports) != tc.n {
			t.Errorf("n=%d: %d ports", tc.n, len(v.Service.Ports))
		}
	}
}

func TestExpansionStepsPerFieldLimit(t *testing.T) {
	// A shared group referenced by many groups: the visits, not the
	// distinct ranges, hit MaxExpansionSteps.
	s := labSnapshot()
	s.AddressGroups = append(s.AddressGroups, Group{Name: "leaf", Static: []string{"web-server"}})
	var mid []string
	for i := range MaxGroupMembers {
		mid = append(mid, "leaf")
		_ = i
	}
	s.AddressGroups = append(s.AddressGroups, Group{Name: "mid", Static: mid})
	var top []string
	for range MaxGroupMembers {
		top = append(top, "mid")
	}
	s.AddressGroups = append(s.AddressGroups, Group{Name: "top", Static: top})
	s.SecurityRules[1].Source = list("top")
	v := mustIndex(t, s).SecurityRules()[1]
	if !v.LimitReached || v.Evaluable() {
		t.Fatalf("got limit %v", v.LimitReached)
	}
}

func TestNewIndexRejectsDuplicates(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Snapshot)
	}{
		{"address and group", func(s *Snapshot) {
			s.AddressGroups = append(s.AddressGroups, Group{Name: "lan-net", Static: []string{"pool"}})
		}},
		{"two addresses", func(s *Snapshot) { s.Addresses = append(s.Addresses, s.Addresses[0]) }},
		{"service and group", func(s *Snapshot) {
			s.ServiceGroups = append(s.ServiceGroups, Group{Name: "svc-dns", Static: []string{"svc-https"}})
		}},
		{"two zones", func(s *Snapshot) { s.Zones = append(s.Zones, Zone{Name: "lan"}) }},
		{"two interfaces", func(s *Snapshot) { s.Interfaces = append(s.Interfaces, s.Interfaces[0]) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := labSnapshot()
			tc.mod(s)
			if _, err := NewIndex(s); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("err = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func TestParsePorts(t *testing.T) {
	good := map[string][][2]uint16{
		"80":           {{80, 80}},
		"80,443":       {{80, 80}, {443, 443}},
		"1-65535":      {{1, 65535}},
		"8000-8080,22": {{8000, 8080}, {22, 22}},
	}
	for in, want := range good {
		got, err := parsePorts(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "65536", "80-79", "+80", "8 0", "80,", "-80", "1-2-3", "080000", strings.Repeat("1,", maxPortItems) + "1"} {
		if got, err := parsePorts(in); err == nil {
			t.Errorf("%q accepted: %v", in, got)
		}
	}
}
