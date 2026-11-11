// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"strings"
	"testing"
)

// Hosts of the lab fixture.
const (
	lanHost  = "10.0.1.5"      // lan, IPAM lan-a
	lanHost2 = "10.0.2.5"      // lan, IPAM lan-b (other segment, same zone)
	dmzHost  = "10.20.0.10"    // dmz, translated address of fwd-https
	dmzHost2 = "10.20.0.11"    // dmz, no NAT
	wanAddr  = "203.0.113.2"   // the firewall's WAN address (wan-ip)
	mgmtHost = "192.168.99.10" // mgmt
)

func addrQuery(src, dst string, port uint16) Query {
	return Query{Source: SourceAddress, SourceAddr: addr(src), Destination: addr(dst), Protocol: "tcp", Port: port}
}

func internetQuery(dst string, port uint16) Query {
	return Query{Source: SourceInternet, Destination: addr(dst), Protocol: "tcp", Port: port}
}

func evalQ(t *testing.T, s *Snapshot, q Query) Result {
	t.Helper()
	return mustIndex(t, s).Evaluate(t.Context(), q)
}

func wantVerdict(t *testing.T, r Result, v Verdict, reason string) {
	t.Helper()
	if r.Verdict != v || !strings.Contains(r.Reason, reason) {
		t.Fatalf("verdict %s %q, want %s containing %q\n%s", r.Verdict, r.Reason, v, reason, r.Text())
	}
}

// chainHas reports whether a step of the given kind and name has the
// outcome (and, if set, a detail containing detail).
func chainHas(r Result, kind StepKind, name, outcome, detail string) bool {
	for _, s := range r.Chain {
		if s.Kind == kind && s.Name == name && s.Outcome == outcome && strings.Contains(s.Detail, detail) {
			return true
		}
	}
	return false
}

func wantStep(t *testing.T, r Result, kind StepKind, name, outcome, detail string) {
	t.Helper()
	if !chainHas(r, kind, name, outcome, detail) {
		t.Fatalf("chain lacks %s %s %q (%q)\n%s", kind, name, outcome, detail, r.Text())
	}
}

func rule(name string, a Action, from, to string, opts ...func(*SecurityRule)) SecurityRule {
	r := evaluableRule(name, a, []string{from}, []string{to}, []string{"any"}, []string{"any"}, []string{"any"})
	for _, o := range opts {
		o(&r)
	}
	return r
}

func withRules(rs ...SecurityRule) *Snapshot {
	s := labSnapshot()
	s.SecurityRules = rs
	return s
}

func TestBaseVerdicts(t *testing.T) {
	cases := []struct {
		name   string
		s      *Snapshot
		q      Query
		want   Verdict
		reason string
	}{
		{"default interzone deny", labSnapshot(), addrQuery(lanHost, dmzHost, 443), VerdictDenied, "denied by rule interzone-default"},
		{"default intrazone allow", labSnapshot(), addrQuery(lanHost, lanHost2, 443), VerdictAllowed, "allowed by rule intrazone-default"},
		{"same segment not filtered", labSnapshot(), addrQuery(lanHost, "10.0.1.6", 22), VerdictNotFiltered, ReasonSameSegment},
		{"deny rule", labSnapshot(), addrQuery(lanHost, mgmtHost, 22), VerdictDenied, "denied by rule deny-lan-mgmt"},
		{"allow rule", withRules(rule("allow-lan-dmz", ActionAllow, "lan", "dmz")), addrQuery(lanHost, dmzHost, 443), VerdictAllowed, "allowed by rule allow-lan-dmz"},
		{"drop is a deny", withRules(rule("drop", ActionDrop, "lan", "dmz")), addrQuery(lanHost, dmzHost, 443), VerdictDenied, "denied by rule drop"},
		{"zone source", withRules(rule("allow-lan-dmz", ActionAllow, "lan", "dmz")), Query{Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "udp", Port: 53}, VerdictAllowed, "allow-lan-dmz"},
		{"subnet source", withRules(rule("allow-lan-dmz", ActionAllow, "lan", "dmz")), Query{Source: SourceSubnet, SourcePrefix: pfx("10.0.1.0/24"), Destination: addr(dmzHost), Protocol: "tcp", Port: 22}, VerdictAllowed, "allow-lan-dmz"},
		{"subnet source same segment", labSnapshot(), Query{Source: SourceSubnet, SourcePrefix: pfx("10.0.1.0/24"), Destination: addr(lanHost), Protocol: "tcp", Port: 22}, VerdictNotFiltered, ReasonSameSegment},
		{"subnet source spanning segments", labSnapshot(), Query{Source: SourceSubnet, SourcePrefix: pfx("10.0.0.0/16"), Destination: addr(dmzHost), Protocol: "tcp", Port: 22}, VerdictUnknown, "not one known segment"},
		{"unknown source zone", labSnapshot(), Query{Source: SourceZone, SourceZone: "nope", Destination: addr(dmzHost), Protocol: "tcp", Port: 22}, VerdictUnknown, "not in snapshot"},
		{"invalid protocol", labSnapshot(), Query{Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "icmp", Port: 1}, VerdictUnknown, "invalid query"},
		{"port zero", labSnapshot(), Query{Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "tcp"}, VerdictUnknown, "invalid query"},
		{"no source kind", labSnapshot(), Query{Destination: addr(dmzHost), Protocol: "tcp", Port: 1}, VerdictUnknown, "invalid query"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := evalQ(t, c.s, c.q)
			wantVerdict(t, r, c.want, c.reason)
			if r.ModelVersion != ModelVersion || r.SnapshotHash == "" {
				t.Fatalf("model %q hash %q", r.ModelVersion, r.SnapshotHash)
			}
			if last := r.Chain[len(r.Chain)-1]; last.Kind != StepVerdict || last.Outcome != string(c.want) {
				t.Fatalf("last step %+v", last)
			}
		})
	}
}

func TestFirstMatchWins(t *testing.T) {
	allowFirst := withRules(rule("a", ActionAllow, "lan", "dmz"), rule("d", ActionDeny, "lan", "dmz"))
	wantVerdict(t, evalQ(t, allowFirst, addrQuery(lanHost, dmzHost, 22)), VerdictAllowed, "rule a")
	denyFirst := withRules(rule("d", ActionDeny, "lan", "dmz"), rule("a", ActionAllow, "lan", "dmz"))
	r := evalQ(t, denyFirst, addrQuery(lanHost, dmzHost, 22))
	wantVerdict(t, r, VerdictDenied, "rule d")
	for _, s := range r.Chain {
		if s.Name == "a" {
			t.Fatalf("rule after the first match examined:\n%s", r.Text())
		}
	}
}

func TestNoMatchReasonsAreListed(t *testing.T) {
	s := withRules(
		rule("wrong-from", ActionAllow, "wan", "dmz"),
		rule("wrong-to", ActionAllow, "lan", "mgmt"),
		rule("wrong-src", ActionAllow, "lan", "dmz", func(r *SecurityRule) { r.Source = list("10.0.2.0/24") }),
		rule("wrong-dst", ActionAllow, "lan", "dmz", func(r *SecurityRule) { r.Destination = list(dmzHost2) }),
		rule("wrong-svc", ActionAllow, "lan", "dmz", func(r *SecurityRule) { r.Service = list("svc-dns") }),
	)
	r := evalQ(t, s, addrQuery(lanHost, dmzHost, 443))
	wantVerdict(t, r, VerdictDenied, "interzone-default")
	for name, why := range map[string]string{
		"wrong-from": "from zone", "wrong-to": "to zone", "wrong-src": "source address",
		"wrong-dst": "destination address", "wrong-svc": "service",
	} {
		wantStep(t, r, StepRule, name, OutcomeNoMatch, "because "+why)
	}
}

func TestDisabledRuleSkippedAndListed(t *testing.T) {
	d := rule("off", ActionDeny, "lan", "dmz", func(r *SecurityRule) { r.Disabled = Collected(true) })
	r := evalQ(t, withRules(d, rule("a", ActionAllow, "lan", "dmz")), addrQuery(lanHost, dmzHost, 22))
	wantVerdict(t, r, VerdictAllowed, "rule a")
	wantStep(t, r, StepRule, "off", OutcomeSkippedDisabled, "")
}

func TestNegation(t *testing.T) {
	negDst := rule("allow-not-web", ActionAllow, "lan", "dmz", func(r *SecurityRule) {
		r.Destination = list("web-server")
		r.NegateDestination = Collected(true)
	})
	s := withRules(negDst)
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, dmzHost, 22)), VerdictDenied, "interzone-default")
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, dmzHost2, 22)), VerdictAllowed, "allow-not-web")

	negSrc := rule("allow-not-lan", ActionAllow, "lan", "dmz", func(r *SecurityRule) {
		r.Source = list("lan-net")
		r.NegateSource = Collected(true)
	})
	s = withRules(negSrc)
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, dmzHost, 22)), VerdictDenied, "interzone-default")
	// A zone source holds addresses outside lan-net as well: partial.
	zq := Query{Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "tcp", Port: 22}
	wantVerdict(t, evalQ(t, s, zq), VerdictConditional, "allow-not-lan")

	// Negated "any" matches nothing.
	negAny := rule("neg-any", ActionDeny, "lan", "dmz", func(r *SecurityRule) { r.NegateDestination = Collected(true) })
	wantVerdict(t, evalQ(t, withRules(negAny, rule("a", ActionAllow, "lan", "dmz")), addrQuery(lanHost, dmzHost, 22)), VerdictAllowed, "rule a")
}

func TestZoneSourceWithSourceRestrictedRule(t *testing.T) {
	zq := Query{Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "tcp", Port: 22}
	allow := rule("allow-a", ActionAllow, "lan", "dmz", func(r *SecurityRule) { r.Source = list("10.0.1.0/24") })
	r := evalQ(t, withRules(allow), zq)
	wantVerdict(t, r, VerdictConditional, "allow-a")
	wantStep(t, r, StepRule, "allow-a", OutcomeConditional, "source address")
	// A source-restricted deny decides only for part of the zone; the
	// rest falls through to the allow.
	deny := rule("deny-a", ActionDeny, "lan", "dmz", func(r *SecurityRule) { r.Source = list("10.0.1.0/24") })
	wantVerdict(t, evalQ(t, withRules(deny, rule("a", ActionAllow, "lan", "dmz")), zq), VerdictConditional, "deny-a, a")
	wantVerdict(t, evalQ(t, withRules(deny), zq), VerdictDenied, "interzone-default")
}

// conditionKinds are the conditions of ADR 0012 D2 step 4.
var conditionKinds = []struct {
	name string
	set  func(*SecurityRule)
	text string
}{
	{"App-ID", func(r *SecurityRule) { r.Application = list("ssh") }, "application"},
	{"user", func(r *SecurityRule) { r.SourceUser = list("lab\\admins") }, "source-user"},
	{"URL category", func(r *SecurityRule) { r.Category = list("social-networking") }, "category"},
	{"schedule", func(r *SecurityRule) { r.Schedule = Collected("night") }, "schedule"},
	{"schedule not collected", func(r *SecurityRule) { r.Schedule = Field[string]{} }, "schedule not collected"},
	{"application-default", func(r *SecurityRule) { r.Service = list("application-default") }, "service application-default"},
}

func TestConditionalRules(t *testing.T) {
	inter := addrQuery(lanHost, dmzHost, 22)  // falls through to interzone deny
	intra := addrQuery(lanHost, lanHost2, 22) // falls through to intrazone allow
	for _, k := range conditionKinds {
		t.Run(k.name, func(t *testing.T) {
			cAllow := func(from, to string) SecurityRule { return rule("c-allow", ActionAllow, from, to, k.set) }
			cDeny := func(from, to string) SecurityRule { return rule("c-deny", ActionDeny, from, to, k.set) }
			cases := []struct {
				name   string
				s      *Snapshot
				q      Query
				want   Verdict
				reason string
			}{
				{"conditional allow then default deny", withRules(cAllow("lan", "dmz")), inter, VerdictConditional, "c-allow"},
				{"conditional allow then deny rule", withRules(cAllow("lan", "dmz"), rule("d", ActionDeny, "lan", "dmz")), inter, VerdictConditional, "c-allow"},
				{"conditional deny then allow rule", withRules(cDeny("lan", "dmz"), rule("a", ActionAllow, "lan", "dmz")), inter, VerdictConditional, "c-deny, a"},
				{"conditional deny then conditional allow", withRules(cDeny("lan", "dmz"), rule("c2", ActionAllow, "lan", "dmz", k.set)), inter, VerdictConditional, "c-deny, c2"},
				{"conditional deny then default intrazone allow", withRules(cDeny("lan", "lan")), intra, VerdictConditional, "intrazone-default"},
				{"conditional deny then deny rule", withRules(cDeny("lan", "dmz"), rule("d", ActionDeny, "lan", "dmz")), inter, VerdictDenied, "denied by rule d"},
				{"conditional deny then default interzone deny", withRules(cDeny("lan", "dmz")), inter, VerdictDenied, "interzone-default"},
				{"conditional deny then unevaluable rule", withRules(cDeny("lan", "dmz"), rule("bad", ActionAllow, "lan", "dmz", func(r *SecurityRule) { r.Destination = list("cloud") })), inter, VerdictUnknown, "rule bad unevaluable"},
				// ADR 0012 D2 step 4: a recorded conditional allow is an
				// allow among the matches, so the verdict is conditional
				// whatever follows; never denied.
				{"conditional allow then unevaluable rule", withRules(cAllow("lan", "dmz"), rule("bad", ActionDeny, "lan", "dmz", func(r *SecurityRule) { r.Destination = list("cloud") })), inter, VerdictConditional, "(rules c-allow); otherwise rule bad unevaluable: "},
				{"conditional allow then default rules not collected", func() *Snapshot {
					s := withRules(cAllow("lan", "dmz"))
					s.DefaultRules = Field[DefaultRules]{}
					return s
				}(), inter, VerdictConditional, "(rules c-allow); otherwise rule interzone-default unevaluable: "},
				{"conditional deny then default rules not collected", func() *Snapshot {
					s := withRules(cDeny("lan", "dmz"))
					s.DefaultRules = Field[DefaultRules]{}
					return s
				}(), inter, VerdictUnknown, "rule interzone-default unevaluable"},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					r := evalQ(t, c.s, c.q)
					wantVerdict(t, r, c.want, c.reason)
					name := "c-deny"
					if strings.HasPrefix(c.name, "conditional allow") {
						name = "c-allow"
					}
					wantStep(t, r, StepRule, name, OutcomeConditional, k.text)
				})
			}
		})
	}
}

// failSafeRules are the unevaluable deny rules of ADR 0012 D2, Required
// tests (NS-05) item 1, each with the field or marker its reason names.
// NS-07, NS-08, NS-10 and NS-16 reuse them.
var failSafeRules = []struct {
	name  string
	snap  func(s *Snapshot)
	set   func(r *SecurityRule)
	cause string
}{
	{"rule-type intrazone", nil, func(r *SecurityRule) { r.Type = Collected(RuleTypeIntrazone) }, "rule-type"},
	{"rule-type not collected", nil, func(r *SecurityRule) { r.Type = Field[RuleType]{} }, "rule-type: not collected"},
	{"source-hip", nil, func(r *SecurityRule) { r.SourceHIP = list("hip-ok") }, "source-hip"},
	{"destination-hip", nil, func(r *SecurityRule) { r.DestinationHIP = list("hip-ok") }, "destination-hip"},
	{"dropped marker on rule", nil, func(r *SecurityRule) { r.Dropped = []string{"<dropped:source-imsi>"} }, "<dropped:source-imsi>"},
	{"dropped marker on object", func(s *Snapshot) {
		s.Addresses = append(s.Addresses, AddressObject{Name: "redacted", Type: AddressNetmask, Value: "10.20.0.0/24", Dropped: []string{"<dropped:value>"}})
	}, func(r *SecurityRule) { r.Destination = list("redacted") }, "<dropped:value>"},
	{"dropped marker on group", func(s *Snapshot) {
		s.AddressGroups = append(s.AddressGroups, Group{Name: "g-redacted", Static: []string{"web-server"}, Dropped: []string{"<dropped:member>"}})
	}, func(r *SecurityRule) { r.Destination = list("g-redacted") }, "<dropped:member>"},
	{"field outside allowlist", nil, func(r *SecurityRule) { r.OutsideAllowlist = []string{"source-imei"} }, "source-imei"},
	{"negate-source not collected", nil, func(r *SecurityRule) { r.NegateSource = Field[bool]{} }, "negate-source: not collected"},
	{"negate-destination not collected", nil, func(r *SecurityRule) { r.NegateDestination = Field[bool]{} }, "negate-destination: not collected"},
	{"FQDN object", nil, func(r *SecurityRule) { r.Destination = list("cloud") }, "fqdn not evaluable"},
	{"EDL object", func(s *Snapshot) {
		s.Addresses = append(s.Addresses, AddressObject{Name: "feed", Type: AddressEDL, Value: "feed"})
	}, func(r *SecurityRule) { r.Source = list("feed") }, "edl not evaluable"},
	{"region object", func(s *Snapshot) {
		s.Addresses = append(s.Addresses, AddressObject{Name: "geo", Type: AddressRegion, Value: "DE"})
	}, func(r *SecurityRule) { r.Source = list("geo") }, "region not evaluable"},
	{"dynamic group", nil, func(r *SecurityRule) { r.Destination = list("dyn") }, "dynamic members unknown"},
}

func TestUnevaluableRuleGivesUnknown(t *testing.T) {
	for _, c := range failSafeRules {
		t.Run(c.name, func(t *testing.T) {
			s := withRules(rule("deny-x", ActionDeny, "lan", "dmz", c.set), rule("allow-x", ActionAllow, "lan", "dmz"))
			if c.snap != nil {
				c.snap(s)
			}
			r := evalQ(t, s, addrQuery(lanHost, dmzHost, 22))
			wantVerdict(t, r, VerdictUnknown, "rule deny-x unevaluable: ")
			if !strings.Contains(r.Reason, c.cause) {
				t.Fatalf("reason %q lacks %q", r.Reason, c.cause)
			}
			wantStep(t, r, StepRule, "deny-x", OutcomeUnevaluable, c.cause)
			// The same rule as an allow is never allowed either.
			s.SecurityRules[0].Action = ActionAllow
			wantVerdict(t, evalQ(t, s, addrQuery(lanHost, dmzHost, 22)), VerdictUnknown, "rule deny-x unevaluable")
		})
	}
}

func TestSnapshotWithoutQ11FieldsIsUnknown(t *testing.T) {
	s := withRules(rule("deny", ActionDeny, "lan", "dmz"), rule("allow", ActionAllow, "lan", "lan"))
	for i := range s.SecurityRules {
		r := &s.SecurityRules[i]
		r.NegateSource, r.NegateDestination, r.Type = Field[bool]{}, Field[bool]{}, Field[RuleType]{}
		r.SourceHIP, r.DestinationHIP = Field[[]string]{}, Field[[]string]{}
	}
	s.DefaultRules = Field[DefaultRules]{}
	for _, q := range []Query{addrQuery(lanHost, dmzHost, 22), addrQuery(lanHost, lanHost2, 22), addrQuery(lanHost, mgmtHost, 22)} {
		r := evalQ(t, s, q)
		if r.Verdict != VerdictUnknown {
			t.Fatalf("%v: %s", q.Destination, r.Text())
		}
	}
	// Same segment stays not_filtered: rules are irrelevant there.
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, "10.0.1.6", 22)), VerdictNotFiltered, ReasonSameSegment)
}

func TestDefaultRulesNotCollectedIsUnknown(t *testing.T) {
	s := labSnapshot()
	s.DefaultRules = Field[DefaultRules]{}
	for _, q := range []Query{addrQuery(lanHost, dmzHost, 22), addrQuery(lanHost, lanHost2, 22)} {
		r := evalQ(t, s, q)
		wantVerdict(t, r, VerdictUnknown, "unevaluable: rulebase/default-security-rules: not collected")
	}
	// A rule that decides before the default step is not affected.
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, mgmtHost, 22)), VerdictDenied, "deny-lan-mgmt")
	// A marker on the collected default rules makes them unevaluable.
	s = labSnapshot()
	s.DefaultRules.Value.Dropped = []string{"<dropped:log-setting>"}
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, dmzHost, 22)), VerdictUnknown, "rule interzone-default unevaluable: <dropped:log-setting>")
}

func TestUnevaluableRuleForOtherZonesIsPassed(t *testing.T) {
	other := rule("deny-mgmt", ActionDeny, "mgmt", "mgmt", func(r *SecurityRule) { r.Type = Collected(RuleTypeIntrazone) })
	r := evalQ(t, withRules(other, rule("a", ActionAllow, "lan", "dmz")), addrQuery(lanHost, dmzHost, 22))
	wantVerdict(t, r, VerdictAllowed, "rule a")
	wantStep(t, r, StepRule, "deny-mgmt", OutcomeNoMatch, "from zone; rule is unevaluable")
	// A rule-level marker or a field outside the allowlist could change
	// what the rule matches: it is never passed.
	for _, set := range []func(*SecurityRule){
		func(r *SecurityRule) { r.Dropped = []string{"<dropped:from>"} },
		func(r *SecurityRule) { r.OutsideAllowlist = []string{"source-zone-x"} },
	} {
		o := rule("deny-mgmt", ActionDeny, "mgmt", "mgmt", set)
		wantVerdict(t, evalQ(t, withRules(o, rule("a", ActionAllow, "lan", "dmz")), addrQuery(lanHost, dmzHost, 22)), VerdictUnknown, "rule deny-mgmt unevaluable")
	}
}

func TestLimitReachedRuleIsUnknown(t *testing.T) {
	s := withRules(rule("deep", ActionDeny, "lan", "dmz"))
	s.SecurityRules[0].Destination = list(deepGroups(s, MaxGroupDepth+1))
	wantVerdict(t, evalQ(t, s, addrQuery(lanHost, dmzHost, 22)), VerdictUnknown, "rule deep: limit reached")
}

func TestPlacementFailSafe(t *testing.T) {
	s := withRules(rule("deny-all", ActionDeny, "any", "any"))
	cases := []struct {
		name   string
		q      Query
		want   Verdict
		reason string
	}{
		{"private source outside subnets", addrQuery("10.99.0.1", dmzHost, 22), VerdictUnknown, ReasonPrivateOutsideSubnets},
		{"private destination outside subnets", addrQuery(lanHost, "10.99.0.1", 22), VerdictUnknown, ReasonPrivateOutsideSubnets},
		{"CGNAT destination by specific route", addrQuery(lanHost, "100.64.1.1", 22), VerdictDenied, "deny-all"},
		{"public destination follows default route", addrQuery(lanHost, "8.8.8.8", 53), VerdictDenied, "deny-all"},
		{"source subnet not on firewall interface", addrQuery("172.30.0.5", dmzHost, 22), VerdictUnknown, ReasonSubnetNoInterface},
		{"destination subnet not on firewall interface", addrQuery(lanHost, "172.30.0.5", 22), VerdictUnknown, ReasonSubnetNoInterface},
		{"both sides unowned, different hosts", addrQuery("172.30.0.5", "172.30.0.6", 22), VerdictNotFiltered, ReasonSameSegment},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantVerdict(t, evalQ(t, s, c.q), c.want, c.reason)
		})
	}
	// Both sides unowned and in different unowned segments.
	s.Subnets = append(s.Subnets, Subnet{ID: "lab-behind-host-2", Prefix: pfx("172.31.0.0/24")})
	wantVerdict(t, evalQ(t, s, addrQuery("172.30.0.5", "172.31.0.5", 22)), VerdictUnknown, ReasonSubnetNoInterface)
}

func TestInputStateFailSafe(t *testing.T) {
	for _, c := range []struct {
		name   string
		mod    func(*Snapshot)
		reason string
	}{
		{"stale rules", func(s *Snapshot) { s.Inputs[InputSecurityRules] = Input{State: InputStale} }, "input security_rules stale"},
		{"incomplete NAT", func(s *Snapshot) { s.Inputs[InputNATRules] = Input{State: InputIncomplete} }, "input nat_rules incomplete"},
		{"missing objects", func(s *Snapshot) { delete(s.Inputs, InputObjects) }, "input objects missing"},
		{"multi-vsys", func(s *Snapshot) { s.Vsys = 2 }, "more than one vsys"},
		{"vsys not reported", func(s *Snapshot) { s.Vsys = 0 }, "vsys count not reported"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := labSnapshot()
			c.mod(s)
			wantVerdict(t, evalQ(t, s, addrQuery(lanHost, mgmtHost, 22)), VerdictUnknown, c.reason)
		})
	}
}
