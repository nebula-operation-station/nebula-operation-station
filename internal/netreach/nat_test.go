// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"strings"
	"testing"
)

func TestPortForwardFromInternetIsAllowed(t *testing.T) {
	r := evalQ(t, labSnapshot(), internetQuery(dmzHost, 8443))
	wantVerdict(t, r, VerdictAllowed, "allowed by rule allow-web")
	wantStep(t, r, StepPlacement, "internet", OutcomePlaced, "zone wan")
	wantStep(t, r, StepReverseNAT, "fwd-https", OutcomeTried, "pre-NAT destination wan-ip zone wan port tcp/443")
	wantStep(t, r, StepRule, "allow-web", OutcomeMatch, "allow")
	// The direct path to the internal address alone is denied.
	wantStep(t, r, StepDefaultRule, DefaultInterzoneName, OutcomeMatch, "deny")
}

func TestInternalAddressWithoutPortForwardIsDenied(t *testing.T) {
	s := labSnapshot()
	s.NATRules = nil
	wantVerdict(t, evalQ(t, s, internetQuery(dmzHost, 8443)), VerdictDenied, "interzone-default")
	// A port the NAT rule does not translate to stays denied.
	r := evalQ(t, labSnapshot(), internetQuery(dmzHost, 443))
	wantVerdict(t, r, VerdictDenied, "interzone-default")
	wantStep(t, r, StepReverseNAT, "fwd-https", OutcomeNoMatch, "translated port")
	// A source zone the NAT rule does not take stays denied.
	r = evalQ(t, labSnapshot(), addrQuery(lanHost, dmzHost, 8443))
	wantVerdict(t, r, VerdictDenied, "interzone-default")
	wantStep(t, r, StepReverseNAT, "fwd-https", OutcomeNoMatch, "from zone")
}

func TestForwardNATOnPreNATPacket(t *testing.T) {
	r := evalQ(t, labSnapshot(), internetQuery(wanAddr, 443))
	wantVerdict(t, r, VerdictAllowed, "allowed by rule allow-web")
	wantStep(t, r, StepNAT, "fwd-https", OutcomeMatch, "destination translated to web-server")
	for _, s := range r.Chain {
		if s.Kind == StepRule && s.Name == "allow-web" && s.Path != "via NAT rule fwd-https" {
			t.Fatalf("allow-web on path %q", s.Path)
		}
	}
	// Security rules match the pre-NAT port: 8443 on the WAN address is
	// not forwarded and the allow rule's service does not hold 443's
	// translation.
	wantVerdict(t, evalQ(t, labSnapshot(), internetQuery(wanAddr, 8443)), VerdictAllowed, "intrazone-default")
}

func TestNATWithoutPortTranslation(t *testing.T) {
	s := labSnapshot()
	s.NATRules[0].DestinationTranslation.Value.Port = 0
	r := evalQ(t, s, internetQuery(dmzHost, 443))
	wantVerdict(t, r, VerdictAllowed, "allow-web")
	wantStep(t, r, StepReverseNAT, "fwd-https", OutcomeTried, "port tcp/443")
}

func TestReverseNATListsEveryPreNATDestination(t *testing.T) {
	s := labSnapshot()
	alt := evaluableNAT("fwd-alt")
	alt.Destination = list("203.0.113.3")
	alt.Service = Collected("svc-high")
	s.NATRules = append(s.NATRules, alt)
	r := evalQ(t, s, internetQuery(dmzHost, 8443))
	wantVerdict(t, r, VerdictAllowed, "allow-web")
	wantStep(t, r, StepReverseNAT, "fwd-https", OutcomeTried, "pre-NAT destination wan-ip")
	wantStep(t, r, StepReverseNAT, "fwd-alt", OutcomeTried, "pre-NAT destination 203.0.113.3 zone wan port tcp/8000-8080,9000")
	// Only the alternative forward: its pre-NAT destination is not in
	// allow-web, so it is denied.
	s.NATRules = s.NATRules[1:]
	wantVerdict(t, evalQ(t, s, internetQuery(dmzHost, 8443)), VerdictDenied, "interzone-default")
}

func TestDisabledNATRule(t *testing.T) {
	s := labSnapshot()
	s.NATRules[0].Disabled = Collected(true)
	r := evalQ(t, s, internetQuery(wanAddr, 443))
	wantStep(t, r, StepNAT, "fwd-https", OutcomeSkippedDisabled, "")
	wantVerdict(t, evalQ(t, s, internetQuery(dmzHost, 8443)), VerdictDenied, "interzone-default")
}

func TestNATFirstMatchWithoutDestinationTranslation(t *testing.T) {
	s := labSnapshot()
	snat := evaluableNAT("snat-only")
	snat.DestinationTranslation = Collected[*DestinationTranslation](nil)
	s.NATRules = append([]NATRule{snat}, s.NATRules...)
	r := evalQ(t, s, internetQuery(wanAddr, 443))
	wantStep(t, r, StepNAT, "snat-only", OutcomeMatch, "no destination translation")
	wantVerdict(t, r, VerdictAllowed, "intrazone-default")
	for _, st := range r.Chain {
		if st.Kind == StepNAT && st.Name == "fwd-https" {
			t.Fatalf("NAT rule after the first match examined:\n%s", r.Text())
		}
	}
}

func TestNATMatchingPartOfTheSources(t *testing.T) {
	s := labSnapshot()
	s.NATRules[0].Source = list("198.51.100.0/24")
	r := evalQ(t, s, internetQuery(wanAddr, 443))
	wantVerdict(t, r, VerdictConditional, "")
	wantStep(t, r, StepNAT, "fwd-https", OutcomeConditional, "web-server")
	// An address source outside the NAT source is not translated.
	s.Routes = append(s.Routes, Route{Prefix: pfx("192.0.2.0/24"), Interface: "ethernet1/1"})
	wantVerdict(t, evalQ(t, s, Query{Source: SourceAddress, SourceAddr: addr("8.8.4.4"), Destination: addr(dmzHost), Protocol: "tcp", Port: 8443}), VerdictDenied, "interzone-default")
}

func TestTranslatedAddressWithoutZoneIsUnknown(t *testing.T) {
	s := labSnapshot()
	s.Addresses[1].Value = "172.30.0.5" // web-server in a subnet no firewall interface owns
	wantVerdict(t, evalQ(t, s, internetQuery(wanAddr, 443)), VerdictUnknown, ReasonSubnetNoInterface)
}

// failSafeNATRules are the unevaluable NAT rules of ADR 0012 D2,
// Required tests (NS-05) item 1. NS-07, NS-08, NS-10 and NS-16 reuse them.
var failSafeNATRules = []struct {
	name  string
	snap  func(s *Snapshot)
	set   func(r *NATRule)
	cause string
}{
	{"dropped translated-address sub-element", nil, func(r *NATRule) {
		r.Dropped = []string{"<dropped:destination-translation/translated-address>"}
	}, "<dropped:destination-translation/translated-address>"},
	{"disabled outside allowlist", nil, func(r *NATRule) {
		r.Disabled = Field[bool]{}
		r.OutsideAllowlist = []string{"disabled"}
	}, "disabled"},
	{"translated address object with marker", func(s *Snapshot) {
		s.Addresses[1].Dropped = []string{"<dropped:value>"}
	}, nil, "<dropped:value>"},
	{"FQDN translated address", nil, func(r *NATRule) {
		r.DestinationTranslation.Value.Address = "cloud"
	}, "fqdn not evaluable"},
	{"dynamic destination translation", nil, func(r *NATRule) {
		r.DestinationTranslation.Value.Dynamic = true
	}, "dynamic destination translation"},
	{"FQDN original destination", nil, func(r *NATRule) { r.Destination = list("cloud") }, "fqdn not evaluable"},
}

func TestUnevaluableNATRuleGivesUnknown(t *testing.T) {
	for _, c := range failSafeNATRules {
		t.Run(c.name, func(t *testing.T) {
			s := labSnapshot()
			if c.snap != nil {
				c.snap(s)
			}
			if c.set != nil {
				c.set(&s.NATRules[0])
			}
			// The internal address is otherwise denied (any port): the
			// reverse-NAT lookup cannot exclude a forward to it.
			for _, q := range []Query{internetQuery(dmzHost, 22), internetQuery(dmzHost, 8443), addrQuery(lanHost, dmzHost, 22)} {
				r := evalQ(t, s, q)
				wantVerdict(t, r, VerdictUnknown, "rule fwd-https unevaluable: ")
				if !strings.Contains(r.Reason, c.cause) {
					t.Fatalf("reason %q lacks %q", r.Reason, c.cause)
				}
				wantStep(t, r, StepNAT, "fwd-https", OutcomeUnevaluable, c.cause)
			}
			// The NAT step on the WAN address reaches the rule in order.
			wantVerdict(t, evalQ(t, s, internetQuery(wanAddr, 443)), VerdictUnknown, "rule fwd-https unevaluable")
		})
	}
}

func TestUnevaluableNATRuleNeverHidesAForward(t *testing.T) {
	// A second, unevaluable NAT rule for another service: the query to
	// the internal address on any port must not fall back to denied.
	s := labSnapshot()
	s.NATRules[0].Dropped = []string{"<dropped:destination-translation/translated-address>"}
	s.NATRules[0].From = list("dmz") // its zones do not even match
	r := evalQ(t, s, internetQuery(dmzHost, 22))
	wantVerdict(t, r, VerdictUnknown, "rule fwd-https unevaluable")
	wantStep(t, r, StepReverseNAT, "fwd-https", OutcomeUnevaluable, "cannot exclude a port forward to "+dmzHost)

	// A source NAT rule first ends the forward NAT step before the
	// unevaluable rule: only the reverse-NAT lookup sees it, and it
	// alone keeps the query from being denied.
	snat := evaluableNAT("snat-all")
	snat.From, snat.To, snat.Destination, snat.Service = list("any"), Collected("any"), list("any"), Collected("any")
	snat.DestinationTranslation = Collected[*DestinationTranslation](nil)
	s.NATRules = append([]NATRule{snat}, s.NATRules...)
	r = evalQ(t, s, internetQuery(dmzHost, 22))
	wantStep(t, r, StepNAT, "snat-all", OutcomeMatch, "no destination translation")
	wantStep(t, r, StepDefaultRule, DefaultInterzoneName, OutcomeMatch, "deny")
	wantVerdict(t, r, VerdictUnknown, "rule fwd-https unevaluable: <dropped:destination-translation/translated-address>: NAT rule (reverse-NAT lookup)")
}
