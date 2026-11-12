// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"net/netip"
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

var labFirewallAddrs = []netip.Addr{
	netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("10.0.0.1"),
	netip.MustParseAddr("10.20.0.1"), netip.MustParseAddr("192.168.99.1"),
	netip.MustParseAddr("10.50.0.1"),
}

func flow(src, dst, proto string, port uint16) Flow {
	return Flow{Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), Protocol: FlowProtocol(proto), Port: port, Action: FlowAllow, Sessions: 3, Origin: "traffic-map"}
}

func dnsInput(t *testing.T, snap *nr.Snapshot, flows ...Flow) *Input {
	t.Helper()
	in := newInput(t, snap, nr.Field[map[string]ProfileSetting]{})
	err := in.SetObservations(Observations{
		Flows:         Flows{State: nr.InputFresh, Flows: flows},
		FirewallAddrs: FirewallAddrs{State: nr.InputFresh, Addrs: labFirewallAddrs},
	})
	if err != nil {
		t.Fatalf("SetObservations: %v", err)
	}
	return in
}

func flowFindings(r Report) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		if f.RuleIndex == -1 && f.Flow != nil {
			out[f.Flow.Destination+" "+f.Flow.Protocol] = f
		}
	}
	return out
}

func TestDNSBypassFlows(t *testing.T) {
	denied := flow("10.0.1.5", "9.9.9.9", "udp", 53)
	denied.Action = FlowDeny
	tests := []struct {
		name  string
		flows []Flow
		want  map[string]State
	}{
		{name: "public resolver fires", flows: []Flow{flow("10.0.1.5", "8.8.8.8", "udp", 53)},
			want: map[string]State{"8.8.8.8 udp": StateFinding}},
		{name: "internal resolver other than the firewall fires", flows: []Flow{flow("10.0.1.5", "10.20.0.53", "udp", 53)},
			want: map[string]State{"10.20.0.53 udp": StateFinding}},
		{name: "dns over tls fires", flows: []Flow{flow("10.0.1.5", "1.1.1.1", "tcp", 853)},
			want: map[string]State{"1.1.1.1 tcp": StateFinding}},
		{name: "dns over tcp fires", flows: []Flow{flow("10.50.0.7", "1.1.1.1", "tcp", 53)},
			want: map[string]State{"1.1.1.1 tcp": StateFinding}},
		{name: "firewall is the designated resolver", flows: []Flow{flow("10.0.1.5", "10.0.0.1", "udp", 53), flow("10.0.1.5", "::ffff:10.0.0.1", "tcp", 53)},
			want: map[string]State{}},
		{name: "not a dns port", flows: []Flow{flow("10.0.1.5", "8.8.8.8", "tcp", 443), flow("10.0.1.5", "8.8.8.8", "udp", 853)},
			want: map[string]State{}},
		{name: "denied flow is no bypass", flows: []Flow{denied}, want: map[string]State{}},
		{name: "external source is not internal", flows: []Flow{flow("8.8.4.4", "8.8.8.8", "udp", 53)}, want: map[string]State{}},
		{name: "loopback destination", flows: []Flow{flow("127.0.0.1", "127.0.0.53", "udp", 53)}, want: map[string]State{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := DNSCheck{}.Run(dnsInput(t, labSnapshot(), tc.flows...))
			if rep.State != StateOK {
				t.Fatalf("report %s: %s", rep.State, rep.Reason)
			}
			got := flowFindings(rep)
			if len(got) != len(tc.want) {
				t.Fatalf("flow results %v, want %v", got, tc.want)
			}
			for k, st := range tc.want {
				if got[k].State != st {
					t.Errorf("%s: %s %q, want %s", k, got[k].State, got[k].Reason, st)
				}
			}
		})
	}
}

func TestDNSBypassAggregates(t *testing.T) {
	var flows []Flow
	for i := range MaxListedEndpoints + 2 {
		flows = append(flows, flow(netip.AddrFrom4([4]byte{10, 0, 2, byte(i + 1)}).String(), "8.8.8.8", "udp", 53))
	}
	flows = append(flows, flow("10.0.2.1", "8.8.8.8", "udp", 53))
	f := flowFindings(DNSCheck{}.Run(dnsInput(t, labSnapshot(), flows...)))["8.8.8.8 udp"]
	if f.State != StateFinding || f.Flow.EndpointsTotal != MaxListedEndpoints+2 || len(f.Flow.Endpoints) != MaxListedEndpoints {
		t.Fatalf("aggregate %+v", f.Flow)
	}
	if f.Flow.Endpoints[0] != "10.0.2.1" || f.Flow.Sessions != uint64(3*len(flows)) {
		t.Errorf("endpoints %v sessions %d", f.Flow.Endpoints, f.Flow.Sessions)
	}
}

// TestDNSBypassUnplacedSourceCannotDecide: without a default route a
// public source cannot be placed; its DNS flow is "cannot decide", never
// silently dropped, and the rule part cannot decide either.
func TestDNSBypassUnplacedSourceCannotDecide(t *testing.T) {
	snap := labSnapshot(rule("r", allow, s("lan"), s("any"), s("any"), s("any"), s("any")))
	snap.Routes = nil
	rep := DNSCheck{}.Run(dnsInput(t, snap, flow("8.8.4.4", "9.9.9.9", "udp", 53)))
	if f := flowFindings(rep)["9.9.9.9 udp"]; f.State != StateCannotDecide {
		t.Errorf("flow: %s %q", f.State, f.Reason)
	}
	if f := byRule(t, rep, CheckDNSBypass, 0); f.State != StateCannotDecide {
		t.Errorf("rule: %s %q", f.State, f.Reason)
	}
}

func TestDNSBypassRules(t *testing.T) {
	withApp := func(r nr.SecurityRule, apps ...string) nr.SecurityRule {
		r.Application = list(apps...)
		return r
	}
	disabled := rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any"))
	disabled.Disabled = nr.Collected(true)
	noType := rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any"))
	noType.Type = nr.Field[nr.RuleType]{}
	dropped := rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any"))
	dropped.Dropped = s("<dropped:profile>")
	negated := rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any"))
	negated.NegateDestination = nr.Collected(true)
	negatedHost := rule("r", allow, s("lan"), s("wan"), s("any"), s("9.9.9.9"), s("any"))
	negatedHost.NegateDestination = nr.Collected(true)
	sched := rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any"))
	sched.Schedule = nr.Collected("weekdays")
	tests := []struct {
		name   string
		r      nr.SecurityRule
		state  State
		reason string
	}{
		{"lan to wan any dns service", rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("svc-dns")), StateFinding, "permits DNS"},
		{"service any", rule("r", allow, s("guest"), s("wan"), s("any"), s("any"), s("any")), StateFinding, "guest"},
		{"zones any", rule("r", allow, s("any"), s("any"), s("any"), s("any"), s("any")), StateFinding, "wan"},
		{"app dns with service any", withApp(rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any")), "dns"), StateFinding, "permits DNS"},
		{"application-default with app any", rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("application-default")), StateFinding, "conditional"},
		{"scheduled rule still fires", sched, StateFinding, "conditional: schedule"},
		{"other app only", withApp(rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any")), "ssl"), StateOK, "does not permit DNS"},
		{"web service only", rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("svc-web")), StateOK, "does not permit DNS"},
		{"destination restricted", rule("r", allow, s("lan"), s("wan"), s("any"), s("9.9.9.9"), s("svc-dns")), StateOK, "destination restricted"},
		{"small destination range restricted", rule("r", allow, s("lan"), s("wan"), s("any"), s("9.9.9.0/24"), s("svc-dns")), StateOK, "destination restricted"},
		{"destination 0.0.0.0/0 is not restricted", rule("r", allow, s("lan"), s("wan"), s("any"), s("0.0.0.0/0"), s("svc-dns")), StateFinding, "too broad"},
		{"large public destination is not restricted", rule("r", allow, s("lan"), s("wan"), s("any"), s("8.0.0.0/8"), s("svc-dns")), StateFinding, "too broad"},
		{"broad range next to a host is not restricted", rule("r", allow, s("lan"), s("wan"), s("any"), s("9.9.9.9", "1.0.0.0/16"), s("svc-dns")), StateFinding, "too broad"},
		{"negated destination is not restricted", negatedHost, StateFinding, "negated"},
		{"application group cannot decide", withApp(rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any")), "office-apps"), StateCannotDecide, "office-apps"},
		{"application filter next to known app cannot decide", withApp(rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("svc-dns")), "ssl", "filter-risky"), StateCannotDecide, "filter-risky"},
		{"application group with application-default cannot decide", withApp(rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("application-default")), "office-apps"), StateCannotDecide, "office-apps"},
		{"application group on a non-dns service", withApp(rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("svc-web")), "office-apps"), StateOK, "does not permit DNS"},
		{"negated destination any", negated, StateOK, "destination restricted"},
		{"internal only", rule("r", allow, s("lan"), s("dmz"), s("any"), s("any"), s("any")), StateOK, "not from an internal"},
		{"inbound from wan", rule("r", allow, s("wan"), s("wan"), s("any"), s("any"), s("any")), StateOK, "not from an internal"},
		{"deny rule", rule("r", deny, s("lan"), s("wan"), s("any"), s("any"), s("any")), StateOK, "not an allow"},
		{"disabled", disabled, StateOK, "disabled"},
		{"rule-type not collected", noType, StateDataNotCollected, "rule-type"},
		{"dropped marker", dropped, StateCannotDecide, "<dropped:profile>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := DNSCheck{}.Run(dnsInput(t, labSnapshot(tc.r)))
			f := byRule(t, rep, CheckDNSBypass, 0)
			if f.State != tc.state || !strings.Contains(f.Reason, tc.reason) {
				t.Errorf("got %s %q, want %s containing %q", f.State, f.Reason, tc.state, tc.reason)
			}
		})
	}
}

// TestDNSBypassFailSafe: stale or missing inputs never resolve (no ok)
// and never raise a new finding.
func TestDNSBypassFailSafe(t *testing.T) {
	bypass := rule("r", allow, s("lan"), s("wan"), s("any"), s("any"), s("any"))
	tests := []struct {
		name  string
		obs   Observations
		stale nr.InputKind
		want  State
	}{
		{name: "flows missing", want: StateDataNotCollected,
			obs: Observations{FirewallAddrs: FirewallAddrs{State: nr.InputFresh, Addrs: labFirewallAddrs}}},
		{name: "flows incomplete", want: StateCannotDecide,
			obs: Observations{Flows: Flows{State: nr.InputIncomplete}, FirewallAddrs: FirewallAddrs{State: nr.InputFresh, Addrs: labFirewallAddrs}}},
		{name: "firewall addresses missing", want: StateDataNotCollected,
			obs: Observations{Flows: Flows{State: nr.InputFresh}}},
		{name: "firewall addresses stale", want: StateCannotDecide,
			obs: Observations{Flows: Flows{State: nr.InputFresh}, FirewallAddrs: FirewallAddrs{State: nr.InputStale}}},
		{name: "routes stale", stale: nr.InputRoutes, want: StateCannotDecide,
			obs: Observations{Flows: Flows{State: nr.InputFresh}, FirewallAddrs: FirewallAddrs{State: nr.InputFresh}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := labSnapshot(bypass)
			if tc.stale != "" {
				snap.Inputs[tc.stale] = nr.Input{State: nr.InputStale}
			}
			tc.obs.Flows.Flows = []Flow{flow("10.0.1.5", "8.8.8.8", "udp", 53)}
			in := newInput(t, snap, nr.Field[map[string]ProfileSetting]{})
			if err := in.SetObservations(tc.obs); err != nil {
				t.Fatal(err)
			}
			rep := DNSCheck{}.Run(in)
			if rep.State != tc.want {
				t.Errorf("report %s, want %s", rep.State, tc.want)
			}
			for _, f := range rep.Findings {
				if f.State != tc.want {
					t.Errorf("%+v, want %s", f, tc.want)
				}
			}
		})
	}
}

func TestDNSDestinationRangeSize(t *testing.T) {
	a := netip.MustParseAddr
	tests := []struct {
		name     string
		from, to string
		small    bool
	}{
		{"single host", "9.9.9.9", "9.9.9.9", true},
		{"ipv4 /24", "9.9.9.0", "9.9.9.255", true},
		{"ipv4 257 addresses", "9.9.9.0", "9.9.10.0", false},
		{"ipv4 all", "0.0.0.0", "255.255.255.255", false},
		{"ipv6 /120", "2001:db8::", "2001:db8::ff", true},
		{"ipv6 /64", "2001:db8::", "2001:db8::ffff:ffff:ffff:ffff", false},
		{"ipv6 all", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"mixed families", "9.9.9.9", "2001:db8::1", false},
		{"reversed", "9.9.9.10", "9.9.9.9", false},
		{"mapped equals ipv4", "::ffff:9.9.9.0", "9.9.9.255", true},
	}
	for _, tc := range tests {
		if got := rangeAtMost(nr.AddrRange{From: a(tc.from), To: a(tc.to)}, MaxRestrictedDNSDestination); got != tc.small {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.small)
		}
	}
	if smallRanges(nil) || rangeAtMost(nr.AddrRange{}, MaxRestrictedDNSDestination) {
		t.Error("empty or invalid range counts as restricted")
	}
}

func TestSetObservationsRejectsFlows(t *testing.T) {
	in := newInput(t, labSnapshot(), nr.Field[map[string]ProfileSetting]{})
	bad := flow("10.0.0.5", "8.8.8.8", "udp", 53)
	bad.Origin = "x\xff"
	tests := map[string]Observations{
		"invalid flow address":   {Flows: Flows{Flows: []Flow{{Protocol: FlowUDP}}}},
		"invalid origin":         {Flows: Flows{Flows: []Flow{bad}}},
		"empty protocol":         {Flows: Flows{Flows: []Flow{flow("10.0.0.5", "8.8.8.8", "", 53)}}},
		"too many flows":         {Flows: Flows{Flows: make([]Flow, MaxFlows+1)}},
		"invalid firewall addr":  {FirewallAddrs: FirewallAddrs{Addrs: []netip.Addr{{}}}},
		"too many firewall addr": {FirewallAddrs: FirewallAddrs{Addrs: make([]netip.Addr, MaxFirewallAddrs+1)}},
	}
	// Flow actions are a closed enum: only FlowAllow and FlowDeny.
	for _, a := range []FlowAction{"", "drop", "reset-both", "reset-client", "reset-server", "Allow", "DENY", "allow "} {
		f := flow("10.0.0.5", "8.8.8.8", "udp", 53)
		f.Action = a
		tests["action "+string(a)] = Observations{Flows: Flows{State: nr.InputFresh, Flows: []Flow{f}}}
	}
	// Flow protocols are a closed enum too: no other spelling, no number.
	for _, p := range []string{"TCP", "UDP", "Udp", "ICMP", "6", "17", "1", "tcp ", " udp", "gre", "esp", "sctp", "any"} {
		tests["protocol "+p] = Observations{Flows: Flows{State: nr.InputFresh, Flows: []Flow{flow("10.0.0.5", "8.8.8.8", p, 53)}}}
	}
	for name, o := range tests {
		if err := in.SetObservations(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, p := range []FlowProtocol{FlowTCP, FlowUDP, FlowICMP, FlowOtherProtocol} {
		f := flow("10.0.0.5", "8.8.8.8", string(p), 0)
		if err := in.SetObservations(Observations{Flows: Flows{State: nr.InputFresh, Flows: []Flow{f}}}); err != nil {
			t.Errorf("protocol %s refused: %v", p, err)
		}
	}
}

// TestDNSBypassFlowWithoutPortCannotDecide: a tcp or udp flow without a
// port (0) from an internal endpoint may be DNS; it gives cannot decide,
// never a silent drop under StateOK. icmp and other protocols carry no
// DNS; a portless flow to the firewall is not a bypass.
func TestDNSBypassFlowWithoutPortCannotDecide(t *testing.T) {
	rep := DNSCheck{}.Run(dnsInput(t, labSnapshot(),
		flow("10.0.1.5", "8.8.8.8", "udp", 0), flow("10.0.1.5", "1.1.1.1", "tcp", 0),
		flow("10.0.1.5", "9.9.9.9", "icmp", 0), flow("10.0.1.5", "9.9.9.9", "other", 0),
		flow("10.0.1.5", "10.0.0.1", "udp", 0)))
	if rep.State != StateOK {
		t.Fatalf("report %s: %s", rep.State, rep.Reason)
	}
	got := flowFindings(rep)
	if len(got) != 2 {
		t.Fatalf("flow results %v, want two", got)
	}
	for _, k := range []string{"8.8.8.8 udp", "1.1.1.1 tcp"} {
		if f := got[k]; f.State != StateCannotDecide || !strings.Contains(f.Reason, "no port") || f.Flow.EndpointsTotal != 1 {
			t.Errorf("%s: %s %q %+v", k, f.State, f.Reason, f.Flow)
		}
	}
}
