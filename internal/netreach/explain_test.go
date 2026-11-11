// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func netbirdQuery(dst string, f NetBirdFacts) Query {
	return Query{Source: SourceNetBird, NetBird: f, Destination: addr(dst), Protocol: "tcp", Port: 22}
}

func peers(ps ...RoutingPeer) Field[[]RoutingPeer] { return Collected(ps) }

func TestNetBirdSource(t *testing.T) {
	// A deny rule for every NetBird entry zone: a firewall verdict would
	// be denied everywhere.
	s := withRules(
		rule("deny-vpn", ActionDeny, "vpn", "any"),
		rule("deny-lan-dmz", ActionDeny, "lan", "dmz"),
	)
	cases := []struct {
		name   string
		f      NetBirdFacts
		dst    string
		want   Verdict
		reason string
	}{
		{"destination is a peer", NetBirdFacts{Peer: Collected(true)}, dmzHost, VerdictNotFiltered, ReasonOverlayBypass},
		{"host data not collected", NetBirdFacts{}, dmzHost, VerdictUnknown, ReasonNetBirdNotProven},
		{"routing peers unknown", NetBirdFacts{Peer: Collected(false)}, dmzHost, VerdictUnknown, ReasonNetBirdNotProven + ": routing peers unknown"},
		{"no routing peer", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers()}, dmzHost, VerdictUnknown, ReasonNetBirdNotProven},
		{"routing peer in the destination segment", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-dmz", addr("10.20.0.5")})}, dmzHost, VerdictNotFiltered, ReasonOverlayBypass},
		{"routing peer not placed", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-x", addr("10.99.0.1")})}, dmzHost, VerdictUnknown, ReasonNetBirdNotProven + ": routing peer rp-x: " + ReasonPrivateOutsideSubnets},
		{"routing peer on unowned subnet", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-h", addr("172.30.0.9")})}, dmzHost, VerdictUnknown, ReasonSubnetNoInterface},
		{"proven firewall path gets the rule verdict", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-lan", addr(lanHost)})}, dmzHost, VerdictDenied, "deny-lan-dmz"},
		{"firewall as peer through its tunnel", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"fw", addr("100.64.0.5")})}, dmzHost, VerdictDenied, "deny-vpn"},
		{"one bypass beats a denied path", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-lan", addr(lanHost)}, RoutingPeer{"rp-dmz", addr("10.20.0.5")})}, dmzHost, VerdictNotFiltered, ReasonOverlayBypass},
		{"one unproven path beats a denied path", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-lan", addr(lanHost)}, RoutingPeer{"rp-x", addr("10.99.0.1")})}, dmzHost, VerdictUnknown, ReasonNetBirdNotProven},
		{"destination not placed", NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-lan", addr(lanHost)})}, "10.99.0.1", VerdictUnknown, ReasonNetBirdNotProven},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantVerdict(t, evalQ(t, s, netbirdQuery(c.dst, c.f)), c.want, c.reason)
		})
	}
	// A proven path with an allow rule is allowed.
	s = withRules(rule("allow-lan-dmz", ActionAllow, "lan", "dmz"))
	f := NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(RoutingPeer{"rp-lan", addr(lanHost)})}
	wantVerdict(t, evalQ(t, s, netbirdQuery(dmzHost, f)), VerdictAllowed, "allow-lan-dmz")
}

func TestExplanationText(t *testing.T) {
	s := labSnapshot()
	s.SecurityRules = append([]SecurityRule{rule("off", ActionDeny, "wan", "dmz", func(r *SecurityRule) { r.Disabled = Collected(true) })}, s.SecurityRules...)
	r := evalQ(t, s, internetQuery(dmzHost, 8443))
	txt := r.Text()
	for _, want := range []string{
		"allowed: allowed by rule allow-web\n",
		"model nr-v1, snapshot sha256:",
		"input datasets: placed (zones ds-zones fresh",
		"placement destination 10.20.0.10: placed (segment 10.20.0.0/24 (IPAM dmz), zone dmz through interface ethernet1/2.20)",
		"[direct] rule off: skipped (disabled)",
		"[direct] default-rule interzone-default: match (deny)",
		"reverse-nat fwd-https: tried (pre-NAT destination wan-ip zone wan port tcp/443)",
		"[reverse NAT rule fwd-https] rule allow-web: match (allow)",
		"verdict: allowed (allowed by rule allow-web)",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q\n%s", want, txt)
		}
	}
}

func TestStepTextIsSanitized(t *testing.T) {
	var c chain
	c.max = 4
	rlo := string(rune(0x202e)) // right-to-left override
	c.add(Step{Kind: StepRule, Name: "a" + rlo + "b\x00", Outcome: "x", Detail: string([]byte{0xff})})
	got := c.steps[0]
	if strings.ContainsAny(got.Name, rlo+"\x00") || got.Detail != string(utf8.RuneError) {
		t.Fatalf("not sanitized: %+v", got)
	}
}

func TestDeterminism(t *testing.T) {
	queries := []Query{
		internetQuery(dmzHost, 8443), internetQuery(wanAddr, 443), addrQuery(lanHost, mgmtHost, 22),
		addrQuery(lanHost, lanHost2, 22), {Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "udp", Port: 53},
	}
	a, b := mustIndex(t, labSnapshot()), mustIndex(t, labSnapshot())
	for _, q := range queries {
		r1, r2, r3 := a.Evaluate(q), a.Evaluate(q), b.Evaluate(q)
		if !reflect.DeepEqual(r1, r2) || !reflect.DeepEqual(r1, r3) {
			t.Fatalf("not deterministic for %+v", q)
		}
	}
}

func TestSnapshotHash(t *testing.T) {
	base := SnapshotHash(labSnapshot())
	if base != SnapshotHash(labSnapshot()) || !strings.HasPrefix(base, "sha256:") {
		t.Fatalf("hash %q", base)
	}
	for name, mod := range map[string]func(*Snapshot){
		"redacted digest": func(s *Snapshot) {
			in := s.Inputs[InputSecurityRules]
			in.RedactedDigest = "r2"
			s.Inputs[InputSecurityRules] = in
		},
		"dataset id": func(s *Snapshot) {
			in := s.Inputs[InputIPAM]
			in.DatasetID = "ds-2"
			s.Inputs[InputIPAM] = in
		},
		"state": func(s *Snapshot) {
			in := s.Inputs[InputRoutes]
			in.State = InputStale
			s.Inputs[InputRoutes] = in
		},
	} {
		s := labSnapshot()
		mod(s)
		if SnapshotHash(s) == base {
			t.Errorf("%s change keeps the hash", name)
		}
	}
	// Only the required inputs enter the hash, in a fixed order.
	s := labSnapshot()
	s.Inputs["extra"] = Input{State: InputFresh, DatasetID: "x"}
	if SnapshotHash(s) != base {
		t.Error("an input outside RequiredInputs changes the hash")
	}
	if SnapshotHash(nil) == "" {
		t.Error("nil snapshot has no hash")
	}
}

// forwards returns n NAT rules that all forward a WAN address to dmzHost.
func forwards(n int) []NATRule {
	out := make([]NATRule, n)
	for i := range out {
		out[i] = evaluableNAT(fmt.Sprintf("fwd-%d", i))
	}
	return out
}

func TestPathsPerQueryLimit(t *testing.T) {
	// The direct path plus one path per forward.
	s := labSnapshot()
	s.NATRules = forwards(MaxPathsPerQuery - 1)
	wantVerdict(t, evalQ(t, s, internetQuery(dmzHost, 8443)), VerdictAllowed, "allow-web")
	s.NATRules = forwards(MaxPathsPerQuery)
	r := evalQ(t, s, internetQuery(dmzHost, 8443))
	wantVerdict(t, r, VerdictUnknown, "limit reached")
	if r.Reason != ErrLimitReached.Error() {
		t.Fatalf("reason %q", r.Reason)
	}
	// NetBird routing peers are paths as well.
	ps := make([]RoutingPeer, MaxPathsPerQuery+1)
	for i := range ps {
		ps[i] = RoutingPeer{Name: fmt.Sprint(i), Addr: netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)})}
	}
	f := NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(ps...)}
	wantVerdict(t, evalQ(t, labSnapshot(), netbirdQuery(dmzHost, f)), VerdictUnknown, "limit reached")
}

func TestChainStepsLimit(t *testing.T) {
	x := mustIndex(t, labSnapshot())
	q := internetQuery(dmzHost, 8443)
	full := x.evaluate(q, evalLimits{paths: MaxPathsPerQuery, steps: MaxChainSteps})
	n := len(full.Chain) - 1 // the verdict step is always appended
	at := x.evaluate(q, evalLimits{paths: MaxPathsPerQuery, steps: n})
	if at.Verdict != VerdictAllowed || !reflect.DeepEqual(at, full) {
		t.Fatalf("at limit: %s", at.Text())
	}
	over := x.evaluate(q, evalLimits{paths: MaxPathsPerQuery, steps: n - 1})
	wantVerdict(t, over, VerdictUnknown, "limit reached")
	if len(over.Chain) != n {
		t.Fatalf("chain has %d steps, want %d", len(over.Chain), n)
	}
}

func TestFullChainStopsEvaluation(t *testing.T) {
	s := labSnapshot()
	s.NATRules = forwards(MaxPathsPerQuery - 1)
	x := mustIndex(t, s)
	q := internetQuery(dmzHost, 8443)
	e := &evaluator{x: x, q: q, lim: evalLimits{paths: MaxPathsPerQuery, steps: 1}, chain: chain{max: 1}}
	if out := e.run(); out.verdict == VerdictDenied {
		t.Fatalf("full chain gave %s %q", out.verdict, out.reason)
	}
	if !e.chain.full || e.paths != 0 {
		t.Fatalf("full chain: full %v, %d paths evaluated, want none", e.chain.full, e.paths)
	}
	r := x.evaluate(q, evalLimits{paths: MaxPathsPerQuery, steps: 1})
	wantVerdict(t, r, VerdictUnknown, "limit reached")
	// Inside a path: a full chain ends the rule loop with limit reached.
	e = &evaluator{x: x, q: q, chain: chain{max: 0, full: true}}
	if out := e.securityPath(packet{srcZone: "wan", dstZone: "dmz"}); out.verdict != VerdictUnknown || out.reason != ErrLimitReached.Error() {
		t.Fatalf("securityPath on full chain: %s %q", out.verdict, out.reason)
	}
}

func TestMostReachable(t *testing.T) {
	o := func(v Verdict) outcome { return outcome{verdict: v, reason: string(v)} }
	cases := []struct {
		in   []Verdict
		want Verdict
	}{
		{nil, VerdictUnknown},
		{[]Verdict{VerdictDenied, VerdictDenied}, VerdictDenied},
		{[]Verdict{VerdictDenied, VerdictUnknown}, VerdictUnknown},
		{[]Verdict{VerdictUnknown, VerdictNotFiltered}, VerdictNotFiltered},
		{[]Verdict{VerdictNotFiltered, VerdictConditional}, VerdictConditional},
		{[]Verdict{VerdictConditional, VerdictAllowed, VerdictDenied}, VerdictAllowed},
	}
	for _, c := range cases {
		var outs []outcome
		for _, v := range c.in {
			outs = append(outs, o(v))
		}
		if got := mostReachable(outs).verdict; got != c.want {
			t.Errorf("%v: %s, want %s", c.in, got, c.want)
		}
	}
}

func TestMatchAddr(t *testing.T) {
	r := func(a, b string) AddrRange { return AddrRange{From: addr(a), To: addr(b)} }
	set := AddrSet{Ranges: []AddrRange{r("10.0.0.0", "10.0.0.255"), r("10.0.1.0", "10.0.1.255"), r("::1", "::1")}}
	cases := []struct {
		name string
		neg  bool
		x    []AddrRange
		want match
	}{
		{"inside adjacent ranges", false, []AddrRange{r("10.0.0.200", "10.0.1.10")}, matchFull},
		{"partly outside", false, []AddrRange{r("10.0.1.200", "10.0.2.10")}, matchPartial},
		{"outside", false, []AddrRange{r("10.0.2.0", "10.0.2.10")}, matchNone},
		{"other family", false, []AddrRange{r("::2", "::2")}, matchNone},
		{"universe", false, universe, matchPartial},
		{"negated inside", true, []AddrRange{r("10.0.0.1", "10.0.0.1")}, matchNone},
		{"negated outside", true, []AddrRange{r("10.0.2.1", "10.0.2.1")}, matchFull},
		{"negated universe", true, universe, matchPartial},
	}
	for _, c := range cases {
		if got := matchAddr(set, c.neg, c.x); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if matchAddr(AddrSet{Any: true}, true, universe) != matchNone || matchAddr(AddrSet{Any: true}, false, universe) != matchFull {
		t.Error("any")
	}
}

func TestMatchService(t *testing.T) {
	s := ServiceSet{Ports: []PortRange{{"tcp", 80, 80}, {"tcp", 81, 90}, {"udp", 53, 53}}}
	cases := []struct {
		proto string
		x     []portSpan
		want  match
	}{
		{"tcp", []portSpan{{85, 85}}, matchFull},
		{"tcp", []portSpan{{80, 90}}, matchFull},
		{"tcp", []portSpan{{85, 95}}, matchPartial},
		{"tcp", []portSpan{{53, 53}}, matchNone},
		{"udp", []portSpan{{53, 53}}, matchFull},
	}
	for _, c := range cases {
		if got := matchService(s, c.proto, c.x); got != c.want {
			t.Errorf("%s %v: %d, want %d", c.proto, c.x, got, c.want)
		}
	}
}

// FuzzEvaluate checks that no query and no fail-safe mutation of the lab
// snapshot panics, that the result is deterministic and that the fail-safe
// invariants hold: an unevaluable NAT rule never lets a query be denied,
// and a snapshot with every rule and the default rules unevaluable gives
// only unknown or not_filtered.
func FuzzEvaluate(f *testing.F) {
	f.Add([]byte{203, 0, 113, 9}, []byte{10, 20, 0, 10}, uint16(8443), uint8(0), uint8(0))
	f.Add([]byte{10, 0, 1, 5}, []byte{10, 0, 2, 5}, uint16(22), uint8(1), uint8(1))
	f.Add([]byte{10, 0, 1, 5}, []byte{192, 168, 99, 1}, uint16(22), uint8(2), uint8(2))
	f.Add([]byte{0, 0, 0, 0}, []byte{203, 0, 113, 2}, uint16(443), uint8(3), uint8(4))
	f.Add([]byte{1}, []byte{0x20, 1, 0xd, 0xb8, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint16(1), uint8(4), uint8(7))
	f.Fuzz(func(t *testing.T, src, dst []byte, port uint16, kind, mut uint8) {
		s := labSnapshot()
		natBad := mut&1 != 0
		allBad := mut&2 != 0
		if natBad {
			s.NATRules[0].Dropped = []string{"<dropped:x>"}
		}
		if allBad {
			for i := range s.SecurityRules {
				s.SecurityRules[i].NegateSource = Field[bool]{}
			}
			s.DefaultRules = Field[DefaultRules]{}
		}
		if mut&4 != 0 {
			s.SecurityRules[0].Application = list("ssh")
		}
		if mut&8 != 0 {
			s.NATRules[0].DestinationTranslation.Value.Port = 0
		}
		sa, _ := netip.AddrFromSlice(src)
		da, _ := netip.AddrFromSlice(dst)
		q := Query{Destination: da, Protocol: []string{"tcp", "udp", "icmp"}[int(kind>>4)%3], Port: port}
		switch kind % 5 {
		case 0:
			q.Source, q.SourceAddr = SourceAddress, sa
		case 1:
			q.Source = SourceInternet
		case 2:
			q.Source, q.SourceZone = SourceZone, []string{"lan", "wan", "dmz", "nope"}[int(port)%4]
		case 3:
			q.Source = SourceNetBird
			q.NetBird = NetBirdFacts{Peer: Collected(mut&16 != 0), RoutingPeers: peers(RoutingPeer{"rp", sa})}
		case 4:
			q.Source = SourceSubnet
			if sa.IsValid() {
				q.SourcePrefix, _ = sa.Prefix(int(port) % (sa.BitLen() + 1))
			}
		}
		x, err := NewIndex(s)
		if err != nil {
			t.Fatal(err)
		}
		r := x.Evaluate(q)
		if !reflect.DeepEqual(r, x.Evaluate(q)) {
			t.Fatal("not deterministic")
		}
		switch r.Verdict {
		case VerdictAllowed, VerdictConditional, VerdictDenied, VerdictNotFiltered, VerdictUnknown:
		default:
			t.Fatalf("verdict %q", r.Verdict)
		}
		if r.Reason == "" || len(r.Chain) == 0 || r.Chain[len(r.Chain)-1].Kind != StepVerdict {
			t.Fatalf("no reason or verdict step:\n%s", r.Text())
		}
		if natBad && r.Verdict == VerdictDenied {
			t.Fatalf("denied with an unevaluable NAT rule:\n%s", r.Text())
		}
		if allBad && r.Verdict != VerdictUnknown && r.Verdict != VerdictNotFiltered {
			t.Fatalf("%s with every rule unevaluable:\n%s", r.Verdict, r.Text())
		}
	})
}
