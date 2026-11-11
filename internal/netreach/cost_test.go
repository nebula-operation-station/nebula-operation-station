// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
)

// TestSearchCostBoundsComparisons: the comparisons the address and port
// matchers make, counted by cmpCounter (binary search probes included),
// never exceed searchCost, for field sizes 0–300 and packet sets of 1–6
// ranges that are covered, overlapped, missed or past the end.
func TestSearchCostBoundsComparisons(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for nm := 0; nm <= 300; nm += 1 + nm/8 {
		// nm disjoint ranges of width 4 with gaps of 4: [8k, 8k+3].
		var m []AddrRange
		var ports []portSpan
		for k := range nm {
			m = append(m, AddrRange{From: v4(8 * k), To: v4(8*k + 3)})
			ports = append(ports, portSpan{1 + 8*k, 1 + 8*k + 3})
		}
		addrs := mergedAddrs{m: m}
		svc := mergedService{ports: map[string][]portSpan{"tcp": ports}}
		for nx := 1; nx <= 6; nx++ {
			for range 50 {
				var x []AddrRange
				var xp []portSpan
				for range nx {
					// Mostly inside a range (full cover makes every range
					// reach the comparisons), sometimes in a gap or past
					// the end.
					k := rng.IntN(nm + 2)
					from := 8*k + rng.IntN(4)
					to := from + rng.IntN(4-from%8%4+1)
					if rng.IntN(4) == 0 {
						to = from + rng.IntN(20)
					}
					x = append(x, AddrRange{From: v4(from), To: v4(to)})
					xp = append(xp, portSpan{1 + from, 1 + to})
				}
				for _, neg := range []bool{false, true} {
					c := &cmpCounter{}
					addrs.match(neg, x, c)
					if c.n > addrs.cost(x) || addrs.cost(x) != searchCost(nx, nm) {
						t.Fatalf("address field of %d, %d packet ranges: %d comparisons, cost %d", nm, nx, c.n, addrs.cost(x))
					}
				}
				c := &cmpCounter{}
				svc.match("tcp", xp, c)
				if c.n > svc.cost("tcp", xp) {
					t.Fatalf("service of %d spans, %d packet spans: %d comparisons, cost %d", nm, nx, c.n, svc.cost("tcp", xp))
				}
			}
		}
	}
	// The full-cover case of a single range is within two comparisons of
	// the bound, so the bound is close, not loose by a factor.
	m := make([]AddrRange, 255)
	for k := range m {
		m[k] = AddrRange{From: v4(8 * k), To: v4(8*k + 3)}
	}
	c := &cmpCounter{}
	mergedAddrs{m: m}.match(false, []AddrRange{{From: v4(8 * 254), To: v4(8 * 254)}}, c)
	if bound := searchCost(1, len(m)); c.n < bound-2 {
		t.Fatalf("full cover of 1 range against 255: %d comparisons, bound %d", c.n, bound)
	}
}

func v4(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
}

// manyZones is a zone list of n lab zones, none of them in except.
// Members repeat; the list is still evaluable.
func manyZones(n int, except ...string) []string {
	var pool []string
	for _, z := range []string{"wan", "lan", "dmz", "mgmt", "vpn"} {
		if !slices.Contains(except, z) {
			pool = append(pool, z)
		}
	}
	var l []string
	for i := range n {
		l = append(l, pool[i%len(pool)])
	}
	return l
}

// absentZones is a zone list of n zones that are not in the lab: a rule
// with it is unevaluable.
func absentZones(n int) []string {
	var l []string
	for i := range n {
		l = append(l, fmt.Sprintf("nowhere-%d", i))
	}
	return l
}

// TestStepChargesBoundComparisons: in whole evaluations, the comparisons
// counted after each step (zone list members, address and port
// comparisons) never exceed the cost charged for that step by ruleCost,
// natCost and reverseNATCost, so MaxWorkPerQuery is a true upper bound of
// the matching work. Zone lists that do not match make zoneIn and
// zoneMayMatch run every pass to the end.
func TestStepChargesBoundComparisons(t *testing.T) {
	// The queries come from wan, lan and the zone/subnet sources in lan.
	longFrom := func(r *SecurityRule) { r.From = list(manyZones(40, "wan", "lan")...) }
	longTo := func(r *SecurityRule) { r.To = list(append(manyZones(40, "dmz"), "dmz")...) }
	absentFrom := func(r *SecurityRule) { r.From = list(absentZones(40)...) }
	intrazone := func(r *SecurityRule) { r.Type = Collected(RuleTypeIntrazone) }

	natFrom := labSnapshot()
	natFrom.NATRules = forwards(30)
	for i := range natFrom.NATRules {
		natFrom.NATRules[i].From = list(append(manyZones(30, "wan"), "wan")...)
	}
	natFromMiss := labSnapshot()
	natFromMiss.NATRules = forwards(30)
	for i := range natFromMiss.NATRules {
		natFromMiss.NATRules[i].From = list(manyZones(30, "wan", "lan")...)
	}
	lab := labSnapshot()
	lab.NATRules = append(lab.NATRules, forwards(20)...)
	zones := withRules(
		rule("unevaluable-from", ActionDeny, "lan", "dmz", intrazone, longFrom),
		rule("unevaluable-to", ActionDeny, "lan", "dmz", intrazone, longTo),
		rule("unevaluable-absent", ActionDeny, "lan", "dmz", intrazone, absentFrom),
		rule("evaluable-from", ActionDeny, "lan", "dmz", longFrom),
		rule("evaluable-to", ActionAllow, "lan", "dmz", longTo),
		rule("allow", ActionAllow, "any", "any"),
	)
	for _, s := range []*Snapshot{natFrom, natFromMiss, zones} {
		x := mustIndex(t, s)
		for i := range x.nat {
			if !x.nat[i].Evaluable() {
				t.Fatalf("NAT rule %s unevaluable: %s", x.nat[i].Name, x.nat[i].Reason())
			}
		}
		for i := range x.rules {
			if want := s.SecurityRules[i].Type.Value != RuleTypeIntrazone; x.rules[i].Evaluable() != want {
				t.Fatalf("rule %s evaluable %v: %s", x.rules[i].Name, !want, x.rules[i].Reason())
			}
		}
	}
	queries := []Query{
		internetQuery(dmzHost, 8443), internetQuery(wanAddr, 443), internetQuery(dmzHost2, 22),
		addrQuery(lanHost, dmzHost, 22), addrQuery(lanHost, mgmtHost, 22), addrQuery(lanHost, lanHost2, 22),
		{Source: SourceZone, SourceZone: "lan", Destination: addr(dmzHost), Protocol: "tcp", Port: 443},
		{Source: SourceSubnet, SourcePrefix: pfx("10.0.1.0/24"), Destination: addr(dmzHost), Protocol: "udp", Port: 53},
	}
	cases := []struct {
		name string
		s    *Snapshot
		lim  func(*evalLimits)
	}{
		{"lab", lab, nil},
		{"zone lists", zones, nil},
		{"NAT from zone lists", natFrom, nil},
		{"NAT from zone lists miss", natFromMiss, nil},
		{"hostile within the work budget", hostileSnapshot(), func(l *evalLimits) { l.work = 1 << 22 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := mustIndex(t, c.s)
			total, work := 0, 0
			for _, q := range queries {
				lim := defaultEvalLimits()
				if c.lim != nil {
					c.lim(&lim)
				}
				e := x.newEvaluator(t.Context(), q, lim)
				e.cmp = &cmpCounter{}
				r := e.result()
				if e.cmp.over != 0 {
					t.Fatalf("%v: %d steps made more comparisons than charged (worst by %d)\n%s", q, e.cmp.over, e.cmp.worst, r.Text())
				}
				if e.cmp.total > e.work {
					t.Fatalf("%v: %d comparisons, %d units charged", q, e.cmp.total, e.work)
				}
				total += e.cmp.total
				work += e.work
			}
			if total == 0 {
				t.Fatal("no comparison counted: the counter is not wired")
			}
			t.Logf("%d comparisons, %d units charged", total, work)
		})
	}
}
