// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"fmt"
	"net/netip"
	"testing"
)

// countingPlace wraps Placer.Place and counts the calls per address.
type countingPlace struct {
	p     *Placer
	calls map[netip.Addr]int
	total int
}

func (c *countingPlace) place(a netip.Addr) Placement {
	c.calls[a]++
	c.total++
	return c.p.Place(a)
}

// countingIndex builds the Index of s with a counting placement function
// for the post-NAT zones.
func countingIndex(t *testing.T, s *Snapshot, maxPlacements int) (*Index, *countingPlace) {
	t.Helper()
	p, err := NewPlacer(s)
	if err != nil {
		t.Fatal(err)
	}
	c := &countingPlace{p: p, calls: map[netip.Addr]int{}}
	x, err := buildIndex(s, defaultWorkLimits(), c.place, maxPlacements)
	if err != nil {
		t.Fatal(err)
	}
	return x, c
}

// TestPostNATZonePlacedOncePerIndex: the post-NAT zone of every NAT rule
// is computed when the Index is built. Place runs at most once per
// distinct translated range, however many rules share it and however
// many queries and paths evaluate the rules afterwards.
func TestPostNATZonePlacedOncePerIndex(t *testing.T) {
	s := labSnapshot()
	// MaxPathsPerQuery-1 forwards to the same translated address plus one
	// to a translated range: every query runs every rule on many paths.
	s.NATRules = forwards(MaxPathsPerQuery - 2)
	pooled := evaluableNAT("fwd-pool")
	pooled.DestinationTranslation.Value.Address = "pool"
	s.NATRules = append(s.NATRules, pooled)
	x, c := countingIndex(t, s, MaxNATPlacementsPerSnapshot)
	built := c.total
	if built != 2 || c.calls[addr(dmzHost)] != 1 || c.calls[addr("10.0.1.10")] != 1 {
		t.Fatalf("index build placed %v (%d calls), want each translated range once", c.calls, built)
	}
	queries := []Query{
		internetQuery(wanAddr, 443),
		internetQuery(dmzHost, 8443),
		addrQuery(lanHost, wanAddr, 443),
		netbirdQuery(wanAddr, NetBirdFacts{Peer: Collected(false), RoutingPeers: peers(
			RoutingPeer{Name: "a", Addr: addr("198.51.100.7")}, RoutingPeer{Name: "b", Addr: addr("203.0.113.5")})}),
	}
	for range 20 {
		for _, q := range queries {
			x.Evaluate(q)
		}
	}
	if c.total != built {
		t.Fatalf("queries placed translated addresses %d more times", c.total-built)
	}
	// The cached zone still decides: the forward to the DMZ is allowed.
	wantVerdict(t, x.Evaluate(internetQuery(wanAddr, 443)), VerdictAllowed, "allow-web")
}

// TestPostNATZonePlacementBudget: a hostile snapshot with more distinct
// translated ranges than MaxNATPlacementsPerSnapshot costs at most that
// many placements; the rules past the budget give unknown "limit
// reached", never a zone.
func TestPostNATZonePlacementBudget(t *testing.T) {
	const max = 3
	for _, extra := range []int{0, 1} {
		s := labSnapshot()
		s.NATRules = nil
		for i := range max + extra {
			r := evaluableNAT(fmt.Sprintf("fwd-%d", i))
			r.DestinationTranslation.Value.Address = fmt.Sprintf("10.20.0.%d", 20+i)
			s.NATRules = append(s.NATRules, r)
		}
		x, c := countingIndex(t, s, max)
		if c.total > max {
			t.Fatalf("+%d: %d placements, budget %d", extra, c.total, max)
		}
		last := x.natZone[len(x.natZone)-1]
		if extra == 0 && (last.zone != "dmz" || last.reason != "") {
			t.Fatalf("at budget: last rule zone %+v", last)
		}
		if extra == 1 && (last.zone != "" || last.reason != ErrLimitReached.Error()) {
			t.Fatalf("over budget: last rule zone %+v", last)
		}
	}
	// Every earlier rule takes the query first, so mark them source-NAT
	// only and check the verdict of the rule past the budget.
	s := labSnapshot()
	s.NATRules = nil
	for i := range max + 1 {
		r := evaluableNAT(fmt.Sprintf("fwd-%d", i))
		r.DestinationTranslation.Value.Address = fmt.Sprintf("10.20.0.%d", 20+i)
		if i < max {
			r.Service = Collected("svc-dns")
		}
		s.NATRules = append(s.NATRules, r)
	}
	x, _ := countingIndex(t, s, max)
	r := x.Evaluate(internetQuery(wanAddr, 443))
	wantVerdict(t, r, VerdictUnknown, "NAT rule fwd-3: post-NAT zone: limit reached")
	wantStep(t, r, StepNAT, "fwd-3", OutcomeUnknown, "post-NAT zone: limit reached")
	if d := MaxNATPlacementsPerSnapshot; d <= 0 {
		t.Fatalf("MaxNATPlacementsPerSnapshot %d", d)
	}
}

// TestPostNATZoneNotInSnapshotNamesCause: a translated address placed in
// a zone the snapshot does not list gives unknown, and the chain has a
// NAT step on the translated path that names the cause.
func TestPostNATZoneNotInSnapshotNamesCause(t *testing.T) {
	s := labSnapshot()
	s.Interfaces = append(s.Interfaces, Interface{Name: "ethernet1/5", Zone: "ghost", Prefixes: []netip.Prefix{pfx("10.40.0.0/24")}})
	s.Addresses = append(s.Addresses, AddressObject{Name: "t", Type: AddressNetmask, Value: "10.40.0.9"})
	translatedTo(s, "t")
	r := evalQ(t, s, internetQuery(wanAddr, 443))
	wantVerdict(t, r, VerdictUnknown, "zone ghost not in snapshot")
	for _, st := range r.Chain {
		if st.Kind == StepNAT && st.Name == "fwd-https" && st.Path == "via NAT rule fwd-https" &&
			st.Outcome == OutcomeUnknown && st.Detail == "post-NAT zone: zone ghost not in snapshot" {
			return
		}
	}
	t.Fatalf("chain lacks the NAT step naming the cause\n%s", r.Text())
}

// TestRuleAddressSetsMergedAtBuild: every address field of the Index is
// held sorted and merged; an already merged field shares its ranges, and
// matching on the merged set gives the same result as on the raw ranges.
func TestRuleAddressSetsMergedAtBuild(t *testing.T) {
	s := labSnapshot()
	s.AddressGroups = append(s.AddressGroups, Group{Name: "adjacent", Static: []string{"10.0.1.21", "pool", "10.0.1.9", "10.0.1.15"}})
	s.SecurityRules[1].Source = list("adjacent")
	x := mustIndex(t, s)
	if len(x.ruleAddrs) != len(x.rules) || len(x.natAddrs) != len(x.nat) {
		t.Fatalf("merged sets %d/%d for %d/%d rules", len(x.ruleAddrs), len(x.natAddrs), len(x.rules), len(x.nat))
	}
	got := x.ruleAddrs[1].src.m
	if len(got) != 1 || got[0] != (AddrRange{From: addr("10.0.1.9"), To: addr("10.0.1.21")}) {
		t.Fatalf("merged source %v", got)
	}
	if n := len(x.rules[1].Source.Ranges); n != 4 {
		t.Fatalf("exported view changed: %d ranges", n)
	}
	// wan-ip is a single range: no copy.
	if d := x.ruleAddrs[0].dst.m; len(d) != 1 || &d[0] != &x.rules[0].Destination.Ranges[0] {
		t.Fatal("already merged field was copied")
	}
	// The merged source decides as the union of its parts.
	for _, c := range []struct {
		x    AddrRange
		want match
	}{
		{AddrRange{From: addr("10.0.1.9"), To: addr("10.0.1.21")}, matchFull},
		{AddrRange{From: addr("10.0.1.5"), To: addr("10.0.1.12")}, matchPartial},
		{AddrRange{From: addr("10.0.1.22"), To: addr("10.0.1.30")}, matchNone},
	} {
		if got := x.ruleAddrs[1].src.match(false, []AddrRange{c.x}); got != c.want {
			t.Errorf("match %v = %d, want %d", c.x, got, c.want)
		}
	}
}
