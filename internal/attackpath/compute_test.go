// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

func buildGraph(t *testing.T, nodes []Node, edges []Edge) *Graph {
	t.Helper()
	b := NewBuilder()
	for _, n := range nodes {
		mustNode(t, b, n)
	}
	for _, e := range edges {
		mustEdge(t, b, e)
	}
	return b.Build()
}

func mustCompute(t *testing.T, g *Graph, fs []Finding, ts []Target) *Result {
	t.Helper()
	res, err := Compute(g, fs, ts, Options{})
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return res
}

func host(id string) Node { return Node{ID: "host:" + id, Kind: NodeHost} }

func policy(from, to string, port uint16) Edge {
	return Edge{From: from, To: to, Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: port}
}

func TestUsableStepRules(t *testing.T) {
	// a is reached from the internet by a KEV finding on tcp/1; every case
	// adds one edge into b and one finding on b and asks whether b, the
	// target, is reached and with which e.
	reachA := Finding{Node: "host:a", Key: "A", Vector: weakN, KEV: true, Ports: []Port{{ProtoTCP, 1}}, State: FindingOpen}
	tcp := func(p uint16) []Port { return []Port{{ProtoTCP, p}} }
	cases := []struct {
		name     string
		edge     Edge
		f        Finding
		usable   bool
		e        float64
		possible bool
	}{
		{"AV:N port allowed", policy("host:a", "host:b", 443), Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp(443)}, true, 0.5, false},
		{"AV:N other port", policy("host:a", "host:b", 443), Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp(80)}, false, 0, false},
		{"AV:N other proto", policy("host:a", "host:b", 443), Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: []Port{{ProtoUDP, 443}}}, false, 0, false},
		{"AV:N one of several ports", policy("host:a", "host:b", 443), Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: []Port{{ProtoTCP, 80}, {ProtoTCP, 443}}}, true, 0.5, false},
		{"AV:N port unknown is possible", policy("host:a", "host:b", 443), Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true}, true, 0.5, true},
		{"AV:N observed edge", Edge{From: "host:a", To: "host:b", Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 443}, Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp(443)}, true, 0.5, false},
		{"AV:A over policy", policy("host:a", "host:b", 443), Finding{Vector: weakA, EPSS: 0.5, EPSSKnown: true, Ports: tcp(443)}, false, 0, false},
		{"AV:L over policy", policy("host:a", "host:b", 443), Finding{Vector: weakL, EPSS: 0.5, EPSSKnown: true, Ports: tcp(443)}, false, 0, false},
		{"AV:P over policy", policy("host:a", "host:b", 443), Finding{Vector: weakP, KEV: true, Ports: tcp(443)}, false, 0, false},
		{"AV:N over L2 any port, halved", Edge{From: "host:a", To: "host:b", Kind: EdgeL2Adjacency}, Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp(80)}, true, 0.25, false},
		{"AV:N over L2 port unknown not possible", Edge{From: "host:a", To: "host:b", Kind: EdgeL2Adjacency}, Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true}, true, 0.25, false},
		{"AV:A over L2, halved", Edge{From: "host:a", To: "host:b", Kind: EdgeL2Adjacency}, Finding{Vector: weakA, EPSS: 0.5, EPSSKnown: true}, true, 0.25, false},
		{"AV:L over L2", Edge{From: "host:a", To: "host:b", Kind: EdgeL2Adjacency}, Finding{Vector: weakL, EPSS: 0.5, EPSSKnown: true}, false, 0, false},
		{"KEV over L2", Edge{From: "host:a", To: "host:b", Kind: EdgeL2Adjacency}, Finding{Vector: weakN, KEV: true}, true, 0.45, false},
		{"false positive", policy("host:a", "host:b", 443), Finding{Vector: strongN, KEV: true, Ports: tcp(443), State: FindingFalsePositive}, false, 0, false},
		{"accepted risk stays usable", policy("host:a", "host:b", 443), Finding{Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp(443), State: FindingAcceptedRisk}, true, 0.5, false},
		{"no CVSS v3 vector", policy("host:a", "host:b", 443), Finding{Vector: "", KEV: true, Ports: tcp(443)}, false, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := buildGraph(t, []Node{host("a"), host("b")}, []Edge{policy(InternetID, "host:a", 1), c.edge})
			f := c.f
			f.Node, f.Key = "host:b", "B"
			if f.State == 0 {
				f.State = FindingOpen
			}
			res := mustCompute(t, g, []Finding{reachA, f}, []Target{{Node: "host:b", Impact: 1}})
			paths := res.Targets[0].Paths
			if !c.usable {
				if len(paths) != 0 {
					t.Fatalf("step used: %s", describe(paths[0]))
				}
				return
			}
			if len(paths) != 1 {
				t.Fatalf("paths %d, want 1", len(paths))
			}
			st := paths[0].Steps[1]
			if st.Finding != "B" || !near(st.Terms.E, c.e) || st.Possible != c.possible || !near(paths[0].Likelihood, 0.9*c.e) {
				t.Fatalf("step %+v L %v, want e %v possible %v", st, paths[0].Likelihood, c.e, c.possible)
			}
		})
	}
}

func TestProvenStepsNeedNoFindingButAnOwnedSource(t *testing.T) {
	nodes := []Node{
		host("exec"), host("m"),
		{ID: "pve:p", Kind: NodePVENode}, {ID: "guest:g", Kind: NodeGuest},
		{ID: "ctr:c", Kind: NodeContainer},
	}
	edges := []Edge{
		policy(InternetID, "host:exec", 22),
		policy(InternetID, "pve:p", 8006),
		policy(InternetID, "ctr:c", 80),
		{From: "host:exec", To: "host:m", Kind: EdgeCredential},
		{From: "pve:p", To: "guest:g", Kind: EdgeControl},
		{From: "ctr:c", To: "host:m", Kind: EdgeEscape, Escape: EscapeDockerSocket},
	}
	net := func(node string, port uint16) Finding {
		return Finding{Node: node, Key: "N", Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: []Port{{ProtoTCP, port}}, State: FindingOpen}
	}
	local := func(node string) Finding {
		return Finding{Node: node, Key: "L", Vector: weakL, EPSS: 0.25, EPSSKnown: true, State: FindingOpen}
	}
	targets := []Target{{Node: "host:m", Impact: 1}, {Node: "guest:g", Impact: 2}}

	// Reached only: no proven step is usable.
	res := mustCompute(t, buildGraph(t, nodes, edges),
		[]Finding{net("host:exec", 22), net("pve:p", 8006), net("ctr:c", 80)}, targets)
	for _, tp := range res.Targets {
		if len(tp.Paths) != 0 {
			t.Fatalf("%s reached without owning a source: %s", tp.Node, describe(tp.Paths[0]))
		}
	}

	// With local escalation each proven step is usable at e = 1.
	res = mustCompute(t, buildGraph(t, nodes, edges), []Finding{
		net("host:exec", 22), net("pve:p", 8006), net("ctr:c", 80),
		local("host:exec"), local("pve:p"), local("ctr:c"),
	}, targets)
	want := map[string][]string{
		"guest:g": {"internet network:N local:L control:-"},
		// Equal L and length: the canonical edge order breaks the tie, and
		// internet -> ctr:c sorts before internet -> host:exec.
		"host:m": {
			"internet network:N local:L escape:-",
			"internet network:N local:L credential:-",
		},
	}
	for _, tp := range res.Targets {
		var got []string
		for _, p := range tp.Paths {
			got = append(got, describe(p))
			// 0.5 × 0.25 × 1, × impact
			if !near(p.Likelihood, 0.125) || !near(p.Risk, 0.125*float64(tp.Impact)) {
				t.Fatalf("%s: L %v R %v", describe(p), p.Likelihood, p.Risk)
			}
			if last := p.Steps[len(p.Steps)-1]; last.Terms.E != 1 || last.Finding != "" {
				t.Fatalf("proven step %+v", last)
			}
		}
		if !slices.Equal(got, want[tp.Node]) {
			t.Fatalf("%s: %q, want %q", tp.Node, got, want[tp.Node])
		}
	}
}

func TestDepthIsAtMostSix(t *testing.T) {
	// internet -> h1 -> h2 -> ... -> h7, each hop one usable finding.
	var nodes []Node
	var edges []Edge
	var fs []Finding
	prev := InternetID
	for i := 1; i <= 7; i++ {
		id := fmt.Sprintf("host:h%d", i)
		nodes = append(nodes, Node{ID: id, Kind: NodeHost})
		edges = append(edges, policy(prev, id, 22))
		fs = append(fs, Finding{Node: id, Key: "F", Vector: weakN, KEV: true, Ports: []Port{{ProtoTCP, 22}}, State: FindingOpen})
		prev = id
	}
	res := mustCompute(t, buildGraph(t, nodes, edges), fs,
		[]Target{{Node: "host:h6", Impact: 1}, {Node: "host:h7", Impact: 2}})
	byNode := map[string]TargetPaths{}
	for _, tp := range res.Targets {
		byNode[tp.Node] = tp
	}
	if p := byNode["host:h6"].Paths; len(p) != 1 || len(p[0].Steps) != 6 || !near(p[0].Likelihood, 0.531441) { // 0.9^6
		t.Fatalf("h6 at depth 6: %+v", p)
	}
	if p := byNode["host:h7"]; len(p.Paths) != 0 || !p.Complete {
		t.Fatalf("h7 at depth 7 found: %+v", p)
	}
}

func TestPathsPerTargetIsTwenty(t *testing.T) {
	// 30 parallel policy edges, each with its own finding: 30 one-step paths.
	var edges []Edge
	var fs []Finding
	for p := uint16(1); p <= 30; p++ {
		edges = append(edges, policy(InternetID, "host:t", p))
		fs = append(fs, Finding{Node: "host:t", Key: fmt.Sprintf("F%02d", p), Vector: weakN,
			EPSS: float64(p) / 100, EPSSKnown: true, Ports: []Port{{ProtoTCP, p}}, State: FindingOpen})
	}
	res := mustCompute(t, buildGraph(t, []Node{host("t")}, edges), fs, []Target{{Node: "host:t", Impact: 1}})
	paths := res.Targets[0].Paths
	if len(paths) != PathsPerTarget || res.Truncated {
		t.Fatalf("paths %d truncated %v", len(paths), res.Truncated)
	}
	// Best first: F30 (0.30) down to F11 (0.11).
	for i, p := range paths {
		if want := fmt.Sprintf("F%02d", 30-i); p.Steps[0].Finding != want {
			t.Fatalf("path %d uses %s, want %s", i, p.Steps[0].Finding, want)
		}
	}
}

// enumerate lists every search path to target the rules allow, by brute
// force over the searcher's state graph.
func enumerate(s *searcher, target int32) []cand {
	var all []cand
	var walk func(c cand)
	walk = func(c cand) {
		u := s.lastState(&c)
		if u != s.src && u/2 == target {
			all = append(all, c)
			return
		}
		if c.n >= maxArcs {
			return
		}
		afterLocal := c.n > 0 && s.arcs[c.arcs[c.n-1]].kind == StepLocal
		for _, ai := range s.out[u] {
			a := s.arcs[ai]
			if (afterLocal && a.kind == StepNetwork) || s.visits(&c, a.to) {
				continue
			}
			nc := c
			nc.arcs[nc.n] = ai
			nc.n++
			if a.from >= 0 {
				nc.l *= a.terms.E
			}
			walk(nc)
		}
	}
	walk(cand{l: 1})
	slices.SortFunc(all, func(x, y cand) int {
		if better(&x, &y) {
			return -1
		}
		if better(&y, &x) {
			return 1
		}
		return 0
	})
	return all
}

func randomLab(r *rand.Rand) ([]Node, []Edge, []Finding) {
	var nodes []Node
	hosts := []string{InternetID, NetBirdID}
	for i := range 6 {
		nodes = append(nodes, Node{ID: fmt.Sprintf("host:h%d", i), Kind: NodeHost})
		hosts = append(hosts, fmt.Sprintf("host:h%d", i))
	}
	nodes = append(nodes,
		Node{ID: "pve:p0", Kind: NodePVENode}, Node{ID: "guest:g0", Kind: NodeGuest},
		Node{ID: "guest:g1", Kind: NodeGuest}, Node{ID: "ctr:c0", Kind: NodeContainer})
	hosts = append(hosts, "pve:p0", "guest:g0", "guest:g1", "ctr:c0")
	edges := []Edge{
		{From: "pve:p0", To: "guest:g0", Kind: EdgeControl},
		{From: "pve:p0", To: "guest:g1", Kind: EdgeControl},
		{From: "host:h0", To: "ctr:c0", Kind: EdgeControl},
		{From: "ctr:c0", To: "host:h0", Kind: EdgeEscape, Escape: EscapePrivileged},
		{From: "host:h1", To: "pve:p0", Kind: EdgeCredential},
		{From: "host:h1", To: "host:h2", Kind: EdgeCredential},
	}
	seen := map[edgeKey]bool{}
	for range 22 {
		from, to := hosts[r.IntN(len(hosts))], hosts[2+r.IntN(len(hosts)-2)]
		if from == to {
			continue
		}
		var e Edge
		switch k := r.IntN(4); {
		case k == 0 && from != InternetID && from != NetBirdID:
			e = Edge{From: from, To: to, Kind: EdgeL2Adjacency}
		case k == 1:
			e = Edge{From: from, To: to, Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: uint16(80 + r.IntN(2))}
		default:
			e = policy(from, to, uint16(80+r.IntN(2)))
		}
		if !seen[e.key()] {
			seen[e.key()] = true
			edges = append(edges, e)
		}
	}
	// Exact binary values keep products exact, so the brute-force order
	// and Yen's order agree to the last bit.
	epss := []float64{0.25, 0.5, 0.75, 0.875, 0.625, 1}
	vectors := []string{weakN, weakN, weakA, weakL}
	var fs []Finding
	for _, id := range hosts[2:] {
		for k := range r.IntN(4) {
			f := Finding{Node: id, Key: fmt.Sprintf("F%d", k), Vector: vectors[r.IntN(len(vectors))],
				EPSS: epss[r.IntN(len(epss))], EPSSKnown: true, State: FindingOpen}
			if p := r.IntN(3); p > 0 {
				f.Ports = []Port{{ProtoTCP, uint16(79 + p)}}
			}
			fs = append(fs, f)
		}
	}
	return nodes, edges, fs
}

func TestYenMatchesBruteForce(t *testing.T) {
	checked := 0
	for seed := uint64(1); seed <= 150; seed++ {
		r := rand.New(rand.NewPCG(seed, 99))
		nodes, edges, fs := randomLab(r)
		g := buildGraph(t, nodes, edges)
		res := &Result{}
		usable, err := prepareFindings(g, fs, res)
		if err != nil {
			t.Fatal(err)
		}
		s := newSearcher(g, usable)
		s.deadline = func() bool { return false }
		for _, n := range g.nodes {
			if n.Kind.Entry() {
				continue
			}
			ti := int32(g.index[n.ID])
			want := enumerate(s, ti)
			if len(want) > PathsPerTarget {
				want = want[:PathsPerTarget]
			}
			got, complete := s.topPaths(ti, PathsPerTarget)
			if !complete || len(got) != len(want) {
				t.Fatalf("seed %d target %s: %d paths, want %d", seed, n.ID, len(got), len(want))
			}
			for i := range want {
				if got[i].key() != want[i].key() || got[i].l != want[i].l {
					t.Fatalf("seed %d target %s path %d: %v (L %v), want %v (L %v)", seed, n.ID, i,
						got[i].slice(), got[i].l, want[i].slice(), want[i].l)
				}
			}
			checked += len(want)
		}
	}
	if checked < 500 {
		t.Fatalf("only %d paths checked; the random labs are too sparse", checked)
	}
}

func TestTargetCapKeepsHighestImpact(t *testing.T) {
	var nodes []Node
	var targets []Target
	for i := range MaxTargets + 1 {
		id := fmt.Sprintf("t%02d", i)
		nodes = append(nodes, host(id))
		impact := 5
		if i == 0 {
			impact = 1 // the one to drop, although its ID sorts first
		}
		targets = append(targets, Target{Node: "host:" + id, Impact: impact})
	}
	res := mustCompute(t, buildGraph(t, nodes, nil), nil, targets)
	if len(res.Targets) != MaxTargets || !res.Truncated || !res.Limits.Targets {
		t.Fatalf("targets %d truncated %v limits %+v", len(res.Targets), res.Truncated, res.Limits)
	}
	for _, tp := range res.Targets {
		if tp.Node == "host:t00" {
			t.Fatal("lowest-impact target kept")
		}
	}
	if res.Targets[0].Node != "host:t01" || res.Targets[MaxTargets-1].Node != "host:t50" {
		t.Fatalf("order %s .. %s", res.Targets[0].Node, res.Targets[MaxTargets-1].Node)
	}
}

func TestChokePointCapKeepsHighestRisk(t *testing.T) {
	// 50 targets, each with 25 one-step paths over its own edges and
	// findings: 20 top paths each, 40 candidates each, 2,000 in all.
	var nodes []Node
	var edges []Edge
	var fs []Finding
	var targets []Target
	for i := range MaxTargets {
		id := fmt.Sprintf("host:t%02d", i)
		nodes = append(nodes, Node{ID: id, Kind: NodeHost})
		targets = append(targets, Target{Node: id, Impact: 1 + i%10})
		for p := uint16(1); p <= 25; p++ {
			edges = append(edges, policy(InternetID, id, p))
			fs = append(fs, Finding{Node: id, Key: fmt.Sprintf("F%02d", p), Vector: weakN,
				EPSS: float64(p) / 25, EPSSKnown: true, Ports: []Port{{ProtoTCP, p}}, State: FindingOpen})
		}
	}
	res := mustCompute(t, buildGraph(t, nodes, edges), fs, targets)
	if len(res.ChokePoints) != MaxChokePoints || !res.Truncated || !res.Limits.ChokePoints {
		t.Fatalf("choke points %d truncated %v limits %+v", len(res.ChokePoints), res.Truncated, res.Limits)
	}
	if res.Limits.Targets || res.Limits.Budget {
		t.Fatalf("unexpected limits %+v", res.Limits)
	}
	for i := 1; i < len(res.ChokePoints); i++ {
		if res.ChokePoints[i].Risk > res.ChokePoints[i-1].Risk {
			t.Fatalf("choke point %d not ordered by risk", i)
		}
	}
	// The best is fixing F25 (or its edge) on an impact-10 target: 1 × 10.
	if top := res.ChokePoints[0]; !near(top.Risk, 10) || top.Kind != FixFinding || top.Finding != "F25" {
		t.Fatalf("top choke point %+v", top)
	}
}

func TestBudgetStopsSearchAndTruncates(t *testing.T) {
	_, edges, fs, _ := pathLabInputs()
	nodes, _, _, targets := pathLabInputs()
	g := buildGraph(t, nodes, edges)
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	calls := 0
	now := func() time.Time {
		calls++
		return t0.Add(time.Duration(calls) * time.Second)
	}
	res, err := Compute(g, fs, targets, Options{Now: now, Budget: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || !res.Limits.Budget {
		t.Fatalf("truncated %v limits %+v", res.Truncated, res.Limits)
	}
	if res.Targets[0].Complete || len(res.Targets[0].Paths) == 0 || len(res.Targets[0].Paths) >= 7 {
		t.Fatalf("first target complete %v with %d paths", res.Targets[0].Complete, len(res.Targets[0].Paths))
	}
	for _, tp := range res.Targets[1:] {
		if tp.Complete || len(tp.Paths) != 0 {
			t.Fatalf("%s searched after the budget was spent", tp.Node)
		}
	}
	// A budget that is not reached changes nothing.
	res, err = Compute(g, fs, targets, Options{Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || len(res.Targets[0].Paths) != 7 {
		t.Fatalf("unspent budget truncated: %+v", res.Limits)
	}
}

func TestFindingCapKeepsHighestE(t *testing.T) {
	fs := make([]Finding, 0, MaxFindings+1)
	for i := range MaxFindings {
		fs = append(fs, Finding{Node: "host:t", Key: fmt.Sprintf("F%06d", i), Vector: weakN,
			EPSS: 0.05, EPSSKnown: true, Ports: []Port{{ProtoTCP, 80}}, State: FindingOpen})
	}
	fs = append(fs, Finding{Node: "host:t", Key: "Z-KEV", Vector: weakN, KEV: true,
		Ports: []Port{{ProtoTCP, 80}}, State: FindingOpen})
	g := buildGraph(t, []Node{host("t")}, []Edge{policy(InternetID, "host:t", 80)})
	res := mustCompute(t, g, fs, []Target{{Node: "host:t", Impact: 1}})
	if !res.Truncated || !res.Limits.Findings {
		t.Fatalf("limits %+v", res.Limits)
	}
	if p := res.Targets[0].Paths; len(p) != PathsPerTarget || p[0].Steps[0].Finding != "Z-KEV" {
		t.Fatalf("paths %d, first %s", len(p), describe(p[0]))
	}
}

func TestTruncatedGraphTruncatesResult(t *testing.T) {
	b := NewBuilder()
	for i := range MaxNodes - 1 {
		mustNode(t, b, Node{ID: fmt.Sprintf("unk:n%05d", i), Kind: NodeUnmanaged})
	}
	g := b.Build()
	if !g.Truncated() {
		t.Fatal("graph not truncated")
	}
	res := mustCompute(t, g, nil, nil)
	if !res.Truncated || !res.Limits.Graph {
		t.Fatalf("limits %+v", res.Limits)
	}
}

func TestComputeRejectsInvalidInput(t *testing.T) {
	g := buildGraph(t, []Node{host("a")}, nil)
	good := Finding{Node: "host:a", Key: "K", Vector: weakN, State: FindingOpen}
	cases := []struct {
		name string
		fs   []Finding
		ts   []Target
		want error
	}{
		{"invalid finding", []Finding{{Node: "host:a", Key: "K", State: 9}}, nil, ErrInvalidFinding},
		{"duplicate finding", []Finding{good, good}, nil, ErrInvalidFinding},
		{"target id", nil, []Target{{Node: "host a", Impact: 1}}, ErrInvalidTarget},
		{"impact zero", nil, []Target{{Node: "host:a", Impact: 0}}, ErrInvalidTarget},
		{"impact eleven", nil, []Target{{Node: "host:a", Impact: 11}}, ErrInvalidTarget},
		{"duplicate target", nil, []Target{{Node: "host:a", Impact: 1}, {Node: "host:a", Impact: 2}}, ErrInvalidTarget},
		{"internet target", nil, []Target{{Node: InternetID, Impact: 1}}, ErrInvalidTarget},
		{"netbird target", nil, []Target{{Node: NetBirdID, Impact: 1}}, ErrInvalidTarget},
	}
	for _, c := range cases {
		_, err := Compute(g, c.fs, c.ts, Options{})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "host a") {
			t.Errorf("%s: error echoes the rejected value: %v", c.name, err)
		}
	}
	if _, err := Compute(nil, nil, nil, Options{}); err == nil {
		t.Error("nil graph accepted")
	}
}

func TestNoTargetsNoPaths(t *testing.T) {
	_, edges, fs, _ := pathLabInputs()
	nodes, _, _, _ := pathLabInputs()
	res := mustCompute(t, buildGraph(t, nodes, edges), fs, nil)
	if len(res.Targets) != 0 || len(res.ChokePoints) != 0 || res.Truncated {
		t.Fatalf("result %+v", res)
	}
}
