// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"reflect"
	"strings"
	"testing"
)

// Vectors of the path lab. weakN has a small CVSS prior so EPSS dominates:
// X = 8.22 × 0.85 × 0.44 × 0.27 × 0.62 = 0.514634472, prior 0.0395872…
const (
	strongN = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // X 3.887042775
	// strongNoExecN has strongN's X but no integrity impact.
	strongNoExecN = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"
	weakN         = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" // prior 0.0396
	weakA         = "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" // prior 0.0289
	weakL         = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" // prior 0.0256
	weakP         = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	// rceN, rceLowN and rceA have the weak priors but an integrity impact,
	// so a network step with them may grant code execution and owns.
	rceN    = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:N"
	rceLowN = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
	rceA    = "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:H/A:N"
	// cE5 is e of CVE-E5: no KEV, no EPSS, so 0.3 × 3.887042775 / 3.9.
	cE5 = 0.2990032903846154
)

// pathLabInputs is the lab of the golden path test:
//
//	internet --policy tcp/443--> host:web
//	host:web --observed tcp/8080--> host:app
//	host:web --l2 (assumed)--> host:app
//	netbird --policy tcp/8080--> host:app
//	host:app --policy tcp/22--> host:exec
//	host:exec --credential--> pve:pve1 --control--> guest:db --control--> ctr:cache
func pathLabInputs() ([]Node, []Edge, []Finding, []Target) {
	nodes := []Node{
		{ID: "host:web", Kind: NodeHost, Label: "web"},
		{ID: "host:app", Kind: NodeHost, Label: "app"},
		{ID: "host:exec", Kind: NodeHost, Label: "executor"},
		{ID: "pve:pve1", Kind: NodePVENode, Label: "pve1"},
		{ID: "guest:db", Kind: NodeGuest, Label: "db"},
		{ID: "ctr:cache", Kind: NodeContainer, Label: "cache"},
	}
	edges := []Edge{
		{From: InternetID, To: "host:web", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 443},
		{From: "host:web", To: "host:app", Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 8080},
		{From: "host:web", To: "host:app", Kind: EdgeL2Adjacency},
		{From: NetBirdID, To: "host:app", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 8080},
		{From: "host:app", To: "host:exec", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 22},
		{From: "host:exec", To: "pve:pve1", Kind: EdgeCredential},
		{From: "pve:pve1", To: "guest:db", Kind: EdgeControl},
		{From: "guest:db", To: "ctr:cache", Kind: EdgeControl},
	}
	tcp := func(p uint16) []Port { return []Port{{ProtoTCP, p}} }
	findings := []Finding{
		// e 0.9 (KEV) on tcp/443.
		{Node: "host:web", Key: "CVE-W1", Vector: weakN, KEV: true, Ports: tcp(443), State: FindingOpen},
		// Port tcp/80 is not allowed by any edge: unusable.
		{Node: "host:web", Key: "CVE-W2", Vector: strongN, KEV: true, Ports: tcp(80), State: FindingOpen},
		// No CVSS v3 vector: unscored, counted.
		{Node: "host:web", Key: "CVE-W9", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", KEV: true, State: FindingOpen},
		// e 0.2, port unknown: possible over policy/observed, 0.1 over L2.
		{Node: "host:app", Key: "CVE-A3", Vector: weakN, EPSS: 0.2, EPSSKnown: true, State: FindingOpen},
		// Adjacent vector: only over L2, 0.4 × 0.5 = 0.2.
		{Node: "host:app", Key: "CVE-A4", Vector: weakA, EPSS: 0.4, EPSSKnown: true, Ports: tcp(8080), State: FindingOpen},
		// False positive: never usable although KEV.
		{Node: "host:app", Key: "CVE-A7", Vector: strongN, KEV: true, Ports: tcp(8080), State: FindingFalsePositive},
		// Accepted risk stays usable: e 0.05, 0.025 over L2.
		{Node: "host:app", Key: "CVE-A8", Vector: weakN, EPSS: 0.05, EPSSKnown: true, Ports: tcp(8080), State: FindingAcceptedRisk},
		// Physical vector: never usable.
		{Node: "host:app", Key: "CVE-A9", Vector: weakP, KEV: true, State: FindingOpen},
		// e = cE5 on tcp/22 (CVSS prior only). Integrity impact none: it
		// cannot grant code execution, so it only reaches exec and the
		// credential step needs CVE-E6 first. (An RCE here would own exec
		// at once; see TestKEVRCEOnExecutorOwnsEveryManagedHost.)
		{Node: "host:exec", Key: "CVE-E5", Vector: strongNoExecN, Ports: tcp(22), State: FindingOpen},
		// Local privilege escalation on exec: e 0.6.
		{Node: "host:exec", Key: "CVE-E6", Vector: weakL, EPSS: 0.6, EPSSKnown: true, State: FindingOpen},
		// Local finding on app: app has no owned-only exits, so it never helps.
		{Node: "host:app", Key: "CVE-A5", Vector: weakL, EPSS: 0.9, EPSSKnown: true, State: FindingOpen},
		// On a node not in the graph: unattached, counted.
		{Node: "host:gone", Key: "CVE-G1", Vector: strongN, KEV: true, State: FindingOpen},
	}
	targets := []Target{
		{Node: "host:exec", Impact: 10},
		{Node: "pve:pve1", Impact: 8},
		{Node: "ctr:cache", Impact: 5},
		{Node: "host:missing", Impact: 9},
	}
	return nodes, edges, findings, targets
}

func computeLab(t *testing.T, seed uint64) *Result {
	t.Helper()
	nodes, edges, findings, targets := pathLabInputs()
	if seed != 0 {
		nodes, edges = shuffledCopy(nodes, seed), shuffledCopy(edges, seed+1)
		findings, targets = shuffledCopy(findings, seed+2), shuffledCopy(targets, seed+3)
	}
	b := NewBuilder()
	for _, n := range nodes {
		mustNode(t, b, n)
	}
	for _, e := range edges {
		mustEdge(t, b, e)
	}
	res, err := Compute(b.Build(), findings, targets, frozen)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return res
}

// wantPath describes a path by entry, the findings of its steps ("-" for a
// step without finding), its likelihood in units of cE5 and its flags.
type wantPath struct {
	entry    string
	findings string
	lPerC    float64
	possible bool
	assumed  bool
}

func describe(p Path) string {
	parts := []string{p.Entry}
	for _, s := range p.Steps {
		f := s.Finding
		if f == "" {
			f = "-"
		}
		parts = append(parts, s.Kind.String()+":"+f)
	}
	return strings.Join(parts, " ")
}

func TestGoldenLabPathsHandComputed(t *testing.T) {
	res := computeLab(t, 0)
	if res.FormulaVersion != "ap-v1" || res.Truncated {
		t.Fatalf("formula %q truncated %v", res.FormulaVersion, res.Truncated)
	}
	if res.UnscoredFindings != 1 || res.UnattachedFindings != 1 {
		t.Fatalf("unscored %d unattached %d, want 1 and 1", res.UnscoredFindings, res.UnattachedFindings)
	}
	if !reflect.DeepEqual(res.MissingTargets, []string{"host:missing"}) {
		t.Fatalf("missing targets %v", res.MissingTargets)
	}

	// To host:exec (impact 10): every entry route times cE5 for CVE-E5.
	// Ties at 0.18 (observed A3 vs L2 A4: 0.9 × 0.2 and 0.9 × 0.4 × 0.5)
	// go to the lower edge in canonical order (observed before l2).
	execPaths := []wantPath{
		{"netbird", "network:CVE-A3 network:CVE-E5", 0.2, true, false},                    // 0.2
		{"internet", "network:CVE-W1 network:CVE-A3 network:CVE-E5", 0.18, true, false},   // 0.9 × 0.2
		{"internet", "network:CVE-W1 network:CVE-A4 network:CVE-E5", 0.18, false, true},   // 0.9 × 0.4 × 0.5
		{"internet", "network:CVE-W1 network:CVE-A3 network:CVE-E5", 0.09, false, true},   // 0.9 × 0.2 × 0.5
		{"netbird", "network:CVE-A8 network:CVE-E5", 0.05, false, false},                  // 0.05
		{"internet", "network:CVE-W1 network:CVE-A8 network:CVE-E5", 0.045, false, false}, // 0.9 × 0.05
		{"internet", "network:CVE-W1 network:CVE-A8 network:CVE-E5", 0.0225, false, true}, // 0.9 × 0.05 × 0.5
	}
	// To pve:pve1 (impact 8): the same routes, then local CVE-E6 (0.6) to
	// own exec and the credential step (1).
	var pvePaths []wantPath
	for _, p := range execPaths {
		pvePaths = append(pvePaths, wantPath{p.entry, p.findings + " local:CVE-E6 credential:-", p.lPerC * 0.6, p.possible, p.assumed})
	}
	// To ctr:cache (impact 5): from the internet 7 steps, beyond depth 6;
	// from netbird exactly 6 steps.
	cachePaths := []wantPath{
		{"netbird", "network:CVE-A3 network:CVE-E5 local:CVE-E6 credential:- control:- control:-", 0.12, true, false},  // 0.2 × 0.6
		{"netbird", "network:CVE-A8 network:CVE-E5 local:CVE-E6 credential:- control:- control:-", 0.03, false, false}, // 0.05 × 0.6
	}
	want := []struct {
		node   string
		impact int
		paths  []wantPath
	}{
		{"host:exec", 10, execPaths},
		{"pve:pve1", 8, pvePaths},
		{"ctr:cache", 5, cachePaths},
	}
	if len(res.Targets) != len(want) {
		t.Fatalf("targets %d, want %d", len(res.Targets), len(want))
	}
	for i, w := range want {
		got := res.Targets[i]
		if got.Node != w.node || got.Impact != w.impact || !got.Complete {
			t.Fatalf("target %d: %s impact %d complete %v", i, got.Node, got.Impact, got.Complete)
		}
		if len(got.Paths) != len(w.paths) {
			for _, p := range got.Paths {
				t.Logf("  %s L=%v", describe(p), p.Likelihood)
			}
			t.Fatalf("%s: %d paths, want %d", w.node, len(got.Paths), len(w.paths))
		}
		for j, wp := range w.paths {
			p := got.Paths[j]
			if d := wp.entry + " " + wp.findings; describe(p) != d {
				t.Errorf("%s path %d: %s, want %s", w.node, j, describe(p), d)
			}
			if !near(p.Likelihood, wp.lPerC*cE5) || !near(p.Risk, wp.lPerC*cE5*float64(w.impact)) {
				t.Errorf("%s path %d: L %.17g R %.17g, want L %.17g", w.node, j, p.Likelihood, p.Risk, wp.lPerC*cE5)
			}
			if p.Possible != wp.possible || p.Assumed != wp.assumed {
				t.Errorf("%s path %d: possible %v assumed %v", w.node, j, p.Possible, p.Assumed)
			}
			if len(p.Hash) != 64 {
				t.Errorf("%s path %d: hash %q", w.node, j, p.Hash)
			}
		}
	}
	// The two 0.18 paths and the two A3 paths differ, so do their hashes.
	seen := map[string]bool{}
	for _, p := range res.Targets[0].Paths {
		if seen[p.Hash] {
			t.Fatalf("duplicate path hash %s", p.Hash)
		}
		seen[p.Hash] = true
	}
}

func TestGoldenLabStepsExplainNumbers(t *testing.T) {
	res := computeLab(t, 0)
	p := res.Targets[1].Paths[2] // internet, W1, A4 over L2, E5, E6, credential
	want := []struct {
		kind  StepKind
		from  string
		to    string
		edge  EdgeKind
		owns  bool
		terms Terms
	}{
		{StepNetwork, InternetID, "host:web", EdgeNetworkPolicy, false, Terms{KEV: true, Exploitability: 0.514634472, Vector: AVNetwork, E: 0.9}},
		{StepNetwork, "host:web", "host:app", EdgeL2Adjacency, false, Terms{EPSS: 0.4, EPSSKnown: true, Exploitability: 0.3753804384, Vector: AVAdjacent, Assumed: true, E: 0.2}},
		{StepNetwork, "host:app", "host:exec", EdgeNetworkPolicy, false, Terms{Exploitability: 3.887042775, Vector: AVNetwork, E: cE5}},
		{StepLocal, "host:exec", "host:exec", 0, true, Terms{EPSS: 0.6, EPSSKnown: true, Exploitability: 0.332998776, Vector: AVLocal, E: 0.6}},
		{StepCredential, "host:exec", "pve:pve1", EdgeCredential, true, Terms{E: 1}},
	}
	if len(p.Steps) != len(want) {
		t.Fatalf("steps %d, want %d", len(p.Steps), len(want))
	}
	for i, w := range want {
		s := p.Steps[i]
		if s.Kind != w.kind || s.From != w.from || s.To != w.to || s.Edge.Kind != w.edge || s.Owns != w.owns {
			t.Errorf("step %d: %v %s->%s %v owns %v", i, s.Kind, s.From, s.To, s.Edge.Kind, s.Owns)
		}
		g, wt := s.Terms, w.terms
		if g.KEV != wt.KEV || g.EPSS != wt.EPSS || g.EPSSKnown != wt.EPSSKnown || g.Vector != wt.Vector ||
			g.Assumed != wt.Assumed || !near(g.Exploitability, wt.Exploitability) || !near(g.E, wt.E) {
			t.Errorf("step %d terms %+v, want %+v", i, g, wt)
		}
	}
	// 0.9 × 0.2 × cE5 × 0.6 × 1 × 8
	if !near(p.Risk, 0.9*0.2*cE5*0.6*8) {
		t.Fatalf("risk %.17g", p.Risk)
	}
}

func TestGoldenLabChokePointsHandComputed(t *testing.T) {
	res := computeLab(t, 0)
	// R per path in units of cE5: exec 2, 1.8, 1.8, 0.9, 0.5, 0.45, 0.225
	// (sum 7.675); pve the same × 0.6 × 0.8: 0.96, 0.864, 0.864, 0.432,
	// 0.24, 0.216, 0.108 (sum 3.684); cache 0.6, 0.15 (sum 0.75).
	type want struct {
		kind  FixKind
		id    string
		rPerC float64
		paths int
	}
	edge := func(from, to string) string { return from + ">" + to }
	wants := []want{
		{FixFinding, "host:exec/CVE-E5", 7.675 + 3.684 + 0.75, 16},
		{FixEdge, edge("host:app", "host:exec"), 7.675 + 3.684 + 0.75, 16},
		{FixFinding, "host:web/CVE-W1", (1.8 + 1.8 + 0.9 + 0.45 + 0.225) + (0.864 + 0.864 + 0.432 + 0.216 + 0.108), 10},
		{FixEdge, edge(InternetID, "host:web"), 5.175 + 2.484, 10},
		{FixFinding, "host:app/CVE-A3", (2 + 1.8 + 0.9) + (0.96 + 0.864 + 0.432) + 0.6, 7},
		{FixEdge, edge(NetBirdID, "host:app"), (2 + 0.5) + (0.96 + 0.24) + 0.75, 6},
		{FixFinding, "host:exec/CVE-E6", 3.684 + 0.75, 9},
		{FixEdge, edge("host:web", "host:app") + " l2", (1.8 + 0.9 + 0.225) + (0.864 + 0.432 + 0.108), 6},
		{FixEdge, edge("host:web", "host:app") + " observed", (1.8 + 0.45) + (0.864 + 0.216), 4},
		{FixFinding, "host:app/CVE-A4", 1.8 + 0.864, 2},
		{FixFinding, "host:app/CVE-A8", (0.5 + 0.45 + 0.225) + (0.24 + 0.216 + 0.108) + 0.15, 7},
	}
	if len(res.ChokePoints) != len(wants) {
		for _, c := range res.ChokePoints {
			t.Logf("  %v %s %s %v %v/c=%v %d", c.Kind, c.Node, c.Finding, c.Edge, c.Risk, c.Risk/cE5, c.Paths)
		}
		t.Fatalf("choke points %d, want %d", len(res.ChokePoints), len(wants))
	}
	for i, w := range wants {
		c := res.ChokePoints[i]
		var id string
		switch c.Kind {
		case FixFinding:
			id = c.Node + "/" + c.Finding
		case FixEdge:
			id = edge(c.Edge.From, c.Edge.To)
			if c.Edge.From == "host:web" {
				id += " " + map[EdgeKind]string{EdgeL2Adjacency: "l2", EdgeNetworkObserved: "observed"}[c.Edge.Kind]
			}
		}
		if c.Kind != w.kind || id != w.id || c.Paths != w.paths || !near(c.Risk, w.rPerC*cE5) {
			t.Errorf("choke %d: %v %s risk/c %.12g paths %d, want %v %s %.12g %d",
				i, c.Kind, id, c.Risk/cE5, c.Paths, w.kind, w.id, w.rPerC, w.paths)
		}
	}
}

func TestComputeIsDeterministicAcrossInputOrder(t *testing.T) {
	want := computeLab(t, 0)
	for seed := uint64(1); seed < 30; seed++ {
		got := computeLab(t, seed*7)
		if got.GraphHash != want.GraphHash {
			t.Fatalf("seed %d: graph hash differs", seed)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: result differs for the same snapshot hash and inputs", seed)
		}
	}
}

func TestComputeDoesNotAliasInput(t *testing.T) {
	nodes, edges, findings, targets := pathLabInputs()
	b := NewBuilder()
	for _, n := range nodes {
		mustNode(t, b, n)
	}
	for _, e := range edges {
		mustEdge(t, b, e)
	}
	g := b.Build()
	before := g.Hash()
	res, err := Compute(g, findings, targets, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range findings {
		findings[i].EPSS, findings[i].KEV = 1, true
		for j := range findings[i].Ports {
			findings[i].Ports[j].Number = 1
		}
	}
	again, err := Compute(g, nil, targets, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if g.Hash() != before || len(again.ChokePoints) != 0 {
		t.Fatal("compute changed the graph or kept state")
	}
	if !reflect.DeepEqual(res, computeLab(t, 0)) {
		t.Fatal("result changed after its input was mutated")
	}
}
