// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"slices"
	"testing"
	"time"
)

// provenLab has one proven edge of each kind into the targets host:m and
// guest:g; each source is exposed to the internet on its own port.
func provenLab(t *testing.T) *Graph {
	t.Helper()
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
	return buildGraph(t, nodes, edges)
}

var provenTargets = []Target{{Node: "host:m", Impact: 1}, {Node: "guest:g", Impact: 2}}

// netOn is a network finding with e 0.5 on the node's tcp port.
func netOn(node string, port uint16, vector string) Finding {
	return Finding{Node: node, Key: "N", Vector: vector, EPSS: 0.5, EPSSKnown: true,
		Ports: []Port{{ProtoTCP, port}}, State: FindingOpen}
}

// checkProvenPaths checks that the paths per target are want and that each
// has likelihood l and ends in a proven step at e = 1 without a finding.
func checkProvenPaths(t *testing.T, res *Result, l float64, want map[string][]string) {
	t.Helper()
	for _, tp := range res.Targets {
		var got []string
		for _, p := range tp.Paths {
			got = append(got, describe(p))
			if !near(p.Likelihood, l) || !near(p.Risk, l*float64(tp.Impact)) {
				t.Fatalf("%s: L %v R %v, want L %v", describe(p), p.Likelihood, p.Risk, l)
			}
			if last := p.Steps[len(p.Steps)-1]; last.Terms.E != 1 || last.Finding != "" || !last.Owns {
				t.Fatalf("proven step %+v", last)
			}
		}
		if !slices.Equal(got, want[tp.Node]) {
			t.Fatalf("%s: %q, want %q", tp.Node, got, want[tp.Node])
		}
	}
}

func TestNetworkRCEOwnsSoProvenStepsNeedNoFinding(t *testing.T) {
	// ADR 0011 D10: control, credential and escape steps need no finding,
	// and owning the parent owns the child. A network finding that may grant
	// code execution (integrity impact low or high) owns its node, so each
	// proven step follows it directly, without a local finding: a KEV RCE on
	// the executor host yields the credential path.
	for _, vector := range []string{rceN, rceLowN, strongN} {
		t.Run(vector, func(t *testing.T) {
			res := mustCompute(t, provenLab(t), []Finding{
				netOn("host:exec", 22, vector), netOn("pve:p", 8006, vector), netOn("ctr:c", 80, vector),
			}, provenTargets)
			checkProvenPaths(t, res, 0.5, map[string][]string{
				"guest:g": {"internet network:N control:-"},
				// Equal L and length: the canonical edge order breaks the
				// tie, and internet -> ctr:c sorts before internet -> host:exec.
				"host:m": {"internet network:N escape:-", "internet network:N credential:-"},
			})
			for _, tp := range res.Targets {
				if st := tp.Paths[0].Steps[0]; !st.Owns {
					t.Fatalf("%s: RCE step does not own: %+v", tp.Node, st)
				}
			}
		})
	}
}

func TestKEVRCEOnExecutorOwnsEveryManagedHost(t *testing.T) {
	g := buildGraph(t, []Node{host("exec"), host("m1"), host("m2")}, []Edge{
		policy(InternetID, "host:exec", 443),
		{From: "host:exec", To: "host:m1", Kind: EdgeCredential},
		{From: "host:exec", To: "host:m2", Kind: EdgeCredential},
	})
	fs := []Finding{{Node: "host:exec", Key: "KEV-RCE", Vector: strongN, KEV: true,
		Ports: []Port{{ProtoTCP, 443}}, State: FindingOpen}}
	res := mustCompute(t, g, fs, []Target{{Node: "host:m1", Impact: 8}, {Node: "host:m2", Impact: 8}})
	for _, tp := range res.Targets {
		if len(tp.Paths) != 1 || describe(tp.Paths[0]) != "internet network:KEV-RCE credential:-" ||
			!near(tp.Paths[0].Likelihood, 0.9) {
			t.Fatalf("%s: %d paths, first %v", tp.Node, len(tp.Paths), tp.Paths)
		}
	}
}

func TestNetworkFindingWithoutIntegrityImpactOnlyReaches(t *testing.T) {
	// A network finding with I:N cannot grant code execution: it reaches the
	// node, and a proven step from it needs a local escalation first.
	res := mustCompute(t, provenLab(t), []Finding{
		netOn("host:exec", 22, weakN), netOn("pve:p", 8006, weakN), netOn("ctr:c", 80, weakN),
	}, provenTargets)
	for _, tp := range res.Targets {
		if len(tp.Paths) != 0 {
			t.Fatalf("%s owned without code execution: %s", tp.Node, describe(tp.Paths[0]))
		}
	}
	local := func(node string) Finding {
		return Finding{Node: node, Key: "L", Vector: weakL, EPSS: 0.25, EPSSKnown: true, State: FindingOpen}
	}
	res = mustCompute(t, provenLab(t), []Finding{
		netOn("host:exec", 22, weakN), netOn("pve:p", 8006, weakN), netOn("ctr:c", 80, weakN),
		local("host:exec"), local("pve:p"), local("ctr:c"),
	}, provenTargets)
	// 0.5 × 0.25 × 1
	checkProvenPaths(t, res, 0.125, map[string][]string{
		"guest:g": {"internet network:N local:L control:-"},
		"host:m":  {"internet network:N local:L escape:-", "internet network:N local:L credential:-"},
	})
	for _, tp := range res.Targets {
		if st := tp.Paths[0].Steps; st[0].Owns || !st[1].Owns {
			t.Fatalf("%s: owns flags %+v", tp.Node, st)
		}
	}
}

// counterLab is the shape where the best route into an owned state ends in
// a local step, and only a worse route (over a control step) may continue
// with a network step:
//
//	internet -> ctr:c -> host:h      network, I:N: reached only
//	local escalation on host:h, control host:h -> ctr:c
//	ctr:c -> host:t                  network
//
// ctr:c also has a local finding with e 1, so its owned state is best
// entered by a local step, which bars the network step to host:t.
func counterLab(t *testing.T) (*Graph, []Finding) {
	t.Helper()
	g := buildGraph(t, []Node{{ID: "ctr:c", Kind: NodeContainer}, host("h"), host("t")}, []Edge{
		policy(InternetID, "ctr:c", 80),
		policy("ctr:c", "host:h", 80),
		{From: "host:h", To: "ctr:c", Kind: EdgeControl},
		policy("ctr:c", "host:t", 80),
	})
	tcp80 := []Port{{ProtoTCP, 80}}
	fs := []Finding{
		{Node: "ctr:c", Key: "C", Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp80, State: FindingOpen},
		{Node: "ctr:c", Key: "CL", Vector: weakL, EPSS: 1, EPSSKnown: true, State: FindingOpen},
		{Node: "host:h", Key: "H", Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp80, State: FindingOpen},
		{Node: "host:h", Key: "HL", Vector: weakL, EPSS: 0.5, EPSSKnown: true, State: FindingOpen},
		{Node: "host:t", Key: "T", Vector: weakN, EPSS: 0.5, EPSSKnown: true, Ports: tcp80, State: FindingOpen},
	}
	return g, fs
}

func TestSpurSearchKeepsRoutesTheLocalRuleAllows(t *testing.T) {
	g, fs := counterLab(t)
	res := mustCompute(t, g, fs, []Target{{Node: "host:t", Impact: 1}})
	var got []string
	for _, p := range res.Targets[0].Paths {
		got = append(got, describe(p))
	}
	want := []string{
		"internet network:C network:T",
		"internet network:C network:H local:HL control:- network:T",
	}
	if !slices.Equal(got, want) || !res.Targets[0].Complete {
		t.Fatalf("paths %q, want %q", got, want)
	}
	if n := checkYen(t, g, fs, "counter lab"); n == 0 {
		t.Fatal("counter lab compared no paths")
	}
}

func TestDeadlineStopsInsideASpurSearch(t *testing.T) {
	nodes, edges, fs, _ := pathLabInputs()
	g := buildGraph(t, nodes, edges)
	usable, err := prepareFindings(g, fs, &Result{})
	if err != nil {
		t.Fatal(err)
	}
	s := newSearcher(g, usable)
	calls := 0
	// The check before the first spur search passes; every later one fails.
	s.deadline = func() bool { calls++; return calls > 1 }
	got, complete := s.topPaths(int32(g.index["ctr:cache"]), PathsPerTarget)
	if complete || len(got) != 0 {
		t.Fatalf("first spur search ran past the deadline: complete %v, %d paths", complete, len(got))
	}
}

func TestNilClockEnforcesTheBudget(t *testing.T) {
	if !deadlineFunc(nil, 0)() {
		t.Fatal("nil clock: a zero budget is not spent")
	}
	if deadlineFunc(nil, time.Hour)() {
		t.Fatal("nil clock: an hour's budget is spent at once")
	}
	// A frozen clock is the explicit opt-out: the budget never runs out.
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	if deadlineFunc(func() time.Time { return t0 }, time.Nanosecond)() {
		t.Fatal("frozen clock spent the budget")
	}
}

func TestPathHashIsPinned(t *testing.T) {
	steps := []Step{
		{Kind: StepNetwork, From: InternetID, To: "host:web", Finding: "CVE-W1",
			Edge: Edge{From: InternetID, To: "host:web", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 443}},
		{Kind: StepLocal, From: "host:web", To: "host:web", Finding: "CVE-W6"},
		{Kind: StepControl, From: "host:web", To: "ctr:c", Edge: Edge{From: "host:web", To: "ctr:c", Kind: EdgeControl}},
	}
	// sha256 of the domain tag "nos/attackpath/path/v1\n" followed by
	// {"entry":"internet","steps":[{"kind":"network","from":"internet","to":"host:web","edge":"network_policy","proto":"tcp","port":443,"finding":"CVE-W1"},{"kind":"local","from":"host:web","to":"host:web","finding":"CVE-W6"},{"kind":"control","from":"host:web","to":"ctr:c","edge":"control"}]}
	// computed outside Go with sha256sum.
	const want = "148815239dff360c7cca871b76f47c0ba1cd0de340fe9fcffb11efc6793eca82"
	if got := pathHash(InternetID, steps); got != want {
		t.Fatalf("path hash %s, want %s", got, want)
	}
}
