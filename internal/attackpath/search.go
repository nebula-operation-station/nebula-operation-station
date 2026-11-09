// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"cmp"
	"slices"
	"time"
)

// Search limits (ADR 0011 D10).
const (
	// MaxDepth is the most steps one path has.
	MaxDepth = 6
	// PathsPerTarget is k of Yen's k-shortest paths per target.
	PathsPerTarget = 20
	// MaxStepsPerGroup bounds the parallel steps kept between the same two
	// states over the same edge (one per usable finding, best e first). A
	// path using a step beyond it is beaten by PathsPerTarget paths that
	// differ only in that step, so the cut never changes a top-k result.
	MaxStepsPerGroup = PathsPerTarget
)

// maxArcs is MaxDepth plus the virtual entry arc every search path starts
// with.
const maxArcs = MaxDepth + 1

// StepKind classifies a step of a path.
type StepKind uint8

// Step kinds.
const (
	// StepNetwork exploits a network or adjacent finding on the edge's
	// target over a network or L2 edge; it reaches the target.
	StepNetwork StepKind = iota + 1
	// StepLocal exploits a local-vector finding as privilege escalation on
	// a node already reached; it owns the node.
	StepLocal
	// StepControl follows a control edge from an owned parent.
	StepControl
	// StepCredential follows the executor's credential edge from the owned
	// executor host.
	StepCredential
	// StepEscape follows an escape edge from an owned container.
	StepEscape
)

var stepKindNames = [...]string{
	StepNetwork:    "network",
	StepLocal:      "local",
	StepControl:    "control",
	StepCredential: "credential",
	StepEscape:     "escape",
}

// String returns the stable name of k, or "invalid".
func (k StepKind) String() string {
	if k >= StepNetwork && k <= StepEscape {
		return stepKindNames[k]
	}
	return "invalid"
}

// The attacker's state on a node. A network step reaches a node (code
// execution); a local step or a control, credential or escape step owns it.
// Control, credential and escape steps need the owned state of their source
// (ADR 0011 D10: "owning the parent owns the child"). A local step is only
// followed by such a step: a network step after it would be dominated by
// the same path without it (same continuation, one factor e ≤ 1 fewer),
// and would only crowd the top paths.
const (
	levelReached = 0
	levelOwned   = 1
)

// arc is one step of the state graph.
type arc struct {
	to       int32 // state index
	from     int32 // node index; -1 for the virtual entry arcs
	edge     int32 // index into Graph.edges; -1 for local and virtual arcs
	finding  int32 // index into the searcher's findings; -1 for none
	kind     StepKind
	possible bool
	terms    Terms
}

// searcher holds the state graph of one computation. States are 2·node +
// level; the virtual source, from which one arc leads to each entry node,
// is the last state.
type searcher struct {
	g        *Graph
	findings []scoredFinding
	arcs     []arc
	out      [][]int32 // per state: arc IDs in ascending order
	src      int32
	deadline func() bool

	// scratch, reused across spur searches
	best     []cand
	has      []bool
	touched  []int32
	frontier []cand
	next     []cand
	nextAt   []int32 // per state: index into next, or -1
}

// cand is a search path: the virtual entry arc and up to MaxDepth steps.
type cand struct {
	arcs [maxArcs]int32
	n    uint8
	l    float64 // product of e over the steps, left to right
}

func (c *cand) slice() []int32 { return c.arcs[:c.n] }

func (s *searcher) state(node int32, level int) int32 { return 2*node + int32(level) }

func (s *searcher) addArc(a arc, fromStates ...int32) {
	id := int32(len(s.arcs))
	s.arcs = append(s.arcs, a)
	for _, st := range fromStates {
		s.out[st] = append(s.out[st], id)
	}
}

// newSearcher builds the state graph. findings must be sorted canonically
// and usable (scored, not false positive, on a node of g); arc IDs follow
// the canonical edge order, so ties are broken the same way every time.
func newSearcher(g *Graph, findings []scoredFinding) *searcher {
	n := int32(len(g.nodes))
	states := 2*n + 1
	s := &searcher{
		g:        g,
		findings: findings,
		out:      make([][]int32, states),
		src:      2 * n,
		best:     make([]cand, states),
		has:      make([]bool, states),
		nextAt:   make([]int32, states),
	}
	for i := range s.nextAt {
		s.nextAt[i] = -1
	}
	byNode := make([][]int32, n)
	for i, f := range findings {
		ni := g.index[f.f.Node]
		byNode[ni] = append(byNode[ni], int32(i))
	}
	for _, id := range []string{InternetID, NetBirdID} {
		ni := int32(g.index[id])
		s.addArc(arc{to: s.state(ni, levelReached), from: -1, edge: -1, finding: -1}, s.src)
	}
	for ei, e := range g.edges {
		from, to := int32(g.index[e.From]), int32(g.index[e.To])
		switch e.Kind {
		case EdgeControl, EdgeCredential, EdgeEscape:
			s.addArc(arc{to: s.state(to, levelOwned), from: from, edge: int32(ei), finding: -1, kind: provenStep(e.Kind), terms: Terms{E: 1}},
				s.state(from, levelOwned))
			continue
		}
		for _, a := range s.networkArcs(e, byNode[to]) {
			a.to, a.from, a.edge = s.state(to, levelReached), from, int32(ei)
			s.addArc(a, s.state(from, levelReached), s.state(from, levelOwned))
		}
	}
	for ni := range n {
		var group []arc
		for _, fi := range byNode[ni] {
			f := findings[fi]
			if f.cvss.av == AVLocal {
				group = append(group, arc{finding: fi, kind: StepLocal, terms: f.terms(false)})
			}
		}
		for _, a := range s.bestOf(group) {
			a.to, a.from, a.edge = s.state(ni, levelOwned), ni, -1
			s.addArc(a, s.state(ni, levelReached))
		}
	}
	return s
}

// provenStep maps a control, credential or escape edge to its step kind.
// These steps need no finding and have e = 1.
func provenStep(k EdgeKind) StepKind {
	switch k {
	case EdgeControl:
		return StepControl
	case EdgeCredential:
		return StepCredential
	}
	return StepEscape
}

// networkArcs returns the usable steps over network or L2 edge e into a node
// with the findings fs (ADR 0011 D10, usable step): a network-vector finding
// whose port the edge allows, or with an unknown port mapping ("possible");
// over an L2 edge (all ports, assumed) also adjacent-vector findings, at
// half value.
func (s *searcher) networkArcs(e Edge, fs []int32) []arc {
	var group []arc
	for _, fi := range fs {
		f := s.findings[fi]
		switch {
		case e.Kind == EdgeL2Adjacency && (f.cvss.av == AVNetwork || f.cvss.av == AVAdjacent):
			group = append(group, arc{finding: fi, kind: StepNetwork, terms: f.terms(true)})
		case e.Kind.Network() && f.cvss.av == AVNetwork:
			switch {
			case len(f.f.Ports) == 0:
				group = append(group, arc{finding: fi, kind: StepNetwork, possible: true, terms: f.terms(false)})
			case f.f.hasPort(e.Proto, e.Port):
				group = append(group, arc{finding: fi, kind: StepNetwork, terms: f.terms(false)})
			}
		}
	}
	return s.bestOf(group)
}

// bestOf orders parallel steps by e (highest first), confirmed before
// possible, then by finding order, and keeps MaxStepsPerGroup of them.
func (s *searcher) bestOf(group []arc) []arc {
	slices.SortStableFunc(group, func(x, y arc) int {
		return cmp.Or(
			cmp.Compare(y.terms.E, x.terms.E),
			compareBool(x.possible, y.possible),
			cmp.Compare(x.finding, y.finding),
		)
	})
	if len(group) > MaxStepsPerGroup {
		group = group[:MaxStepsPerGroup]
	}
	return group
}

func compareBool(x, y bool) int {
	switch {
	case x == y:
		return 0
	case !x:
		return -1
	}
	return 1
}

// better is the total path order: higher likelihood, then fewer arcs, then
// lexicographically smaller arc IDs.
func better(x, y *cand) bool {
	if x.l != y.l {
		return x.l > y.l
	}
	if x.n != y.n {
		return x.n < y.n
	}
	return slices.Compare(x.slice(), y.slice()) < 0
}

// lastState returns the state a search path ends in.
func (s *searcher) lastState(c *cand) int32 {
	if c.n == 0 {
		return s.src
	}
	return s.arcs[c.arcs[c.n-1]].to
}

// visits reports whether c passes through state st.
func (s *searcher) visits(c *cand, st int32) bool {
	if st == s.src {
		return true
	}
	for _, a := range c.slice() {
		if s.arcs[a].to == st {
			return true
		}
	}
	return false
}

// spur returns the best path that starts with root, continues from root's
// last state without the removed arcs there, stays simple (so it avoids
// the root's states), has at most maxArcs arcs and ends at the first state of
// target. It is a hop-bounded Bellman-Ford over the frontier: round r
// extends exactly the paths changed in round r−1, so every path within the
// bound is considered and the result is exact for the order of better.
func (s *searcher) spur(root cand, target int32, removed []int32) (cand, bool) {
	defer s.reset()
	start := s.lastState(&root)
	s.frontier = append(s.frontier[:0], root)
	s.set(start, root)
	for len(s.frontier) > 0 {
		s.next = s.next[:0]
		for i := range s.frontier {
			c := &s.frontier[i]
			u := s.lastState(c)
			if c.n >= maxArcs || (u != s.src && u/2 == target) {
				continue
			}
			afterLocal := c.n > 0 && s.arcs[c.arcs[c.n-1]].kind == StepLocal
			for _, ai := range s.out[u] {
				if u == start && slices.Contains(removed, ai) {
					continue
				}
				a := &s.arcs[ai]
				if (afterLocal && a.kind == StepNetwork) || s.visits(c, a.to) {
					continue
				}
				nc := *c
				nc.arcs[nc.n] = ai
				nc.n++
				if a.from >= 0 {
					nc.l = c.l * a.terms.E
				}
				if s.has[a.to] && !better(&nc, &s.best[a.to]) {
					continue
				}
				s.set(a.to, nc)
				if j := s.nextAt[a.to]; j >= 0 {
					s.next[j] = nc
				} else {
					s.nextAt[a.to] = int32(len(s.next))
					s.next = append(s.next, nc)
				}
			}
		}
		for i := range s.next {
			s.nextAt[s.lastState(&s.next[i])] = -1
		}
		s.frontier, s.next = s.next, s.frontier
	}
	r, o := s.state(target, levelReached), s.state(target, levelOwned)
	switch {
	case s.has[r] && s.has[o]:
		if better(&s.best[o], &s.best[r]) {
			return s.best[o], true
		}
		return s.best[r], true
	case s.has[r]:
		return s.best[r], true
	case s.has[o]:
		return s.best[o], true
	}
	return cand{}, false
}

func (s *searcher) set(st int32, c cand) {
	if !s.has[st] {
		s.has[st] = true
		s.touched = append(s.touched, st)
	}
	s.best[st] = c
}

func (s *searcher) reset() {
	for _, st := range s.touched {
		s.has[st] = false
	}
	s.touched = s.touched[:0]
}

// topPaths runs Yen's k-shortest simple paths from the entries to target,
// by likelihood (equivalently by the sum of −log e), at most MaxDepth
// steps. It returns the paths in order and false if the deadline stopped
// it early.
func (s *searcher) topPaths(target int32, k int) ([]cand, bool) {
	if s.deadline() {
		return nil, false
	}
	first, ok := s.spur(cand{l: 1}, target, nil)
	if !ok {
		return nil, true
	}
	a := []cand{first}
	var b []cand
	seen := map[[maxArcs]int32]bool{first.key(): true}
	for len(a) < k {
		prev := a[len(a)-1]
		for i := 0; i < int(prev.n); i++ {
			if s.deadline() {
				return a, false
			}
			root := cand{n: uint8(i), l: 1}
			copy(root.arcs[:], prev.arcs[:i])
			for _, ai := range root.slice() {
				if s.arcs[ai].from >= 0 {
					root.l *= s.arcs[ai].terms.E
				}
			}
			var removed []int32
			for j := range a {
				if int(a[j].n) > i && slices.Equal(a[j].arcs[:i], root.slice()) {
					removed = append(removed, a[j].arcs[i])
				}
			}
			c, ok := s.spur(root, target, removed)
			if ok && !seen[c.key()] {
				seen[c.key()] = true
				b = append(b, c)
			}
		}
		if len(b) == 0 {
			break
		}
		bi := 0
		for j := 1; j < len(b); j++ {
			if better(&b[j], &b[bi]) {
				bi = j
			}
		}
		a = append(a, b[bi])
		b = slices.Delete(b, bi, bi+1)
	}
	return a, true
}

// key identifies a search path; unused arc slots are -1.
func (c *cand) key() [maxArcs]int32 {
	k := c.arcs
	for i := int(c.n); i < maxArcs; i++ {
		k[i] = -1
	}
	return k
}

// deadlineFunc returns a function reporting whether the budget is spent;
// without a clock the budget is not enforced.
func deadlineFunc(now func() time.Time, budget time.Duration) func() bool {
	if now == nil {
		return func() bool { return false }
	}
	end := now().Add(budget)
	return func() bool { return !now().Before(end) }
}
