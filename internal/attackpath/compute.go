// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Computation limits (ADR 0011 D10).
const (
	// MaxTargets is the most crown-jewel targets one computation searches.
	// Beyond it the targets with the highest impact (then lowest node ID)
	// are kept and the result is truncated.
	MaxTargets = 50
	// MaxChokePoints is the most choke-point candidates one computation
	// returns, highest summed risk first; beyond it the result is truncated.
	MaxChokePoints = 500
	// DefaultBudget is the wall-clock budget of one computation.
	DefaultBudget = 60 * time.Second
	// MinImpact and MaxImpact bound a target's impact weight.
	MinImpact = 1
	// MaxImpact is the highest impact weight.
	MaxImpact = 10
)

// pathHashDomain separates path hashes from other SHA-256 uses.
const pathHashDomain = "nos/attackpath/path/v1\n"

// ErrInvalidTarget reports a target with a bad node ID or impact, an entry
// node as target, or a node named twice.
var ErrInvalidTarget = errors.New("invalid target")

// Target is a crown jewel with its impact weight 1–10.
type Target struct {
	// Node is the ID of the target node.
	Node string
	// Impact is the maintainer's impact weight, MinImpact..MaxImpact.
	Impact int
}

// Options configure one computation.
type Options struct {
	// Now is the clock for the wall-clock budget. Nil disables the budget,
	// which keeps the computation a pure function of its inputs.
	Now func() time.Time
	// Budget is the wall-clock budget; zero means DefaultBudget.
	Budget time.Duration
}

// Step is one step of a path, with everything that explains its e.
type Step struct {
	// Kind classifies the step.
	Kind StepKind
	// From and To are node IDs; equal for a local step.
	From, To string
	// Edge is the edge the step follows; zero for a local step.
	Edge Edge
	// Finding is the key of the finding exploited on To; empty for
	// control, credential and escape steps.
	Finding string
	// Possible is set when the finding's port mapping is unknown, so the
	// step may not be usable (ADR 0011 D10).
	Possible bool
	// Terms explains e(step).
	Terms Terms
}

// Path is one attack path from an entry to a target.
type Path struct {
	// Hash identifies the steps (not the scores) of the path.
	Hash string
	// Entry is the entry node ID (internet or netbird).
	Entry string
	// Steps are the steps in order.
	Steps []Step
	// Likelihood is L(path), the product of e over the steps.
	Likelihood float64
	// Risk is R(path) = L(path) × impact(target).
	Risk float64
	// Possible is set when any step is possible.
	Possible bool
	// Assumed is set when any step follows an assumed edge.
	Assumed bool
}

// TargetPaths are the top paths to one target.
type TargetPaths struct {
	// Node is the target node ID.
	Node string
	// Impact is the target's impact weight.
	Impact int
	// Paths are the top paths, highest likelihood first.
	Paths []Path
	// Complete is false when the budget stopped the search for this target
	// before it finished; its paths are then a prefix at best.
	Complete bool
}

// FixKind classifies a choke-point candidate.
type FixKind uint8

// Fix kinds (ADR 0011 D10, choke points).
const (
	// FixFinding fixes one finding on one subject.
	FixFinding FixKind = iota + 1
	// FixEdge removes one network edge by a rule change.
	FixEdge
)

// String returns "finding", "edge" or "invalid".
func (k FixKind) String() string {
	switch k {
	case FixFinding:
		return "finding"
	case FixEdge:
		return "edge"
	}
	return "invalid"
}

// ChokePoint is one candidate fix with the risk it removes from the top
// paths.
type ChokePoint struct {
	// Kind says whether a finding is fixed or an edge removed.
	Kind FixKind
	// Node and Finding name the finding of a FixFinding.
	Node, Finding string
	// Edge is the edge of a FixEdge.
	Edge Edge
	// Risk is the sum of R over the top paths the fix cuts.
	Risk float64
	// Paths is the number of top paths the fix cuts.
	Paths int
}

// Limits says which limit truncated a result.
type Limits struct {
	// Graph: the graph itself was truncated by its node or edge caps.
	Graph bool
	// Findings: more than MaxFindings findings were given.
	Findings bool
	// Targets: more than MaxTargets targets were given.
	Targets bool
	// ChokePoints: more than MaxChokePoints candidates were found.
	ChokePoints bool
	// Budget: the wall-clock budget stopped the search.
	Budget bool
}

// Result is the outcome of one computation. With equal graph, findings,
// targets and FormulaVersion, and no budget hit, it is equal, whatever the
// input order.
type Result struct {
	// FormulaVersion is the score formula, FormulaVersion.
	FormulaVersion string
	// GraphHash is the snapshot hash of the graph.
	GraphHash string
	// Targets are ordered by impact (highest first), then node ID.
	Targets []TargetPaths
	// ChokePoints are ordered by risk removed, then paths cut, findings
	// before edges, then by identity.
	ChokePoints []ChokePoint
	// Truncated is set when any limit was hit; see Limits.
	Truncated bool
	// Limits says which limits were hit.
	Limits Limits
	// MissingTargets are target node IDs not in the graph, sorted.
	MissingTargets []string
	// UnscoredFindings counts findings without a CVSS v3 vector; they are
	// uncertainty, not safety.
	UnscoredFindings int
	// UnattachedFindings counts findings on nodes not in the graph.
	UnattachedFindings int
}

// Compute scores the top attack paths to each target with ap-v1 and ranks
// choke points (ADR 0011 D10). It is deterministic: findings and targets
// are put into canonical order first. Structurally invalid findings or
// targets are an error naming the field, never the value.
func Compute(g *Graph, findings []Finding, targets []Target, opt Options) (*Result, error) {
	if g == nil {
		return nil, errors.New("compute attack paths: nil graph")
	}
	res := &Result{
		FormulaVersion: FormulaVersion,
		GraphHash:      g.Hash(),
		Limits:         Limits{Graph: g.Truncated()},
	}
	usable, err := prepareFindings(g, findings, res)
	if err != nil {
		return nil, fmt.Errorf("compute attack paths: %w", err)
	}
	tg, err := prepareTargets(g, targets, res)
	if err != nil {
		return nil, fmt.Errorf("compute attack paths: %w", err)
	}
	budget := opt.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	s := newSearcher(g, usable)
	s.deadline = deadlineFunc(opt.Now, budget)
	for _, t := range tg {
		tp := TargetPaths{Node: t.Node, Impact: t.Impact}
		if !res.Limits.Budget {
			var cands []cand
			cands, tp.Complete = s.topPaths(int32(g.index[t.Node]), PathsPerTarget)
			res.Limits.Budget = !tp.Complete
			for i := range cands {
				tp.Paths = append(tp.Paths, s.path(&cands[i], t.Impact))
			}
		}
		res.Targets = append(res.Targets, tp)
	}
	res.ChokePoints, res.Limits.ChokePoints = chokePoints(res.Targets)
	l := res.Limits
	res.Truncated = l.Graph || l.Findings || l.Targets || l.ChokePoints || l.Budget
	return res, nil
}

// prepareFindings validates findings, counts unscored and unattached ones,
// drops false positives and physical-vector findings (never usable) and
// returns the rest in canonical order, capped at MaxFindings by e.
func prepareFindings(g *Graph, findings []Finding, res *Result) ([]scoredFinding, error) {
	type id struct{ node, key string }
	seen := make(map[id]bool, len(findings))
	var out []scoredFinding
	for _, f := range findings {
		if err := validateFinding(f); err != nil {
			return nil, err
		}
		if seen[id{f.Node, f.Key}] {
			return nil, fmt.Errorf("finding %s on %s: duplicate: %w", f.Key, f.Node, ErrInvalidFinding)
		}
		seen[id{f.Node, f.Key}] = true
		if _, ok := g.index[f.Node]; !ok {
			res.UnattachedFindings++
			continue
		}
		c, ok := parseCVSS3(f.Vector)
		if !ok {
			res.UnscoredFindings++
			continue
		}
		if f.State == FindingFalsePositive || c.av == AVPhysical {
			continue
		}
		f.Ports = slices.Clone(f.Ports)
		out = append(out, scoredFinding{f: f, cvss: c, base: baseE(f.KEV, f.EPSS, f.EPSSKnown, c.x)})
	}
	if len(out) > MaxFindings {
		slices.SortFunc(out, func(x, y scoredFinding) int {
			return cmp.Or(cmp.Compare(y.base, x.base), compareFindings(x, y))
		})
		out = out[:MaxFindings]
		res.Limits.Findings = true
	}
	slices.SortFunc(out, compareFindings)
	return out, nil
}

func compareFindings(x, y scoredFinding) int {
	return cmp.Or(cmp.Compare(x.f.Node, y.f.Node), cmp.Compare(x.f.Key, y.f.Key))
}

// prepareTargets validates targets, records those missing from the graph
// and returns the rest by impact (highest first) and node ID, capped at
// MaxTargets.
func prepareTargets(g *Graph, targets []Target, res *Result) ([]Target, error) {
	seen := make(map[string]bool, len(targets))
	var out []Target
	for _, t := range targets {
		if !validID(t.Node) {
			return nil, fmt.Errorf("target node: %w", ErrInvalidTarget)
		}
		if t.Impact < MinImpact || t.Impact > MaxImpact {
			return nil, fmt.Errorf("target %s impact: %w", t.Node, ErrInvalidTarget)
		}
		if seen[t.Node] {
			return nil, fmt.Errorf("target %s: duplicate: %w", t.Node, ErrInvalidTarget)
		}
		seen[t.Node] = true
		n, ok := g.Node(t.Node)
		if !ok {
			if t.Node == InternetID || t.Node == NetBirdID {
				return nil, fmt.Errorf("target %s: entry: %w", t.Node, ErrInvalidTarget)
			}
			res.MissingTargets = append(res.MissingTargets, t.Node)
			continue
		}
		if n.Kind.Entry() {
			return nil, fmt.Errorf("target %s: entry: %w", t.Node, ErrInvalidTarget)
		}
		out = append(out, t)
	}
	slices.Sort(res.MissingTargets)
	slices.SortFunc(out, func(x, y Target) int {
		return cmp.Or(cmp.Compare(y.Impact, x.Impact), cmp.Compare(x.Node, y.Node))
	})
	if len(out) > MaxTargets {
		out = out[:MaxTargets]
		res.Limits.Targets = true
	}
	return out, nil
}

// path renders a search path; L is recomputed left to right over the steps.
func (s *searcher) path(c *cand, impact int) Path {
	p := Path{Likelihood: 1}
	for _, ai := range c.slice() {
		a := s.arcs[ai]
		if a.from < 0 {
			p.Entry = s.g.nodes[a.to/2].ID
			continue
		}
		st := Step{
			Kind:     a.kind,
			From:     s.g.nodes[a.from].ID,
			To:       s.g.nodes[a.to/2].ID,
			Possible: a.possible,
			Terms:    a.terms,
		}
		if a.edge >= 0 {
			st.Edge = s.g.edges[a.edge]
		}
		if a.finding >= 0 {
			st.Finding = s.findings[a.finding].f.Key
		}
		p.Steps = append(p.Steps, st)
		p.Likelihood *= a.terms.E
		p.Possible = p.Possible || a.possible
		p.Assumed = p.Assumed || a.terms.Assumed
	}
	p.Risk = p.Likelihood * float64(impact)
	p.Hash = pathHash(p.Entry, p.Steps)
	return p
}

type hashStep struct {
	Kind    string `json:"kind"`
	From    string `json:"from"`
	To      string `json:"to"`
	Edge    string `json:"edge,omitempty"`
	Proto   string `json:"proto,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Finding string `json:"finding,omitempty"`
}

// pathHash is the hex SHA-256 of the domain-tagged canonical encoding of the
// path's entry and step identities.
func pathHash(entry string, steps []Step) string {
	hs := make([]hashStep, len(steps))
	for i, st := range steps {
		hs[i] = hashStep{Kind: st.Kind.String(), From: st.From, To: st.To, Finding: st.Finding}
		if st.Kind != StepLocal {
			hs[i].Edge, hs[i].Proto, hs[i].Port = st.Edge.Kind.String(), st.Edge.Proto.String(), st.Edge.Port
		}
	}
	b, err := json.Marshal(struct {
		Entry string     `json:"entry"`
		Steps []hashStep `json:"steps"`
	}{entry, hs})
	if err != nil {
		// Only strings and ints: Marshal cannot fail.
		return ""
	}
	h := sha256.New()
	h.Write([]byte(pathHashDomain))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// chokePoints sums R per candidate fix over the top paths it cuts: every
// finding a step exploits and every network or L2 edge a step follows. It
// returns at most MaxChokePoints candidates and whether more existed.
func chokePoints(targets []TargetPaths) ([]ChokePoint, bool) {
	type fixKey struct {
		kind      FixKind
		node, key string
		edge      edgeKey
	}
	idx := map[fixKey]int{}
	var out []ChokePoint
	for _, t := range targets {
		for _, p := range t.Paths {
			cut := map[fixKey]bool{}
			for _, st := range p.Steps {
				var keys []fixKey
				if st.Finding != "" {
					keys = append(keys, fixKey{kind: FixFinding, node: st.To, key: st.Finding})
				}
				if st.Kind == StepNetwork {
					keys = append(keys, fixKey{kind: FixEdge, edge: st.Edge.key()})
				}
				for _, k := range keys {
					if cut[k] {
						continue
					}
					cut[k] = true
					i, ok := idx[k]
					if !ok {
						i = len(out)
						idx[k] = i
						cp := ChokePoint{Kind: k.kind, Node: k.node, Finding: k.key}
						if k.kind == FixEdge {
							cp.Edge = st.Edge
						}
						out = append(out, cp)
					}
					out[i].Risk += p.Risk
					out[i].Paths++
				}
			}
		}
	}
	slices.SortFunc(out, func(x, y ChokePoint) int {
		return cmp.Or(
			cmp.Compare(y.Risk, x.Risk),
			cmp.Compare(y.Paths, x.Paths),
			cmp.Compare(x.Kind, y.Kind),
			cmp.Compare(x.Node, y.Node),
			cmp.Compare(x.Finding, y.Finding),
			compareEdges(x.Edge, y.Edge),
		)
	})
	if len(out) > MaxChokePoints {
		return out[:MaxChokePoints], true
	}
	return out, false
}
