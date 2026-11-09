// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sources holds the attack-path data adapters of ADR 0011 D10
// (VU-22): one adapter per data source, each reading its store through a
// narrow read-only interface and returning a Result of attackpath nodes and
// edges together with what it could not see.
//
// Adapters that exist today:
//
//   - Flows: observed network edges from the traffic map (ADR 0009,
//     internal/trafficstore, read-only).
//   - Placements: PVE node → guest control edges (ADR 0006).
//   - Docker: Docker host → container control edges and container → host
//     escape edges proven by docker.inspect.
//   - Credentials: executor host → every managed host.
//
// Firewall/NAT policy and VLAN adjacency need ADR 0010 network-device data
// and are stubs that report the source as unknown (FirewallPolicy,
// VLANAdjacency).
//
// Uncertainty is explicit. A store that cannot be read, an unmanaged
// endpoint, a managed address without observed flows, a top-N cut in the
// flow query, a partial dataset or a missing source never reads as "no
// edge": it becomes an Uncertainty and lowers the coverage figure, so
// "no path found" with low coverage reads "unknown", never "safe".
//
// Everything read from a store may originate on a managed host and is
// untrusted: node IDs are built only from validated parts, labels are
// bounded UTF-8 text or empty, and uncertainty records name node IDs and
// fixed kinds, never raw values. Every adapter bounds its output by the
// VU-20 input caps of the attackpath Builder.
package sources

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
)

// Limits enforced by this package.
const (
	// MaxResultNodes bounds the nodes one adapter returns; it is the input
	// cap of the attackpath Builder.
	MaxResultNodes = attackpath.MaxInputNodes
	// MaxResultEdges bounds the edges one adapter returns; it is the
	// per-kind input cap of the attackpath Builder.
	MaxResultEdges = attackpath.MaxInputEdgesPerKind
	// MaxUncertainties bounds the uncertainty records one adapter returns
	// and Merge keeps; the rest are counted in Overflow.
	MaxUncertainties = 10000
)

// Source names, stable for snapshots and the UI.
const (
	SourceFlows       = "flows"
	SourcePlacements  = "placements"
	SourceDocker      = "docker"
	SourceCredentials = "credentials"
	SourceFirewall    = "firewall"
	SourceVLAN        = "vlan"
)

// requiredSources are the data sources ADR 0011 D10 builds the graph from,
// sorted. A merge without any of them is never complete.
var requiredSources = []string{
	SourceCredentials,
	SourceDocker,
	SourceFirewall,
	SourceFlows,
	SourcePlacements,
	SourceVLAN,
}

// RequiredSources returns the names of the sources every complete merge
// needs (ADR 0011 D10), sorted. A source that does not exist yet (firewall,
// VLAN) is still required: its stub reports it unknown.
func RequiredSources() []string { return slices.Clone(requiredSources) }

// ErrSourceUnavailable is wrapped by adapter errors when the store could not
// be read; the Result then has StatusUnknown.
var ErrSourceUnavailable = errors.New("attack-path source unavailable")

// ErrRejectedInput is returned (wrapped) by Merge when the Builder refused
// adapter output as invalid; Report.Rejected counts the inputs.
var ErrRejectedInput = errors.New("attack-path source input rejected")

// Status says how much of a source an adapter saw.
type Status uint8

// Statuses. The zero value is invalid and treated as StatusUnknown.
const (
	// StatusComplete: everything the source holds was read.
	StatusComplete Status = iota + 1
	// StatusPartial: some of the source was read; Uncertain says what not.
	StatusPartial
	// StatusUnknown: nothing usable was read, or the source does not exist
	// yet. No edge of this source may be read as "no edge".
	StatusUnknown
)

// String returns the stable name of s.
func (s Status) String() string {
	switch s {
	case StatusComplete:
		return "complete"
	case StatusPartial:
		return "partial"
	}
	return "unknown"
}

// UncertaintyKind classifies one uncertainty record.
type UncertaintyKind uint8

// Uncertainty kinds.
const (
	// UncertainSourceUnavailable: the store could not be read.
	UncertainSourceUnavailable UncertaintyKind = iota + 1
	// UncertainSourceMissing: the data source does not exist yet (ADR 0010
	// device data).
	UncertainSourceMissing
	// UncertainUnmanagedEndpoint: a flow end without an inventory entry.
	UncertainUnmanagedEndpoint
	// UncertainNoFlows: a managed address with no observed flow in the
	// window; its reachability is unknown, not absent.
	UncertainNoFlows
	// UncertainFlowsIncomplete: a managed address hit the top-N cut of the
	// flow query; flows below the cut are unknown.
	UncertainFlowsIncomplete
	// UncertainAmbiguousAddress: one address is claimed by several nodes;
	// its flows cannot be attributed.
	UncertainAmbiguousAddress
	// UncertainPartialData: a dataset was partial, unavailable or stale.
	UncertainPartialData
	// UncertainPlacementUnknown: a guest whose PVE node is not known.
	UncertainPlacementUnknown
	// UncertainEscapeUnverified: a container whose escape conditions could
	// not be fully read (docker.inspect does not report "privileged").
	UncertainEscapeUnverified
	// UncertainExecutorUnassigned: the executor host is not set or not in
	// the inventory.
	UncertainExecutorUnassigned
	// UncertainInvalidRecord: a record failed validation and was skipped.
	UncertainInvalidRecord
	// UncertainTruncated: a read or output limit was reached.
	UncertainTruncated
	// UncertainAliasConflict: a managed host is linked to several guests.
	UncertainAliasConflict
)

var uncertaintyNames = [...]string{
	UncertainSourceUnavailable:  "source_unavailable",
	UncertainSourceMissing:      "source_missing",
	UncertainUnmanagedEndpoint:  "unmanaged_endpoint",
	UncertainNoFlows:            "no_flows_observed",
	UncertainFlowsIncomplete:    "flows_incomplete",
	UncertainAmbiguousAddress:   "ambiguous_address",
	UncertainPartialData:        "partial_data",
	UncertainPlacementUnknown:   "placement_unknown",
	UncertainEscapeUnverified:   "escape_unverified",
	UncertainExecutorUnassigned: "executor_unassigned",
	UncertainInvalidRecord:      "invalid_record",
	UncertainTruncated:          "truncated",
	UncertainAliasConflict:      "alias_conflict",
}

// String returns the stable name of k, or "invalid".
func (k UncertaintyKind) String() string {
	if k >= UncertainSourceUnavailable && k <= UncertainAliasConflict {
		return uncertaintyNames[k]
	}
	return "invalid"
}

// Uncertainty is one thing an adapter could not see. Subject is a validated
// node ID, or empty when the record concerns the whole source or a record
// whose identity could not be validated.
type Uncertainty struct {
	Source  string
	Kind    UncertaintyKind
	Subject string
}

// String renders u as "source kind subject".
func (u Uncertainty) String() string {
	if u.Subject == "" {
		return u.Source + " " + u.Kind.String()
	}
	return u.Source + " " + u.Kind.String() + " " + u.Subject
}

func compareUncertainty(x, y Uncertainty) int {
	return cmp.Or(cmp.Compare(x.Source, y.Source), cmp.Compare(x.Kind, y.Kind), cmp.Compare(x.Subject, y.Subject))
}

// Coverage counts the units a source should cover and the units it covered
// without uncertainty. The unit is per source (managed addresses, PVE
// remotes, Docker hosts, managed hosts).
type Coverage struct {
	Covered, Total int
}

// Result is what one adapter read.
type Result struct {
	// Source is one of the Source* names.
	Source string
	// Status says how much of the source was read.
	Status Status
	// Nodes and Edges are the graph input, at most MaxResultNodes and
	// MaxResultEdges.
	Nodes []attackpath.Node
	Edges []attackpath.Edge
	// Aliases maps a managed host node ID ("host:<id>") to the node that
	// represents the same machine (a linked PVE guest), so one machine is
	// one node across all sources.
	Aliases map[string]string
	// Uncertain lists what the adapter could not see, sorted, at most
	// MaxUncertainties; Overflow counts the records beyond.
	Uncertain []Uncertainty
	Overflow  int
	// Coverage is the adapter's coverage figure.
	Coverage Coverage
}

// collector accumulates one adapter's Result within the caps.
type collector struct {
	r         Result
	nodes     map[string]struct{}
	edges     map[attackpath.Edge]struct{}
	seenU     map[Uncertainty]struct{}
	truncated bool
}

func newCollector(source string) *collector {
	return &collector{
		r:     Result{Source: source, Status: StatusComplete},
		nodes: map[string]struct{}{},
		edges: map[attackpath.Edge]struct{}{},
		seenU: map[Uncertainty]struct{}{},
	}
}

// node adds n once; it reports false when the node cap is reached.
func (c *collector) node(n attackpath.Node) bool {
	if _, ok := c.nodes[n.ID]; ok {
		return true
	}
	if len(c.nodes) >= MaxResultNodes {
		c.truncated = true
		return false
	}
	c.nodes[n.ID] = struct{}{}
	c.r.Nodes = append(c.r.Nodes, n)
	return true
}

// edge adds e once; endpoints must have been added.
func (c *collector) edge(e attackpath.Edge) {
	if _, ok := c.edges[e]; ok {
		return
	}
	if len(c.edges) >= MaxResultEdges {
		c.truncated = true
		return
	}
	c.edges[e] = struct{}{}
	c.r.Edges = append(c.r.Edges, e)
}

func (c *collector) uncertain(kind UncertaintyKind, subject string) {
	u := Uncertainty{Source: c.r.Source, Kind: kind, Subject: subject}
	if _, ok := c.seenU[u]; ok {
		return
	}
	if len(c.seenU) >= MaxUncertainties {
		c.r.Overflow++
		return
	}
	c.seenU[u] = struct{}{}
	c.r.Uncertain = append(c.r.Uncertain, u)
}

// partial lowers the status to partial unless it is already unknown.
func (c *collector) partial() {
	if c.r.Status == StatusComplete {
		c.r.Status = StatusPartial
	}
}

// unavailable marks the whole source unknown and drops what was read: a
// half-read source must not look like a smaller complete one.
func (c *collector) unavailable() {
	c.r.Status = StatusUnknown
	c.r.Nodes, c.r.Edges, c.r.Aliases = nil, nil, nil
	c.r.Coverage.Covered = 0
	c.uncertain(UncertainSourceUnavailable, "")
}

func (c *collector) result() Result {
	if c.truncated {
		c.partial()
		c.uncertain(UncertainTruncated, "")
	}
	if c.r.Status != StatusComplete && c.r.Status != StatusPartial {
		c.r.Status = StatusUnknown
	}
	slices.SortFunc(c.r.Nodes, func(x, y attackpath.Node) int { return cmp.Compare(x.ID, y.ID) })
	slices.SortFunc(c.r.Edges, compareEdge)
	slices.SortFunc(c.r.Uncertain, compareUncertainty)
	return c.r
}

func compareEdge(x, y attackpath.Edge) int {
	return cmp.Or(
		cmp.Compare(x.From, y.From),
		cmp.Compare(x.To, y.To),
		cmp.Compare(x.Kind, y.Kind),
		cmp.Compare(x.Proto, y.Proto),
		cmp.Compare(x.Port, y.Port),
	)
}

// nodeID returns prefix+part if the result is a valid attackpath node ID
// (printable ASCII [A-Za-z0-9._:/@-], longer than prefix, at most
// attackpath.MaxIDBytes), mirroring the Builder's rules so an adapter can
// report a bad record instead of losing it silently.
func nodeID(prefix string, parts ...string) (string, bool) {
	id := prefix + strings.Join(parts, "/")
	if len(id) <= len(prefix) || len(id) > attackpath.MaxIDBytes {
		return "", false
	}
	for _, p := range parts {
		if p == "" {
			return "", false
		}
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == ':', c == '/', c == '@', c == '-':
		default:
			return "", false
		}
	}
	return id, true
}

// label returns s if it is a valid attackpath label (bounded UTF-8, no
// control or bidi characters except tab), else "". Untrusted names that do
// not pass are not repaired, only dropped.
func label(s string) string {
	if len(s) > attackpath.MaxLabelBytes || !utf8.ValidString(s) {
		return ""
	}
	for _, r := range s {
		if r == '\t' {
			continue
		}
		if unicode.IsControl(r) || r == 0x061c || r == 0x200e || r == 0x200f ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return ""
		}
	}
	return s
}

// SourceReport is one source's status and coverage within a Report.
type SourceReport struct {
	Source   string
	Status   Status
	Coverage Coverage
}

// Report is what Merge did: per-source status, the union of uncertainty and
// the overall coverage figure.
type Report struct {
	Sources []SourceReport
	// Missing names the required sources (RequiredSources) no result was
	// merged for, sorted; each is also an UncertainSourceMissing record.
	Missing   []string
	Uncertain []Uncertainty
	Overflow  int
	// Rejected counts nodes and edges the Builder refused as invalid.
	Rejected int
	// InputLimited counts inputs the Builder dropped or evicted at its
	// input caps, and edges lost with them; the graph is then marked
	// truncated.
	InputLimited int
}

// Coverage returns the overall coverage figure: the sum of all sources'
// covered and total units, where a source with StatusUnknown and no units
// and a missing required source each count as one uncovered unit, so a
// missing source always lowers it.
func (r Report) Coverage() Coverage {
	c := Coverage{Total: len(r.Missing)}
	for _, s := range r.Sources {
		if s.Status == StatusUnknown && s.Coverage.Total == 0 {
			c.Total++
			continue
		}
		c.Covered += s.Coverage.Covered
		c.Total += s.Coverage.Total
	}
	return c
}

// Complete reports whether every required source was merged and read
// completely, nothing is uncertain and the Builder neither rejected nor
// dropped any input. Only then may "no path found" read as "no path".
func (r Report) Complete() bool {
	if len(r.Missing) > 0 || len(r.Uncertain) > 0 || r.Overflow > 0 ||
		r.Rejected > 0 || r.InputLimited > 0 || len(r.Sources) == 0 {
		return false
	}
	for _, s := range r.Sources {
		if s.Status != StatusComplete {
			return false
		}
	}
	return true
}

// Merge adds the results to b. Aliases of every result are applied to the
// nodes and edges of all results first, so a managed host linked to a PVE
// guest is one node. A host linked to several targets is not aliased and is
// reported as UncertainAliasConflict. Builder conflicts (same ID, other
// label) are resolved by the Builder and not counted; invalid inputs are
// counted in Rejected and input-limit drops and evictions in InputLimited.
// A required source without a result is listed in Missing and reported as
// UncertainSourceMissing.
//
// b must be fresh from attackpath.NewBuilder: Merge counts the nodes the
// Builder evicts at its input cap from what it offered, which is exact only
// when nothing else is held.
func Merge(b *attackpath.Builder, results ...Result) (Report, error) {
	if b == nil {
		return Report{}, errors.New("merge attack-path sources: nil builder")
	}
	if g := b.Build(); len(g.Nodes()) != len(entryIDs) || len(g.Edges()) != 0 || g.Truncated() {
		return Report{}, errors.New("merge attack-path sources: builder not fresh")
	}
	var rep Report
	uncertain := map[Uncertainty]struct{}{}
	addU := func(u Uncertainty) {
		if _, ok := uncertain[u]; ok {
			return
		}
		if len(uncertain) >= MaxUncertainties {
			rep.Overflow++
			return
		}
		uncertain[u] = struct{}{}
		rep.Uncertain = append(rep.Uncertain, u)
	}

	known := map[string]bool{}
	for _, r := range results {
		for _, n := range r.Nodes {
			known[n.ID] = true
		}
	}
	alias := map[string]string{}
	conflict := map[string]bool{}
	for _, r := range results {
		for from, to := range r.Aliases {
			if !strings.HasPrefix(from, "host:") || !known[to] {
				continue
			}
			if old, ok := alias[from]; ok && old != to {
				conflict[from] = true
			}
			alias[from] = to
		}
	}
	for _, from := range slices.Sorted(maps.Keys(conflict)) {
		delete(alias, from)
		addU(Uncertainty{Source: SourcePlacements, Kind: UncertainAliasConflict, Subject: from})
	}
	resolve := func(id string) string {
		if to, ok := alias[id]; ok {
			return to
		}
		return id
	}

	// A node offered by several sources keeps a non-empty label: a source
	// that only knows the ID (Docker hosts, flow owners without a name)
	// must not blank the inventory's label. Among non-empty labels the
	// Builder's rule (first in sort order) decides.
	nodes := map[string]attackpath.Node{}
	present := map[string]bool{}
	for _, r := range results {
		present[r.Source] = true
		rep.Sources = append(rep.Sources, SourceReport{Source: r.Source, Status: r.Status, Coverage: r.Coverage})
		for _, u := range r.Uncertain {
			u.Subject = resolve(u.Subject)
			addU(u)
		}
		rep.Overflow += r.Overflow
		for _, n := range r.Nodes {
			if _, aliased := alias[n.ID]; aliased {
				continue
			}
			old, seen := nodes[n.ID]
			if !seen || old.Label == "" || (n.Label != "" && n.Label < old.Label) {
				nodes[n.ID] = n
			}
		}
	}
	for _, s := range requiredSources {
		if !present[s] {
			rep.Missing = append(rep.Missing, s)
			addU(Uncertainty{Source: s, Kind: UncertainSourceMissing})
		}
	}

	// valid holds the offered nodes the Builder accepted as valid, whether
	// it holds them, dropped them or later evicted them at its input cap.
	valid := map[string]bool{}
	accepted := 0
	for _, id := range slices.Sorted(maps.Keys(nodes)) {
		switch err := b.AddNode(nodes[id]); {
		case err == nil:
			valid[id] = true
			accepted++
		case errors.Is(err, attackpath.ErrConflict):
			valid[id] = true // already held: the label rule decided
		case errors.Is(err, attackpath.ErrInputLimit):
			valid[id] = true
			rep.InputLimited++
		default:
			rep.Rejected++
		}
	}
	// Each node accepted beyond the input cap evicted one held node
	// without an error (b was fresh, holding only the entries).
	rep.InputLimited += max(0, len(entryIDs)+accepted-attackpath.MaxInputNodes)

	for _, r := range results {
		for _, e := range r.Edges {
			e.From, e.To = resolve(e.From), resolve(e.To)
			if e.From == e.To {
				continue
			}
			switch err := b.AddEdge(e); {
			case err == nil:
			case errors.Is(err, attackpath.ErrInputLimit),
				errors.Is(err, attackpath.ErrUnknownNode) && validEnd(valid, e.From) && validEnd(valid, e.To):
				// An edge between valid nodes that is unknown to the
				// Builder lost an endpoint to the input cap: the same
				// truncation, not a rejection.
				rep.InputLimited++
			default:
				rep.Rejected++
			}
		}
	}
	slices.SortFunc(rep.Sources, func(x, y SourceReport) int { return cmp.Compare(x.Source, y.Source) })
	slices.SortFunc(rep.Uncertain, compareUncertainty)
	if rep.Rejected > 0 {
		return rep, fmt.Errorf("merge attack-path sources: %d inputs: %w", rep.Rejected, ErrRejectedInput)
	}
	return rep, nil
}

// entryIDs are the synthetic entry nodes every Builder holds from the start.
var entryIDs = []string{attackpath.InternetID, attackpath.NetBirdID}

// validEnd reports whether id is an entry or an offered node the Builder
// accepted as valid.
func validEnd(valid map[string]bool, id string) bool {
	return valid[id] || slices.Contains(entryIDs, id)
}
