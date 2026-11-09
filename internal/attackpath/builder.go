// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
)

// Builder collects nodes and edges, validates each on entry and builds an
// immutable Graph. The result does not depend on insertion order: Build
// sorts its input and applies the caps deterministically. A Builder is not
// safe for concurrent use.
type Builder struct {
	nodes        map[string]Node
	edges        map[edgeKey]Edge
	droppedNodes int
	droppedEdges int
}

// NewBuilder returns a builder that already holds the synthetic entry nodes
// internet and netbird.
func NewBuilder() *Builder {
	return &Builder{
		nodes: map[string]Node{
			InternetID: {ID: InternetID, Kind: NodeInternet, Label: "Internet"},
			NetBirdID:  {ID: NetBirdID, Kind: NodeNetBird, Label: "NetBird peers"},
		},
		edges: map[edgeKey]Edge{},
	}
}

// AddNode adds n. Adding an identical node again is a no-op; the same ID
// with another kind or label is ErrConflict. Synthetic entry kinds and IDs
// are ErrReservedNode. Once MaxInputNodes distinct nodes are held, new nodes
// are dropped with ErrInputLimit and the graph will be marked truncated.
func (b *Builder) AddNode(n Node) error {
	if err := validateNode(n); err != nil {
		return fmt.Errorf("add node: %w", err)
	}
	if old, ok := b.nodes[n.ID]; ok {
		if old != n {
			return fmt.Errorf("add node %s: %w", n.ID, ErrConflict)
		}
		return nil
	}
	if len(b.nodes) >= MaxInputNodes {
		b.droppedNodes++
		return fmt.Errorf("add node %s: %w", n.ID, ErrInputLimit)
	}
	b.nodes[n.ID] = n
	return nil
}

// AddEdge adds e. Both endpoints must have been added; the edge must follow
// the rules of its kind (see Edge and EdgeKind). Adding the same edge again
// is a no-op, except that escape reasons of the same escape edge are merged.
// Once MaxInputEdges distinct edges are held, new edges are dropped with
// ErrInputLimit and the graph will be marked truncated.
func (b *Builder) AddEdge(e Edge) error {
	from, ok := b.nodes[e.From]
	if !ok {
		return fmt.Errorf("add edge: from: %w", ErrUnknownNode)
	}
	to, ok := b.nodes[e.To]
	if !ok {
		return fmt.Errorf("add edge: to: %w", ErrUnknownNode)
	}
	if err := validateEdge(e, from.Kind, to.Kind); err != nil {
		return fmt.Errorf("add edge: %w", err)
	}
	k := e.key()
	if old, ok := b.edges[k]; ok {
		old.Escape |= e.Escape
		b.edges[k] = old
		return nil
	}
	if len(b.edges) >= MaxInputEdges {
		b.droppedEdges++
		return fmt.Errorf("add edge %s -> %s: %w", e.From, e.To, ErrInputLimit)
	}
	b.edges[k] = e
	return nil
}

// Build returns the graph. If more than MaxNodes nodes are held, nodes are
// kept by kind (entries, network devices, PVE nodes, hosts, guests,
// containers, unmanaged endpoints) and then by ID; edges touching a dropped
// node are dropped. If more than MaxEdges edges remain, edges are kept by
// kind (credential, control, escape, policy, observed, assumed) and then by
// (from, to, proto, port). Any drop, including inputs rejected with
// ErrInputLimit, marks the graph truncated. The builder stays usable.
func (b *Builder) Build() *Graph {
	nodes := slices.Collect(maps.Values(b.nodes))
	slices.SortFunc(nodes, func(x, y Node) int {
		return cmp.Or(cmp.Compare(keepRank[x.Kind], keepRank[y.Kind]), cmp.Compare(x.ID, y.ID))
	})
	droppedNodes := b.droppedNodes
	if len(nodes) > MaxNodes {
		droppedNodes += len(nodes) - MaxNodes
		nodes = nodes[:MaxNodes]
	}
	slices.SortFunc(nodes, func(x, y Node) int { return cmp.Compare(x.ID, y.ID) })
	index := make(map[string]int, len(nodes))
	for i, n := range nodes {
		index[n.ID] = i
	}

	droppedEdges := b.droppedEdges
	edges := make([]Edge, 0, min(len(b.edges), MaxEdges))
	for _, e := range b.edges {
		_, okFrom := index[e.From]
		_, okTo := index[e.To]
		if !okFrom || !okTo {
			droppedEdges++
			continue
		}
		edges = append(edges, e)
	}
	if len(edges) > MaxEdges {
		slices.SortFunc(edges, func(x, y Edge) int {
			return cmp.Or(cmp.Compare(edgeKeepRank[x.Kind], edgeKeepRank[y.Kind]), compareEdges(x, y))
		})
		droppedEdges += len(edges) - MaxEdges
		edges = edges[:MaxEdges]
	}
	slices.SortFunc(edges, compareEdges)

	out := make([][]int, len(nodes))
	for i, e := range edges {
		f := index[e.From]
		out[f] = append(out[f], i)
	}
	return &Graph{
		nodes:        slices.Clip(nodes),
		edges:        slices.Clip(edges),
		index:        index,
		out:          out,
		droppedNodes: droppedNodes,
		droppedEdges: droppedEdges,
	}
}

// compareEdges is the canonical edge order: from, to, kind, proto, port.
func compareEdges(x, y Edge) int {
	return cmp.Or(
		cmp.Compare(x.From, y.From),
		cmp.Compare(x.To, y.To),
		cmp.Compare(x.Kind, y.Kind),
		cmp.Compare(x.Proto, y.Proto),
		cmp.Compare(x.Port, y.Port),
	)
}
