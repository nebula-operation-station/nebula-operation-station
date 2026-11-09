// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

// SnapshotVersion names the snapshot encoding. It changes whenever the
// encoding or the build rules change, so equal hashes mean equal graphs
// under equal rules.
const SnapshotVersion = "attackpath-graph-v1"

// hashDomain separates graph snapshot hashes from other SHA-256 uses.
const hashDomain = "nos/attackpath/graph-snapshot/v1\n"

// Graph is an immutable, bounded attack-path graph. Accessors return copies.
type Graph struct {
	nodes        []Node // sorted by ID
	edges        []Edge // canonical order (compareEdges)
	index        map[string]int
	out          [][]int // per node index: indices into edges
	droppedNodes int
	droppedEdges int
}

// Nodes returns the nodes sorted by ID.
func (g *Graph) Nodes() []Node { return slices.Clone(g.nodes) }

// Edges returns the edges sorted by from, to, kind, proto, port.
func (g *Graph) Edges() []Edge { return slices.Clone(g.edges) }

// Node returns the node with the given ID.
func (g *Graph) Node(id string) (Node, bool) {
	i, ok := g.index[id]
	if !ok {
		return Node{}, false
	}
	return g.nodes[i], true
}

// Out returns the edges leaving id in canonical order; nil for an unknown
// node.
func (g *Graph) Out(id string) []Edge {
	i, ok := g.index[id]
	if !ok {
		return nil
	}
	out := make([]Edge, len(g.out[i]))
	for j, ei := range g.out[i] {
		out[j] = g.edges[ei]
	}
	return out
}

// Truncated reports whether any node or edge was dropped by a cap or an
// input limit. A truncated graph must be presented as incomplete.
func (g *Graph) Truncated() bool { return g.droppedNodes > 0 || g.droppedEdges > 0 }

// Dropped returns how many nodes and edges were dropped.
func (g *Graph) Dropped() (nodes, edges int) { return g.droppedNodes, g.droppedEdges }

type snapNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
}

type snapEdge struct {
	From    string   `json:"from"`
	To      string   `json:"to"`
	Kind    string   `json:"kind"`
	Basis   string   `json:"basis"`
	Assumed bool     `json:"assumed"`
	Proto   string   `json:"proto,omitempty"`
	Port    uint16   `json:"port,omitempty"`
	Escape  []string `json:"escape,omitempty"`
}

type snapshot struct {
	Version      string     `json:"version"`
	Nodes        []snapNode `json:"nodes"`
	Edges        []snapEdge `json:"edges"`
	Truncated    bool       `json:"truncated"`
	DroppedNodes int        `json:"dropped_nodes"`
	DroppedEdges int        `json:"dropped_edges"`
}

// Snapshot returns the canonical compact JSON encoding of g. It is the input
// of Hash and depends only on the graph contents, never on input order.
func (g *Graph) Snapshot() []byte {
	s := snapshot{
		Version:      SnapshotVersion,
		Nodes:        make([]snapNode, len(g.nodes)),
		Edges:        make([]snapEdge, len(g.edges)),
		Truncated:    g.Truncated(),
		DroppedNodes: g.droppedNodes,
		DroppedEdges: g.droppedEdges,
	}
	for i, n := range g.nodes {
		s.Nodes[i] = snapNode{ID: n.ID, Kind: n.Kind.String(), Label: n.Label}
	}
	for i, e := range g.edges {
		s.Edges[i] = snapEdge{
			From:    e.From,
			To:      e.To,
			Kind:    e.Kind.String(),
			Basis:   e.Kind.Basis().String(),
			Assumed: e.Assumed(),
			Proto:   e.Proto.String(),
			Port:    e.Port,
			Escape:  e.Escape.names(),
		}
	}
	b, err := json.Marshal(s)
	if err != nil {
		// Only strings, bools, ints and slices of them: Marshal cannot
		// fail. Return an empty snapshot rather than panic.
		return nil
	}
	return b
}

// Hash returns the hex SHA-256 of the domain-tagged snapshot: the "graph
// snapshot hash" of ADR 0011 D10.
func (g *Graph) Hash() string {
	h := sha256.New()
	h.Write([]byte(hashDomain))
	h.Write(g.Snapshot())
	return hex.EncodeToString(h.Sum(nil))
}
