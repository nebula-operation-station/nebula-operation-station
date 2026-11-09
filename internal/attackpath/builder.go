// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
)

// Builder collects nodes and edges, validates each on entry and builds an
// immutable Graph. A Builder is not safe for concurrent use.
//
// The input limits are rank-aware: once MaxInputNodes nodes (MaxInputEdges
// edges) are held, a new input is kept only if it ranks before the input
// kept last, which is then evicted. Ranks are the ones Build truncates by
// (see Build), so input added first, hostile or not, can never crowd out a
// node or edge of a better rank: unmanaged endpoints never displace managed
// hosts, and observed or assumed edges never displace credential, control
// or escape edges.
//
// The result does not depend on insertion order: the held nodes are always
// the best MaxInputNodes of all distinct nodes offered, and while no node
// has been evicted the held edges are the best MaxInputEdges of all distinct
// valid edges offered. Each distinct input dropped by a limit is counted
// once, however often it is offered again (up to MaxInputNodes and
// MaxInputEdges remembered drops; beyond that, counts are lower bounds).
// Two limits of a bounded builder remain: an edge into a node the input
// limit has dropped is ErrUnknownNode and is not counted, in any order; and
// an edge dropped by the edge limit is not restored by itself when a later
// node eviction frees room, only when it is offered again.
type Builder struct {
	nodes     map[string]Node
	nodeOrder *keepHeap[string]
	edges     map[edgeKey]Edge
	edgeOrder *keepHeap[edgeKey]
	// edgesOf indexes each held (true) and each remembered dropped (false)
	// edge under its endpoint kept last. The node input limit always evicts
	// the node kept last, so it evicts that endpoint before the other one
	// and finds every edge touching it here.
	edgesOf map[string]map[edgeKey]bool
	// droppedNodeSet remembers nodes dropped by the input limit, so a
	// repeat is not counted again and other contents are ErrConflict.
	droppedNodeSet map[string]Node
	// droppedEdgeMarks counts the false entries in edgesOf.
	droppedEdgeMarks int
	// untrackedNodes and untrackedEdges count drops beyond the remembered
	// ones.
	untrackedNodes int
	untrackedEdges int
}

// NewBuilder returns a builder that already holds the synthetic entry nodes
// internet and netbird.
func NewBuilder() *Builder {
	b := &Builder{
		nodes:          map[string]Node{},
		edges:          map[edgeKey]Edge{},
		edgeOrder:      newKeepHeap(compareKeepEdges),
		edgesOf:        map[string]map[edgeKey]bool{},
		droppedNodeSet: map[string]Node{},
	}
	b.nodeOrder = newKeepHeap(func(x, y string) int { return compareKeepNodes(b.nodes[x], b.nodes[y]) })
	b.hold(Node{ID: InternetID, Kind: NodeInternet, Label: "Internet"})
	b.hold(Node{ID: NetBirdID, Kind: NodeNetBird, Label: "NetBird peers"})
	return b
}

// AddNode adds n. Adding an identical node again is a no-op; the same ID
// with another kind or label is ErrConflict. Synthetic entry kinds and IDs
// are ErrReservedNode. Once MaxInputNodes nodes are held, n is kept only if
// it ranks before the node kept last, which is evicted together with its
// edges; otherwise n is dropped with ErrInputLimit. Either way the graph
// will be marked truncated.
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
	if old, ok := b.droppedNodeSet[n.ID]; ok {
		if old != n {
			return fmt.Errorf("add node %s: %w", n.ID, ErrConflict)
		}
		return fmt.Errorf("add node %s: %w", n.ID, ErrInputLimit)
	}
	if len(b.nodes) >= MaxInputNodes {
		lastID, ok := b.nodeOrder.last()
		if !ok || compareKeepNodes(n, b.nodes[lastID]) > 0 {
			b.recordDroppedNode(n)
			return fmt.Errorf("add node %s: %w", n.ID, ErrInputLimit)
		}
		b.evictNode(lastID)
	}
	b.hold(n)
	return nil
}

func (b *Builder) hold(n Node) {
	b.nodes[n.ID] = n
	b.nodeOrder.add(n.ID)
}

// evictNode drops the held node kept last and every edge touching it. Its
// held edges are not counted as dropped and its remembered dropped edges
// are forgotten: had the node never been held, they would have been
// ErrUnknownNode, so the counts stay independent of insertion order.
func (b *Builder) evictNode(id string) {
	n := b.nodes[id]
	b.nodeOrder.remove(id)
	delete(b.nodes, id)
	for k, held := range b.edgesOf[id] {
		if held {
			b.edgeOrder.remove(k)
			delete(b.edges, k)
		} else {
			b.droppedEdgeMarks--
		}
	}
	delete(b.edgesOf, id)
	b.recordDroppedNode(n)
}

func (b *Builder) recordDroppedNode(n Node) {
	if len(b.droppedNodeSet) < MaxInputNodes {
		b.droppedNodeSet[n.ID] = n
		return
	}
	b.untrackedNodes++
}

// AddEdge adds e. Both endpoints must be held; the edge must follow the
// rules of its kind (see Edge and EdgeKind). Adding the same edge again is a
// no-op, except that escape reasons of the same escape edge are merged.
// Once MaxInputEdges edges are held, e is kept only if it ranks before the
// edge kept last, which is evicted; otherwise e is dropped with
// ErrInputLimit. Either way the graph will be marked truncated.
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
	owner := lastEndpoint(from, to)
	held, remembered := b.edgesOf[owner][k]
	if remembered && held {
		old := b.edges[k]
		old.Escape |= e.Escape
		b.edges[k] = old
		return nil
	}
	if len(b.edges) >= MaxInputEdges {
		lastKey, ok := b.edgeOrder.last()
		if !ok || compareKeepEdges(k, lastKey) > 0 {
			if !remembered {
				b.recordDroppedEdge(owner, k)
			}
			return fmt.Errorf("add edge %s -> %s: %w", e.From, e.To, ErrInputLimit)
		}
		b.evictEdge(lastKey)
	}
	if remembered {
		// A dropped edge offered again fits now: it is no longer dropped.
		b.droppedEdgeMarks--
	}
	b.edges[k] = e
	b.edgeOrder.add(k)
	if b.edgesOf[owner] == nil {
		b.edgesOf[owner] = map[edgeKey]bool{}
	}
	b.edgesOf[owner][k] = true
	return nil
}

// evictEdge drops the held edge k.
func (b *Builder) evictEdge(k edgeKey) {
	b.edgeOrder.remove(k)
	delete(b.edges, k)
	b.recordDroppedEdge(lastEndpoint(b.nodes[k.from], b.nodes[k.to]), k)
}

func (b *Builder) recordDroppedEdge(owner string, k edgeKey) {
	set := b.edgesOf[owner]
	if b.droppedEdgeMarks < MaxInputEdges {
		if set == nil {
			set = map[edgeKey]bool{}
			b.edgesOf[owner] = set
		}
		set[k] = false
		b.droppedEdgeMarks++
		return
	}
	delete(set, k)
	b.untrackedEdges++
}

// lastEndpoint returns the ID of whichever of x and y is kept last.
func lastEndpoint(x, y Node) string {
	if compareKeepNodes(x, y) > 0 {
		return x.ID
	}
	return y.ID
}

// Build returns the graph. If more than MaxNodes nodes are held, nodes are
// kept by kind (entries, network devices, PVE nodes, hosts, guests,
// containers, unmanaged endpoints) and then by ID; edges touching a dropped
// node are dropped. If more than MaxEdges edges remain, edges are kept by
// kind (credential, control, escape, policy, observed, assumed) and then by
// (from, to, proto, port). Any drop, including inputs dropped by an input
// limit, marks the graph truncated. The builder stays usable.
func (b *Builder) Build() *Graph {
	nodes := slices.Collect(maps.Values(b.nodes))
	slices.SortFunc(nodes, compareKeepNodes)
	droppedNodes := len(b.droppedNodeSet) + b.untrackedNodes
	if len(nodes) > MaxNodes {
		droppedNodes += len(nodes) - MaxNodes
		nodes = nodes[:MaxNodes]
	}
	slices.SortFunc(nodes, func(x, y Node) int { return cmp.Compare(x.ID, y.ID) })
	index := make(map[string]int, len(nodes))
	for i, n := range nodes {
		index[n.ID] = i
	}

	droppedEdges := b.droppedEdgeMarks + b.untrackedEdges
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
		slices.SortFunc(edges, func(x, y Edge) int { return compareKeepEdges(x.key(), y.key()) })
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

// compareKeepNodes is the node keep order shared by the input limit and
// MaxNodes: by kind rank, then by ID.
func compareKeepNodes(x, y Node) int {
	return cmp.Or(cmp.Compare(keepRank[x.Kind], keepRank[y.Kind]), cmp.Compare(x.ID, y.ID))
}

// compareKeepEdges is the edge keep order shared by the input limit and
// MaxEdges: by kind rank, then canonically.
func compareKeepEdges(x, y edgeKey) int {
	return cmp.Or(cmp.Compare(edgeKeepRank[x.kind], edgeKeepRank[y.kind]), compareKeys(x, y))
}

// compareEdges is the canonical edge order: from, to, kind, proto, port.
func compareEdges(x, y Edge) int { return compareKeys(x.key(), y.key()) }

func compareKeys(x, y edgeKey) int {
	return cmp.Or(
		cmp.Compare(x.from, y.from),
		cmp.Compare(x.to, y.to),
		cmp.Compare(x.kind, y.kind),
		cmp.Compare(x.proto, y.proto),
		cmp.Compare(x.port, y.port),
	)
}
