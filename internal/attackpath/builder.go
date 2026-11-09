// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"cmp"
	"fmt"
	"slices"
)

// Builder collects nodes and edges, validates each on entry and builds an
// immutable Graph. A Builder is not safe for concurrent use.
//
// The input limits are rank-aware. Nodes are ranked by kind, then ID (the
// order Build truncates by); once MaxInputNodes nodes are held, a new node
// is kept only if it ranks before the node kept last, which is evicted
// together with its edges. Unmanaged endpoints therefore never displace
// managed hosts, and since a node ID is bound to its kind (IDPrefix), no
// node can take the ID of a node of another kind.
//
// Edges are held in one pool per kind, so observed or assumed edges never
// displace credential, control or escape edges. Within a pool an edge
// ranks by its endpoint kept last (its owner), then canonically; once a
// pool holds MaxInputEdgesPerKind edges, a new edge is kept only if it
// ranks before the pool's edge kept last, which is then forgotten. Node
// eviction always evicts the node kept last, so the edges it removes rank
// after every other edge of their pool: an edge the pool limit forgot can
// never come back into the top of its pool, because nothing that ranked
// before it is ever removed.
//
// The result does not depend on insertion order, provided each edge is
// offered after its endpoints: the held nodes are the best MaxInputNodes of
// all distinct nodes offered, and each pool holds the best
// MaxInputEdgesPerKind edges of its kind among all distinct edges offered
// between held nodes. An edge into a node the input limit has dropped is
// ErrUnknownNode and not counted, in any order. Drop counts come from what
// the builder remembers (the best MaxDroppedNodes dropped nodes, the pooled
// edges Build does not keep), so a repeated input is never counted twice;
// beyond those bounds counts are order-independent lower bounds.
type Builder struct {
	nodes     map[string]Node
	nodeOrder *keepHeap[string]
	// dropped remembers the best MaxDroppedNodes nodes dropped by the
	// input limit.
	dropped      map[string]Node
	droppedOrder *keepHeap[string]
	pools        [EdgeCredential + 1]*edgePool
	// owned indexes each pooled edge under its owner, the endpoint kept
	// last. Evicting a node finds every edge touching it here: it is the
	// node kept last, so it owns each of its edges.
	owned map[string]map[edgeKey]struct{}
}

// edgePool holds the edges of one kind.
type edgePool struct {
	entries map[edgeKey]poolEntry
	order   *keepHeap[edgeKey]
}

type poolEntry struct {
	edge  Edge
	owner Node
}

// NewBuilder returns a builder that already holds the synthetic entry nodes
// internet and netbird.
func NewBuilder() *Builder {
	b := &Builder{
		nodes:   map[string]Node{},
		dropped: map[string]Node{},
		owned:   map[string]map[edgeKey]struct{}{},
	}
	b.nodeOrder = newKeepHeap(func(x, y string) int { return compareKeepNodes(b.nodes[x], b.nodes[y]) })
	b.droppedOrder = newKeepHeap(func(x, y string) int { return compareKeepNodes(b.dropped[x], b.dropped[y]) })
	for k := EdgeNetworkPolicy; k <= EdgeCredential; k++ {
		p := &edgePool{entries: map[edgeKey]poolEntry{}}
		p.order = newKeepHeap(func(x, y edgeKey) int { return compareEntries(p.entries[x], p.entries[y]) })
		b.pools[k] = p
	}
	b.hold(Node{ID: InternetID, Kind: NodeInternet, Label: "Internet"})
	b.hold(Node{ID: NetBirdID, Kind: NodeNetBird, Label: "NetBird peers"})
	return b
}

// AddNode adds n. Adding an identical node again is a no-op; the same ID
// with another label is ErrConflict and the label that sorts first is
// kept. Synthetic entry kinds and IDs are ErrReservedNode; an ID outside
// the namespace of its kind is ErrInvalidNode. Once MaxInputNodes nodes are
// held, n is kept only if it ranks before the node kept last, which is
// evicted together with its edges; otherwise n is dropped with
// ErrInputLimit. Either way the graph will be marked truncated.
func (b *Builder) AddNode(n Node) error {
	if err := validateNode(n); err != nil {
		return fmt.Errorf("add node: %w", err)
	}
	if old, ok := b.nodes[n.ID]; ok {
		return mergeLabel(b.nodes, old, n, nil)
	}
	if old, ok := b.dropped[n.ID]; ok {
		return mergeLabel(b.dropped, old, n, ErrInputLimit)
	}
	if len(b.nodes) >= MaxInputNodes {
		lastID, ok := b.nodeOrder.last()
		if !ok || compareKeepNodes(n, b.nodes[lastID]) > 0 {
			b.rememberDropped(n)
			return fmt.Errorf("add node %s: %w", n.ID, ErrInputLimit)
		}
		b.evictNode(lastID)
	}
	b.hold(n)
	return nil
}

// mergeLabel resolves a repeated node ID: the label that sorts first wins,
// so the result is the same in any order. Kind and ID, and with them the
// rank, are equal (the ID is bound to the kind), so no heap is affected.
// It returns ErrConflict for another label, else same (nil for a held node,
// ErrInputLimit for a dropped one).
func mergeLabel(set map[string]Node, old, n Node, same error) error {
	if old.Label == n.Label {
		if same != nil {
			return fmt.Errorf("add node %s: %w", n.ID, same)
		}
		return nil
	}
	if n.Label < old.Label {
		set[n.ID] = n
	}
	return fmt.Errorf("add node %s: %w", n.ID, ErrConflict)
}

func (b *Builder) hold(n Node) {
	b.nodes[n.ID] = n
	b.nodeOrder.add(n.ID)
}

// evictNode drops the held node kept last and forgets every edge touching
// it, uncounted: had the node never been held, they would have been
// ErrUnknownNode, so the counts stay independent of insertion order.
func (b *Builder) evictNode(id string) {
	for k := range b.owned[id] {
		p := b.pools[k.kind]
		p.order.remove(k)
		delete(p.entries, k)
	}
	delete(b.owned, id)
	n := b.nodes[id]
	b.nodeOrder.remove(id)
	delete(b.nodes, id)
	b.rememberDropped(n)
}

// rememberDropped records n as dropped if it is among the best
// MaxDroppedNodes dropped nodes; the worst remembered one is forgotten to
// make room. A node once forgotten ranks after everything remembered from
// then on, so it is never remembered or counted again.
func (b *Builder) rememberDropped(n Node) {
	if len(b.dropped) >= MaxDroppedNodes {
		worst, ok := b.droppedOrder.last()
		if !ok || compareKeepNodes(n, b.dropped[worst]) > 0 {
			return
		}
		b.droppedOrder.remove(worst)
		delete(b.dropped, worst)
	}
	b.dropped[n.ID] = n
	b.droppedOrder.add(n.ID)
}

// AddEdge adds e. Both endpoints must be held; the edge must follow the
// rules of its kind (see Edge and EdgeKind). Adding the same edge again is a
// no-op, except that escape reasons of the same escape edge are merged.
// Once MaxInputEdgesPerKind edges of e's kind are held, e is kept only if it
// ranks before the edge of that kind kept last, which is forgotten;
// otherwise e is dropped with ErrInputLimit. Either way the graph will be
// marked truncated.
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
	p := b.pools[e.Kind]
	if old, ok := p.entries[k]; ok {
		old.edge.Escape |= e.Escape
		p.entries[k] = old
		return nil
	}
	entry := poolEntry{edge: e, owner: from}
	if compareKeepNodes(to, from) > 0 {
		entry.owner = to
	}
	if len(p.entries) >= MaxInputEdgesPerKind {
		lastKey, ok := p.order.last()
		if !ok || compareEntries(entry, p.entries[lastKey]) > 0 {
			return fmt.Errorf("add edge %s -> %s: %w", e.From, e.To, ErrInputLimit)
		}
		b.forgetEdge(p, lastKey)
	}
	p.entries[k] = entry
	p.order.add(k)
	set := b.owned[entry.owner.ID]
	if set == nil {
		set = map[edgeKey]struct{}{}
		b.owned[entry.owner.ID] = set
	}
	set[k] = struct{}{}
	return nil
}

// forgetEdge removes the pooled edge k from p.
func (b *Builder) forgetEdge(p *edgePool, k edgeKey) {
	owner := p.entries[k].owner.ID
	p.order.remove(k)
	delete(p.entries, k)
	delete(b.owned[owner], k)
	if len(b.owned[owner]) == 0 {
		delete(b.owned, owner)
	}
}

// Build returns the graph. If more than MaxNodes nodes are held, nodes are
// kept by kind (entries, network devices, PVE nodes, hosts, guests,
// containers, unmanaged endpoints) and then by ID; edges touching a dropped
// node are dropped. If more than MaxEdges edges remain, edges are kept by
// kind (credential, control, escape, policy, observed, assumed), then by
// their endpoint kept last and then by (from, to, proto, port). Any drop,
// including inputs dropped by an input limit, marks the graph truncated.
// The builder stays usable.
func (b *Builder) Build() *Graph {
	nodes := make([]Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		nodes = append(nodes, n)
	}
	slices.SortFunc(nodes, compareKeepNodes)
	droppedNodes := len(b.dropped)
	if len(nodes) > MaxNodes {
		droppedNodes += len(nodes) - MaxNodes
		nodes = nodes[:MaxNodes]
	}
	slices.SortFunc(nodes, func(x, y Node) int { return cmp.Compare(x.ID, y.ID) })
	index := make(map[string]int, len(nodes))
	for i, n := range nodes {
		index[n.ID] = i
	}

	pooled := 0
	var kept []poolEntry
	for _, p := range b.pools[EdgeNetworkPolicy:] {
		pooled += len(p.entries)
		for _, en := range p.entries {
			_, okFrom := index[en.edge.From]
			_, okTo := index[en.edge.To]
			if okFrom && okTo {
				kept = append(kept, en)
			}
		}
	}
	if len(kept) > MaxEdges {
		slices.SortFunc(kept, compareEntries)
		kept = kept[:MaxEdges]
	}
	edges := make([]Edge, len(kept))
	for i, en := range kept {
		edges[i] = en.edge
	}
	slices.SortFunc(edges, compareEdges)

	out := make([][]int, len(nodes))
	for i, e := range edges {
		f := index[e.From]
		out[f] = append(out[f], i)
	}
	return &Graph{
		nodes:        slices.Clip(nodes),
		edges:        edges,
		index:        index,
		out:          out,
		droppedNodes: droppedNodes,
		droppedEdges: pooled - len(edges),
	}
}

// compareKeepNodes is the node keep order shared by the input limit and
// MaxNodes: by kind rank, then by ID.
func compareKeepNodes(x, y Node) int {
	return cmp.Or(cmp.Compare(keepRank[x.Kind], keepRank[y.Kind]), cmp.Compare(x.ID, y.ID))
}

// compareEntries is the edge keep order shared by the input limit and
// MaxEdges: by kind rank, then by owner in node keep order, then
// canonically. Ranking by owner before anything else within a kind is what
// makes node eviction remove only the last edges of each pool.
func compareEntries(x, y poolEntry) int {
	return cmp.Or(
		cmp.Compare(edgeKeepRank[x.edge.Kind], edgeKeepRank[y.edge.Kind]),
		compareKeepNodes(x.owner, y.owner),
		compareKeys(x.edge.key(), y.edge.key()),
	)
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
