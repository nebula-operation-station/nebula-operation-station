// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
)

// addAll offers the nodes and edges of each step, in step order, to a new
// builder. Rejections that the input limits explain (ErrInputLimit, and
// ErrUnknownNode for an edge whose endpoint was dropped) are tolerated;
// anything else fails the test.
func addAll(t *testing.T, steps ...any) *Builder {
	t.Helper()
	b := NewBuilder()
	for _, step := range steps {
		switch s := step.(type) {
		case []Node:
			for _, n := range s {
				if err := b.AddNode(n); err != nil && !errors.Is(err, ErrInputLimit) {
					t.Fatalf("AddNode(%s): %v", n.ID, err)
				}
			}
		case []Edge:
			for _, e := range s {
				if err := b.AddEdge(e); err != nil && !errors.Is(err, ErrInputLimit) && !errors.Is(err, ErrUnknownNode) {
					t.Fatalf("AddEdge(%s -> %s %s): %v", e.From, e.To, e.Kind, err)
				}
			}
		default:
			t.Fatalf("bad step %T", step)
		}
	}
	return b
}

func shuffledCopy[T any](s []T, seed uint64) []T {
	out := slices.Clone(s)
	rand.New(rand.NewPCG(seed, seed)).Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// assertSameGraphs fails for every build whose hash differs from want's.
func assertSameGraphs(t *testing.T, wantName string, builds map[string]*Graph) {
	t.Helper()
	want := builds[wantName]
	for name, g := range builds {
		if g.Hash() != want.Hash() {
			dn, de := g.Dropped()
			wn, we := want.Dropped()
			t.Errorf("%s: hash differs from %s (dropped %d/%d, want %d/%d, edges %d, want %d)",
				name, wantName, dn, de, wn, we, len(g.Edges()), len(want.Edges()))
		}
	}
}

// nodeFloodInputs returns an unmanaged-endpoint flood far above
// MaxInputNodes, an inventory, flood edges (some into endpoints that will be
// dropped) and inventory edges.
func nodeFloodInputs() (flood, inventory []Node, floodEdges, invEdges []Edge) {
	const floodN = MaxInputNodes + 3000
	for i := range floodN {
		flood = append(flood, Node{ID: fmt.Sprintf("unk:%06d", i), Kind: NodeUnmanaged, Label: "flood"})
	}
	add := func(kind NodeKind, prefix string, n int) {
		for i := range n {
			inventory = append(inventory, Node{ID: fmt.Sprintf("%s%04d", prefix, i), Kind: kind, Label: prefix})
		}
	}
	add(NodeHost, "host:", 50)
	add(NodePVENode, "pve:", 3)
	add(NodeGuest, "guest:", 100)
	add(NodeContainer, "ctr:", 200)
	add(NodeNetworkDevice, "dev:", 20)
	// Observed flood edges into low IDs (kept), into IDs cut by MaxNodes
	// (4999, 6000, 19000) and into IDs the input limit drops (19900 once the
	// inventory arrives, the last one always).
	for _, i := range []int{0, 1, 2, 4000, 4999, 6000, 19000, 19900, floodN - 1} {
		floodEdges = append(floodEdges, Edge{From: InternetID, To: fmt.Sprintf("unk:%06d", i), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 22})
	}
	for i := range 100 {
		g := fmt.Sprintf("guest:%04d", i)
		invEdges = append(invEdges,
			Edge{From: "host:0000", To: g, Kind: EdgeCredential},
			Edge{From: fmt.Sprintf("pve:%04d", i%3), To: g, Kind: EdgeControl},
		)
	}
	for i := range 200 {
		c := fmt.Sprintf("ctr:%04d", i)
		h := fmt.Sprintf("host:%04d", i%50)
		invEdges = append(invEdges,
			Edge{From: h, To: c, Kind: EdgeControl},
			Edge{From: c, To: h, Kind: EdgeEscape, Escape: EscapeDockerSocket},
		)
	}
	return flood, inventory, floodEdges, invEdges
}

func TestNodeFloodAddedFirstCannotCrowdOutInventory(t *testing.T) {
	flood, inventory, floodEdges, invEdges := nodeFloodInputs()
	shuffled := shuffledCopy(slices.Concat(flood, inventory), 5)
	reversed := slices.Concat(flood, inventory)
	slices.Reverse(reversed)
	orders := map[string]*Builder{
		// Flood edges are held before the inventory evicts their endpoints.
		"flood first":     addAll(t, flood, floodEdges, inventory, invEdges),
		"inventory first": addAll(t, inventory, invEdges, flood, floodEdges),
		"shuffled":        addAll(t, shuffled, floodEdges, invEdges),
		"reversed":        addAll(t, reversed, invEdges, floodEdges),
		// Re-offering the whole flood must not change the result or counts.
		"flood twice": addAll(t, flood, floodEdges, inventory, invEdges, flood, floodEdges, inventory),
	}
	builds := map[string]*Graph{}
	for name, b := range orders {
		builds[name] = b.Build()
	}
	assertSameGraphs(t, "inventory first", builds)
	g := builds["flood first"]
	for _, n := range inventory {
		if _, ok := g.Node(n.ID); !ok {
			t.Fatalf("flood added first crowded out %s %s", n.Kind, n.ID)
		}
	}
	for _, e := range invEdges {
		if !slices.Contains(g.Out(e.From), e) {
			t.Fatalf("inventory edge %s -> %s %s missing", e.From, e.To, e.Kind)
		}
	}
	// 5,000 kept: 2 entries, 373 inventory nodes, the 4,625 lowest unmanaged.
	kept := MaxNodes - 2 - len(inventory)
	for _, n := range g.Nodes() {
		if n.Kind == NodeUnmanaged && n.ID >= fmt.Sprintf("unk:%06d", kept) {
			t.Fatalf("kept unmanaged %s beyond the cut unk:%06d", n.ID, kept-1)
		}
	}
	if _, ok := g.Node(fmt.Sprintf("unk:%06d", kept-1)); !ok {
		t.Fatalf("unmanaged unk:%06d below the cut was dropped", kept-1)
	}
	dn, de := g.Dropped()
	if wantDN := 2 + len(inventory) + len(flood) - MaxNodes; dn != wantDN {
		t.Fatalf("dropped nodes = %d, want %d (each distinct node once)", dn, wantDN)
	}
	// Flood edges into unk:004999, unk:006000 and unk:019000 are cut with
	// their nodes by MaxNodes; edges into nodes the input limit dropped are
	// not counted in any order (held then evicted with the node, or
	// ErrUnknownNode).
	if de != 3 {
		t.Fatalf("dropped edges = %d, want 3", de)
	}
	if !g.Truncated() {
		t.Fatal("flood exceeded the input limit but graph not truncated")
	}
}

// evictionWithFullPoolInputs returns an unmanaged flood that the inventory
// partly evicts, and observed flood edges among them that overfill the
// observed pool even counting only the edges between surviving nodes.
// low and high split the flood edges at unk:010000.
func evictionWithFullPoolInputs() (flood, inventory []Node, low, high, invEdges []Edge, ports int) {
	const floodN = MaxInputNodes + 3000
	const hosts = 400
	for i := range floodN {
		flood = append(flood, Node{ID: fmt.Sprintf("unk:%06d", i), Kind: NodeUnmanaged})
	}
	for i := range hosts {
		inventory = append(inventory, Node{ID: fmt.Sprintf("host:%04d", i), Kind: NodeHost})
	}
	for i := 1; i < hosts; i++ {
		invEdges = append(invEdges, Edge{From: "host:0000", To: fmt.Sprintf("host:%04d", i), Kind: EdgeCredential})
	}
	// Every 10th flood node gets edges on ports 1..ports; the survivors
	// (unk:000000..unk:019597) alone get 1,960*ports > MaxInputEdgesPerKind.
	// The sources unk:000001..unk:000009 survive and sort before every
	// target, so the canonical order (by source first) would rank edges
	// into evicted nodes early; the keep order must rank by owner.
	ports = MaxInputEdgesPerKind*12/10/(floodN/10) + 1
	for i := 0; i < floodN; i += 10 {
		for p := 1; p <= ports; p++ {
			from := fmt.Sprintf("unk:%06d", 1+p%9)
			e := Edge{From: from, To: fmt.Sprintf("unk:%06d", i), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: uint16(p)}
			if i < 10000 {
				low = append(low, e)
			} else {
				high = append(high, e)
			}
		}
	}
	return flood, inventory, low, high, invEdges, ports
}

// TestNodeEvictionAndFullEdgePoolAreOrderIndependent combines both input
// limits: the inventory evicts flood nodes while the observed edge pool is
// full. In "evict after partial fill" the pool holds edges into nodes that
// are evicted later, eviction frees room, and later edges between
// surviving nodes overfill it again; the result must equal every other
// order.
func TestNodeEvictionAndFullEdgePoolAreOrderIndependent(t *testing.T) {
	flood, inventory, low, high, invEdges, ports := evictionWithFullPoolInputs()
	if len(high) >= MaxInputEdgesPerKind {
		t.Fatalf("fixture: high part %d must fit the pool", len(high))
	}
	all := slices.Concat(low, high)
	reversed := slices.Clone(all)
	slices.Reverse(reversed)
	builds := map[string]*Graph{
		"inventory first":           addAll(t, inventory, invEdges, flood, all).Build(),
		"flood first":               addAll(t, flood, all, inventory, invEdges).Build(),
		"flood edges reversed":      addAll(t, flood, reversed, inventory, invEdges).Build(),
		"evict after partial fill":  addAll(t, flood, high, inventory, low, invEdges).Build(),
		"evict after reversed fill": addAll(t, flood, reversed[:len(high)], inventory, invEdges, reversed[len(high):]).Build(),
		"shuffled":                  addAll(t, shuffledCopy(slices.Concat(flood, inventory), 11), shuffledCopy(slices.Concat(all, invEdges), 12)).Build(),
		"twice":                     addAll(t, flood, high, inventory, low, invEdges, flood, all, inventory).Build(),
	}
	assertSameGraphs(t, "inventory first", builds)

	g := builds["evict after partial fill"]
	if !g.Truncated() {
		t.Fatal("graph not truncated")
	}
	for _, e := range invEdges {
		if !slices.Contains(g.Out(e.From), e) {
			t.Fatalf("credential edge %s -> %s missing", e.From, e.To)
		}
	}
	// MaxNodes keeps 2 entries, 400 hosts and unk:000000..unk:004597: the
	// sampled nodes unk:000000..unk:004590 (460) with all their ports.
	keptUnmanaged := MaxNodes - 2 - len(inventory)
	sampled := (keptUnmanaged + 9) / 10
	if want := len(invEdges) + sampled*ports; len(g.Edges()) != want {
		t.Fatalf("edges = %d, want %d", len(g.Edges()), want)
	}
	// The observed pool is full with the best edges between surviving
	// nodes; what Build does not keep of it is counted, each edge once.
	dn, de := g.Dropped()
	if want := MaxInputEdgesPerKind + len(invEdges) - len(g.Edges()); de != want {
		t.Fatalf("dropped edges = %d, want %d", de, want)
	}
	if want := 2 + len(inventory) + len(flood) - MaxNodes; dn != want {
		t.Fatalf("dropped nodes = %d, want %d", dn, want)
	}
}

func TestNodeInputLimitEvictsLowestRankAndReportsDrops(t *testing.T) {
	b := NewBuilder()
	for i := range MaxInputNodes - 2 {
		mustNode(t, b, Node{ID: fmt.Sprintf("unk:%06d", i), Kind: NodeUnmanaged})
	}
	// Full. A worse node is dropped with ErrInputLimit.
	if err := b.AddNode(Node{ID: "unk:999999", Kind: NodeUnmanaged}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("worse node at limit = %v, want ErrInputLimit", err)
	}
	// Re-offering the same dropped node is ErrInputLimit again, another
	// label under that ID is ErrConflict, another kind is invalid.
	if err := b.AddNode(Node{ID: "unk:999999", Kind: NodeUnmanaged}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("re-offered dropped node = %v, want ErrInputLimit", err)
	}
	if err := b.AddNode(Node{ID: "unk:999999", Kind: NodeUnmanaged, Label: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("dropped ID with other label = %v, want ErrConflict", err)
	}
	if err := b.AddNode(Node{ID: "unk:999999", Kind: NodeHost}); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("dropped ID with other kind = %v, want ErrInvalidNode", err)
	}
	// A managed host is accepted and evicts the highest unmanaged ID together
	// with its edges.
	last := fmt.Sprintf("unk:%06d", MaxInputNodes-3)
	mustEdge(t, b, Edge{From: InternetID, To: last, Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 80})
	mustNode(t, b, Node{ID: "host:zz", Kind: NodeHost})
	if err := b.AddEdge(Edge{From: InternetID, To: last, Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 81}); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("edge to evicted node = %v, want ErrUnknownNode", err)
	}
	if err := b.AddNode(Node{ID: last, Kind: NodeUnmanaged}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("evicted node re-offered = %v, want ErrInputLimit", err)
	}
	g := b.Build()
	if _, ok := g.Node("host:zz"); !ok {
		t.Fatal("managed host added at the input limit was dropped")
	}
	// The cap drops 20,000 held to 5,000; the input limit dropped
	// unk:999999 and the evicted node, each once.
	wantDN := MaxInputNodes - MaxNodes + 2
	if dn, de := g.Dropped(); dn != wantDN || de != 0 {
		t.Fatalf("dropped %d/%d, want %d/0", dn, de, wantDN)
	}
}

// Beyond MaxDroppedNodes the builder remembers the best-ranked drops, so
// the count is the same in any order and repeats never inflate it.
func TestForgottenDropsAreNotCountedTwice(t *testing.T) {
	const n = MaxInputNodes + MaxDroppedNodes + 500
	var nodes []Node
	for i := range n {
		nodes = append(nodes, Node{ID: fmt.Sprintf("unk:%06d", i), Kind: NodeUnmanaged})
	}
	builds := map[string]*Graph{
		"ascending": addAll(t, nodes).Build(),
		"shuffled":  addAll(t, shuffledCopy(nodes, 3)).Build(),
		"repeated":  addAll(t, shuffledCopy(nodes, 4), nodes, shuffledCopy(nodes, 5)).Build(),
	}
	assertSameGraphs(t, "ascending", builds)
	if dn, _ := builds["repeated"].Dropped(); dn != MaxDroppedNodes+MaxInputNodes-MaxNodes {
		t.Fatalf("dropped nodes = %d, want %d (a lower bound, never inflated)", dn, MaxDroppedNodes+MaxInputNodes-MaxNodes)
	}
}

// edgeFloodInputs returns one tier per edge kind so that the input limit and
// the edge cap both cut inside a known tier.
func edgeFloodInputs() (nodes []Node, tiers [][]Edge) {
	const hosts = 500
	for i := range hosts {
		nodes = append(nodes, Node{ID: fmt.Sprintf("host:%03d", i), Kind: NodeHost})
	}
	nodes = append(nodes,
		Node{ID: "pve:1", Kind: NodePVENode},
		Node{ID: "guest:1", Kind: NodeGuest},
		Node{ID: "ctr:1", Kind: NodeContainer},
	)
	var assumed, observed, policy, proven []Edge
	for i := 0; len(assumed) < 120000; i++ {
		from, to := i/hosts, i%hosts
		if from == to {
			continue
		}
		assumed = append(assumed, Edge{From: fmt.Sprintf("host:%03d", from), To: fmt.Sprintf("host:%03d", to), Kind: EdgeL2Adjacency})
	}
	for i := range 60000 {
		observed = append(observed, Edge{From: InternetID, To: fmt.Sprintf("host:%03d", i%hosts), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: uint16(1 + i/hosts)})
	}
	for i := range 40000 {
		policy = append(policy, Edge{From: NetBirdID, To: fmt.Sprintf("host:%03d", i%hosts), Kind: EdgeNetworkPolicy, Proto: ProtoUDP, Port: uint16(1 + i/hosts)})
	}
	proven = []Edge{
		{From: "host:499", To: "pve:1", Kind: EdgeCredential},
		{From: "host:499", To: "guest:1", Kind: EdgeCredential},
		{From: "pve:1", To: "guest:1", Kind: EdgeControl},
		{From: "guest:1", To: "ctr:1", Kind: EdgeControl},
		{From: "ctr:1", To: "guest:1", Kind: EdgeEscape, Escape: EscapePrivileged},
	}
	// Lowest rank first: the flood order.
	return nodes, [][]Edge{assumed, observed, policy, proven}
}

func TestEdgeFloodAddedFirstCannotCrowdOutProvenEdges(t *testing.T) {
	nodes, tiers := edgeFloodInputs()
	floodFirst := slices.Concat(tiers...)
	provenFirst := slices.Concat(tiers[3], tiers[2], tiers[1], tiers[0])
	builds := map[string]*Graph{
		"flood first":  addAll(t, nodes, floodFirst).Build(),
		"proven first": addAll(t, nodes, provenFirst).Build(),
		"shuffled":     addAll(t, nodes, shuffledCopy(floodFirst, 9)).Build(),
		"flood twice":  addAll(t, nodes, floodFirst, tiers[0], tiers[1]).Build(),
	}
	assertSameGraphs(t, "proven first", builds)

	g := builds["flood first"]
	if len(g.Edges()) != MaxEdges || !g.Truncated() {
		t.Fatalf("edges %d truncated %v, want %d and true", len(g.Edges()), g.Truncated(), MaxEdges)
	}
	count := map[EdgeKind]int{}
	for _, e := range g.Edges() {
		count[e.Kind]++
	}
	// Kept by kind: all 5 proven, all 40,000 policy, then the 9,995 lowest
	// observed edges; no assumed edge survives.
	wantCount := map[EdgeKind]int{
		EdgeCredential: 2, EdgeControl: 2, EdgeEscape: 1,
		EdgeNetworkPolicy: 40000, EdgeNetworkObserved: MaxEdges - 40005,
	}
	for k := EdgeNetworkPolicy; k <= EdgeCredential; k++ {
		if count[k] != wantCount[k] {
			t.Errorf("kept %s = %d, want %d", k, count[k], wantCount[k])
		}
	}
	// Observed edges all leave internet, so their owner is the target and
	// the keep order is the canonical order.
	observed := slices.Clone(tiers[1])
	slices.SortFunc(observed, compareEdges)
	for _, e := range observed[:wantCount[EdgeNetworkObserved]] {
		if !slices.Contains(g.Out(e.From), e) {
			t.Fatalf("observed edge %s -> %s %d below the cut was dropped", e.From, e.To, e.Port)
		}
	}
	for _, e := range tiers[3] {
		if !slices.Contains(g.Out(e.From), e) {
			t.Fatalf("proven edge %s -> %s %s missing", e.From, e.To, e.Kind)
		}
	}
	// Each distinct edge held is counted once; the 120,000 assumed edges
	// overfill their pool, so only MaxInputEdgesPerKind of them are known.
	total := 0
	for _, tier := range tiers {
		total += min(len(tier), MaxInputEdgesPerKind)
	}
	if dn, de := g.Dropped(); dn != 0 || de != total-MaxEdges {
		t.Fatalf("dropped %d/%d, want 0/%d (each distinct edge once)", dn, de, total-MaxEdges)
	}
}

func TestEdgeInputLimitEvictsLowestRank(t *testing.T) {
	nodes, tiers := edgeFloodInputs()
	b := addAll(t, nodes)
	for _, e := range tiers[0][:MaxInputEdgesPerKind] {
		mustEdge(t, b, e)
	}
	// The assumed pool is full. A worse edge is dropped, every time.
	worse := Edge{From: "host:499", To: "host:498", Kind: EdgeL2Adjacency}
	for range 2 {
		if err := b.AddEdge(worse); !errors.Is(err, ErrInputLimit) {
			t.Fatalf("worse edge at limit = %v, want ErrInputLimit", err)
		}
	}
	// A better one is accepted and evicts the pool's last edge.
	better := Edge{From: "host:300", To: "host:301", Kind: EdgeL2Adjacency}
	mustEdge(t, b, better)
	// Edges of other kinds have their own pools: all are accepted.
	for _, e := range slices.Concat(tiers[1], tiers[2], tiers[3]) {
		mustEdge(t, b, e)
	}
	// Merging escape reasons into a held escape edge still works.
	mustEdge(t, b, Edge{From: "ctr:1", To: "guest:1", Kind: EdgeEscape, Escape: EscapeFindingNote})
	g := b.Build()
	if out := g.Out("ctr:1"); len(out) != 1 || out[0].Escape != EscapePrivileged|EscapeFindingNote {
		t.Fatalf("escape edge = %+v", out)
	}
	for _, e := range tiers[3] {
		if e.Kind != EdgeEscape && !slices.Contains(g.Out(e.From), e) {
			t.Fatalf("proven edge %s -> %s %s missing", e.From, e.To, e.Kind)
		}
	}
	// Everything held beyond the edge cap is counted once; the worse edge
	// and the evicted one were never held at the end.
	held := MaxInputEdgesPerKind + len(tiers[1]) + len(tiers[2]) + len(tiers[3])
	if _, de := g.Dropped(); de != held-MaxEdges {
		t.Fatalf("dropped edges = %d, want %d", de, held-MaxEdges)
	}
}
