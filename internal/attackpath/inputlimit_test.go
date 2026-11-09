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

// nodeFloodInputs returns an unmanaged-endpoint flood far above
// MaxInputNodes, an inventory, flood edges (some into endpoints that will be
// dropped) and inventory edges.
func nodeFloodInputs() (flood, inventory []Node, floodEdges, invEdges []Edge) {
	const floodN = MaxInputNodes + 3000
	for i := range floodN {
		flood = append(flood, Node{ID: fmt.Sprintf("u%06d", i), Kind: NodeUnmanaged, Label: "flood"})
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
		floodEdges = append(floodEdges, Edge{From: InternetID, To: fmt.Sprintf("u%06d", i), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 22})
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
	cat := func(parts ...[]Node) []Node { return slices.Concat(parts...) }
	shuffled := cat(flood, inventory)
	rand.New(rand.NewPCG(5, 5)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	reversed := cat(flood, inventory)
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
	want := orders["inventory first"].Build()
	for name, b := range orders {
		g := b.Build()
		if g.Hash() != want.Hash() {
			dn, de := g.Dropped()
			wn, we := want.Dropped()
			t.Errorf("%s: hash differs from inventory first (dropped %d/%d, want %d/%d)", name, dn, de, wn, we)
		}
	}
	g := orders["flood first"].Build()
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
		if n.Kind == NodeUnmanaged && n.ID >= fmt.Sprintf("u%06d", kept) {
			t.Fatalf("kept unmanaged %s beyond the cut u%06d", n.ID, kept-1)
		}
	}
	if _, ok := g.Node(fmt.Sprintf("u%06d", kept-1)); !ok {
		t.Fatalf("unmanaged u%06d below the cut was dropped", kept-1)
	}
	dn, de := g.Dropped()
	if wantDN := 2 + len(inventory) + len(flood) - MaxNodes; dn != wantDN {
		t.Fatalf("dropped nodes = %d, want %d (each distinct node once)", dn, wantDN)
	}
	// Flood edges into u004999, u006000 and u019000 are cut with their nodes
	// by MaxNodes; edges into nodes the input limit dropped are not counted
	// in any order (held then evicted with the node, or ErrUnknownNode).
	if de != 3 {
		t.Fatalf("dropped edges = %d, want 3", de)
	}
	if !g.Truncated() {
		t.Fatal("flood exceeded the input limit but graph not truncated")
	}
}

func TestNodeInputLimitEvictsLowestRankAndReportsDrops(t *testing.T) {
	b := NewBuilder()
	for i := range MaxInputNodes - 2 {
		mustNode(t, b, Node{ID: fmt.Sprintf("u%06d", i), Kind: NodeUnmanaged})
	}
	// Full. A worse node is dropped with ErrInputLimit.
	if err := b.AddNode(Node{ID: "u999999", Kind: NodeUnmanaged}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("worse node at limit = %v, want ErrInputLimit", err)
	}
	// Re-offering the same dropped node is ErrInputLimit again, other
	// contents under that ID is ErrConflict.
	if err := b.AddNode(Node{ID: "u999999", Kind: NodeUnmanaged}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("re-offered dropped node = %v, want ErrInputLimit", err)
	}
	if err := b.AddNode(Node{ID: "u999999", Kind: NodeHost}); !errors.Is(err, ErrConflict) {
		t.Fatalf("dropped ID with other kind = %v, want ErrConflict", err)
	}
	// A managed host is accepted and evicts the highest unmanaged ID together
	// with its edges.
	last := fmt.Sprintf("u%06d", MaxInputNodes-3)
	mustEdge(t, b, Edge{From: InternetID, To: last, Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 80})
	mustNode(t, b, Node{ID: "zz-host", Kind: NodeHost})
	if err := b.AddEdge(Edge{From: InternetID, To: last, Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 81}); !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("edge to evicted node = %v, want ErrUnknownNode", err)
	}
	if err := b.AddNode(Node{ID: last, Kind: NodeUnmanaged}); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("evicted node re-offered = %v, want ErrInputLimit", err)
	}
	g := b.Build()
	if _, ok := g.Node("zz-host"); !ok {
		t.Fatal("managed host added at the input limit was dropped")
	}
	// The cap drops 20,000 held to 5,000; the input limit dropped u999999
	// and the evicted node, each once.
	wantDN := MaxInputNodes - MaxNodes + 2
	if dn, de := g.Dropped(); dn != wantDN || de != 0 {
		t.Fatalf("dropped %d/%d, want %d/0", dn, de, wantDN)
	}
}

// edgeFloodInputs returns one tier per edge kind so that the input limit and
// the edge cap both cut inside a known tier.
func edgeFloodInputs() (nodes []Node, tiers [][]Edge) {
	const hosts = 500
	for i := range hosts {
		nodes = append(nodes, Node{ID: fmt.Sprintf("h%03d", i), Kind: NodeHost})
	}
	nodes = append(nodes,
		Node{ID: "pve", Kind: NodePVENode},
		Node{ID: "guest", Kind: NodeGuest},
		Node{ID: "ctr", Kind: NodeContainer},
	)
	var assumed, observed, policy, proven []Edge
	for i := 0; len(assumed) < 120000; i++ {
		from, to := i/hosts, i%hosts
		if from == to {
			continue
		}
		assumed = append(assumed, Edge{From: fmt.Sprintf("h%03d", from), To: fmt.Sprintf("h%03d", to), Kind: EdgeL2Adjacency})
	}
	for i := range 60000 {
		observed = append(observed, Edge{From: InternetID, To: fmt.Sprintf("h%03d", i%hosts), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: uint16(1 + i/hosts)})
	}
	for i := range 40000 {
		policy = append(policy, Edge{From: NetBirdID, To: fmt.Sprintf("h%03d", i%hosts), Kind: EdgeNetworkPolicy, Proto: ProtoUDP, Port: uint16(1 + i/hosts)})
	}
	proven = []Edge{
		{From: "h499", To: "pve", Kind: EdgeCredential},
		{From: "h499", To: "guest", Kind: EdgeCredential},
		{From: "pve", To: "guest", Kind: EdgeControl},
		{From: "guest", To: "ctr", Kind: EdgeControl},
		{From: "ctr", To: "guest", Kind: EdgeEscape, Escape: EscapePrivileged},
	}
	// Lowest rank first: the flood order.
	return nodes, [][]Edge{assumed, observed, policy, proven}
}

func TestEdgeFloodAddedFirstCannotCrowdOutProvenEdges(t *testing.T) {
	nodes, tiers := edgeFloodInputs()
	floodFirst := slices.Concat(tiers...)
	provenFirst := slices.Concat(tiers[3], tiers[2], tiers[1], tiers[0])
	shuffled := slices.Clone(floodFirst)
	rand.New(rand.NewPCG(9, 9)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	builds := map[string]*Graph{
		"flood first":  addAll(t, nodes, floodFirst).Build(),
		"proven first": addAll(t, nodes, provenFirst).Build(),
		"shuffled":     addAll(t, nodes, shuffled).Build(),
		"flood twice":  addAll(t, nodes, floodFirst, tiers[0], tiers[1]).Build(),
	}
	want := builds["proven first"]
	for name, g := range builds {
		if g.Hash() != want.Hash() {
			dn, de := g.Dropped()
			wn, we := want.Dropped()
			t.Errorf("%s: hash differs from proven first (dropped %d/%d, want %d/%d)", name, dn, de, wn, we)
		}
	}

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
	total := 0
	for _, tier := range tiers {
		total += len(tier)
	}
	if dn, de := g.Dropped(); dn != 0 || de != total-MaxEdges {
		t.Fatalf("dropped %d/%d, want 0/%d (each distinct edge once)", dn, de, total-MaxEdges)
	}
}

func TestEdgeInputLimitEvictsLowestRank(t *testing.T) {
	nodes, tiers := edgeFloodInputs()
	b := addAll(t, nodes)
	held := 0
	for _, e := range slices.Concat(tiers[0], tiers[1], tiers[2]) {
		if held == MaxInputEdges {
			break
		}
		mustEdge(t, b, e)
		held++
	}
	if held != MaxInputEdges {
		t.Fatalf("fixture holds %d edges, want %d", held, MaxInputEdges)
	}
	// Full of assumed, observed and policy edges. A worse edge is dropped;
	// the same edge again is not counted twice.
	worse := Edge{From: "h499", To: "h498", Kind: EdgeL2Adjacency}
	for range 2 {
		if err := b.AddEdge(worse); !errors.Is(err, ErrInputLimit) {
			t.Fatalf("worse edge at limit = %v, want ErrInputLimit", err)
		}
	}
	// Proven edges are accepted and evict the worst held edges.
	for _, e := range tiers[3] {
		mustEdge(t, b, e)
	}
	// Merging escape reasons into a held escape edge still works.
	mustEdge(t, b, Edge{From: "ctr", To: "guest", Kind: EdgeEscape, Escape: EscapeFindingNote})
	g := b.Build()
	if out := g.Out("ctr"); len(out) != 1 || out[0].Escape != EscapePrivileged|EscapeFindingNote {
		t.Fatalf("escape edge = %+v", out)
	}
	// Input drops: the worse edge plus 5 evicted ones; the cap drops the
	// rest of the 200,000 held down to 50,000.
	if _, de := g.Dropped(); de != 1+len(tiers[3])+MaxInputEdges-MaxEdges {
		t.Fatalf("dropped edges = %d, want %d", de, 1+len(tiers[3])+MaxInputEdges-MaxEdges)
	}
}
