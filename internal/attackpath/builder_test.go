// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

func mustNode(t *testing.T, b *Builder, n Node) {
	t.Helper()
	if err := b.AddNode(n); err != nil {
		t.Fatalf("AddNode(%s): %v", n.ID, err)
	}
}

func mustEdge(t *testing.T, b *Builder, e Edge) {
	t.Helper()
	if err := b.AddEdge(e); err != nil {
		t.Fatalf("AddEdge(%s -> %s %s): %v", e.From, e.To, e.Kind, err)
	}
}

func TestKindStringsAreStable(t *testing.T) {
	nodes := map[NodeKind]string{
		NodeInternet: "internet", NodeNetBird: "netbird", NodeHost: "host",
		NodePVENode: "pve_node", NodeGuest: "guest", NodeContainer: "container",
		NodeNetworkDevice: "network_device", NodeUnmanaged: "unmanaged",
	}
	for k, want := range nodes {
		if got := k.String(); got != want {
			t.Errorf("NodeKind %d = %q, want %q", k, got, want)
		}
	}
	edges := map[EdgeKind][2]string{
		EdgeNetworkPolicy:   {"network_policy", "policy"},
		EdgeNetworkObserved: {"network_observed", "observed"},
		EdgeL2Adjacency:     {"l2_adjacency", "assumed"},
		EdgeControl:         {"control", "inventory"},
		EdgeEscape:          {"escape", "inventory"},
		EdgeCredential:      {"credential", "inventory"},
	}
	for k, want := range edges {
		if got := k.String(); got != want[0] {
			t.Errorf("EdgeKind %d = %q, want %q", k, got, want[0])
		}
		if got := k.Basis().String(); got != want[1] {
			t.Errorf("EdgeKind %s basis = %q, want %q", k, got, want[1])
		}
	}
	if NodeKind(0).String() != "invalid" || EdgeKind(0).String() != "invalid" || Basis(0).String() != "invalid" {
		t.Error("zero kinds must render as invalid")
	}
}

func TestOnlyL2AdjacencyIsAssumed(t *testing.T) {
	for k := EdgeNetworkPolicy; k <= EdgeCredential; k++ {
		e := Edge{Kind: k}
		if got, want := e.Assumed(), k == EdgeL2Adjacency; got != want {
			t.Errorf("%s Assumed() = %v, want %v", k, got, want)
		}
	}
}

func TestNewBuilderHasSyntheticEntries(t *testing.T) {
	g := NewBuilder().Build()
	for _, id := range []string{InternetID, NetBirdID} {
		n, ok := g.Node(id)
		if !ok || !n.Kind.Entry() {
			t.Fatalf("entry %q missing or not an entry: %+v", id, n)
		}
	}
	if len(g.Nodes()) != 2 || len(g.Edges()) != 0 || g.Truncated() {
		t.Fatalf("empty graph: %d nodes, %d edges, truncated %v", len(g.Nodes()), len(g.Edges()), g.Truncated())
	}
	if in, _ := g.Node(InternetID); in.Kind != NodeInternet {
		t.Fatalf("internet kind = %s", in.Kind)
	}
	if n, _ := g.Node(NetBirdID); n.Kind != NodeNetBird {
		t.Fatalf("netbird kind = %s, want its own entry class", n.Kind)
	}
}

func TestAddNodeRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		node Node
		want error
	}{
		{"empty id", Node{ID: "", Kind: NodeHost}, ErrInvalidNode},
		{"long id", Node{ID: strings.Repeat("a", MaxIDBytes+1), Kind: NodeHost}, ErrInvalidNode},
		{"space in id", Node{ID: "host 1", Kind: NodeHost}, ErrInvalidNode},
		{"non-ascii id", Node{ID: "hóst", Kind: NodeHost}, ErrInvalidNode},
		{"zero kind", Node{ID: "h1", Kind: 0}, ErrInvalidNode},
		{"unknown kind", Node{ID: "h1", Kind: 99}, ErrInvalidNode},
		{"internet kind", Node{ID: "other", Kind: NodeInternet}, ErrReservedNode},
		{"netbird kind", Node{ID: "other", Kind: NodeNetBird}, ErrReservedNode},
		{"internet id", Node{ID: InternetID, Kind: NodeHost}, ErrReservedNode},
		{"long label", Node{ID: "h1", Kind: NodeHost, Label: strings.Repeat("x", MaxLabelBytes+1)}, ErrInvalidNode},
		{"invalid utf-8 label", Node{ID: "h1", Kind: NodeHost, Label: "a\xffb"}, ErrInvalidNode},
		{"control char label", Node{ID: "h1", Kind: NodeHost, Label: "a\nb"}, ErrInvalidNode},
		{"nul label", Node{ID: "h1", Kind: NodeHost, Label: "a\x00b"}, ErrInvalidNode},
		{"bidi override label", Node{ID: "h1", Kind: NodeHost, Label: "a" + string(rune(0x202e)) + "b"}, ErrInvalidNode},
		{"bidi isolate label", Node{ID: "h1", Kind: NodeHost, Label: "a" + string(rune(0x2066)) + "b"}, ErrInvalidNode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuilder()
			err := b.AddNode(tt.node)
			if !errors.Is(err, tt.want) {
				t.Fatalf("AddNode = %v, want %v", err, tt.want)
			}
			if strings.Contains(err.Error(), "\xff") || (tt.node.Label != "" && strings.Contains(err.Error(), tt.node.Label)) {
				t.Fatalf("error echoes untrusted label: %q", err)
			}
			if got := len(b.Build().Nodes()); got != 2 {
				t.Fatalf("rejected node stored: %d nodes", got)
			}
		})
	}
}

func TestAddNodeAcceptsMaxSizes(t *testing.T) {
	b := NewBuilder()
	mustNode(t, b, Node{ID: strings.Repeat("a", MaxIDBytes), Kind: NodeHost, Label: strings.Repeat("ü", MaxLabelBytes/2)})
	mustNode(t, b, Node{ID: "host:Az09._:/@-", Kind: NodeHost, Label: "web\tserver"})
}

func TestAddNodeDuplicates(t *testing.T) {
	b := NewBuilder()
	n := Node{ID: "host:a", Kind: NodeHost, Label: "a"}
	mustNode(t, b, n)
	mustNode(t, b, n) // identical: idempotent
	if err := b.AddNode(Node{ID: "host:a", Kind: NodeGuest, Label: "a"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("kind conflict = %v, want ErrConflict", err)
	}
	if err := b.AddNode(Node{ID: "host:a", Kind: NodeHost, Label: "b"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("label conflict = %v, want ErrConflict", err)
	}
	if got := len(b.Build().Nodes()); got != 3 {
		t.Fatalf("nodes = %d, want 3", got)
	}
}

// edgeFixture is a builder holding one node of every kind.
func edgeFixture(t *testing.T) *Builder {
	t.Helper()
	b := NewBuilder()
	for _, n := range []Node{
		{ID: "host", Kind: NodeHost},
		{ID: "host2", Kind: NodeHost},
		{ID: "pve", Kind: NodePVENode},
		{ID: "guest", Kind: NodeGuest},
		{ID: "ctr", Kind: NodeContainer},
		{ID: "dev", Kind: NodeNetworkDevice},
		{ID: "unk", Kind: NodeUnmanaged},
	} {
		mustNode(t, b, n)
	}
	return b
}

func TestAddEdgeKindRules(t *testing.T) {
	net := func(k EdgeKind, from, to string) Edge {
		return Edge{From: from, To: to, Kind: k, Proto: ProtoTCP, Port: 443}
	}
	plain := func(k EdgeKind, from, to string) Edge { return Edge{From: from, To: to, Kind: k} }
	esc := func(from, to string, r EscapeReason) Edge {
		return Edge{From: from, To: to, Kind: EdgeEscape, Escape: r}
	}
	tests := []struct {
		name string
		edge Edge
		want error // nil = accepted
	}{
		// network edges
		{"policy internet->host", net(EdgeNetworkPolicy, InternetID, "host"), nil},
		{"policy netbird->guest", net(EdgeNetworkPolicy, NetBirdID, "guest"), nil},
		{"observed unmanaged->container", net(EdgeNetworkObserved, "unk", "ctr"), nil},
		{"observed host->device udp", Edge{From: "host", To: "dev", Kind: EdgeNetworkObserved, Proto: ProtoUDP, Port: 161}, nil},
		{"policy port 65535", Edge{From: "host", To: "dev", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 65535}, nil},
		{"policy port 0", Edge{From: "host", To: "dev", Kind: EdgeNetworkPolicy, Proto: ProtoTCP}, ErrInvalidEdge},
		{"policy no proto", Edge{From: "host", To: "dev", Kind: EdgeNetworkPolicy, Port: 22}, ErrInvalidEdge},
		{"policy bad proto", Edge{From: "host", To: "dev", Kind: EdgeNetworkPolicy, Proto: 9, Port: 22}, ErrInvalidEdge},
		{"policy with escape reason", Edge{From: "host", To: "dev", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 22, Escape: EscapePrivileged}, ErrInvalidEdge},
		{"policy into internet", net(EdgeNetworkPolicy, "host", InternetID), ErrInvalidEdge},
		{"observed into netbird", net(EdgeNetworkObserved, "host", NetBirdID), ErrInvalidEdge},
		// L2 adjacency
		{"l2 host->guest", plain(EdgeL2Adjacency, "host", "guest"), nil},
		{"l2 unmanaged->device", plain(EdgeL2Adjacency, "unk", "dev"), nil},
		{"l2 with port", Edge{From: "host", To: "guest", Kind: EdgeL2Adjacency, Proto: ProtoTCP, Port: 22}, ErrInvalidEdge},
		{"l2 from internet", plain(EdgeL2Adjacency, InternetID, "host"), ErrInvalidEdge},
		// control
		{"control pve->guest", plain(EdgeControl, "pve", "guest"), nil},
		{"control host->container", plain(EdgeControl, "host", "ctr"), nil},
		{"control guest->container", plain(EdgeControl, "guest", "ctr"), nil},
		{"control pve->container", plain(EdgeControl, "pve", "ctr"), nil},
		{"control host->guest", plain(EdgeControl, "host", "guest"), ErrInvalidEdge},
		{"control pve->host", plain(EdgeControl, "pve", "host"), ErrInvalidEdge},
		{"control device->container", plain(EdgeControl, "dev", "ctr"), ErrInvalidEdge},
		{"control with port", Edge{From: "pve", To: "guest", Kind: EdgeControl, Proto: ProtoTCP, Port: 8006}, ErrInvalidEdge},
		// escape
		{"escape privileged", esc("ctr", "host", EscapePrivileged), nil},
		{"escape socket to guest", esc("ctr", "guest", EscapeDockerSocket), nil},
		{"escape note to pve", esc("ctr", "pve", EscapeFindingNote), nil},
		{"escape all reasons", esc("ctr", "host", EscapePrivileged|EscapeDockerSocket|EscapeFindingNote), nil},
		{"escape without reason", esc("ctr", "host", 0), ErrInvalidEdge},
		{"escape unknown reason bit", esc("ctr", "host", 0x80), ErrInvalidEdge},
		{"escape from host", esc("host", "host2", EscapePrivileged), ErrInvalidEdge},
		{"escape to device", esc("ctr", "dev", EscapePrivileged), ErrInvalidEdge},
		// credential
		{"credential host->host", plain(EdgeCredential, "host", "host2"), nil},
		{"credential host->pve", plain(EdgeCredential, "host", "pve"), nil},
		{"credential host->guest", plain(EdgeCredential, "host", "guest"), nil},
		{"credential host->container", plain(EdgeCredential, "host", "ctr"), ErrInvalidEdge},
		{"credential host->unmanaged", plain(EdgeCredential, "host", "unk"), ErrInvalidEdge},
		{"credential unmanaged->host", plain(EdgeCredential, "unk", "host"), ErrInvalidEdge},
		{"credential internet->host", plain(EdgeCredential, InternetID, "host"), ErrInvalidEdge},
		// generic
		{"self loop", net(EdgeNetworkPolicy, "host", "host"), ErrInvalidEdge},
		{"zero kind", Edge{From: "host", To: "host2"}, ErrInvalidEdge},
		{"unknown kind", Edge{From: "host", To: "host2", Kind: 42}, ErrInvalidEdge},
		{"unknown from", net(EdgeNetworkPolicy, "nope", "host"), ErrUnknownNode},
		{"unknown to", net(EdgeNetworkPolicy, "host", "nope"), ErrUnknownNode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := edgeFixture(t)
			err := b.AddEdge(tt.edge)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("AddEdge = %v, want accepted", err)
				}
				if got := len(b.Build().Edges()); got != 1 {
					t.Fatalf("edges = %d, want 1", got)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("AddEdge = %v, want %v", err, tt.want)
			}
			if got := len(b.Build().Edges()); got != 0 {
				t.Fatalf("rejected edge stored: %d edges", got)
			}
		})
	}
}

func TestAssumedEdgesStayDistinctFromObserved(t *testing.T) {
	b := edgeFixture(t)
	mustEdge(t, b, Edge{From: "host", To: "guest", Kind: EdgeL2Adjacency})
	mustEdge(t, b, Edge{From: "host", To: "guest", Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 22})
	mustEdge(t, b, Edge{From: "host", To: "guest", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 22})
	mustEdge(t, b, Edge{From: "host", To: "guest", Kind: EdgeL2Adjacency}) // duplicate: idempotent
	g := b.Build()
	out := g.Out("host")
	if len(out) != 3 {
		t.Fatalf("out edges = %d, want 3 (assumed, observed and policy kept apart): %+v", len(out), out)
	}
	var assumed, observed, policy int
	for _, e := range out {
		switch {
		case e.Assumed():
			assumed++
			if e.Kind != EdgeL2Adjacency || e.Proto != 0 || e.Port != 0 {
				t.Errorf("assumed edge not L2 all-ports: %+v", e)
			}
		case e.Kind.Basis() == BasisObserved:
			observed++
		case e.Kind.Basis() == BasisPolicy:
			policy++
		}
	}
	if assumed != 1 || observed != 1 || policy != 1 {
		t.Fatalf("assumed %d, observed %d, policy %d; want 1 each", assumed, observed, policy)
	}
	snap := string(g.Snapshot())
	if !strings.Contains(snap, `"basis":"assumed","assumed":true`) || !strings.Contains(snap, `"basis":"observed","assumed":false`) {
		t.Fatalf("snapshot does not label basis/assumed: %s", snap)
	}
}

func TestEscapeReasonsMerge(t *testing.T) {
	b := edgeFixture(t)
	mustEdge(t, b, Edge{From: "ctr", To: "host", Kind: EdgeEscape, Escape: EscapePrivileged})
	mustEdge(t, b, Edge{From: "ctr", To: "host", Kind: EdgeEscape, Escape: EscapeDockerSocket})
	edges := b.Build().Edges()
	if len(edges) != 1 || edges[0].Escape != EscapePrivileged|EscapeDockerSocket {
		t.Fatalf("escape edges = %+v, want one with both reasons", edges)
	}
}

func TestGraphAccessorsReturnCopies(t *testing.T) {
	b := edgeFixture(t)
	mustEdge(t, b, Edge{From: "pve", To: "guest", Kind: EdgeControl})
	g := b.Build()
	h := g.Hash()
	g.Nodes()[0].ID = "mutated"
	g.Edges()[0].To = "mutated"
	g.Out("pve")[0].To = "mutated"
	if g.Hash() != h {
		t.Fatal("mutating returned slices changed the graph")
	}
	if len(g.Out("missing")) != 0 {
		t.Fatal("Out of unknown node must be empty")
	}
	// The builder stays usable and does not alias the built graph.
	mustEdge(t, b, Edge{From: "host", To: "ctr", Kind: EdgeControl})
	if g.Hash() != h || len(g.Edges()) != 1 {
		t.Fatal("builder change leaked into built graph")
	}
}

// labInputs returns the nodes and edges of a small fixed lab.
func labInputs() ([]Node, []Edge) {
	nodes := []Node{
		{ID: "host:exec", Kind: NodeHost, Label: "executor"},
		{ID: "pve:n1", Kind: NodePVENode, Label: "pve-1"},
		{ID: "guest:101", Kind: NodeGuest, Label: "nas"},
		{ID: "guest:102", Kind: NodeGuest, Label: "docker"},
		{ID: "ctr:web", Kind: NodeContainer, Label: "web"},
		{ID: "dev:fw", Kind: NodeNetworkDevice, Label: "firewall"},
		{ID: "unk:10.0.0.9", Kind: NodeUnmanaged, Label: ""},
	}
	edges := []Edge{
		{From: InternetID, To: "dev:fw", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 443},
		{From: InternetID, To: "ctr:web", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 8443},
		{From: NetBirdID, To: "pve:n1", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 8006},
		{From: "unk:10.0.0.9", To: "guest:101", Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 445},
		{From: "guest:102", To: "guest:101", Kind: EdgeL2Adjacency},
		{From: "guest:101", To: "guest:102", Kind: EdgeL2Adjacency},
		{From: "guest:102", To: "guest:101", Kind: EdgeNetworkObserved, Proto: ProtoUDP, Port: 2049},
		{From: "pve:n1", To: "guest:101", Kind: EdgeControl},
		{From: "pve:n1", To: "guest:102", Kind: EdgeControl},
		{From: "guest:102", To: "ctr:web", Kind: EdgeControl},
		{From: "ctr:web", To: "guest:102", Kind: EdgeEscape, Escape: EscapeDockerSocket | EscapePrivileged},
		{From: "host:exec", To: "pve:n1", Kind: EdgeCredential},
		{From: "host:exec", To: "guest:101", Kind: EdgeCredential},
		{From: "host:exec", To: "guest:102", Kind: EdgeCredential},
	}
	return nodes, edges
}

func buildLab(t *testing.T, seed uint64) *Graph {
	t.Helper()
	nodes, edges := labInputs()
	r := rand.New(rand.NewPCG(seed, seed))
	r.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })
	r.Shuffle(len(edges), func(i, j int) { edges[i], edges[j] = edges[j], edges[i] })
	b := NewBuilder()
	for _, n := range nodes {
		mustNode(t, b, n)
	}
	for _, e := range edges {
		mustEdge(t, b, e)
	}
	return b.Build()
}

func TestBuildIsDeterministicAcrossInputOrder(t *testing.T) {
	want := buildLab(t, 0)
	for seed := uint64(1); seed < 20; seed++ {
		got := buildLab(t, seed)
		if got.Hash() != want.Hash() || string(got.Snapshot()) != string(want.Snapshot()) {
			t.Fatalf("seed %d: hash %s, want %s", seed, got.Hash(), want.Hash())
		}
	}
}

func TestNodeCapTruncatesDeterministically(t *testing.T) {
	build := func(seed uint64) *Graph {
		ids := make([]Node, 0, MaxNodes+10)
		for i := range MaxNodes + 10 {
			kind := NodeHost
			if i%2 == 0 {
				kind = NodeUnmanaged
			}
			ids = append(ids, Node{ID: fmt.Sprintf("n%05d", i), Kind: kind})
		}
		r := rand.New(rand.NewPCG(seed, 7))
		r.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
		b := NewBuilder()
		for _, n := range ids {
			mustNode(t, b, n)
		}
		// One edge into a node that will be dropped (unmanaged, highest ID).
		mustEdge(t, b, Edge{From: InternetID, To: fmt.Sprintf("n%05d", MaxNodes+8), Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 80})
		// One edge into a kept managed host.
		mustEdge(t, b, Edge{From: InternetID, To: "n00001", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 80})
		return b.Build()
	}
	g := build(1)
	if !g.Truncated() {
		t.Fatal("node cap exceeded but Truncated() is false")
	}
	if got := len(g.Nodes()); got != MaxNodes {
		t.Fatalf("nodes = %d, want %d", got, MaxNodes)
	}
	dn, de := g.Dropped()
	// 5,012 inputs including the two entries; 12 dropped.
	if dn != 12 || de != 1 {
		t.Fatalf("dropped nodes %d edges %d, want 12 and 1", dn, de)
	}
	for _, id := range []string{InternetID, NetBirdID, "n00001"} {
		if _, ok := g.Node(id); !ok {
			t.Fatalf("node %s dropped; entries and managed hosts must be kept first", id)
		}
	}
	// Kept: 2 entries, 2,505 hosts (odd IDs) and the 2,493 lowest unmanaged
	// (even IDs n00000..n04984); the cut is exact.
	for _, n := range g.Nodes() {
		if n.Kind == NodeUnmanaged && n.ID > "n04984" {
			t.Fatalf("kept unmanaged %s beyond the cut n04984", n.ID)
		}
	}
	if _, ok := g.Node("n04984"); !ok {
		t.Fatal("unmanaged n04984 at the cut was dropped")
	}
	if len(g.Edges()) != 1 {
		t.Fatalf("edges = %d, want 1 (edge to dropped node removed)", len(g.Edges()))
	}
	if !strings.Contains(string(g.Snapshot()), `"truncated":true`) {
		t.Fatal("snapshot does not state truncation")
	}
	if build(2).Hash() != g.Hash() {
		t.Fatal("truncated graph depends on input order")
	}
}

func TestEdgeCapTruncatesDeterministically(t *testing.T) {
	const hosts = 10
	build := func(seed uint64) *Graph {
		b := NewBuilder()
		for i := range hosts {
			mustNode(t, b, Node{ID: fmt.Sprintf("h%d", i), Kind: NodeHost})
		}
		var edges []Edge
		// Credential edges rank first and must survive the cap.
		for i := 1; i < hosts; i++ {
			edges = append(edges, Edge{From: "h0", To: fmt.Sprintf("h%d", i), Kind: EdgeCredential})
		}
		for i := 0; len(edges) < MaxEdges+100; i++ {
			edges = append(edges, Edge{From: InternetID, To: fmt.Sprintf("h%d", i%hosts), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: uint16(1 + i/hosts)})
		}
		r := rand.New(rand.NewPCG(seed, 3))
		r.Shuffle(len(edges), func(i, j int) { edges[i], edges[j] = edges[j], edges[i] })
		for _, e := range edges {
			mustEdge(t, b, e)
		}
		return b.Build()
	}
	g := build(1)
	if !g.Truncated() {
		t.Fatal("edge cap exceeded but Truncated() is false")
	}
	if got := len(g.Edges()); got != MaxEdges {
		t.Fatalf("edges = %d, want %d", got, MaxEdges)
	}
	if dn, de := g.Dropped(); dn != 0 || de != 100 {
		t.Fatalf("dropped nodes %d edges %d, want 0 and 100", dn, de)
	}
	if got := len(g.Out("h0")); got != hosts-1 {
		t.Fatalf("credential edges kept = %d, want %d", got, hosts-1)
	}
	if build(2).Hash() != g.Hash() {
		t.Fatal("truncated graph depends on input order")
	}
}

func TestExactCapsAreNotTruncated(t *testing.T) {
	b := NewBuilder()
	for i := range MaxNodes - 2 {
		mustNode(t, b, Node{ID: fmt.Sprintf("h%04d", i), Kind: NodeHost})
	}
	for i := range MaxEdges {
		mustEdge(t, b, Edge{From: InternetID, To: fmt.Sprintf("h%04d", i%10), Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: uint16(1 + i/10)})
	}
	g := b.Build()
	if g.Truncated() || len(g.Nodes()) != MaxNodes || len(g.Edges()) != MaxEdges {
		t.Fatalf("truncated %v, nodes %d, edges %d", g.Truncated(), len(g.Nodes()), len(g.Edges()))
	}
}

func TestInputLimitsBoundBuilderMemory(t *testing.T) {
	b := NewBuilder()
	var err error
	i := 0
	for ; i < MaxInputNodes+5; i++ {
		if err = b.AddNode(Node{ID: fmt.Sprintf("u%06d", i), Kind: NodeUnmanaged}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrInputLimit) {
		t.Fatalf("AddNode beyond input limit = %v, want ErrInputLimit", err)
	}
	if i+2 != MaxInputNodes {
		t.Fatalf("input limit hit after %d nodes (+2 entries), want %d", i, MaxInputNodes)
	}
	// Re-adding a known node is still fine; a new edge budget applies. The
	// edges come in keep order, so the first one past the limit ranks last
	// and is dropped (an edge ranking earlier would evict instead).
	mustNode(t, b, Node{ID: "u000000", Kind: NodeUnmanaged})
	for i = 0; i < MaxInputEdges+5; i++ {
		if err = b.AddEdge(Edge{From: fmt.Sprintf("u%06d", i/1000), To: fmt.Sprintf("u%06d", 1000+i%1000), Kind: EdgeL2Adjacency}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrInputLimit) || i != MaxInputEdges {
		t.Fatalf("AddEdge beyond input limit after %d: %v", i, err)
	}
	g := b.Build()
	if !g.Truncated() {
		t.Fatal("input limit hit but graph not truncated")
	}
	if dn, de := g.Dropped(); dn < 1 || de < 1 {
		t.Fatalf("dropped counts %d/%d must include rejected inputs", dn, de)
	}
}
