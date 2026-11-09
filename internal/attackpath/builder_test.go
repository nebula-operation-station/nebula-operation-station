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
		{"zero kind", Node{ID: "host:1", Kind: 0}, ErrInvalidNode},
		{"unknown kind", Node{ID: "host:1", Kind: 99}, ErrInvalidNode},
		{"internet kind", Node{ID: "other", Kind: NodeInternet}, ErrReservedNode},
		{"netbird kind", Node{ID: "other", Kind: NodeNetBird}, ErrReservedNode},
		{"internet id", Node{ID: InternetID, Kind: NodeHost}, ErrReservedNode},
		{"long label", Node{ID: "host:1", Kind: NodeHost, Label: strings.Repeat("x", MaxLabelBytes+1)}, ErrInvalidNode},
		{"invalid utf-8 label", Node{ID: "host:1", Kind: NodeHost, Label: "a\xffb"}, ErrInvalidNode},
		{"control char label", Node{ID: "host:1", Kind: NodeHost, Label: "a\nb"}, ErrInvalidNode},
		{"nul label", Node{ID: "host:1", Kind: NodeHost, Label: "a\x00b"}, ErrInvalidNode},
		{"bidi override label", Node{ID: "host:1", Kind: NodeHost, Label: "a" + string(rune(0x202e)) + "b"}, ErrInvalidNode},
		{"bidi isolate label", Node{ID: "host:1", Kind: NodeHost, Label: "a" + string(rune(0x2066)) + "b"}, ErrInvalidNode},
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
	mustNode(t, b, Node{ID: "host:" + strings.Repeat("a", MaxIDBytes-len("host:")), Kind: NodeHost, Label: strings.Repeat("ü", MaxLabelBytes/2)})
	mustNode(t, b, Node{ID: "host:Az09._:/@-", Kind: NodeHost, Label: "web\tserver"})
}

func TestAddNodeDuplicates(t *testing.T) {
	b := NewBuilder()
	n := Node{ID: "host:a", Kind: NodeHost, Label: "a"}
	mustNode(t, b, n)
	mustNode(t, b, n) // identical: idempotent
	// Another kind cannot use the ID at all: the ID names the kind.
	if err := b.AddNode(Node{ID: "host:a", Kind: NodeGuest, Label: "a"}); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("kind conflict = %v, want ErrInvalidNode", err)
	}
	if err := b.AddNode(Node{ID: "host:a", Kind: NodeHost, Label: "b"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("label conflict = %v, want ErrConflict", err)
	}
	g := b.Build()
	if got := len(g.Nodes()); got != 3 {
		t.Fatalf("nodes = %d, want 3", got)
	}
	if got, _ := g.Node("host:a"); got != n {
		t.Fatalf("node = %+v, want %+v", got, n)
	}
}

func TestNodeIDIsBoundToKind(t *testing.T) {
	tests := []struct {
		name string
		node Node
	}{
		{"unmanaged under host id", Node{ID: "host:a", Kind: NodeUnmanaged}},
		{"container under host id", Node{ID: "host:a", Kind: NodeContainer}},
		{"host under unmanaged id", Node{ID: "unk:10.0.0.1", Kind: NodeHost}},
		{"guest under pve id", Node{ID: "pve:a", Kind: NodeGuest}},
		{"device under container id", Node{ID: "ctr:a", Kind: NodeNetworkDevice}},
		{"pve under device id", Node{ID: "dev:a", Kind: NodePVENode}},
		{"no prefix", Node{ID: "a", Kind: NodeHost}},
		{"prefix only", Node{ID: "host:", Kind: NodeHost}},
		{"prefix without colon", Node{ID: "hosta", Kind: NodeHost}},
		{"upper-case prefix", Node{ID: "HOST:a", Kind: NodeHost}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewBuilder().AddNode(tt.node); !errors.Is(err, ErrInvalidNode) {
				t.Fatalf("AddNode = %v, want ErrInvalidNode", err)
			}
		})
	}
	for k := NodeHost; k <= NodeUnmanaged; k++ {
		if err := NewBuilder().AddNode(Node{ID: k.IDPrefix() + "x", Kind: k}); err != nil {
			t.Errorf("%s with its own prefix: %v", k, err)
		}
	}
	if NodeInternet.IDPrefix() != "" || NodeNetBird.IDPrefix() != "" || NodeKind(0).IDPrefix() != "" {
		t.Error("entry and invalid kinds must have no ID prefix")
	}
}

// A hostile node offered first under a managed host's ID can neither take
// the ID nor turn the real host into a conflict, in either order; the
// label conflict between two hosts resolves the same way in both orders.
func TestHostileNodeCannotClaimManagedHostID(t *testing.T) {
	host := Node{ID: "host:web", Kind: NodeHost, Label: "web"}
	hostile := Node{ID: "host:web", Kind: NodeUnmanaged, Label: "evil"}
	relabel := Node{ID: "host:web", Kind: NodeHost, Label: "aaa-evil"}
	edge := Edge{From: InternetID, To: "host:web", Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 22}
	build := func(first, second Node) *Graph {
		b := NewBuilder()
		errFirst, errSecond := b.AddNode(first), b.AddNode(second)
		for _, x := range []struct {
			n   Node
			err error
		}{{first, errFirst}, {second, errSecond}} {
			if x.n == hostile && !errors.Is(x.err, ErrInvalidNode) {
				t.Fatalf("hostile node = %v, want ErrInvalidNode", x.err)
			}
			if x.n == host && x.err != nil {
				t.Fatalf("real host = %v, want accepted", x.err)
			}
		}
		mustEdge(t, b, edge)
		return b.Build()
	}
	a, b := build(hostile, host), build(host, hostile)
	if a.Hash() != b.Hash() {
		t.Fatal("hostile node changes the graph depending on order")
	}
	if got, ok := a.Node("host:web"); !ok || got != host {
		t.Fatalf("host:web = %+v %v, want the real host", got, ok)
	}
	// Label conflict: the label sorting first wins in both orders, and the
	// later offer is ErrConflict either way.
	for _, order := range [][2]Node{{host, relabel}, {relabel, host}} {
		bl := NewBuilder()
		mustNode(t, bl, order[0])
		if err := bl.AddNode(order[1]); !errors.Is(err, ErrConflict) {
			t.Fatalf("relabel = %v, want ErrConflict", err)
		}
		if got, _ := bl.Build().Node("host:web"); got != relabel {
			t.Fatalf("label after conflict = %q, want %q", got.Label, relabel.Label)
		}
	}
}

// edgeFixture is a builder holding one node of every kind.
func edgeFixture(t *testing.T) *Builder {
	t.Helper()
	b := NewBuilder()
	for _, n := range []Node{
		{ID: "host:1", Kind: NodeHost},
		{ID: "host:2", Kind: NodeHost},
		{ID: "pve:1", Kind: NodePVENode},
		{ID: "guest:1", Kind: NodeGuest},
		{ID: "ctr:1", Kind: NodeContainer},
		{ID: "dev:1", Kind: NodeNetworkDevice},
		{ID: "unk:1", Kind: NodeUnmanaged},
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
		{"policy internet->host", net(EdgeNetworkPolicy, InternetID, "host:1"), nil},
		{"policy netbird->guest", net(EdgeNetworkPolicy, NetBirdID, "guest:1"), nil},
		{"observed unmanaged->container", net(EdgeNetworkObserved, "unk:1", "ctr:1"), nil},
		{"observed host->device udp", Edge{From: "host:1", To: "dev:1", Kind: EdgeNetworkObserved, Proto: ProtoUDP, Port: 161}, nil},
		{"policy port 65535", Edge{From: "host:1", To: "dev:1", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 65535}, nil},
		{"policy port 0", Edge{From: "host:1", To: "dev:1", Kind: EdgeNetworkPolicy, Proto: ProtoTCP}, ErrInvalidEdge},
		{"policy no proto", Edge{From: "host:1", To: "dev:1", Kind: EdgeNetworkPolicy, Port: 22}, ErrInvalidEdge},
		{"policy bad proto", Edge{From: "host:1", To: "dev:1", Kind: EdgeNetworkPolicy, Proto: 9, Port: 22}, ErrInvalidEdge},
		{"policy with escape reason", Edge{From: "host:1", To: "dev:1", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 22, Escape: EscapePrivileged}, ErrInvalidEdge},
		{"policy into internet", net(EdgeNetworkPolicy, "host:1", InternetID), ErrInvalidEdge},
		{"observed into netbird", net(EdgeNetworkObserved, "host:1", NetBirdID), ErrInvalidEdge},
		// L2 adjacency
		{"l2 host->guest", plain(EdgeL2Adjacency, "host:1", "guest:1"), nil},
		{"l2 unmanaged->device", plain(EdgeL2Adjacency, "unk:1", "dev:1"), nil},
		{"l2 with port", Edge{From: "host:1", To: "guest:1", Kind: EdgeL2Adjacency, Proto: ProtoTCP, Port: 22}, ErrInvalidEdge},
		{"l2 from internet", plain(EdgeL2Adjacency, InternetID, "host:1"), ErrInvalidEdge},
		// control
		{"control pve->guest", plain(EdgeControl, "pve:1", "guest:1"), nil},
		{"control host->container", plain(EdgeControl, "host:1", "ctr:1"), nil},
		{"control guest->container", plain(EdgeControl, "guest:1", "ctr:1"), nil},
		{"control pve->container", plain(EdgeControl, "pve:1", "ctr:1"), nil},
		{"control host->guest", plain(EdgeControl, "host:1", "guest:1"), ErrInvalidEdge},
		{"control pve->host", plain(EdgeControl, "pve:1", "host:1"), ErrInvalidEdge},
		{"control device->container", plain(EdgeControl, "dev:1", "ctr:1"), ErrInvalidEdge},
		{"control with port", Edge{From: "pve:1", To: "guest:1", Kind: EdgeControl, Proto: ProtoTCP, Port: 8006}, ErrInvalidEdge},
		// escape
		{"escape privileged", esc("ctr:1", "host:1", EscapePrivileged), nil},
		{"escape socket to guest", esc("ctr:1", "guest:1", EscapeDockerSocket), nil},
		{"escape note to pve", esc("ctr:1", "pve:1", EscapeFindingNote), nil},
		{"escape all reasons", esc("ctr:1", "host:1", EscapePrivileged|EscapeDockerSocket|EscapeFindingNote), nil},
		{"escape without reason", esc("ctr:1", "host:1", 0), ErrInvalidEdge},
		{"escape unknown reason bit", esc("ctr:1", "host:1", 0x80), ErrInvalidEdge},
		{"escape from host", esc("host:1", "host:2", EscapePrivileged), ErrInvalidEdge},
		{"escape to device", esc("ctr:1", "dev:1", EscapePrivileged), ErrInvalidEdge},
		// credential
		{"credential host->host", plain(EdgeCredential, "host:1", "host:2"), nil},
		{"credential host->pve", plain(EdgeCredential, "host:1", "pve:1"), nil},
		{"credential host->guest", plain(EdgeCredential, "host:1", "guest:1"), nil},
		{"credential host->container", plain(EdgeCredential, "host:1", "ctr:1"), ErrInvalidEdge},
		{"credential host->unmanaged", plain(EdgeCredential, "host:1", "unk:1"), ErrInvalidEdge},
		{"credential unmanaged->host", plain(EdgeCredential, "unk:1", "host:1"), ErrInvalidEdge},
		{"credential internet->host", plain(EdgeCredential, InternetID, "host:1"), ErrInvalidEdge},
		// generic
		{"self loop", net(EdgeNetworkPolicy, "host:1", "host:1"), ErrInvalidEdge},
		{"zero kind", Edge{From: "host:1", To: "host:2"}, ErrInvalidEdge},
		{"unknown kind", Edge{From: "host:1", To: "host:2", Kind: 42}, ErrInvalidEdge},
		{"unknown from", net(EdgeNetworkPolicy, "nope", "host:1"), ErrUnknownNode},
		{"unknown to", net(EdgeNetworkPolicy, "host:1", "nope"), ErrUnknownNode},
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
	mustEdge(t, b, Edge{From: "host:1", To: "guest:1", Kind: EdgeL2Adjacency})
	mustEdge(t, b, Edge{From: "host:1", To: "guest:1", Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: 22})
	mustEdge(t, b, Edge{From: "host:1", To: "guest:1", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 22})
	mustEdge(t, b, Edge{From: "host:1", To: "guest:1", Kind: EdgeL2Adjacency}) // duplicate: idempotent
	g := b.Build()
	out := g.Out("host:1")
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
	mustEdge(t, b, Edge{From: "ctr:1", To: "host:1", Kind: EdgeEscape, Escape: EscapePrivileged})
	mustEdge(t, b, Edge{From: "ctr:1", To: "host:1", Kind: EdgeEscape, Escape: EscapeDockerSocket})
	edges := b.Build().Edges()
	if len(edges) != 1 || edges[0].Escape != EscapePrivileged|EscapeDockerSocket {
		t.Fatalf("escape edges = %+v, want one with both reasons", edges)
	}
}

func TestGraphAccessorsReturnCopies(t *testing.T) {
	b := edgeFixture(t)
	mustEdge(t, b, Edge{From: "pve:1", To: "guest:1", Kind: EdgeControl})
	g := b.Build()
	h := g.Hash()
	g.Nodes()[0].ID = "mutated"
	g.Edges()[0].To = "mutated"
	g.Out("pve:1")[0].To = "mutated"
	if g.Hash() != h {
		t.Fatal("mutating returned slices changed the graph")
	}
	if len(g.Out("missing")) != 0 {
		t.Fatal("Out of unknown node must be empty")
	}
	// The builder stays usable and does not alias the built graph.
	mustEdge(t, b, Edge{From: "host:1", To: "ctr:1", Kind: EdgeControl})
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
			ids = append(ids, Node{ID: kind.IDPrefix() + fmt.Sprintf("n%05d", i), Kind: kind})
		}
		r := rand.New(rand.NewPCG(seed, 7))
		r.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
		b := NewBuilder()
		for _, n := range ids {
			mustNode(t, b, n)
		}
		// One edge into a node that will be dropped (unmanaged, highest ID).
		mustEdge(t, b, Edge{From: InternetID, To: fmt.Sprintf("unk:n%05d", MaxNodes+8), Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 80})
		// One edge into a kept managed host.
		mustEdge(t, b, Edge{From: InternetID, To: "host:n00001", Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: 80})
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
	for _, id := range []string{InternetID, NetBirdID, "host:n00001"} {
		if _, ok := g.Node(id); !ok {
			t.Fatalf("node %s dropped; entries and managed hosts must be kept first", id)
		}
	}
	// Kept: 2 entries, 2,505 hosts (odd IDs) and the 2,493 lowest unmanaged
	// (even IDs n00000..n04984); the cut is exact.
	for _, n := range g.Nodes() {
		if n.Kind == NodeUnmanaged && n.ID > "unk:n04984" {
			t.Fatalf("kept unmanaged %s beyond the cut n04984", n.ID)
		}
	}
	if _, ok := g.Node("unk:n04984"); !ok {
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
			mustNode(t, b, Node{ID: fmt.Sprintf("host:%d", i), Kind: NodeHost})
		}
		var edges []Edge
		// Credential edges rank first and must survive the cap.
		for i := 1; i < hosts; i++ {
			edges = append(edges, Edge{From: "host:0", To: fmt.Sprintf("host:%d", i), Kind: EdgeCredential})
		}
		for i := 0; len(edges) < MaxEdges+100; i++ {
			edges = append(edges, Edge{From: InternetID, To: fmt.Sprintf("host:%d", i%hosts), Kind: EdgeNetworkObserved, Proto: ProtoTCP, Port: uint16(1 + i/hosts)})
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
	if got := len(g.Out("host:0")); got != hosts-1 {
		t.Fatalf("credential edges kept = %d, want %d", got, hosts-1)
	}
	if build(2).Hash() != g.Hash() {
		t.Fatal("truncated graph depends on input order")
	}
}

func TestExactCapsAreNotTruncated(t *testing.T) {
	b := NewBuilder()
	for i := range MaxNodes - 2 {
		mustNode(t, b, Node{ID: fmt.Sprintf("host:%04d", i), Kind: NodeHost})
	}
	for i := range MaxEdges {
		mustEdge(t, b, Edge{From: InternetID, To: fmt.Sprintf("host:%04d", i%10), Kind: EdgeNetworkPolicy, Proto: ProtoTCP, Port: uint16(1 + i/10)})
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
		if err = b.AddNode(Node{ID: fmt.Sprintf("unk:%06d", i), Kind: NodeUnmanaged}); err != nil {
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
	// edges come in keep order (owner = the higher ID "to", then "from"),
	// so the first one past the limit ranks last and is dropped (an edge
	// ranking earlier would evict instead).
	mustNode(t, b, Node{ID: "unk:000000", Kind: NodeUnmanaged})
	for i = 0; i < MaxInputEdgesPerKind+5; i++ {
		if err = b.AddEdge(Edge{From: fmt.Sprintf("unk:%06d", i%1000), To: fmt.Sprintf("unk:%06d", 1000+i/1000), Kind: EdgeL2Adjacency}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrInputLimit) || i != MaxInputEdgesPerKind {
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
