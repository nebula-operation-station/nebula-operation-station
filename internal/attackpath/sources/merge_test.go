// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// labResults runs every adapter over the fixture stores. The lab: host
// "web" is PVE guest lab/100 (linked), "nas" a PVE guest without link,
// "exec" runs the executor, "quiet" has no traffic.
func labResults(t *testing.T) []Result {
	t.Helper()
	ctx := context.Background()
	hosts := fakeHosts{hosts: []inventory.Host{
		{ID: "exec", DisplayName: "executor"},
		{ID: "hv1", DisplayName: "hypervisor"},
		{ID: "nas", DisplayName: "nas"},
		{ID: "quiet", DisplayName: "quiet"},
		{ID: "web", DisplayName: "web"},
	}}
	creds, err := Credentials(ctx, CredentialConfig{Hosts: hosts, ExecutorHostID: "exec"})
	if err != nil {
		t.Fatal(err)
	}
	place, err := Placements(ctx, labPlacementConfig(labPVE()))
	if err != nil {
		t.Fatal(err)
	}
	fc := labFlowConfig(labFlows())
	fc.Hosts, fc.Managed, fc.Aliases = hosts, ManagedNodes(place), place.Aliases
	flows, err := Flows(ctx, fc)
	if err != nil {
		t.Fatal(err)
	}
	docker, err := Docker(ctx, DockerConfig{Reader: labDocker(), Hosts: hosts, Managed: ManagedNodes(place), Aliases: place.Aliases})
	if err != nil {
		t.Fatal(err)
	}
	return []Result{creds, flows, place, docker, FirewallPolicy(), VLANAdjacency()}
}

// renderReport is the golden text form of a Report.
func renderReport(rep Report) string {
	var b strings.Builder
	for _, s := range rep.Sources {
		fmt.Fprintf(&b, "source %s %s %d/%d\n", s.Source, s.Status, s.Coverage.Covered, s.Coverage.Total)
	}
	c := rep.Coverage()
	fmt.Fprintf(&b, "coverage %d/%d complete=%v rejected=%d input_limited=%d overflow=%d\n",
		c.Covered, c.Total, rep.Complete(), rep.Rejected, rep.InputLimited, rep.Overflow)
	for _, u := range rep.Uncertain {
		fmt.Fprintf(&b, "uncertain %s\n", u)
	}
	return b.String()
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs:\ngot\n%s\nwant\n%s", p, got, want)
	}
}

func TestLabMergeMatchesGolden(t *testing.T) {
	b := attackpath.NewBuilder()
	rep, err := Merge(b, labResults(t)...)
	if err != nil {
		t.Fatal(err)
	}
	g := b.Build()
	var snap bytes.Buffer
	if err := json.Indent(&snap, g.Snapshot(), "", "  "); err != nil {
		t.Fatal(err)
	}
	snap.WriteByte('\n')
	checkGolden(t, "lab.graph.golden.json", snap.Bytes())
	checkGolden(t, "lab.report.golden", []byte(renderReport(rep)))
}

func TestLabMergeIsOrderIndependent(t *testing.T) {
	rs := labResults(t)
	b1 := attackpath.NewBuilder()
	if _, err := Merge(b1, rs...); err != nil {
		t.Fatal(err)
	}
	rev := make([]Result, len(rs))
	for i, r := range rs {
		rev[len(rs)-1-i] = r
	}
	b2 := attackpath.NewBuilder()
	rep2, err := Merge(b2, rev...)
	if err != nil {
		t.Fatal(err)
	}
	if h1, h2 := b1.Build().Hash(), b2.Build().Hash(); h1 != h2 {
		t.Fatalf("hash depends on order: %s vs %s", h1, h2)
	}
	b3 := attackpath.NewBuilder()
	rep1, _ := Merge(b3, rs...)
	if renderReport(rep1) != renderReport(rep2) {
		t.Fatal("report depends on order")
	}
}

func TestMergeAliasesLinkedHostToGuest(t *testing.T) {
	b := attackpath.NewBuilder()
	if _, err := Merge(b, labResults(t)...); err != nil {
		t.Fatal(err)
	}
	g := b.Build()
	if _, ok := g.Node("host:web"); ok {
		t.Fatal("aliased host kept as its own node")
	}
	has := func(from, to string, k attackpath.EdgeKind) bool {
		for _, e := range g.Out(from) {
			if e.To == to && e.Kind == k {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		from, to string
		kind     attackpath.EdgeKind
	}{
		{"host:exec", "guest:lab/100", attackpath.EdgeCredential},
		{"host:exec", "pve:lab/pve1", attackpath.EdgeCredential},
		{"internet", "guest:lab/100", attackpath.EdgeNetworkObserved},
		{"pve:lab/pve1", "guest:lab/100", attackpath.EdgeControl},
		{"guest:lab/100", "ctr:web/aaaaaaaaaaaa", attackpath.EdgeControl},
		{"ctr:web/aaaaaaaaaaaa", "guest:lab/100", attackpath.EdgeEscape},
	} {
		if !has(c.from, c.to, c.kind) {
			t.Errorf("missing %s %s -> %s", c.kind, c.from, c.to)
		}
	}
	if n, _ := g.Node("host:nas"); n.Label != "nas" {
		t.Fatalf("label of host:nas = %q, want inventory label", n.Label)
	}
}

// reachable reports whether to can be reached from from over any edges.
func reachable(g *attackpath.Graph, from, to string) bool {
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if id == to {
			return true
		}
		for _, e := range g.Out(id) {
			if !seen[e.To] {
				seen[e.To] = true
				queue = append(queue, e.To)
			}
		}
	}
	return false
}

func TestGuestUnderPVEIsReachableFromExecutor(t *testing.T) {
	ctx := context.Background()
	creds, err := Credentials(ctx, CredentialConfig{
		Hosts:          fakeHosts{hosts: []inventory.Host{{ID: "exec"}, {ID: "hv1"}}},
		ExecutorHostID: "exec",
	})
	if err != nil {
		t.Fatal(err)
	}
	pve := &fakePVE{
		remotes: []pveinventory.Remote{{RemoteID: "lab"}},
		nodes:   map[string][]pveinventory.Node{"lab": {{Node: "pve1", State: avail}}},
		// Guest 200 is no managed host: only its PVE node leads to it.
		guests: map[string][]pveinventory.Guest{"lab": {{VMID: 200, Generation: 1, Node: "pve1", State: avail}}},
	}
	for name, c := range map[string]struct {
		nodeHosts map[string]string
		reach     bool
	}{
		"mapped":   {map[string]string{"pve:lab/pve1": "hv1"}, true},
		"unmapped": {nil, false},
	} {
		place, err := Placements(ctx, PlacementConfig{Reader: pve, NodeHosts: c.nodeHosts})
		if err != nil {
			t.Fatal(err)
		}
		b := attackpath.NewBuilder()
		rep, err := Merge(b, creds, place)
		if err != nil {
			t.Fatal(err)
		}
		g := b.Build()
		if got := reachable(g, "host:exec", "guest:lab/200"); got != c.reach {
			t.Fatalf("%s: guest reachable from executor = %v, want %v", name, got, c.reach)
		}
		if got := reachable(g, "host:exec", "pve:lab/pve1"); got != c.reach {
			t.Fatalf("%s: PVE node reachable from executor = %v, want %v", name, got, c.reach)
		}
		if !c.reach && !hasUncertainty(rep.Uncertain, UncertainPVEHostUnknown, "pve:lab/pve1") {
			t.Fatalf("%s: unreachable PVE node without uncertainty: %v", name, rep.Uncertain)
		}
		if c.reach {
			if _, ok := g.Node("host:hv1"); ok {
				t.Fatalf("%s: managed host and PVE node are two nodes", name)
			}
		}
	}
}

func TestMergeUnknownSourceIsNeverComplete(t *testing.T) {
	creds, err := Credentials(context.Background(), CredentialConfig{
		Hosts:          fakeHosts{hosts: []inventory.Host{{ID: "a"}, {ID: "b"}}},
		ExecutorHostID: "a",
	})
	if err != nil {
		t.Fatal(err)
	}
	others := append(coveringStubs([]string{"host:a", "host:b"}, SourceDocker, SourceFlows), completeStubs(SourcePlacements, SourceVLAN)...)
	rep, err := Merge(attackpath.NewBuilder(), append(others, creds, FirewallPolicy())...)
	if err != nil || rep.Complete() || rep.Coverage() != (Coverage{Covered: 2, Total: 3}) {
		t.Fatalf("with unknown firewall: %v complete=%v coverage %+v", err, rep.Complete(), rep.Coverage())
	}
	if rep, _ := Merge(attackpath.NewBuilder()); rep.Complete() {
		t.Fatal("no sources reads complete")
	}
}

// completeStubs returns an empty, completely read Result per source.
func completeStubs(names ...string) []Result {
	var rs []Result
	for _, n := range names {
		rs = append(rs, Result{Source: n, Status: StatusComplete})
	}
	return rs
}

func TestMergeAllRequiredSourcesCompleteIsComplete(t *testing.T) {
	rep, err := Merge(attackpath.NewBuilder(), completeStubs(RequiredSources()...)...)
	if err != nil || !rep.Complete() || len(rep.Missing) != 0 {
		t.Fatalf("all required sources complete: %v %+v", err, rep)
	}
}

func TestMergeMissingRequiredSourceIsNeverComplete(t *testing.T) {
	creds, err := Credentials(context.Background(), CredentialConfig{
		Hosts:          fakeHosts{hosts: []inventory.Host{{ID: "a"}, {ID: "b"}}},
		ExecutorHostID: "a",
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Merge(attackpath.NewBuilder(), creds)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{SourceDocker, SourceFirewall, SourceFlows, SourcePlacements, SourceVLAN}
	if rep.Complete() || !slices.Equal(rep.Missing, want) {
		t.Fatalf("credentials only: complete=%v missing %v", rep.Complete(), rep.Missing)
	}
	for _, s := range want {
		if !slices.Contains(rep.Uncertain, Uncertainty{Source: s, Kind: UncertainSourceMissing}) {
			t.Errorf("missing source %s not named in %v", s, rep.Uncertain)
		}
	}
	// Each missing source is one uncovered unit.
	if c := rep.Coverage(); c != (Coverage{Covered: 2, Total: 7}) {
		t.Fatalf("coverage %+v", c)
	}
	// Leaving out any single required source is never complete.
	for _, skip := range RequiredSources() {
		var rs []Result
		for _, s := range RequiredSources() {
			if s != skip {
				rs = append(rs, completeStubs(s)...)
			}
		}
		rep, err := Merge(attackpath.NewBuilder(), rs...)
		if err != nil || rep.Complete() || !slices.Equal(rep.Missing, []string{skip}) {
			t.Errorf("without %s: %v complete=%v missing %v", skip, err, rep.Complete(), rep.Missing)
		}
	}
}

func TestMergeCountsEvictedNodesAsInputLimited(t *testing.T) {
	// Fill the Builder's input cap with hosts, then offer a PVE node: it
	// ranks before every host, so the host kept last is evicted silently.
	r := Result{Source: SourceCredentials, Status: StatusComplete}
	for i := range attackpath.MaxInputNodes - 2 {
		r.Nodes = append(r.Nodes, attackpath.Node{ID: fmt.Sprintf("host:h%06d", i), Kind: attackpath.NodeHost})
	}
	last := r.Nodes[len(r.Nodes)-1].ID
	r.Nodes = append(r.Nodes, attackpath.Node{ID: "pve:lab/pve1", Kind: attackpath.NodePVENode})
	r.Edges = []attackpath.Edge{{From: "host:h000000", To: last, Kind: attackpath.EdgeCredential}}
	rs := append(completeStubs(SourceDocker, SourceFirewall, SourceFlows, SourcePlacements, SourceVLAN), r)
	b := attackpath.NewBuilder()
	rep, err := Merge(b, rs...)
	if err != nil || rep.Rejected != 0 {
		t.Fatalf("eviction counted as rejection: %v rejected %d", err, rep.Rejected)
	}
	// One evicted node and the edge into it.
	if rep.InputLimited != 2 || rep.Complete() {
		t.Fatalf("input_limited %d complete %v", rep.InputLimited, rep.Complete())
	}
	if _, ok := b.Build().Node(last); ok {
		t.Fatalf("%s not evicted", last)
	}
}

func TestMergeEdgeToRejectedNodeIsRejected(t *testing.T) {
	r := Result{Source: "test", Status: StatusComplete,
		Nodes: []attackpath.Node{
			{ID: "host:a", Kind: attackpath.NodeHost},
			{ID: "host:b", Kind: attackpath.NodeGuest}, // wrong namespace
		},
		Edges: []attackpath.Edge{{From: "host:a", To: "host:b", Kind: attackpath.EdgeCredential}},
	}
	rep, err := Merge(attackpath.NewBuilder(), r)
	if !errors.Is(err, ErrRejectedInput) || rep.Rejected != 2 || rep.InputLimited != 0 {
		t.Fatalf("err %v rejected %d input_limited %d", err, rep.Rejected, rep.InputLimited)
	}
}

func TestMergeRefusesUsedBuilder(t *testing.T) {
	b := attackpath.NewBuilder()
	if err := b.AddNode(attackpath.Node{ID: "host:x", Kind: attackpath.NodeHost}); err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(b, completeStubs(RequiredSources()...)...); err == nil {
		t.Fatal("non-empty builder accepted")
	}
}

func TestMergeRejectsInvalidInput(t *testing.T) {
	bad := Result{
		Source: "test",
		Status: StatusComplete,
		Nodes:  []attackpath.Node{{ID: "host:a", Kind: attackpath.NodeGuest}},
		Edges:  []attackpath.Edge{{From: "internet", To: "host:zz", Kind: attackpath.EdgeCredential}},
	}
	rep, err := Merge(attackpath.NewBuilder(), append(completeStubs(RequiredSources()...), bad)...)
	if !errors.Is(err, ErrRejectedInput) || rep.Rejected != 2 {
		t.Fatalf("err %v rejected %d", err, rep.Rejected)
	}
	if rep.Complete() || len(rep.Uncertain) != 0 || rep.InputLimited != 0 {
		t.Fatalf("rejected input reads complete: %+v", rep)
	}
	if _, err := Merge(nil); err == nil {
		t.Fatal("nil builder accepted")
	}
}

func TestMergeAliasConflictAcrossResults(t *testing.T) {
	a := Result{Source: SourcePlacements, Status: StatusComplete,
		Nodes:   []attackpath.Node{{ID: "guest:r1/1", Kind: attackpath.NodeGuest}},
		Aliases: map[string]string{"host:x": "guest:r1/1"}}
	b := Result{Source: SourcePlacements, Status: StatusComplete,
		Nodes:   []attackpath.Node{{ID: "guest:r2/1", Kind: attackpath.NodeGuest}},
		Aliases: map[string]string{"host:x": "guest:r2/1"}}
	c := Result{Source: SourceCredentials, Status: StatusComplete,
		Nodes: []attackpath.Node{{ID: "host:x", Kind: attackpath.NodeHost}}}
	bld := attackpath.NewBuilder()
	rep, err := Merge(bld, a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bld.Build().Node("host:x"); !ok || !hasUncertainty(rep.Uncertain, UncertainAliasConflict, "host:x") {
		t.Fatalf("conflicting alias applied: %+v", rep)
	}
}

func TestMergeOverBuildNodeCapIsNeverComplete(t *testing.T) {
	// More nodes than attackpath.MaxNodes but fewer than its input cap:
	// the Builder holds them all and drops the excess only in Build, so
	// no input limit fires. The report must still not read complete.
	r := Result{Source: SourceCredentials, Status: StatusComplete}
	for i := range attackpath.MaxNodes + 1 {
		r.Nodes = append(r.Nodes, attackpath.Node{ID: fmt.Sprintf("host:h%06d", i), Kind: attackpath.NodeHost})
	}
	rs := append(completeStubs(SourceDocker, SourceFirewall, SourceFlows, SourcePlacements, SourceVLAN), r)
	b := attackpath.NewBuilder()
	rep, err := Merge(b, rs...)
	if err != nil || rep.Rejected != 0 || rep.InputLimited != 0 {
		t.Fatalf("merge: %v rejected %d input_limited %d", err, rep.Rejected, rep.InputLimited)
	}
	if !b.Build().Truncated() {
		t.Fatal("fixture does not truncate the built graph")
	}
	if rep.Complete() || !rep.GraphTruncated {
		t.Fatalf("truncated graph: complete=%v graph_truncated=%v", rep.Complete(), rep.GraphTruncated)
	}
	if !slices.Contains(rep.Uncertain, Uncertainty{Source: SourceGraph, Kind: UncertainTruncated}) {
		t.Fatalf("truncation not named in %v", rep.Uncertain)
	}
}

func TestMergeOverBuildEdgeCapIsNeverComplete(t *testing.T) {
	// More edges than attackpath.MaxEdges, within one kind's input cap.
	const hosts = 300 // 300*299 possible credential edges > MaxEdges
	r := Result{Source: SourceCredentials, Status: StatusComplete}
	for i := range hosts {
		r.Nodes = append(r.Nodes, attackpath.Node{ID: fmt.Sprintf("host:h%03d", i), Kind: attackpath.NodeHost})
	}
	for i := range hosts {
		for j := range hosts {
			if i != j && len(r.Edges) <= attackpath.MaxEdges {
				r.Edges = append(r.Edges, attackpath.Edge{From: r.Nodes[i].ID, To: r.Nodes[j].ID, Kind: attackpath.EdgeCredential})
			}
		}
	}
	rs := append(completeStubs(SourceDocker, SourceFirewall, SourceFlows, SourcePlacements, SourceVLAN), r)
	b := attackpath.NewBuilder()
	rep, err := Merge(b, rs...)
	if err != nil || rep.Rejected != 0 || rep.InputLimited != 0 {
		t.Fatalf("merge: %v rejected %d input_limited %d", err, rep.Rejected, rep.InputLimited)
	}
	if !b.Build().Truncated() {
		t.Fatal("fixture does not truncate the built graph")
	}
	if rep.Complete() || !rep.GraphTruncated {
		t.Fatalf("truncated graph: complete=%v graph_truncated=%v", rep.Complete(), rep.GraphTruncated)
	}
}

func TestMergeUntruncatedGraphStaysComplete(t *testing.T) {
	r := Result{Source: SourceCredentials, Status: StatusComplete}
	var ids []string
	for i := range attackpath.MaxNodes - 2 { // plus the two entry nodes
		id := fmt.Sprintf("host:h%06d", i)
		ids = append(ids, id)
		r.Nodes = append(r.Nodes, attackpath.Node{ID: id, Kind: attackpath.NodeHost})
	}
	// Docker and flows cover every managed host of the graph.
	rs := append(coveringStubs(ids, SourceDocker, SourceFlows), r)
	rs = append(rs, completeStubs(SourceFirewall, SourcePlacements, SourceVLAN)...)
	rep, err := Merge(attackpath.NewBuilder(), rs...)
	if err != nil || !rep.Complete() || rep.GraphTruncated {
		t.Fatalf("graph at the cap: %v complete=%v graph_truncated=%v uncertain %d", err, rep.Complete(), rep.GraphTruncated, len(rep.Uncertain))
	}
	if c := rep.Coverage(); c.Covered != c.Total {
		t.Fatalf("coverage %+v", c)
	}
	// The same graph with empty Docker and flow results is not complete.
	rs = append(completeStubs(SourceDocker, SourceFirewall, SourceFlows, SourcePlacements, SourceVLAN), r)
	rep, err = Merge(attackpath.NewBuilder(), rs...)
	if err != nil || rep.Complete() {
		t.Fatalf("empty Docker and flows over %d hosts: %v complete=%v", len(ids), err, rep.Complete())
	}
}

// coveringStubs returns per source a completely read Result that covers
// the managed nodes ids.
func coveringStubs(ids []string, names ...string) []Result {
	var rs []Result
	for _, n := range names {
		rs = append(rs, Result{Source: n, Status: StatusComplete, Covered: slices.Clone(ids)})
	}
	return rs
}

// credsFor returns a complete credentials Result over the hosts ids, the
// first being the executor.
func credsFor(t *testing.T, ids ...string) Result {
	t.Helper()
	r, err := Credentials(context.Background(), CredentialConfig{Hosts: inventoryOf(ids...), ExecutorHostID: ids[0]})
	if err != nil || r.Status != StatusComplete {
		t.Fatalf("credentials: %v %s", err, r.Status)
	}
	return r
}

func TestMergeEmptyCompleteStubsAreIncomplete(t *testing.T) {
	// Docker and flows claim "complete" but cover none of the managed
	// hosts the credentials source put into the graph.
	rs := append(completeStubs(SourceDocker, SourceFirewall, SourceFlows, SourcePlacements, SourceVLAN), credsFor(t, "a", "b"))
	rep, err := Merge(attackpath.NewBuilder(), rs...)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete() {
		t.Fatal("empty Docker and flow results read complete")
	}
	for _, u := range []Uncertainty{
		{SourceDocker, UncertainDockerUnread, "host:a"},
		{SourceDocker, UncertainDockerUnread, "host:b"},
		{SourceFlows, UncertainNoFlows, "host:a"},
		{SourceFlows, UncertainNoFlows, "host:b"},
	} {
		if !slices.Contains(rep.Uncertain, u) {
			t.Errorf("missing %s in %v", u, rep.Uncertain)
		}
	}
	if rep.Uncovered != 4 {
		t.Errorf("uncovered %d, want 4", rep.Uncovered)
	}
	if c := rep.Coverage(); c != (Coverage{Covered: 2, Total: 6}) {
		t.Errorf("coverage %+v", c)
	}
}

func TestMergeNilHostsAdaptersAreIncomplete(t *testing.T) {
	// Docker and flows were wired with an empty host list: each reads
	// "complete" over nothing, while the graph holds managed hosts a, b,
	// a guest and a PVE node.
	ctx := context.Background()
	docker, err := Docker(ctx, DockerConfig{
		Reader: fakeDocker{hosts: []DockerHost{{HostID: "a", Complete: true}, {HostID: "b", Complete: true}}},
		Hosts:  fakeHosts{},
	})
	if err != nil {
		t.Fatal(err)
	}
	flows, err := Flows(ctx, FlowConfig{Reader: &fakeFlows{}, Hosts: fakeHosts{}, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	place := Result{Source: SourcePlacements, Status: StatusComplete, Nodes: []attackpath.Node{
		{ID: "guest:r/1", Kind: attackpath.NodeGuest},
		{ID: "pve:r/n1", Kind: attackpath.NodePVENode},
	}}
	rs := append(completeStubs(SourceFirewall, SourceVLAN), credsFor(t, "a", "b"), docker, flows, place)
	rep, err := Merge(attackpath.NewBuilder(), rs...)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete() {
		t.Fatalf("nil-host adapters read complete: %v", rep.Uncertain)
	}
	for _, id := range []string{"host:a", "host:b", "guest:r/1", "pve:r/n1"} {
		if !hasUncertainty(rep.Uncertain, UncertainDockerUnread, id) {
			t.Errorf("docker_unread %s missing in %v", id, rep.Uncertain)
		}
		if !hasUncertainty(rep.Uncertain, UncertainNoFlows, id) {
			t.Errorf("no_flows_observed %s missing in %v", id, rep.Uncertain)
		}
	}
	if c := rep.Coverage(); c.Covered == c.Total {
		t.Fatalf("coverage %+v", c)
	}

	// A partial Managed list: flows know host a only.
	out := flow("10.0.0.1", "203.0.113.9", flowagg.TCP, 443)
	out.ServerReported = true
	flows, err = Flows(ctx, FlowConfig{
		Reader: &fakeFlows{flows: []flowagg.FlowTotal{out}},
		Hosts:  inventoryOf("a"),
		Owners: []AddressOwner{owner("10.0.0.1", "host:a", attackpath.NodeHost)},
		Now:    func() time.Time { return fixedNow },
	})
	if err != nil || flows.Status != StatusComplete {
		t.Fatalf("flows over a: %v %s %v", err, flows.Status, flows.Uncertain)
	}
	rs = append(completeStubs(SourceFirewall, SourcePlacements, SourceVLAN), credsFor(t, "a", "b"), flows,
		coveringStubs([]string{"host:a", "host:b"}, SourceDocker)[0])
	rep, err = Merge(attackpath.NewBuilder(), rs...)
	if err != nil || rep.Complete() || !slices.Equal(rep.Uncertain, []Uncertainty{{SourceFlows, UncertainNoFlows, "host:b"}}) {
		t.Fatalf("partial managed list: %v complete=%v uncertain %v", err, rep.Complete(), rep.Uncertain)
	}
}

func TestMergeFullCoverageIsComplete(t *testing.T) {
	ctx := context.Background()
	hosts := inventoryOf("a", "b")
	docker, err := Docker(ctx, DockerConfig{
		Reader: fakeDocker{hosts: []DockerHost{{HostID: "a", Complete: true}, {HostID: "b", Complete: true}}},
		Hosts:  hosts,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := flow("10.0.0.1", "10.0.0.2", flowagg.TCP, 22)
	f.ServerReported = true
	flows, err := Flows(ctx, FlowConfig{
		Reader: &fakeFlows{flows: []flowagg.FlowTotal{f}},
		Hosts:  hosts,
		Owners: []AddressOwner{owner("10.0.0.1", "host:a", attackpath.NodeHost), owner("10.0.0.2", "host:b", attackpath.NodeHost)},
		Now:    func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	rs := append(completeStubs(SourceFirewall, SourcePlacements, SourceVLAN), credsFor(t, "a", "b"), docker, flows)
	rep, err := Merge(attackpath.NewBuilder(), rs...)
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Coverage(); !rep.Complete() || c.Covered != c.Total || rep.Uncovered != 0 {
		t.Fatalf("full coverage: complete=%v coverage %+v uncertain %v", rep.Complete(), c, rep.Uncertain)
	}
}

func TestCompleteRequiresFullCoverage(t *testing.T) {
	rep := Report{Sources: []SourceReport{{Source: SourceCredentials, Status: StatusComplete, Coverage: Coverage{Covered: 1, Total: 2}}}}
	if rep.Complete() {
		t.Fatal("coverage 1/2 reads complete")
	}
	rep = Report{Sources: []SourceReport{{Source: SourceCredentials, Status: StatusComplete}}, Uncovered: 1}
	if rep.Complete() {
		t.Fatal("uncovered graph node reads complete")
	}
}
