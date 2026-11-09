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
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
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
		{ID: "nas", DisplayName: "nas"},
		{ID: "quiet", DisplayName: "quiet"},
		{ID: "web", DisplayName: "web"},
	}}
	creds, err := Credentials(ctx, CredentialConfig{Hosts: hosts, ExecutorHostID: "exec"})
	if err != nil {
		t.Fatal(err)
	}
	flows, err := Flows(ctx, labFlowConfig(labFlows()))
	if err != nil {
		t.Fatal(err)
	}
	place, err := Placements(ctx, labPVE())
	if err != nil {
		t.Fatal(err)
	}
	docker, err := Docker(ctx, labDocker())
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

func TestMergeUnknownSourceIsNeverComplete(t *testing.T) {
	creds, err := Credentials(context.Background(), CredentialConfig{
		Hosts:          fakeHosts{hosts: []inventory.Host{{ID: "a"}, {ID: "b"}}},
		ExecutorHostID: "a",
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Merge(attackpath.NewBuilder(), creds)
	if err != nil || !rep.Complete() {
		t.Fatalf("complete credential source: %v %+v", err, rep)
	}
	rep, err = Merge(attackpath.NewBuilder(), creds, FirewallPolicy())
	if err != nil || rep.Complete() || rep.Coverage() != (Coverage{Covered: 2, Total: 3}) {
		t.Fatalf("with missing firewall: %v complete=%v coverage %+v", err, rep.Complete(), rep.Coverage())
	}
	if rep, _ := Merge(attackpath.NewBuilder()); rep.Complete() {
		t.Fatal("no sources reads complete")
	}
}

func TestMergeRejectsInvalidInput(t *testing.T) {
	bad := Result{
		Source: "test",
		Status: StatusComplete,
		Nodes:  []attackpath.Node{{ID: "host:a", Kind: attackpath.NodeGuest}},
		Edges:  []attackpath.Edge{{From: "internet", To: "host:zz", Kind: attackpath.EdgeCredential}},
	}
	rep, err := Merge(attackpath.NewBuilder(), bad)
	if !errors.Is(err, ErrRejectedInput) || rep.Rejected != 2 {
		t.Fatalf("err %v rejected %d", err, rep.Rejected)
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
