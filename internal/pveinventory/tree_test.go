// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the org-chart read model (ADR 0006, P1-15): the pure
// BuildTree function and the bounded ChartData store query. They cover
// the acceptance criteria: PVE/guest/bare-metal branches, Compose
// grouping, reviewed placements and full-ID incarnations, bounded
// queries, no duplicate counts for linked guests, no inferred SSH
// authority, and aggregate worst state and child counts per box.

package pveinventory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

var treeNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func freshAt() time.Time { return treeNow.Add(-30 * time.Second) }
func staleAt() time.Time { return treeNow.Add(-10 * time.Minute) }

func treeInput() TreeInput {
	return TreeInput{Now: treeNow}
}

func nodeIn(name string) NodeInput {
	return NodeInput{Node: name, Status: string(pvecontract.NodeOnline), State: StateAvailable, ObservedAt: freshAt()}
}

func guestIn(vmid uint64, node, name string) GuestInput {
	return GuestInput{
		VMID:       vmid,
		Generation: 1,
		Kind:       string(pvecontract.GuestQEMU),
		Node:       node,
		Name:       name,
		Status:     string(pvecontract.GuestRunning),
		State:      StateAvailable,
		ObservedAt: freshAt(),
	}
}

func hostIn(id string) HostInput {
	return HostInput{ID: id, DisplayName: id, OpsState: executions.StateReady}
}

func findBox(t *testing.T, boxes []Box, id string) Box {
	t.Helper()
	for _, b := range boxes {
		if b.ID == id {
			return b
		}
	}
	t.Fatalf("box %q not found (have %d boxes)", id, len(boxes))
	return Box{}
}

func TestBuildTreePVEBranchAndCounts(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Name:     "Lab A",
		Nodes:    []NodeInput{nodeIn("p1")},
		Guests:   []GuestInput{guestIn(200, "p1", "vm-200"), guestIn(100, "p1", "vm-100")},
	}}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if len(tree.Roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(tree.Roots))
	}
	root := tree.Roots[0]
	if root.Kind != KindPVENode || root.Name != "p1" || root.RemoteID != "remote-a" || root.RemoteName != "Lab A" {
		t.Fatalf("wrong root box: %+v", root)
	}
	if root.State != StateOK || root.Worst != StateOK {
		t.Fatalf("root state: %s/%s", root.State, root.Worst)
	}
	if root.Counts[KindGuest] != 2 {
		t.Fatalf("expected 2 guest children, got %d", root.Counts[KindGuest])
	}
	// Guests are ordered by VMID, not input order.
	if root.Children[0].VMID != 100 || root.Children[1].VMID != 200 {
		t.Fatalf("guests not ordered by vmid: %d, %d", root.Children[0].VMID, root.Children[1].VMID)
	}
	g := root.Children[0]
	if g.ID != "guest/remote-a/100/1" || g.Generation != 1 {
		t.Fatalf("wrong guest id: %+v", g)
	}
	if g.State != StateOK || len(g.Children) != 0 {
		t.Fatalf("running guest: state=%s children=%d", g.State, len(g.Children))
	}
}

func TestBuildTreeStoppedGuestIsOff(t *testing.T) {
	in := treeInput()
	g := guestIn(100, "p1", "vm-100")
	g.Status = string(pvecontract.GuestStopped)
	in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	gb := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
	if gb.State != StateOff {
		t.Fatalf("stopped guest state = %s, want off", gb.State)
	}
}

func TestBuildTreeBareMetalRootsWithContainersAndServices(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	h.DisplayName = "web-1"
	h.OS = "debian-12"
	h.Containers = []Container{
		{ID: "aaa", Name: "web1", Image: "nginx:1.27", State: "running", Project: "stack"},
		{ID: "bbb", Name: "web2", Image: "nginx:1.27", State: "running", Project: "stack"},
		{ID: "ccc", Name: "db", Image: "pg:16", State: "exited", Project: ""},
	}
	h.Services = []Service{
		{Name: "nginx.service", Active: "active"},
		{Name: "cron.service", Active: "inactive"},
	}
	in.Hosts = []HostInput{h}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if len(tree.Roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(tree.Roots))
	}
	root := tree.Roots[0]
	if root.Kind != KindHost || root.HostID != "h1" || root.Name != "web-1" {
		t.Fatalf("wrong host root: %+v", root)
	}
	// Compose group first (first-seen order), then standalone container,
	// then services.
	want := []struct {
		kind BoxKind
		id   string
	}{
		{KindCompose, "compose/h1/stack"},
		{KindContainer, "container/h1/ccc"},
		{KindService, "service/h1/nginx.service"},
		{KindService, "service/h1/cron.service"},
	}
	if len(root.Children) != len(want) {
		t.Fatalf("expected %d children, got %d", len(want), len(root.Children))
	}
	for i, w := range want {
		if root.Children[i].Kind != w.kind || root.Children[i].ID != w.id {
			t.Fatalf("child %d = %s %s, want %s %s", i, root.Children[i].Kind, root.Children[i].ID, w.kind, w.id)
		}
	}
	compose := root.Children[0]
	if compose.Name != "stack" || len(compose.Children) != 2 {
		t.Fatalf("compose box: %+v", compose)
	}
	if compose.Children[0].ID != "container/h1/aaa" || compose.Children[1].ID != "container/h1/bbb" {
		t.Fatalf("compose children order: %s, %s", compose.Children[0].ID, compose.Children[1].ID)
	}
	if root.Counts[KindCompose] != 1 || root.Counts[KindContainer] != 1 || root.Counts[KindService] != 2 {
		t.Fatalf("wrong counts: %+v", root.Counts)
	}
	// Exited container is off; the host aggregate is off (grey), since
	// off ranks above ok in the worst-state order (ADR: red > yellow >
	// grey for off/expected off > green).
	db := findBox(t, root.Children, "container/h1/ccc")
	if db.State != StateOff {
		t.Fatalf("exited container state = %s, want off", db.State)
	}
	if root.Worst != StateOff {
		t.Fatalf("host worst = %s, want off (off child)", root.Worst)
	}
	cron := findBox(t, root.Children, "service/h1/cron.service")
	if cron.State != StateOff || cron.Unit != "cron.service" {
		t.Fatalf("inactive service: %+v", cron)
	}
}

func TestBuildTreeHealthyComposeAggregation(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	h.Containers = []Container{
		{ID: "c1", State: "running", Health: "healthy", Project: "stack"},
		{ID: "c2", State: "running", Health: "healthy", Project: "stack"},
	}
	in.Hosts = []HostInput{h}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	compose := findBox(t, tree.Roots[0].Children, "compose/h1/stack")
	if compose.State != StateOK || compose.Worst != StateOK {
		t.Fatalf("healthy compose state = %q/%q, want ok/ok", compose.State, compose.Worst)
	}
	if compose.Counts[KindContainer] != 2 || tree.Roots[0].Worst != StateOK {
		t.Fatalf("healthy compose counts = %v, host worst = %s", compose.Counts, tree.Roots[0].Worst)
	}
}

func TestBuildTreeHostStalenessPropagatesToObservations(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, stale := range []bool{false, true} {
			t.Run(fmt.Sprintf("linked=%v/stale=%v", linked, stale), func(t *testing.T) {
				in := treeInput()
				h := hostIn("h1")
				h.Stale = stale
				h.Containers = []Container{
					{ID: "running", State: "running", Health: "healthy"},
					{ID: "exited", State: "exited"},
					{ID: "compose-running", State: "running", Health: "healthy", Project: "stack"},
					{ID: "compose-exited", State: "exited", Project: "stack"},
					{ID: "unhealthy", State: "running", Health: "unhealthy"},
					{ID: "paused", State: "paused"},
				}
				h.Services = []Service{
					{Name: "active.service", Active: "active"},
					{Name: "inactive.service", Active: "inactive"},
					{Name: "failed.service", Active: "failed"},
				}
				in.Hosts = []HostInput{h}
				if linked {
					in.Remotes = []RemoteInput{{
						RemoteID: "remote-a",
						Nodes:    []NodeInput{nodeIn("p1")},
						Guests:   []GuestInput{guestIn(100, "p1", "vm-100")},
					}}
					in.Links = []HostLink{{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "h1"}}
				}
				tree, err := BuildTree(in)
				if err != nil {
					t.Fatalf("BuildTree: %v", err)
				}
				parent := tree.Roots[0]
				if linked {
					parent = findBox(t, parent.Children, "guest/remote-a/100/1")
				}
				wantParent := StateOK
				if stale {
					wantParent = StateUnknown
				}
				if parent.Stale != stale || parent.State != wantParent {
					t.Errorf("parent stale=%v state=%s, want %v/%s", parent.Stale, parent.State, stale, wantParent)
				}
				compose := findBox(t, parent.Children, "compose/h1/stack")
				for _, tc := range []struct {
					id    string
					state BoxState
				}{
					{"container/h1/running", StateOK},
					{"container/h1/exited", StateOff},
					{"container/h1/compose-running", StateOK},
					{"container/h1/compose-exited", StateOff},
					{"container/h1/unhealthy", StateCritical},
					{"container/h1/paused", StateWarning},
					{"service/h1/active.service", StateOK},
					{"service/h1/inactive.service", StateOff},
					{"service/h1/failed.service", StateCritical},
				} {
					b := findBox(t, append(parent.Children, compose.Children...), tc.id)
					want := tc.state
					if stale && StateRank(want) < StateRank(StateUnknown) {
						want = StateUnknown
					}
					if b.Stale != stale || b.State != want || b.Worst != want {
						t.Errorf("%s stale=%v state=%s/%s, want %v/%s/%s", tc.id, b.Stale, b.State, b.Worst, stale, want, want)
					}
					if stale && want == StateUnknown && b.StateReason != "stale" {
						t.Errorf("%s reason=%q, want stale", tc.id, b.StateReason)
					}
				}
				if stale && (!compose.Stale || compose.State != StateUnknown || compose.Worst != StateUnknown || compose.StateReason != "stale") {
					t.Errorf("stale compose: %+v", compose)
				}
			})
		}
	}
}

func TestBuildTreeWorstStateAggregation(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	h.Services = []Service{{Name: "bad.service", Active: "failed"}}
	h.Containers = []Container{{ID: "c1", Name: "c1", State: "running", Health: "unhealthy"}}
	in.Hosts = []HostInput{h}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	root := tree.Roots[0]
	if root.State != StateOK {
		t.Fatalf("host own state = %s, want ok (ops ready)", root.State)
	}
	if root.Worst != StateCritical {
		t.Fatalf("host worst = %s, want critical", root.Worst)
	}
	if bad := findBox(t, root.Children, "service/h1/bad.service"); bad.State != StateCritical {
		t.Fatalf("failed service state = %s", bad.State)
	}
	if c := findBox(t, root.Children, "container/h1/c1"); c.State != StateCritical {
		t.Fatalf("unhealthy container state = %s", c.State)
	}

	// A critical guest propagates to its node root.
	g := guestIn(100, "p1", "vm-100")
	g.State = StateUnavailable
	g.Reason = "not read"
	in2 := treeInput()
	in2.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}
	tree2, err := BuildTree(in2)
	if err != nil {
		t.Fatalf("BuildTree 2: %v", err)
	}
	if tree2.Roots[0].Worst != StateUnknown {
		t.Fatalf("node worst = %s, want unknown (unavailable guest dataset)", tree2.Roots[0].Worst)
	}
}

func TestBuildTreeUpdatesAndRebootAreWarning(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	h.UpdatesTotal = 5
	in.Hosts = []HostInput{h}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if tree.Roots[0].State != StateWarning || tree.Roots[0].Worst != StateWarning {
		t.Fatalf("updates host state = %s/%s, want warning", tree.Roots[0].State, tree.Roots[0].Worst)
	}

	in = treeInput()
	h = hostIn("h1")
	h.RebootRequired = true
	in.Hosts = []HostInput{h}
	tree, err = BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree reboot: %v", err)
	}
	if tree.Roots[0].State != StateWarning {
		t.Fatalf("reboot host state = %s, want warning", tree.Roots[0].State)
	}
}

func TestBuildTreeBlockedKeyIsCritical(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	h.KeyBlocked = true
	in.Hosts = []HostInput{h}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if tree.Roots[0].State != StateCritical {
		t.Fatalf("blocked host state = %s, want critical", tree.Roots[0].State)
	}
}

func TestBuildTreeLinkedGuestAttachesHostOnce(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1")},
		Guests:   []GuestInput{guestIn(100, "p1", "vm-100")},
	}}
	h := hostIn("h1")
	h.Containers = []Container{{ID: "c1", Name: "c1", State: "running"}}
	h.Services = []Service{{Name: "nginx.service", Active: "active"}}
	in.Hosts = []HostInput{h}
	in.Links = []HostLink{{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "h1"}}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	// The linked host is not a separate root: exactly one root (the node).
	if len(tree.Roots) != 1 || tree.Roots[0].Kind != KindPVENode {
		t.Fatalf("expected only the node root, got %d roots", len(tree.Roots))
	}
	g := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
	if g.HostID != "h1" {
		t.Fatalf("guest HostID = %q, want h1", g.HostID)
	}
	if len(g.Children) != 2 {
		t.Fatalf("linked guest children = %d, want 2", len(g.Children))
	}
	if g.Counts[KindContainer] != 1 || g.Counts[KindService] != 1 {
		t.Fatalf("linked guest counts: %+v", g.Counts)
	}
	// The node counts the guest once.
	if tree.Roots[0].Counts[KindGuest] != 1 {
		t.Fatalf("node guest count = %d, want 1", tree.Roots[0].Counts[KindGuest])
	}
}

func TestBuildTreeOffParentDoesNotMaskCriticalChild(t *testing.T) {
	in := treeInput()
	g := guestIn(100, "p1", "vm-100")
	g.Status = string(pvecontract.GuestStopped)
	in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}
	h := hostIn("h1")
	h.OpsState = executions.StateUnreachable
	in.Hosts = []HostInput{h}
	in.Links = []HostLink{{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "h1"}}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	gb := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
	if gb.State != StateCritical {
		t.Fatalf("linked stopped+unreachable guest state = %s, want critical", gb.State)
	}
	if tree.Roots[0].Worst != StateCritical {
		t.Fatalf("node worst = %s, want critical", tree.Roots[0].Worst)
	}
}

func TestBuildTreeNoSSHAuthorityInferred(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1")},
		Guests:   []GuestInput{guestIn(100, "p1", "vm-100")},
	}}
	// A managed host with the same name as the guest and its own
	// observations. Without a reviewed link nothing may attach to the
	// guest.
	h := hostIn("h1")
	h.DisplayName = "vm-100"
	h.Containers = []Container{{ID: "c1", Name: "c1", State: "running"}}
	in.Hosts = []HostInput{h}

	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	g := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
	if g.HostID != "" {
		t.Fatalf("guest HostID = %q, want empty (no link)", g.HostID)
	}
	if len(g.Children) != 0 {
		t.Fatalf("unlinked guest has %d children, want 0", len(g.Children))
	}
	// The host stays a bare-metal root with its own observations.
	if len(tree.Roots) != 2 {
		t.Fatalf("expected 2 roots, got %d", len(tree.Roots))
	}
	hostRoot := findBox(t, tree.Roots, "host/h1")
	if len(hostRoot.Children) != 1 {
		t.Fatalf("host root children = %d, want 1", len(hostRoot.Children))
	}
}

func TestBuildTreeLinksToUnknownTargetsIgnored(t *testing.T) {
	// Link to a guest that is not observed: ignored, host stays a root.
	in := treeInput()
	h := hostIn("h1")
	in.Hosts = []HostInput{h}
	in.Links = []HostLink{{RemoteID: "remote-a", VMID: 999, Generation: 1, HostID: "h1"}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if len(tree.Roots) != 1 || tree.Roots[0].ID != "host/h1" {
		t.Fatalf("unknown-guest link must not consume the host: %+v", tree.Roots)
	}

	// Link to a host that is not in the inventory: ignored, guest has no
	// observations.
	in = treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1")},
		Guests:   []GuestInput{guestIn(100, "p1", "vm-100")},
	}}
	in.Links = []HostLink{{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "ghost"}}
	tree, err = BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree 2: %v", err)
	}
	g := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
	if g.HostID != "" || len(g.Children) != 0 {
		t.Fatalf("unknown-host link must not attach observations: %+v", g)
	}
}

func TestBuildTreeHostLinkedToTwoGuestsIsError(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1")},
		Guests:   []GuestInput{guestIn(100, "p1", "vm-100"), guestIn(110, "p1", "vm-110")},
	}}
	in.Hosts = []HostInput{hostIn("h1")}
	in.Links = []HostLink{
		{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "h1"},
		{RemoteID: "remote-a", VMID: 110, Generation: 1, HostID: "h1"},
	}
	if _, err := BuildTree(in); err == nil {
		t.Fatal("expected error for a host linked to two guests")
	}
}

func TestBuildTreeDuplicateIdentitiesAreErrors(t *testing.T) {
	mk := func() TreeInput {
		in := treeInput()
		in.Remotes = []RemoteInput{{
			RemoteID: "remote-a",
			Nodes:    []NodeInput{nodeIn("p1")},
			Guests:   []GuestInput{guestIn(100, "p1", "vm-100")},
		}}
		in.Hosts = []HostInput{hostIn("h1")}
		return in
	}
	cases := []struct {
		name    string
		mutate  func(in *TreeInput)
		wantSub string
	}{
		{
			name: "duplicate remote id",
			mutate: func(in *TreeInput) {
				in.Remotes = append(in.Remotes, RemoteInput{RemoteID: "remote-a"})
			},
			wantSub: "remote",
		},
		{
			name: "duplicate node name in remote",
			mutate: func(in *TreeInput) {
				in.Remotes[0].Nodes = append(in.Remotes[0].Nodes, nodeIn("p1"))
			},
			wantSub: "node",
		},
		{
			name: "duplicate guest incarnation in remote",
			mutate: func(in *TreeInput) {
				in.Remotes[0].Guests = append(in.Remotes[0].Guests, guestIn(100, "p1", "vm-100-copy"))
			},
			wantSub: "guest",
		},
		{
			name: "duplicate host id",
			mutate: func(in *TreeInput) {
				in.Hosts = append(in.Hosts, hostIn("h1"))
			},
			wantSub: "host",
		},
		{
			name: "duplicate container id per host",
			mutate: func(in *TreeInput) {
				in.Hosts[0].Containers = []Container{
					{ID: "c1", Name: "a", State: "running"},
					{ID: "c1", Name: "b", State: "running"},
				}
			},
			wantSub: "container",
		},
		{
			name: "duplicate service name per host",
			mutate: func(in *TreeInput) {
				in.Hosts[0].Services = []Service{
					{Name: "a.service", Active: "active"},
					{Name: "a.service", Active: "active"},
				}
			},
			wantSub: "service",
		},
		{
			name: "duplicate link",
			mutate: func(in *TreeInput) {
				in.Links = []HostLink{
					{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "h1"},
					{RemoteID: "remote-a", VMID: 100, Generation: 1, HostID: "h1"},
				}
			},
			wantSub: "link",
		},
		{
			name: "empty container id",
			mutate: func(in *TreeInput) {
				in.Hosts[0].Containers = []Container{{ID: "", Name: "a", State: "running"}}
			},
			wantSub: "container",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := mk()
			tc.mutate(&in)
			_, err := BuildTree(in)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !containsFold(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func containsFold(s, sub string) bool {
	return len(sub) > 0 && indexOfFold(s, sub) >= 0
}

func indexOfFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestBuildTreeLimits(t *testing.T) {
	t.Run("remotes", func(t *testing.T) {
		in := treeInput()
		for i := 0; i <= MaxTreeRemotes; i++ {
			in.Remotes = append(in.Remotes, RemoteInput{RemoteID: fmt.Sprintf("r%d", i)})
		}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many remotes")
		}
	})
	t.Run("nodes per remote", func(t *testing.T) {
		in := treeInput()
		rem := RemoteInput{RemoteID: "remote-a"}
		for i := 0; i <= MaxTreeNodesPerRemote; i++ {
			rem.Nodes = append(rem.Nodes, NodeInput{Node: fmt.Sprintf("n%d", i), Status: string(pvecontract.NodeOnline), State: StateAvailable, ObservedAt: freshAt()})
		}
		in.Remotes = []RemoteInput{rem}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many nodes")
		}
	})
	t.Run("guests per remote", func(t *testing.T) {
		in := treeInput()
		rem := RemoteInput{RemoteID: "remote-a"}
		for i := 0; i <= MaxTreeGuestsPerRemote; i++ {
			rem.Guests = append(rem.Guests, GuestInput{VMID: uint64(i + 1), Generation: 1, Node: "p1", Name: fmt.Sprintf("g%d", i), Status: string(pvecontract.GuestRunning), State: StateAvailable, ObservedAt: freshAt()})
		}
		in.Remotes = []RemoteInput{rem}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many guests")
		}
	})
	t.Run("hosts", func(t *testing.T) {
		in := treeInput()
		for i := 0; i <= MaxTreeHosts; i++ {
			in.Hosts = append(in.Hosts, HostInput{ID: fmt.Sprintf("h%d", i), OpsState: executions.StateReady})
		}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many hosts")
		}
	})
	t.Run("containers per host", func(t *testing.T) {
		in := treeInput()
		h := hostIn("h1")
		for i := 0; i <= MaxTreeContainers; i++ {
			h.Containers = append(h.Containers, Container{ID: fmt.Sprintf("c%d", i), Name: fmt.Sprintf("c%d", i), State: "running"})
		}
		in.Hosts = []HostInput{h}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many containers")
		}
	})
	t.Run("services per host", func(t *testing.T) {
		in := treeInput()
		h := hostIn("h1")
		for i := 0; i <= MaxTreeServices; i++ {
			h.Services = append(h.Services, Service{Name: fmt.Sprintf("s%d.service", i), Active: "active"})
		}
		in.Hosts = []HostInput{h}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many services")
		}
	})
	t.Run("links", func(t *testing.T) {
		in := treeInput()
		for i := 0; i <= MaxTreeLinks; i++ {
			in.Links = append(in.Links, HostLink{RemoteID: "remote-x", VMID: uint64(i + 1), Generation: 1, HostID: "ghost"})
		}
		if _, err := BuildTree(in); err == nil {
			t.Fatal("expected error for too many links")
		}
	})
}

func TestBuildTreeStaleness(t *testing.T) {
	t.Run("fresh guest is ok", func(t *testing.T) {
		in := treeInput()
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{guestIn(100, "p1", "vm-100")}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		g := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
		if g.Stale || g.State != StateOK {
			t.Fatalf("fresh guest: stale=%v state=%s", g.Stale, g.State)
		}
	})
	t.Run("stale running guest is unknown, not ok", func(t *testing.T) {
		in := treeInput()
		g := guestIn(100, "p1", "vm-100")
		g.ObservedAt = staleAt()
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		gb := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
		if !gb.Stale || gb.State != StateUnknown {
			t.Fatalf("stale guest: stale=%v state=%s, want stale unknown", gb.Stale, gb.State)
		}
	})
	t.Run("stale stopped guest is unknown, not off", func(t *testing.T) {
		in := treeInput()
		g := guestIn(100, "p1", "vm-100")
		g.Status = string(pvecontract.GuestStopped)
		g.ObservedAt = staleAt()
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		gb := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
		if !gb.Stale || gb.State != StateUnknown {
			t.Fatalf("stale stopped guest: stale=%v state=%s, want stale unknown", gb.Stale, gb.State)
		}
	})
	t.Run("stale node is unknown", func(t *testing.T) {
		in := treeInput()
		n := nodeIn("p1")
		n.ObservedAt = staleAt()
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{n}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		if !tree.Roots[0].Stale || tree.Roots[0].State != StateUnknown {
			t.Fatalf("stale node: stale=%v state=%s, want stale unknown", tree.Roots[0].Stale, tree.Roots[0].State)
		}
	})
	t.Run("stale host is unknown", func(t *testing.T) {
		in := treeInput()
		h := hostIn("h1")
		h.Stale = true
		in.Hosts = []HostInput{h}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		if !tree.Roots[0].Stale || tree.Roots[0].State != StateUnknown {
			t.Fatalf("stale host: stale=%v state=%s, want stale unknown", tree.Roots[0].Stale, tree.Roots[0].State)
		}
	})
	t.Run("custom stale threshold", func(t *testing.T) {
		in := treeInput()
		in.StaleAfter = time.Hour
		g := guestIn(100, "p1", "vm-100")
		g.ObservedAt = treeNow.Add(-30 * time.Minute) // stale at 3m, fresh at 1h
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		gb := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
		if gb.Stale || gb.State != StateOK {
			t.Fatalf("custom threshold: stale=%v state=%s, want fresh ok", gb.Stale, gb.State)
		}
	})
	t.Run("zero observed time is stale", func(t *testing.T) {
		in := treeInput()
		g := guestIn(100, "p1", "vm-100")
		g.ObservedAt = time.Time{}
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Guests: []GuestInput{g}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		gb := findBox(t, tree.Roots[0].Children, "guest/remote-a/100/1")
		if !gb.Stale || gb.State != StateUnknown {
			t.Fatalf("zero observed: stale=%v state=%s, want stale unknown", gb.Stale, gb.State)
		}
	})
}

func TestBuildTreeComposeGroupingOrder(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	h.Containers = []Container{
		{ID: "c1", Name: "a", State: "running", Project: "p2"},
		{ID: "c2", Name: "b", State: "running", Project: "p1"},
		{ID: "c3", Name: "c", State: "running", Project: "p2"},
		{ID: "c4", Name: "d", State: "running", Project: ""},
		{ID: "c5", Name: "e", State: "running", Project: "p1"},
	}
	in.Hosts = []HostInput{h}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	root := tree.Roots[0]
	// Groups in first-seen order: p2, p1; standalone last.
	if len(root.Children) != 3 {
		t.Fatalf("expected 3 children, got %d", len(root.Children))
	}
	if root.Children[0].ID != "compose/h1/p2" || root.Children[1].ID != "compose/h1/p1" || root.Children[2].ID != "container/h1/c4" {
		t.Fatalf("grouping order: %s, %s, %s", root.Children[0].ID, root.Children[1].ID, root.Children[2].ID)
	}
	if len(root.Children[0].Children) != 2 || len(root.Children[1].Children) != 2 {
		t.Fatalf("group sizes: %d, %d", len(root.Children[0].Children), len(root.Children[1].Children))
	}
}

func TestBuildTreeReplicasAreDistinctBoxes(t *testing.T) {
	in := treeInput()
	h := hostIn("h1")
	// Two replicas: same name and project, distinct full IDs.
	h.Containers = []Container{
		{ID: "aaaa", Name: "web", State: "running", Project: "stack"},
		{ID: "bbbb", Name: "web", State: "running", Project: "stack"},
	}
	in.Hosts = []HostInput{h}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	compose := findBox(t, tree.Roots[0].Children, "compose/h1/stack")
	if len(compose.Children) != 2 {
		t.Fatalf("replicas: %d boxes, want 2", len(compose.Children))
	}
	if compose.Children[0].ID != "container/h1/aaaa" || compose.Children[1].ID != "container/h1/bbbb" {
		t.Fatalf("replica ids: %s, %s", compose.Children[0].ID, compose.Children[1].ID)
	}
}

func TestBuildTreeContainerStates(t *testing.T) {
	cases := []struct {
		state  string
		health string
		want   BoxState
	}{
		{"running", "", StateOK},
		{"running", "healthy", StateOK},
		{"running", "unhealthy", StateCritical},
		{"exited", "", StateOff},
		{"dead", "", StateOff},
		{"created", "", StateOff},
		{"paused", "", StateWarning},
		{"restarting", "", StateWarning},
		{"weird", "", StateUnknown},
	}
	for _, tc := range cases {
		in := treeInput()
		h := hostIn("h1")
		h.Containers = []Container{{ID: "c1", Name: "c1", State: tc.state, Health: tc.health}}
		in.Hosts = []HostInput{h}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree %s: %v", tc.state, err)
		}
		got := findBox(t, tree.Roots[0].Children, "container/h1/c1").State
		if got != tc.want {
			t.Fatalf("container state %q health %q = %s, want %s", tc.state, tc.health, got, tc.want)
		}
	}
}

func TestBuildTreeServiceStates(t *testing.T) {
	cases := []struct {
		active string
		want   BoxState
	}{
		{"active", StateOK},
		{"failed", StateCritical},
		{"inactive", StateOff},
		{"activating", StateUnknown},
		{"", StateUnknown},
	}
	for _, tc := range cases {
		in := treeInput()
		h := hostIn("h1")
		h.Services = []Service{{Name: "a.service", Active: tc.active}}
		in.Hosts = []HostInput{h}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree %q: %v", tc.active, err)
		}
		got := findBox(t, tree.Roots[0].Children, "service/h1/a.service").State
		if got != tc.want {
			t.Fatalf("service active %q = %s, want %s", tc.active, got, tc.want)
		}
	}
}

func TestBuildTreeNodeStates(t *testing.T) {
	cases := []struct {
		status string
		state  DatasetState
		want   BoxState
	}{
		{string(pvecontract.NodeOnline), StateAvailable, StateOK},
		{string(pvecontract.NodeOffline), StateAvailable, StateOff},
		{"maintenance", StateAvailable, StateUnknown},
		{string(pvecontract.NodeOnline), StateUnavailable, StateUnknown},
	}
	for _, tc := range cases {
		in := treeInput()
		n := NodeInput{Node: "p1", Status: tc.status, State: tc.state, ObservedAt: freshAt()}
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{n}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree %s: %v", tc.status, err)
		}
		if tree.Roots[0].State != tc.want {
			t.Fatalf("node status %q state %s = %s, want %s", tc.status, tc.state, tree.Roots[0].State, tc.want)
		}
	}
}

func TestBuildTreeImplicitNodeForOrphanGuest(t *testing.T) {
	in := treeInput()
	// The guest dataset names a node the node dataset did not report.
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Guests:   []GuestInput{guestIn(100, "ghost", "vm-100")},
	}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if len(tree.Roots) != 1 || tree.Roots[0].Kind != KindPVENode || tree.Roots[0].Name != "ghost" {
		t.Fatalf("expected implicit node root, got %+v", tree.Roots)
	}
	if tree.Roots[0].State != StateUnknown {
		t.Fatalf("implicit node state = %s, want unknown", tree.Roots[0].State)
	}
	if len(tree.Roots[0].Children) != 1 {
		t.Fatalf("implicit node children = %d, want 1", len(tree.Roots[0].Children))
	}
}

func TestBuildTreeRootOrdering(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{
		{RemoteID: "remote-a", Name: "A", Nodes: []NodeInput{nodeIn("a1"), nodeIn("a2")}},
		{RemoteID: "remote-b", Name: "B", Nodes: []NodeInput{nodeIn("b1")}},
	}
	in.Hosts = []HostInput{hostIn("h2"), hostIn("h1")}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	want := []string{"node/remote-a/a1", "node/remote-a/a2", "node/remote-b/b1", "host/h2", "host/h1"}
	if len(tree.Roots) != len(want) {
		t.Fatalf("expected %d roots, got %d", len(want), len(tree.Roots))
	}
	for i, id := range want {
		if tree.Roots[i].ID != id {
			t.Fatalf("root %d = %s, want %s", i, tree.Roots[i].ID, id)
		}
	}
}

func TestBuildTreeEmptyInput(t *testing.T) {
	tree, err := BuildTree(treeInput())
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if len(tree.Roots) != 0 {
		t.Fatalf("expected no roots, got %d", len(tree.Roots))
	}
}

func TestBuildTreeStateRank(t *testing.T) {
	if !(StateRank(StateCritical) > StateRank(StateWarning) &&
		StateRank(StateWarning) > StateRank(StateUnknown) &&
		StateRank(StateUnknown) > StateRank(StateOff) &&
		StateRank(StateOff) > StateRank(StateOK)) {
		t.Fatal("state rank order is wrong")
	}
}

// --- ChartData store query ---

func seedChartStore(t *testing.T) *Store {
	t.Helper()
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote A: %v", err)
	}
	if err := s.UpsertRemote(ctx, remoteB()); err != nil {
		t.Fatalf("UpsertRemote B: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsA().
		nodes(mkNode("p1"), mkNode("p2")).
		guests(mkGuest(100, 1, "vm-100"), mkGuest(110, 1, "vm-110"), mkGuest(120, 1, "vm-120")).
		storages(
			onNode(mkStorage("local-lvm", "lvmthin", 100<<30, 10<<30), "p1", false),
			onNode(mkStorage("shared-nfs", "nfs", 1<<40, 500<<30), "p1", true),
			onNode(mkStorage("pbs-backup", "pbs", 0, 0), "p1", true),
		).
		build()); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsB().
		nodes(mkNode("q1")).
		guests(mkGuest(100, 1, "vm-b100")).
		storages(onNode(mkStorage("local-dir", "dir", 10<<30, 9<<30), "q1", false)).
		build()); err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	return s
}

func TestChartDataBoundedQueries(t *testing.T) {
	s := seedChartStore(t)
	ctx := context.Background()

	data, err := s.ChartData(ctx, ChartQuery{})
	if err != nil {
		t.Fatalf("ChartData: %v", err)
	}
	if len(data.Remotes) != 2 {
		t.Fatalf("expected 2 remotes, got %d", len(data.Remotes))
	}
	if len(data.Nodes["remote-a"]) != 2 || len(data.Guests["remote-a"]) != 3 {
		t.Fatalf("remote-a: %d nodes, %d guests", len(data.Nodes["remote-a"]), len(data.Guests["remote-a"]))
	}
	if len(data.Nodes["remote-b"]) != 1 || len(data.Guests["remote-b"]) != 1 {
		t.Fatalf("remote-b: %d nodes, %d guests", len(data.Nodes["remote-b"]), len(data.Guests["remote-b"]))
	}
	if data.Remotes[0].RemoteID != "remote-a" || data.Remotes[0].Name != "Lab A" {
		t.Fatalf("remote order/content: %+v", data.Remotes[0])
	}

	// Remote filter.
	data, err = s.ChartData(ctx, ChartQuery{RemoteID: "remote-a"})
	if err != nil {
		t.Fatalf("ChartData filter: %v", err)
	}
	if len(data.Remotes) != 1 || len(data.Guests["remote-a"]) != 3 {
		t.Fatalf("filtered: %d remotes, %d guests", len(data.Remotes), len(data.Guests["remote-a"]))
	}

	// Unknown remote fails closed.
	if _, err = s.ChartData(ctx, ChartQuery{RemoteID: "missing"}); !errors.Is(err, ErrRemoteNotFound) {
		t.Fatalf("unknown remote err = %v, want ErrRemoteNotFound", err)
	}

	// Bounded remotes: only the first remote by id.
	data, err = s.ChartData(ctx, ChartQuery{MaxRemotes: 1})
	if err != nil {
		t.Fatalf("ChartData MaxRemotes: %v", err)
	}
	if len(data.Remotes) != 1 || data.Remotes[0].RemoteID != "remote-a" {
		t.Fatalf("bounded remotes: %+v", data.Remotes)
	}

	// Bounded guests: truncated in vmid order.
	data, err = s.ChartData(ctx, ChartQuery{RemoteID: "remote-a", MaxGuests: 2})
	if err != nil {
		t.Fatalf("ChartData MaxGuests: %v", err)
	}
	if len(data.Guests["remote-a"]) != 2 || data.Guests["remote-a"][0].VMID != 100 || data.Guests["remote-a"][1].VMID != 110 {
		t.Fatalf("bounded guests: %+v", data.Guests["remote-a"])
	}

	// Bounded nodes.
	data, err = s.ChartData(ctx, ChartQuery{RemoteID: "remote-a", MaxNodes: 1})
	if err != nil {
		t.Fatalf("ChartData MaxNodes: %v", err)
	}
	if len(data.Nodes["remote-a"]) != 1 || data.Nodes["remote-a"][0].Node != "p1" {
		t.Fatalf("bounded nodes: %+v", data.Nodes["remote-a"])
	}

	// Limits above the maximum are rejected.
	for _, q := range []ChartQuery{
		{MaxRemotes: MaxTreeRemotes + 1},
		{MaxNodes: MaxTreeNodesPerRemote + 1},
		{MaxGuests: MaxTreeGuestsPerRemote + 1},
		{MaxStorages: MaxStoragesQuery + 1},
	} {
		if _, err := s.ChartData(ctx, q); err == nil {
			t.Fatalf("expected error for limit %d above maximum", q.MaxRemotes)
		}
	}
}

func TestChartDataStorages(t *testing.T) {
	s := seedChartStore(t)
	ctx := context.Background()

	data, err := s.ChartData(ctx, ChartQuery{})
	if err != nil {
		t.Fatalf("ChartData: %v", err)
	}
	// Storages are returned per remote, ordered by storage name.
	gotA := data.Storages["remote-a"]
	if len(gotA) != 3 {
		t.Fatalf("remote-a storages: %d, want 3", len(gotA))
	}
	wantA := []struct {
		name string
		typ  string
	}{
		{"local-lvm", "lvmthin"},
		{"pbs-backup", "pbs"},
		{"shared-nfs", "nfs"},
	}
	for i, w := range wantA {
		if gotA[i].Name != w.name || gotA[i].Type != w.typ {
			t.Fatalf("remote-a storage %d = %s/%s, want %s/%s", i, gotA[i].Name, gotA[i].Type, w.name, w.typ)
		}
	}
	// Size and free bytes are carried through.
	if gotA[0].SizeBytes != 100<<30 || gotA[0].FreeBytes != 10<<30 {
		t.Fatalf("local-lvm bytes: %d/%d", gotA[0].SizeBytes, gotA[0].FreeBytes)
	}
	if gotA[1].SizeBytes != 0 || gotA[1].FreeBytes != 0 {
		t.Fatalf("pbs-backup bytes: %d/%d", gotA[1].SizeBytes, gotA[1].FreeBytes)
	}
	if gotB := data.Storages["remote-b"]; len(gotB) != 1 || gotB[0].Name != "local-dir" {
		t.Fatalf("remote-b storages: %+v", gotB)
	}

	// Bounded storages: truncated in name order.
	data, err = s.ChartData(ctx, ChartQuery{RemoteID: "remote-a", MaxStorages: 2})
	if err != nil {
		t.Fatalf("ChartData MaxStorages: %v", err)
	}
	if len(data.Storages["remote-a"]) != 2 || data.Storages["remote-a"][1].Name != "pbs-backup" {
		t.Fatalf("bounded storages: %+v", data.Storages["remote-a"])
	}
}

func TestChartDataTreeInputStorages(t *testing.T) {
	s := seedChartStore(t)
	data, err := s.ChartData(context.Background(), ChartQuery{})
	if err != nil {
		t.Fatalf("ChartData: %v", err)
	}
	in := data.TreeInput(treeNow, 0, nil, nil)

	// remote-a: storages anchored to their reporting node, p1, with
	// PVE's shared flag carried through (no type guessing).
	ra := in.Remotes[0]
	if ra.RemoteID != "remote-a" {
		t.Fatalf("remote order: %+v", ra)
	}
	if len(ra.Storages) != 3 {
		t.Fatalf("remote-a storages: %d, want 3", len(ra.Storages))
	}
	for _, st := range ra.Storages {
		if st.Node != "p1" {
			t.Fatalf("storage %s anchored to %q, want p1", st.ID, st.Node)
		}
	}
	byID := make(map[string]StorageInput, len(ra.Storages))
	for _, st := range ra.Storages {
		byID[st.ID] = st
	}
	lvm := byID["local-lvm"]
	if lvm.Shared || !lvm.CapacityKnown || lvm.UsedBytes != 90<<30 || lvm.TotalBytes != 100<<30 {
		t.Fatalf("local-lvm: %+v", lvm)
	}
	nfs := byID["shared-nfs"]
	// Seeded with size 1 TiB and 500 GiB free, so used is 524 GiB.
	if !nfs.Shared || !nfs.CapacityKnown || nfs.UsedBytes != 1<<40-500<<30 || nfs.TotalBytes != 1<<40 {
		t.Fatalf("shared-nfs: %+v", nfs)
	}
	pbs := byID["pbs-backup"]
	if !pbs.Shared || pbs.CapacityKnown || pbs.Stale {
		t.Fatalf("pbs-backup: %+v", pbs)
	}
	// remote-b: anchored to its only node, not shared.
	rb := in.Remotes[1]
	if len(rb.Storages) != 1 || rb.Storages[0].Node != "q1" || rb.Storages[0].Shared {
		t.Fatalf("remote-b storages: %+v", rb.Storages)
	}

	// BuildTree places the boxes under the anchor node; the pbs box
	// is unknown (no capacity), never 0 percent.
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	p1 := findBox(t, tree.Roots, "node/remote-a/p1")
	if len(p1.Children) != 6 { // 3 guests + 3 storages
		t.Fatalf("p1 children: %d, want 6", len(p1.Children))
	}
	stBox := findBox(t, p1.Children, "storage/remote-a/local-lvm")
	if stBox.State != StateCritical || stBox.StorageFillPercent != 90 {
		t.Fatalf("local-lvm box: state=%s fill=%d, want critical 90", stBox.State, stBox.StorageFillPercent)
	}
	pbsBox := findBox(t, p1.Children, "storage/remote-a/pbs-backup")
	if pbsBox.State != StateUnknown || pbsBox.StorageFillPercent != 0 || !pbsBox.StorageBackup || !pbsBox.StorageShared {
		t.Fatalf("pbs box: %+v", pbsBox)
	}
	// The shared nfs box is marked shared and appears once.
	nfsBox := findBox(t, p1.Children, "storage/remote-a/shared-nfs")
	if !nfsBox.StorageShared || nfsBox.State != StateOK {
		t.Fatalf("nfs box: %+v", nfsBox)
	}
	if got := countBoxes(tree.Roots, "storage/remote-a/shared-nfs"); got != 1 {
		t.Fatalf("shared nfs counted %d times, want 1", got)
	}
}

func countBoxes(boxes []Box, id string) int {
	n := 0
	for _, b := range boxes {
		if b.ID == id {
			n++
		}
		n += countBoxes(b.Children, id)
	}
	return n
}

func TestChartDataTreeInputStorageEdgeCases(t *testing.T) {
	// Inactive and stale storages are unknown, never 0 percent.
	data := ChartData{
		Remotes: []Remote{{RemoteID: "remote-a", Name: "A"}},
		Nodes: map[string][]Node{
			"remote-a": {{Node: "p1", Status: "online", State: StateAvailable, ObservedAt: freshAt()}},
		},
		Storages: map[string][]Storage{
			"remote-a": {
				{Name: "fresh", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: freshAt(), State: StateAvailable},
				{Name: "inactive", Type: "dir", Active: false, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: freshAt(), State: StateAvailable},
				{Name: "stale", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: treeNow.Add(-16 * time.Minute), State: StateAvailable},
			},
		},
	}
	tree, err := BuildTree(data.TreeInput(treeNow, 0, nil, nil))
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	p1 := findBox(t, tree.Roots, "node/remote-a/p1")
	freshBox := findBox(t, p1.Children, "storage/remote-a/fresh")
	if freshBox.State != StateOK || freshBox.StorageFillPercent != 10 {
		t.Fatalf("fresh box: %+v", freshBox)
	}
	inactiveBox := findBox(t, p1.Children, "storage/remote-a/inactive")
	if inactiveBox.State != StateUnknown || inactiveBox.StorageFillPercent != 0 {
		t.Fatalf("inactive box: %+v", inactiveBox)
	}
	staleBox := findBox(t, p1.Children, "storage/remote-a/stale")
	if !staleBox.Stale || staleBox.State != StateUnknown || staleBox.StorageFillPercent != 0 {
		t.Fatalf("stale box: %+v", staleBox)
	}
}

func TestChartDataTreeInputStorageAnchoring(t *testing.T) {
	ctx := context.Background()

	// No node observations: storages anchor to the first guest's node.
	s, _, _ := newTestStore(t)
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsA().
		guests(mkGuest(101, 1, "vm-101")).
		storages(mkStorage("local", "dir", 10<<30, 5<<30)).
		build()); err != nil {
		t.Fatalf("ingest guest-only: %v", err)
	}
	data, err := s.ChartData(ctx, ChartQuery{})
	if err != nil {
		t.Fatalf("ChartData: %v", err)
	}
	in := data.TreeInput(treeNow, 0, nil, nil)
	if len(in.Remotes[0].Storages) != 1 || in.Remotes[0].Storages[0].Node != "p1" {
		t.Fatalf("guest-anchor: %+v", in.Remotes[0].Storages)
	}

	// No nodes and no guests: storages are dropped, remote kept.
	s2, _, _ := newTestStore(t)
	if err := s2.UpsertRemote(ctx, remoteB()); err != nil {
		t.Fatalf("UpsertRemote B: %v", err)
	}
	if _, err := s2.IngestObservation(ctx, newObsB().
		storages(mkStorage("orphan", "dir", 10<<30, 5<<30)).
		build()); err != nil {
		t.Fatalf("ingest orphan: %v", err)
	}
	data2, err := s2.ChartData(ctx, ChartQuery{})
	if err != nil {
		t.Fatalf("ChartData orphan: %v", err)
	}
	in2 := data2.TreeInput(treeNow, 0, nil, nil)
	if len(in2.Remotes) != 1 || len(in2.Remotes[0].Storages) != 0 {
		t.Fatalf("orphan: %+v", in2.Remotes)
	}
	tree2, err := BuildTree(in2)
	if err != nil {
		t.Fatalf("BuildTree orphan: %v", err)
	}
	if len(tree2.Roots) != 0 {
		t.Fatalf("orphan tree roots: %+v", tree2.Roots)
	}
}

func TestChartDataExcludesTombstonedGuests(t *testing.T) {
	s := seedChartStore(t)
	ctx := context.Background()

	// A complete observation without vmid 120 tombstones it.
	if _, err := s.IngestObservation(ctx, newObsA().
		nodes(mkNode("p1"), mkNode("p2")).
		guests(mkGuest(100, 1, "vm-100"), mkGuest(110, 1, "vm-110")).
		build()); err != nil {
		t.Fatalf("ingest prune: %v", err)
	}
	data, err := s.ChartData(ctx, ChartQuery{RemoteID: "remote-a"})
	if err != nil {
		t.Fatalf("ChartData: %v", err)
	}
	if len(data.Guests["remote-a"]) != 2 {
		t.Fatalf("expected 2 active guests, got %d", len(data.Guests["remote-a"]))
	}
	for _, g := range data.Guests["remote-a"] {
		if g.VMID == 120 {
			t.Fatal("tombstoned guest 120 must not appear")
		}
	}
}

// --- PVE storage boxes (owner request: datastores under each PVE host) ---

func storageIn(node, id, typ string, used, total uint64) StorageInput {
	return StorageInput{Node: node, ID: id, Type: typ, Active: true,
		UsedBytes: used, TotalBytes: total, CapacityKnown: total > 0}
}

func TestBuildTreeStorageBoxesAfterGuests(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1")},
		Guests:   []GuestInput{guestIn(100, "p1", "vm-100")},
		Storages: []StorageInput{
			storageIn("p1", "zfs-data", "zfspool", 70, 100),
			storageIn("p1", "local", "dir", 10, 100),
			storageIn("p1", "backup", "pbs", 0, 0),
		},
	}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	root := tree.Roots[0]
	// The guest box first, then the storage boxes sorted by id.
	if len(root.Children) != 4 {
		t.Fatalf("expected 4 children, got %d", len(root.Children))
	}
	if root.Children[0].Kind != KindGuest {
		t.Fatalf("first child is %s, want guest", root.Children[0].Kind)
	}
	want := []string{"storage/remote-a/backup", "storage/remote-a/local", "storage/remote-a/zfs-data"}
	for i, id := range want {
		if root.Children[i+1].ID != id {
			t.Fatalf("child %d = %s, want %s", i+1, root.Children[i+1].ID, id)
		}
	}
	if root.Counts[KindStorage] != 3 {
		t.Fatalf("storage count = %d, want 3", root.Counts[KindStorage])
	}
	zfs := findBox(t, root.Children, "storage/remote-a/zfs-data")
	if zfs.Kind != KindStorage || zfs.Name != "zfs-data" || zfs.StorageType != "zfspool" {
		t.Fatalf("wrong storage box: %+v", zfs)
	}
	if zfs.StorageUsedBytes != 70 || zfs.StorageTotalBytes != 100 || zfs.StorageFillPercent != 70 {
		t.Fatalf("zfs fill: %d/%d pct=%d", zfs.StorageUsedBytes, zfs.StorageTotalBytes, zfs.StorageFillPercent)
	}
	if zfs.State != StateWarning {
		t.Fatalf("70%% storage state = %s, want warning", zfs.State)
	}
	backup := findBox(t, root.Children, "storage/remote-a/backup")
	if !backup.StorageBackup {
		t.Fatal("pbs storage not marked as backup datastore")
	}
	if backup.State != StateUnknown {
		t.Fatalf("pbs storage without capacity: state = %s, want unknown (never 0%%)", backup.State)
	}
	local := findBox(t, root.Children, "storage/remote-a/local")
	if local.State != StateOK || local.StorageFillPercent != 10 {
		t.Fatalf("local storage: state=%s pct=%d", local.State, local.StorageFillPercent)
	}
}

func TestBuildTreeSharedStorageOncePerCluster(t *testing.T) {
	in := treeInput()
	shared := storageIn("p1", "nfs-shared", "nfs", 50, 100)
	shared.Shared = true
	shared2 := storageIn("p2", "nfs-shared", "nfs", 50, 100)
	shared2.Shared = true
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1"), nodeIn("p2")},
		Storages: []StorageInput{
			shared,
			shared2,
			storageIn("p2", "local2", "dir", 10, 100),
		},
	}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	p1 := findBox(t, tree.Roots, "node/remote-a/p1")
	p2 := findBox(t, tree.Roots, "node/remote-a/p2")
	s1 := findBox(t, p1.Children, "storage/remote-a/nfs-shared")
	if !s1.StorageShared {
		t.Fatal("shared storage not marked shared")
	}
	for _, c := range p2.Children {
		if c.ID == "storage/remote-a/nfs-shared" {
			t.Fatal("shared storage double-counted on the second node")
		}
	}
	if len(p2.Children) != 1 || p2.Children[0].ID != "storage/remote-a/local2" {
		t.Fatalf("p2 children: %+v", p2.Children)
	}

	// A storage reported by more than one node but not explicitly shared
	// is kept per node and never derived as shared.
	in.Remotes[0].Storages[0].Shared = false
	in.Remotes[0].Storages[1].Shared = false
	tree, err = BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	p1 = findBox(t, tree.Roots, "node/remote-a/p1")
	p2 = findBox(t, tree.Roots, "node/remote-a/p2")
	s1 = findBox(t, p1.Children, "storage/remote-a/nfs-shared")
	if s1.StorageShared {
		t.Fatal("non-shared multi-node storage derived as shared")
	}
	s2 := findBox(t, p2.Children, "storage/remote-a/nfs-shared")
	if s2.StorageShared {
		t.Fatal("non-shared multi-node storage derived as shared on second node")
	}
	if len(p2.Children) != 2 {
		t.Fatalf("p2 children: %+v", p2.Children)
	}
}

func TestBuildTreeSameIDLocalStoresNotDeduped(t *testing.T) {
	// Two independent node-local stores with the same id on different
	// nodes must both render; dedup applies only to explicitly shared
	// stores. The second node's critical store must not be hidden.
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1"), nodeIn("p2")},
		Storages: []StorageInput{
			storageIn("p1", "local", "dir", 10, 100),
			storageIn("p2", "local", "dir", 90, 100),
		},
	}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	p1 := findBox(t, tree.Roots, "node/remote-a/p1")
	p2 := findBox(t, tree.Roots, "node/remote-a/p2")
	s1 := findBox(t, p1.Children, "storage/remote-a/local")
	s2 := findBox(t, p2.Children, "storage/remote-a/local")
	if s1.StorageShared {
		t.Fatal("local store on p1 marked shared")
	}
	if s2.StorageShared {
		t.Fatal("local store on p2 marked shared")
	}
	if s2.State != StateCritical {
		t.Fatalf("p2 local store state = %s, want critical", s2.State)
	}
}

func TestBuildTreeStorageStates(t *testing.T) {
	cases := []struct {
		name   string
		st     StorageInput
		want   BoxState
		reason string
	}{
		{"inactive", func() StorageInput { s := storageIn("p1", "s", "dir", 0, 100); s.Active = false; return s }(), StateUnknown, "inactive"},
		{"no capacity", storageIn("p1", "s", "pbs", 0, 0), StateUnknown, "capacity unknown"},
		{"zero total", storageIn("p1", "s", "dir", 5, 0), StateUnknown, "capacity unknown"},
		{"stale", func() StorageInput { s := storageIn("p1", "s", "dir", 50, 100); s.Stale = true; return s }(), StateUnknown, "stale"},
		{"ok 49", storageIn("p1", "s", "dir", 49, 100), StateOK, ""},
		{"warn 70", storageIn("p1", "s", "dir", 70, 100), StateWarning, "70% full"},
		{"warn 89", storageIn("p1", "s", "dir", 89, 100), StateWarning, "89% full"},
		{"crit 90", storageIn("p1", "s", "dir", 90, 100), StateCritical, "90% full"},
		{"crit 100", storageIn("p1", "s", "dir", 100, 100), StateCritical, "100% full"},
		{"over 100 clamped", storageIn("p1", "s", "dir", 150, 100), StateCritical, "100% full"},
	}
	for _, tc := range cases {
		in := treeInput()
		in.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Storages: []StorageInput{tc.st}}}
		tree, err := BuildTree(in)
		if err != nil {
			t.Fatalf("BuildTree %s: %v", tc.name, err)
		}
		b := findBox(t, tree.Roots[0].Children, "storage/remote-a/s")
		if b.State != tc.want || b.StateReason != tc.reason {
			t.Errorf("%s: state=%s reason=%q, want %s %q", tc.name, b.State, b.StateReason, tc.want, tc.reason)
		}
	}
}

func TestChartDataTreeInputStorageCapacityValidation(t *testing.T) {
	// A malformed capacity pair (free > total) must not render as a
	// healthy zero fill; it is capacity-unknown. The stored
	// availability is preserved: unavailable is unknown, partial is a
	// warning, available with a valid pair is healthy.
	data := ChartData{
		Remotes: []Remote{{RemoteID: "remote-a", Name: "A"}},
		Nodes: map[string][]Node{
			"remote-a": {{Node: "p1", Status: "online", State: StateAvailable, ObservedAt: freshAt()}},
		},
		Storages: map[string][]Storage{
			"remote-a": {
				{Name: "malformed", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 20 << 30, ObservedAt: freshAt(), State: StateAvailable},
				{Name: "unavail", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: freshAt(), State: StateUnavailable, Reason: "read failed"},
				{Name: "partial", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: freshAt(), State: StatePartial, Reason: "truncated"},
				{Name: "valid", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: freshAt(), State: StateAvailable},
			},
		},
	}
	tree, err := BuildTree(data.TreeInput(treeNow, 0, nil, nil))
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	p1 := findBox(t, tree.Roots, "node/remote-a/p1")
	m := findBox(t, p1.Children, "storage/remote-a/malformed")
	if m.State != StateUnknown || m.StateReason != "capacity unknown" {
		t.Fatalf("malformed box: %+v", m)
	}
	u := findBox(t, p1.Children, "storage/remote-a/unavail")
	if u.State != StateUnknown || u.StateReason != "read failed" {
		t.Fatalf("unavail box: %+v", u)
	}
	p := findBox(t, p1.Children, "storage/remote-a/partial")
	if p.State != StateWarning || p.StateReason != "truncated" {
		t.Fatalf("partial box: %+v", p)
	}
	v := findBox(t, p1.Children, "storage/remote-a/valid")
	if v.State != StateOK {
		t.Fatalf("valid box: %+v", v)
	}
}

func TestStorageFillPercentOverflowSafe(t *testing.T) {
	// Hostile used/total pairs where used*100 overflows uint64 must
	// still yield the correct percentage, not wrap to zero and
	// suppress the critical threshold.
	cases := []struct {
		name  string
		used  uint64
		total uint64
		want  int
	}{
		{"fast path", 1, 2, 50},
		{"fast path boundary", math.MaxUint64 / 100, 2 * math.MaxUint64 / 100, 50},
		{"overflow half full", 50 << 55, 100 << 55, 50},
		{"overflow three quarters", 75 << 55, 100 << 55, 75},
		{"overflow near full", 99 << 55, 100 << 55, 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := storageFillPercent(StorageInput{UsedBytes: tc.used, TotalBytes: tc.total})
			if got != tc.want {
				t.Fatalf("storageFillPercent(used=%d, total=%d) = %d, want %d", tc.used, tc.total, got, tc.want)
			}
		})
	}
}

func TestChartDataTreeInputStorageStaleThreshold(t *testing.T) {
	// Storage is refreshed on a five-minute cadence (spec 12), so a
	// valid observation must not be expired by the three-minute node
	// window. The storage threshold is cadence-appropriate: an
	// observation within the cadence is fresh, one at the boundary is
	// fresh (strict >), and one just past it is stale.
	build := func(observedAt time.Time) Box {
		data := ChartData{
			Remotes: []Remote{{RemoteID: "remote-a", Name: "A"}},
			Nodes: map[string][]Node{
				"remote-a": {{Node: "p1", Status: "online", State: StateAvailable, ObservedAt: freshAt()}},
			},
			Storages: map[string][]Storage{
				"remote-a": {{Name: "s", Type: "dir", Active: true, SizeBytes: 10 << 30, FreeBytes: 9 << 30, ObservedAt: observedAt, State: StateAvailable}},
			},
		}
		tree, err := BuildTree(data.TreeInput(treeNow, 0, nil, nil))
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		p1 := findBox(t, tree.Roots, "node/remote-a/p1")
		return findBox(t, p1.Children, "storage/remote-a/s")
	}
	isStale := func(b Box) bool { return b.State == StateUnknown && b.StateReason == "stale" }
	// Within the five-minute cadence: fresh (stale under the old
	// three-minute node window).
	if isStale(build(treeNow.Add(-4 * time.Minute))) {
		t.Fatal("4-min-old storage marked stale")
	}
	// Ten minutes old (staleAt): still fresh for storage.
	if isStale(build(staleAt())) {
		t.Fatal("10-min-old storage marked stale")
	}
	// At the boundary: fresh (strict >).
	if isStale(build(treeNow.Add(-StorageStaleAfter))) {
		t.Fatal("boundary storage marked stale")
	}
	// Just past the boundary: stale.
	if !isStale(build(treeNow.Add(-StorageStaleAfter - time.Second))) {
		t.Fatal("past-boundary storage not stale")
	}
}

func TestBuildTreeStorageThresholdFeedsNodeState(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Nodes:    []NodeInput{nodeIn("p1")},
		Storages: []StorageInput{storageIn("p1", "full", "lvmthin", 95, 100)},
	}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	root := tree.Roots[0]
	// The node's own state stays ok; the storage feeds the worst
	// state the chart renders on the node box.
	if root.State != StateOK || root.Worst != StateCritical {
		t.Fatalf("node state/worst = %s/%s, want ok/critical", root.State, root.Worst)
	}
}

func TestBuildTreeStorageValidation(t *testing.T) {
	dup := treeInput()
	dup.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Storages: []StorageInput{
		storageIn("p1", "local", "dir", 1, 10),
		storageIn("p1", "local", "dir", 2, 20),
	}}}
	if _, err := BuildTree(dup); err == nil {
		t.Error("duplicate (node, id) storage accepted")
	}
	noNode := treeInput()
	noNode.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Storages: []StorageInput{
		storageIn("", "local", "dir", 1, 10),
	}}}
	if _, err := BuildTree(noNode); err == nil {
		t.Error("storage without node accepted")
	}
	noID := treeInput()
	noID.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Storages: []StorageInput{
		storageIn("p1", "", "dir", 1, 10),
	}}}
	if _, err := BuildTree(noID); err == nil {
		t.Error("storage without id accepted")
	}
	over := treeInput()
	sts := make([]StorageInput, 0, MaxTreeStoragesPerRemote+1)
	for i := 0; i <= MaxTreeStoragesPerRemote; i++ {
		sts = append(sts, storageIn("p1", fmt.Sprintf("s%02d", i), "dir", 1, 10))
	}
	over.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Storages: sts}}
	if _, err := BuildTree(over); err == nil {
		t.Error("storage count above the limit accepted")
	}
	at := treeInput()
	at.Remotes = []RemoteInput{{RemoteID: "remote-a", Nodes: []NodeInput{nodeIn("p1")}, Storages: sts[:MaxTreeStoragesPerRemote]}}
	if _, err := BuildTree(at); err != nil {
		t.Errorf("storage count at the limit rejected: %v", err)
	}
}

func TestBuildTreeImplicitNodeForOrphanStorage(t *testing.T) {
	in := treeInput()
	in.Remotes = []RemoteInput{{
		RemoteID: "remote-a",
		Storages: []StorageInput{storageIn("ghost", "local", "dir", 10, 100)},
	}}
	tree, err := BuildTree(in)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if len(tree.Roots) != 1 || tree.Roots[0].Kind != KindPVENode || tree.Roots[0].Name != "ghost" {
		t.Fatalf("expected implicit node root, got %+v", tree.Roots)
	}
	if tree.Roots[0].State != StateUnknown {
		t.Fatalf("implicit node state = %s, want unknown", tree.Roots[0].State)
	}
	if len(tree.Roots[0].Children) != 1 || tree.Roots[0].Children[0].Kind != KindStorage {
		t.Fatalf("implicit node children: %+v", tree.Roots[0].Children)
	}
}

// TestChartTreeSharedStorageSeenByThreeNodesAppearsOnce ingests a
// three-node cluster where every node reports the same shared NFS store
// and its own node-local "local" store. The shared store must appear
// once, the node-local stores once per node, and an inactive store as
// unknown rather than as 0 percent.
func TestChartTreeSharedStorageSeenByThreeNodesAppearsOnce(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	inactive := onNode(mkStorage("old-iscsi", "iscsi", 100<<30, 50<<30), "p3", false)
	inactive.Active = false
	if _, err := s.IngestObservation(ctx, newObsA().
		nodes(mkNode("p1"), mkNode("p2"), mkNode("p3")).
		storages(
			onNode(mkStorage("shared-nfs", "nfs", 1<<40, 512<<30), "p1", true),
			onNode(mkStorage("local", "dir", 100<<30, 90<<30), "p1", false),
			onNode(mkStorage("shared-nfs", "nfs", 1<<40, 512<<30), "p2", true),
			onNode(mkStorage("local", "dir", 200<<30, 20<<30), "p2", false),
			onNode(mkStorage("shared-nfs", "nfs", 1<<40, 512<<30), "p3", true),
			onNode(mkStorage("local", "dir", 50<<30, 25<<30), "p3", false),
			inactive,
		).
		build()); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// The store keeps one row per (node, storage) with node and shared.
	rows, err := s.ListStorages(ctx, "remote-a", 0)
	if err != nil {
		t.Fatalf("ListStorages: %v", err)
	}
	if len(rows) != 7 {
		t.Fatalf("stored rows: %d, want 7", len(rows))
	}
	shared := 0
	nodes := map[string]bool{}
	for _, r := range rows {
		if r.Name == "shared-nfs" {
			if !r.Shared {
				t.Fatalf("shared-nfs on %s stored unshared", r.Node)
			}
			shared++
			nodes[r.Node] = true
		} else if r.Shared {
			t.Fatalf("%s on %s stored shared", r.Name, r.Node)
		}
	}
	if shared != 3 || !nodes["p1"] || !nodes["p2"] || !nodes["p3"] {
		t.Fatalf("shared-nfs rows: %d on %v", shared, nodes)
	}

	tree, err := s.ChartTree(ctx, testBase.Add(time.Minute))
	if err != nil {
		t.Fatalf("ChartTree: %v", err)
	}
	if got := countBoxes(tree.Roots, "storage/remote-a/shared-nfs"); got != 1 {
		t.Fatalf("shared-nfs boxes: %d, want 1", got)
	}
	if got := countBoxes(tree.Roots, "storage/remote-a/local"); got != 3 {
		t.Fatalf("local boxes: %d, want 3 (one per node)", got)
	}
	p1 := findBox(t, tree.Roots, "node/remote-a/p1")
	nfs := findBox(t, p1.Children, "storage/remote-a/shared-nfs")
	if !nfs.StorageShared || nfs.StorageTotalBytes != 1<<40 || nfs.StorageFillPercent != 50 {
		t.Fatalf("shared-nfs box: %+v", nfs)
	}
	p2 := findBox(t, tree.Roots, "node/remote-a/p2")
	local2 := findBox(t, p2.Children, "storage/remote-a/local")
	if local2.StorageTotalBytes != 200<<30 || local2.StorageFillPercent != 90 {
		t.Fatalf("p2 local box carries the wrong node's usage: %+v", local2)
	}
	p3 := findBox(t, tree.Roots, "node/remote-a/p3")
	old := findBox(t, p3.Children, "storage/remote-a/old-iscsi")
	if old.State != StateUnknown || old.StorageFillPercent != 0 {
		t.Fatalf("inactive storage: state=%s fill=%d, want unknown", old.State, old.StorageFillPercent)
	}
}

// TestChartTreeInactiveStorageCapacityUnknown checks that an inactive
// storage never feeds a capacity, even when PVE still reports bytes.
func TestChartTreeInactiveStorageCapacityUnknown(t *testing.T) {
	d := ChartData{
		Remotes: []Remote{{RemoteID: "remote-a", Name: "Lab A"}},
		Nodes:   map[string][]Node{"remote-a": {{RemoteID: "remote-a", Node: "p1"}}},
		Storages: map[string][]Storage{"remote-a": {{
			RemoteID: "remote-a", Node: "p1", Name: "gone", Type: "dir",
			Active: false, SizeBytes: 100, FreeBytes: 10,
		}}},
	}
	in := d.TreeInput(treeNow, 0, nil, nil)
	st := in.Remotes[0].Storages[0]
	if st.CapacityKnown || st.UsedBytes != 0 {
		t.Fatalf("inactive storage input: %+v", st)
	}
}
