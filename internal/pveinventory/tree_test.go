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
		build()); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsB().
		nodes(mkNode("q1")).
		guests(mkGuest(100, 1, "vm-b100")).
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
	} {
		if _, err := s.ChartData(ctx, q); err == nil {
			t.Fatalf("expected error for limit %d above maximum", q.MaxRemotes)
		}
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
