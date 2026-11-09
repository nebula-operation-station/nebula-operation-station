// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// fakePVE is a fixture placement store.
type fakePVE struct {
	remotes []pveinventory.Remote
	nodes   map[string][]pveinventory.Node
	guests  map[string][]pveinventory.Guest
	links   map[string][]pveinventory.Link
	err     error
}

func (f *fakePVE) ListRemotes(context.Context, int) ([]pveinventory.Remote, error) {
	return f.remotes, f.err
}

func (f *fakePVE) ListNodes(_ context.Context, r string, _ int) ([]pveinventory.Node, error) {
	return f.nodes[r], nil
}

func (f *fakePVE) ListGuests(_ context.Context, r string, _ pveinventory.GuestFilter, _ int) ([]pveinventory.Guest, error) {
	return f.guests[r], nil
}

func (f *fakePVE) ListLinks(_ context.Context, r string, _ int) ([]pveinventory.Link, error) {
	if f.err == nil && r == "broken" {
		return nil, errors.New("links table locked")
	}
	return f.links[r], nil
}

const avail = pveinventory.StateAvailable

func labPVE() *fakePVE {
	return &fakePVE{
		remotes: []pveinventory.Remote{{RemoteID: "lab"}},
		nodes: map[string][]pveinventory.Node{"lab": {
			{Node: "pve1", State: avail},
			{Node: "pve2", State: pveinventory.StatePartial},
		}},
		guests: map[string][]pveinventory.Guest{"lab": {
			{VMID: 100, Generation: 1, Node: "pve1", Name: "web", State: avail},
			{VMID: 101, Generation: 2, Node: "pve2", Name: "nas", State: avail},
			{VMID: 102, Generation: 1, Node: "gone", Name: "orphan", State: avail},
			{VMID: 103, Generation: 1, Node: "pve1", Name: "old", State: avail, Tombstoned: true},
		}},
		links: map[string][]pveinventory.Link{"lab": {
			{VMID: 100, Generation: 1, HostID: "web"},
			{VMID: 101, Generation: 1, HostID: "nas"}, // past incarnation
		}},
	}
}

func TestPlacementsControlEdgesAndAliases(t *testing.T) {
	r, err := Placements(context.Background(), labPVE())
	if err != nil {
		t.Fatal(err)
	}
	want := []attackpath.Edge{
		{From: "pve:lab/pve1", To: "guest:lab/100", Kind: attackpath.EdgeControl},
		{From: "pve:lab/pve2", To: "guest:lab/101", Kind: attackpath.EdgeControl},
	}
	if !slices.Equal(r.Edges, want) {
		t.Fatalf("edges %v", r.Edges)
	}
	if len(r.Aliases) != 1 || r.Aliases["host:web"] != "guest:lab/100" {
		t.Fatalf("aliases %v", r.Aliases)
	}
	for _, u := range []Uncertainty{
		{SourcePlacements, UncertainPartialData, "pve:lab/pve2"},
		{SourcePlacements, UncertainPlacementUnknown, "guest:lab/102"},
	} {
		if !slices.Contains(r.Uncertain, u) {
			t.Errorf("missing %s in %v", u, r.Uncertain)
		}
	}
	for _, n := range r.Nodes {
		if n.ID == "guest:lab/103" {
			t.Fatal("tombstoned guest added")
		}
	}
	if r.Status != StatusPartial || r.Coverage != (Coverage{Covered: 0, Total: 1}) {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}
}

func TestPlacementsCompleteRemoteIsCovered(t *testing.T) {
	f := labPVE()
	f.nodes["lab"][1].State = avail
	f.guests["lab"] = f.guests["lab"][:2]
	r, err := Placements(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusComplete || len(r.Uncertain) != 0 || r.Coverage != (Coverage{1, 1}) {
		t.Fatalf("result %+v", r)
	}
}

func TestPlacementsReadErrorIsUnknown(t *testing.T) {
	for name, f := range map[string]*fakePVE{
		"remotes": {err: errors.New("x")},
		"links":   {remotes: []pveinventory.Remote{{RemoteID: "broken"}}},
	} {
		r, err := Placements(context.Background(), f)
		if !errors.Is(err, ErrSourceUnavailable) || r.Status != StatusUnknown || len(r.Nodes) != 0 || r.Aliases != nil {
			t.Fatalf("%s: err %v result %+v", name, err, r)
		}
	}
	if _, err := Placements(context.Background(), nil); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatal(err)
	}
}

func TestPlacementsHostileNamesAreRejected(t *testing.T) {
	f := &fakePVE{
		remotes: []pveinventory.Remote{{RemoteID: "lab"}, {RemoteID: "bad remote"}},
		nodes: map[string][]pveinventory.Node{"lab": {
			{Node: "pve 1", State: avail},
			{Node: "pve2", State: avail},
		}},
		guests: map[string][]pveinventory.Guest{"lab": {
			{VMID: 100, Generation: 1, Node: "pve2", Name: "evil\x1b[31m", State: avail},
		}},
		links: map[string][]pveinventory.Link{"lab": {{VMID: 100, Generation: 1, HostID: "a b"}}},
	}
	r, err := Placements(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "") || r.Coverage != (Coverage{0, 2}) || r.Aliases != nil {
		t.Fatalf("result %+v", r)
	}
	for _, n := range r.Nodes {
		if n.ID == "guest:lab/100" && n.Label != "" {
			t.Fatalf("control characters kept in label %q", n.Label)
		}
	}
}

func TestPlacementsAliasConflictDropsAlias(t *testing.T) {
	f := labPVE()
	f.links["lab"] = []pveinventory.Link{
		{VMID: 100, Generation: 1, HostID: "web"},
		{VMID: 101, Generation: 2, HostID: "web"},
	}
	r, err := Placements(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Aliases != nil || !hasUncertainty(r.Uncertain, UncertainAliasConflict, "host:web") {
		t.Fatalf("aliases %v uncertain %v", r.Aliases, r.Uncertain)
	}
}
