// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"fmt"
	"maps"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// PlacementReader reads PVE placements (ADR 0006) read-only.
// *pveinventory.Store implements it.
type PlacementReader interface {
	ListRemotes(ctx context.Context, limit int) ([]pveinventory.Remote, error)
	ListNodes(ctx context.Context, remoteID string, limit int) ([]pveinventory.Node, error)
	ListGuests(ctx context.Context, remoteID string, f pveinventory.GuestFilter, limit int) ([]pveinventory.Guest, error)
	ListLinks(ctx context.Context, remoteID string, limit int) ([]pveinventory.Link, error)
}

var _ PlacementReader = (*pveinventory.Store)(nil)

// PlacementConfig configures the placement adapter.
type PlacementConfig struct {
	// Reader reads the placements.
	Reader PlacementReader
	// NodeHosts maps a PVE node ID ("pve:<remote>/<node>") to the
	// inventory ID of the managed host that is this PVE node. The
	// placement store does not record it; without it the executor's
	// credential edge to the PVE node, and so to its guests, cannot be
	// placed.
	NodeHosts map[string]string
}

// Placements returns the PVE control edges of ADR 0011 D10: PVE node →
// guest, since owning the node owns the guest. PVE node IDs are
// "pve:<remote>/<node>", guest IDs "guest:<remote>/<vmid>". An active
// link from a guest incarnation to a managed host becomes an alias
// "host:<id>" → guest ID, and a PVE node's managed host from
// cfg.NodeHosts an alias "host:<id>" → PVE node ID, so Merge treats them
// as one machine: owning the managed host owns the PVE node and its
// guests. A PVE node without a valid managed host is
// UncertainPVEHostUnknown, never silently unreachable.
//
// The coverage unit is a PVE remote: covered when its nodes and guests were
// read completely, none hit a read limit, every guest's node is known and
// every node's managed host is known. A dataset that is not "available", a
// guest on an unknown node, a node without a managed host and a list cut
// by its read limit are uncertainty.
//
// A read error yields StatusUnknown and an error wrapping
// ErrSourceUnavailable; the Result is still meant to be merged.
func Placements(ctx context.Context, cfg PlacementConfig) (Result, error) {
	c := newCollector(SourcePlacements)
	r := cfg.Reader
	fail := func(what string, err error) (Result, error) {
		c.unavailable()
		return c.result(), fmt.Errorf("placement source: %s: %w: %w", what, ErrSourceUnavailable, err)
	}
	if r == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("placement source: no reader: %w", ErrSourceUnavailable)
	}
	remotes, err := r.ListRemotes(ctx, pveinventory.MaxRemotesQuery)
	if err != nil {
		return fail("list remotes", err)
	}
	if len(remotes) >= pveinventory.MaxRemotesQuery {
		c.truncated = true
	}
	aliases := map[string]string{}
	for _, rem := range remotes {
		c.r.Coverage.Total++
		ok, err := placeRemote(ctx, c, r, rem.RemoteID, cfg.NodeHosts, aliases)
		if err != nil {
			return fail("remote", err)
		}
		if ok {
			c.r.Coverage.Covered++
		} else {
			c.partial()
		}
	}
	maps.DeleteFunc(aliases, func(_, to string) bool { return to == "" })
	if len(aliases) > 0 {
		c.r.Aliases = aliases
	}
	return c.result(), nil
}

// placeRemote adds one remote's nodes, guests and links; it reports
// whether the remote was covered without uncertainty.
func placeRemote(ctx context.Context, c *collector, r PlacementReader, remote string, nodeHosts, aliases map[string]string) (bool, error) {
	if _, ok := nodeID("pve:", remote, "x"); !ok {
		c.uncertain(UncertainInvalidRecord, "")
		return false, nil
	}
	covered := true
	nodes, err := r.ListNodes(ctx, remote, pveinventory.MaxNodesQuery)
	if err != nil {
		return false, fmt.Errorf("list nodes: %w", err)
	}
	if len(nodes) >= pveinventory.MaxNodesQuery {
		c.uncertain(UncertainTruncated, "")
		covered = false
	}
	pve := map[string]string{} // node name -> node ID
	for _, n := range nodes {
		id, ok := nodeID("pve:", remote, n.Node)
		if !ok {
			c.uncertain(UncertainInvalidRecord, "")
			covered = false
			continue
		}
		if !c.node(attackpath.Node{ID: id, Kind: attackpath.NodePVENode, Label: label(n.Node)}) {
			covered = false
			continue
		}
		pve[n.Node] = id
		if n.State != pveinventory.StateAvailable {
			c.uncertain(UncertainPartialData, id)
			covered = false
		}
		hostID, mapped := nodeHosts[id]
		if !mapped {
			c.uncertain(UncertainPVEHostUnknown, id)
			covered = false
			continue
		}
		host, ok := nodeID("host:", hostID)
		if !ok {
			c.uncertain(UncertainInvalidRecord, "")
			c.uncertain(UncertainPVEHostUnknown, id)
			covered = false
			continue
		}
		if !alias(c, aliases, host, id) {
			covered = false
		}
	}

	guests, err := r.ListGuests(ctx, remote, pveinventory.GuestFilter{}, pveinventory.MaxGuestsQuery)
	if err != nil {
		return false, fmt.Errorf("list guests: %w", err)
	}
	if len(guests) >= pveinventory.MaxGuestsQuery {
		c.uncertain(UncertainTruncated, "")
		covered = false
	}
	generation := map[uint64]uint64{} // vmid -> active generation
	for _, g := range guests {
		if g.Tombstoned {
			continue
		}
		id, ok := nodeID("guest:", remote, strconv.FormatUint(g.VMID, 10))
		if !ok {
			c.uncertain(UncertainInvalidRecord, "")
			covered = false
			continue
		}
		if !c.node(attackpath.Node{ID: id, Kind: attackpath.NodeGuest, Label: label(g.Name)}) {
			covered = false
			continue
		}
		generation[g.VMID] = g.Generation
		if g.State != pveinventory.StateAvailable {
			c.uncertain(UncertainPartialData, id)
			covered = false
		}
		parent, ok := pve[g.Node]
		if !ok {
			c.uncertain(UncertainPlacementUnknown, id)
			covered = false
			continue
		}
		c.edge(attackpath.Edge{From: parent, To: id, Kind: attackpath.EdgeControl})
	}

	links, err := r.ListLinks(ctx, remote, pveinventory.MaxLinksQuery)
	if err != nil {
		return false, fmt.Errorf("list links: %w", err)
	}
	if len(links) >= pveinventory.MaxLinksQuery {
		c.uncertain(UncertainTruncated, "")
		covered = false
	}
	for _, l := range links {
		gen, ok := generation[l.VMID]
		if !ok || gen != l.Generation || !l.UnlinkedAt.IsZero() {
			continue // link to a past incarnation: not this machine
		}
		host, okH := nodeID("host:", l.HostID)
		guest, okG := nodeID("guest:", remote, strconv.FormatUint(l.VMID, 10))
		if !okH || !okG {
			c.uncertain(UncertainInvalidRecord, "")
			covered = false
			continue
		}
		if !alias(c, aliases, host, guest) {
			covered = false
		}
	}
	return covered, nil
}

// alias records host → target in aliases. A host already aliased to another
// target is ambiguous: it keeps no alias at all, becomes
// UncertainAliasConflict, and alias reports false.
func alias(c *collector, aliases map[string]string, host, target string) bool {
	if old, dup := aliases[host]; dup && old != target {
		c.uncertain(UncertainAliasConflict, host)
		aliases[host] = "" // ambiguous: no alias at all
		return false
	}
	aliases[host] = target
	return true
}
