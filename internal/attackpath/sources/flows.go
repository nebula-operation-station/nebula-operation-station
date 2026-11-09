// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// Limits of the flow adapter.
const (
	// MaxFlowOwners bounds the managed addresses the flow adapter queries;
	// beyond it the result is truncated.
	MaxFlowOwners = 4 * trafficstore.MaxOverviewNodes
	// MaxNetBirdPrefixes bounds the configured NetBird prefixes.
	MaxNetBirdPrefixes = 64
	// DefaultFlowLookback is the flow window when none is configured.
	DefaultFlowLookback = 7 * 24 * time.Hour
)

// FlowReader reads the traffic map flows (ADR 0009) read-only.
// *trafficstore.Store implements it.
type FlowReader interface {
	OverviewUnion(ctx context.Context, nodes []netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error)
}

var _ FlowReader = (*trafficstore.Store)(nil)

// AddressOwner says which managed node an address belongs to (from the
// inventory, placements or Docker networks).
type AddressOwner struct {
	Addr   netip.Addr
	NodeID string
	Kind   attackpath.NodeKind
	Label  string
}

// FlowConfig configures the flow adapter.
type FlowConfig struct {
	// Reader reads the flows.
	Reader FlowReader
	// Hosts reads the managed hosts. Each is expected to own an address
	// in Owners; one without is UncertainNoFlows.
	Hosts HostLister
	// Managed are the IDs of the other managed nodes, the guests and PVE
	// nodes (ManagedNodes of the Placements result). Each is expected to
	// own an address in Owners, like the hosts.
	Managed []string
	// Aliases maps a managed host node ID to the node of the same machine
	// (the Placements result's Aliases), so a host and its guest or PVE
	// node are one expected node.
	Aliases map[string]string
	// Owners are the managed addresses; their flows are queried.
	Owners []AddressOwner
	// NetBird are the prefixes of NetBird peers; a client there is the
	// netbird entry class.
	NetBird []netip.Prefix
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Lookback is the window length; zero means DefaultFlowLookback. The
	// store refuses a window wider than its retention.
	Lookback time.Duration
	// TopN is the per-address flow count; zero means trafficstore.MaxTopN.
	TopN int
}

// Flows returns the observed network edges (ADR 0011 D10) client → server
// (proto, server port). A client that is a public address is the internet
// entry, one in a NetBird prefix the netbird entry; a flow end that is
// neither managed nor an entry becomes an unmanaged node and an
// UncertainUnmanagedEndpoint. Flows to an entry (outbound) are no attack
// step and are skipped; one whose server end only the client reported
// may be inbound and is UncertainDirectionUnverified for its managed end.
//
// The store keeps the top-N flows per address only, so an address with N
// flows may have more (UncertainFlowsIncomplete), and one without flows is
// unknown, not unreachable (UncertainNoFlows). The coverage unit is a
// managed address: covered when it had flows below the cut. An address
// claimed by several nodes is ambiguous and not queried.
//
// Every managed host (cfg.Hosts), guest and PVE node (cfg.Managed) is
// expected to own a queried address. One that does not (no owner entry,
// an ambiguous address, or cut by MaxFlowOwners) has no flow data at all:
// it is UncertainNoFlows and one more uncovered unit, so a missing owner
// list never makes "no edge" out of "unknown".
//
// A read error of either store yields StatusUnknown and an error wrapping
// ErrSourceUnavailable; the Result is still meant to be merged.
func Flows(ctx context.Context, cfg FlowConfig) (Result, error) {
	c := newCollector(SourceFlows)
	if cfg.Reader == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("flow source: no reader: %w", ErrSourceUnavailable)
	}
	if cfg.Hosts == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("flow source: no host lister: %w", ErrSourceUnavailable)
	}
	hosts, err := cfg.Hosts.List(ctx)
	if err != nil {
		c.unavailable()
		return c.result(), fmt.Errorf("flow source: list hosts: %w: %w", ErrSourceUnavailable, err)
	}
	expected := expectedNodes(c, hosts, cfg.Managed, cfg.Aliases)
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	lookback := cfg.Lookback
	if lookback <= 0 {
		lookback = DefaultFlowLookback
	}
	n := cfg.TopN
	if n <= 0 || n > trafficstore.MaxTopN {
		n = trafficstore.MaxTopN
	}
	netbird := cfg.NetBird
	if len(netbird) > MaxNetBirdPrefixes {
		netbird = netbird[:MaxNetBirdPrefixes]
		c.truncated = true
	}

	book := ownerBook(c, cfg.Owners)
	addrs := slices.SortedFunc(maps.Keys(book), netip.Addr.Compare)
	if len(addrs) > MaxFlowOwners {
		addrs = addrs[:MaxFlowOwners]
		c.truncated = true
	}
	c.r.Coverage.Total = len(addrs)

	w := flowagg.Window{From: now().Add(-lookback), To: now()}
	var flows []flowagg.FlowTotal
	for lo := 0; lo < len(addrs); lo += trafficstore.MaxOverviewNodes {
		hi := min(lo+trafficstore.MaxOverviewNodes, len(addrs))
		got, err := cfg.Reader.OverviewUnion(ctx, addrs[lo:hi], w, n)
		if err != nil {
			c.unavailable()
			return c.result(), fmt.Errorf("flow source: read flows: %w: %w", ErrSourceUnavailable, err)
		}
		flows = append(flows, got...)
	}

	seen := map[netip.Addr]int{}
	for _, f := range flows {
		k := f.Key
		var proto attackpath.Proto
		switch k.Proto {
		case flowagg.TCP:
			proto = attackpath.ProtoTCP
		case flowagg.UDP:
			proto = attackpath.ProtoUDP
		default:
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		if k.ServerPort == 0 || (k.Server != flowagg.SideA && k.Server != flowagg.SideB) {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		server, client := k.A, k.B
		if k.Server == flowagg.SideB {
			server, client = k.B, k.A
		}
		server, client = server.Unmap().WithZone(""), client.Unmap().WithZone("")
		for _, a := range []netip.Addr{server, client} {
			if _, ok := book[a]; ok {
				seen[a]++
			}
		}
		to, toEntry, ok := flowEnd(c, book, netbird, server)
		if !ok {
			continue
		}
		if toEntry {
			// Outbound to an entry is no attack step. Without a server
			// report the server end is the client's guess (an incomplete
			// listener table), so the flow may be inbound: say so.
			if o, managed := book[client]; managed && !f.ServerReported {
				c.uncertain(UncertainDirectionUnverified, o.NodeID)
				c.partial()
			}
			continue
		}
		from, _, ok := flowEnd(c, book, netbird, client)
		if !ok || from == to {
			continue
		}
		c.edge(attackpath.Edge{From: from, To: to, Kind: attackpath.EdgeNetworkObserved, Proto: proto, Port: k.ServerPort})
	}

	for _, a := range addrs {
		o := book[a]
		switch cnt := seen[a]; {
		case cnt == 0:
			c.uncertain(UncertainNoFlows, o.NodeID)
		case cnt >= n:
			c.uncertain(UncertainFlowsIncomplete, o.NodeID)
		default:
			c.r.Coverage.Covered++
		}
	}
	queried := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		queried[resolveAlias(cfg.Aliases, book[a].NodeID)] = true
	}
	for _, id := range expected {
		if !queried[id] {
			c.r.Coverage.Total++
			c.uncertain(UncertainNoFlows, id)
		}
	}
	if c.r.Coverage.Covered < c.r.Coverage.Total {
		c.partial()
	}
	return c.result(), nil
}

// expectedNodes returns the managed node IDs that must own a queried
// address, after aliasing, sorted and unique: every managed host and every
// valid guest or PVE node of managed. Invalid records are reported and
// skipped; beyond MaxResultNodes the result is truncated.
func expectedNodes(c *collector, hosts []inventory.Host, managed []string, aliases map[string]string) []string {
	set := map[string]struct{}{}
	add := func(id string) {
		id = resolveAlias(aliases, id)
		if _, ok := set[id]; ok {
			return
		}
		if len(set) >= MaxResultNodes {
			c.truncated = true
			return
		}
		set[id] = struct{}{}
	}
	for _, h := range hosts {
		id, ok := nodeID("host:", h.ID)
		if !ok {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		add(id)
	}
	for _, id := range managed {
		if !validManagedID(id) {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		add(id)
	}
	return slices.Sorted(maps.Keys(set))
}

// managedPrefixes are the node ID namespaces of managed nodes.
var managedPrefixes = []string{
	attackpath.NodeHost.IDPrefix(),
	attackpath.NodeGuest.IDPrefix(),
	attackpath.NodePVENode.IDPrefix(),
}

// validManagedID reports whether id is a valid node ID of a managed kind.
func validManagedID(id string) bool {
	for _, p := range managedPrefixes {
		if rest, ok := strings.CutPrefix(id, p); ok {
			_, valid := nodeID(p, rest)
			return valid
		}
	}
	return false
}

// resolveAlias returns the alias target of a managed host ID if it is a
// valid managed node ID, else id itself: a bad target never becomes an
// uncertainty subject.
func resolveAlias(aliases map[string]string, id string) string {
	if to, ok := aliases[id]; ok && strings.HasPrefix(id, attackpath.NodeHost.IDPrefix()) && validManagedID(to) {
		return to
	}
	return id
}

// ManagedNodes returns the IDs of r's managed nodes (hosts, guests and
// PVE nodes), sorted: the Managed input of FlowConfig.
func ManagedNodes(r Result) []string {
	var ids []string
	for _, n := range r.Nodes {
		if n.Kind.Managed() {
			ids = append(ids, n.ID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// ownerBook validates the owners and returns the unambiguous ones by
// address. Owner nodes are added to c.
func ownerBook(c *collector, owners []AddressOwner) map[netip.Addr]AddressOwner {
	byAddr := map[netip.Addr][]AddressOwner{}
	for _, o := range owners {
		a := o.Addr.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || !o.Kind.Managed() && o.Kind != attackpath.NodeContainer {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		p := o.Kind.IDPrefix()
		if !strings.HasPrefix(o.NodeID, p) {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		if _, ok := nodeID(p, o.NodeID[len(p):]); !ok {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		o.Addr = a
		if !slices.ContainsFunc(byAddr[a], func(x AddressOwner) bool { return x.NodeID == o.NodeID }) {
			byAddr[a] = append(byAddr[a], o)
		}
	}
	book := make(map[netip.Addr]AddressOwner, len(byAddr))
	for a, os := range byAddr {
		if len(os) > 1 {
			slices.SortFunc(os, func(x, y AddressOwner) int { return cmp.Compare(x.NodeID, y.NodeID) })
			for _, o := range os {
				c.uncertain(UncertainAmbiguousAddress, o.NodeID)
			}
			c.partial()
			continue
		}
		o := os[0]
		book[a] = o
	}
	// Add owner nodes in address order so the node cap cuts
	// deterministically.
	for _, a := range slices.SortedFunc(maps.Keys(book), netip.Addr.Compare) {
		o := book[a]
		if !c.node(attackpath.Node{ID: o.NodeID, Kind: o.Kind, Label: label(o.Label)}) {
			delete(book, a)
		}
	}
	return book
}

// flowEnd maps one flow end to a node ID. entry is set for the internet
// and netbird entry nodes; ok is false when the end cannot become a node.
func flowEnd(c *collector, book map[netip.Addr]AddressOwner, netbird []netip.Prefix, a netip.Addr) (id string, entry, ok bool) {
	if o, found := book[a]; found {
		return o.NodeID, false, true
	}
	for _, p := range netbird {
		if p.Contains(a) {
			return attackpath.NetBirdID, true, true
		}
	}
	if public(a) {
		return attackpath.InternetID, true, true
	}
	if !a.IsValid() {
		c.uncertain(UncertainInvalidRecord, "")
		c.partial()
		return "", false, false
	}
	id, valid := nodeID("unk:", a.String())
	if !valid || !c.node(attackpath.Node{ID: id, Kind: attackpath.NodeUnmanaged, Label: "unmanaged " + a.String()}) {
		return "", false, false
	}
	c.uncertain(UncertainUnmanagedEndpoint, id)
	return id, false, true
}

// cgnat is the shared address space (RFC 6598); not the internet.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// public reports whether a is a global unicast address outside the private
// and shared ranges. NetBird's default range lies in the shared range, so
// peers outside a configured NetBird prefix stay unmanaged, never internal.
func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}
