// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/connections"
)

// connHosts is the inventory read the connections pages need;
// *inventory.Store implements it.
type connHosts interface {
	Get(ctx context.Context, id string) (inventory.Host, error)
	List(ctx context.Context) ([]inventory.Host, error)
}

// connAssets is the IPAM read the connections pages need; *ipam.Store
// implements it.
type connAssets interface {
	Asset(ctx context.Context, id string) (ipam.Asset, error)
	Assets(ctx context.Context) ([]ipam.Asset, error)
}

// newConnectionsPages builds the connections tab of the host and asset
// pages (ADR 0009 D3, TM20). They are mounted behind the same security
// middleware and session check as every other page (webServer); the
// handler also asks for the session itself (sessionAuthorized) and
// fails closed. The window list is clamped to the configured retention
// (traffic.retention_days), the same value the traffic map and the
// ingest store use: the page offers and accepts exactly the windows the
// store keeps.
func newConnectionsPages(db *sql.DB, hosts connHosts, assets connAssets, log *slog.Logger, retention time.Duration) (*connections.Handler, error) {
	store, err := trafficstore.NewWithRetention(db, retention)
	if err != nil {
		return nil, fmt.Errorf("connections pages: %w", err)
	}
	h, err := connections.New(connections.Options{
		Flows:     connections.SQLFlows(db, store.Retention()),
		Directory: connDirectory{hosts: hosts, assets: assets},
		Authorize: sessionAuthorized,
		Chrome:    connectionsChrome,
		Log:       log,
	})
	if err != nil {
		return nil, fmt.Errorf("connections pages: %w", err)
	}
	return h, nil
}

// sessionAuthorized approves a request that carries a verified web
// session (auth.Handler.Wrap). Every signed-in user is an admin of the
// whole inventory, so a session may read the connections of every host
// and asset; requests outside the session check are refused.
func sessionAuthorized(r *http.Request) bool {
	_, ok := auth.SessionFrom(r.Context())
	return ok
}

// connectionsChrome is softwareChrome for the connections pages.
func connectionsChrome(r *http.Request) connections.Chrome {
	c := softwareChrome(r)
	return connections.Chrome{Theme: c.Theme, NavCollapsed: c.NavCollapsed, PVENav: c.PVENav, DeployEnabled: c.DeployEnabled}
}

// connDirectory resolves hosts, assets and peers from the inventory and
// the IPAM, never from flow reports. A host's addresses are its endpoint
// IP literals and the addresses of the IPAM assets linked to it.
type connDirectory struct {
	hosts  connHosts
	assets connAssets
}

// endpointAddrs returns the IP literals among a host's endpoints.
func endpointAddrs(h inventory.Host) []netip.Addr {
	var out []netip.Addr
	for _, e := range h.Endpoints {
		a, err := netip.ParseAddr(strings.Trim(e.Address, "[]"))
		if err != nil || a.Zone() != "" {
			continue
		}
		out = append(out, a.Unmap())
	}
	return out
}

// Host returns a managed host with the addresses the server attributes
// to it alone: its endpoint IP literals and the addresses of its linked
// IPAM assets, minus every address another host also claims (two hosts
// behind one NAT address, say). Such an address is ambiguous, as in
// Peers and the traffic map (trafficmap addrOwners), so its flows are
// shown on neither host's page instead of on both.
func (d connDirectory) Host(ctx context.Context, id string) (connections.Subject, error) {
	h, err := d.hosts.Get(ctx, id)
	if errors.Is(err, inventory.ErrHostNotFound) {
		return connections.Subject{}, connections.ErrNotFound
	}
	if err != nil {
		return connections.Subject{}, err
	}
	name := h.DisplayName
	if name == "" {
		name = h.ID
	}
	hosts, assets, err := d.records(ctx)
	if err != nil {
		return connections.Subject{}, err
	}
	addrs := endpointAddrs(h)
	for _, a := range assets {
		if a.HostID == h.ID {
			addrs = append(addrs, a.Addresses...)
		}
	}
	own := connections.Peer{Kind: connections.PeerHost, ID: h.ID}
	return connections.Subject{Name: name, Addrs: ownedAddrs(addrs, own, hosts, assets)}, nil
}

// Asset returns an IPAM asset with the addresses the server attributes
// to it alone. An asset linked to a managed host shares that host's
// addresses; any other address claimed by more than one host or asset
// is ambiguous and left out, by the same rule as Host and Peers.
func (d connDirectory) Asset(ctx context.Context, id string) (connections.Subject, error) {
	a, err := d.assets.Asset(ctx, id)
	if errors.Is(err, ipam.ErrNotFound) {
		return connections.Subject{}, connections.ErrNotFound
	}
	if err != nil {
		return connections.Subject{}, err
	}
	name := a.Name
	if name == "" {
		name = a.Hostname
	}
	hosts, assets, err := d.records(ctx)
	if err != nil {
		return connections.Subject{}, err
	}
	own := connections.Peer{Kind: connections.PeerAsset, ID: a.ID}
	if a.HostID != "" && slices.ContainsFunc(hosts, func(h inventory.Host) bool { return h.ID == a.HostID }) {
		own = connections.Peer{Kind: connections.PeerHost, ID: a.HostID}
	}
	return connections.Subject{Name: name, Addrs: ownedAddrs(a.Addresses, own, hosts, assets)}, nil
}

// records reads every host and asset.
func (d connDirectory) records(ctx context.Context) ([]inventory.Host, []ipam.Asset, error) {
	hosts, err := d.hosts.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	assets, err := d.assets.Assets(ctx)
	if err != nil {
		return nil, nil, err
	}
	return hosts, assets, nil
}

// ownedAddrs returns the addresses among addrs, normalised and without
// duplicates, that resolveOwners attributes to own (kind and ID).
func ownedAddrs(addrs []netip.Addr, own connections.Peer, hosts []inventory.Host, assets []ipam.Asset) []netip.Addr {
	want := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		want[a.Unmap().WithZone("")] = true
	}
	owners := resolveOwners(want, hosts, assets)
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if p, ok := owners[a]; ok && p.Kind == own.Kind && p.ID == own.ID && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// Peers resolves addrs to managed hosts first (endpoints and linked
// assets), then to IPAM assets. An address that matches several hosts,
// or several assets and no host, is ambiguous and left out.
func (d connDirectory) Peers(ctx context.Context, addrs []netip.Addr) (map[netip.Addr]connections.Peer, error) {
	if len(addrs) == 0 {
		return make(map[netip.Addr]connections.Peer), nil
	}
	want := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		want[a.Unmap().WithZone("")] = true
	}
	hosts, as, err := d.records(ctx)
	if err != nil {
		return nil, err
	}
	return resolveOwners(want, hosts, as), nil
}

// resolveOwners resolves the addresses in want to managed hosts first
// (endpoints and linked assets), then to IPAM assets not linked to a
// known host. An address that matches several hosts, or several assets
// and no host, is ambiguous and left out. Addresses in want must be
// unmapped and without zone.
func resolveOwners(want map[netip.Addr]bool, hosts []inventory.Host, as []ipam.Asset) map[netip.Addr]connections.Peer {
	out := make(map[netip.Addr]connections.Peer, len(want))
	hostName := make(map[string]string, len(hosts))
	hostAt := map[netip.Addr]map[string]bool{}
	addHost := func(a netip.Addr, id string) {
		a = a.Unmap().WithZone("")
		if !want[a] {
			return
		}
		if hostAt[a] == nil {
			hostAt[a] = map[string]bool{}
		}
		hostAt[a][id] = true
	}
	for _, h := range hosts {
		hostName[h.ID] = h.DisplayName
		for _, a := range endpointAddrs(h) {
			addHost(a, h.ID)
		}
	}
	// assetAt maps each address to the unlinked assets that claim it,
	// keyed by asset ID so an asset listing the same address twice is
	// counted once and never ambiguous with itself.
	assetAt := map[netip.Addr]map[string]ipam.Asset{}
	for _, as := range as {
		for _, a := range as.Addresses {
			if _, known := hostName[as.HostID]; known {
				addHost(a, as.HostID)
				continue
			}
			if a = a.Unmap().WithZone(""); want[a] {
				if assetAt[a] == nil {
					assetAt[a] = map[string]ipam.Asset{}
				}
				assetAt[a][as.ID] = as
			}
		}
	}
	for a, ids := range hostAt {
		if len(ids) != 1 {
			continue
		}
		for id := range ids {
			out[a] = connections.Peer{Kind: connections.PeerHost, ID: id, Name: hostName[id]}
		}
	}
	// An address a managed host claims (directly or via a linked asset)
	// resolves to that host even when an unlinked asset also claims it:
	// the host is the authoritative owner of the address, so the asset is
	// at best a stale or behind-the-host (NAT) record. This is safe for
	// the no-cross-host-attribution property: an address is attributed to
	// a host only when exactly one host claims it; two hosts claiming the
	// same address leave it out as ambiguous, never assigned to the wrong
	// host.
	for a, m := range assetAt {
		if _, ok := hostAt[a]; ok || len(m) != 1 {
			continue
		}
		for id, as := range m {
			name := as.Name
			if name == "" {
				name = as.Hostname
			}
			out[a] = connections.Peer{Kind: connections.PeerAsset, ID: id, Name: name}
		}
	}
	return out
}
