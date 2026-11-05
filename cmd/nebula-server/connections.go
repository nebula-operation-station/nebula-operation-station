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
	"strings"

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
// fails closed. The server keeps flow data for the traffic store's
// default retention (there is no setting to shorten it yet), so that is
// the retention the window list is clamped to.
func newConnectionsPages(db *sql.DB, hosts connHosts, assets connAssets, log *slog.Logger) (*connections.Handler, error) {
	h, err := connections.New(connections.Options{
		Flows:     connections.SQLFlows(db, trafficstore.DefaultRetention),
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

func (d connDirectory) Host(ctx context.Context, id string) (connections.Subject, error) {
	h, err := d.hosts.Get(ctx, id)
	if errors.Is(err, inventory.ErrHostNotFound) {
		return connections.Subject{}, connections.ErrNotFound
	}
	if err != nil {
		return connections.Subject{}, err
	}
	s := connections.Subject{Name: h.DisplayName, Addrs: endpointAddrs(h)}
	if s.Name == "" {
		s.Name = h.ID
	}
	as, err := d.assets.Assets(ctx)
	if err != nil {
		return connections.Subject{}, err
	}
	for _, a := range as {
		if a.HostID == h.ID {
			s.Addrs = append(s.Addrs, a.Addresses...)
		}
	}
	return s, nil
}

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
	return connections.Subject{Name: name, Addrs: a.Addresses}, nil
}

// Peers resolves addrs to managed hosts first (endpoints and linked
// assets), then to IPAM assets. An address that matches several hosts,
// or several assets and no host, is ambiguous and left out.
func (d connDirectory) Peers(ctx context.Context, addrs []netip.Addr) (map[netip.Addr]connections.Peer, error) {
	out := make(map[netip.Addr]connections.Peer, len(addrs))
	if len(addrs) == 0 {
		return out, nil
	}
	want := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		want[a.Unmap().WithZone("")] = true
	}
	hosts, err := d.hosts.List(ctx)
	if err != nil {
		return nil, err
	}
	as, err := d.assets.Assets(ctx)
	if err != nil {
		return nil, err
	}
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
	assetAt := map[netip.Addr][]ipam.Asset{}
	for _, as := range as {
		for _, a := range as.Addresses {
			if _, known := hostName[as.HostID]; known {
				addHost(a, as.HostID)
				continue
			}
			if a = a.Unmap().WithZone(""); want[a] {
				assetAt[a] = append(assetAt[a], as)
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
	for a, list := range assetAt {
		if _, ok := hostAt[a]; ok || len(list) != 1 {
			continue
		}
		name := list[0].Name
		if name == "" {
			name = list[0].Hostname
		}
		out[a] = connections.Peer{Kind: connections.PeerAsset, ID: list[0].ID, Name: name}
	}
	return out, nil
}
