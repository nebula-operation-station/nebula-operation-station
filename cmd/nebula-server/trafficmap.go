// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	tmui "github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/trafficmap"
)

// trafficMapAPIPath is the session-authenticated traffic map model the
// traffic map page reads (ADR 0009 D4). It lies under the API prefix but
// is served by the session chain, not by the token API (webServer).
const trafficMapAPIPath = api.Prefix + tmapi.Path

// trafficIPAM is the part of the IPAM the traffic map reads: assets and
// networks the admins recorded (*ipam.Store).
type trafficIPAM interface {
	Assets(ctx context.Context) ([]ipam.Asset, error)
	Networks(ctx context.Context) ([]ipam.Network, error)
}

// mountTrafficMap adds the traffic map (ADR 0009 D4, TM19) to pages, the
// mux the server serves behind the session check and the security
// middleware (webServer):
//
//   - GET /traffic and GET /traffic/frame, the page and the renderer
//     document, need a session like every page;
//   - /api/v1/trafficmap, the bounded model, needs a session too (webServer
//     routes the path to the session chain even when the token API is on);
//   - GET /static/trafficmap/{file}, the renderer modules, lies under
//     /static/, which the session check serves without a session: the
//     sandboxed renderer imports them from an opaque origin without
//     cookies.
//
// Flows come from the traffic store with its default retention. Nodes and
// their addresses come only from the server's own records (inventory
// hosts, IPAM assets and networks), never from what agents report; an
// address claimed by more than one node stays unresolved (the builder
// drops it, tmapi.Builder).
func mountTrafficMap(pages *http.ServeMux, publicOrigin string, db *sql.DB,
	hosts func(ctx context.Context) ([]inventory.Host, error), ip trafficIPAM, log *slog.Logger,
) error {
	flows, err := trafficstore.NewWithRetention(db, trafficstore.DefaultRetention)
	if err != nil {
		return fmt.Errorf("traffic map: %w", err)
	}
	inv := trafficInventory(hosts, ip)
	limits := tmapi.Limits{Retention: trafficstore.DefaultRetention}
	builder, err := tmapi.NewBuilder(inv, flows, nil, limits)
	if err != nil {
		return fmt.Errorf("traffic map: %w", err)
	}
	model, err := tmapi.New(tmapi.Options{
		Inventory: inv,
		Flows:     flows,
		// The session chain in front has already checked the session;
		// this repeats the check so the model never leaves without one.
		Authorize: func(r *http.Request) bool {
			_, ok := auth.SessionFrom(r.Context())
			return ok
		},
		Limits: limits,
		Log:    log,
	})
	if err != nil {
		return fmt.Errorf("traffic map API: %w", err)
	}
	page, err := tmui.New(tmui.Options{
		PublicOrigin: publicOrigin,
		Windows:      builder.Windows,
		Chrome:       trafficChrome,
		Log:          log,
	})
	if err != nil {
		return fmt.Errorf("traffic map page: %w", err)
	}
	page.RegisterPages(pages)
	page.RegisterModules(pages)
	pages.Handle(trafficMapAPIPath, model)
	return nil
}

// trafficChrome is softwareChrome for the traffic map page.
func trafficChrome(r *http.Request) tmui.Chrome {
	c := softwareChrome(r)
	return tmui.Chrome{Theme: c.Theme, NavCollapsed: c.NavCollapsed, PVENav: c.PVENav, DeployEnabled: c.DeployEnabled}
}

// trafficInventory returns the map's nodes and zones from the server's
// records: every inventory host with its literal IP endpoints, every IPAM
// asset with its recorded addresses (an asset that became a known host
// adds its addresses to that host instead), and every IPAM network as a
// zone. A node lies in the most specific network containing one of its
// addresses; a network's gateway is the node owning the gateway address
// when exactly one node claims it.
func trafficInventory(hosts func(ctx context.Context) ([]inventory.Host, error), ip trafficIPAM) func(ctx context.Context) (tmapi.Inventory, error) {
	return func(ctx context.Context) (tmapi.Inventory, error) {
		hs, err := hosts(ctx)
		if err != nil {
			return tmapi.Inventory{}, fmt.Errorf("hosts: %w", err)
		}
		// The same literal-address rule as the IPAM's host view, on the
		// same host list.
		byAddr, err := ipam.FromInventory(func(context.Context) ([]inventory.Host, error) { return hs, nil })(ctx)
		if err != nil {
			return tmapi.Inventory{}, fmt.Errorf("host addresses: %w", err)
		}
		assets, err := ip.Assets(ctx)
		if err != nil {
			return tmapi.Inventory{}, fmt.Errorf("assets: %w", err)
		}
		nets, err := ip.Networks(ctx)
		if err != nil {
			return tmapi.Inventory{}, fmt.Errorf("networks: %w", err)
		}

		var inv tmapi.Inventory
		hostNode := make(map[string]int, len(hs))
		for _, h := range hs {
			if _, dup := hostNode[h.ID]; dup {
				continue
			}
			hostNode[h.ID] = len(inv.Nodes)
			label := h.DisplayName
			if label == "" {
				label = h.ID
			}
			inv.Nodes = append(inv.Nodes, tmapi.NodeInput{ID: h.ID, Label: label, Kind: tmapi.KindHost})
		}
		for a, ids := range byAddr {
			for _, id := range ids {
				if i, ok := hostNode[id]; ok {
					inv.Nodes[i].Addrs = append(inv.Nodes[i].Addrs, a)
				}
			}
		}
		for _, a := range assets {
			if i, ok := hostNode[a.HostID]; ok && a.HostID != "" {
				inv.Nodes[i].Addrs = append(inv.Nodes[i].Addrs, a.Addresses...)
				continue
			}
			label := a.Name
			if label == "" {
				label = a.Hostname
			}
			inv.Nodes = append(inv.Nodes, tmapi.NodeInput{ID: a.ID, Label: label, Kind: tmapi.KindAsset, Addrs: slices.Clone(a.Addresses)})
		}

		owners := make(map[netip.Addr][]string)
		for i := range inv.Nodes {
			n := &inv.Nodes[i]
			slices.SortFunc(n.Addrs, func(a, b netip.Addr) int { return a.Compare(b) })
			n.Addrs = slices.Compact(n.Addrs)
			for _, a := range n.Addrs {
				owners[a] = append(owners[a], n.ID)
			}
			best := -1
			for j, nw := range nets {
				if (best < 0 || nw.Prefix.Bits() > nets[best].Prefix.Bits()) &&
					slices.ContainsFunc(n.Addrs, func(a netip.Addr) bool { return nw.Prefix.Contains(a) }) {
					best = j
				}
			}
			if best >= 0 {
				n.Zone, n.VLAN = nets[best].ID, nets[best].VLAN
			}
		}
		for _, nw := range nets {
			z := tmapi.ZoneInput{ID: nw.ID, Name: nw.Name, VLAN: nw.VLAN}
			if nw.Gateway.IsValid() {
				if ids := owners[nw.Gateway.Unmap()]; len(ids) == 1 {
					z.Gateway = ids[0]
				}
			}
			inv.Zones = append(inv.Zones, z)
		}
		return inv, nil
	}
}
