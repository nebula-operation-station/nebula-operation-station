// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	jewelspage "github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/jewels"
)

// Crown-jewels page (ADR 0011 D10, ticket uf09). The page is an admin page
// behind the session check; its subjects are the server's own inventory
// (managed hosts, PVE nodes and PVE guests), never flow reports.

// jewelStores holds one crown-jewel store per database, so the page and the
// attack-path computation (uf10) share one instance.
var jewelStores = struct {
	sync.Mutex
	byDB map[*sql.DB]*jewels.Store
}{byDB: map[*sql.DB]*jewels.Store{}}

// crownJewelStore returns the crown-jewel store on d.db, creating it on the
// first call. The page and the attack-path computation (uf10) both call it,
// so they read and write through one instance.
func crownJewelStore(d serverDeps) (*jewels.Store, error) {
	if d.db == nil {
		return nil, errors.New("crown jewels: no server database")
	}
	jewelStores.Lock()
	defer jewelStores.Unlock()
	if st, ok := jewelStores.byDB[d.db]; ok {
		return st, nil
	}
	st, err := jewels.New(d.db, d.log, nil)
	if err != nil {
		return nil, fmt.Errorf("crown jewels: %w", err)
	}
	jewelStores.byDB[d.db] = st
	return st, nil
}

// jewelHosts is the inventory read the crown-jewels directory needs;
// *inventory.Store implements it.
type jewelHosts interface {
	List(ctx context.Context) ([]inventory.Host, error)
}

// jewelPVE is the PVE read the crown-jewels directory needs;
// *pveinventory.Store implements it.
type jewelPVE interface {
	ListRemotes(ctx context.Context, limit int) ([]pveinventory.Remote, error)
	ListNodes(ctx context.Context, remoteID string, limit int) ([]pveinventory.Node, error)
	ListGuests(ctx context.Context, remoteID string, f pveinventory.GuestFilter, limit int) ([]pveinventory.Guest, error)
}

// jewelDirectory offers the markable subjects of the server's stores under
// their attack-path node IDs: "host:<id>", "pve:<remote>/<node>" and
// "guest:<remote>/<vmid>" (active guests only). IPAM assets are not offered:
// the attack-path graph has no node kind for them, so a crown jewel on one
// could never be reached. The page drops any ID the graph would not accept.
type jewelDirectory struct {
	hosts jewelHosts
	pve   jewelPVE
}

// Subjects implements jewelspage.Directory.
func (d jewelDirectory) Subjects(ctx context.Context) ([]jewelspage.Subject, error) {
	hosts, err := d.hosts.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("crown jewels: list hosts: %w", err)
	}
	var out []jewelspage.Subject
	for _, h := range hosts {
		label := h.DisplayName
		if label == "" {
			label = h.ID
		}
		out = append(out, jewelspage.Subject{Node: "host:" + h.ID, Label: label})
	}
	remotes, err := d.pve.ListRemotes(ctx, pveinventory.MaxRemotesQuery)
	if err != nil {
		return nil, fmt.Errorf("crown jewels: list PVE remotes: %w", err)
	}
	for _, r := range remotes {
		nodes, err := d.pve.ListNodes(ctx, r.RemoteID, pveinventory.MaxNodesQuery)
		if err != nil {
			return nil, fmt.Errorf("crown jewels: list PVE nodes: %w", err)
		}
		for _, n := range nodes {
			out = append(out, jewelspage.Subject{Node: "pve:" + r.RemoteID + "/" + n.Node, Label: n.Node})
		}
		guests, err := d.pve.ListGuests(ctx, r.RemoteID, pveinventory.GuestFilter{}, pveinventory.MaxGuestsQuery)
		if err != nil {
			return nil, fmt.Errorf("crown jewels: list PVE guests: %w", err)
		}
		for _, g := range guests {
			label := g.Name
			if label == "" {
				label = strconv.FormatUint(g.VMID, 10)
			}
			out = append(out, jewelspage.Subject{Node: "guest:" + r.RemoteID + "/" + strconv.FormatUint(g.VMID, 10), Label: label})
		}
	}
	return out, nil
}

// jewelUser names the admin of a request for the audit trail.
func jewelUser(r *http.Request) string {
	s, ok := auth.SessionFrom(r.Context())
	if !ok {
		return ""
	}
	return s.UserName
}

// jewelsChrome is softwareChrome for the crown-jewels page.
func jewelsChrome(r *http.Request) jewelspage.Chrome {
	c := softwareChrome(r)
	return jewelspage.Chrome{Theme: c.Theme, NavCollapsed: c.NavCollapsed, PVENav: c.PVENav, DeployEnabled: c.DeployEnabled, NotificationsNav: c.NotificationsNav}
}

// mountCrownJewels adds the crown-jewels routes to the pages mux. Only
// admins pass (d.isAdmin, the rule of the findings export); the page
// refuses (403) every request it does not approve. Without a server
// database there is nothing to show, and no route is added.
func mountCrownJewels(d serverDeps, mux *http.ServeMux) error {
	if d.db == nil {
		return nil
	}
	if d.isAdmin == nil || d.inventory == nil || d.pveStore == nil {
		return errors.New("crown jewels pages: admin rule, inventory and PVE store are required")
	}
	st, err := crownJewelStore(d)
	if err != nil {
		return fmt.Errorf("crown jewels pages: %w", err)
	}
	h, err := jewelspage.New(jewelspage.Options{
		Store:        st,
		Directory:    jewelDirectory{hosts: d.inventory, pve: d.pveStore},
		Authorize:    func(r *http.Request) bool { return d.isAdmin(r.Context()) },
		User:         jewelUser,
		PublicOrigin: d.cfg.PublicOrigin,
		Chrome:       jewelsChrome,
		Log:          d.log,
	})
	if err != nil {
		return fmt.Errorf("crown jewels pages: %w", err)
	}
	h.Register(mux)
	return nil
}

// The crown-jewels page is a feature of the registry (features.go).
func init() {
	registerServerFeature(serverFeature{
		name: "jewels",
		pages: func(d serverDeps, mux *http.ServeMux) error {
			return mountCrownJewels(d, mux)
		},
	})
}
