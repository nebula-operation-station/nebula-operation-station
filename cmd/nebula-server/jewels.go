// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	jewelspage "github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/jewels"
)

// Crown-jewels page (ADR 0011 D10, ticket uf09). The page is an admin page
// behind the session check; its subjects are the server's own inventory
// (managed hosts, PVE nodes and PVE guests), never flow reports.

// crownJewelStore returns a crown-jewel store on d.db. The store holds no
// state besides the database handle, the logger and the clock, so every
// caller gets a store that reads and writes the same rows; nothing is cached
// per process, and this package keeps no closed database alive.
func crownJewelStore(d serverDeps) (*jewels.Store, error) {
	if d.db == nil {
		return nil, errors.New("crown jewels: no server database")
	}
	st, err := jewels.New(d.db, d.log, nil)
	if err != nil {
		return nil, fmt.Errorf("crown jewels: %w", err)
	}
	return st, nil
}

// jewelNodeID joins prefix and parts into an attack-path node ID, or reports
// false when a part is empty. It mirrors attackpath/sources nodeID (which is
// unexported there): an empty part would make "pve:<remote>/" or
// "pve:/<node>", which the Builder accepts but no adapter creates, so a
// crown jewel on it could never be reached.
func jewelNodeID(prefix string, parts ...string) (string, bool) {
	for _, p := range parts {
		if p == "" {
			return "", false
		}
	}
	return prefix + strings.Join(parts, "/"), true
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
			id, ok := jewelNodeID("pve:", r.RemoteID, n.Node)
			if !ok {
				continue
			}
			out = append(out, jewelspage.Subject{Node: id, Label: n.Node})
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
			id, ok := jewelNodeID("guest:", r.RemoteID, strconv.FormatUint(g.VMID, 10))
			if !ok {
				continue
			}
			out = append(out, jewelspage.Subject{Node: id, Label: label})
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

// newCrownJewelsPage builds the crown-jewels page on d.db with the given
// directory. Only admins pass (d.isAdmin, the rule of the findings export);
// the page refuses (403) every request it does not approve.
func newCrownJewelsPage(d serverDeps, dir jewelspage.Directory) (*jewelspage.Handler, error) {
	st, err := crownJewelStore(d)
	if err != nil {
		return nil, err
	}
	h, err := jewelspage.New(jewelspage.Options{
		Store:        st,
		Directory:    dir,
		Authorize:    func(r *http.Request) bool { return d.isAdmin(r.Context()) },
		User:         jewelUser,
		PublicOrigin: d.cfg.PublicOrigin,
		Chrome:       jewelsChrome,
		Log:          d.log,
	})
	if err != nil {
		return nil, fmt.Errorf("crown jewels pages: %w", err)
	}
	return h, nil
}

// mountCrownJewels adds the crown-jewels routes to the pages mux. The page
// needs the admin rule, the inventory and the PVE store, because its
// subjects come from them. A server without a database, or without one of
// these, mounts no route: the page is absent (404 behind the session check),
// which is the closed choice, and the server still starts. The production
// wiring (main.go) always gives all of them, so the page is mounted there;
// a missing dependency is logged.
func mountCrownJewels(d serverDeps, mux *http.ServeMux) error {
	if d.db == nil {
		return nil
	}
	if d.isAdmin == nil || d.inventory == nil || d.pveStore == nil {
		if d.log != nil {
			d.log.Warn("crown jewels page not mounted: admin rule, inventory or PVE store missing")
		}
		return nil
	}
	h, err := newCrownJewelsPage(d, jewelDirectory{hosts: d.inventory, pve: d.pveStore})
	if err != nil {
		return err
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
