// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"
)

// attackPathHostPrefix starts an attack-path host node ID ("host:<id>");
// the traffic map's node ID of that host is the inventory host ID.
const attackPathHostPrefix = "host:"

// noAttackPaths is the attack-path source until a computation is wired
// into the server: there is no result yet, so the pages say the paths are
// not computed and every crown jewel reads unknown, never safe.
type noAttackPaths struct{}

func (noAttackPaths) Snapshot(context.Context) (paths.Snapshot, error) {
	return paths.Snapshot{}, nil
}

// attackPathMapNode maps an attack-path host node to its traffic map node
// (the inventory host ID). Other nodes are not drawn by the map. Host IDs
// never contain ':' (trafficInventory), so asset node IDs cannot be hit.
func attackPathMapNode(id string) (string, bool) {
	h, ok := strings.CutPrefix(id, attackPathHostPrefix)
	if !ok || h == "" || strings.Contains(h, ":") {
		return "", false
	}
	return h, true
}

// mountAttackPaths adds the attack-path pages (ADR 0011 D10, VU-24) to
// pages, the mux the server serves behind the session check and the
// security middleware (webServer). isAdmin is the admin rule of the
// findings export (vulnAdmin); the pages refuse (403) every request it
// does not approve. The overlay frame sets its own CSP, which replaces the
// global page policy.
func mountAttackPaths(pages *http.ServeMux, publicOrigin string, isAdmin func(ctx context.Context) bool, log *slog.Logger) error {
	h, err := paths.New(paths.Options{
		Source:       noAttackPaths{},
		Authorize:    func(r *http.Request) bool { return isAdmin(r.Context()) },
		PublicOrigin: publicOrigin,
		MapNode:      attackPathMapNode,
		Chrome:       attackPathChrome,
		Log:          log,
	})
	if err != nil {
		return fmt.Errorf("attack-path pages: %w", err)
	}
	h.Register(pages)
	return nil
}

// attackPathChrome is softwareChrome for the attack-path pages.
func attackPathChrome(r *http.Request) paths.Chrome {
	c := softwareChrome(r)
	return paths.Chrome{Theme: c.Theme, NavCollapsed: c.NavCollapsed, PVENav: c.PVENav, DeployEnabled: c.DeployEnabled}
}
