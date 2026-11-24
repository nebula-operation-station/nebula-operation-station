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
// security middleware (webServer). src is the snapshot the pages show
// (attackPathSource in production). isAdmin is the admin rule of the
// findings export (vulnAdmin); the pages refuse (403) every request it
// does not approve. The overlay frame sets its own CSP, which replaces the
// global page policy.
func mountAttackPaths(pages *http.ServeMux, publicOrigin string, src paths.Source, isAdmin func(ctx context.Context) bool, log *slog.Logger) error {
	h, err := paths.New(paths.Options{
		Source:       src,
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

// The attack-path pages are the first feature on the registry (features.go):
// the same mount, behind the same session check, from its own file.
func init() {
	registerServerFeature(serverFeature{
		name: "attackpaths",
		pages: func(d serverDeps, mux *http.ServeMux) error {
			src := newAttackPathSource(d)
			if d.run != nil {
				if err := d.run(src.run); err != nil {
					return fmt.Errorf("attack paths: %w", err)
				}
			}
			return mountAttackPaths(mux, d.cfg.PublicOrigin, src, d.isAdmin, d.log)
		},
	})
}

// attackPathChrome is softwareChrome for the attack-path pages.
func attackPathChrome(r *http.Request) paths.Chrome {
	c := softwareChrome(r)
	return paths.Chrome{Theme: c.Theme, NavCollapsed: c.NavCollapsed, PVENav: c.PVENav, DeployEnabled: c.DeployEnabled, NotificationsNav: c.NotificationsNav}
}
