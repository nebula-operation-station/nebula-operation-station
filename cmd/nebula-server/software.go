// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/software"
)

// Cookie names and values of the shared layout, as set by internal/web/ui
// (settings.go, nav.go). Only these exact values change the layout; the
// software package validates the theme again.
const (
	themeCookie  = "nebula_theme"
	navCookie    = "nebula_nav"
	navCollapsed = "collapsed"
)

// newSoftwarePages builds the software catalog pages (ADR 0009 D5/D6,
// TM17): the catalog list, the unknown queue and the icon pages. They are
// mounted behind the same session check and security middleware as every
// other page (webServer). The icon service has no server configuration
// yet (icon store and fetch spool, TM16), so the icon pages are read-only
// and the icon change routes answer 404.
func newSoftwarePages(db *sql.DB, log *slog.Logger) (*software.Handler, error) {
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		return nil, fmt.Errorf("software catalog: %w", err)
	}
	h, err := software.New(software.Options{
		Catalog: cat,
		List:    software.SQLList(db),
		Chrome:  softwareChrome,
		Log:     log,
	})
	if err != nil {
		return nil, fmt.Errorf("software pages: %w", err)
	}
	return h, nil
}

// softwareChrome returns the layout data of a software page: the theme
// and navigation cookies, and the navigation items this server always
// serves (PVE remotes and deployments are always configured in run).
func softwareChrome(r *http.Request) software.Chrome {
	c := software.Chrome{Theme: "system", PVENav: true, DeployEnabled: true}
	if k, err := r.Cookie(themeCookie); err == nil {
		c.Theme = k.Value
	}
	if k, err := r.Cookie(navCookie); err == nil {
		c.NavCollapsed = k.Value == navCollapsed
	}
	return c
}

// sessionGate wraps the pages with the session check (auth.Handler.Wrap).
type sessionGate interface {
	Wrap(next http.Handler) http.Handler
}

// webServer assembles the HTTP chain of the server: the security
// middleware first (headers, origin check, body limit), then the session
// check, then the pages. apiHandler, when not nil, serves the read-only
// API under api.Prefix with its own token check instead of sessions.
// The traffic map model (trafficMapAPIPath) lies under that prefix but is
// read by a page, so it always goes to the session chain (pages).
func webServer(publicOrigin string, login sessionGate, pages, apiHandler http.Handler) (*http.Server, error) {
	root := http.NewServeMux()
	gated := login.Wrap(pages)
	root.Handle("/", gated)
	root.Handle(trafficMapAPIPath, gated)
	if apiHandler != nil {
		root.Handle(api.Prefix, apiHandler)
	}
	return middleware.NewServer(middleware.Options{PublicOrigin: publicOrigin}, root)
}
