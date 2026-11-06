// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/software"
)

// Icon service wiring (ADR 0009 D6).
const (
	// defaultIconSpool is the nebula-iconfetch spool, the helper's default
	// and the path its systemd units are written for.
	defaultIconSpool = "/var/lib/nebula/iconfetch"
	// iconStoreDirName is the icon store below the data directory.
	iconStoreDirName = "icons"
	// iconStoreDirMode keeps the store private to the server.
	iconStoreDirMode = 0o750
	// iconImportInterval is how often the server looks for helper results.
	iconImportInterval = 15 * time.Second
	// iconImportTimeout bounds one import round.
	iconImportTimeout = 30 * time.Second
)

// Cookie names and values of the shared layout, as set by internal/web/ui
// (settings.go, nav.go). Only these exact values change the layout; the
// software package validates the theme again.
const (
	themeCookie  = "nebula_theme"
	navCookie    = "nebula_nav"
	navCollapsed = "collapsed"
)

// iconWiring is the server's icon service with the spool it imports from.
type iconWiring struct {
	service *icons.Service
	spool   iconjob.Spool
	log     *slog.Logger
}

// newIconWiring builds the icon service (TM16): the icon store below
// dataDir, created if missing, and the nebula-iconfetch spool at spoolDir.
// A spool that is not installed is not an error: fetches answer "not
// installed" until it is, uploads and rollbacks do not need it. log must be
// the audit-recording logger, so every change reaches the audit trail.
func newIconWiring(db *sql.DB, dataDir, spoolDir string, log *slog.Logger) (*iconWiring, error) {
	dir := filepath.Join(dataDir, iconStoreDirName)
	if err := os.Mkdir(dir, iconStoreDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create icon store: %w", err)
	}
	store, err := iconstore.NewStore(dir)
	if err != nil {
		return nil, fmt.Errorf("icon store: %w", err)
	}
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		return nil, fmt.Errorf("software catalog: %w", err)
	}
	spool := iconjob.Spool{Dir: spoolDir}
	svc, err := icons.New(icons.Config{Spool: spool, Store: store, Catalog: cat, Log: log})
	if err != nil {
		return nil, fmt.Errorf("icon service: %w", err)
	}
	return &iconWiring{service: svc, spool: spool, log: log}, nil
}

// importResults runs one bounded import of the helper's results. The
// service audits each job; an error leaves the job for the next round.
func (w *iconWiring) importResults(ctx context.Context) {
	if !w.spool.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, iconImportTimeout)
	defer cancel()
	if _, err := w.service.ImportResults(ctx); err != nil {
		w.log.Error("import icon results", "error", err)
	}
}

// run imports helper results every interval until ctx ends.
func (w *iconWiring) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.importResults(ctx)
		}
	}
}

// newSoftwarePages builds the software catalog pages (ADR 0009 D5/D6,
// TM17) without an icon service: the icon pages are read-only and the icon
// change routes answer 404.
func newSoftwarePages(db *sql.DB, log *slog.Logger) (*software.Handler, error) {
	return softwarePagesWith(db, log, nil)
}

// softwarePagesWith builds the catalog list, the unknown queue and the icon
// pages. They are mounted behind the same session check and security
// middleware as every other page (webServer). w, when not nil, enables the
// icon change routes and /icons/.
func softwarePagesWith(db *sql.DB, log *slog.Logger, w *iconWiring) (*software.Handler, error) {
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		return nil, fmt.Errorf("software catalog: %w", err)
	}
	o := software.Options{
		Catalog: cat,
		List:    software.SQLList(db),
		Chrome:  softwareChrome,
		Log:     log,
	}
	if w != nil {
		o.Icons = w.service
	}
	h, err := software.New(o)
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
