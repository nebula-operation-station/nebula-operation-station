// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Network device inventory wiring (ADR 0010, the nx10 ticket). The collector
// writes its read results to a spool; this feature imports the spool into the
// netdev inventory store and mounts the network device pages over the same
// store. The decisions are in internal/netdevcollect (the importer) and
// internal/netdevinventory (the store); this file only starts and mounts them.
//
// Rules of this file:
//   - The spool directory is the collector's default. No configuration key
//     exists for it in this change.
//   - A spool that cannot be opened is not fatal: the server runs without a
//     collector, logs once and retries at the next interval.
//   - The pages are mounted only when the server has its database and the
//     admin rule. Every page answers only admins; the store check is the same
//     one the pages use (NetDevPages and NetDevFirewallPage each refuse
//     non-admins).
//   - The collector unit (nebula-netdev-collector.service) stays disabled.
//     Nothing here starts a collector.

const (
	// netdevSpoolDir is the spool directory the network device collector
	// writes to by default (cmd/nebula-netdev-collector, defaultSpool).
	netdevSpoolDir = "/var/lib/nebula/netdev"
	// netdevImportInterval is how often the spool is imported. It matches
	// the PVE import: the collector's default poll is one minute.
	netdevImportInterval = 30 * time.Second
)

// netdevImport runs the spool importer until its context ends.
type netdevImport struct {
	root     string
	imp      *netdevcollect.Importer
	log      *slog.Logger
	interval time.Duration
}

// newNetDevImport wires the importer of the spool at root over the server
// database. The importer writes device rows through the metadata writer and
// dataset rows through the same store the pages read.
func newNetDevImport(db *sql.DB, root string, log *slog.Logger, now func() time.Time) *netdevImport {
	store := netdevinventory.NewWithNow(db, now)
	return &netdevImport{
		root: root,
		imp: &netdevcollect.Importer{
			Spool: &netdevcollect.Spool{Dir: root, Now: now},
			Store: store,
			Meta:  store,
			Now:   now,
			Log:   log,
		},
		log:      log,
		interval: netdevImportInterval,
	}
}

// run imports the spool once now and then every interval until ctx ends. A
// pass that fails is logged once per outage and retried at the next interval.
func (n *netdevImport) run(ctx context.Context) {
	t := time.NewTicker(n.interval)
	defer t.Stop()
	unavailable := false
	for {
		_, err := n.imp.Run(ctx)
		switch {
		case err == nil:
			unavailable = false
		case ctx.Err() == nil:
			if !unavailable {
				n.log.Warn("netdev spool unavailable, retrying", "root", n.root, "error", err)
			}
			unavailable = true
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// netdevUIOptions holds the ui.Options ui.New received in runServer. The
// options hook fills it before the pages hook runs; the netdev pages need
// the same handler configuration (layout, navigation, banner) as the rest of
// the UI.
var netdevUIOptions ui.Options

// mountNetDevPages adds the network device pages and the PAN-OS firewall view
// to mux, over the server database and the admin rule. A server without a
// database or without the admin rule mounts no pages (404 behind the session
// check) and logs why.
func mountNetDevPages(d serverDeps, o ui.Options, mux *http.ServeMux) error {
	if d.db == nil || d.isAdmin == nil {
		if d.log != nil {
			d.log.Warn("network device pages not mounted: database or admin rule missing")
		}
		return nil
	}
	h, err := ui.New(o)
	if err != nil {
		return fmt.Errorf("network device pages: %w", err)
	}
	store := netdevinventory.NewWithNow(d.db, time.Now)
	isAdmin := func(ctx context.Context, _ string) (bool, error) { return d.isAdmin(ctx), nil }
	pages, err := h.NetDevPages(ui.NetDevOptions{Store: store, IsAdmin: isAdmin})
	if err != nil {
		return fmt.Errorf("network device pages: %w", err)
	}
	firewall, err := h.NetDevFirewallPage(ui.NetDevFirewallOptions{Store: store, IsAdmin: isAdmin})
	if err != nil {
		return fmt.Errorf("network device firewall view: %w", err)
	}
	pages.Register(mux)
	firewall.Register(mux)
	return nil
}

// startNetDevImport starts the importer as a server background run. It does
// nothing without a database or a run function (a wiring that starts no
// background work, as in the feature tests).
func startNetDevImport(d serverDeps) error {
	if d.db == nil || d.run == nil {
		return nil
	}
	n := newNetDevImport(d.db, netdevSpoolDir, d.log, time.Now)
	if err := d.run(func(ctx context.Context) { n.run(ctx) }); err != nil {
		return fmt.Errorf("netdev import: %w", err)
	}
	return nil
}

// The network device feature is on the registry (features.go). Its options
// hook keeps the ui.Options of runServer for the pages hook; its pages hook
// mounts the pages and starts the importer.
func init() {
	registerServerFeature(serverFeature{
		name: "netdev",
		options: func(_ serverDeps, o *ui.Options) error {
			netdevUIOptions = *o
			return nil
		},
		pages: func(d serverDeps, mux *http.ServeMux) error {
			if err := mountNetDevPages(d, netdevUIOptions, mux); err != nil {
				return err
			}
			return startNetDevImport(d)
		},
	})
}
