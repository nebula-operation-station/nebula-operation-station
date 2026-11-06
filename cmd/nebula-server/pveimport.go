// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// pveImportInterval is how often the spool is imported and, while it is
// unavailable, opened again. It stays below the collector's default
// interval of one minute, so a healthy server keeps results/ near empty.
const pveImportInterval = 30 * time.Second

// pveImport feeds the collector's spool (ADR 0006, P1-10) into the server:
// observations into the PVE inventory, guest NIC records into the traffic
// store as provider links (ADR 0009 TM14). The spool is the server's only
// PVE input; everything in it is untrusted and revalidated by the importers.
type pveImport struct {
	root     string
	store    *pveinventory.Store
	sink     pvecollect.GuestNetSink
	log      *slog.Logger
	interval time.Duration
}

// newPVEImport wires the import of the spool at root over the server
// database. retention is traffic.retention_days, so a record is judged by
// the window the traffic pages show.
func newPVEImport(db *sql.DB, root string, retention time.Duration, log *slog.Logger) (*pveImport, error) {
	traffic, err := trafficstore.NewWithRetention(db, retention)
	if err != nil {
		return nil, fmt.Errorf("open traffic store for guest NICs: %w", err)
	}
	sink, err := pvecollect.NewGuestNetStoreSink(traffic)
	if err != nil {
		return nil, fmt.Errorf("build guest NIC sink: %w", err)
	}
	return &pveImport{root: root, store: pveinventory.New(db), sink: sink, log: log, interval: pveImportInterval}, nil
}

// run imports the spool until ctx is cancelled and returns after both
// importers stopped. A spool that cannot be opened is not fatal: a server
// without a collector works, so run logs that once and keeps trying.
func (p *pveImport) run(ctx context.Context) {
	spool := p.open(ctx)
	if spool == nil {
		return
	}
	defer spool.Close()
	importer, err := pvecollect.NewImporter(spool, p.store, p.log)
	if err != nil {
		p.log.Error("PVE import not started", "error", err)
		return
	}
	guests, err := pvecollect.NewGuestNetImporter(spool, p.sink, p.log)
	if err != nil {
		p.log.Error("PVE import not started", "error", err)
		return
	}
	p.log.Info("PVE import started", "root", p.root)
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := importer.Run(ctx, p.interval); err != nil {
			p.log.Error("PVE import stopped", "error", err)
		}
	})
	wg.Go(func() {
		if err := guests.Run(ctx, p.interval); err != nil {
			p.log.Error("guest NIC import stopped", "error", err)
		}
	})
	wg.Wait()
}

// open returns the read-side spool, or nil when ctx ended first.
func (p *pveImport) open(ctx context.Context) *pvecollect.Spool {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	logged := false
	for {
		spool, err := pvecollect.OpenSpool(p.root)
		if err == nil {
			return spool
		}
		if !logged {
			logged = true
			p.log.Warn("PVE spool unavailable, retrying", "root", p.root, "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
