// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// Traffic ingestion (ADR 0009 TM12): the server feeds the traffic store
// from the net.facts results it recorded. A cheap check runs every
// trafficCheckInterval; a full Sync runs only when a net.facts host run
// finished since the last one, the server's host records changed, or a
// clock hour passed (the ingester then reconciles ownership and prunes).
const (
	// trafficCheckInterval is the cadence of the change check.
	trafficCheckInterval = 30 * time.Second
	// trafficSyncTimeout bounds one check including its Sync.
	trafficSyncTimeout = 2 * time.Minute
	// maxTrafficHosts bounds the managed hosts one Sync works on (one
	// latest-result read and at most trafficingest.MaxEndpointsPerResult
	// endpoint writes per host). More hosts fail the round closed: no
	// identities are reconciled from a cut list.
	maxTrafficHosts = 4096
)

// errTooManyTrafficHosts is returned by trafficRecords when the
// inventory holds more than its host limit.
var errTooManyTrafficHosts = errors.New("too many managed hosts for traffic ingestion")

// trafficRecords is trafficingest.Records over the server's own records:
// the literal IP endpoints of each inventory host and the MAC and
// addresses of IPAM assets linked to it. Nothing comes from host output.
// Assets linked to a host ID that is not in the inventory are ignored
// (no host is created or implied); values more than one host claims are
// removed by the ingester (trafficingest.Exclusive).
type trafficRecords struct {
	hosts  func(context.Context) ([]inventory.Host, error)
	assets func(context.Context) ([]ipam.Asset, error)
	// maxHosts is maxTrafficHosts; tests lower it.
	maxHosts int
}

var _ trafficingest.Records = trafficRecords{}

// HostIdentities implements trafficingest.Records.
func (r trafficRecords) HostIdentities(ctx context.Context) (map[string]trafficstore.Identity, error) {
	hosts, err := r.hosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	if len(hosts) > r.maxHosts {
		return nil, fmt.Errorf("%w: %d > %d", errTooManyTrafficHosts, len(hosts), r.maxHosts)
	}
	out := make(map[string]trafficstore.Identity, len(hosts))
	for _, h := range hosts {
		var id trafficstore.Identity
		for _, e := range h.Endpoints {
			// Hostname endpoints are not resolved: a DNS answer is not
			// a server record.
			a, err := netip.ParseAddr(strings.Trim(e.Address, "[]"))
			if err != nil || a.Zone() != "" {
				continue
			}
			id.Addrs = append(id.Addrs, a.Unmap())
		}
		out[h.ID] = id
	}
	assets, err := r.assets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	for _, a := range assets {
		id, ok := out[a.HostID]
		if a.HostID == "" || !ok {
			continue
		}
		if a.MAC != "" {
			id.MACs = append(id.MACs, a.MAC)
		}
		id.Addrs = append(id.Addrs, a.Addresses...)
		out[a.HostID] = id
	}
	return out, nil
}

// trafficSyncer is the ingester surface the loop drives.
type trafficSyncer interface {
	Sync(ctx context.Context) (trafficingest.SyncResult, error)
}

// trafficLoop decides when to run a Sync. Only run touches its state.
type trafficLoop struct {
	ing     trafficSyncer
	records trafficingest.Records
	// mark returns a value that changes whenever a successful net.facts
	// host run finishes (netFactsMark).
	mark func(context.Context) (string, error)
	now  func() time.Time
	log  *slog.Logger

	synced   bool
	lastMark string
	lastRecs map[string]trafficstore.Identity
	lastHour int64
}

// newTrafficIngest wires the ingester over the server database. The
// store and in-memory aggregator keep data for retention
// (traffic.retention_days), the same value the read-side stores use:
// the hourly prune removes exactly the data the pages stop offering.
func newTrafficIngest(db *sql.DB, hosts func(context.Context) ([]inventory.Host, error),
	assets func(context.Context) ([]ipam.Asset, error), log *slog.Logger, now func() time.Time,
	retention time.Duration) (*trafficLoop, error) {
	recs := trafficRecords{hosts: hosts, assets: assets, maxHosts: maxTrafficHosts}
	store, err := trafficstore.NewWithNowAndRetention(db, now, retention)
	if err != nil {
		return nil, fmt.Errorf("traffic ingest: %w", err)
	}
	ing, err := trafficingest.New(trafficingest.Config{
		Source:  trafficingest.ExecutionSource{DB: db},
		Records: recs,
		Store:   store,
		Limits:  flowagg.Limits{Retention: retention},
		Now:     now,
		Log:     log,
	})
	if err != nil {
		return nil, fmt.Errorf("traffic ingest: %w", err)
	}
	return &trafficLoop{ing: ing, records: recs, mark: netFactsMark(db), now: now, log: log}, nil
}

// netFactsMarkSQL counts the successful net.facts host runs and their
// latest finish time; a new run changes the count even within the same
// second.
const netFactsMarkSQL = `
	SELECT COUNT(*), COALESCE(MAX(h.finished_at), 0)
	FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
	WHERE e.action_id = ? AND h.state = 'finished' AND h.class = 'success' AND h.finished_at IS NOT NULL`

// netFactsMark returns the change mark of the net.facts results in db.
func netFactsMark(db *sql.DB) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var n, last int64
		if err := db.QueryRowContext(ctx, netFactsMarkSQL, trafficingest.ActionID).Scan(&n, &last); err != nil {
			return "", fmt.Errorf("net.facts change mark: %w", err)
		}
		return fmt.Sprintf("%d/%d", n, last), nil
	}
}

// run checks every interval until ctx ends, starting at once.
func (l *trafficLoop) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		l.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// check runs a Sync when a net.facts run finished, the host records
// changed or the clock hour moved since the last successful Sync. It
// reports whether a Sync ran. A failed Sync is retried on the next check.
func (l *trafficLoop) check(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, trafficSyncTimeout)
	defer cancel()
	mark, err := l.mark(ctx)
	if err != nil {
		l.log.Warn("traffic ingest: check results", "error", err)
		return false
	}
	recs, err := l.records.HostIdentities(ctx)
	if err != nil {
		l.log.Warn("traffic ingest: load host records", "error", err)
		return false
	}
	hour := l.now().Unix() / 3600
	if l.synced && mark == l.lastMark && hour == l.lastHour && recordsEqual(recs, l.lastRecs) {
		return false
	}
	res, err := l.ing.Sync(ctx)
	if err != nil {
		l.log.Warn("traffic ingest: sync", "error", err)
		return true
	}
	l.synced, l.lastMark, l.lastRecs, l.lastHour = true, mark, recs, hour
	l.logResult(res)
	return true
}

// logResult logs one line per Sync that wrote or reconciled anything.
func (l *trafficLoop) logResult(res trafficingest.SyncResult) {
	var endpoints, buckets, failed int
	for _, h := range res.Hosts {
		endpoints += h.Endpoints
		buckets += h.Buckets
		if h.Err != nil {
			failed++
		}
	}
	if endpoints == 0 && buckets == 0 && failed == 0 && !res.Reconciled {
		return
	}
	l.log.Info("traffic ingest", "hosts", len(res.Hosts), "endpoints", endpoints, "buckets", buckets,
		"failed", failed, "reconciled", res.Reconciled, "released", res.Reconcile.Released, "pruned", res.Pruned)
}

// recordsEqual reports whether two raw record maps are the same.
func recordsEqual(a, b map[string]trafficstore.Identity) bool {
	return maps.EqualFunc(a, b, func(x, y trafficstore.Identity) bool {
		return slices.Equal(x.MACs, y.MACs) && slices.Equal(x.Addrs, y.Addrs)
	})
}
