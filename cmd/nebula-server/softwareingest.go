// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
)

// Software ingest (ADR 0009 TM17, ticket uf11): the software catalog is fed
// from the stored results of the read actions NOS already runs. The loop
// reads the newest successful result of each action per host and hands it
// to the matching softwarecat ingest function, which owns the limits and
// the parsing of these untrusted results. The loop never writes a result
// itself and never changes hosts, assets or placements.
//
// The loop is a feature (features.go): it starts from the pages hook with
// the server database and the server's background runs, so the store is
// the one the software pages read (softwarePagesWith opens the same
// configuration on the same database).

const (
	// softwareIngestInterval is how often the loop looks for stored results
	// it has not handled yet.
	softwareIngestInterval = time.Minute
	// softwarePruneInterval is how often observations last seen before the
	// retention window are removed.
	softwarePruneInterval = time.Hour
	// softwareIngestTimeout bounds one ingest round.
	softwareIngestTimeout = 60 * time.Second
	// softwareIngestLogMsg is the message of the one log line a round writes
	// when it did something. It carries counters only, never host content.
	softwareIngestLogMsg = "software ingest"
)

// softwareIngestActions are the read actions whose stored results feed the
// catalog, in the order they are ingested per host.
var softwareIngestActions = []string{"core.facts", "docker.list", "service.list", "gpu.status"}

// softwareLatestSQL picks the newest successful result of one action on one
// host. The execution ID breaks ties between runs that finished in the same
// second, so the choice is stable.
const softwareLatestSQL = `
	SELECT h.execution_id, h.finished_at
	FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
	WHERE e.action_id = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success'
	  AND h.finished_at IS NOT NULL
	ORDER BY h.finished_at DESC, h.execution_id DESC
	LIMIT 1`

// softwareResultSQL reads the stored result of one host of one execution. It
// runs only for a result the loop has not handled yet, so a large result is
// not read on every round.
const softwareResultSQL = `SELECT result FROM execution_hosts WHERE execution_id = ? AND host_id = ?`

// softwareRun counts what one ingest round did. It holds counters only.
type softwareRun struct {
	Hosts    int
	Results  int
	Observed int
	Created  int
	Skipped  int
	Limited  int
	// Rejected is the number of stored results refused as defective. Their
	// host is skipped for that action; the round goes on.
	Rejected int
	// Failed is the number of reads or writes that failed (retried on the
	// next round).
	Failed int
	// Pruned is the number of observations removed past retention.
	Pruned int
}

// softwareIngest is the loop that ingests stored results into the catalog.
// Only check touches its state; run calls check, so it is not concurrent.
type softwareIngest struct {
	db        *sql.DB
	store     *softwarecat.Store
	hosts     func(context.Context) ([]inventory.Host, error)
	retention time.Duration
	now       func() time.Time
	log       *slog.Logger
	// handled maps a host and an action to the execution ID last ingested or
	// refused. Memory only: after a restart the results are read again, and
	// the ingest functions are idempotent, so no row is duplicated.
	handled   map[string]string
	lastPrune time.Time
}

// newSoftwareIngest returns the loop on the server database. hosts lists the
// managed hosts, retention is traffic.retention_days (the window the pages
// use), now is the injected clock.
func newSoftwareIngest(db *sql.DB, hosts func(context.Context) ([]inventory.Host, error), retention time.Duration, log *slog.Logger, now func() time.Time) (*softwareIngest, error) {
	if db == nil || hosts == nil || log == nil || now == nil {
		return nil, errors.New("software ingest: missing database, host list, logger or clock")
	}
	if retention <= 0 {
		return nil, fmt.Errorf("software ingest: retention %s is not positive", retention)
	}
	// The same configuration as softwarePagesWith, on the same database.
	store, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		return nil, fmt.Errorf("software ingest: %w", err)
	}
	return &softwareIngest{db: db, store: store, hosts: hosts, retention: retention, now: now, log: log,
		handled: map[string]string{}}, nil
}

// softwarePruneDue reports whether the observations are pruned at now: at
// the first round and then once per softwarePruneInterval.
func softwarePruneDue(last, now time.Time) bool {
	return last.IsZero() || now.Sub(last) >= softwarePruneInterval
}

// check runs one round: every host and action, then the prune when due. A
// defective result skips that host's result of that action and nothing
// else. It writes one log line when the round changed something.
func (l *softwareIngest) check(ctx context.Context) softwareRun {
	var run softwareRun
	if ctx.Err() != nil {
		return run
	}
	ctx, cancel := context.WithTimeout(ctx, softwareIngestTimeout)
	defer cancel()
	now := l.now()
	hosts, err := l.hosts(ctx)
	if err != nil {
		l.log.Warn("software ingest: list hosts", "error", err)
	}
	for _, h := range hosts {
		run.Hosts++
		for _, action := range softwareIngestActions {
			l.ingestOne(ctx, h.ID, action, &run)
		}
	}
	if softwarePruneDue(l.lastPrune, now) {
		n, err := l.store.PruneObservations(ctx, now.Add(-l.retention))
		if err != nil {
			l.log.Error("software ingest: prune observations", "error", err)
		} else {
			l.lastPrune = now
			run.Pruned = int(n)
		}
	}
	if run.Results+run.Rejected+run.Failed+run.Pruned > 0 {
		l.log.Info(softwareIngestLogMsg, "hosts", run.Hosts, "results", run.Results,
			"observed", run.Observed, "created", run.Created, "skipped", run.Skipped,
			"limited", run.Limited, "rejected", run.Rejected, "failed", run.Failed, "pruned", run.Pruned)
	}
	return run
}

// ingestOne handles the newest stored result of action on host, unless it
// was handled already.
func (l *softwareIngest) ingestOne(ctx context.Context, host, action string, run *softwareRun) {
	id, finished, ok, err := l.latest(ctx, host, action)
	if err != nil {
		run.Failed++
		l.log.Warn("software ingest: latest result", "action", action, "host", host, "error", err)
		return
	}
	if !ok {
		return
	}
	key := host + "\x00" + action
	if l.handled[key] == id {
		return
	}
	result, err := l.result(ctx, id, host)
	if err != nil {
		run.Failed++
		l.log.Warn("software ingest: read result", "action", action, "host", host, "error", err)
		return
	}
	rep, err := l.ingest(ctx, action, host, result, time.Unix(finished, 0).UTC())
	if err != nil {
		if errors.Is(err, softwarecat.ErrInvalidResult) || errors.Is(err, softwarecat.ErrInvalidInput) {
			// A defective result is refused for good: the same bytes give the
			// same refusal, so it is not read again.
			l.handled[key] = id
			run.Rejected++
			l.log.Warn("software ingest: result refused", "action", action, "host", host, "error", err)
			return
		}
		run.Failed++
		l.log.Error("software ingest: ingest", "action", action, "host", host, "error", err)
		return
	}
	l.handled[key] = id
	run.Results++
	run.Observed += rep.Observed
	run.Created += rep.Created
	run.Skipped += rep.Skipped
	run.Limited += rep.Limited
}

// ingest hands a stored result to the ingest function of its action. A panic
// in the parsers is a refused result: the panic value may carry host text, so
// it is not logged.
func (l *softwareIngest) ingest(ctx context.Context, action, host string, result []byte, at time.Time) (rep softwarecat.IngestReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ingest %s: parser panic: %w", action, softwarecat.ErrInvalidResult)
		}
	}()
	target := softwarecat.Target{Kind: softwarecat.TargetHost, HostID: host}
	switch action {
	case "core.facts":
		return l.store.IngestCoreFacts(ctx, target, result, at)
	case "docker.list":
		return l.store.IngestDockerList(ctx, target, result, at)
	case "service.list":
		return l.store.IngestServiceList(ctx, target, result, at)
	case "gpu.status":
		return l.store.IngestGPUStatus(ctx, target, result, at)
	}
	return rep, fmt.Errorf("software ingest: action %q: %w", action, softwarecat.ErrInvalidInput)
}

// latest returns the execution ID and finish time (unix seconds) of the
// newest successful result of action on host, and false if there is none.
func (l *softwareIngest) latest(ctx context.Context, host, action string) (string, int64, bool, error) {
	var id string
	var finished int64
	err := l.db.QueryRowContext(ctx, softwareLatestSQL, action, host).Scan(&id, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, fmt.Errorf("latest %s result: %w", action, err)
	}
	return id, finished, true, nil
}

// result reads the stored result of host in execution id.
func (l *softwareIngest) result(ctx context.Context, id, host string) ([]byte, error) {
	var b []byte
	if err := l.db.QueryRowContext(ctx, softwareResultSQL, id, host).Scan(&b); err != nil {
		return nil, fmt.Errorf("read result of execution %s: %w", id, err)
	}
	return b, nil
}

// run checks every interval until ctx ends, starting at once.
func (l *softwareIngest) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
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

// startSoftwareIngest starts the loop as a server background run. It does
// nothing when the deps carry no database or run function (a wiring that
// starts no background work, as in the feature tests).
func startSoftwareIngest(d serverDeps) error {
	if d.db == nil || d.inventory == nil || d.run == nil {
		return nil
	}
	l, err := newSoftwareIngest(d.db, d.inventory.List, d.retention, d.log, time.Now)
	if err != nil {
		return err
	}
	if err := d.run(func(ctx context.Context) { l.run(ctx, softwareIngestInterval) }); err != nil {
		return fmt.Errorf("software ingest: %w", err)
	}
	return nil
}

// The software ingest is a feature on the registry (features.go). Its pages
// hook adds no route; it starts the loop with the server's background runs.
func init() {
	registerServerFeature(serverFeature{
		name: "softwareingest",
		pages: func(d serverDeps, _ *http.ServeMux) error {
			return startSoftwareIngest(d)
		},
	})
}
