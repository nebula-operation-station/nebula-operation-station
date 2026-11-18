// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/leasewatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsdigest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Lease watch and daily digest wiring (ADR 0016 D10, spec 13). The decisions
// are made by internal/leasewatch and internal/opsdigest; this file reads the
// inputs from the server's own stores, persists what was already decided and
// hands the due messages to internal/notify.
//
// Rules of this file:
//   - The executor is read through the executions service only (read grants,
//     schedules, stored runs and updates). No executor method is added.
//   - If the grant list cannot be read, the grant part of the tick is
//     skipped: an empty or partial snapshot would forget the marks and send
//     the same events again.
//   - The state is saved before any message is sent. A restart therefore
//     never repeats a message. A crash between save and send loses that
//     message; the notification log records a failed send.

const (
	// leaseWatchInterval is how often the grants and stored runs are looked at.
	leaseWatchInterval = 5 * time.Minute
	// leaseWatchStateFile is the file in the data directory that holds the
	// lease watch and digest state.
	leaseWatchStateFile = "leasewatch-state.json"
	// leaseRunBatch bounds the stored runs read per query.
	leaseRunBatch = 5000
	// leaseWatchMaxState bounds the state file size on read.
	leaseWatchMaxState = leasewatch.MaxStateBytes + 4096
	// digestLang is the text language of the daily digest (ADR 0016: de).
	digestLang = opsdigest.LangDE
	// digestGrantWindow is the window of the "grants expiring" digest count.
	digestGrantWindow = 7 * 24 * time.Hour
)

// errDigestFindingsTruncated reports that the open findings did not fit in one
// read. The digest is then not sent rather than sent with a wrong count.
var errDigestFindingsTruncated = errors.New("open findings exceed the digest read limit")

// leaseSource is the read side of the executions service the watch needs.
type leaseSource interface {
	ReadGrants(ctx context.Context) ([]executions.ReadGrantView, error)
	Schedules(ctx context.Context) ([]executions.Schedule, error)
	AllUpdates(ctx context.Context) (map[string]executions.HostUpdates, error)
	AllOpsStates(ctx context.Context) (map[string]executions.OpsState, error)
}

// leaseSender is the part of the notifier the watch uses. *notify.Notifier
// implements it.
type leaseSender interface {
	Notify(ctx context.Context, e notify.Event) int
	Enabled() bool
}

// hostLister lists the managed hosts (inventory.Store implements it).
type hostLister interface {
	List(ctx context.Context) ([]inventory.Host, error)
}

// leaseWatchState is what is saved between runs. The State part holds the
// expiry marks and open run-failure episodes; the run mark is the last stored
// run that was looked at, ordered by finish time, execution and host.
type leaseWatchState struct {
	Watch      leasewatch.State
	Init       bool
	RunAt      int64
	RunExec    string
	RunHost    string
	DigestSent time.Time
}

// leaseFile is the on-disk form. The watch state uses the leasewatch codec,
// which validates the limits when it is read.
type leaseFile struct {
	Init       bool            `json:"init"`
	Watch      json.RawMessage `json:"watch,omitempty"`
	RunAt      int64           `json:"run_at"`
	RunExec    string          `json:"run_exec,omitempty"`
	RunHost    string          `json:"run_host,omitempty"`
	DigestSent time.Time       `json:"digest_sent"`
}

// leaseWatcher holds the lease watch and digest state of the server.
type leaseWatcher struct {
	db     *sql.DB
	src    leaseSource
	hosts  hostLister
	vulns  *vulnstore.Store
	send   leaseSender
	base   string
	digest serverconfig.DailyDigest
	loc    *time.Location
	path   string
	now    func() time.Time
	log    *slog.Logger

	st    leaseWatchState
	saved []byte
}

// newLeaseWatcher returns a watcher that keeps its state in dataDir. base is
// the NOS origin used for links; loc is the time zone of the digest time.
func newLeaseWatcher(db *sql.DB, src leaseSource, hosts hostLister, vulns *vulnstore.Store, send leaseSender,
	base string, digest serverconfig.DailyDigest, loc *time.Location, dataDir string, now func() time.Time, log *slog.Logger) *leaseWatcher {
	if now == nil {
		now = time.Now
	}
	if loc == nil {
		loc = time.Local
	}
	return &leaseWatcher{db: db, src: src, hosts: hosts, vulns: vulns, send: send, base: base, digest: digest,
		loc: loc, path: filepath.Join(dataDir, leaseWatchStateFile), now: now, log: log}
}

// load reads the saved state. A missing file is a first start. A file that is
// too large or malformed is logged and ignored: the watch then starts over
// from now, which can repeat an expiry message at worst.
func (w *leaseWatcher) load() {
	data, err := os.ReadFile(w.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		w.log.Error("lease watch: read state", "error", err)
		return
	}
	if len(data) > leaseWatchMaxState {
		w.log.Error("lease watch: state too large, ignored", "bytes", len(data))
		return
	}
	st, err := decodeLeaseFile(data)
	if err != nil {
		w.log.Error("lease watch: state malformed, ignored", "error", err)
		return
	}
	w.st = st
	w.saved = data
}

// decodeLeaseFile parses and validates the on-disk state.
func decodeLeaseFile(data []byte) (leaseWatchState, error) {
	var f leaseFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return leaseWatchState{}, fmt.Errorf("decode lease watch state: %w", err)
	}
	st := leaseWatchState{Init: f.Init, RunAt: f.RunAt, RunExec: f.RunExec, RunHost: f.RunHost, DigestSent: f.DigestSent}
	if len(f.Watch) > 0 {
		ws, err := leasewatch.DecodeState(f.Watch)
		if err != nil {
			return leaseWatchState{}, fmt.Errorf("decode lease watch marks: %w", err)
		}
		st.Watch = ws
	}
	return st, nil
}

// encode returns the on-disk form of the state.
func (w *leaseWatcher) encode() ([]byte, error) {
	watch, err := leasewatch.EncodeState(w.st.Watch)
	if err != nil {
		return nil, fmt.Errorf("encode lease watch marks: %w", err)
	}
	return json.Marshal(leaseFile{Init: w.st.Init, Watch: watch, RunAt: w.st.RunAt, RunExec: w.st.RunExec,
		RunHost: w.st.RunHost, DigestSent: w.st.DigestSent})
}

// save writes the state if it changed, atomically (0600 in the data dir).
func (w *leaseWatcher) save() error {
	data, err := w.encode()
	if err != nil {
		return err
	}
	if string(data) == string(w.saved) {
		return nil
	}
	if err := writeFileAtomic(w.path, data); err != nil {
		return fmt.Errorf("save lease watch state: %w", err)
	}
	w.saved = data
	return nil
}

// Run runs a tick at start and then every leaseWatchInterval until ctx ends.
func (w *leaseWatcher) Run(ctx context.Context) {
	w.load()
	t := time.NewTicker(leaseWatchInterval)
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick decides and sends what is due at the watcher's clock. It never panics
// on an unreachable executor: each part logs its own failure and leaves its
// state alone.
func (w *leaseWatcher) Tick(ctx context.Context) {
	now := w.now()
	prev := w.st
	prevSaved := w.saved

	var events []notify.Event
	if !w.st.Init {
		// First start: nothing before now is reported. Expiry marks are set
		// by the first snapshot, so grants that are already inside 7 days
		// are still reported once.
		w.st.Init = true
		w.st.RunAt = now.Unix()
		w.st.RunExec, w.st.RunHost = "", ""
	}
	events = append(events, w.expiryEvents(ctx, now)...)
	events = append(events, w.runEvents(ctx, now)...)

	if err := w.save(); err != nil {
		// Nothing is sent without the saved state: after a restart the
		// same decisions would be made again and sent twice.
		w.log.Error("lease watch: save state", "error", err)
		w.st = prev
		w.saved = prevSaved
		return
	}
	for _, e := range events {
		w.deliver(ctx, e)
	}
	w.digestTick(ctx, now)
}

// deliver sends one event. A failure is logged by the notifier and recorded in
// the notification log; the event is not retried.
func (w *leaseWatcher) deliver(ctx context.Context, e notify.Event) {
	if w.send == nil || !w.send.Enabled() {
		return
	}
	if n := w.send.Notify(ctx, e); n == 0 {
		w.log.Warn("lease watch: no provider accepted the event", "kind", e.Kind)
	}
}

// grantSnapshot returns the active read leases and schedule grants as the
// watch sees them. It fails if either list cannot be read.
func (w *leaseWatcher) grantSnapshot(ctx context.Context) ([]leasewatch.Grant, error) {
	reads, err := w.src.ReadGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list read grants: %w", err)
	}
	scheds, err := w.src.Schedules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	var out []leasewatch.Grant
	for _, g := range reads {
		if g.State != "active" || g.Legacy {
			continue
		}
		out = append(out, leasewatch.Grant{ID: g.ID, Name: g.ID, Kind: leasewatch.KindReadLease, ExpiresAt: g.Expiry})
	}
	for _, s := range scheds {
		if s.State != "active" {
			continue
		}
		out = append(out, leasewatch.Grant{ID: s.ID, Name: s.ID, Kind: leasewatch.KindScheduleGrant, ExpiresAt: s.ExpiresAt})
	}
	return out, nil
}

// expiryEvents returns the due lease.expiring messages and updates the state.
// Without a readable grant list it returns nothing and changes nothing.
func (w *leaseWatcher) expiryEvents(ctx context.Context, now time.Time) []notify.Event {
	grants, err := w.grantSnapshot(ctx)
	if err != nil {
		w.log.Warn("lease watch: grants not read, expiry skipped", "error", err)
		return nil
	}
	due, next, err := leasewatch.Expiring(grants, w.st.Watch, now)
	if err != nil {
		w.log.Error("lease watch: expiry decision", "error", err)
		return nil
	}
	w.st.Watch = next
	var out []notify.Event
	for _, d := range due {
		e, err := notify.NewLeaseExpiring(w.base, notify.LeaseExpiry{
			GrantID: d.GrantID, GrantName: d.GrantName, Threshold: d.Threshold, ExpiresAt: d.ExpiresAt, At: now,
		})
		if err != nil {
			w.log.Error("lease watch: build expiry message", "error", err)
			continue
		}
		out = append(out, e)
	}
	return out
}

// runEvents reads the stored runs after the run mark and returns the due
// lease.run_failed messages. It reads in batches until none are left.
func (w *leaseWatcher) runEvents(ctx context.Context, now time.Time) []notify.Event {
	var out []notify.Event
	for {
		results, mark, n, err := storedLeaseRuns(ctx, w.db, w.st.RunAt, w.st.RunExec, w.st.RunHost, leaseRunBatch)
		if err != nil {
			w.log.Error("lease watch: read stored runs", "error", err)
			return out
		}
		if n == 0 {
			return out
		}
		due, next, err := leasewatch.RunFailed(results, w.st.Watch)
		if err != nil {
			w.log.Error("lease watch: run decision", "error", err)
			return out
		}
		// RunFailed returns only the episodes. The expiry marks belong to
		// Expiring and must survive this step, or the next tick and the
		// next restart would report the expiry again.
		next.Expiry = w.st.Watch.Expiry
		w.st.Watch = next
		w.st.RunAt, w.st.RunExec, w.st.RunHost = mark.at, mark.exec, mark.host
		for _, d := range due {
			e, err := notify.NewLeaseRunFailed(w.base, notify.LeaseRunFailure{
				GrantID: d.GrantID, GrantName: d.GrantID, Action: d.Action, HostLabel: w.hostLabel(ctx, d.HostLabel), At: d.At,
			})
			if err != nil {
				w.log.Error("lease watch: build run failure message", "error", err)
				continue
			}
			out = append(out, e)
		}
		if n < leaseRunBatch {
			return out
		}
	}
}

// hostLabel returns the display name of a host, or the ID when the host is
// unknown or the inventory cannot be read.
func (w *leaseWatcher) hostLabel(ctx context.Context, id string) string {
	if w.hosts == nil {
		return id
	}
	hs, err := w.hosts.List(ctx)
	if err != nil {
		return id
	}
	for _, h := range hs {
		if h.ID == id && h.DisplayName != "" {
			return h.DisplayName
		}
	}
	return id
}

// runMark is the position of the last stored run that was read.
type runMark struct {
	at   int64
	exec string
	host string
}

// storedLeaseRuns returns up to limit finished runs of leases after the mark,
// in finish order, and the mark of the last one. Each run is a leasewatch
// result: a grant ID, an action, the host ID and whether it succeeded. Runs
// that did not run (skipped, not run, not executed) are left out. The second
// return is the number of rows read, so the caller can tell whether to read on.
func storedLeaseRuns(ctx context.Context, db *sql.DB, at int64, exec, host string, limit int) ([]leasewatch.RunResult, runMark, int, error) {
	rows, err := db.QueryContext(ctx, `SELECT e.id, e.schedule_id, e.action_id, h.host_id, h.class, h.finished_at
		FROM executions e JOIN execution_hosts h ON h.execution_id = e.id
		WHERE e.schedule_id IS NOT NULL AND e.schedule_id <> '' AND h.state = 'finished' AND h.finished_at IS NOT NULL
		AND (h.finished_at > ? OR (h.finished_at = ? AND (h.execution_id > ? OR (h.execution_id = ? AND h.host_id > ?))))
		ORDER BY h.finished_at, h.execution_id, h.host_id LIMIT ?`,
		at, at, exec, exec, host, limit)
	if err != nil {
		return nil, runMark{}, 0, fmt.Errorf("query lease runs: %w", err)
	}
	defer rows.Close()
	var out []leasewatch.RunResult
	mark := runMark{at: at, exec: exec, host: host}
	n := 0
	for rows.Next() {
		var execID, grant, action, hostID, class string
		var finished int64
		if err := rows.Scan(&execID, &grant, &action, &hostID, &class, &finished); err != nil {
			return nil, runMark{}, 0, fmt.Errorf("scan lease run: %w", err)
		}
		n++
		mark = runMark{at: finished, exec: execID, host: hostID}
		if notRunClass(class) {
			continue
		}
		out = append(out, leasewatch.RunResult{GrantID: grant, Action: action, HostLabel: hostID,
			Success: class == classSuccess, At: time.Unix(finished, 0)})
	}
	if err := rows.Err(); err != nil {
		return nil, runMark{}, 0, fmt.Errorf("read lease runs: %w", err)
	}
	return out, mark, n, nil
}

// classSuccess is the class of a successful host run (executions package).
const classSuccess = "success"

// notRunClass reports whether a run class means the action did not run on the
// host, so it is neither a success nor a failure.
func notRunClass(c string) bool {
	switch c {
	case "skipped", "not_run", "not_executed":
		return true
	}
	return false
}

// digestTick sends the daily digest when it is due. A failure to read a count
// sends nothing and is retried at the next tick; a sent or skipped digest is
// recorded so that it counts once for the day.
func (w *leaseWatcher) digestTick(ctx context.Context, now time.Time) {
	if !w.digest.Enabled {
		return
	}
	h, m, err := w.digest.SendTime()
	if err != nil {
		w.log.Error("daily digest: send time", "error", err)
		return
	}
	due, err := opsdigest.Due(w.st.DigestSent, opsdigest.TimeOfDay{Hour: h, Minute: m}, now, w.loc)
	if err != nil || !due {
		if err != nil {
			w.log.Error("daily digest: due check", "error", err)
		}
		return
	}
	in, err := opsdigest.Collect(ctx, w.digestSources(now))
	if err != nil {
		w.log.Warn("daily digest: counts not read, retried later", "error", err)
		return
	}
	text, err := opsdigest.Build(in, opsdigest.Options{Lang: digestLang, NOSLink: w.base + "/", SkipEmpty: w.digest.SkipEmpty})
	switch {
	case errors.Is(err, opsdigest.ErrNothingToSend):
		w.recordDigest(now)
		return
	case err != nil:
		w.log.Error("daily digest: build", "error", err)
		return
	}
	e, err := notify.NewDailyDigest(text, now)
	if err != nil {
		w.log.Error("daily digest: message", "error", err)
		return
	}
	prev := w.st.DigestSent
	w.st.DigestSent = now
	if err := w.save(); err != nil {
		// As for the lease events: no send without the saved record.
		w.log.Error("daily digest: save state", "error", err)
		w.st.DigestSent = prev
		return
	}
	w.deliver(ctx, e)
}

// recordDigest marks the day's digest as handled without sending anything.
func (w *leaseWatcher) recordDigest(now time.Time) {
	prev := w.st.DigestSent
	w.st.DigestSent = now
	if err := w.save(); err != nil {
		w.log.Error("daily digest: save state", "error", err)
		w.st.DigestSent = prev
	}
}

// digestSources connects the digest counts to the server's stores.
func (w *leaseWatcher) digestSources(now time.Time) opsdigest.Sources {
	return opsdigest.Sources{
		Updates:        countFunc(w.countOpenUpdates),
		Reboots:        countFunc(w.countRebootsPending),
		NotReady:       countFunc(w.countHostsNotReady),
		GrantsExpiring: countFunc(func(ctx context.Context) (int, error) { return w.countGrantsExpiring(ctx, now) }),
		Findings:       findingsFunc(w.countFindings),
		FailedRuns:     countFunc(func(ctx context.Context) (int, error) { return w.countFailedRuns(ctx, now) }),
	}
}

// countFunc adapts a function to opsdigest.CountSource.
type countFunc func(ctx context.Context) (int, error)

// Count implements opsdigest.CountSource.
func (f countFunc) Count(ctx context.Context) (int, error) { return f(ctx) }

// findingsFunc adapts a function to opsdigest.FindingSource.
type findingsFunc func(ctx context.Context) (opsdigest.Findings, error)

// Findings implements opsdigest.FindingSource.
func (f findingsFunc) Findings(ctx context.Context) (opsdigest.Findings, error) { return f(ctx) }

func (w *leaseWatcher) countOpenUpdates(ctx context.Context) (int, error) {
	ups, err := w.src.AllUpdates(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range ups {
		n += u.Total
	}
	return n, nil
}

func (w *leaseWatcher) countRebootsPending(ctx context.Context) (int, error) {
	ups, err := w.src.AllUpdates(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range ups {
		if u.RebootRequired {
			n++
		}
	}
	return n, nil
}

// countHostsNotReady counts managed hosts whose Ops State is not READY. A host
// without a stored state counts as not READY.
func (w *leaseWatcher) countHostsNotReady(ctx context.Context) (int, error) {
	if w.hosts == nil {
		return 0, opsdigest.ErrMissingSource
	}
	hs, err := w.hosts.List(ctx)
	if err != nil {
		return 0, err
	}
	states, err := w.src.AllOpsStates(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range hs {
		if st, ok := states[h.ID]; !ok || st.State != executions.StateReady {
			n++
		}
	}
	return n, nil
}

// countGrantsExpiring counts active grants that end within the digest window.
func (w *leaseWatcher) countGrantsExpiring(ctx context.Context, now time.Time) (int, error) {
	grants, err := w.grantSnapshot(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, g := range grants {
		if g.ExpiresAt.After(now) && !g.ExpiresAt.After(now.Add(digestGrantWindow)) {
			n++
		}
	}
	return n, nil
}

// countFindings counts open findings per tier and the KEV-listed ones. The tier
// and KEV rules are those of the vulnerability notifications. A read that does
// not return every finding is an error, so the digest never shows a partial count.
func (w *leaseWatcher) countFindings(ctx context.Context) (opsdigest.Findings, error) {
	if w.vulns == nil {
		return opsdigest.Findings{}, opsdigest.ErrMissingSource
	}
	fs, more, err := w.vulns.List(ctx, vulnstore.ListQuery{Limit: vulnstore.MaxListFindings})
	if err != nil {
		return opsdigest.Findings{}, err
	}
	if more {
		return opsdigest.Findings{}, errDigestFindingsTruncated
	}
	var out opsdigest.Findings
	for _, f := range fs {
		if f.State != vulnstore.StateOpen {
			continue
		}
		switch f.EpisodePeakTier {
		case vulnstore.TierCritical:
			out.Critical++
		case vulnstore.TierHigh:
			out.High++
		case vulnstore.TierMedium:
			out.Medium++
		case vulnstore.TierLow:
			out.Low++
		default:
			out.Unknown++
		}
		if f.EpisodeKEV() || f.Record.Scores.KEV != nil {
			out.KEV++
		}
	}
	return out, nil
}

// countFailedRuns counts host runs of the last 24 hours that finished and did
// not succeed or did not run.
func (w *leaseWatcher) countFailedRuns(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := w.db.QueryRowContext(ctx, `SELECT count(*) FROM execution_hosts
		WHERE state = 'finished' AND finished_at >= ? AND class NOT IN ('success', 'skipped', 'not_run', 'not_executed')`,
		now.Add(-24*time.Hour).Unix()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count failed runs: %w", err)
	}
	return n, nil
}
