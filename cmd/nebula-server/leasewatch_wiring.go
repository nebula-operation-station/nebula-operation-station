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
	"regexp"
	"sort"
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
	// leaseRunMaxPages bounds the queries per tick, so that a backlog of runs
	// is read over several ticks instead of one long one. The scan resumes at
	// the last run read, so no run is skipped.
	leaseRunMaxPages = 10
	// leaseRunWindow is how far behind the clock the stored runs are still
	// read. A run row that commits later than its finish time plus this window
	// is not read.
	leaseRunWindow = time.Hour
	// leaseRunSeenMax bounds the saved set of runs read inside the window.
	leaseRunSeenMax = 4096
	// leaseExecIDMax and leaseHostIDMax bound the two parts of a saved run key
	// (execution ID, tab, host ID). They match the ID formats of the executions
	// and inventory packages; runKeyRe enforces them so that no key needs JSON
	// escaping.
	leaseExecIDMax = 36
	leaseHostIDMax = 63
	// leaseRunSeenEntryMax is the largest encoded size of one saved run: the key
	// with its escaped tab, quotes, colon, an int64 and a comma.
	leaseRunSeenEntryMax = leaseExecIDMax + 1 + leaseHostIDMax + 1 + 2 + 1 + 20 + 1
	// leaseWatchMaxState bounds the state file size, on save and on load: the
	// marks (leasewatch.MaxStateBytes), the recorded runs at their maximum size,
	// and a small allowance for the envelope.
	leaseWatchMaxState = leasewatch.MaxStateBytes + leaseRunSeenMax*leaseRunSeenEntryMax + 4096
	// digestLang is the text language of the daily digest (ADR 0016: de).
	digestLang = opsdigest.LangDE
	// digestGrantWindow is the window of the "grants expiring" digest count.
	digestGrantWindow = 7 * 24 * time.Hour
)

// runKeyRe is the form of a saved run key: an execution ID, a tab and a host ID,
// in plain character sets and within their length limits. The parts may be
// empty: a row with an empty host is still recorded (so it is read once) and
// then rejected by leasewatch. A key that does not match is not saved, so its
// JSON form is exactly its length (no escaping).
var runKeyRe = regexp.MustCompile(`^[0-9A-Za-z._-]{0,36}\t[0-9A-Za-z._-]{0,63}$`)

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
// expiry marks and open run-failure episodes. The run part is the scan start
// for stored runs (RunFrom, Unix seconds, trailing the clock by leaseRunWindow)
// and the set of runs already read inside it (RunSeen, keyed by run, with
// the finish time), so that a run is read once even when its row commits late.
type leaseWatchState struct {
	Watch      leasewatch.State
	Init       bool
	RunFrom    int64
	RunSeen    map[string]int64
	DigestSent time.Time
}

// leaseFile is the on-disk form. The watch state uses the leasewatch codec,
// which validates the limits when it is read.
type leaseFile struct {
	Init       bool             `json:"init"`
	Watch      json.RawMessage  `json:"watch,omitempty"`
	RunFrom    int64            `json:"run_from"`
	RunSeen    map[string]int64 `json:"run_seen,omitempty"`
	DigestSent time.Time        `json:"digest_sent"`
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

	// runBatch and runMaxPages bound the stored-run reads of one tick. They
	// are set by newLeaseWatcher; tests lower them.
	runBatch    int
	runMaxPages int

	st    leaseWatchState
	saved []byte
	// blocked is set while the state file exists but cannot be used (not
	// readable, too large, malformed or over a limit). Nothing is sent and
	// nothing is written while it is set: the file is kept for the admin, and
	// the watch retries the load at each tick.
	blocked bool
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
		loc: loc, path: filepath.Join(dataDir, leaseWatchStateFile), now: now, log: log,
		runBatch: leaseRunBatch, runMaxPages: leaseRunMaxPages}
}

// load reads the saved state. A missing file is a first start. A file that
// cannot be read, is too large or does not validate blocks the watch (see
// blocked): the file is not overwritten, so the marks it holds are not lost and
// no message is repeated. The admin fixes or removes the file; the load is
// retried at each tick.
func (w *leaseWatcher) load() {
	data, err := os.ReadFile(w.path)
	if errors.Is(err, os.ErrNotExist) {
		w.blocked = false
		return
	}
	if err != nil {
		w.blocked = true
		w.log.Error("lease watch: state not readable, nothing sent until it is", "error", err)
		return
	}
	if len(data) > leaseWatchMaxState {
		w.blocked = true
		w.log.Error("lease watch: state too large, nothing sent until it is fixed", "bytes", len(data), "limit", leaseWatchMaxState)
		return
	}
	st, err := decodeLeaseFile(data)
	if err != nil {
		w.blocked = true
		w.log.Error("lease watch: state invalid, nothing sent until it is fixed", "error", err)
		return
	}
	w.blocked = false
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
	if err := validateRunSeen(f.RunSeen); err != nil {
		return leaseWatchState{}, err
	}
	st := leaseWatchState{Init: f.Init, RunFrom: f.RunFrom, RunSeen: f.RunSeen, DigestSent: f.DigestSent}
	if len(f.Watch) > 0 {
		ws, err := leasewatch.DecodeState(f.Watch)
		if err != nil {
			return leaseWatchState{}, fmt.Errorf("decode lease watch marks: %w", err)
		}
		st.Watch = ws
	}
	return st, nil
}

// validateRunSeen checks the recorded runs: at most leaseRunSeenMax entries, each
// with a well-formed run key and a finish time after the epoch.
func validateRunSeen(seen map[string]int64) error {
	if len(seen) > leaseRunSeenMax {
		return fmt.Errorf("lease watch run_seen: %d entries > %d", len(seen), leaseRunSeenMax)
	}
	for k, at := range seen {
		if !runKeyRe.MatchString(k) {
			return fmt.Errorf("lease watch run_seen: malformed run key")
		}
		if at <= 0 {
			return fmt.Errorf("lease watch run_seen: finish time %d not positive", at)
		}
	}
	return nil
}

// encode returns the on-disk form of the state. It refuses a state that the
// load would not accept, so that a save never leaves an unreadable file.
func (w *leaseWatcher) encode() ([]byte, error) {
	if err := validateRunSeen(w.st.RunSeen); err != nil {
		return nil, err
	}
	watch, err := leasewatch.EncodeState(w.st.Watch)
	if err != nil {
		return nil, fmt.Errorf("encode lease watch marks: %w", err)
	}
	data, err := json.Marshal(leaseFile{Init: w.st.Init, Watch: watch, RunFrom: w.st.RunFrom, RunSeen: w.st.RunSeen,
		DigestSent: w.st.DigestSent})
	if err != nil {
		return nil, fmt.Errorf("encode lease watch state: %w", err)
	}
	if len(data) > leaseWatchMaxState {
		return nil, fmt.Errorf("%w: %d > %d bytes", leasewatch.ErrStateTooLarge, len(data), leaseWatchMaxState)
	}
	return data, nil
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
	if w.blocked {
		w.load()
		if w.blocked {
			return
		}
	}
	now := w.now()
	prev := w.st
	prevSaved := w.saved

	var events []notify.Event
	silent := !w.st.Init
	if silent {
		// First start: nothing before now is reported. Expiry marks are set
		// by the first snapshot, so grants that are already inside 7 days
		// are still reported once.
		w.st.Init = true
		w.st.RunFrom = now.Add(-leaseRunWindow).Unix()
		w.st.RunSeen = nil
	}
	events = append(events, w.expiryEvents(ctx, now)...)
	events = append(events, w.runEvents(ctx, now, silent)...)

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
// watch sees them. It fails only if either list cannot be read.
//
// One bad grant does not stop the others. A grant that is invalid (no expiry,
// an ID the notification cannot link, a duplicate ID) is skipped, and so is
// every grant beyond leasewatch.MaxTrackedGrants, the first ones by ID being
// kept. A skipped grant gets no expiry mark, so it is never recorded as warned
// without a message. The skips are logged as counts, not per ID.
func (w *leaseWatcher) grantSnapshot(ctx context.Context) ([]leasewatch.Grant, error) {
	reads, err := w.src.ReadGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("list read grants: %w", err)
	}
	scheds, err := w.src.Schedules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	var all []leasewatch.Grant
	for _, g := range reads {
		if g.State != "active" || g.Legacy {
			continue
		}
		all = append(all, leasewatch.Grant{ID: g.ID, Name: g.ID, Kind: leasewatch.KindReadLease, ExpiresAt: g.Expiry})
	}
	for _, s := range scheds {
		if s.State != "active" {
			continue
		}
		all = append(all, leasewatch.Grant{ID: s.ID, Name: s.ID, Kind: leasewatch.KindScheduleGrant, ExpiresAt: s.ExpiresAt})
	}

	skipped := 0
	seen := make(map[string]struct{}, len(all))
	out := make([]leasewatch.Grant, 0, len(all))
	for _, g := range all {
		if _, dup := seen[g.ID]; dup || !notify.ValidLeaseID(g.ID) || g.ExpiresAt.IsZero() {
			skipped++
			continue
		}
		seen[g.ID] = struct{}{}
		out = append(out, g)
	}
	if len(out) > leasewatch.MaxTrackedGrants {
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		skipped += len(out) - leasewatch.MaxTrackedGrants
		out = out[:leasewatch.MaxTrackedGrants]
	}
	if skipped > 0 {
		w.log.Warn("lease watch: grants skipped", "count", skipped, "limit", leasewatch.MaxTrackedGrants)
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
	prev := w.st.Watch.Expiry
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
			// The mark was set for a warning that was not built. Roll it back
			// so that the warning is still due at the next tick.
			w.log.Error("lease watch: build expiry message", "error", err)
			w.rollbackExpiryMark(d.GrantID, prev)
			continue
		}
		out = append(out, e)
	}
	return out
}

// rollbackExpiryMark restores the expiry marks of one grant to their value
// before this tick.
func (w *leaseWatcher) rollbackExpiryMark(id string, prev map[string]leasewatch.ExpiryMarks) {
	if m, ok := prev[id]; ok {
		w.st.Watch.Expiry[id] = m
		return
	}
	delete(w.st.Watch.Expiry, id)
}

// runEvents reads the finished lease runs from the scan start on, sends a
// lease.run_failed for each failure that opens an episode, and records the
// runs it has read. The scan start trails the clock by leaseRunWindow, so a run
// whose row commits after a newer run was read is still read. The recorded set
// keeps a run from being read, and so from being reported, twice. With silent
// set (the first start) the runs are recorded but nothing is reported.
//
// Reads come first: if a read fails, nothing is decided and the state is not
// changed, so the next tick reads the same window again.
func (w *leaseWatcher) runEvents(ctx context.Context, now time.Time, silent bool) []notify.Event {
	seen := make(map[string]int64, len(w.st.RunSeen))
	for k, at := range w.st.RunSeen {
		seen[k] = at
	}
	var fresh []storedRun
	// The first position is one second before the scan start, so that runs
	// finishing exactly at the scan start are read (finish times are whole
	// seconds).
	pageAt, pageExec, pageHost := w.st.RunFrom-1, "", ""
	lastAt := w.st.RunFrom
	truncated := false
	skippedKeys := 0
	for pages := 0; ; pages++ {
		if pages == w.runMaxPages {
			// The backlog goes on. The scan resumes at lastAt on the next
			// tick; the runs seen so far stay in the recorded set.
			truncated = true
			break
		}
		page, err := storedLeaseRuns(ctx, w.db, pageAt, pageExec, pageHost, w.runBatch)
		if err != nil {
			w.log.Error("lease watch: read stored runs", "error", err)
			return nil
		}
		for _, r := range page {
			lastAt = r.at
			if !runKeyRe.MatchString(r.key()) {
				// An ID outside its format cannot be saved. It is skipped
				// and counted, not reported.
				skippedKeys++
				continue
			}
			if _, ok := seen[r.key()]; ok {
				continue
			}
			seen[r.key()] = r.at
			fresh = append(fresh, r)
		}
		if len(page) < w.runBatch {
			break
		}
		last := page[len(page)-1]
		pageAt, pageExec, pageHost = last.at, last.exec, last.host
	}

	if skippedKeys > 0 {
		w.log.Warn("lease watch: stored runs with malformed IDs skipped", "count", skippedKeys)
	}
	var out []notify.Event
	if !silent {
		label := w.lazyHostNames(ctx)
		for _, r := range fresh {
			if notRunClass(r.class) {
				continue
			}
			res := leasewatch.RunResult{GrantID: r.grant, Action: r.action, HostLabel: r.host,
				Success: r.class == classSuccess, At: time.Unix(r.at, 0)}
			// One run at a time: a run that cannot be used is logged and
			// skipped. It is already in the recorded set, so it is not retried.
			due, next, err := leasewatch.RunFailed([]leasewatch.RunResult{res}, w.st.Watch)
			if err != nil {
				w.log.Error("lease watch: stored run skipped", "execution", r.exec, "error", err)
				continue
			}
			// RunFailed returns only the episodes. The expiry marks belong to
			// Expiring and must survive this step, or the next tick and the
			// next restart would report the expiry again.
			next.Expiry = w.st.Watch.Expiry
			w.st.Watch = next
			for _, d := range due {
				e, err := notify.NewLeaseRunFailed(w.base, notify.LeaseRunFailure{
					GrantID: d.GrantID, GrantName: d.GrantID, Action: d.Action, HostLabel: label(d.HostLabel), At: d.At,
				})
				if err != nil {
					w.log.Error("lease watch: build run failure message", "error", err)
					continue
				}
				out = append(out, e)
			}
		}
	}

	// Runs that finished more than leaseRunWindow ago are no longer read, and
	// the recorded set keeps only the runs still in the window. If the set is
	// over its limit, the window is shortened to the newest leaseRunSeenMax runs.
	newFrom := now.Add(-leaseRunWindow).Unix()
	if newFrom < w.st.RunFrom {
		newFrom = w.st.RunFrom
	}
	if truncated {
		// Runs after lastAt were not read yet. The scan must start there, not
		// at the clock's window, or they would be skipped.
		newFrom = lastAt
	}
	pruneRunSeen(seen, newFrom)
	if len(seen) > leaseRunSeenMax {
		// Keep only the runs that finished after cut, the second of the
		// (leaseRunSeenMax+1)-th newest run. That keeps at most leaseRunSeenMax
		// runs. A second is never split: its runs are all kept or all dropped,
		// and moving the scan start past a dropped second means its runs are
		// not read again.
		ats := make([]int64, 0, len(seen))
		for _, at := range seen {
			ats = append(ats, at)
		}
		sort.Slice(ats, func(i, j int) bool { return ats[i] > ats[j] })
		cut := ats[leaseRunSeenMax] + 1
		if truncated && cut > lastAt {
			// Unread runs of second lastAt follow on the next tick. They
			// cannot be kept without the bound, so they are skipped.
			w.log.Warn("lease watch: more runs finished in one second than are recorded; some are not reported", "second", lastAt)
			cut = lastAt + 1
		}
		if cut > newFrom {
			newFrom = cut
		}
		pruneRunSeen(seen, newFrom)
	}
	w.st.RunFrom = newFrom
	w.st.RunSeen = seen
	return out
}

// pruneRunSeen removes the recorded runs that finished before from.
func pruneRunSeen(seen map[string]int64, from int64) {
	for k, at := range seen {
		if at < from {
			delete(seen, k)
		}
	}
}

// lazyHostNames returns a function that maps a host ID to its display name. The
// inventory is read on the first call only, so a tick reads it at most once,
// and not at all when nothing is due.
func (w *leaseWatcher) lazyHostNames(ctx context.Context) func(id string) string {
	var names map[string]string
	read := false
	return func(id string) string {
		if !read {
			read = true
			names = w.hostNames(ctx)
		}
		if n, ok := names[id]; ok {
			return n
		}
		return id
	}
}

// hostNames reads the inventory and returns the display names by host ID. An
// inventory that cannot be read gives no names; the IDs are shown instead.
func (w *leaseWatcher) hostNames(ctx context.Context) map[string]string {
	if w.hosts == nil {
		return nil
	}
	hs, err := w.hosts.List(ctx)
	if err != nil {
		w.log.Warn("lease watch: inventory not read, host IDs shown", "error", err)
		return nil
	}
	names := make(map[string]string, len(hs))
	for _, h := range hs {
		if h.DisplayName != "" {
			names[h.ID] = h.DisplayName
		}
	}
	return names
}

// storedRun is one finished host run of a lease, as stored. at is the finish
// time in Unix seconds.
type storedRun struct {
	exec, grant, action, host, class string
	at                               int64
}

// key identifies a host run: an execution and a host.
func (r storedRun) key() string { return r.exec + "\t" + r.host }

// storedLeaseRuns returns up to limit finished runs of leases that sort after
// the position (at, exec, host), in that order: finish time, execution, host.
// Pass a position of (scan start - 1, "", "") to start at the scan start.
//
// The query has no index on execution_hosts.finished_at, so each page is a
// scan of the host rows. A migration adding one is a follow-up; it is not part
// of this change.
func storedLeaseRuns(ctx context.Context, db *sql.DB, at int64, exec, host string, limit int) ([]storedRun, error) {
	rows, err := db.QueryContext(ctx, `SELECT e.id, e.schedule_id, e.action_id, h.host_id, h.class, h.finished_at
		FROM executions e JOIN execution_hosts h ON h.execution_id = e.id
		WHERE e.schedule_id IS NOT NULL AND e.schedule_id <> '' AND h.state = 'finished' AND h.finished_at IS NOT NULL
		AND (h.finished_at > ? OR (h.finished_at = ? AND (h.execution_id > ? OR (h.execution_id = ? AND h.host_id > ?))))
		ORDER BY h.finished_at, h.execution_id, h.host_id LIMIT ?`,
		at, at, exec, exec, host, limit)
	if err != nil {
		return nil, fmt.Errorf("query lease runs: %w", err)
	}
	defer rows.Close()
	var out []storedRun
	for rows.Next() {
		var r storedRun
		if err := rows.Scan(&r.exec, &r.grant, &r.action, &r.host, &r.class, &r.at); err != nil {
			return nil, fmt.Errorf("scan lease run: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read lease runs: %w", err)
	}
	return out, nil
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

// countFindings counts open findings per tier and the KEV-listed ones. It counts
// in the database, so the number of closed findings does not matter and there
// is no read limit to hit. The tier and KEV rules are those of the vulnerability
// notifications: the episode's peak tier, and KEV when the episode was ever
// KEV-listed or the record carries a KEV score (as in vulnstore's KEV filter).
// The query groups by tier and KEV; it scans the findings table once, and no
// index on state exists for it (a follow-up if the table grows large).
func (w *leaseWatcher) countFindings(ctx context.Context) (opsdigest.Findings, error) {
	if w.vulns == nil {
		return opsdigest.Findings{}, opsdigest.ErrMissingSource
	}
	rows, err := w.db.QueryContext(ctx, `SELECT episode_peak_tier,
		episode_kev_date IS NOT NULL OR json_extract(record, '$.scores.kev') IS NOT NULL, count(*)
		FROM vuln_findings WHERE state = ? GROUP BY 1, 2`, vulnstore.StateOpen)
	if err != nil {
		return opsdigest.Findings{}, fmt.Errorf("count open findings: %w", err)
	}
	defer rows.Close()
	var out opsdigest.Findings
	for rows.Next() {
		var tier int
		var kev bool
		var n int
		if err := rows.Scan(&tier, &kev, &n); err != nil {
			return opsdigest.Findings{}, fmt.Errorf("scan open findings: %w", err)
		}
		switch vulnstore.Tier(tier) {
		case vulnstore.TierCritical:
			out.Critical += n
		case vulnstore.TierHigh:
			out.High += n
		case vulnstore.TierMedium:
			out.Medium += n
		case vulnstore.TierLow:
			out.Low += n
		default:
			out.Unknown += n
		}
		if kev {
			out.KEV += n
		}
	}
	if err := rows.Err(); err != nil {
		return opsdigest.Findings{}, fmt.Errorf("read open findings: %w", err)
	}
	return out, nil
}

// countFailedRuns counts the executions that ended in state failed within the
// last 24 hours (opsdigest FailedRuns24h). A failed execution with several
// failed host rows counts once, and host rows of other executions do not count.
func (w *leaseWatcher) countFailedRuns(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := w.db.QueryRowContext(ctx, `SELECT count(*) FROM executions
		WHERE state = 'failed' AND finished_at >= ?`,
		now.Add(-24*time.Hour).Unix()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count failed runs: %w", err)
	}
	return n, nil
}
