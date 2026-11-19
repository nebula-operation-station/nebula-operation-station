// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/leasewatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsdigest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// leaseFixture is a server.db, a fake executor read side and a recording
// sender, with a clock the test moves by hand.
type leaseFixture struct {
	t    *testing.T
	db   *sql.DB
	dir  string
	src  *fakeLeaseSource
	send *recordingSender
	now  time.Time
	seq  int
	vuln *vulnService
}

// fakeLeaseSource stands in for the executions service.
type fakeLeaseSource struct {
	reads    []executions.ReadGrantView
	readErr  error
	scheds   []executions.Schedule
	schedErr error
}

func (f *fakeLeaseSource) ReadGrants(context.Context) ([]executions.ReadGrantView, error) {
	return f.reads, f.readErr
}

func (f *fakeLeaseSource) Schedules(context.Context) ([]executions.Schedule, error) {
	return f.scheds, f.schedErr
}

func (f *fakeLeaseSource) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	return nil, nil
}

func (f *fakeLeaseSource) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	return nil, nil
}

// recordingSender keeps every event it was asked to send.
type recordingSender struct{ events []notify.Event }

func (r *recordingSender) Notify(_ context.Context, e notify.Event) int {
	r.events = append(r.events, e)
	return 1
}

func (r *recordingSender) Enabled() bool { return true }

// emptyHosts is an inventory with no hosts.
type emptyHosts struct{}

func (emptyHosts) List(context.Context) ([]inventory.Host, error) { return nil, nil }

var leaseT0 = time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)

func newLeaseFixture(t *testing.T) *leaseFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The vulnerability store needs a sink; a notifier without providers
	// sends nothing, which is what these tests need.
	vs, err := newVulnService(db, notify.NewWithSenders(log, nil), log, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &leaseFixture{t: t, db: db, dir: dir, src: &fakeLeaseSource{}, send: &recordingSender{}, now: leaseT0, vuln: vs}
}

// watcher returns a watcher over the fixture's state directory, as a restarted
// server would build it.
func (f *leaseFixture) watcher(digest serverconfig.DailyDigest) *leaseWatcher {
	return f.watcherWith(digest, emptyHosts{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// watcherWith is watcher with the inventory and the log the test wants.
func (f *leaseFixture) watcherWith(digest serverconfig.DailyDigest, hosts hostLister, log *slog.Logger) *leaseWatcher {
	w := newLeaseWatcher(f.db, f.src, hosts, f.vuln.store, f.send, "https://nebula.example.org", digest,
		time.UTC, f.dir, func() time.Time { return f.now }, log)
	w.load()
	return w
}

// countingHosts is an inventory that counts how often it is read.
type countingHosts struct {
	hosts []inventory.Host
	calls int
}

func (c *countingHosts) List(context.Context) ([]inventory.Host, error) {
	c.calls++
	return c.hosts, nil
}

// failedCount returns how many lease.run_failed events were sent.
func (r *recordingSender) failedCount() int {
	n := 0
	for _, k := range r.kinds() {
		if k == notify.KindLeaseRunFailed {
			n++
		}
	}
	return n
}

// run inserts one finished lease run of grant on host, finished at at.
func (f *leaseFixture) run(grant, action, host, class string, at time.Time) {
	f.t.Helper()
	f.seq++
	id := fmt.Sprintf("%036d", f.seq)
	sha := strings.Repeat("a", 64)
	if _, err := f.db.Exec(`INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
		durable, timeout_s, created_by, created_at, finished_at, params, schedule_id) VALUES (?, '', ?, '1', ?, 'LOW', 'read lease', 'finished', 0, 60, 'schedule', ?, ?, '{}', ?)`,
		id, action, sha, at.Unix(), at.Unix(), grant); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, exit_code, started_at, finished_at)
		VALUES (?, ?, 'fp', '', '[]', 'finished', ?, 0, ?, ?)`, id, host, class, at.Unix(), at.Unix()); err != nil {
		f.t.Fatal(err)
	}
}

// kinds returns the event kinds sent so far.
func (r *recordingSender) kinds() []string {
	var out []string
	for _, e := range r.events {
		out = append(out, e.Kind)
	}
	return out
}

// activeRead is an active read lease that ends at expiry.
func activeRead(id string, expiry time.Time) executions.ReadGrantView {
	return executions.ReadGrantView{ID: id, State: "active", Expiry: expiry}
}

func TestLeaseWatchRestartDoesNotRepeatExpiryOrRunFailure(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(6*24*time.Hour))}

	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0: the grant is inside 7 days
	f.now = leaseT0.Add(time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	f.now = leaseT0.Add(2 * time.Minute)
	w.Tick(context.Background())
	if got := f.send.kinds(); len(got) != 2 || got[0] != notify.KindLeaseExpiring || got[1] != notify.KindLeaseRunFailed {
		t.Fatalf("first run sent %v; want one lease.expiring and one lease.run_failed", got)
	}

	// Restart: a new watcher reads the saved state; nothing is due again.
	f.now = leaseT0.Add(10 * time.Minute)
	restarted := f.watcher(serverconfig.DailyDigest{})
	restarted.Tick(context.Background())
	if n := len(f.send.events); n != 2 {
		t.Fatalf("after restart %d events were sent in total, want 2: %v", n, f.send.kinds())
	}
	// A second restart, with the same grant still inside the window, is quiet too.
	f.now = leaseT0.Add(20 * time.Minute)
	f.watcher(serverconfig.DailyDigest{}).Tick(context.Background())
	if n := len(f.send.events); n != 2 {
		t.Fatalf("second restart sent again: %d events in total, want 2", n)
	}
}

func TestLeaseWatchFirstStartReportsNoOldFailures(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(30*24*time.Hour))}
	f.run("lease-a", "os.updates.list", "host-1", "failed", leaseT0.Add(-time.Hour))

	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("first start sent %v; a failure before the first start must not be reported", f.send.kinds())
	}
}

func TestLeaseWatchExecutorUnreachableSendsNothingAndKeepsDueEvents(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.readErr = errors.New("executor down")
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(2*time.Hour))}

	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start; grants unreadable
	f.now = leaseT0.Add(time.Minute)
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("with the executor down %d events were sent, want none", n)
	}

	// The executor is back: the grant is inside the 1-day window and the event
	// is sent exactly once, not dropped.
	f.src.readErr = nil
	f.now = leaseT0.Add(2 * time.Minute)
	w.Tick(context.Background())
	f.now = leaseT0.Add(3 * time.Minute)
	w.Tick(context.Background())
	if got := f.send.kinds(); len(got) != 1 || got[0] != notify.KindLeaseExpiring {
		t.Fatalf("after recovery sent %v; want one lease.expiring", got)
	}
}

func TestLeaseWatchRunFailureOncePerEpisode(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(30*24*time.Hour))}
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start

	f.now = leaseT0.Add(time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now.Add(time.Second))
	w.Tick(context.Background())
	f.now = leaseT0.Add(2 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "success", f.now)
	w.Tick(context.Background())
	f.now = leaseT0.Add(3 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(context.Background())

	want := []string{notify.KindLeaseRunFailed, notify.KindLeaseRunFailed}
	if got := f.send.kinds(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sent %v; want one event per episode %v", got, want)
	}
}

// TestLeaseWatchRunFailureOnceForGrantOutsideSnapshot: a grant that is not in
// the snapshot (here: no grant is active at all) keeps its open episode across
// ticks. Each later failure of the same run is silent until a success.
func TestLeaseWatchRunFailureOnceForGrantOutsideSnapshot(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start

	f.now = leaseT0.Add(time.Minute)
	f.run("lease-x", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(context.Background())
	f.now = leaseT0.Add(2 * time.Minute)
	f.run("lease-x", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(context.Background())
	f.now = leaseT0.Add(3 * time.Minute)
	w = f.watcher(serverconfig.DailyDigest{}) // restart
	w.Tick(context.Background())
	f.now = leaseT0.Add(4 * time.Minute)
	f.run("lease-x", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(context.Background())

	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("%d lease.run_failed events for one open episode, want 1", n)
	}
}

// TestLeaseWatchRunFailureEpisodeSurvivesTicksAndRestarts: the grant stays
// active in the snapshot across several ticks and a restart. The open episode
// must survive those ticks, so repeated failures of the same grant, action and
// host are one event until a success ends the episode.
func TestLeaseWatchRunFailureEpisodeSurvivesTicksAndRestarts(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(30*24*time.Hour))}
	w := f.watcher(serverconfig.DailyDigest{})
	ctx := context.Background()
	w.Tick(ctx) // first start at T0

	f.now = leaseT0.Add(1 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(ctx)
	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("first failure sent %d lease.run_failed events, want 1", n)
	}

	// Failures of the open episode across several ticks, and across a restart.
	f.now = leaseT0.Add(2 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(ctx)
	f.now = leaseT0.Add(3 * time.Minute)
	w.Tick(ctx)
	f.now = leaseT0.Add(4 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	w = f.watcher(serverconfig.DailyDigest{})
	w.Tick(ctx)
	f.now = leaseT0.Add(5 * time.Minute)
	w.Tick(ctx)
	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("repeated failures of one open episode sent %d lease.run_failed events, want 1", n)
	}

	// A success ends the episode; the next failure is a new episode.
	f.now = leaseT0.Add(6 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "success", f.now)
	w.Tick(ctx)
	f.now = leaseT0.Add(7 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	w.Tick(ctx)
	f.now = leaseT0.Add(8 * time.Minute)
	w.Tick(ctx)
	if n := f.send.failedCount(); n != 2 {
		t.Fatalf("after a success and a new failure sent %d lease.run_failed events, want 2", n)
	}
}

func TestLeaseWatchSkippedRunIsNotAFailure(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background())
	f.now = leaseT0.Add(time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "skipped", f.now)
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("a skipped run sent %v", f.send.kinds())
	}
}

func TestDigestOffSendsNothing(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{Enabled: false})
	f.now = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("digest off sent %v", f.send.kinds())
	}
}

func TestDigestSendsOnceAfterAnOutage(t *testing.T) {
	f := newLeaseFixture(t)
	digest := serverconfig.DailyDigest{Enabled: true, Time: "07:00"}
	w := f.watcher(digest)
	w.Tick(context.Background()) // first start at 08:00, after the 07:00 slot

	count := func() int {
		n := 0
		for _, k := range f.send.kinds() {
			if k == notify.KindDailyDigest {
				n++
			}
		}
		return n
	}
	first := count()
	if first != 1 {
		t.Fatalf("digest on first start after 07:00: %d sent, want 1", first)
	}

	// Same day, later tick: no second digest.
	f.now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	w.Tick(context.Background())
	if count() != 1 {
		t.Fatalf("second digest on the same day")
	}

	// Server down for three days, then back before the next slot: one digest.
	f.now = time.Date(2026, 11, 21, 6, 30, 0, 0, time.UTC)
	restarted := f.watcher(digest)
	restarted.Tick(context.Background())
	f.now = time.Date(2026, 11, 21, 7, 30, 0, 0, time.UTC)
	restarted.Tick(context.Background())
	f.now = time.Date(2026, 11, 21, 8, 30, 0, 0, time.UTC)
	restarted.Tick(context.Background())
	if count() != 2 {
		t.Fatalf("after the outage %d digests in total, want 2", count())
	}
}

func TestDigestSkipEmptySendsNothingOnAnEmptyDay(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{Enabled: true, Time: "07:00", SkipEmpty: true})
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("skip_empty sent %v on an empty day", f.send.kinds())
	}
}

// execution inserts one finished execution in the given state, with no hosts.
func (f *leaseFixture) execution(state string, at time.Time) {
	f.t.Helper()
	f.seq++
	id := fmt.Sprintf("%036d", f.seq)
	sha := strings.Repeat("b", 64)
	if _, err := f.db.Exec(`INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
		durable, timeout_s, created_by, created_at, finished_at, params)
		VALUES (?, '', 'os.updates.list', '1', ?, 'LOW', '', ?, 0, 60, 'admin', ?, ?, '{}')`,
		id, sha, state, at.Unix(), at.Unix()); err != nil {
		f.t.Fatal(err)
	}
}

// TestDigestCountsFailedExecutionsOfTheLast24h: FailedRuns24h counts failed
// executions, not host rows, and only those finished inside the last 24 hours.
func TestDigestCountsFailedExecutionsOfTheLast24h(t *testing.T) {
	f := newLeaseFixture(t)
	f.now = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	f.execution("failed", f.now.Add(-2*time.Hour))
	f.execution("failed", f.now.Add(-30*time.Hour))
	f.execution("finished", f.now.Add(-time.Hour))
	// A finished execution with a failed host row is not a failed execution.
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now.Add(-3*time.Hour))
	w := f.watcher(serverconfig.DailyDigest{Enabled: true, Time: "07:00"})
	n, err := w.countFailedRuns(context.Background(), f.now)
	if err != nil || n != 1 {
		t.Fatalf("countFailedRuns = %d, %v; want 1", n, err)
	}
}

// TestLeaseWatchRunCommittedLateIsNotifiedOnce: a failed run whose finished_at
// is older than the mark, and which commits only after the watcher has moved
// past it, is still notified, exactly once.
func TestLeaseWatchRunCommittedLateIsNotifiedOnce(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0

	f.now = leaseT0.Add(11 * time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "success", leaseT0.Add(10*time.Minute))
	w.Tick(context.Background()) // the mark is now at T0+10m

	// The failure finished at T0+5m, but its row commits only now.
	f.run("lease-b", "os.updates.list", "host-2", "failed", leaseT0.Add(5*time.Minute))
	f.now = leaseT0.Add(12 * time.Minute)
	w.Tick(context.Background())
	f.now = leaseT0.Add(13 * time.Minute)
	w.Tick(context.Background())
	f.now = leaseT0.Add(20 * time.Minute)
	f.watcher(serverconfig.DailyDigest{}).Tick(context.Background()) // restart

	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("late failure sent %d lease.run_failed events, want exactly 1: %v", n, f.send.kinds())
	}
}

// TestLeaseWatchSaveFailureSendsNothing: no event is sent when the state cannot
// be saved, and the event is sent once when the save works again.
func TestLeaseWatchSaveFailureSendsNothing(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0; state saved

	f.now = leaseT0.Add(time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	// A directory in place of the state file makes the atomic save fail.
	statePath := filepath.Join(f.dir, leaseWatchStateFile)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	f.now = leaseT0.Add(2 * time.Minute)
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("state could not be saved, but %v was sent", f.send.kinds())
	}

	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	f.now = leaseT0.Add(3 * time.Minute)
	w.Tick(context.Background())
	f.now = leaseT0.Add(4 * time.Minute)
	f.watcher(serverconfig.DailyDigest{}).Tick(context.Background()) // restart
	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("after the save works again %d lease.run_failed events, want exactly 1", n)
	}
}

// TestLeaseWatchInvalidStoredRowIsSkippedOnceAndTheMarkAdvances: one bad row
// does not block the good rows after it, and it is logged once, not per tick.
func TestLeaseWatchInvalidStoredRowIsSkippedOnceAndTheMarkAdvances(t *testing.T) {
	f := newLeaseFixture(t)
	var logs bytes.Buffer
	w := f.watcherWith(serverconfig.DailyDigest{}, emptyHosts{}, slog.New(slog.NewTextHandler(&logs, nil)))
	w.Tick(context.Background()) // first start at T0

	f.now = leaseT0.Add(time.Minute)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now)
	f.run("lease-b", strings.Repeat("x", leasewatch.MaxActionLen+1), "host-1", "failed", f.now.Add(time.Second))
	f.run("lease-c", "os.updates.list", "", "failed", f.now.Add(2*time.Second))
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("with two invalid rows sent %d lease.run_failed events, want the one valid run", n)
	}

	f.now = leaseT0.Add(2 * time.Minute)
	f.run("lease-d", "os.updates.list", "host-2", "failed", f.now)
	w.Tick(context.Background())
	f.now = leaseT0.Add(3 * time.Minute)
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 2 {
		t.Fatalf("after the later run sent %d lease.run_failed events, want 2", n)
	}
	if n := strings.Count(logs.String(), "lease watch: stored run skipped"); n != 2 {
		t.Fatalf("invalid rows logged %d times, want once each (2)", n)
	}
}

// TestLeaseWatchReadsTheInventoryOncePerTick: a burst of failures in one tick
// reads the inventory once, not once per event.
func TestLeaseWatchReadsTheInventoryOncePerTick(t *testing.T) {
	f := newLeaseFixture(t)
	hosts := &countingHosts{hosts: []inventory.Host{{ID: "host-1", DisplayName: "Web"}}}
	w := f.watcherWith(serverconfig.DailyDigest{}, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.Tick(context.Background()) // first start at T0

	hosts.calls = 0
	f.now = leaseT0.Add(time.Minute)
	for i := 0; i < 3; i++ {
		f.run(fmt.Sprintf("lease-%d", i), "os.updates.list", "host-1", "failed", f.now.Add(time.Duration(i)*time.Second))
	}
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 3 {
		t.Fatalf("sent %d lease.run_failed events, want 3", n)
	}
	if hosts.calls > 1 {
		t.Fatalf("inventory read %d times in one tick, want at most once", hosts.calls)
	}
	if f.send.events[0].Host != "Web" {
		t.Fatalf("host label %q, want the display name", f.send.events[0].Host)
	}
}

// TestLeaseWatchRunAtTheScanStartIsReadWhenItCommitsLate: a failed run that
// finished exactly at the scan start, and whose row commits after the window
// has moved to that start, is still read.
func TestLeaseWatchRunAtTheScanStartIsReadWhenItCommitsLate(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0: scan start T0-1h

	f.now = leaseT0.Add(10 * time.Minute)
	w.Tick(context.Background()) // the scan start moves to T0+10m-1h = T0-50m

	f.run("lease-a", "os.updates.list", "host-1", "failed", leaseT0.Add(-50*time.Minute))
	f.now = leaseT0.Add(11 * time.Minute)
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("run at the scan start sent %d lease.run_failed events, want 1", n)
	}
	f.now = leaseT0.Add(12 * time.Minute)
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 1 {
		t.Fatalf("run at the scan start was sent again: %d events, want 1", n)
	}
}

// TestLeaseWatchStoredRunsAreReadInBoundedPages: a backlog larger than one
// tick may read is read over several ticks, each run once, with no run skipped.
func TestLeaseWatchStoredRunsAreReadInBoundedPages(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0
	w.runBatch = 2
	w.runMaxPages = 2

	f.now = leaseT0.Add(time.Minute)
	for i := 1; i <= 5; i++ {
		f.run("lease-a", "os.updates.list", fmt.Sprintf("host-%d", i), "failed", leaseT0.Add(time.Duration(i)*time.Minute))
	}
	f.now = leaseT0.Add(6 * time.Minute)
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 4 {
		t.Fatalf("one tick with two pages of two sent %d events, want 4", n)
	}
	f.now = leaseT0.Add(7 * time.Minute)
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 5 {
		t.Fatalf("after the next tick %d lease.run_failed events, want 5 (each run once)", n)
	}
	f.now = leaseT0.Add(8 * time.Minute)
	w.Tick(context.Background())
	if n := f.send.failedCount(); n != 5 {
		t.Fatalf("a quiet tick sent again: %d events, want 5", n)
	}
}

// TestLeaseWatchInvalidGrantDoesNotStopOtherWarnings: one grant with a zero
// expiry, a duplicate ID, or an ID that the notification cannot link, is
// skipped; the valid grants in the same snapshot are still warned, and the
// skipped ones get no expiry mark.
func TestLeaseWatchInvalidGrantDoesNotStopOtherWarnings(t *testing.T) {
	f := newLeaseFixture(t)
	soon := leaseT0.Add(2 * time.Hour)
	f.src.reads = []executions.ReadGrantView{
		activeRead("lease-a", soon),
		activeRead("lease-zero", time.Time{}),
		activeRead("lease-a", soon),
		activeRead("bad id/with slash", soon),
		activeRead("lease-b", soon),
	}
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0
	if n := len(f.send.events); n != 2 {
		t.Fatalf("with one invalid grant sent %d events %v, want the two valid grants", n, f.send.kinds())
	}
	for _, id := range []string{"lease-zero", "bad id/with slash"} {
		if _, ok := w.st.Watch.Expiry[id]; ok {
			t.Fatalf("skipped grant %q got an expiry mark", id)
		}
	}
	f.now = leaseT0.Add(time.Minute)
	w.Tick(context.Background())
	if n := len(f.send.events); n != 2 {
		t.Fatalf("a later tick sent again: %d events, want 2", n)
	}
}

// TestLeaseWatchOverLimitSnapshotKeepsTheFirstGrantsByID: with more grants
// than the watch tracks, the first ones by ID are warned and the rest are
// skipped; the over-long snapshot does not stop the tracked grants.
func TestLeaseWatchOverLimitSnapshotKeepsTheFirstGrantsByID(t *testing.T) {
	f := newLeaseFixture(t)
	far := leaseT0.Add(30 * 24 * time.Hour)
	for i := 0; i <= leasewatch.MaxTrackedGrants; i++ {
		exp := far
		if i == 0 || i == leasewatch.MaxTrackedGrants {
			exp = leaseT0.Add(2 * time.Hour)
		}
		f.src.reads = append(f.src.reads, activeRead(fmt.Sprintf("lease-%04d", i), exp))
	}
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background())
	if n := len(f.send.events); n != 1 || !strings.Contains(f.send.events[0].Reason, "lease-0000") {
		t.Fatalf("over-limit snapshot sent %v; want one warning for lease-0000 only", f.send.kinds())
	}
}

// TestLeaseWatchFailedBuildKeepsTheWarningDue: when the message cannot be
// built (here a bad NOS origin), the warning is not lost: its mark is rolled
// back, so the warning is sent once the origin is fixed.
func TestLeaseWatchFailedBuildKeepsTheWarningDue(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(2*time.Hour))}
	w := f.watcher(serverconfig.DailyDigest{})
	good := w.base
	w.base = "ftp://nebula.example.org"
	w.Tick(context.Background()) // first start: the build fails
	if n := len(f.send.events); n != 0 {
		t.Fatalf("with a bad origin sent %d events, want none", n)
	}
	w.base = good
	f.now = leaseT0.Add(time.Minute)
	w.Tick(context.Background())
	if n := len(f.send.events); n != 1 {
		t.Fatalf("after the origin is fixed sent %d events, want the one warning", n)
	}
}

// writeLeaseFile writes raw bytes as the state file of the fixture.
func (f *leaseFixture) writeLeaseFile(data []byte) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, leaseWatchStateFile), data, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// runSeenJSON returns a state file body whose run_seen has n entries.
func runSeenJSON(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"init":true,"run_from":1,"run_seen":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%036d\thost-%d":%d`, i, i, leaseT0.Unix())
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

// TestLeaseWatchUnusableStateFileIsKeptAndNothingIsSent: a state file that
// cannot be parsed or validated is not overwritten, and nothing is sent from
// it. Overwriting it would forget the marks and repeat every expiry message.
func TestLeaseWatchUnusableStateFileIsKeptAndNothingIsSent(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"malformed", []byte(`{"init":true,`)},
		{"too large", bytes.Repeat([]byte("x"), leaseWatchMaxState+1)},
		{"run_seen over the limit", runSeenJSON(leaseRunSeenMax + 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLeaseFixture(t)
			f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(2*time.Hour))}
			f.writeLeaseFile(tc.body)
			w := f.watcher(serverconfig.DailyDigest{})
			f.run("lease-a", "os.updates.list", "host-1", "failed", leaseT0.Add(-time.Minute))
			for i := 0; i < 3; i++ {
				f.now = leaseT0.Add(time.Duration(i) * time.Minute)
				w.Tick(context.Background())
			}
			if n := len(f.send.events); n != 0 {
				t.Fatalf("unusable state file, but %v was sent", f.send.kinds())
			}
			got, err := os.ReadFile(filepath.Join(f.dir, leaseWatchStateFile))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Fatalf("unusable state file was overwritten (%d bytes, was %d)", len(got), len(tc.body))
			}
		})
	}
}

// TestLeaseWatchStateFileReadErrorIsKept: a state path that cannot be read
// (here a directory) is left alone and nothing is sent.
func TestLeaseWatchStateFileReadErrorIsKept(t *testing.T) {
	f := newLeaseFixture(t)
	f.src.reads = []executions.ReadGrantView{activeRead("lease-a", leaseT0.Add(2*time.Hour))}
	statePath := filepath.Join(f.dir, leaseWatchStateFile)
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background())
	if n := len(f.send.events); n != 0 {
		t.Fatalf("state file unreadable, but %v was sent", f.send.kinds())
	}
	if fi, err := os.Stat(statePath); err != nil || !fi.IsDir() {
		t.Fatalf("state path was replaced: %v", err)
	}
}

// TestLeaseWatchRunSeenStaysBoundedWhenRunsShareASecond: more runs finish in one
// second than leaseRunSeenMax. The recorded set must stay bounded, and the
// saved state must load after a restart.
func TestLeaseWatchRunSeenStaysBoundedWhenRunsShareASecond(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.Tick(context.Background()) // first start at T0

	at := leaseT0.Add(time.Minute)
	for i := 0; i < leaseRunSeenMax+50; i++ {
		f.run("lease-a", "os.updates.list", fmt.Sprintf("host-%d", i), "success", at)
	}
	f.now = leaseT0.Add(2 * time.Minute)
	w.Tick(context.Background())
	if n := len(w.st.RunSeen); n > leaseRunSeenMax {
		t.Fatalf("recorded runs %d > limit %d", n, leaseRunSeenMax)
	}
	restarted := f.watcher(serverconfig.DailyDigest{})
	if restarted.blocked || !restarted.st.Init {
		t.Fatalf("saved state does not load after a restart (blocked=%v init=%v)", restarted.blocked, restarted.st.Init)
	}
}

// TestLeaseWatchSaveRejectsRunSeenOverLimit: the save checks the recorded set
// with the same limit as the load.
func TestLeaseWatchSaveRejectsRunSeenOverLimit(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	w.st.RunSeen = make(map[string]int64, leaseRunSeenMax+1)
	for i := 0; i <= leaseRunSeenMax; i++ {
		w.st.RunSeen[fmt.Sprintf("%036d\thost-%d", i, i)] = leaseT0.Unix()
	}
	if _, err := w.encode(); err == nil {
		t.Fatalf("encode accepted %d recorded runs, limit %d", len(w.st.RunSeen), leaseRunSeenMax)
	}
}

// TestLeaseWatchWorstCaseStateFitsTheFileLimit: a state with every bounded part
// at its maximum must fit in leaseWatchMaxState, or a valid state could never
// be saved.
func TestLeaseWatchWorstCaseStateFitsTheFileLimit(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	pad := func(s string, n int) string {
		return s + strings.Repeat("a", n-len(s))
	}
	w.st.Watch.Expiry = make(map[string]leasewatch.ExpiryMarks, leasewatch.MaxTrackedGrants)
	for i := 0; i < leasewatch.MaxTrackedGrants; i++ {
		w.st.Watch.Expiry[pad(fmt.Sprintf("g%d", i), leasewatch.MaxIDLen)] = leasewatch.ExpiryMarks{Long: true, Short: true}
	}
	w.st.Watch.Seq = leasewatch.MaxOpenEpisodes
	for i := 0; i < leasewatch.MaxOpenEpisodes; i++ {
		w.st.Watch.Episodes = append(w.st.Watch.Episodes, leasewatch.Episode{
			GrantID: pad(fmt.Sprintf("g%d", i), leasewatch.MaxIDLen), Action: pad("a", leasewatch.MaxActionLen),
			HostLabel: pad("h", leasewatch.MaxLabelLen), Seq: uint64(i + 1)})
	}
	w.st.RunSeen = make(map[string]int64, leaseRunSeenMax)
	for i := 0; i < leaseRunSeenMax; i++ {
		w.st.RunSeen[fmt.Sprintf("%036d\t%s", i, pad(fmt.Sprintf("h%d", i), leaseHostIDMax))] = 1<<40 + int64(i)
	}
	data, err := w.encode()
	if err != nil {
		t.Fatalf("worst-case state: %v", err)
	}
	if len(data) > leaseWatchMaxState {
		t.Fatalf("worst-case state %d bytes > limit %d", len(data), leaseWatchMaxState)
	}
}

// TestDigestFindingsCountOpenFindingsBeyondTheListLimit: closed findings do not
// count, and they do not stop the count either. The digest used to read every
// finding, closed ones included, and gave up above the list limit.
func TestDigestFindingsCountOpenFindingsBeyondTheListLimit(t *testing.T) {
	f := newLeaseFixture(t)
	w := f.watcher(serverconfig.DailyDigest{})
	closedRows := vulnstore.MaxListFindings + 1
	if _, err := f.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
		INSERT INTO vuln_findings (finding_key, subject, subject_kind, record, nos_checked, state, closed_by, closed_at,
		state_run_seq, episode_opened_at, episode_opened_run_seq, episode_peak_tier, first_seen_at, last_seen_at, updated_at)
		SELECT CAST(printf('%032d', i) AS BLOB), 'host-1', 'host', '{}', 0, 'fixed', 'nos_inventory', 1, 1, 1, 1, 4, 1, 1, 1 FROM n`, closedRows); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO vuln_findings (finding_key, subject, subject_kind, record, nos_checked, state,
		state_run_seq, episode_opened_at, episode_opened_run_seq, episode_peak_tier, episode_kev_date, first_seen_at, last_seen_at, updated_at)
		VALUES (CAST(printf('open%028d', 0) AS BLOB), 'host-1', 'host', '{}', 0, 'open', 1, 1, 1, 4, '2026-01-01', 1, 1, 1),
		(CAST(printf('open%028d', 1) AS BLOB), 'host-1', 'host', '{"scores":{"kev":{"date_added":"2026-01-01"}}}', 0, 'open', 1, 1, 1, 3, NULL, 1, 1, 1),
		(CAST(printf('open%028d', 2) AS BLOB), 'host-1', 'host', '{}', 0, 'open', 1, 1, 1, 1, NULL, 1, 1, 1)`); err != nil {
		t.Fatal(err)
	}
	got, err := w.countFindings(context.Background())
	if err != nil {
		t.Fatalf("countFindings: %v", err)
	}
	want := opsdigest.Findings{Critical: 1, High: 1, Low: 1, KEV: 2}
	if got != want {
		t.Fatalf("countFindings = %+v, want %+v", got, want)
	}
}
