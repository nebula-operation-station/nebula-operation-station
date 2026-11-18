// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
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
	w := newLeaseWatcher(f.db, f.src, emptyHosts{}, f.vuln.store, f.send, "https://nebula.example.org", digest,
		time.UTC, f.dir, func() time.Time { return f.now }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.load()
	return w
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

func TestDigestCountsFailedRunsOfTheLast24h(t *testing.T) {
	f := newLeaseFixture(t)
	f.now = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now.Add(-2*time.Hour))
	f.run("lease-a", "os.updates.list", "host-1", "failed", f.now.Add(-30*time.Hour))
	f.run("lease-a", "os.updates.list", "host-1", "success", f.now.Add(-time.Hour))
	w := f.watcher(serverconfig.DailyDigest{Enabled: true, Time: "07:00"})
	n, err := w.countFailedRuns(context.Background(), f.now)
	if err != nil || n != 1 {
		t.Fatalf("countFailedRuns = %d, %v; want 1", n, err)
	}
}
