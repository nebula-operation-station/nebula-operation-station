// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// siDockerFixture is the docker.list result the executions tests use
// (docker 29, a running and an exited container).
const siDockerFixture = "../../internal/executions/dockerhost/testdata/docker29.json"

// siT0 is the injected clock of the ingest tests.
var siT0 = time.Unix(1_800_000_000, 0).UTC()

// siFacts builds a core.facts result with the given os-release text the way
// the core.facts action prints it.
func siFacts(osRelease string) []byte {
	return []byte(fmt.Sprintf(`{"os_release":%q,"uname":"","hostname":"","uptime":"","proxmox":false}`,
		base64.StdEncoding.EncodeToString([]byte(osRelease))))
}

// siStore stores one finished, successful host result of action on host at
// finished (unix seconds), the rows the executions service writes. n makes
// the execution ID unique.
func siStore(t *testing.T, db *sql.DB, n int, action, host string, finished int64, result []byte) {
	t.Helper()
	id := fmt.Sprintf("6e1f0a2b-3c4d-4e5f-8a6b-%012d", n)
	if _, err := db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at, finished_at)
		VALUES (?, ?, '1', ?, 'read', 'finished', 0, 60, 'admin', ?, ?)`,
		id, action, strings.Repeat("a", 64), finished, finished); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, exit_code, result, started_at, finished_at)
		VALUES (?, ?, 'SHA256:si', 'cred', '[]', 'finished', 'success', 0, ?, ?, ?)`,
		id, host, result, finished, finished); err != nil {
		t.Fatal(err)
	}
}

// siDB opens a server database in a temporary directory with two managed
// hosts in the inventory.
func siDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, id := range []string{"h1", "h2"} {
		if _, err := inventory.New(db).Create(context.Background(), inventory.Host{ID: id, Environment: inventory.EnvProd,
			Criticality: inventory.CriticalityMedium, CredentialRef: id,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.10", Port: 22}}}, inventory.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// siLoop builds the ingest loop on db with the injected clock now.
func siLoop(t *testing.T, db *sql.DB, now *time.Time) *softwareIngest {
	t.Helper()
	inv := inventory.New(db)
	l, err := newSoftwareIngest(db, inv.List, softwareRetention, slog.New(slog.DiscardHandler), func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// softwareRetention is the traffic retention the ingest tests run with.
const softwareRetention = 21 * 24 * time.Hour

// siObservedIDs returns the identifiers observed on host, sorted by the store.
func siObservedIDs(t *testing.T, db *sql.DB, host string) []string {
	t.Helper()
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := cat.Observations(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range obs {
		out = append(out, o.Identifier)
	}
	return out
}

// TestSoftwareIngestUsesLatestStoredResult: only the newest stored core.facts
// of a host is read; an older run does not add an observation.
func TestSoftwareIngestUsesLatestStoredResult(t *testing.T) {
	db := siDB(t)
	now := siT0
	siStore(t, db, 1, "core.facts", "h1", siT0.Add(-2*time.Hour).Unix(), siFacts("ID=debian\nVERSION_ID=\"12\"\n"))
	siStore(t, db, 2, "core.facts", "h1", siT0.Add(-time.Hour).Unix(), siFacts("ID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	l := siLoop(t, db, &now)
	run := l.check(context.Background())
	if run.Results != 1 || run.Rejected != 0 || run.Failed != 0 {
		t.Fatalf("run %+v, want one result ingested", run)
	}
	if got := siObservedIDs(t, db, "h1"); len(got) != 1 || got[0] != "ubuntu" {
		t.Fatalf("observed on h1 %v, want [ubuntu]", got)
	}
}

// TestSoftwareIngestProcessesEachResultOnce: a second check of an unchanged
// result ingests nothing and leaves the observations as they are.
func TestSoftwareIngestProcessesEachResultOnce(t *testing.T) {
	db := siDB(t)
	now := siT0
	siStore(t, db, 1, "core.facts", "h1", siT0.Add(-time.Hour).Unix(), siFacts("ID=debian\nVERSION_ID=\"12\"\n"))
	siStore(t, db, 2, "docker.list", "h1", siT0.Add(-time.Hour).Unix(), mustRead(t, siDockerFixture))
	l := siLoop(t, db, &now)
	first := l.check(context.Background())
	if first.Results != 2 || first.Observed == 0 {
		t.Fatalf("first run %+v, want two results observed", first)
	}
	before := siObservedIDs(t, db, "h1")
	second := l.check(context.Background())
	if second.Results != 0 || second.Observed != 0 || second.Rejected != 0 {
		t.Fatalf("second run %+v, want nothing to do", second)
	}
	if after := siObservedIDs(t, db, "h1"); len(after) != len(before) {
		t.Fatalf("observations %v after second run, want %v", after, before)
	}
}

// TestSoftwareIngestRestartIsIdempotent: after a restart the loop reads the
// stored results again; the ingest functions write no duplicate rows.
func TestSoftwareIngestRestartIsIdempotent(t *testing.T) {
	db := siDB(t)
	now := siT0
	siStore(t, db, 1, "core.facts", "h1", siT0.Add(-time.Hour).Unix(), siFacts("ID=debian\nVERSION_ID=\"12\"\n"))
	siStore(t, db, 2, "docker.list", "h1", siT0.Add(-time.Hour).Unix(), mustRead(t, siDockerFixture))
	siLoop(t, db, &now).check(context.Background())
	before := softwareObservationRows(t, db)
	restarted := siLoop(t, db, &now)
	run := restarted.check(context.Background())
	if run.Results != 2 {
		t.Fatalf("restarted run %+v, want both stored results read again", run)
	}
	if after := softwareObservationRows(t, db); after != before {
		t.Fatalf("observation rows %d after restart, want %d", after, before)
	}
}

// softwareObservationRows counts the observation rows of the server database.
func softwareObservationRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM software_observations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSoftwareIngestDefectiveResultSkipsOnlyThatHost: a truncated result of
// h1 is refused and counted; h2 is still ingested and the run completes. The
// refused result is not read again on the next check.
func TestSoftwareIngestDefectiveResultSkipsOnlyThatHost(t *testing.T) {
	db := siDB(t)
	now := siT0
	good := siFacts("ID=debian\nVERSION_ID=\"12\"\n")
	siStore(t, db, 1, "core.facts", "h1", siT0.Add(-time.Hour).Unix(), good[:len(good)/2])
	siStore(t, db, 2, "core.facts", "h2", siT0.Add(-time.Hour).Unix(), good)
	l := siLoop(t, db, &now)
	run := l.check(context.Background())
	if run.Rejected != 1 || run.Results != 1 || run.Failed != 0 {
		t.Fatalf("run %+v, want one rejected and one ingested result", run)
	}
	if got := siObservedIDs(t, db, "h1"); len(got) != 0 {
		t.Fatalf("observed on h1 from a truncated result: %v", got)
	}
	if got := siObservedIDs(t, db, "h2"); len(got) != 1 || got[0] != "debian" {
		t.Fatalf("observed on h2 %v, want [debian]", got)
	}
	if again := l.check(context.Background()); again.Rejected != 0 || again.Results != 0 {
		t.Fatalf("second run %+v, want the refused result not read again", again)
	}
}

// TestSoftwareIngestPrunesPastRetention: observations last seen before the
// retention window are removed; the prune runs when it is due, not on every
// check.
func TestSoftwareIngestPrunesPastRetention(t *testing.T) {
	db := siDB(t)
	now := siT0
	old := siT0.Add(-softwareRetention - 48*time.Hour).Unix()
	siStore(t, db, 1, "core.facts", "h1", old, siFacts("ID=debian\nVERSION_ID=\"12\"\n"))
	l := siLoop(t, db, &now)
	run := l.check(context.Background())
	if run.Pruned != 1 {
		t.Fatalf("run %+v, want the expired observation pruned", run)
	}
	if got := siObservedIDs(t, db, "h1"); len(got) != 0 {
		t.Fatalf("observed on h1 after prune: %v", got)
	}
	siStore(t, db, 2, "core.facts", "h1", old, siFacts("ID=alpine\nVERSION_ID=\"3.20\"\n"))
	now = siT0.Add(softwarePruneInterval - time.Minute)
	if again := l.check(context.Background()); again.Pruned != 0 {
		t.Fatalf("prune ran again before it was due: %+v", again)
	}
}

// TestSoftwarePruneDue: the prune runs at the first check and then once per
// softwarePruneInterval.
func TestSoftwarePruneDue(t *testing.T) {
	tests := []struct {
		name string
		last time.Time
		now  time.Time
		want bool
	}{
		{"never run", time.Time{}, siT0, true},
		{"just run", siT0, siT0, false},
		{"almost an hour", siT0, siT0.Add(softwarePruneInterval - time.Second), false},
		{"an hour", siT0, siT0.Add(softwarePruneInterval), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := softwarePruneDue(tc.last, tc.now); got != tc.want {
				t.Fatalf("softwarePruneDue = %t, want %t", got, tc.want)
			}
		})
	}
}

// mustRead returns the bytes of a test fixture.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// siLogSignal is a log handler that reports each "software ingest" line
// once, so the test waits for a run instead of polling.
type siLogSignal struct {
	ch chan struct{}
}

func (h siLogSignal) Enabled(context.Context, slog.Level) bool { return true }
func (h siLogSignal) Handle(_ context.Context, r slog.Record) error {
	if r.Message == softwareIngestLogMsg {
		select {
		case h.ch <- struct{}{}:
		default:
		}
	}
	return nil
}
func (h siLogSignal) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h siLogSignal) WithGroup(string) slog.Handler      { return h }

// TestSoftwareIngestFeedsSoftwarePages drives the real path: the server's
// feature registry mounts the ingest (as run does), the stored results of a
// host (core.facts, docker.list) and of a host with a truncated result are
// ingested by the background loop, and the software pages behind the
// session chain show what was found.
func TestSoftwareIngestFeedsSoftwarePages(t *testing.T) {
	db := siDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	siStore(t, db, 1, "core.facts", "h1", time.Now().Add(-time.Hour).Unix(), siFacts("ID=debian\nVERSION_ID=\"12\"\n"))
	siStore(t, db, 2, "docker.list", "h1", time.Now().Add(-time.Hour).Unix(), mustRead(t, siDockerFixture))
	bad := siFacts("ID=ubuntu\nVERSION_ID=\"24.04\"\n")
	siStore(t, db, 3, "core.facts", "h2", time.Now().Add(-time.Hour).Unix(), bad[:len(bad)/2])

	sig := make(chan struct{}, 1)
	log := slog.New(siLogSignal{ch: sig})
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	sw, err := newSoftwarePages(db, log)
	if err != nil {
		t.Fatal(err)
	}
	sw.Register(pages)
	deps := serverDeps{
		cfg:       serverconfig.Config{PublicOrigin: swOrigin},
		db:        db,
		log:       log,
		inventory: inventory.New(db),
		retention: softwareRetention,
		isAdmin:   func(context.Context) bool { return true },
		run: func(f func(context.Context)) error {
			go f(ctx)
			return nil
		},
	}
	if err := mountServerFeaturePages(deps, pages); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sig:
	case <-time.After(10 * time.Second):
		t.Fatal("software ingest did not run")
	}

	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(ctx, "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, swOrigin+path, nil)
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rec.Code)
		}
		b, err := io.ReadAll(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	sw1 := get("/software")
	for _, want := range []string{"Debian", "Docker"} {
		if !strings.Contains(sw1, want) {
			t.Errorf("/software does not show %s", want)
		}
	}
	queue, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := queue.UnknownQueue(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) == 0 {
		t.Fatal("unknown queue is empty, want the unknown images of docker.list")
	}
	page := get("/software/unknown")
	if !strings.Contains(page, string(unknown[0].Key)) {
		t.Errorf("/software/unknown does not list %q", unknown[0].Key)
	}
	if got := siObservedIDs(t, db, "h2"); len(got) != 0 {
		t.Errorf("h2 observed from a truncated result: %v", got)
	}
}
