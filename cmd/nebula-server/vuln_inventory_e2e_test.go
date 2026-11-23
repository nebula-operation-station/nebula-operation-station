// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// End-to-end test of the package inventory chain (ADR 0011 D3, D5):
//
//	package_list_installed.sh result (real script run, fixture)
//	  -> ObserveInstalled (stores the read; closes findings by inventory)
//	  -> runServer over loopback HTTP with the vuln token and the real middleware
//	  -> nosclient.Client (bearer token, pinned CA) -> run.Runner, no LLM
//	  -> POST runs, findings, complete, stored by the server
//	  -> the closure by the upgraded read, through the server's own inventory
//	     service (runServer's setCloser wiring), then the vulnerabilities page.
//
// The only stand-ins are loopback: the feeds come from a loopback TLS
// server with testdata content dated to the test run, and a loopback TLS
// reverse proxy stands in for the TLS termination in front of the server,
// because nosclient accepts https only and runServer serves plain HTTP
// (production runs behind a TLS terminator). No mock sits between the agent
// and the server.

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	vulnrun "github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

const (
	// ivcHost is the inventory host the run covers.
	ivcHost = "web-e2e"
	// e2eCVE is the vulnerability the feed fixture lists for openssl.
	e2eCVE = "CVE-2026-1000"
	// e2eVulnerable and e2eFixed are the openssl source versions of the
	// fixture and of the second reading (after the upgrade).
	e2eVulnerable = "3.0.14-1~deb12u1"
	e2eFixed      = "3.0.15-1~deb12u1"
	// e2eFixtureResult is the real package_list_installed.sh result the
	// actions package regenerates and compares with this file.
	e2eFixtureResult = "../../internal/executions/actions/testdata/package_list_installed_result.json"
	// e2eFeedDir holds the feed bodies; their dates are filled in per run.
	e2eFeedDir = "testdata/vuln_inventory"
	// e2eSources and e2eBinaries are the counts of the fixture's complete
	// read that the inventory line shows: the source packages (openssl,
	// glibc, restic) and their binary packages (openssl, libssl3, libc6,
	// restic). The kernel meta source is not a component (convert.go skips
	// it), so the two kernel images are not counted.
	e2eSources  = 3
	e2eBinaries = 4
	// e2eWriteBackdate is how far behind real time the server's store clock
	// runs during the agent run. The closure read must be at most
	// vulninventory.MaxReadSkew after the real clock, and it must be at least
	// vulnListLag after the finding's write to close the finding. A write at
	// real time would need a read in the future, so the write is placed this
	// far back. The facts row the closure needs is seeded at real time, after
	// the read.
	e2eWriteBackdate = time.Hour
)

// e2eFixture returns the fixture result bytes.
func e2eFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(e2eFixtureResult)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// e2eUpgraded is the fixture after the openssl upgrade: the installed
// openssl version is replaced in the script's own text, the envelope is kept.
func e2eUpgraded(t *testing.T) []byte {
	t.Helper()
	doc := struct {
		Format    string `json:"format"`
		Text      string `json:"text"`
		Truncated bool   `json:"truncated"`
	}{}
	if err := json.Unmarshal(e2eFixture(t), &doc); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if !strings.Contains(doc.Text, e2eVulnerable) {
		t.Fatalf("fixture has no %s", e2eVulnerable)
	}
	return installedEnvelope(t, strings.ReplaceAll(doc.Text, e2eVulnerable, e2eFixed), false)
}

// e2eFeeds starts the loopback feed server and returns the feed table
// pointed at it. The DSA list and the KEV catalogue are dated one hour
// before now, so the feeds are fresh whenever the test runs.
func e2eFeeds(t *testing.T, now time.Time) ([]vulnfeed.Feed, *vulnfeed.Fetcher) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(e2eFeedDir, name))
		if err != nil {
			t.Fatalf("read feed %s: %v", name, err)
		}
		return string(b)
	}
	dsa := strings.ReplaceAll(read("debian-dsa.txt"), "{{DSA_DATE}}", now.Add(-time.Hour).Format("02 Jan 2006"))
	kev := strings.ReplaceAll(read("cisa-kev.json"), "{{KEV_DATE}}", now.Add(-time.Hour).UTC().Format(time.RFC3339))
	bodies := map[string]string{"/dsa": dsa, "/tracker": read("debian-tracker.json"), "/kev": kev}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)

	var feeds []vulnfeed.Feed
	for name, path := range map[string]string{"debian-tracker": "/tracker", "debian-dsa": "/dsa", "cisa-kev": "/kev"} {
		f, ok := vulnfeed.FeedByName(name)
		if !ok {
			t.Fatalf("feed %s not in the table", name)
		}
		f.URL = srv.URL + path
		if name == "debian-tracker" {
			f.ProxyCompanions = []string{"debian-dsa"}
		}
		feeds = append(feeds, f)
	}
	al, err := vulnfeed.NewAllowlist([]string{srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	fetcher, err := vulnfeed.NewFetcher(vulnfeed.FetcherConfig{Allowlist: al, RootCAs: pool, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return feeds, fetcher
}

// e2eFront is the loopback TLS terminator in front of the plain-HTTP server:
// a reverse proxy, so the agent sees https and the server sees its own
// middleware and handlers unchanged.
func e2eFront(t *testing.T, backend string) *httptest.Server {
	t.Helper()
	u, err := url.Parse(backend)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(u))
	t.Cleanup(srv.Close)
	return srv
}

// e2eTokenFile writes token to dir with the owner-only mode nosclient needs.
func e2eTokenFile(t *testing.T, dir, name, token string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// e2eCAFile writes the certificate of srv as the pinned CA of the agent.
func e2eCAFile(t *testing.T, dir string, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// e2eClient is the real nosclient against base with token.
func e2eClient(t *testing.T, base, tokenFile, caFile string) *nosclient.Client {
	t.Helper()
	c, err := nosclient.New(nosclient.Config{BaseURL: base, TokenFile: tokenFile, CAFile: caFile,
		Now:   time.Now,
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// e2eClock is the server's injected store clock: real time moved by an
// offset the test sets between steps. It is safe for concurrent use, since
// the server's loops read it while the test sets it.
type e2eClock struct{ offset atomic.Int64 }

// now returns the clock's time.
func (c *e2eClock) now() time.Time { return time.Now().Add(time.Duration(c.offset.Load())) }

// set moves the clock by d from real time.
func (c *e2eClock) set(d time.Duration) { c.offset.Store(int64(d)) }

// e2eWiring receives the server's own inventory and vulnerability services
// from runServer through the test hooks.
type e2eWiring struct {
	mu   sync.Mutex
	inv  *vulnInventoryService
	vuln *vulnService
}

// startE2E starts runServer on a loopback address with the vulnerability
// hooks of the test: the store clock (nil for real time), and the services
// runServer wires, recorded in w. It returns when the server answers.
func startE2E(t *testing.T, dir string, cfg map[string]any, clock func() time.Time, w *e2eWiring) *vrServer {
	t.Helper()
	listen := freeListenAddr(t)
	cfg["listen"] = listen
	path := writeConfig(t, dir, cfg)
	s := &vrServer{base: "http://" + listen, sink: newVTSink(), obs: &vrObserved{}, stderr: &bytes.Buffer{}}
	hooks := vulnHooks{sweepInterval: vrFast, notifyInterval: vrFast, sink: s.sink, now: clock,
		started: func(v *vulnService, _ bool) {
			w.mu.Lock()
			w.vuln = v
			w.mu.Unlock()
		},
		inventory: func(inv *vulnInventoryService) {
			w.mu.Lock()
			w.inv = inv
			w.mu.Unlock()
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServer(ctx, []string{"-config", path}, s.stderr, hooks) }()
	stopped := false
	s.stop = func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("runServer: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("runServer did not return after cancel")
		}
	}
	t.Cleanup(s.stop)
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(s.base + "/login")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// e2eInventory is the inventory service on the database, the one the test
// uses to store the first complete read before the server starts.
func e2eInventory(t *testing.T, db *sql.DB, log *slog.Logger) *vulnInventoryService {
	t.Helper()
	ops := executions.New(context.Background(), nil, db, nil, log)
	inv, err := newVulnInventoryService(db, ops, log)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// e2eUpgradedRead stores the upgraded openssl read of ivcHost taken at at,
// through the inventory service of the server. The facts of the release are
// seeded by the test before the server starts (see the test).
func e2eUpgradedRead(t *testing.T, inv *vulnInventoryService, n int, at time.Time) {
	t.Helper()
	inv.ObserveInstalled(context.Background(), ivcHost, fmt.Sprintf("exec-e2e-list-%d", n), at.Add(-time.Minute), at, e2eUpgraded(t))
}

// e2eFindings lists the findings of host in the stored order.
func e2eFindings(t *testing.T, st *vulnstore.Store, host string) []vulnstore.Finding {
	t.Helper()
	fs, _, err := st.List(context.Background(), vulnstore.ListQuery{
		Subject: &vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: host}, Limit: 50})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	return fs
}

// TestPackageListInstalledFindingReachesServerOverHTTP is the chain of the
// inventory test: a real script result, stored by the server, read by the
// real agent over HTTP with the bearer token, and the finding the run
// stores, and then closed by the upgraded read through the server's own
// inventory service.
func TestPackageListInstalledFindingReachesServerOverHTTP(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	alice, _ := vrSessions(t, dir)
	cfg := vrConfig(t, dir, sock, map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})

	// Seed: the host, the first complete read, and the Debian 12 release from
	// a core.facts run that finished now, after every list and every upgraded
	// read of this test. The first read is older than the upgraded reads (they
	// are placed e2eWriteBackdate back), so the page shows the upgraded read as
	// the latest one.
	now := time.Now().UTC().Truncate(time.Second)
	listAt := now.Add(-2 * e2eWriteBackdate)
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inventory.New(db).Create(ctx, inventory.Host{ID: ivcHost, DisplayName: "web-e2e.lab",
		Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
		Endpoints: []inventory.Endpoint{{Address: "192.0.2.10", Port: 22}}, CredentialRef: "lab"}, inventory.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	seed := &invEnv{db: db}
	seed.insertFactsAt(t, 100, ivcHost, factsResult(t, debian12Release), now)
	inv := e2eInventory(t, db, log)
	inv.ObserveInstalled(ctx, ivcHost, "exec-e2e-list-1", listAt.Add(-time.Minute), listAt, e2eFixture(t))
	if r, err := inv.store.Latest(ctx, ivcHost); err != nil || !r.Complete {
		t.Fatalf("first read: complete=%v err=%v, want a complete stored read", r.Complete, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The agent run against the server, through runServer, with the vuln token.
	// The store clock runs e2eWriteBackdate behind real time, so the finding
	// is written early enough for the upgraded read to close it (see the
	// constant).
	clock := &e2eClock{}
	clock.set(-e2eWriteBackdate)
	w := &e2eWiring{}
	s := startE2E(t, dir, cfg, clock.now, w)
	front := e2eFront(t, s.base)
	ca := e2eCAFile(t, dir, front)
	tok := e2eTokenFile(t, dir, "token", vrToken)
	client := e2eClient(t, front.URL, tok, ca)

	// Authentication: no token and a wrong token are refused by the server's
	// middleware, before the inventory is read.
	for name, bearer := range map[string]string{"no token": "", "wrong token": "nos_wrong-token"} {
		req, err := http.NewRequest(http.MethodGet, front.URL+"/api/v1/vuln/inventory", nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("inventory with %s = %d, want 401", name, resp.StatusCode)
		}
	}
	wrong := e2eClient(t, front.URL, e2eTokenFile(t, dir, "wrong-token", "nos_wrong-token"), ca)
	if _, err := wrong.Export(ctx, func(nosclient.Page) error { return nil }); err == nil {
		t.Fatal("the agent's export with a wrong token succeeded")
	}

	// The export the run will use: at least one subject, complete, and a
	// real snapshot.
	snap, err := client.Export(ctx, func(nosclient.Page) error { return nil })
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.HasPrefix(snap.ID, "nos-empty-") {
		t.Fatalf("export is the empty snapshot %q: the stored read did not reach the server", snap.ID)
	}
	complete := 0
	for _, sc := range snap.Subjects {
		if sc.Complete {
			complete++
		}
	}
	if complete < 1 {
		t.Fatalf("export has %d subjects, none complete", len(snap.Subjects))
	}

	// The real agent run, no LLM: sync the feeds, match, submit.
	feeds, fetcher := e2eFeeds(t, now)
	var out, logs bytes.Buffer
	runner, err := vulnrun.New(vulnrun.Config{DataDir: filepath.Join(dir, "agent"), Feeds: feeds, Fetcher: fetcher,
		NOS: client, Out: &out, Logger: slog.New(slog.NewTextHandler(&logs, nil)), Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := runner.Run(ctx, vulnrun.ModeRun)
	if err != nil {
		t.Fatalf("run: %v (log %s)", err, logs.String())
	}
	if rep.Subjects < 1 || rep.InventorySnapshotID == "" || strings.HasPrefix(rep.InventorySnapshotID, "nos-empty-") {
		t.Fatalf("report: subjects=%d snapshot=%q", rep.Subjects, rep.InventorySnapshotID)
	}
	if rep.RunID == "" || rep.Completion == nil || rep.Findings != 1 || rep.Degraded() {
		t.Fatalf("run not accepted and completed cleanly: run=%q completion=%v findings=%d degraded=%v error=%q",
			rep.RunID, rep.Completion, rep.Findings, rep.Degraded(), rep.Error)
	}
	if strings.Contains(logs.String()+out.String(), vrToken) {
		t.Fatal("the run's log or output holds the token")
	}
	s.stop()

	// A second server on the same database, with the real clock. Its services
	// are the ones runServer wires: the inventory service with the findings
	// store as its closer, and the findings store itself.
	s2 := startE2E(t, dir, cfg, nil, w)
	w.mu.Lock()
	inv2, vuln := w.inv, w.vuln
	w.mu.Unlock()
	if inv2 == nil || vuln == nil {
		t.Fatal("runServer did not hand out its inventory and vulnerability services")
	}
	st := vuln.store

	// The effect in the server's store: one open finding of the host.
	fs := e2eFindings(t, st, ivcHost)
	if len(fs) != 1 {
		t.Fatalf("%d findings for %s, want exactly the openssl finding", len(fs), ivcHost)
	}
	f := fs[0]
	if f.State != vulnstore.StateOpen || f.Subject.ID != ivcHost || f.Record.Vuln.ID != e2eCVE ||
		f.Record.Component.SourcePackage != "openssl" || !f.NOSChecked {
		t.Fatalf("finding = state %s subject %+v vuln %q source %q nos_checked %v",
			f.State, f.Subject, f.Record.Vuln.ID, f.Record.Component.SourcePackage, f.NOSChecked)
	}

	// The upgraded read closes it (path 1: the installed version is at or
	// above the fixed version). The closure needs the finding's last write to
	// be strictly older than the read less the listing lag (vulnListLag). A
	// read at exactly that edge holds the finding open; one second later
	// closes it.
	written := f.Updated
	edge := written.Add(vulnListLag)
	e2eUpgradedRead(t, inv2, 101, edge)
	if fs = e2eFindings(t, st, ivcHost); len(fs) != 1 || fs[0].State != vulnstore.StateOpen {
		t.Fatalf("read at the listing lag edge: %d findings, want 1 open (write at %s, read at %s)",
			len(fs), written.Format(time.RFC3339), edge.Format(time.RFC3339))
	}
	after := edge.Add(time.Second)
	e2eUpgradedRead(t, inv2, 102, after)
	fs = e2eFindings(t, st, ivcHost)
	if len(fs) != 1 {
		t.Fatalf("after the upgraded read: %d findings, want 1", len(fs))
	}
	if fs[0].State != vulnstore.StateFixed || fs[0].ClosedBy != vulnstore.ClosedByNOSInventory {
		t.Fatalf("after the upgraded read: state %v closed_by %v; want fixed by nos_inventory", fs[0].State, fs[0].ClosedBy)
	}

	// The vulnerabilities page of the host shows the inventory line of the
	// last read exactly: its time, the source and binary counts of the
	// fixture, and the complete flag; then the running kernel line.
	code, body := s2.do(t, http.MethodGet, "/vulnerabilities/subject/host/"+ivcHost, alice, "", nil)
	wantLine := "read " + after.UTC().Format("2006-01-02 15:04 UTC") + ", " +
		strconv.Itoa(e2eSources) + " source packages (" + strconv.Itoa(e2eBinaries) + " binaries), complete"
	if code != http.StatusOK || !strings.Contains(string(body), wantLine) || !strings.Contains(string(body), "Running kernel 6.1.0-26-amd64: mapped") {
		t.Fatalf("vulnerabilities page = %d; want the inventory line %q and the mapped kernel:\n%s", code, wantLine, body)
	}
}
