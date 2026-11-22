// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// End-to-end test of the package inventory chain (ADR 0011 D3, D5):
//
//	package_list_installed.sh result (real script run, fixture)
//	  -> ObserveInstalled (stores the read; closes findings by inventory)
//	  -> runServer over loopback HTTP with the vuln token and the real middleware
//	  -> nosclient.Client (bearer token, pinned CA) -> run.Runner, no LLM
//	  -> POST runs, findings, complete, stored by the server
//	  -> vulnstore reads of the stored finding, the vulnerabilities page.
//
// The only stand-ins are loopback: the feeds come from a loopback TLS
// server with testdata content dated to the test run, and a loopback TLS
// reverse proxy stands in for the TLS termination in front of the server,
// because nosclient accepts https only and runServer serves plain HTTP
// (production runs behind a TLS terminator). No mock sits between the agent
// and the server. The server's own installed-result observer is private to
// runServer, so the test feeds the same ObserveInstalled code through a
// service on the server's database.

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// e2eObserver is the installed-result observer on the server's database:
// the same ObserveInstalled code runServer runs for package.list_installed,
// with the store configuration of the server, so complete reads close
// findings by inventory.
func e2eObserver(t *testing.T, db *sql.DB, log *slog.Logger) (*vulnInventoryService, *vulnstore.Store) {
	t.Helper()
	ops := executions.New(context.Background(), nil, db, nil, log)
	inv, err := newVulnInventoryService(db, ops, log)
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulnstore.New(db, vulnstore.Config{Sources: vulnSources, Tier: vulnTier, Classifier: vulnClassifier{}})
	if err != nil {
		t.Fatal(err)
	}
	inv.setCloser(st)
	return inv, st
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
// stores, and then closed by the upgraded read.
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

	// Seed: the host, and the Debian 12 release from a core.facts run that
	// finished after the list. Then the list itself, observed as the
	// executions service does on success.
	now := time.Now().UTC().Truncate(time.Second)
	listAt := now.Add(-2 * time.Minute)
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
	seed.insertFactsAt(t, 100, ivcHost, factsResult(t, debian12Release), now.Add(-time.Minute))
	inv, _ := e2eObserver(t, db, log)
	inv.ObserveInstalled(ctx, ivcHost, "exec-e2e-list-1", listAt, e2eFixture(t))
	if r, err := inv.store.Latest(ctx, ivcHost); err != nil || !r.Complete {
		t.Fatalf("first read: complete=%v err=%v, want a complete stored read", r.Complete, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The server, through runServer, with the vuln token.
	s := startVR(t, dir, cfg)
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

	// The effect in the server's store: one open finding of the host.
	db, err = serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, st := e2eObserver(t, db, log)
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
	// above the fixed version). The finding was written moments ago; the
	// closure needs its write to be older than the read by the listing lag,
	// so its write time is moved back an hour in the database. The store
	// clock cannot be injected through runServer.
	if _, err := db.ExecContext(ctx, `UPDATE vuln_findings SET updated_at = updated_at - 3600`); err != nil {
		t.Fatal(err)
	}
	at2 := time.Now().UTC().Truncate(time.Second)
	seed2 := &invEnv{db: db}
	seed2.insertFactsAt(t, 101, ivcHost, factsResult(t, debian12Release), at2)
	inv, _ = e2eObserver(t, db, log)
	inv.ObserveInstalled(ctx, ivcHost, "exec-e2e-list-2", at2, e2eUpgraded(t))
	fs = e2eFindings(t, st, ivcHost)
	if len(fs) != 1 {
		t.Fatalf("after the upgraded read: %d findings, want 1", len(fs))
	}
	if fs[0].State != vulnstore.StateFixed || fs[0].ClosedBy != vulnstore.ClosedByNOSInventory {
		t.Fatalf("after the upgraded read: state %v closed_by %v; want fixed by nos_inventory", fs[0].State, fs[0].ClosedBy)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The vulnerabilities page of the host shows the inventory line.
	s2 := startVR(t, dir, cfg)
	defer s2.stop()
	code, body := s2.do(t, http.MethodGet, "/vulnerabilities/subject/host/"+ivcHost, alice, "", nil)
	if code != http.StatusOK || !strings.Contains(string(body), "complete") || !strings.Contains(string(body), "Running kernel 6.1.0-26-amd64: mapped") {
		t.Fatalf("vulnerabilities page = %d; inventory line missing:\n%s", code, body)
	}
}
