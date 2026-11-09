// SPDX-License-Identifier: AGPL-3.0-or-later

// Wiring tests of the vulnerability management through runServer, the
// function run calls: the server is started from a configuration file as
// in production, with only the loop intervals shortened and the
// notification sink observed (vulnHooks).

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	vrOrigin = "https://nebula.example.org"
	vrToken  = "nos_hermes-vuln-run-test-token"
	vrFast   = 20 * time.Millisecond
)

// vrObserved counts what the vulnerability loops of one runServer did.
type vrObserved struct {
	mu        sync.Mutex
	notifying bool
	sweeps    int
	ticks     int
}

func (o *vrObserved) get() (notifying bool, sweeps, ticks int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.notifying, o.sweeps, o.ticks
}

// vrServer is one runServer started on a free loopback port.
type vrServer struct {
	base   string
	sink   *vtSink
	obs    *vrObserved
	stderr *bytes.Buffer
	stop   func()
}

// startVR runs runServer with cfg (written to dir/server.json) and fast
// vulnerability loops, and waits until it serves /login.
func startVR(t *testing.T, dir string, cfg map[string]any) *vrServer {
	t.Helper()
	listen := freeListenAddr(t)
	cfg["listen"] = listen
	path := writeConfig(t, dir, cfg)
	s := &vrServer{base: "http://" + listen, sink: newVTSink(), obs: &vrObserved{}, stderr: &bytes.Buffer{}}
	hooks := vulnHooks{sweepInterval: vrFast, notifyInterval: vrFast, sink: s.sink,
		started: func(v *vulnService, notifying bool) {
			s.obs.mu.Lock()
			s.obs.notifying = notifying
			s.obs.mu.Unlock()
			v.swept = func(_ vulnstore.PruneResult, err error) {
				if err == nil {
					s.obs.mu.Lock()
					s.obs.sweeps++
					s.obs.mu.Unlock()
				}
			}
			v.ticked = func() {
				s.obs.mu.Lock()
				s.obs.ticks++
				s.obs.mu.Unlock()
			}
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

// do sends one request; token is a session cookie, bearer an API token.
func (s *vrServer) do(t *testing.T, method, path, token, bearer string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", vrOrigin)
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(vtWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitTicks waits until n more notification ticks ran.
func (s *vrServer) waitTicks(t *testing.T, n int) {
	t.Helper()
	_, _, from := s.obs.get()
	waitFor(t, "notification ticks", func() bool { _, _, ticks := s.obs.get(); return ticks >= from+n })
}

// vrConfig is a server configuration in dir with the given executor
// socket; api (may be nil) is the "api" section.
func vrConfig(t *testing.T, dir, sock string, apiCfg any) map[string]any {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{"public_origin": vrOrigin, "data_dir": dir, "executor_socket": sock, "executor_user": u.Username}
	if apiCfg != nil {
		cfg["api"] = apiCfg
	}
	return cfg
}

// vrSessions creates web sessions for alice and bob in dir's server.db.
func vrSessions(t *testing.T, dir string) (alice, bob string) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st := auth.NewStore(db, nil)
	if alice, _, err = st.Create(context.Background(), "cred-alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if bob, _, err = st.Create(context.Background(), "cred-bob", "bob"); err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

// TestRunWiresVulnManagement starts the server through runServer with the
// API enabled and a vuln token and proves the wiring: the agent API is
// mounted behind the token, a run start reaches the store, the sweep and
// notification loops run (a seen, stale feed is alerted, the never-seen
// ones are not), the export answers through the real admin check (the
// holder of the privileged session is granted and audited, another user
// is refused and audited), and a restart does not repeat the alert.
func TestRunWiresVulnManagement(t *testing.T) {
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	alice, bob := vrSessions(t, dir)
	cfg := vrConfig(t, dir, sock, map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})
	s := startVR(t, dir, cfg)
	if notifying, _, _ := s.obs.get(); !notifying {
		t.Fatal("runServer did not start the notifications with a vuln token configured")
	}

	// Agent API: mounted, behind the token.
	if code, _ := s.do(t, http.MethodGet, "/api/v1/vuln/inventory", "", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("inventory without token = %d, want 401", code)
	}
	code, body := s.do(t, http.MethodGet, "/api/v1/vuln/inventory", "", vrToken, nil)
	if code != http.StatusOK {
		t.Fatalf("inventory with the vuln token = %d %s", code, body)
	}
	var inv struct {
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.Unmarshal(body, &inv); err != nil || inv.SnapshotID == "" {
		t.Fatalf("inventory body %s: %v", body, err)
	}
	// A run names kev with data past its 72 h maximum age and osv fresh.
	now := time.Now().UTC()
	src := func(id string, at time.Time) map[string]any {
		return map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none", "date_kind": "data",
			"content_date": at.Format(time.RFC3339)}
	}
	code, body = s.do(t, http.MethodPost, "/api/v1/vuln/runs", "", vrToken, map[string]any{
		"inventory_snapshot_id": inv.SnapshotID, "matcher_version": "1.4.0",
		"sources": []any{src("kev", now.Add(-100*time.Hour)), src("osv", now.Add(-time.Hour))}})
	if code != http.StatusCreated {
		t.Fatalf("run start = %d %s", code, body)
	}

	// Notification loop: kev is alerted, osv (fresh) and the seven
	// sources no run named are not.
	ev := s.sink.waitKind(t, vulnnotify.KindFeedStale)
	if !strings.Contains(ev.Reason, "feed kev stale since") {
		t.Fatalf("feed_stale reason = %q, want kev", ev.Reason)
	}
	s.waitTicks(t, 2)
	if got := s.sink.reasons(vulnnotify.KindFeedStale); len(got) != 1 {
		t.Fatalf("feed_stale alerts = %v, want only kev", got)
	}
	// Sweep loop.
	waitFor(t, "a sweep", func() bool { _, sweeps, _ := s.obs.get(); return sweeps >= 1 })

	// Export through the real admin check: nobody holds the privileged
	// session yet, so alice is refused too; after alice opens it she is
	// granted, bob is still refused.
	if code, _ := s.do(t, http.MethodGet, vulnExportPath+"?format=csv", alice, "", nil); code != http.StatusForbidden {
		t.Fatalf("export before the privileged session = %d, want 403", code)
	}
	waitFor(t, "the privileged session", func() bool {
		code, _ := s.do(t, http.MethodPost, "/privileged/finish", alice, "", map[string]any{"assertion": map[string]any{"id": "k"}})
		return code == http.StatusOK
	})
	code, body = s.do(t, http.MethodGet, vulnExportPath+"?format=csv", alice, "", nil)
	if code != http.StatusOK || !strings.HasPrefix(string(body), "finding_key,") {
		t.Fatalf("export by the privileged session holder = %d %q (log: %s)", code, body, s.stderr)
	}
	if code, body := s.do(t, http.MethodGet, vulnExportPath+"?format=csv", bob, "", nil); code != http.StatusForbidden || strings.HasPrefix(string(body), "finding_key,") {
		t.Fatalf("export by another user = %d %q, want 403", code, body)
	}
	s.stop()

	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	audit := auditlog.New(db, false)
	exported, err := audit.List(context.Background(), 0, 10, vulnnotify.AuditKindExport)
	if err != nil {
		t.Fatal(err)
	}
	refused, err := audit.List(context.Background(), 0, 10, vulnAuditExportRefused)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if len(exported) != 1 || len(refused) != 2 || refused[0].Attrs["reason"] != "not_admin" {
		t.Fatalf("audit: %d exports, refused %+v; want 1 export and 2 not_admin refusals (log: %s)", len(exported), refused, s.stderr)
	}

	// Restart on the same data directory: kev is still stale in the same
	// episode, so the alert is not sent again.
	s2 := startVR(t, dir, cfg)
	s2.waitTicks(t, 3)
	if got := s2.sink.reasons(vulnnotify.KindFeedStale); len(got) != 0 {
		t.Fatalf("restart repeated %v", got)
	}
	s2.stop()
}

// TestRunWithoutVulnTokenSendsNoVulnAlerts: without a vuln token (here
// without the API) runServer starts no notification loop, so even a seen,
// stale feed raises nothing, while the sweeps still keep the store.
func TestRunWithoutVulnTokenSendsNoVulnAlerts(t *testing.T) {
	dir := t.TempDir()
	// A store left by an earlier use: kev stale.
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulnstore.New(db, vulnstore.Config{Sources: vulnSources, Tier: vulnTier, Classifier: vulnClassifier{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := st.StartRun(context.Background(), vulnstore.StartRequest{TokenID: serverconfig.DefaultVulnTokenName,
		InventoryGeneration: 1, InventoryAt: now.Add(-time.Minute), MatcherVersion: "1.4.0",
		Sources: []vulnstore.RunSource{{ID: "kev", SnapshotID: "snap-kev", Integrity: vulnfinding.IntegrityNone,
			DateKind: vulnstore.DateKindData, ContentDate: now.Add(-100 * time.Hour)}}}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	for name, apiCfg := range map[string]any{
		"api disabled": nil,
		"api without vuln token": map[string]any{"enabled": true, "tokens": []any{map[string]any{
			"name": "dash", "sha256": api.HashToken("nos_dash"), "scopes": []string{serverconfig.ScopeInventoryRead}}}},
	} {
		t.Run(name, func(t *testing.T) {
			s := startVR(t, dir, vrConfig(t, dir, filepath.Join(dir, "no-executor.sock"), apiCfg))
			waitFor(t, "sweeps", func() bool { _, sweeps, _ := s.obs.get(); return sweeps >= 3 })
			if code, _ := s.do(t, http.MethodGet, "/api/v1/vuln/inventory", "", vrToken, nil); code == http.StatusOK {
				t.Fatal("agent API served without a vuln token")
			}
			s.stop()
			notifying, _, ticks := s.obs.get()
			if notifying || ticks != 0 {
				t.Fatalf("notifications started (%v, %d ticks) without a vuln token", notifying, ticks)
			}
			s.sink.mu.Lock()
			defer s.sink.mu.Unlock()
			if len(s.sink.events) != 0 {
				t.Fatalf("sent %+v without a vuln token", s.sink.events)
			}
		})
	}
}
