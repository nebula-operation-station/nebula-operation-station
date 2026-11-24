// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/enroll"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Tests of the trusted-proxy settings of server.json on the enrollment
// routes (ADR 0013 D7): the resolver comes from the configuration, a
// forwarded header counts only from a configured proxy, and an invalid
// setting stops the start.

const (
	proxyTestProxy     = "192.0.2.1"    // the configured trusted proxy
	proxyTestStranger  = "198.51.100.7" // a peer that is not a trusted proxy
	proxyTestClient    = "203.0.113.9"  // the client the proxy names
	proxyTestUnknownID = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
)

// newProxyChain builds the real webServerPublic chain with the public routes
// mounted by mountServerPublicRoutes from cfg, a fake executor that releases
// enrollTestID once, and a JSON log like the server's.
func newProxyChain(t *testing.T, cfg serverconfig.Config) *enrollChain {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: auth.NewStore(db, nil), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	svc := &enrollScriptFake{offerID: enrollTestID, script: []byte("#!/bin/sh\necho enroll\n")}
	l := new(lazyExecutor)
	connectLazy(t, l, serveEnrollRelay(t, svc))

	deps := serverDeps{cfg: cfg, exec: l, log: log}
	public := newPublicRoutes()
	if err := mountServerPublicRoutes(deps, public); err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	srv, err := webServerPublic(swOrigin, login, pages, nil, public)
	if err != nil {
		t.Fatal(err)
	}
	return &enrollChain{srv: srv, svc: svc, logs: &logs}
}

// get sends GET path through the chain from peer with the given headers.
func (c *enrollChain) get(t *testing.T, path, peer string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, swOrigin+path, nil)
	req.RemoteAddr = peer + ":40000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.srv.Handler.ServeHTTP(rec, req)
	return rec
}

// logRecords returns the JSON log lines whose msg is msg.
func logRecords(t *testing.T, logs string, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(logs))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue // not a JSON line
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// auditRecord returns the one enroll_script_downloaded audit record.
func auditRecord(t *testing.T, logs string) map[string]any {
	t.Helper()
	var found []map[string]any
	for _, r := range logRecords(t, logs, "audit") {
		if r["kind"] == enroll.AuditKind {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d %s audit records, want 1; log:\n%s", len(found), enroll.AuditKind, logs)
	}
	return found[0]
}

// proxyCfg is a configuration with proxyTestProxy as the trusted proxy,
// loaded through the strict loader as the server does.
func proxyCfg(t *testing.T) serverconfig.Config {
	t.Helper()
	cfg, err := serverconfig.Parse([]byte(fmt.Sprintf(`{
		"public_origin": "https://nebula.example.org",
		"data_dir": "/var/lib/nebula",
		"executor_socket": "/run/nebula/executor.sock",
		"executor_user": "nebula-exec",
		"trusted_proxies": [%q]
	}`, proxyTestProxy)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestEnrollTrustedProxyNamesClientInAudit: a download through the
// configured proxy is audited with the client from X-Forwarded-For, the
// proxy as peer and forwarded=true.
func TestEnrollTrustedProxyNamesClientInAudit(t *testing.T) {
	c := newProxyChain(t, proxyCfg(t))
	rec := c.get(t, enroll.PathPrefix+enrollTestID, proxyTestProxy, map[string]string{"X-Forwarded-For": proxyTestClient})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; log:\n%s", rec.Code, c.logs.String())
	}
	a := auditRecord(t, c.logs.String())
	if a["client"] != proxyTestClient || a["peer"] != proxyTestProxy || a["forwarded"] != true {
		t.Errorf("audit client=%v peer=%v forwarded=%v, want %s / %s / true", a["client"], a["peer"], a["forwarded"], proxyTestClient, proxyTestProxy)
	}
}

// TestEnrollUntrustedPeerForwardedHeaderIgnored: the same header from a peer
// that is not a trusted proxy is never read; the audit names the peer.
func TestEnrollUntrustedPeerForwardedHeaderIgnored(t *testing.T) {
	c := newProxyChain(t, proxyCfg(t))
	rec := c.get(t, enroll.PathPrefix+enrollTestID, proxyTestStranger, map[string]string{
		"X-Forwarded-For": proxyTestClient,
		"Forwarded":       "for=" + proxyTestClient,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; log:\n%s", rec.Code, c.logs.String())
	}
	a := auditRecord(t, c.logs.String())
	if a["client"] != proxyTestStranger || a["peer"] != proxyTestStranger || a["forwarded"] != false {
		t.Errorf("audit client=%v peer=%v forwarded=%v, want the peer %s and forwarded=false", a["client"], a["peer"], a["forwarded"], proxyTestStranger)
	}
}

// TestEnrollWithoutTrustedProxiesBehavesAsBefore: with no setting (uf07),
// the TCP peer is the client even if it sends X-Forwarded-For.
func TestEnrollWithoutTrustedProxiesBehavesAsBefore(t *testing.T) {
	c := newProxyChain(t, serverconfig.Config{})
	rec := c.get(t, enroll.PathPrefix+enrollTestID, proxyTestProxy, map[string]string{"X-Forwarded-For": proxyTestClient})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; log:\n%s", rec.Code, c.logs.String())
	}
	a := auditRecord(t, c.logs.String())
	if a["client"] != proxyTestProxy || a["forwarded"] != false {
		t.Errorf("audit client=%v forwarded=%v, want the peer %s and forwarded=false", a["client"], a["forwarded"], proxyTestProxy)
	}
}

// TestEnrollTrustedProxyOnlyForwardedHeaderRefused: a trusted proxy that
// sends only the Forwarded header (never read) has no usable client address
// and is refused without an executor call and without charging a bucket.
func TestEnrollTrustedProxyOnlyForwardedHeaderRefused(t *testing.T) {
	c := newProxyChain(t, proxyCfg(t))
	for range enroll.PerMinute + 1 {
		rec := c.get(t, enroll.PathPrefix+enrollTestID, proxyTestProxy, map[string]string{"Forwarded": "for=" + proxyTestClient})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d, want the uniform 404", rec.Code)
		}
	}
	if c.svc.calls != 0 {
		t.Errorf("executor called %d times, want 0", c.svc.calls)
	}
	if n := len(logRecords(t, c.logs.String(), "enroll download refused: rate limit")); n != 0 {
		t.Errorf("%d rate-limit refusals, want 0: a refused header charges no bucket", n)
	}
	// The client itself, through the proxy with X-Forwarded-For, still gets its script.
	if rec := c.get(t, enroll.PathPrefix+enrollTestID, proxyTestProxy, map[string]string{"X-Forwarded-For": proxyTestClient}); rec.Code != http.StatusOK {
		t.Fatalf("status %d after the refusals, want 200", rec.Code)
	}
}

// TestEnrollTrustedProxyLimitsPerClient: behind the trusted proxy each
// client has its own bucket. Exhausting one client's allowance does not
// refuse another client behind the same proxy, and the refusal names the
// client.
func TestEnrollTrustedProxyLimitsPerClient(t *testing.T) {
	c := newProxyChain(t, proxyCfg(t))
	xff := map[string]string{"X-Forwarded-For": proxyTestClient}
	for range enroll.PerMinute {
		c.get(t, enroll.PathPrefix+proxyTestUnknownID, proxyTestProxy, xff)
	}
	before := c.svc.calls
	c.get(t, enroll.PathPrefix+proxyTestUnknownID, proxyTestProxy, xff)
	if c.svc.calls != before {
		t.Fatalf("over the limit the executor was called")
	}
	refusals := logRecords(t, c.logs.String(), "enroll download refused: rate limit")
	if len(refusals) != 1 || refusals[0]["client"] != proxyTestClient || refusals[0]["peer"] != proxyTestProxy {
		t.Fatalf("rate-limit refusals = %v, want one naming client %s via %s", refusals, proxyTestClient, proxyTestProxy)
	}
	// Another client behind the same proxy is not limited.
	rec := c.get(t, enroll.PathPrefix+enrollTestID, proxyTestProxy, map[string]string{"X-Forwarded-For": "203.0.113.10"})
	if rec.Code != http.StatusOK {
		t.Fatalf("second client: status %d, want 200", rec.Code)
	}
}

// TestEnrollUntrustedPeerCannotEscapeLimit: a peer that is not a trusted
// proxy cannot move to a fresh bucket by sending a new X-Forwarded-For on
// every request.
func TestEnrollUntrustedPeerCannotEscapeLimit(t *testing.T) {
	c := newProxyChain(t, proxyCfg(t))
	for i := range enroll.PerMinute + 1 {
		c.get(t, enroll.PathPrefix+proxyTestUnknownID, proxyTestStranger, map[string]string{"X-Forwarded-For": fmt.Sprintf("203.0.113.%d", i+20)})
	}
	refusals := logRecords(t, c.logs.String(), "enroll download refused: rate limit")
	if len(refusals) != 1 || refusals[0]["client"] != proxyTestStranger {
		t.Fatalf("rate-limit refusals = %v, want one naming the peer %s", refusals, proxyTestStranger)
	}
}

// TestEnrollDialogAndDownloadShareResolver: the dialog's resolver (options
// hook) resolves a request exactly like the download route, for a trusted
// proxy and for a stranger.
func TestEnrollDialogAndDownloadShareResolver(t *testing.T) {
	cfg := proxyCfg(t)
	var o ui.Options
	if err := enrollFeature().options(serverDeps{cfg: cfg, log: slog.New(slog.DiscardHandler)}, &o); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ peer, want string }{
		{proxyTestProxy, proxyTestClient},
		{proxyTestStranger, proxyTestStranger},
	} {
		req := httptest.NewRequest(http.MethodGet, "/inventory/enroll/onestep", nil)
		req.RemoteAddr = tc.peer + ":40000"
		req.Header.Set("X-Forwarded-For", proxyTestClient)
		res, err := o.EnrollClientAddr.Resolve(req)
		if err != nil {
			t.Fatalf("peer %s: %v", tc.peer, err)
		}
		if res.Client.String() != tc.want {
			t.Errorf("dialog: peer %s resolves to %s, want %s", tc.peer, res.Client, tc.want)
		}
		// The download route, from the same configuration, audits the same client.
		c := newProxyChain(t, cfg)
		if rec := c.get(t, enroll.PathPrefix+enrollTestID, tc.peer, map[string]string{"X-Forwarded-For": proxyTestClient}); rec.Code != http.StatusOK {
			t.Fatalf("download: status %d", rec.Code)
		}
		if a := auditRecord(t, c.logs.String()); a["client"] != tc.want {
			t.Errorf("download: peer %s audited as %v, want %s", tc.peer, a["client"], tc.want)
		}
	}
}

// proxyRunConfig returns a server.json for run with extra keys.
func proxyRunConfig(t *testing.T, dir, listen string, extra map[string]any) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	cfg := map[string]any{
		"listen":          listen,
		"public_origin":   "https://nebula.example.org",
		"data_dir":        dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"),
		"executor_user":   u.Username,
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return writeConfig(t, dir, cfg)
}

// startRun starts the real server (run, as the binary does) with extra
// server.json keys and returns its base URL and log. The server stops at
// the end of the test.
func startRun(t *testing.T, extra map[string]any) (string, *syncBuffer) {
	t.Helper()
	dir := t.TempDir()
	listen := freeListenAddr(t)
	path := proxyRunConfig(t, dir, listen, extra)
	ctx, cancel := context.WithCancel(context.Background())
	stderr := new(syncBuffer)
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, stderr) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	base := "http://" + listen
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(base + "/login")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base, stderr
			}
		}
		select {
		case err := <-done:
			t.Fatalf("server stopped during start: %v (log: %s)", err, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v (log: %s)", err, stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// runGet sends GET base+path with X-Forwarded-For xff ("" for none).
func runGet(t *testing.T, base, path, xff string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestRunTrustedProxyFromServerJSON: with trusted_proxies ["127.0.0.1"] in
// server.json, the real server limits per forwarded client: the refusal
// names the client, and another client behind the same proxy is not
// limited. A request from the proxy without X-Forwarded-For is refused as
// having no usable client address.
func TestRunTrustedProxyFromServerJSON(t *testing.T) {
	base, logs := startRun(t, map[string]any{"trusted_proxies": []string{"127.0.0.1"}})
	for range enroll.PerMinute + 1 {
		runGet(t, base, enroll.PathPrefix+proxyTestUnknownID, proxyTestClient)
	}
	runGet(t, base, enroll.PathPrefix+proxyTestUnknownID, "203.0.113.10")
	refusals := logRecords(t, logs.String(), "enroll download refused: rate limit")
	if len(refusals) != 1 || refusals[0]["client"] != proxyTestClient || refusals[0]["peer"] != "127.0.0.1" {
		t.Fatalf("rate-limit refusals = %v, want exactly one naming %s via 127.0.0.1; log:\n%s", refusals, proxyTestClient, logs.String())
	}
	runGet(t, base, enroll.PathPrefix+proxyTestUnknownID, "")
	if n := len(logRecords(t, logs.String(), "enroll download refused: no usable client address")); n != 1 {
		t.Errorf("%d refusals without X-Forwarded-For, want 1", n)
	}
	if strings.Contains(logs.String(), "enrollment download enabled without trusted proxies") {
		t.Error("startup warning about missing trusted proxies logged although one is configured")
	}
}

// TestRunWithoutTrustedProxiesSharesPeerBucket: without the setting the
// real server behaves as in uf07: X-Forwarded-For is ignored, every request
// from 127.0.0.1 charges the peer's bucket, and the startup warning fires.
func TestRunWithoutTrustedProxiesSharesPeerBucket(t *testing.T) {
	base, logs := startRun(t, nil)
	for i := range enroll.PerMinute + 1 {
		runGet(t, base, enroll.PathPrefix+proxyTestUnknownID, fmt.Sprintf("203.0.113.%d", i+20))
	}
	refusals := logRecords(t, logs.String(), "enroll download refused: rate limit")
	if len(refusals) != 1 || refusals[0]["client"] != "127.0.0.1" {
		t.Fatalf("rate-limit refusals = %v, want one naming the peer 127.0.0.1", refusals)
	}
	if !strings.Contains(logs.String(), "enrollment download enabled without trusted proxies") {
		t.Error("startup warning missing")
	}
}

// TestRunLogsTrustedProxyNetworkOnce: a trusted proxy network is logged at
// startup once with the proxy-only statement, not once per route.
func TestRunLogsTrustedProxyNetworkOnce(t *testing.T) {
	_, logs := startRun(t, map[string]any{"trusted_proxy_networks": []string{"172.18.0.0/16"}})
	recs := logRecords(t, logs.String(), "trusted proxy network: networks that contain reverse proxies and no clients")
	if len(recs) != 1 || recs[0]["network"] != "172.18.0.0/16" {
		t.Fatalf("trusted proxy network lines = %v, want one for 172.18.0.0/16", recs)
	}
}

// TestRunInvalidTrustedProxiesStopsStart: an invalid setting in server.json
// stops the start with an error that names the key; the server never
// listens.
func TestRunInvalidTrustedProxiesStopsStart(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"network in trusted_proxies", map[string]any{"trusted_proxies": []string{"10.0.0.0/8"}}, "trusted_proxies[0]"},
		{"not an address", map[string]any{"trusted_proxies": []string{"proxy.lan"}}, "trusted_proxies[0]"},
		{"bare address in networks", map[string]any{"trusted_proxy_networks": []string{"10.0.0.5"}}, "trusted_proxy_networks[0]"},
		{"duplicate", map[string]any{"trusted_proxies": []string{"10.0.0.5", "10.0.0.5"}}, "trusted_proxies[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			listen := freeListenAddr(t)
			path := proxyRunConfig(t, dir, listen, tc.extra)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var stderr bytes.Buffer
			err := run(ctx, []string{"-config", path}, &stderr)
			if err == nil {
				t.Fatal("run started with an invalid trusted-proxy setting")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("run error %q does not name %s", err, tc.want)
			}
		})
	}
}
