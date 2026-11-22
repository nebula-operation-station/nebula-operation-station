// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/enroll"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// enrollTestDeps returns deps with the listen address and a logger that
// writes into buf.
func enrollTestDeps(listen string, buf *bytes.Buffer) serverDeps {
	return serverDeps{
		cfg: serverconfig.Config{Listen: listen},
		log: slog.New(slog.NewTextHandler(buf, nil)),
	}
}

// TestEnrollOptionsResolverIgnoresForwardedFor: without trusted proxies the
// client address is the TCP peer, so a client-sent X-Forwarded-For cannot
// move the dialog's address or the download's rate-limit bucket.
func TestEnrollOptionsResolverIgnoresForwardedFor(t *testing.T) {
	var buf bytes.Buffer
	var o ui.Options
	if err := enrollFeature().options(enrollTestDeps("127.0.0.1:8080", &buf), &o); err != nil {
		t.Fatalf("options hook: %v", err)
	}
	if o.EnrollClientAddr == nil {
		t.Fatal("EnrollClientAddr not set")
	}
	req := httptest.NewRequest(http.MethodGet, "/enroll/x", nil)
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.5")
	res, err := o.EnrollClientAddr.Resolve(req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Forwarded {
		t.Error("X-Forwarded-For used without a trusted proxy")
	}
	if got := res.Client.String(); got != "192.0.2.10" {
		t.Errorf("client = %s, want the TCP peer 192.0.2.10", got)
	}
}

// TestEnrollOptionsWarnsOnNonPublicListenerWithoutProxy: the startup warning
// of ADR 0013 fires when no trusted proxy is configured and the listener is
// loopback, private, link-local or wildcard (likely behind a reverse proxy
// that makes every client share one bucket). A public address stays quiet.
func TestEnrollOptionsWarnsOnNonPublicListenerWithoutProxy(t *testing.T) {
	cases := []struct {
		name   string
		listen string
		warn   bool
	}{
		{"loopback warns", "127.0.0.1:8080", true},
		{"private address warns", "192.168.1.10:8080", true},
		{"public address stays quiet", "203.0.113.7:8080", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			var o ui.Options
			if err := enrollFeature().options(enrollTestDeps(tc.listen, &buf), &o); err != nil {
				t.Fatalf("options hook: %v", err)
			}
			got := strings.Contains(buf.String(), "enrollment download enabled without trusted proxies")
			if got != tc.warn {
				t.Errorf("warning logged = %v, want %v; log:\n%s", got, tc.warn, buf.String())
			}
		})
	}
}

// TestEnrollRouteNeverLogsOfferID: the startup path of the route writes no
// path or offer ID; the log holds only the listener text.
func TestEnrollRouteNeverLogsOfferID(t *testing.T) {
	var buf bytes.Buffer
	var o ui.Options
	if err := enrollFeature().options(enrollTestDeps("203.0.113.7:8080", &buf), &o); err != nil {
		t.Fatalf("options hook: %v", err)
	}
	const id = "abcdefghijklmnopqrstuvwxyz234567"
	if strings.Contains(buf.String(), id) || strings.Contains(buf.String(), "/enroll/") {
		t.Errorf("log names the download route or an offer ID:\n%s", buf.String())
	}
}

// enrollScriptFake is the executor service the download route calls. It
// releases the script once for the one offer it knows; every other call,
// including the second fetch of that offer, answers NotFound, as the
// executor does after an offer is consumed.
type enrollScriptFake struct {
	pb.UnimplementedExecutorServiceServer
	offerID string
	script  []byte
	spent   bool
	calls   int
}

// GetStatus answers the dial probe of executorclient.New.
func (f *enrollScriptFake) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// FetchEnrollScript implements pb.ExecutorServiceServer.
func (f *enrollScriptFake) FetchEnrollScript(_ context.Context, in *pb.FetchEnrollScriptRequest) (*pb.FetchEnrollScriptResponse, error) {
	f.calls++
	if in.GetOfferId() != f.offerID || f.spent {
		return nil, status.Error(codes.NotFound, "no such offer")
	}
	f.spent = true
	sum := sha256.Sum256(f.script)
	return &pb.FetchEnrollScriptResponse{Script: f.script, ScriptSha256: hex.EncodeToString(sum[:])}, nil
}

// enrollChain is the real webServer chain with the public download route
// mounted by the feature's public hook, a page behind the session check,
// and a fake executor reached through lazyExecutor. logs collects every log
// line the server writes.
type enrollChain struct {
	srv    *http.Server
	svc    *enrollScriptFake
	logs   *bytes.Buffer
	cookie string // a valid session cookie value
}

// newEnrollChain builds the chain for one offer ID.
func newEnrollChain(t *testing.T, offerID string) *enrollChain {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, err := sessions.Create(context.Background(), "cred-enroll", "admin")
	if err != nil {
		t.Fatal(err)
	}
	svc := &enrollScriptFake{offerID: offerID, script: []byte("#!/bin/sh\necho enroll\n")}
	l := new(lazyExecutor)
	connectLazy(t, l, serveEnrollRelay(t, svc))

	deps := serverDeps{exec: l, log: log}
	public := newPublicRoutes()
	if err := mountServerPublicRoutes(deps, public); err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	pages.Handle("GET /inventory", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("inventory"))
	}))
	srv, err := webServerPublic(swOrigin, login, pages, nil, public)
	if err != nil {
		t.Fatal(err)
	}
	return &enrollChain{srv: srv, svc: svc, logs: &logs, cookie: cookie}
}

// do sends one request through the chain. cookie is "" for no session.
func (c *enrollChain) do(t *testing.T, method, path, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, swOrigin+path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	c.srv.Handler.ServeHTTP(rec, req)
	return rec
}

// enrollTestID is a syntactically valid offer ID (32 lowercase base32 chars).
const enrollTestID = "abcdefghijklmnopqrstuvwxyz234567"

// TestEnrollRouteServesScriptWithoutSession: a GET with no session gets the
// script with the handler's headers, and the security headers of the
// middleware stay on it.
func TestEnrollRouteServesScriptWithoutSession(t *testing.T) {
	c := newEnrollChain(t, enrollTestID)
	rec := c.do(t, http.MethodGet, enroll.PathPrefix+enrollTestID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body %q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != string(c.svc.script) {
		t.Fatalf("body = %q, want the enroll script", got)
	}
	want := map[string]string{
		"Content-Disposition":        `attachment; filename="nebula-enroll.sh"`,
		"Cache-Control":              "no-store",
		"X-Content-Type-Options":     "nosniff",
		"Content-Security-Policy":    "default-src 'none'; sandbox",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("download route sets a cookie")
	}
}

// TestEnrollRouteRefusalsAreUniform: a second fetch of the same offer, an
// unknown offer and HEAD all get the same 404, not the login page. The
// executor is called only for GET with a well-formed ID. A POST without an
// Origin header is refused by the security middleware (403) before the route
// runs, so the executor is never called for it.
func TestEnrollRouteRefusalsAreUniform(t *testing.T) {
	c := newEnrollChain(t, enrollTestID)
	if rec := c.do(t, http.MethodGet, enroll.PathPrefix+enrollTestID, ""); rec.Code != http.StatusOK {
		t.Fatalf("first fetch: status %d, want 200", rec.Code)
	}
	calls := c.svc.calls
	refusals := []struct {
		name, method, path string
		wantCalls          int
	}{
		{"second fetch", http.MethodGet, enroll.PathPrefix + enrollTestID, 1},
		{"unknown offer", http.MethodGet, enroll.PathPrefix + "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 1},
		{"HEAD", http.MethodHead, enroll.PathPrefix + enrollTestID, 0},
	}
	var first *httptest.ResponseRecorder
	for _, tc := range refusals {
		rec := c.do(t, tc.method, tc.path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", tc.name, rec.Code)
		}
		if rec.Body.String() != "not found\n" {
			t.Errorf("%s: body %q, want the handler's refusal", tc.name, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s: redirect to %q, want no redirect to the login", tc.name, loc)
		}
		if first == nil {
			first = rec
		} else if rec.Header().Get("Content-Disposition") != first.Header().Get("Content-Disposition") {
			t.Errorf("%s: headers differ from the other refusals", tc.name)
		}
		if got := c.svc.calls - calls; got != tc.wantCalls {
			t.Errorf("%s: executor calls %d, want %d", tc.name, got, tc.wantCalls)
		}
		calls = c.svc.calls
	}
	// POST: refused by the origin check of the middleware, before the route.
	rec := c.do(t, http.MethodPost, enroll.PathPrefix+enrollTestID, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST: status %d, want 403 from the origin check", rec.Code)
	}
	if c.svc.calls != calls {
		t.Errorf("POST reached the executor %d times, want 0", c.svc.calls-calls)
	}
}

// TestEnrollRouteRateLimit: after the per-minute allowance the route refuses
// without calling the executor, and the refusal is the handler's 404.
func TestEnrollRouteRateLimit(t *testing.T) {
	c := newEnrollChain(t, enrollTestID)
	for i := range enroll.PerMinute {
		rec := c.do(t, http.MethodGet, enroll.PathPrefix+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("attempt %d: status %d, want 404", i+1, rec.Code)
		}
	}
	before := c.svc.calls
	rec := c.do(t, http.MethodGet, enroll.PathPrefix+enrollTestID, "")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "not found\n" {
		t.Fatalf("over the limit: status %d body %q, want the 404 refusal", rec.Code, rec.Body.String())
	}
	if c.svc.calls != before {
		t.Errorf("over the limit the executor was called %d times, want 0", c.svc.calls-before)
	}
	if !strings.Contains(c.logs.String(), "enroll download refused: rate limit") {
		t.Errorf("rate limit refusal not logged; log:\n%s", c.logs.String())
	}
}

// TestInventoryStaysBehindLogin: the one public prefix does not open the
// rest of the server. A page without a session still goes to /login, and
// with a session it is served.
func TestInventoryStaysBehindLogin(t *testing.T) {
	c := newEnrollChain(t, enrollTestID)
	if rec := c.do(t, http.MethodGet, "/inventory", ""); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("/inventory without session: status %d location %q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
	if rec := c.do(t, http.MethodGet, "/inventory", c.cookie); rec.Code != http.StatusOK {
		t.Fatalf("/inventory with session: status %d, want 200", rec.Code)
	}
}

// TestEnrollRouteLogsHoldNoOfferID: the offer ID is in no log line, for a
// released script, a second fetch, an unknown offer and a refused POST.
func TestEnrollRouteLogsHoldNoOfferID(t *testing.T) {
	c := newEnrollChain(t, enrollTestID)
	c.do(t, http.MethodGet, enroll.PathPrefix+enrollTestID, "")
	c.do(t, http.MethodGet, enroll.PathPrefix+enrollTestID, "")
	c.do(t, http.MethodGet, enroll.PathPrefix+"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "")
	c.do(t, http.MethodPost, enroll.PathPrefix+enrollTestID, "")
	if strings.Contains(c.logs.String(), enrollTestID) {
		t.Errorf("offer ID in the log:\n%s", c.logs.String())
	}
}

// TestRunServesEnrollRouteOutsideSession starts the real server (run, as the
// binary does) and checks the public route through the wiring of runServer:
// GET /enroll/<id> without a session is not redirected to the login, while
// /inventory still is. The executor socket does not exist, so the download
// itself fails; the test only checks that the route is reached and that the
// offer ID is in no log line.
func TestRunServesEnrollRouteOutsideSession(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	listen := freeListenAddr(t)
	path := writeConfig(t, dir, map[string]any{
		"listen":          listen,
		"public_origin":   "https://nebula.example.org",
		"data_dir":        dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"),
		"executor_user":   u.Username,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &stderr) }()

	base := "http://" + listen
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(base + "/login")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up: %v (stderr: %s)", err, stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, p string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, base+p, nil)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, p, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	// The public route: not sent to the login, and the security headers stay.
	resp := do(http.MethodGet, enroll.PathPrefix+enrollTestID)
	if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/login" {
		t.Fatal("GET enroll route without session went to the login")
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("GET enroll route: security headers missing (CSP %q)", resp.Header.Get("Content-Security-Policy"))
	}
	if resp := do(http.MethodPost, enroll.PathPrefix+enrollTestID); resp.StatusCode == http.StatusSeeOther {
		t.Errorf("POST enroll route: status %d, want a refusal", resp.StatusCode)
	}

	// Everything else stays behind the login.
	if resp := do(http.MethodGet, "/inventory"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET /inventory without session: %d %q, want 303 to /login", resp.StatusCode, resp.Header.Get("Location"))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(stderr.String(), enrollTestID) {
		t.Errorf("offer ID in the server log:\n%s", stderr.String())
	}
}
