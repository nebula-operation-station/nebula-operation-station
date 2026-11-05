// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	swOrigin = "https://nebula.example.org"
	// swStrictCSP is the CSP of docs/spec/09 that internal/web/middleware
	// sets on every response.
	swStrictCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)

// swFixture is the server's HTTP chain (webServer: security middleware,
// session check, pages) with the software pages mounted as in run, on a
// real server database with one observed catalog entry.
type swFixture struct {
	srv   *http.Server
	cat   *softwarecat.Store
	token string // a valid web session of the admin
}

func newSWFixture(t *testing.T) *swFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		t.Fatal(err)
	}
	units := base64.StdEncoding.EncodeToString([]byte("widgetd.service loaded active running Some unit"))
	doc := []byte(fmt.Sprintf(`{"format":"systemd-units-v1","units":%q}`, units))
	if _, err := cat.IngestServiceList(ctx, softwarecat.Target{Kind: softwarecat.TargetHost, HostID: "h1"}, doc, time.Now()); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	sw, err := newSoftwarePages(db, log)
	if err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	sw.Register(pages)

	// The real login with an executor that is not connected: the session
	// check keeps a session it cannot verify (auth.credentialStillRegistered).
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
	return &swFixture{srv: srv, cat: cat, token: token}
}

func (f *swFixture) do(t *testing.T, method, path, token, origin, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, swOrigin+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler.ServeHTTP(rec, req)
	return rec
}

func checkStrictHeaders(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if csp := rec.Header().Get("Content-Security-Policy"); csp != swStrictCSP {
		t.Errorf("%s: CSP %q, want %q", what, csp, swStrictCSP)
	}
	if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("%s: X-Content-Type-Options %q, want nosniff", what, v)
	}
}

var swPages = []string{"/software", "/software?state=observed", "/software/unknown", "/software/icon/widgetd", "/software/assets/icon?id=asset-1"}

// TestSoftwarePagesServedToSignedInAdmin checks that the server mounts the
// software pages: a signed-in admin reaches each of them through the full
// chain, with the strict CSP and no inline script.
func TestSoftwarePagesServedToSignedInAdmin(t *testing.T) {
	f := newSWFixture(t)
	for _, p := range swPages {
		rec := f.do(t, http.MethodGet, p, f.token, "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", p, rec.Code)
			continue
		}
		checkStrictHeaders(t, "GET "+p, rec)
		body := rec.Body.String()
		if !strings.Contains(body, "widgetd") && !strings.Contains(body, "asset-1") {
			t.Errorf("GET %s: page does not show the catalog data", p)
		}
		if strings.Contains(body, "<script>") || strings.Contains(body, " onclick=") || strings.Contains(body, "<style") {
			t.Errorf("GET %s: page carries inline script or style", p)
		}
	}
}

// TestSoftwarePagesRefuseWithoutSession checks that every software page
// and change route needs a valid web session: no cookie or an unknown
// token is sent to the login (GET) or refused (POST), and nothing changes.
func TestSoftwarePagesRefuseWithoutSession(t *testing.T) {
	f := newSWFixture(t)
	for _, token := range []string{"", "not-a-session-token", strings.Repeat("A", 43)} {
		for _, p := range swPages {
			rec := f.do(t, http.MethodGet, p, token, "", "")
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
				t.Errorf("token %q: GET %s: status %d location %q, want 303 to /login", token, p, rec.Code, rec.Header().Get("Location"))
			}
			if strings.Contains(rec.Body.String(), "widgetd") {
				t.Errorf("token %q: GET %s leaks catalog data", token, p)
			}
			checkStrictHeaders(t, "GET "+p, rec)
		}
		rec := f.do(t, http.MethodPost, "/software/ignore", token, swOrigin, url.Values{"key": {"widgetd"}}.Encode())
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: POST /software/ignore: status %d, want 401", token, rec.Code)
		}
	}
	f.checkUnchanged(t)
}

// TestSoftwarePostsNeedThePublicOrigin checks the origin check of the
// middleware in front of the software change routes: a foreign, null or
// missing Origin is refused even with a valid session, and only the
// public origin reaches the handler.
func TestSoftwarePostsNeedThePublicOrigin(t *testing.T) {
	f := newSWFixture(t)
	form := url.Values{"key": {"widgetd"}}.Encode()
	routes := []string{"/software/ignore", "/software/rename", "/software/merge", "/software/icon/fetch",
		"/software/icon/candidate", "/software/icon/rollback", "/software/icon/upload?kind=catalog&id=widgetd"}
	for _, origin := range []string{"", "null", "https://evil.example", "http://nebula.example.org", swOrigin + ":444", swOrigin + "/"} {
		for _, p := range routes {
			rec := f.do(t, http.MethodPost, p, f.token, origin, form)
			if rec.Code != http.StatusForbidden {
				t.Errorf("Origin %q: POST %s: status %d, want 403", origin, p, rec.Code)
			}
			checkStrictHeaders(t, "POST "+p, rec)
		}
	}
	f.checkUnchanged(t)

	rec := f.do(t, http.MethodPost, "/software/ignore", f.token, swOrigin, form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/software/unknown?done=ignored" {
		t.Fatalf("POST /software/ignore with the public origin: status %d location %q, want 303", rec.Code, rec.Header().Get("Location"))
	}
	e, err := f.cat.Entry(context.Background(), "widgetd")
	if err != nil {
		t.Fatal(err)
	}
	if e.State != softwarecat.StateIgnored {
		t.Errorf("state after ignore %q, want %q", e.State, softwarecat.StateIgnored)
	}
}

// TestSoftwareIconChangesOffWithoutIconService checks that the server,
// which has no icon store or fetch spool configured yet, mounts the icon
// pages read-only: the change routes answer 404 after the origin and
// session checks.
func TestSoftwareIconChangesOffWithoutIconService(t *testing.T) {
	f := newSWFixture(t)
	rec := f.do(t, http.MethodPost, "/software/icon/fetch", f.token, swOrigin,
		url.Values{"key": {"widgetd"}, "url": {"https://example.org/i.png"}}.Encode())
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /software/icon/fetch: status %d, want 404", rec.Code)
	}
	rec = f.do(t, http.MethodGet, "/software/icon/widgetd", f.token, "", "")
	if strings.Contains(rec.Body.String(), `action="/software/icon/fetch"`) {
		t.Error("icon page offers a fetch form without an icon service")
	}
}

// checkUnchanged fails when the catalog entry is no longer observed.
func (f *swFixture) checkUnchanged(t *testing.T) {
	t.Helper()
	e, err := f.cat.Entry(context.Background(), "widgetd")
	if err != nil {
		t.Fatal(err)
	}
	if e.State != softwarecat.StateObserved {
		t.Errorf("refused requests changed the entry: state %q, want %q", e.State, softwarecat.StateObserved)
	}
}

// TestRunServesSoftwarePages starts the real server (run) and checks that
// it mounts the software pages and the connections tab (TM20): a signed-in admin gets them with the
// strict CSP, without a session they redirect to the login, and a change
// with a null Origin is refused.
func TestRunServesSoftwarePages(t *testing.T) {
	dir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.NewStore(db, nil).Create(context.Background(), "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	// A host, so the connections tab (TM20) has a page to serve.
	if _, err := inventory.New(db).Create(context.Background(), inventory.Host{ID: "web1", Environment: inventory.EnvProd,
		Criticality: inventory.CriticalityMedium, CredentialRef: "web1",
		Endpoints: []inventory.Endpoint{{Address: "10.0.0.10", Port: 22}}}, inventory.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	listen := freeListenAddr(t)
	path := writeConfig(t, dir, map[string]any{
		"listen":          listen,
		"public_origin":   swOrigin,
		"data_dir":        dir,
		"executor_socket": filepath.Join(dir, "no-executor.sock"),
		"executor_user":   u.Username,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &stderr) }()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, p, token, origin string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+listen+p, strings.NewReader(url.Values{"key": {"widgetd"}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if token != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}
	deadline := time.Now().Add(15 * time.Second)
	var resp *http.Response
	for {
		if resp = send(http.MethodGet, "/software", token, ""); resp != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up (stderr: %s)", stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range []string{"/software", "/software/unknown", "/hosts/web1/connections"} {
		if p != "/software" {
			resp = send(http.MethodGet, p, token, "")
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s as admin: status %d, want 200", p, resp.StatusCode)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); csp != swStrictCSP {
			t.Errorf("GET %s: CSP %q, want %q", p, csp, swStrictCSP)
		}
		resp = send(http.MethodGet, p, "", "")
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Errorf("GET %s without session: %d %q, want 303 to /login", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	for _, origin := range []string{"null", "https://evil.example"} {
		if resp = send(http.MethodPost, "/software/ignore", token, origin); resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST /software/ignore with Origin %q: status %d, want 403", origin, resp.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run after cancel: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return within 5s of cancel")
	}
}

// TestSoftwareChromeReadsLayoutCookies checks the layout data taken from
// the theme and navigation cookies.
func TestSoftwareChromeReadsLayoutCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/software", nil)
	if c := softwareChrome(r); c.Theme != "system" || c.NavCollapsed || !c.PVENav || !c.DeployEnabled {
		t.Errorf("defaults: %+v", c)
	}
	r.AddCookie(&http.Cookie{Name: themeCookie, Value: "dark"})
	r.AddCookie(&http.Cookie{Name: navCookie, Value: navCollapsed})
	if c := softwareChrome(r); c.Theme != "dark" || !c.NavCollapsed {
		t.Errorf("cookies: %+v", c)
	}
}
