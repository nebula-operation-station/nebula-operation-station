// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// apToken is the bearer token the fake token API accepts.
const apToken = "nos_test_token_for_webserver"

// apiFake stands in for the token API mounted under api.Prefix. It answers
// 202 to a request with the right bearer token and 401 otherwise, and counts
// the requests that reached it, so a test can tell whether the origin check
// let a request through to the handler.
type apiFake struct {
	calls int
	paths []string
}

func (f *apiFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls++
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer "+apToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// wsFixture is the real webServer chain (security middleware, session check,
// pages) with a fake token API mounted under api.Prefix, and a real session.
type wsFixture struct {
	srv   *http.Server
	api   *apiFake
	token string // a valid web session cookie value
}

func newWSFixture(t *testing.T) *wsFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.DiscardHandler)
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	fake := &apiFake{}
	srv, err := webServer(swOrigin, login, pages, fake)
	if err != nil {
		t.Fatal(err)
	}
	return &wsFixture{srv: srv, api: fake, token: token}
}

// do sends one request through the real chain. cookie is the session cookie
// value ("" for none), bearer the Authorization token ("" for none), origin
// the Origin header ("" for none).
func (f *wsFixture) do(t *testing.T, method, path, cookie, bearer, origin, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, swOrigin+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler.ServeHTTP(rec, req)
	return rec
}

// TestTokenAPIPostReachesHandlerWithoutOrigin is the end-to-end check of the
// agent POSTs: an agent sends a bearer token and no Origin, so the browser
// origin check must not refuse it before the token API sees it.
func TestTokenAPIPostReachesHandlerWithoutOrigin(t *testing.T) {
	for _, path := range []string{"/api/v1/vuln/runs", "/api/v1/vuln/batches/b1/complete", "/api/v1/ops/notes"} {
		t.Run(path, func(t *testing.T) {
			f := newWSFixture(t)
			rec := f.do(t, http.MethodPost, path, "", apToken, "", `{}`)
			if rec.Code != http.StatusAccepted {
				t.Fatalf("POST %s with bearer, no Origin: status %d body %q, want 202 from the token API", path, rec.Code, rec.Body.String())
			}
			if f.api.calls != 1 {
				t.Fatalf("token API calls = %d, want 1", f.api.calls)
			}
			checkStrictHeaders(t, "token API POST", rec)
		})
	}
}

// TestTokenAPIBearerStillChecksToken keeps the token check in place: the
// origin exemption does not authenticate anything, a wrong token gets 401
// from the token API itself.
func TestTokenAPIBearerStillChecksToken(t *testing.T) {
	f := newWSFixture(t)
	rec := f.do(t, http.MethodPost, "/api/v1/vuln/runs", "", "nos_wrong", "", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer: status %d, want 401", rec.Code)
	}
	if f.api.calls != 1 {
		t.Fatalf("token API calls = %d, want 1", f.api.calls)
	}
}

// TestTokenAPIBodyLimitStillApplies: the exemption skips only the origin
// check; a declared body over the limit is still refused with 413 before
// the token API runs.
func TestTokenAPIBodyLimitStillApplies(t *testing.T) {
	f := newWSFixture(t)
	big := strings.Repeat("a", 1<<20+1)
	rec := f.do(t, http.MethodPost, "/api/v1/vuln/runs", "", apToken, "", big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized bearer POST: status %d, want 413", rec.Code)
	}
	if f.api.calls != 0 {
		t.Fatalf("token API calls = %d, want 0 for a refused body", f.api.calls)
	}
}

// TestCookieSessionPostOriginCheckUnchanged: a browser session POST is still
// subject to the origin check, with or without a wrong Origin, on UI pages
// and on the API prefix.
func TestCookieSessionPostOriginCheckUnchanged(t *testing.T) {
	cases := []struct {
		name, path, origin string
		want               int
	}{
		{"UI page, no Origin", "/software/x", "", http.StatusForbidden},
		{"UI page, wrong Origin", "/software/x", "https://evil.example", http.StatusForbidden},
		{"UI page, right Origin", "/software/x", swOrigin, http.StatusNotFound},
		{"API prefix, cookie, no bearer, no Origin", "/api/v1/vuln/runs", "", http.StatusForbidden},
		{"API prefix, cookie, no bearer, wrong Origin", "/api/v1/vuln/runs", "https://evil.example", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newWSFixture(t)
			rec := f.do(t, http.MethodPost, c.path, f.token, "", c.origin, `{}`)
			if rec.Code != c.want {
				t.Fatalf("status %d, want %d (body %q)", rec.Code, c.want, rec.Body.String())
			}
			if strings.HasPrefix(c.path, "/api/v1/") && f.api.calls != 0 {
				t.Fatalf("token API reached by a cookie-only POST: calls = %d", f.api.calls)
			}
		})
	}
}

// TestBearerWithCookieKeepsOriginCheck: a request carrying both the bearer
// token and the session cookie is treated as a browser session, so the origin
// check applies and refuses it without a matching Origin.
func TestBearerWithCookieKeepsOriginCheck(t *testing.T) {
	f := newWSFixture(t)
	rec := f.do(t, http.MethodPost, "/api/v1/vuln/runs", f.token, apToken, "", `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bearer + cookie, no Origin: status %d, want 403", rec.Code)
	}
	if f.api.calls != 0 {
		t.Fatalf("token API calls = %d, want 0", f.api.calls)
	}
}

// TestBearerOutsideTokenAPIKeepsOriginCheck: a bearer header does not lift the
// origin check on UI paths, which are not the token API.
func TestBearerOutsideTokenAPIKeepsOriginCheck(t *testing.T) {
	f := newWSFixture(t)
	rec := f.do(t, http.MethodPost, "/software/x", "", apToken, "", `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bearer on UI path, no Origin: status %d, want 403", rec.Code)
	}
}

// TestTokenAPIGetUnaffected: safe methods never needed the origin check; the
// token API still answers them.
func TestTokenAPIGetUnaffected(t *testing.T) {
	f := newWSFixture(t)
	rec := f.do(t, http.MethodGet, "/api/v1/vuln/runs", "", apToken, "", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("GET with bearer: status %d, want 202", rec.Code)
	}
}
