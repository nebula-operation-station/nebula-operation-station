// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

// fakeStatus is a minimal StatusProvider for tests.
type fakeStatus struct {
	resp *pb.GetStatusResponse
	err  error
}

func (f fakeStatus) GetStatus(ctx context.Context, in *pb.GetStatusRequest, opts ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	return f.resp, f.err
}

func newTestHandler(t *testing.T, o ui.Options) *ui.Handler {
	t.Helper()
	h, err := ui.New(o)
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return h
}

func getBody(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

var navItems = []struct {
	path string
	text string
}{
	{"/dashboard", "Dashboard"},
	{"/inventory", "Inventory"},
	{"/network", "Network"},
	{"/operations", "Operations"},
	{"/runbooks", "Runbooks / Modules"},
	{"/history", "History"},
	{"/settings", "Settings"},
}

func TestNewRequiresPublicOrigin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		wantOK bool
	}{
		{name: "missing origin rejected", origin: ""},
		{name: "origin accepted", origin: "https://nebula.example.org", wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ui.New(ui.Options{PublicOrigin: tc.origin})
			if tc.wantOK && err != nil {
				t.Fatalf("ui.New: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("ui.New: expected error for empty PublicOrigin, got nil")
			}
		})
	}
}

func TestAllPagesRenderWithNavigation(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, item := range navItems {
		t.Run(item.path, func(t *testing.T) {
			body := getBody(t, h.Handler(), item.path)
			if !strings.Contains(body, item.text) {
				t.Errorf("GET %s: body missing nav item %q", item.path, item.text)
			}
			// Every page carries the full navigation.
			for _, other := range navItems {
				if !strings.Contains(body, other.text) {
					t.Errorf("GET %s: nav missing %q", item.path, other.text)
				}
			}
		})
	}
}

func TestRootRedirectsToDashboard(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /: status %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/dashboard" {
		t.Fatalf("GET /: Location %q, want /dashboard", got)
	}
}

func TestRenderedOutputHasNoInlineScriptOrStyle(t *testing.T) {
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		HostNames:    func(ctx context.Context) []string { return []string{"web-01", "nas-01"} },
	})
	scriptTag := regexp.MustCompile(`<script[^>]*>`)
	for _, item := range navItems {
		body := getBody(t, h.Handler(), item.path)
		if strings.Contains(body, "style=") {
			t.Errorf("GET %s: contains inline style attribute", item.path)
		}
		for _, tag := range scriptTag.FindAllString(body, -1) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("GET %s: inline <script> tag %q", item.path, tag)
			}
		}
	}
}

func TestHostNameIsEscaped(t *testing.T) {
	malicious := "<script>alert(1)</script>"
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		HostNames:    func(ctx context.Context) []string { return []string{malicious} },
	})
	body := getBody(t, h.Handler(), "/dashboard")
	if strings.Contains(body, malicious) {
		t.Fatal("host name rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("host name not rendered escaped")
	}
}

func TestDashboardShowsExecutorStatus(t *testing.T) {
	expiry := time.Date(2026, 10, 12, 17, 0, 0, 0, time.UTC).Unix()
	for _, tc := range []struct {
		name     string
		status   fakeStatus
		wantBody []string
	}{
		{
			name: "unlocked with active session",
			status: fakeStatus{resp: &pb.GetStatusResponse{
				Unlocked:                    true,
				PrivilegedSessionActive:     true,
				PrivilegedSessionExpiryUnix: expiry,
			}},
			wantBody: []string{"Unlocked", "active, expires 2026-10-12 17:00:00 UTC"},
		},
		{
			name:     "locked without session",
			status:   fakeStatus{resp: &pb.GetStatusResponse{Unlocked: false}},
			wantBody: []string{"Locked", "Privileged session: none"},
		},
		{
			name:     "unreachable executor",
			status:   fakeStatus{err: errors.New("connection refused")},
			wantBody: []string{"Executor unavailable"},
		},
		{
			name:     "no executor configured",
			wantBody: []string{"Executor unavailable"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ui.Options{PublicOrigin: "https://nebula.example.org"}
			if tc.name != "no executor configured" {
				opts.Status = tc.status
			}
			body := getBody(t, newTestHandler(t, opts).Handler(), "/dashboard")
			for _, want := range tc.wantBody {
				if !strings.Contains(body, want) {
					t.Errorf("dashboard missing %q", want)
				}
			}
		})
	}
}

func TestStaticHtmxIsServed(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/htmx.min.js: status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type %q, want javascript", ct)
	}
	want, err := static.FS.ReadFile("htmx.min.js")
	if err != nil {
		t.Fatalf("embedded htmx.min.js missing: %v", err)
	}
	if len(want) < 10<<10 {
		t.Fatalf("embedded htmx.min.js is only %d bytes; looks like a placeholder", len(want))
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Error("served bytes differ from embedded file")
	}
}

func TestStaticAppCSSIsServed(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/app.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/app.css: status %d, want 200", rec.Code)
	}
}

func TestVendoredHashMatchesEmbeddedFile(t *testing.T) {
	data, err := os.ReadFile("../../../web/static/VENDORED.md")
	if err != nil {
		t.Fatalf("read VENDORED.md: %v", err)
	}
	htmx, err := static.FS.ReadFile("htmx.min.js")
	if err != nil {
		t.Fatalf("read embedded htmx.min.js: %v", err)
	}
	sum := sha256.Sum256(htmx)
	if !strings.Contains(string(data), hex.EncodeToString(sum[:])) {
		t.Fatalf("VENDORED.md does not record the SHA-256 of the embedded htmx.min.js (%s)", hex.EncodeToString(sum[:]))
	}
	if !strings.Contains(string(data), "4.0.0") {
		t.Error("VENDORED.md does not record the htmx version")
	}
}

func TestSecurityHeadersPresentOnResponses(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	srv, err := h.Server()
	if err != nil {
		t.Fatalf("h.Server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	for _, path := range []string{"/dashboard", "/static/htmx.min.js"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("GET %s: CSP %q", path, csp)
		}
		if nosniff := resp.Header.Get("X-Content-Type-Options"); nosniff != "nosniff" {
			t.Errorf("GET %s: X-Content-Type-Options %q", path, nosniff)
		}
	}
}

func TestStaticPathTraversalIsRejected(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, path := range []string{"/static/../templates/layout.html", "/static/%2e%2e/static.go"} {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body, _ := io.ReadAll(rec.Result().Body)
		if rec.Code == http.StatusOK && strings.Contains(string(body), "define") {
			t.Errorf("GET %s: served file outside static/", path)
		}
	}
}
