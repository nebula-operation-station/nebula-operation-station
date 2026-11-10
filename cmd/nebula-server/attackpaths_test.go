// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// apFixture is the server's HTTP chain (webServer) with the attack-path
// pages mounted as in run. The admin rule is the session user "admin"
// (run passes vulnAdmin, the export's rule); "bob" has a session but is
// no admin.
type apFixture struct {
	*swFixture
	bob string
}

func newAPFixture(t *testing.T) *apFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.DiscardHandler)
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	isAdmin := func(ctx context.Context) bool {
		s, ok := auth.SessionFrom(ctx)
		return ok && s.UserName == "admin"
	}
	if err := mountAttackPaths(pages, swOrigin, isAdmin, log); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := sessions.Create(context.Background(), "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := sessions.Create(context.Background(), "cred-2", "bob")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &apFixture{swFixture: &swFixture{srv: srv, token: admin}, bob: bob}
}

var apPages = []string{"/vuln/paths", "/vuln/paths/map", "/vuln/paths/map/frame"}

// TestAttackPathPagesMountedBehindAdminGuard: an admin reaches the pages
// through the full chain (session check, security middleware); a signed-in
// non-admin gets 403 and nothing of the page; without a session the chain
// sends to the login.
func TestAttackPathPagesMountedBehindAdminGuard(t *testing.T) {
	f := newAPFixture(t)

	rec := f.do(t, http.MethodGet, "/vuln/paths", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vuln/paths as admin: status %d", rec.Code)
	}
	checkStrictHeaders(t, "GET /vuln/paths", rec)
	// No computation is wired yet: every crown jewel reads unknown.
	if !strings.Contains(rec.Body.String(), "not computed yet") {
		t.Error("list page does not say the paths are not computed yet")
	}

	rec = f.do(t, http.MethodGet, "/vuln/paths/map", f.token, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `src="/vuln/paths/map/frame"`) {
		t.Fatalf("GET /vuln/paths/map as admin: status %d", rec.Code)
	}
	checkStrictHeaders(t, "GET /vuln/paths/map", rec)

	// The frame keeps its own sandboxing CSP through the global middleware.
	rec = f.do(t, http.MethodGet, "/vuln/paths/map/frame", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vuln/paths/map/frame as admin: status %d", rec.Code)
	}
	checkFrameCSP(t, "GET /vuln/paths/map/frame", rec.Header().Get("Content-Security-Policy"))
	if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("frame: nosniff %q", v)
	}

	for _, p := range append(apPages, "/vuln/paths/p/"+strings.Repeat("a", 64)) {
		rec := f.do(t, http.MethodGet, p, f.bob, "", "")
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s as non-admin: status %d, want 403", p, rec.Code)
		}
		if b := rec.Body.String(); strings.Contains(b, "Attack paths") || strings.Contains(b, "data-paths") || strings.Contains(b, "<iframe") {
			t.Errorf("GET %s as non-admin leaks page content", p)
		}
		for _, token := range []string{"", "not-a-session-token"} {
			rec := f.do(t, http.MethodGet, p, token, "", "")
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
				t.Errorf("token %q: GET %s: status %d location %q, want 303 to /login", token, p, rec.Code, rec.Header().Get("Location"))
			}
		}
	}
}

func TestAttackPathMapNode(t *testing.T) {
	cases := map[string]struct {
		id, want string
		ok       bool
	}{
		"host":          {"host:web01", "web01", true},
		"not a host":    {"container:web01/app", "", false},
		"entry class":   {"entry:internet", "", false},
		"empty host":    {"host:", "", false},
		"asset-like id": {"host:asset:x", "", false},
	}
	for name, c := range cases {
		got, ok := attackPathMapNode(c.id)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: attackPathMapNode(%q) = %q, %v; want %q, %v", name, c.id, got, ok, c.want, c.ok)
		}
	}
}
