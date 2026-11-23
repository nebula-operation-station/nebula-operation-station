// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"
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
	// Mounted through the real registry, as run does (no withServerFeatures).
	return newAPChain(t, db, func(pages *http.ServeMux, log *slog.Logger) error {
		isAdmin := func(ctx context.Context) bool {
			s, ok := auth.SessionFrom(ctx)
			return ok && s.UserName == "admin"
		}
		deps := serverDeps{cfg: serverconfig.Config{PublicOrigin: swOrigin}, isAdmin: isAdmin, log: log}
		return mountServerFeaturePages(deps, pages)
	})
}

// newAPChain serves the pages mount() adds on db through the server's HTTP
// chain (webServer), with an admin session "admin" and a non-admin "bob".
func newAPChain(t *testing.T, db *sql.DB, mount func(pages *http.ServeMux, log *slog.Logger) error) *apFixture {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	if err := mount(pages, log); err != nil {
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

// apPageLine returns the first line of body that contains sub.
func apPageLine(body, sub string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

// apAdminSource mounts the attack-path pages of src on the chain of db.
func apAdminChain(t *testing.T, db *sql.DB, src paths.Source) *apFixture {
	t.Helper()
	return newAPChain(t, db, func(pages *http.ServeMux, log *slog.Logger) error {
		isAdmin := func(ctx context.Context) bool {
			s, ok := auth.SessionFrom(ctx)
			return ok && s.UserName == "admin"
		}
		return mountAttackPaths(pages, swOrigin, src, isAdmin, log)
	})
}

// TestAttackPathsPageShowsComputedPathAndCoverage: through the server chain
// on a real server.db, a computed run shows its time, a path to the crown
// jewel and the coverage with the sources it does not read. A failed run
// keeps the page as it was.
func TestAttackPathsPageShowsComputedPathAndCoverage(t *testing.T) {
	ctx := context.Background()
	e := newAPSourceEnv(t)
	e.markWebJewel(t)
	e.submitAppFinding(t)
	if err := e.src.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	f := apAdminChain(t, e.db, e.src)

	rec := f.do(t, http.MethodGet, "/vuln/paths", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vuln/paths as admin: status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "not computed yet") {
		t.Fatal("computed run still says not computed")
	}
	if !strings.Contains(body, "/vuln/paths/p/") {
		t.Errorf("page shows no path to the crown jewel; body:\n%s", body)
	}
	for _, m := range []string{"docker", "firewall", "vlan"} {
		if !strings.Contains(body, m) {
			t.Errorf("coverage does not name the missing source %s", m)
		}
	}
	computed := apPageLine(body, "Computed ")
	if computed == "" {
		t.Fatal("page shows no computation time")
	}

	// A read error of a source keeps the last result and its time.
	e.src.placements = failingPlacements{}
	if err := e.src.Refresh(ctx); err == nil {
		t.Fatal("Refresh with unreadable placements succeeded")
	}
	rec = f.do(t, http.MethodGet, "/vuln/paths", f.token, "", "")
	if got := apPageLine(rec.Body.String(), "Computed "); got != computed {
		t.Errorf("failed run changed the page: %q, want %q", got, computed)
	}
}

// TestAttackPathsPageWithoutCrownJewelSaysNotComputed: no crown jewel, no
// computation; the page never reads as an all-clear.
func TestAttackPathsPageWithoutCrownJewelSaysNotComputed(t *testing.T) {
	ctx := context.Background()
	e := newAPSourceEnv(t)
	e.submitAppFinding(t)
	if err := e.src.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	f := apAdminChain(t, e.db, e.src)
	rec := f.do(t, http.MethodGet, "/vuln/paths", f.token, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not computed yet") {
		t.Fatalf("no crown jewel: status %d, page does not say not computed", rec.Code)
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
