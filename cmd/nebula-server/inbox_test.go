// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// inboxNavPages are the subpackage pages that show the Notifications
// navigation entry: software, attack paths, traffic map and connections.
// The jewels page is not mounted by the server (no jewels handler in
// cmd/nebula-server), so it has no Chrome adapter to wire.
var inboxNavPages = []string{"/software", "/vuln/paths", "/traffic", "/hosts/web1/connections"}

// newInboxFixture serves the server's page chain as run builds it: the UI
// page, the subpackage pages with their Chrome adapters, and the request
// wrapper of the inbox (WithNotificationsNav) behind the session check. The
// inbox is wired with newInboxWiring when wired is true; admin is the admin
// rule of the other admin pages.
func newInboxFixture(t *testing.T, wired, admin bool) *swFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	isAdmin := func(context.Context) bool { return admin }

	opts := ui.Options{PublicOrigin: swOrigin, Log: log}
	if wired {
		w, err := newInboxWiring(db, func(ctx context.Context) (bool, error) { return isAdmin(ctx), nil })
		if err != nil {
			t.Fatal(err)
		}
		opts.Notifications = w.Log
		opts.NotificationsAdmin = w.Admin
	}
	uh, err := ui.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", uh.Handler())

	sw, err := newSoftwarePages(db, log)
	if err != nil {
		t.Fatal(err)
	}
	sw.Register(pages)
	if err := mountAttackPaths(pages, swOrigin, isAdmin, log); err != nil {
		t.Fatal(err)
	}
	hosts, ip := tmInventory()
	if err := mountTrafficMap(pages, swOrigin, db, hosts, ip, log, trafficstore.DefaultRetention); err != nil {
		t.Fatal(err)
	}
	cp, err := newConnectionsPages(db, fakeConnHosts{{ID: "web1", DisplayName: "web1.lab", CredentialRef: "web1"}},
		fakeConnAssets(nil), log, trafficstore.DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	cp.Register(pages)

	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(ctx, "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, uh.WithNotificationsNav(pages), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &swFixture{srv: srv, token: token}
}

// TestInboxPageServedOnlyWhenWired: the server serves /notifications only
// when the inbox is wired; an unwired server answers 404, a wired one 200
// for an admin. Before the wiring, the page was 404 in every deployment.
func TestInboxPageServedOnlyWhenWired(t *testing.T) {
	cases := []struct {
		name  string
		wired bool
		want  int
	}{
		{"wired", true, http.StatusOK},
		{"unwired", false, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newInboxFixture(t, c.wired, true)
			if rec := f.do(t, http.MethodGet, "/notifications", f.token, "", ""); rec.Code != c.want {
				t.Errorf("GET /notifications = %d, want %d", rec.Code, c.want)
			}
		})
	}
}

// TestNotificationsNavOnEverySubpackagePage: the entry appears on each
// subpackage page for an admin of a wired inbox, and on none otherwise.
func TestNotificationsNavOnEverySubpackagePage(t *testing.T) {
	cases := []struct {
		name  string
		wired bool
		admin bool
		want  bool
	}{
		{"admin with inbox", true, true, true},
		{"non-admin with inbox", true, false, false},
		{"admin without inbox", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newInboxFixture(t, c.wired, c.admin)
			for _, p := range inboxNavPages {
				rec := f.do(t, http.MethodGet, p, f.token, "", "")
				// The attack-path pages are admin-only (ADR 0011 D10): a
				// non-admin gets 403 and no page to show the entry on.
				if rec.Code == http.StatusForbidden && !c.admin {
					continue
				}
				if rec.Code != http.StatusOK {
					t.Errorf("GET %s = %d, want 200", p, rec.Code)
					continue
				}
				if got := strings.Contains(rec.Body.String(), `href="/notifications"`); got != c.want {
					t.Errorf("GET %s: Notifications entry shown = %v, want %v", p, got, c.want)
				}
			}
		})
	}
}

// TestNotificationsNavVisibleNeedsTheInboxRequestWrapper: the Chrome
// adapters read the entry only through the request wrapper; a request
// that does not pass it never shows the entry.
func TestNotificationsNavVisibleNeedsTheInboxRequestWrapper(t *testing.T) {
	f := newInboxFixture(t, true, true)
	rec := f.do(t, http.MethodGet, "/software", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /software = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `href="/notifications"`) {
		t.Fatal("wrapped request: entry missing")
	}
	plain := httptest.NewRequest(http.MethodGet, "/hosts/web1/connections", nil)
	if c := connectionsChrome(plain); c.NotificationsNav {
		t.Error("request without the inbox wrapper shows the entry")
	}
}

// An executor outage must reach the inbox as an admin check error, not as a
// plain "no": the inbox then logs the failure (logInboxCheckFailure) and
// denies. The wiring of main is cachedVulnAdmin behind newInboxWiring.
func TestInboxAdminErrorReachesTheInbox(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	boom := errors.New("executor unavailable")
	w, err := newInboxWiring(db, cachedVulnAdmin(&countingStatus{err: boom}, inboxStatusTTL, time.Now, testSpawn(t)))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := w.Admin(context.Background(), "alice")
	if ok {
		t.Fatal("admin granted on a failed executor status read")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("inbox admin error = %v, want the executor status error", err)
	}
}
