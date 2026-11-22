// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// jwFixture is the server's HTTP chain (webServer) with the registry's
// pages mounted as run does it, on a real server database that holds one
// managed host. "admin" is the admin of the rule isAdmin; "bob" has a
// session but is no admin.
type jwFixture struct {
	*swFixture
	db  *sql.DB
	bob string
}

const jwHost = "xss-host"

// jwHostName is an untrusted display name that must render as text.
const jwHostName = "<script>alert(1)</script>"

func newJWFixture(t *testing.T) *jwFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	h := inventory.Host{ID: jwHost, DisplayName: jwHostName, CredentialRef: "lab", Endpoints: []inventory.Endpoint{{Address: "10.0.0.7"}}}
	if _, err := inventory.New(db).Create(ctx, h, inventory.CreateOptions{}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	log := slog.New(slog.DiscardHandler)
	isAdmin := func(ctx context.Context) bool {
		s, ok := auth.SessionFrom(ctx)
		return ok && s.UserName == "admin"
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	deps := serverDeps{cfg: serverconfig.Config{PublicOrigin: swOrigin}, db: db, log: log,
		inventory: inventory.New(db), pveStore: pveinventory.New(db), isAdmin: isAdmin}
	if err := mountServerFeaturePages(deps, pages); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := sessions.Create(ctx, "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	bob, _, err := sessions.Create(ctx, "cred-2", "bob")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &jwFixture{swFixture: &swFixture{srv: srv, token: admin}, db: db, bob: bob}
}

// store returns the crown-jewel store of the fixture's database.
func (f *jwFixture) store(t *testing.T) *jewels.Store {
	t.Helper()
	st, err := crownJewelStore(serverDeps{db: f.db, log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// post sends a form to path as the given session with the public origin.
func (f *jwFixture) post(t *testing.T, path, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, http.MethodPost, path, token, swOrigin, form.Encode())
}

// TestCrownJewelMarkAndUnmarkThroughServer: an admin marks a managed host
// through the real routes; the row is in the real store and on the page,
// and removing it deletes the row again.
func TestCrownJewelMarkAndUnmarkThroughServer(t *testing.T) {
	f := newJWFixture(t)
	ctx := context.Background()

	rec := f.do(t, http.MethodGet, "/vuln/jewels", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vuln/jewels as admin: status %d", rec.Code)
	}
	checkStrictHeaders(t, "GET /vuln/jewels", rec)
	if !strings.Contains(rec.Body.String(), jwHost) {
		t.Error("the page does not offer the managed host as a subject")
	}

	node := "host:" + jwHost
	rec = f.post(t, "/vuln/jewels/mark", f.token, url.Values{"node": {node}, "role": {"executor_host"}, "impact": {"10"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/vuln/jewels?done=marked" {
		t.Fatalf("POST mark: status %d, location %q", rec.Code, rec.Header().Get("Location"))
	}
	st := f.store(t)
	list, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Node != node || list[0].Impact != 10 || list[0].Role != jewels.RoleExecutorHost {
		t.Fatalf("store after mark: %+v", list)
	}

	rec = f.do(t, http.MethodGet, "/vuln/jewels?done=marked", f.token, "", "")
	body := rec.Body.String()
	if !strings.Contains(body, "Crown jewel saved.") || !strings.Contains(body, node) {
		t.Error("the page does not show the marked crown jewel")
	}

	rec = f.post(t, "/vuln/jewels/unmark", f.token, url.Values{"node": {node}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST unmark: status %d", rec.Code)
	}
	list, err = st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("store after unmark: %+v", list)
	}
}

// TestCrownJewelRefusesNonAdmin: a signed-in non-admin gets 403 on all
// three routes and changes nothing.
func TestCrownJewelRefusesNonAdmin(t *testing.T) {
	f := newJWFixture(t)
	node := "host:" + jwHost

	if rec := f.do(t, http.MethodGet, "/vuln/jewels", f.bob, "", ""); rec.Code != http.StatusForbidden {
		t.Errorf("GET /vuln/jewels as non-admin: status %d, want 403", rec.Code)
	}
	form := url.Values{"node": {node}, "role": {"executor_host"}, "impact": {"10"}}
	if rec := f.post(t, "/vuln/jewels/mark", f.bob, form); rec.Code != http.StatusForbidden {
		t.Errorf("POST mark as non-admin: status %d, want 403", rec.Code)
	}
	list, err := f.store(t).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("non-admin changed the store: %+v", list)
	}
	if rec := f.post(t, "/vuln/jewels/unmark", f.bob, url.Values{"node": {node}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST unmark as non-admin: status %d, want 403", rec.Code)
	}
}

// TestCrownJewelRejectsSubjectOutsideDirectory: a node the server does not
// know (here a host that is not in the inventory) is refused and not stored.
func TestCrownJewelRejectsSubjectOutsideDirectory(t *testing.T) {
	f := newJWFixture(t)
	rec := f.post(t, "/vuln/jewels/mark", f.token, url.Values{"node": {"host:ghost"}, "role": {"other"}, "impact": {"5"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST mark of an unknown subject: status %d, want 400", rec.Code)
	}
	list, err := f.store(t).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("unknown subject stored: %+v", list)
	}
}

// TestCrownJewelHostNameRenderedAsText: a host name with markup is shown
// escaped, never as an element.
func TestCrownJewelHostNameRenderedAsText(t *testing.T) {
	f := newJWFixture(t)
	rec := f.do(t, http.MethodGet, "/vuln/jewels", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vuln/jewels: status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, jwHostName) {
		t.Error("host name rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("host name not rendered escaped as text")
	}
}

// fakePVE serves one remote with one node and one active guest, for the
// directory mapping; the store methods are not used here.
type fakePVE struct{}

func (fakePVE) ListRemotes(context.Context, int) ([]pveinventory.Remote, error) {
	return []pveinventory.Remote{{RemoteID: "r1"}}, nil
}

func (fakePVE) ListNodes(context.Context, string, int) ([]pveinventory.Node, error) {
	return []pveinventory.Node{{RemoteID: "r1", Node: "pve1"}}, nil
}

func (fakePVE) ListGuests(context.Context, string, pveinventory.GuestFilter, int) ([]pveinventory.Guest, error) {
	return []pveinventory.Guest{{RemoteID: "r1", VMID: 101, Name: "db"}}, nil
}

// TestCrownJewelDirectoryOffersOnlyInventoryNodes: the directory offers the
// managed hosts, the PVE nodes and the PVE guests under their attack-path
// IDs, and the page's subject check drops IDs the graph would not accept.
func TestCrownJewelDirectoryOffersOnlyInventoryNodes(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if _, err := inventory.New(db).Create(ctx, inventory.Host{ID: "web-01", DisplayName: "Web 01", CredentialRef: "lab", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5"}}}, inventory.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	d := jewelDirectory{hosts: inventory.New(db), pve: fakePVE{}}
	subjects, err := d.Subjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range subjects {
		got[s.Node] = s.Label
	}
	want := map[string]string{"host:web-01": "Web 01", "pve:r1/pve1": "pve1", "guest:r1/101": "db"}
	for node, label := range want {
		if got[node] != label {
			t.Errorf("subject %s: label %q, want %q (all: %v)", node, got[node], label, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("directory offers %d subjects, want %d: %v", len(got), len(want), got)
	}
}
