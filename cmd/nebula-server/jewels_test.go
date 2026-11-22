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

// fakePVE serves the given remotes, nodes and guests for the directory
// mapping. ListGuests honours GuestFilter the way pveinventory.Store does:
// tombstoned incarnations are returned only with IncludeTombstoned. The
// store methods are not used here.
type fakePVE struct {
	remotes []string
	nodes   []pveinventory.Node
	guests  []pveinventory.Guest
	// filters records the GuestFilter of every ListGuests call.
	filters []pveinventory.GuestFilter
}

func (f *fakePVE) ListRemotes(context.Context, int) ([]pveinventory.Remote, error) {
	var out []pveinventory.Remote
	for _, id := range f.remotes {
		out = append(out, pveinventory.Remote{RemoteID: id})
	}
	return out, nil
}

func (f *fakePVE) ListNodes(_ context.Context, remoteID string, _ int) ([]pveinventory.Node, error) {
	var out []pveinventory.Node
	for _, n := range f.nodes {
		if n.RemoteID == remoteID {
			out = append(out, n)
		}
	}
	return out, nil
}

func (f *fakePVE) ListGuests(_ context.Context, remoteID string, flt pveinventory.GuestFilter, _ int) ([]pveinventory.Guest, error) {
	f.filters = append(f.filters, flt)
	var out []pveinventory.Guest
	for _, g := range f.guests {
		if g.RemoteID != remoteID || (g.Tombstoned && !flt.IncludeTombstoned) {
			continue
		}
		if flt.VMID != 0 && g.VMID != flt.VMID {
			continue
		}
		out = append(out, g)
	}
	return out, nil
}

// subjectsOf maps the directory's subjects by node ID.
func subjectsOf(t *testing.T, d jewelDirectory) map[string]string {
	t.Helper()
	subjects, err := d.Subjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range subjects {
		got[s.Node] = s.Label
	}
	return got
}

// jwHostsDB returns a server database that holds the given managed hosts.
func jwHostsDB(t *testing.T, ids ...string) *sql.DB {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, id := range ids {
		h := inventory.Host{ID: id, DisplayName: "Web 01", CredentialRef: "lab", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5"}}}
		if _, err := inventory.New(db).Create(context.Background(), h, inventory.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// TestCrownJewelDirectoryOffersOnlyInventoryNodes: the directory offers the
// managed hosts, the PVE nodes and the active PVE guests under their
// attack-path IDs.
func TestCrownJewelDirectoryOffersOnlyInventoryNodes(t *testing.T) {
	db := jwHostsDB(t, "web-01")
	pve := &fakePVE{
		remotes: []string{"r1"},
		nodes:   []pveinventory.Node{{RemoteID: "r1", Node: "pve1"}},
		guests:  []pveinventory.Guest{{RemoteID: "r1", VMID: 101, Name: "db"}},
	}
	got := subjectsOf(t, jewelDirectory{hosts: inventory.New(db), pve: pve})
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

// TestCrownJewelDirectoryOffersActiveGuestsOnly: a tombstoned guest is not
// offered, and the directory asks the store for active guests only.
func TestCrownJewelDirectoryOffersActiveGuestsOnly(t *testing.T) {
	db := jwHostsDB(t)
	pve := &fakePVE{
		remotes: []string{"r1"},
		guests: []pveinventory.Guest{
			{RemoteID: "r1", VMID: 101, Name: "db"},
			{RemoteID: "r1", VMID: 102, Name: "old", Tombstoned: true},
		},
	}
	got := subjectsOf(t, jewelDirectory{hosts: inventory.New(db), pve: pve})
	if _, ok := got["guest:r1/102"]; ok {
		t.Errorf("tombstoned guest offered: %v", got)
	}
	if got["guest:r1/101"] != "db" {
		t.Errorf("active guest not offered: %v", got)
	}
	if len(pve.filters) == 0 {
		t.Fatal("ListGuests was not called")
	}
	for _, f := range pve.filters {
		if f.IncludeTombstoned {
			t.Errorf("directory asked for tombstoned guests: %+v", f)
		}
	}
}

// TestCrownJewelDirectoryDropsIDsWithEmptyParts: a PVE remote or node with
// an empty name would give "pve:r1/" or "pve:/pve1"; the directory does not
// offer such IDs, because the graph never creates them.
func TestCrownJewelDirectoryDropsIDsWithEmptyParts(t *testing.T) {
	db := jwHostsDB(t)
	pve := &fakePVE{
		remotes: []string{"r1", ""},
		nodes: []pveinventory.Node{
			{RemoteID: "r1", Node: ""},
			{RemoteID: "r1", Node: "pve1"},
			{RemoteID: "", Node: "pve1"},
		},
		guests: []pveinventory.Guest{{RemoteID: "", VMID: 7, Name: "x"}, {RemoteID: "r1", VMID: 101, Name: "db"}},
	}
	got := subjectsOf(t, jewelDirectory{hosts: inventory.New(db), pve: pve})
	for node := range got {
		if strings.HasSuffix(node, "/") || strings.Contains(node, ":/") || strings.Contains(node, "//") {
			t.Errorf("directory offers an ID with an empty part: %q", node)
		}
	}
	if got["pve:r1/pve1"] != "pve1" || got["guest:r1/101"] != "db" {
		t.Errorf("valid subjects missing: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("directory offers %d subjects, want 2: %v", len(got), got)
	}
}

// TestCrownJewelPageDropsIDsTheGraphRefuses: the served page, not only the
// directory, offers no ID the graph would not accept. The directory here is
// a fake that returns one invalid ID, so the page's own check is the guard.
func TestCrownJewelPageDropsIDsTheGraphRefuses(t *testing.T) {
	db := jwHostsDB(t, "web-01")
	dir := jewelDirectory{hosts: inventory.New(db), pve: &fakePVE{
		remotes: []string{"r1"},
		nodes:   []pveinventory.Node{{RemoteID: "r1", Node: ""}},
	}}
	deps := serverDeps{cfg: serverconfig.Config{PublicOrigin: swOrigin}, db: db, log: slog.New(slog.DiscardHandler), isAdmin: func(context.Context) bool { return true }}
	h, err := newCrownJewelsPage(deps, dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, swOrigin+"/vuln/jewels", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /vuln/jewels: status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "host:web-01") {
		t.Error("the page does not offer the valid host")
	}
	if strings.Contains(body, "pve:r1/") {
		t.Error("the page offers pve:r1/, an ID the graph never creates")
	}
}

// TestCrownJewelPageMountsOnlyWithItsDeps: the page is mounted when the
// admin rule, the inventory and the PVE store are given, and not mounted
// (no route, so 404 behind the session check) when one is missing. A server
// without them starts; it simply has no crown-jewels page.
func TestCrownJewelPageMountsOnlyWithItsDeps(t *testing.T) {
	db := jwHostsDB(t, "web-01")
	log := slog.New(slog.DiscardHandler)
	admin := func(context.Context) bool { return true }
	full := serverDeps{cfg: serverconfig.Config{PublicOrigin: swOrigin}, db: db, log: log,
		inventory: inventory.New(db), pveStore: pveinventory.New(db), isAdmin: admin}

	cases := []struct {
		name     string
		deps     serverDeps
		wantCode int
	}{
		{"all deps", full, http.StatusOK},
		{"no admin rule", func() serverDeps { d := full; d.isAdmin = nil; return d }(), http.StatusNotFound},
		{"no inventory", func() serverDeps { d := full; d.inventory = nil; return d }(), http.StatusNotFound},
		{"no PVE store", func() serverDeps { d := full; d.pveStore = nil; return d }(), http.StatusNotFound},
		{"no database", func() serverDeps { d := full; d.db = nil; return d }(), http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/", http.NotFoundHandler())
			if err := mountCrownJewels(tc.deps, mux); err != nil {
				t.Fatalf("mountCrownJewels: %v", err)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, swOrigin+"/vuln/jewels", nil))
			if rec.Code != tc.wantCode {
				t.Errorf("GET /vuln/jewels: status %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}

// TestCrownJewelStoreHasNoProcessState: each call returns a store on the
// given database; closing one database leaves no store behind for it, and a
// reopened database gets a store that reads the same rows.
func TestCrownJewelStoreHasNoProcessState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	st, err := crownJewelStore(serverDeps{db: db, log: log})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Mark(context.Background(), jewels.Mark{Node: "host:web-01", Role: jewels.RoleExecutorHost, Impact: 3, Admin: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	st2, err := crownJewelStore(serverDeps{db: db2, log: log})
	if err != nil {
		t.Fatal(err)
	}
	list, err := st2.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Node != "host:web-01" {
		t.Fatalf("reopened store: %+v", list)
	}
}
