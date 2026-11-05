// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/connections"
)

var (
	connWebAddr     = netip.MustParseAddr("10.0.0.10")
	connNASAddr     = netip.MustParseAddr("10.0.0.20")
	connPrinterAddr = netip.MustParseAddr("10.0.0.99")
)

// connFixture is the server's HTTP chain (webServer: security
// middleware, session check, pages) with the connections pages mounted
// as in run, on a real server database: hosts web1 and nas, the asset
// printer, and flows web1 → nas:443 and web1 → printer:631.
type connFixture struct {
	sw    *swFixture // srv and token; cat unused
	pages *http.ServeMux
	inv   *inventory.Store
	ipam  *ipam.Store
	flows *trafficstore.Store
}

func newConnFixture(t *testing.T) *connFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	inv := inventory.New(db)
	for _, h := range []inventory.Host{
		{ID: "web1", DisplayName: "web1.lab", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
			Endpoints: []inventory.Endpoint{{Address: connWebAddr.String(), Port: 22}}, CredentialRef: "web1"},
		{ID: "nas", DisplayName: "nas.lab", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
			Endpoints: []inventory.Endpoint{{Address: connNASAddr.String(), Port: 22}}, CredentialRef: "nas"},
	} {
		if _, err := inv.Create(ctx, h, inventory.CreateOptions{}); err != nil {
			t.Fatalf("create host %s: %v", h.ID, err)
		}
	}
	ipamStore := ipam.New(db, ipam.FromInventory(inv.List))
	if err := ipamStore.SaveAsset(ctx, ipam.Asset{ID: "printer", Name: "Office printer", Kind: ipam.KindPrinter,
		Addresses: []netip.Addr{connPrinterAddr}}); err != nil {
		t.Fatal(err)
	}
	ts := trafficstore.New(db)
	hour := time.Now().Add(-time.Hour).Truncate(time.Hour)
	for _, b := range []struct {
		key flowagg.FlowKey
		rep string
		own netip.Addr
	}{
		{flowagg.FlowKey{A: connWebAddr, B: connNASAddr, Proto: flowagg.TCP, ServerPort: 443, Server: flowagg.SideB, Tier: flowagg.TierSocket}, "web1", connWebAddr},
		{flowagg.FlowKey{A: connWebAddr, B: connPrinterAddr, Proto: flowagg.TCP, ServerPort: 631, Server: flowagg.SideB, Tier: flowagg.TierSocket}, "web1", connWebAddr},
	} {
		if err := ts.UpsertBucket(ctx, trafficstore.Bucket{Hour: hour, Key: b.key, Reporter: b.rep, BytesAB: 4096, BytesBA: 2048, Connections: 1},
			[]netip.Addr{b.own}); err != nil {
			t.Fatal(err)
		}
	}

	log := slog.New(slog.DiscardHandler)
	cp, err := newConnectionsPages(db, inv, ipamStore, log)
	if err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
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
	srv, err := webServer(swOrigin, login, pages, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &connFixture{sw: &swFixture{srv: srv, token: token}, pages: pages, inv: inv, ipam: ipamStore, flows: ts}
}

var connPages = []string{
	"/hosts/web1/connections",
	"/hosts/web1/connections?window=1h&sort=peer&order=asc",
	"/hosts/web1/connections?window=21d",
	"/network/a/printer/connections",
}

// TestConnectionsPagesServedToSignedInAdmin checks that the server mounts
// the connections tab the host and asset pages link to: a signed-in
// admin gets each page through the full chain with the strict CSP, the
// flows and the peers resolved from the server's records.
func TestConnectionsPagesServedToSignedInAdmin(t *testing.T) {
	f := newConnFixture(t)
	for _, p := range connPages {
		rec := f.sw.do(t, http.MethodGet, p, f.sw.token, "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200", p, rec.Code)
			continue
		}
		checkStrictHeaders(t, "GET "+p, rec)
		body := rec.Body.String()
		if strings.Contains(body, "<script>") || strings.Contains(body, " onclick=") || strings.Contains(body, "<style") {
			t.Errorf("GET %s: page carries inline script or style", p)
		}
		if strings.HasPrefix(p, "/hosts/") {
			if !strings.Contains(body, `href="/hosts/nas"`) || !strings.Contains(body, `href="/network/a/printer"`) {
				t.Errorf("GET %s: peers nas and printer not linked", p)
			}
		} else if !strings.Contains(body, `href="/hosts/web1"`) {
			t.Errorf("GET %s: peer web1 not linked", p)
		}
	}
	for p, want := range map[string]int{
		"/hosts/nope/connections":             http.StatusNotFound,
		"/network/a/nope/connections":         http.StatusNotFound,
		"/hosts/web1/connections?window=30d":  http.StatusBadRequest,
		"/hosts/web1/connections?sort=secret": http.StatusBadRequest,
	} {
		if rec := f.sw.do(t, http.MethodGet, p, f.sw.token, "", ""); rec.Code != want {
			t.Errorf("GET %s: status %d, want %d", p, rec.Code, want)
		}
	}
}

// TestConnectionsPagesRefuseWithoutSession checks that every connections
// page needs a valid web session: no cookie or an unknown token is sent
// to the login and sees no flow data.
func TestConnectionsPagesRefuseWithoutSession(t *testing.T) {
	f := newConnFixture(t)
	for _, token := range []string{"", "not-a-session-token", strings.Repeat("A", 43)} {
		for _, p := range append(connPages, "/hosts/nope/connections") {
			rec := f.sw.do(t, http.MethodGet, p, token, "", "")
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
				t.Errorf("token %q: GET %s: status %d location %q, want 303 to /login", token, p, rec.Code, rec.Header().Get("Location"))
			}
			if body := rec.Body.String(); strings.Contains(body, "nas.lab") || strings.Contains(body, connNASAddr.String()) {
				t.Errorf("token %q: GET %s leaks flow data", token, p)
			}
			checkStrictHeaders(t, "GET "+p, rec)
		}
	}
}

// TestConnectionsPagesReadOnly checks that the pages take no changes: a
// POST with a foreign Origin is stopped by the middleware, one with the
// public origin finds no route.
func TestConnectionsPagesReadOnly(t *testing.T) {
	f := newConnFixture(t)
	for _, origin := range []string{"", "null", "https://evil.example"} {
		if rec := f.sw.do(t, http.MethodPost, "/hosts/web1/connections", f.sw.token, origin, "x=1"); rec.Code != http.StatusForbidden {
			t.Errorf("POST with Origin %q: status %d, want 403", origin, rec.Code)
		}
	}
	if rec := f.sw.do(t, http.MethodPost, "/hosts/web1/connections", f.sw.token, swOrigin, "x=1"); rec.Code != http.StatusNotFound {
		t.Errorf("POST with the public origin: status %d, want 404", rec.Code)
	}
}

// TestConnectionsPagesFailClosedOutsideTheChain checks that the handler
// itself refuses a request that did not pass the session check, so a
// mount outside the authenticated chain exposes nothing.
func TestConnectionsPagesFailClosedOutsideTheChain(t *testing.T) {
	f := newConnFixture(t)
	for _, p := range connPages {
		rec := httptest.NewRecorder()
		f.pages.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, swOrigin+p, nil))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "nas.lab") {
			t.Errorf("GET %s without the session check: status %d, want 403 without data", p, rec.Code)
		}
	}
}

// TestConnDirectoryPeers checks peer resolution from the server's
// records: hosts by endpoint and linked asset, assets otherwise, and an
// address claimed by two hosts left unresolved.
func TestConnDirectoryPeers(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	d := connDirectory{
		hosts: fakeConnHosts{
			{ID: "h1", DisplayName: "one", Endpoints: []inventory.Endpoint{{Address: "10.0.0.1"}, {Address: "[fd00::1]"}, {Address: "h1.example.org"}}},
			{ID: "h2", Endpoints: []inventory.Endpoint{{Address: "10.0.0.2"}, {Address: "10.0.0.9"}}},
			{ID: "h3", Endpoints: []inventory.Endpoint{{Address: "10.0.0.9"}}},
		},
		assets: fakeConnAssets{
			{ID: "as1", Name: "", Hostname: "sw1", Addresses: []netip.Addr{a("10.0.0.50")}},
			{ID: "as2", HostID: "h2", Addresses: []netip.Addr{a("10.0.0.60")}},
			{ID: "as3", Name: "dup", Addresses: []netip.Addr{a("10.0.0.1")}},
		},
	}
	got, err := d.Peers(context.Background(), []netip.Addr{a("10.0.0.1"), a("fd00::1"), a("10.0.0.50"), a("10.0.0.60"), a("10.0.0.9"), a("10.9.9.9")})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"10.0.0.1": "host h1 one", "fd00::1": "host h1 one", "10.0.0.50": "asset as1 sw1", "10.0.0.60": "host h2 ",
	}
	if len(got) != len(want) {
		t.Errorf("peers %v, want %v", got, want)
	}
	for addr, w := range want {
		p, ok := got[a(addr)]
		kind := map[connections.PeerKind]string{connections.PeerHost: "host", connections.PeerAsset: "asset"}[p.Kind]
		if !ok || kind+" "+p.ID+" "+p.Name != w {
			t.Errorf("peer %s = %+v, want %s", addr, p, w)
		}
	}

	// A subject keeps only the addresses Peers attributes to it: the
	// 10.0.0.9 h2 shares with h3 belongs to neither, and as3's 10.0.0.1
	// resolves to h1.
	for _, c := range []struct {
		host  bool
		id    string
		addrs string
	}{
		{true, "h1", "10.0.0.1,fd00::1"},
		{true, "h2", "10.0.0.2,10.0.0.60"},
		{true, "h3", ""},
		{false, "as1", "10.0.0.50"},
		{false, "as2", "10.0.0.60"},
		{false, "as3", ""},
	} {
		var s connections.Subject
		if c.host {
			s, err = d.Host(context.Background(), c.id)
		} else {
			s, err = d.Asset(context.Background(), c.id)
		}
		var got []string
		for _, a := range s.Addrs {
			got = append(got, a.String())
		}
		if err != nil || strings.Join(got, ",") != c.addrs {
			t.Errorf("subject %s = %v, %v; want addresses %q", c.id, got, err, c.addrs)
		}
	}
	if s, err := d.Host(context.Background(), "h2"); err != nil || s.Name != "h2" {
		t.Errorf("host h2 = %+v, %v", s, err)
	}
	if _, err := d.Host(context.Background(), "nope"); err == nil {
		t.Error("unknown host resolved")
	}
	if s, err := d.Asset(context.Background(), "as1"); err != nil || s.Name != "sw1" {
		t.Errorf("asset as1 = %+v, %v", s, err)
	}
	if _, err := d.Asset(context.Background(), "nope"); err == nil {
		t.Error("unknown asset resolved")
	}
}

// TestConnDirectorySelfDuplicateNotAmbiguous checks that an unlinked
// asset listing the same address twice is not ambiguous with itself: the
// address still resolves to the asset, so its flows are not lost.
func TestConnDirectorySelfDuplicateNotAmbiguous(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	d := connDirectory{
		hosts:  fakeConnHosts{},
		assets: fakeConnAssets{{ID: "dup", Name: "dup", Addresses: []netip.Addr{a("10.0.0.50"), a("10.0.0.50")}}},
	}
	got, err := d.Peers(context.Background(), []netip.Addr{a("10.0.0.50")})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := got[a("10.0.0.50")]
	if !ok {
		t.Fatalf("address claimed twice by one asset not resolved: %v", got)
	}
	if p.Kind != connections.PeerAsset || p.ID != "dup" || p.Name != "dup" {
		t.Errorf("peer = %+v, want asset dup", p)
	}
}

// TestConnectionsSharedAddressNotAttributed checks that a host page does
// not show another host's flows as its own through an address both
// claim: hosts gwa and gwb sit behind the NAT address 10.0.0.77 (gwb by
// a linked IPAM asset), so gwb's flow from that address appears on
// neither page, while each host's flow from its own address does.
func TestConnectionsSharedAddressNotAttributed(t *testing.T) {
	f := newConnFixture(t)
	ctx := context.Background()
	nat, gwa, gwb := netip.MustParseAddr("10.0.0.77"), netip.MustParseAddr("10.0.0.71"), netip.MustParseAddr("10.0.0.72")
	for _, h := range []inventory.Host{
		{ID: "gwa", DisplayName: "gwa.lab", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
			Endpoints: []inventory.Endpoint{{Address: gwa.String(), Port: 22}, {Address: nat.String(), Port: 2222}}, CredentialRef: "gwa"},
		{ID: "gwb", DisplayName: "gwb.lab", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
			Endpoints: []inventory.Endpoint{{Address: gwb.String(), Port: 22}}, CredentialRef: "gwb"},
	} {
		if _, err := f.inv.Create(ctx, h, inventory.CreateOptions{}); err != nil {
			t.Fatalf("create host %s: %v", h.ID, err)
		}
	}
	if err := f.ipam.SaveAsset(ctx, ipam.Asset{ID: "gwb-nat", Name: "gwb NAT", Kind: ipam.KindServer, HostID: "gwb",
		Addresses: []netip.Addr{nat}}); err != nil {
		t.Fatal(err)
	}
	hour := time.Now().Add(-time.Hour).Truncate(time.Hour)
	for _, b := range []struct {
		from netip.Addr
		port uint16
		rep  string
	}{
		{nat, 8001, "gwb"},
		{gwa, 8002, "gwa"},
		{gwb, 8003, "gwb"},
	} {
		key := flowagg.FlowKey{A: connNASAddr, B: b.from, Proto: flowagg.TCP, ServerPort: b.port, Server: flowagg.SideA, Tier: flowagg.TierSocket}
		if err := f.flows.UpsertBucket(ctx, trafficstore.Bucket{Hour: hour, Key: key, Reporter: b.rep, BytesAB: 100, BytesBA: 100, Connections: 1},
			[]netip.Addr{b.from}); err != nil {
			t.Fatal(err)
		}
	}
	for p, c := range map[string]struct{ want, not []string }{
		"/hosts/gwa/connections": {want: []string{"tcp/8002"}, not: []string{"tcp/8001", "tcp/8003", nat.String()}},
		"/hosts/gwb/connections": {want: []string{"tcp/8003"}, not: []string{"tcp/8001", "tcp/8002", nat.String()}},
	} {
		rec := f.sw.do(t, http.MethodGet, p, f.sw.token, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", p, rec.Code)
		}
		body := rec.Body.String()
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("GET %s: own flow %s missing", p, w)
			}
		}
		for _, n := range c.not {
			if strings.Contains(body, n) {
				t.Errorf("GET %s: shows %s, which is not the host's own", p, n)
			}
		}
	}
}

type fakeConnHosts []inventory.Host

func (f fakeConnHosts) Get(_ context.Context, id string) (inventory.Host, error) {
	for _, h := range f {
		if h.ID == id {
			return h, nil
		}
	}
	return inventory.Host{}, inventory.ErrHostNotFound
}

func (f fakeConnHosts) List(context.Context) ([]inventory.Host, error) { return f, nil }

type fakeConnAssets []ipam.Asset

func (f fakeConnAssets) Asset(_ context.Context, id string) (ipam.Asset, error) {
	for _, a := range f {
		if a.ID == id {
			return a, nil
		}
	}
	return ipam.Asset{}, ipam.ErrNotFound
}

func (f fakeConnAssets) Assets(context.Context) ([]ipam.Asset, error) { return f, nil }
