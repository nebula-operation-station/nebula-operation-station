// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

// tmFrameCSP are the directives of the renderer document's own policy
// (internal/web/ui/trafficmap.frameCSP) that must survive the global
// middleware, which sets the strict page CSP first.
var tmFrameCSP = []string{
	"default-src 'none'",
	"script-src " + swOrigin + "/static/trafficmap/",
	"connect-src 'none'",
	"frame-ancestors " + swOrigin,
	"sandbox allow-scripts",
}

// tmModules are renderer modules the frame imports.
var tmModules = []string{"boot.js", "main.js", "model.js"}

// fakeTrafficIPAM is a fixed set of IPAM assets and networks.
type fakeTrafficIPAM struct {
	assets []ipam.Asset
	nets   []ipam.Network
}

func (f fakeTrafficIPAM) Assets(context.Context) ([]ipam.Asset, error)     { return f.assets, nil }
func (f fakeTrafficIPAM) Networks(context.Context) ([]ipam.Network, error) { return f.nets, nil }

// tmInventory: host h1 and the unlinked asset a1 both claim 10.0.0.5 (the
// gateway of lan), so that address stays unresolved; asset a2 alone owns
// 10.0.1.1 (the gateway of dmz); asset a3 became host h1.
func tmInventory() (func(context.Context) ([]inventory.Host, error), fakeTrafficIPAM) {
	hosts := []inventory.Host{{ID: "h1", DisplayName: "Web one", Endpoints: []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}}}}
	ip := fakeTrafficIPAM{
		assets: []ipam.Asset{
			{ID: "a1", Name: "Printer", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.5")}},
			{ID: "a2", Name: "Firewall", Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.1")}},
			{ID: "a3", Name: "Was a server", HostID: "h1", Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.7")}},
		},
		nets: []ipam.Network{
			{ID: "lan", Name: "LAN", Prefix: netip.MustParsePrefix("10.0.0.0/24"), VLAN: 10, Gateway: netip.MustParseAddr("10.0.0.5")},
			{ID: "dmz", Name: "DMZ", Prefix: netip.MustParsePrefix("10.0.1.0/24"), VLAN: 20, Gateway: netip.MustParseAddr("10.0.1.1")},
		},
	}
	return func(context.Context) ([]inventory.Host, error) { return hosts, nil }, ip
}

// newTMFixture is the server's HTTP chain (webServer) with the traffic map
// mounted as in run, the token API enabled (a stub) and a real session.
func newTMFixture(t *testing.T) *swFixture {
	return newTMFixtureWithRetention(t, trafficstore.DefaultRetention)
}

// newTMFixtureWithRetention is newTMFixture with a configured traffic
// retention.
func newTMFixtureWithRetention(t *testing.T, retention time.Duration) *swFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.DiscardHandler)
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	hosts, ip := tmInventory()
	if err := mountTrafficMap(pages, swOrigin, db, hosts, ip, log, retention); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), "cred-1", "admin")
	if err != nil {
		t.Fatal(err)
	}
	tokenAPI := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "token API", http.StatusTeapot) })
	srv, err := webServer(swOrigin, login, pages, tokenAPI)
	if err != nil {
		t.Fatal(err)
	}
	return &swFixture{srv: srv, token: token}
}

func checkFrameCSP(t *testing.T, what, csp string) {
	t.Helper()
	got := map[string]bool{}
	for _, d := range strings.Split(csp, ";") {
		got[strings.TrimSpace(d)] = true
	}
	for _, d := range tmFrameCSP {
		if !got[d] {
			t.Errorf("%s: CSP %q lacks %q", what, csp, d)
		}
	}
	if got["frame-ancestors 'none'"] || got["default-src 'self'"] {
		t.Errorf("%s: CSP %q still carries the page policy", what, csp)
	}
}

// TestTrafficMapMountedBehindSession checks the mount through the full
// chain: the page, the frame and the model need a session, the frame
// keeps its own sandboxing CSP through the global middleware, and the
// model is served by the session chain although the token API is on.
func TestTrafficMapMountedBehindSession(t *testing.T) {
	f := newTMFixture(t)
	rec := f.do(t, http.MethodGet, "/traffic", f.token, "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `src="/traffic/frame"`) {
		t.Fatalf("GET /traffic: status %d", rec.Code)
	}
	checkStrictHeaders(t, "GET /traffic", rec)

	rec = f.do(t, http.MethodGet, "/traffic/frame", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /traffic/frame: status %d", rec.Code)
	}
	checkFrameCSP(t, "GET /traffic/frame", rec.Header().Get("Content-Security-Policy"))
	if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("frame: nosniff %q", v)
	}

	rec = f.do(t, http.MethodGet, "/api/v1/trafficmap?window=24h", f.token, "", "")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("GET model: status %d type %q: %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}

	for _, token := range []string{"", "not-a-session-token"} {
		for _, p := range []string{"/traffic", "/traffic?window=1h", "/traffic/frame", "/api/v1/trafficmap", "/api/v1/trafficmap?window=1h"} {
			rec := f.do(t, http.MethodGet, p, token, "", "")
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
				t.Errorf("token %q: GET %s: status %d location %q, want 303 to /login", token, p, rec.Code, rec.Header().Get("Location"))
			}
			if strings.Contains(rec.Body.String(), "Web one") || strings.Contains(rec.Body.String(), "<iframe") {
				t.Errorf("token %q: GET %s leaks content", token, p)
			}
		}
	}
}

// TestTrafficMapModulesServedWithoutSession checks that the renderer
// modules are reachable as the sandboxed frame requests them: Origin null
// and no cookie, without a login redirect.
func TestTrafficMapModulesServedWithoutSession(t *testing.T) {
	f := newTMFixture(t)
	for _, name := range tmModules {
		rec := f.do(t, http.MethodGet, "/static/trafficmap/"+name, "", "null", "")
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d (location %q), want 200", name, rec.Code, rec.Header().Get("Location"))
			continue
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", name, ct)
		}
		if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "*" {
			t.Errorf("%s: Access-Control-Allow-Origin %q", name, v)
		}
		if v := rec.Header().Get("Access-Control-Allow-Credentials"); v != "" {
			t.Errorf("%s: credentials allowed: %q", name, v)
		}
		want, err := static.FS.ReadFile("trafficmap/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rec.Body.Bytes(), want) {
			t.Errorf("%s: body differs from the embedded module", name)
		}
	}
}

// TestTrafficMapModelUsesServerRecords checks the model's inventory: only
// the server's hosts and IPAM assets become nodes, an asset that became a
// host is not a node of its own, an address claimed by two nodes stays
// unresolved (no gateway), and a single owner becomes the gateway.
func TestTrafficMapModelUsesServerRecords(t *testing.T) {
	f := newTMFixture(t)
	rec := f.do(t, http.MethodGet, "/api/v1/trafficmap?window=1h", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var m struct {
		Zones []struct {
			ID, Gateway string
		} `json:"zones"`
		Nodes []struct {
			ID, Kind, Zone string
		} `json:"nodes"`
		Omitted struct {
			Addresses int `json:"addresses"`
		} `json:"omitted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]string{}
	for _, n := range m.Nodes {
		nodes[n.ID] = n.Kind + "@" + n.Zone
	}
	want := map[string]string{"h1": "host@lan", "asset:a1": "asset@lan", "asset:a2": "asset@dmz"}
	if len(nodes) != len(want) {
		t.Errorf("nodes %v, want %v", nodes, want)
	}
	for id, w := range want {
		if nodes[id] != w {
			t.Errorf("node %s: %q, want %q", id, nodes[id], w)
		}
	}
	gw := map[string]string{}
	for _, z := range m.Zones {
		gw[z.ID] = z.Gateway
	}
	if gw["lan"] != "" || gw["dmz"] != "asset:a2" {
		t.Errorf("gateways %v, want lan unresolved and dmz asset:a2", gw)
	}
	if m.Omitted.Addresses != 1 {
		t.Errorf("omitted addresses %d, want 1 (10.0.0.5 claimed twice)", m.Omitted.Addresses)
	}
}

// tmFixedFlows serves the same flows for every query.
type tmFixedFlows []flowagg.FlowTotal

func (f tmFixedFlows) TopN(context.Context, netip.Addr, flowagg.Window, int) ([]flowagg.FlowTotal, error) {
	return f, nil
}

func (f tmFixedFlows) OverviewUnion(context.Context, []netip.Addr, flowagg.Window, int) ([]flowagg.FlowTotal, error) {
	return f, nil
}

// TestTrafficMapAssetCannotDisplaceHost: an unlinked IPAM asset whose ID
// (derived from a hostname the network reported) equals a managed host's
// ID gets its own node ID, so the host keeps its node and its flows and
// the asset is a separate node; neither is dropped as a duplicate.
func TestTrafficMapAssetCannotDisplaceHost(t *testing.T) {
	hostAddr, assetAddr, peer := netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.7")
	hosts := func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{
			{ID: "h1", DisplayName: "Web one", Endpoints: []inventory.Endpoint{{Address: hostAddr.String(), Port: 22}}},
			{ID: "h2", DisplayName: "Web two", Endpoints: []inventory.Endpoint{{Address: peer.String(), Port: 22}}},
		}, nil
	}
	ip := fakeTrafficIPAM{assets: []ipam.Asset{{ID: "h1", Hostname: "h1", Addresses: []netip.Addr{assetAddr}}}}
	now := time.Now()
	flow := func(a, b netip.Addr, bytes uint64) flowagg.FlowTotal {
		return flowagg.FlowTotal{Key: flowagg.FlowKey{A: a, B: b, Proto: flowagg.TCP, ServerPort: 443, Server: flowagg.SideB},
			BytesAB: bytes, BytesBA: bytes, Connections: 1, FirstSeen: now.Add(-time.Minute), LastSeen: now}
	}
	flows := tmFixedFlows{flow(hostAddr, peer, 100), flow(assetAddr, peer, 50)}
	b, err := tmapi.NewBuilder(trafficInventory(hosts, ip), flows, nil, tmapi.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.Build(context.Background(), tmapi.Query{Window: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Nodes []struct {
			ID, Label, Kind string
		} `json:"nodes"`
		Edges []struct {
			A, B string
		} `json:"edges"`
		Unmapped int `json:"unmapped_flows"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]string{}
	for _, n := range m.Nodes {
		nodes[n.ID] = n.Kind + "/" + n.Label
	}
	want := map[string]string{"h1": "host/Web one", "h2": "host/Web two", "asset:h1": "asset/h1"}
	if len(nodes) != len(want) {
		t.Errorf("nodes %v, want %v", nodes, want)
	}
	for id, w := range want {
		if nodes[id] != w {
			t.Errorf("node %s: %q, want %q (nodes %v)", id, nodes[id], w, nodes)
		}
	}
	edges := map[string]bool{}
	for _, e := range m.Edges {
		edges[e.A+"-"+e.B], edges[e.B+"-"+e.A] = true, true
	}
	if !edges["h1-h2"] || !edges["asset:h1-h2"] || len(m.Edges) != 2 {
		t.Errorf("edges %v, want h1-h2 and asset:h1-h2", m.Edges)
	}
	if m.Unmapped != 0 {
		t.Errorf("unmapped flows %d, want 0", m.Unmapped)
	}
}

// TestTrafficMapRetentionShortened checks that the configured retention
// is used where the store is opened: with a 7-day retention the model
// offers 7d at most and refuses a 21d window.
func TestTrafficMapRetentionShortened(t *testing.T) {
	f := newTMFixtureWithRetention(t, 7*24*time.Hour)
	rec := f.do(t, http.MethodGet, "/api/v1/trafficmap?window=7d", f.token, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("window=7d: status %d: %s", rec.Code, rec.Body)
	}
	rec = f.do(t, http.MethodGet, "/api/v1/trafficmap?window=21d", f.token, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("window=21d over a 7d retention: status %d, want 400: %s", rec.Code, rec.Body)
	}
}

// TestRunServesTrafficMap starts the real server (run) and checks that it
// mounts the traffic map: the page and the frame need a session, the
// frame keeps its CSP, the modules and the model are reachable as the
// page needs them.
func TestRunServesTrafficMap(t *testing.T) {
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
	type result struct {
		code      int
		h         http.Header
		body      string
		connected bool
	}
	send := func(p, token, origin string) result {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "http://"+listen+p, nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := client.Do(req)
		if err != nil {
			return result{}
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return result{resp.StatusCode, resp.Header, string(b), true}
	}
	deadline := time.Now().Add(15 * time.Second)
	var r result
	for {
		if r = send("/traffic", token, ""); r.connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not come up (stderr: %s)", stderr.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if r.code != http.StatusOK || !strings.Contains(r.body, `src="/traffic/frame"`) {
		t.Errorf("GET /traffic as admin: status %d", r.code)
	}
	if csp := r.h.Get("Content-Security-Policy"); csp != swStrictCSP {
		t.Errorf("GET /traffic: CSP %q, want %q", csp, swStrictCSP)
	}
	if r = send("/traffic/frame", token, ""); r.code != http.StatusOK {
		t.Errorf("GET /traffic/frame as admin: status %d", r.code)
	}
	checkFrameCSP(t, "GET /traffic/frame", r.h.Get("Content-Security-Policy"))
	if r = send("/api/v1/trafficmap?window=24h", token, ""); r.code != http.StatusOK || !strings.HasPrefix(r.h.Get("Content-Type"), "application/json") {
		t.Errorf("GET model as admin: status %d type %q", r.code, r.h.Get("Content-Type"))
	}
	for _, p := range []string{"/traffic", "/traffic/frame", "/api/v1/trafficmap"} {
		if r = send(p, "", ""); r.code != http.StatusSeeOther || r.h.Get("Location") != "/login" {
			t.Errorf("GET %s without session: %d %q, want 303 to /login", p, r.code, r.h.Get("Location"))
		}
	}
	for _, name := range tmModules {
		r = send("/static/trafficmap/"+name, "", "null")
		if r.code != http.StatusOK || r.h.Get("Content-Type") != "text/javascript; charset=utf-8" || r.h.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("GET module %s without session: status %d type %q ACAO %q", name, r.code, r.h.Get("Content-Type"), r.h.Get("Access-Control-Allow-Origin"))
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

// TestTrafficChromeReadsLayoutCookies checks the layout data of the page.
func TestTrafficChromeReadsLayoutCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/traffic", nil)
	r.AddCookie(&http.Cookie{Name: themeCookie, Value: "dark"})
	r.AddCookie(&http.Cookie{Name: navCookie, Value: navCollapsed})
	if c := trafficChrome(r); c.Theme != "dark" || !c.NavCollapsed || !c.PVENav || !c.DeployEnabled {
		t.Errorf("chrome %+v", c)
	}
}
