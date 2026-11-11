// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the network device list and detail pages (ADR 0010, ND-19
// part 1). They cover: hostile device text rendered as escaped text,
// admin-only access, unknown device 404, staleness labels from the store's
// dataset state, the strict CSP on every page, MAC table paging bounds and
// deep links built from the registry's approved endpoints only.

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// netdevCSP is the strict CSP of internal/web/middleware, spelled out so a
// change of the header is noticed here too (ADR 0010 ND-19: the existing
// CSP applies unchanged).
const netdevCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

var netdevNow = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// fakeNetDevStore is an in-memory ui.NetDevStore.
type fakeNetDevStore struct {
	devices  []netdevinventory.Device
	datasets map[string]map[netdevinventory.Read]netdevinventory.Dataset
	facts    map[string]netdevcontract.Facts
	vlans    map[string][]netdevcontract.VLAN
	ports    map[string][]netdevcontract.Port
	macs     map[string][]netdevcontract.MACEntry
	lldp     map[string][]netdevcontract.LLDPNeighbor
	policy   map[string]netdevcontract.FirewallPolicy
	// macCalls records the (offset, limit) of MACEntries calls.
	macCalls [][2]int
	listErr  error
}

func newFakeNetDevStore() *fakeNetDevStore {
	return &fakeNetDevStore{
		datasets: map[string]map[netdevinventory.Read]netdevinventory.Dataset{},
		facts:    map[string]netdevcontract.Facts{},
		vlans:    map[string][]netdevcontract.VLAN{},
		ports:    map[string][]netdevcontract.Port{},
		macs:     map[string][]netdevcontract.MACEntry{},
		lldp:     map[string][]netdevcontract.LLDPNeighbor{},
		policy:   map[string]netdevcontract.FirewallPolicy{},
	}
}

func (f *fakeNetDevStore) ListDevices(_ context.Context, limit int) ([]netdevinventory.Device, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if len(f.devices) > limit {
		return f.devices[:limit], nil
	}
	return f.devices, nil
}

func (f *fakeNetDevStore) GetDevice(_ context.Context, id string) (netdevinventory.Device, error) {
	for _, d := range f.devices {
		if d.DeviceID == id {
			return d, nil
		}
	}
	return netdevinventory.Device{}, netdevinventory.ErrDeviceNotFound
}

func (f *fakeNetDevStore) GetDataset(_ context.Context, id string, read netdevinventory.Read) (netdevinventory.Dataset, error) {
	if ds, ok := f.datasets[id][read]; ok {
		return ds, nil
	}
	return netdevinventory.Dataset{}, netdevinventory.ErrDatasetNotFound
}

func (f *fakeNetDevStore) Facts(_ context.Context, id string) (netdevcontract.Facts, error) {
	if v, ok := f.facts[id]; ok {
		return v, nil
	}
	return netdevcontract.Facts{}, netdevinventory.ErrDatasetNotFound
}

func (f *fakeNetDevStore) VLANs(_ context.Context, id string) ([]netdevcontract.VLAN, error) {
	if v, ok := f.vlans[id]; ok {
		return v, nil
	}
	return nil, netdevinventory.ErrDatasetNotFound
}

func (f *fakeNetDevStore) Ports(_ context.Context, id string) ([]netdevcontract.Port, error) {
	if v, ok := f.ports[id]; ok {
		return v, nil
	}
	return nil, netdevinventory.ErrDatasetNotFound
}

func (f *fakeNetDevStore) MACEntries(_ context.Context, id string, offset, limit int) ([]netdevcontract.MACEntry, int, error) {
	f.macCalls = append(f.macCalls, [2]int{offset, limit})
	v, ok := f.macs[id]
	if !ok {
		return nil, 0, netdevinventory.ErrDatasetNotFound
	}
	if offset >= len(v) {
		return nil, len(v), nil
	}
	end := min(offset+limit, len(v))
	return v[offset:end], len(v), nil
}

func (f *fakeNetDevStore) LLDPNeighbors(_ context.Context, id string) ([]netdevcontract.LLDPNeighbor, error) {
	if v, ok := f.lldp[id]; ok {
		return v, nil
	}
	return nil, netdevinventory.ErrDatasetNotFound
}

func (f *fakeNetDevStore) FirewallPolicy(_ context.Context, id string) (netdevcontract.FirewallPolicy, error) {
	if v, ok := f.policy[id]; ok {
		return v, nil
	}
	return netdevcontract.FirewallPolicy{}, netdevinventory.ErrDatasetNotFound
}

func (f *fakeNetDevStore) setDataset(id string, read netdevinventory.Read, state netdevinventory.DatasetState, at time.Time) {
	if f.datasets[id] == nil {
		f.datasets[id] = map[netdevinventory.Read]netdevinventory.Dataset{}
	}
	f.datasets[id][read] = netdevinventory.Dataset{DeviceID: id, Read: read, ObservedAt: at, StoredAt: at, State: state, Current: true}
}

// netdevEnv is the UI with the netdev pages mounted behind the real auth
// and security middleware.
type netdevEnv struct {
	t        *testing.T
	srv      *httptest.Server
	store    *fakeNetDevStore
	registry []ui.NetDevRegistryEntry
	regErr   error
	admins   map[string]bool
	sessions *auth.Store
	cookie   *http.Cookie
}

func newNetDevEnv(t *testing.T) *netdevEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	e := &netdevEnv{t: t, store: newFakeNetDevStore(), admins: map[string]bool{"alice": true}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{PublicOrigin: pveOrigin, Log: log, Now: func() time.Time { return netdevNow }})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	pages, err := u.NetDevPages(ui.NetDevOptions{
		Store: e.store,
		Registry: func(context.Context) ([]ui.NetDevRegistryEntry, error) {
			return e.registry, e.regErr
		},
		IsAdmin: func(_ context.Context, user string) (bool, error) { return e.admins[user], nil },
	})
	if err != nil {
		t.Fatalf("NetDevPages: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", u.Handler())
	pages.Register(mux)
	e.sessions = auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: e.sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: pveOrigin}, a.Wrap(mux)))
	t.Cleanup(e.srv.Close)
	e.cookie = e.session("cred-alice", "alice")
	return e
}

func (e *netdevEnv) session(cred, user string) *http.Cookie {
	e.t.Helper()
	token, _, err := e.sessions.Create(context.Background(), cred, user)
	if err != nil {
		e.t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: token}
}

// getAs fetches path with cookie (nil: logged out) without following
// redirects.
func (e *netdevEnv) getAs(cookie *http.Cookie, path string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return res, string(body)
}

func (e *netdevEnv) get(path string) (int, string) {
	e.t.Helper()
	res, body := e.getAs(e.cookie, path)
	if got := res.Header.Get("Content-Security-Policy"); got != netdevCSP {
		e.t.Errorf("GET %s: CSP = %q, want %q", path, got, netdevCSP)
	}
	return res.StatusCode, body
}

// addCBS adds a fresh CBS switch with every dataset fresh.
func (e *netdevEnv) addCBS(id, label string) {
	e.store.devices = append(e.store.devices, netdevinventory.Device{DeviceID: id, Family: netdevcontract.FamilyCBS,
		Label: label, TrustGeneration: 3, LastSeen: netdevNow.Add(-5 * time.Minute), State: netdevinventory.DeviceFresh})
	for _, r := range []netdevinventory.Read{netdevinventory.ReadFacts, netdevinventory.ReadPorts, netdevinventory.ReadVLANs,
		netdevinventory.ReadMACTable, netdevinventory.ReadLLDPNeighbors} {
		e.store.setDataset(id, r, netdevinventory.StateFresh, netdevNow.Add(-5*time.Minute))
	}
}

// addPANOS adds a fresh PAN-OS firewall with every dataset fresh.
func (e *netdevEnv) addPANOS(id, label string) {
	e.store.devices = append(e.store.devices, netdevinventory.Device{DeviceID: id, Family: netdevcontract.FamilyPANOS,
		Label: label, TrustGeneration: 1, LastSeen: netdevNow.Add(-10 * time.Minute), State: netdevinventory.DeviceFresh})
	for _, r := range []netdevinventory.Read{netdevinventory.ReadFacts, netdevinventory.ReadFirewallPolicy, netdevinventory.ReadHitCounts} {
		e.store.setDataset(id, r, netdevinventory.StateFresh, netdevNow.Add(-10*time.Minute))
	}
}

// rlo is U+202E RIGHT-TO-LEFT OVERRIDE and replacement U+FFFD, built
// from code points so that the source itself holds no bidi control.
var (
	rlo         = string(rune(0x202e))
	replacement = string(rune(0xfffd))
)

// hostileStrings are device-supplied texts that must render as inert text.
var hostileStrings = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(2)>`,
	`' onmouseover='alert(3)`,
	"evil" + rlo + "gnp.exe",
	`javascript:alert(4)`,
}

func assertNoHostileMarkup(t *testing.T, body string) {
	t.Helper()
	// The texts may appear escaped (as inert text); never as markup.
	for _, bad := range []string{"<script>alert", "<img", "' onmouseover='", rlo, `href="javascript:`} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains unescaped hostile text %q", bad)
		}
	}
	if strings.Contains(body, "<iframe") || strings.Contains(body, "<frame") || strings.Contains(body, "<embed") || strings.Contains(body, "<object") {
		t.Error("page embeds content (iframe/frame/embed/object)")
	}
	if strings.Contains(body, "<style") || strings.Contains(body, " style=") || strings.Contains(body, " onclick=") {
		t.Error("page has inline style or event handler")
	}
	// Only the layout's external scripts: no inline <script> body.
	for _, part := range strings.Split(body, "<script")[1:] {
		head, _, _ := strings.Cut(part, ">")
		if !strings.Contains(head, `src="/static/`) {
			t.Errorf("inline script tag: <script%s>", head)
		}
	}
}

func TestNetDevHostileDeviceTextIsEscaped(t *testing.T) {
	e := newNetDevEnv(t)
	long := strings.Repeat("Ω<b>", 1024) // 5 KiB, multi-byte runes and markup
	for i, s := range hostileStrings {
		id := fmt.Sprintf("sw%d", i)
		e.addCBS(id, s)
		e.store.facts[id] = netdevcontract.Facts{Model: s, FirmwareVersion: s, Serial: s, Hostname: long}
		e.store.vlans[id] = []netdevcontract.VLAN{{ID: 10, Name: s}, {ID: 20, Name: long}}
		e.store.ports[id] = []netdevcontract.Port{{Name: s, AdminState: netdevcontract.LinkUp, OperState: netdevcontract.LinkDown,
			Mode: netdevcontract.ModeAccess, Description: long}}
		e.store.macs[id] = []netdevcontract.MACEntry{{VLAN: 10, MAC: "00:11:22:33:44:55", Port: s, Type: netdevcontract.MACDynamic}}
		e.store.lldp[id] = []netdevcontract.LLDPNeighbor{{LocalPort: s, ChassisID: s, PortID: long, SystemName: s, ManagementAddress: s}}
	}
	e.addPANOS("fw1", hostileStrings[0])
	e.store.policy["fw1"] = netdevcontract.FirewallPolicy{
		Zones:         []netdevcontract.Zone{{Name: hostileStrings[1], Interfaces: []string{hostileStrings[3]}}},
		Interfaces:    []netdevcontract.FirewallInterface{{Name: hostileStrings[2], Zone: hostileStrings[0], Addresses: []string{long}}},
		SecurityRules: []netdevcontract.SecurityRule{{Name: hostileStrings[0], Action: netdevcontract.ActionAllow}},
	}

	code, body := e.get("/netdev")
	if code != http.StatusOK {
		t.Fatalf("GET /netdev = %d", code)
	}
	assertNoHostileMarkup(t, body)
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("list does not show the hostile label as escaped text")
	}
	if !strings.Contains(body, "evil"+replacement+"gnp.exe") {
		t.Error("bidi override not replaced by a visible U+FFFD")
	}
	for _, id := range []string{"sw0", "sw1", "sw2", "sw3", "sw4", "fw1"} {
		code, body := e.get("/netdev/" + id)
		if code != http.StatusOK {
			t.Fatalf("GET /netdev/%s = %d", id, code)
		}
		assertNoHostileMarkup(t, body)
		if strings.Contains(body, strings.Repeat("Ω&lt;b&gt;", 200)) {
			t.Errorf("%s: 4 KiB device text not shortened", id)
		}
	}
	_, body = e.get("/netdev/sw0")
	if !strings.Contains(body, "Ω&lt;b&gt;") || !strings.Contains(body, "…") {
		t.Error("shortened long text missing or not marked with an ellipsis")
	}
}

func TestNetDevPagesNeedAdmin(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "Core")
	bob := e.session("cred-bob", "bob")
	for _, path := range []string{"/netdev", "/netdev/sw1", "/netdev/unknown", "/netdev/sw1?mac_page=2"} {
		res, body := e.getAs(bob, path)
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s as non-admin = %d, want 403", path, res.StatusCode)
		}
		if strings.Contains(body, "Core") {
			t.Errorf("GET %s as non-admin leaks device data", path)
		}
		if got := res.Header.Get("Content-Security-Policy"); got != netdevCSP {
			t.Errorf("GET %s as non-admin: CSP = %q", path, got)
		}
	}
	// Logged out: the auth layer redirects to the login page.
	res, _ := e.getAs(nil, "/netdev")
	if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
		t.Errorf("GET /netdev logged out = %d, want redirect", res.StatusCode)
	}
	// Only GET (and HEAD) are served.
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/netdev/sw1", strings.NewReader(""))
	req.Header.Set("Origin", pveOrigin)
	req.AddCookie(e.cookie)
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /netdev/sw1 = %d, want 405", res2.StatusCode)
	}
}

func TestNetDevAdminCheckErrorFailsClosed(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u, err := ui.New(ui.Options{PublicOrigin: pveOrigin, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeNetDevStore()
	if _, err := u.NetDevPages(ui.NetDevOptions{Store: store}); err == nil {
		t.Error("NetDevPages without IsAdmin accepted")
	}
	if _, err := u.NetDevPages(ui.NetDevOptions{IsAdmin: func(context.Context, string) (bool, error) { return true, nil }}); err == nil {
		t.Error("NetDevPages without Store accepted")
	}
	pages, err := u.NetDevPages(ui.NetDevOptions{Store: store,
		IsAdmin: func(context.Context, string) (bool, error) { return true, errors.New("role lookup failed") }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pages.Register(mux)
	// Without the auth layer there is no session: 403, never the page.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/netdev", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /netdev without session = %d, want 403", rec.Code)
	}
	sessions := auth.NewStore(db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), "cred", "alice")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/netdev", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	rec = httptest.NewRecorder()
	a.Wrap(mux).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /netdev with failing admin check = %d, want 403", rec.Code)
	}
}

func TestNetDevUnknownDeviceIs404(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "Core")
	for _, path := range []string{"/netdev/nope", "/netdev/UPPER", "/netdev/%3Cscript%3E", "/netdev/" + strings.Repeat("a", 65)} {
		code, body := e.get(path)
		if code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
		if strings.Contains(body, "<script>") {
			t.Errorf("GET %s reflects the ID unescaped", path)
		}
	}
}

func TestNetDevStoreErrorsDoNotLeak(t *testing.T) {
	e := newNetDevEnv(t)
	e.store.listErr = errors.New("sqlite: secret detail /var/lib/nebula")
	code, body := e.get("/netdev")
	if code != http.StatusOK {
		t.Fatalf("GET /netdev = %d", code)
	}
	if !strings.Contains(body, "Stored device inventory unavailable") {
		t.Error("store error not reported as unavailable")
	}
	if strings.Contains(body, "secret detail") {
		t.Error("store error detail leaked into the page")
	}
}

func TestNetDevStaleBadges(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "Core")
	staleAt := netdevNow.Add(-2 * time.Hour)
	e.store.setDataset("sw1", netdevinventory.ReadMACTable, netdevinventory.StateStale, staleAt)
	e.store.setDataset("sw1", netdevinventory.ReadVLANs, netdevinventory.StatePartial, netdevNow.Add(-3*time.Minute))
	delete(e.store.datasets["sw1"], netdevinventory.ReadLLDPNeighbors)
	e.store.devices[0].State = netdevinventory.DeviceStale

	_, list := e.get("/netdev")
	for _, want := range []string{
		`<span class="badge badge--warning">mac_table: stale</span>`,
		`<span class="badge badge--warning">vlans: partial</span>`,
		`<span class="badge badge--ok">facts: fresh</span>`,
		`<span class="badge badge--unknown">lldp_neighbors: never read</span>`,
		`<span class="badge badge--warning">stale</span>`, // the device itself
	} {
		if !strings.Contains(list, want) {
			t.Errorf("list misses %s", want)
		}
	}
	// PAN-OS reads are not listed for a switch.
	if strings.Contains(list, "firewall_policy") {
		t.Error("switch row lists a PAN-OS dataset")
	}

	_, detail := e.get("/netdev/sw1")
	if !strings.Contains(detail, `<span class="badge badge--warning">stale</span>`) {
		t.Error("detail has no stale badge")
	}
	if !strings.Contains(detail, `<time datetime="`+staleAt.Format(time.RFC3339)+`">`) {
		t.Error("detail does not show the stale dataset's observed_at")
	}
	if !strings.Contains(detail, "(2h ago)") {
		t.Error("detail does not show the stale dataset's age")
	}
}

func TestNetDevMACTablePaging(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "Core")
	var macs []netdevcontract.MACEntry
	for i := range 450 {
		macs = append(macs, netdevcontract.MACEntry{VLAN: 1, MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256), Port: "gi1", Type: netdevcontract.MACDynamic})
	}
	e.store.macs["sw1"] = macs

	_, body := e.get("/netdev/sw1")
	if !strings.Contains(body, "02:00:00:00:00:00") || !strings.Contains(body, "02:00:00:00:00:c7") {
		t.Error("page 1 misses its first or last entry")
	}
	if strings.Contains(body, "02:00:00:00:00:c8") {
		t.Error("page 1 shows more than 200 entries")
	}
	if !strings.Contains(body, `href="/netdev/sw1?mac_page=2#mac"`) || strings.Contains(body, "mac_page=0") {
		t.Error("page 1 next/previous links wrong")
	}
	if !strings.Contains(body, "page 1 of 3") || !strings.Contains(body, "450 entries") {
		t.Error("page 1 does not show the page count and total")
	}

	_, body = e.get("/netdev/sw1?mac_page=3")
	if !strings.Contains(body, "02:00:00:00:01:90") || !strings.Contains(body, "02:00:00:00:01:c1") {
		t.Error("page 3 misses entries 400..449")
	}
	if strings.Contains(body, "mac_page=4") || !strings.Contains(body, `href="/netdev/sw1?mac_page=2#mac"`) {
		t.Error("page 3 next/previous links wrong")
	}

	for _, q := range []string{"0", "-1", "abc", "1e3", "+2", "99999999999999999999", "", "2&mac_page=3"} {
		code, _ := e.get("/netdev/sw1?mac_page=" + q)
		want := http.StatusBadRequest
		if q == "" {
			want = http.StatusOK
		}
		if code != want {
			t.Errorf("mac_page=%q: %d, want %d", q, code, want)
		}
	}
	if code, _ := e.get("/netdev/sw1?mac_page=4"); code != http.StatusNotFound {
		t.Errorf("mac_page past the last page = %d, want 404", code)
	}
	for _, c := range e.store.macCalls {
		if c[1] != 200 || c[0] < 0 || c[0] > netdevcontract.MaxMACEntriesPerDevice {
			t.Errorf("MACEntries called with offset %d limit %d", c[0], c[1])
		}
	}
}

func TestNetDevDeepLinksFromRegistryOnly(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw-https", "A")
	e.addCBS("sw-http", "B")
	e.addCBS("sw-none", "C")
	e.addPANOS("fw1", "FW")
	e.addPANOS("fw-bad", "FW bad")
	e.addCBS("sw-unreg", "D")
	e.addCBS("sw-ftp", "E")
	e.store.facts["sw-none"] = netdevcontract.Facts{Model: "x", ManagementAddresses: []string{"https://evil.example"}}
	e.registry = []ui.NetDevRegistryEntry{
		{DeviceID: "sw-https", Name: "A", Family: netdevcontract.FamilyCBS, WebUIScheme: "https",
			Endpoints: []netdevcontract.Endpoint{{Address: "10.0.0.2", Port: 22}}, TrustGeneration: 3},
		{DeviceID: "sw-http", Name: "B", Family: netdevcontract.FamilyCBS, WebUIScheme: "http",
			Endpoints: []netdevcontract.Endpoint{{Address: "fd00::5", Port: 22}}, TrustGeneration: 3},
		{DeviceID: "sw-none", Name: "C", Family: netdevcontract.FamilyCBS,
			Endpoints: []netdevcontract.Endpoint{{Address: "10.0.0.4", Port: 22}}, TrustGeneration: 3},
		{DeviceID: "fw1", Name: "FW", Family: netdevcontract.FamilyPANOS,
			Endpoints: []netdevcontract.Endpoint{{Address: "192.168.1.1", Port: 443}, {Address: "192.168.2.1", Port: 443}}, TrustGeneration: 1},
		// A public address is never an approved endpoint: no link.
		{DeviceID: "fw-bad", Name: "FW bad", Family: netdevcontract.FamilyPANOS,
			Endpoints: []netdevcontract.Endpoint{{Address: "8.8.8.8", Port: 443}}, TrustGeneration: 1},
		{DeviceID: "sw-ftp", Name: "E", Family: netdevcontract.FamilyCBS, WebUIScheme: "javascript",
			Endpoints: []netdevcontract.Endpoint{{Address: "10.0.0.9", Port: 22}}, TrustGeneration: 3},
	}
	want := map[string]string{
		"sw-https": `<a href="https://10.0.0.2/" target="_blank" rel="noopener noreferrer">`,
		"sw-http":  `<a href="http://[fd00::5]/" target="_blank" rel="noopener noreferrer">`,
		"fw1":      `<a href="https://192.168.1.1/" target="_blank" rel="noopener noreferrer">`,
	}
	_, list := e.get("/netdev")
	for id, link := range want {
		if !strings.Contains(list, link) {
			t.Errorf("list misses deep link for %s: %s", id, link)
		}
	}
	for _, id := range []string{"sw-none", "fw-bad", "sw-unreg", "sw-ftp"} {
		_, body := e.get("/netdev/" + id)
		if strings.Contains(body, `target="_blank"`) {
			t.Errorf("%s: deep link rendered without an approved endpoint and scheme", id)
		}
	}
	if strings.Contains(list, "evil.example") && strings.Contains(list, `href="https://evil`) {
		t.Error("deep link built from device-reported address")
	}
	for id, link := range want {
		_, body := e.get("/netdev/" + id)
		if !strings.Contains(body, link) {
			t.Errorf("detail of %s misses deep link %s", id, link)
		}
	}
	// Every external link opens without opener and referrer.
	for _, part := range strings.Split(list, `<a href="http`)[1:] {
		tag, _, _ := strings.Cut(part, ">")
		if !strings.Contains(tag, `rel="noopener noreferrer"`) {
			t.Errorf("external link without rel=noopener noreferrer: %s", tag)
		}
	}
	// The registry being unavailable hides every deep link.
	e.regErr = errors.New("registry down")
	_, list = e.get("/netdev")
	if strings.Contains(list, `target="_blank"`) {
		t.Error("deep links rendered although the registry is unavailable")
	}
}

func TestNetDevListShowsRegistryEndpointAndTrust(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "stored label")
	e.registry = []ui.NetDevRegistryEntry{{DeviceID: "sw1", Name: "Core switch", Family: netdevcontract.FamilyCBS,
		Endpoints: []netdevcontract.Endpoint{{Address: "10.0.0.2", Port: 22}}, TrustGeneration: 3}}
	_, body := e.get("/netdev")
	for _, want := range []string{"Core switch", "cbs", "10.0.0.2:22", `href="/netdev/sw1"`, ">3<"} {
		if !strings.Contains(body, want) {
			t.Errorf("list misses %q", want)
		}
	}
	// A trust generation mismatch between registry and store is flagged.
	e.registry[0].TrustGeneration = 4
	_, body = e.get("/netdev")
	if !strings.Contains(body, "re-pinned") {
		t.Error("trust generation mismatch not flagged")
	}
}

func TestNetDevDetailShowsDatasets(t *testing.T) {
	e := newNetDevEnv(t)
	e.addCBS("sw1", "Core")
	e.store.facts["sw1"] = netdevcontract.Facts{Model: "CBS350-24P", FirmwareVersion: "3.4.1.3", Serial: "SN123"}
	e.store.vlans["sw1"] = []netdevcontract.VLAN{{ID: 10, Name: "servers"}}
	e.store.ports["sw1"] = []netdevcontract.Port{{Name: "gi1/0/1", AdminState: netdevcontract.LinkUp, OperState: netdevcontract.LinkUp, Mode: netdevcontract.ModeTrunk}}
	e.store.lldp["sw1"] = []netdevcontract.LLDPNeighbor{{LocalPort: "gi1/0/1", ChassisID: "aa:bb", PortID: "eth0", SystemName: "nas"}}
	_, body := e.get("/netdev/sw1")
	for _, want := range []string{"CBS350-24P", "3.4.1.3", "SN123", "servers", "gi1/0/1", "trunk", "nas", "aa:bb"} {
		if !strings.Contains(body, want) {
			t.Errorf("CBS detail misses %q", want)
		}
	}
	if strings.Contains(body, "Security rules") {
		t.Error("CBS detail shows the PAN-OS section")
	}

	e.addPANOS("fw1", "Edge")
	e.store.facts["fw1"] = netdevcontract.Facts{Model: "PA-440", FirmwareVersion: "11.1.4"}
	e.store.policy["fw1"] = netdevcontract.FirewallPolicy{
		Zones:         []netdevcontract.Zone{{Name: "trust", Interfaces: []string{"ethernet1/2"}}, {Name: "untrust"}},
		Interfaces:    []netdevcontract.FirewallInterface{{Name: "ethernet1/2", Zone: "trust", Addresses: []string{"10.0.0.1/24"}}},
		SecurityRules: make([]netdevcontract.SecurityRule, 7),
		NATRules:      make([]netdevcontract.NATRule, 2),
		Addresses:     make([]netdevcontract.AddressObject, 5),
		AddressGroups: make([]netdevcontract.Group, 1),
		Services:      make([]netdevcontract.ServiceObject, 3),
		ServiceGroups: make([]netdevcontract.Group, 1),
	}
	_, body = e.get("/netdev/fw1")
	for _, want := range []string{"PA-440", "11.1.4", "trust", "untrust", "ethernet1/2", "10.0.0.1/24",
		"Security rules</th><td>7", "NAT rules</th><td>2", "Objects</th><td>10", `href="/netdev/fw1/firewall"`} {
		if !strings.Contains(body, want) {
			t.Errorf("PAN-OS detail misses %q", want)
		}
	}
	if strings.Contains(body, "MAC table") {
		t.Error("PAN-OS detail shows the switch MAC table")
	}
	if strings.Contains(body, "not available yet") {
		t.Error("PAN-OS detail still shows the ND-19 firewall view placeholder")
	}
}
