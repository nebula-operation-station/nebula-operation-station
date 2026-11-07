// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for linking PVE guests to managed hosts on the PVE detail page
// (ADR 0006 "explicit reviewed link", P1-12). They cover: suggestions are
// shown but never link by themselves, links and unlinks need the click
// (a POST through the full middleware chain with the right Origin, a web
// session and an open privileged session), every change is audited with
// the logged-in user, conflicts and VMID reuse are shown, hostile PVE and
// inventory text stays escaped, and a link shows the host in the chart.

package ui_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const linkRemote = "remote-a"

// linkStatus is a fake executor: whether a privileged session is open and
// until when (the expiry CompletePrivilegedSession reports too), or an
// error.
type linkStatus struct {
	mu     sync.Mutex
	active bool
	expiry int64
	err    error
}

func (s *linkStatus) GetStatus(context.Context, *pb.GetStatusRequest, ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	res := &pb.GetStatusResponse{PrivilegedSessionActive: s.active}
	if s.active {
		res.PrivilegedSessionExpiryUnix = s.expiry
	}
	return res, nil
}

func (s *linkStatus) set(active bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active, s.err = active, err
}

// setExpiry changes the executor's privileged session expiry, as a session
// opened or reopened outside the web would.
func (s *linkStatus) setExpiry(exp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expiry = exp
}

// linkExec is the login executor of the link tests: a privileged session
// completes with the expiry linkStatus reports.
type linkExec struct {
	pveFakeExec
	status *linkStatus
}

func (x linkExec) CompletePrivilegedSession(context.Context, *pb.CompletePrivilegedSessionRequest, ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	x.status.mu.Lock()
	defer x.status.mu.Unlock()
	x.status.active = true
	return &pb.CompletePrivilegedSessionResponse{SessionExpiryUnix: x.status.expiry}, nil
}

// Lock succeeds without touching linkStatus, so a test can check that a web
// lock ends the holder even while the reported status is stale.
func (linkExec) Lock(context.Context, *pb.LockRequest, ...grpc.CallOption) (*pb.LockResponse, error) {
	return &pb.LockResponse{}, nil
}

// linkClock is the web session clock of the link tests.
type linkClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *linkClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *linkClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// lockedBuffer is a log sink safe for the server goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// linkEnv serves the UI behind the real middleware and login chain, backed
// by real pveinventory, inventory and IPAM stores on one server DB.
type linkEnv struct {
	t        *testing.T
	srv      *httptest.Server
	pve      *pveinventory.Store
	inv      *inventory.Store
	ipam     *ipam.Store
	sessions *auth.Store
	status   *linkStatus
	clk      *linkClock
	logs     *lockedBuffer
	// cookie is alice's web session, which opened the privileged session.
	cookie *http.Cookie
}

func newLinkEnv(t *testing.T) *linkEnv {
	t.Helper()
	return newLinkEnvWith(t, nil)
}

// newLinkEnvWith is newLinkEnv with the PVE store the UI sees wrapped by
// wrap (nil: the real store).
func newLinkEnvWith(t *testing.T, wrap func(*pveinventory.Store) ui.PVEStore) *linkEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &linkClock{t: time.Now()}
	e := &linkEnv{
		t: t, pve: pveinventory.New(db), inv: inventory.New(db), ipam: ipam.New(db, nil),
		sessions: auth.NewStore(db, clk.now), clk: clk,
		status: &linkStatus{expiry: clk.now().Add(15 * time.Minute).Unix()}, logs: &lockedBuffer{},
	}
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	var pveStore ui.PVEStore = e.pve
	if wrap != nil {
		pveStore = wrap(e.pve)
	}
	u, err := ui.New(ui.Options{
		PublicOrigin: pveOrigin,
		Log:          log,
		Status:       e.status,
		Inventory:    e.inv,
		Hosts:        func(ctx context.Context) ([]inventory.Host, error) { return e.inv.List(ctx) },
		PVE:          pveStore,
		PVEChart:     func(ctx context.Context) (pveinventory.Tree, error) { return e.pve.ChartTree(ctx, time.Now()) },
		PVERemotes: func(context.Context) ([]ui.PVERemoteMeta, error) {
			return []ui.PVERemoteMeta{{RemoteID: linkRemote, Name: "Lab", Kind: string(pvecontract.KindStandalone),
				TrustPin: pvePin(0), TrustGeneration: 1, State: "active"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	a, err := auth.New(auth.Options{Executor: linkExec{status: e.status}, Sessions: e.sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: pveOrigin}, a.Wrap(u.Handler())))
	t.Cleanup(e.srv.Close)
	e.cookie = e.session("cred-alice", "alice")
	e.openPrivileged(e.cookie)
	seedRemote(t, e.pve, pvecontract.Remote{RemoteID: linkRemote, Name: "Lab", Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "pve1.lab", Port: 8006}},
		TrustPin:  pvePin(0), TrustGeneration: 1})
	return e
}

// session opens a web session for credential cred of user.
func (e *linkEnv) session(cred, user string) *http.Cookie {
	e.t.Helper()
	token, _, err := e.sessions.Create(context.Background(), cred, user)
	if err != nil {
		e.t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: token}
}

// postJSON sends a JSON POST with the right Origin from the web session c.
func (e *linkEnv) postJSON(path, body string, c *http.Cookie) int {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", pveOrigin)
	req.AddCookie(c)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// openPrivileged opens the executor privileged session from the web
// session c (POST /privileged/finish); c becomes its holder.
func (e *linkEnv) openPrivileged(c *http.Cookie) {
	e.t.Helper()
	if code := e.postJSON("/privileged/finish", `{"assertion":{"id":"k"}}`, c); code != http.StatusOK {
		e.t.Fatalf("privileged finish = %d", code)
	}
}

// linkAs and unlinkAs post a link or unlink from the web session c.
func (e *linkEnv) linkAs(c *http.Cookie, vmid, gen, host string) (int, string) {
	e.t.Helper()
	code, body, _ := e.do(http.MethodPost, "/pve/"+linkRemote+"/links", pveOrigin, c,
		url.Values{"vmid": {vmid}, "generation": {gen}, "host": {host}})
	return code, body
}

func (e *linkEnv) unlinkAs(c *http.Cookie, vmid, gen, reason string) (int, string) {
	e.t.Helper()
	code, body, _ := e.do(http.MethodPost, "/pve/"+linkRemote+"/links/remove", pveOrigin, c,
		url.Values{"vmid": {vmid}, "generation": {gen}, "reason": {reason}})
	return code, body
}

// guests stores one observation with the given guests.
func (e *linkEnv) guests(gen uint64, gs ...pvecontract.GuestObservation) {
	e.t.Helper()
	obs := newPVEObs(linkRemote, time.Now())
	obs.CollectionGeneration = gen
	obs.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{pveNodeObs("pve1", pvecontract.NodeOnline)})
	obs.Guests = pvecontract.AvailableDataset(gs)
	seedObs(e.t, e.pve, obs)
}

func (e *linkEnv) host(id, name, addr string) {
	e.t.Helper()
	if _, err := e.inv.Create(context.Background(), inventory.Host{
		ID: id, DisplayName: name, Environment: inventory.EnvProd, Criticality: inventory.CriticalityLow,
		Endpoints: []inventory.Endpoint{{Address: addr}},
	}, inventory.CreateOptions{}); err != nil {
		e.t.Fatalf("create host %s: %v", id, err)
	}
}

// do sends one request; origin "" omits the Origin header and a nil
// cookie sends no session.
func (e *linkEnv) do(method, path, origin string, cookie *http.Cookie, form url.Values) (int, string, http.Header) {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return res.StatusCode, string(b), res.Header
}

func (e *linkEnv) page() string {
	e.t.Helper()
	code, body, _ := e.do(http.MethodGet, "/pve/"+linkRemote, "", e.cookie, nil)
	if code != http.StatusOK {
		e.t.Fatalf("GET /pve/%s = %d\n%s", linkRemote, code, body)
	}
	return body
}

func (e *linkEnv) link(vmid, gen, host string, extra ...string) (int, string, http.Header) {
	e.t.Helper()
	f := url.Values{"vmid": {vmid}, "generation": {gen}, "host": {host}}
	for i := 0; i+1 < len(extra); i += 2 {
		f.Set(extra[i], extra[i+1])
	}
	return e.do(http.MethodPost, "/pve/"+linkRemote+"/links", pveOrigin, e.cookie, f)
}

func (e *linkEnv) unlink(vmid, gen, reason string) (int, string, http.Header) {
	e.t.Helper()
	f := url.Values{"vmid": {vmid}, "generation": {gen}, "reason": {reason}}
	return e.do(http.MethodPost, "/pve/"+linkRemote+"/links/remove", pveOrigin, e.cookie, f)
}

func agentGuest(vmid, gen uint64, name, mac, ip string) pvecontract.GuestObservation {
	g := pveGuestObs(vmid, pvecontract.GuestQEMU, "pve1", name, pvecontract.GuestRunning)
	g.Generation = gen
	g.Interfaces = pvecontract.AvailableDataset([]pvecontract.GuestInterface{
		{Name: "net0", MAC: mac, Bridge: "vmbr0", IPs: []string{ip + "/24"}, Source: pvecontract.SourceQEMUAgent},
	})
	return g
}

// TestPVEGuestSuggestionsNeverLink checks that the page shows the
// candidates with their match kind and a "Verknüpfen" button, and that
// rendering it creates no link.
func TestPVEGuestSuggestionsNeverLink(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-web", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")
	e.host("db1", "DB one", "10.77.10.250")
	if err := e.ipam.SaveAsset(context.Background(), ipam.Asset{
		ID: "asset-1", Name: "db1", Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:01",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.10.250")}, HostID: "db1",
	}); err != nil {
		t.Fatalf("SaveAsset: %v", err)
	}

	body := e.page()
	for _, want := range []string{
		"Web one", "DB one",
		">MAC<", ">POSSIBLE MATCH<",
		`action="/pve/remote-a/links"`,
		`name="host" value="web1"`, `name="host" value="db1"`,
		"Verknüpfen",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("guest view misses %q", want)
		}
	}
	if _, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("rendering suggestions created a link: %v", err)
	}
	if strings.Contains(e.logs.String(), "pve_guest_linked") {
		t.Errorf("rendering suggestions wrote a link audit line")
	}
}

// TestPVEGuestLinkAndUnlinkAreAudited links a guest with the click, checks
// the page shows host, since and by, then unlinks it with a reason.
func TestPVEGuestLinkAndUnlinkAreAudited(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-web", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")

	code, body, hdr := e.link("101", "1", "web1")
	if code != http.StatusSeeOther {
		t.Fatalf("link = %d, want 303\n%s", code, body)
	}
	if loc := hdr.Get("Location"); loc != "/pve/remote-a#guest-101" {
		t.Errorf("link redirect = %q", loc)
	}
	l, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1)
	if err != nil || l.HostID != "web1" || l.CreatedBy != "alice" {
		t.Fatalf("link = %+v, %v; want web1 by alice", l, err)
	}
	logs := e.logs.String()
	for _, want := range []string{"kind=pve_guest_linked", "remote=remote-a", "vmid=101", "generation=1", "host=web1", "user=alice"} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit line misses %q:\n%s", want, logs)
		}
	}

	page := e.page()
	for _, want := range []string{"Linked to", "Web one", "web1", "by alice", `action="/pve/remote-a/links/remove"`, "Lösen", `name="reason"`} {
		if !strings.Contains(page, want) {
			t.Errorf("linked guest view misses %q", want)
		}
	}
	if strings.Contains(page, `name="host" value="web1"`) {
		t.Errorf("a linked guest still offers link buttons")
	}

	code, body, _ = e.unlink("101", "1", "")
	if code != http.StatusBadRequest {
		t.Errorf("unlink without reason = %d, want 400\n%s", code, body)
	}
	code, body, _ = e.unlink("101", "1", "wrong host")
	if code != http.StatusSeeOther {
		t.Fatalf("unlink = %d, want 303\n%s", code, body)
	}
	if _, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("link still active after unlink: %v", err)
	}
	hist, err := e.pve.LinkHistory(context.Background(), linkRemote, 101, 1)
	if err != nil || len(hist) != 1 || hist[0].UnlinkReason != "wrong host" {
		t.Fatalf("history = %+v, %v", hist, err)
	}
	logs = e.logs.String()
	for _, want := range []string{"kind=pve_guest_unlinked", `reason="wrong host"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("unlink audit misses %q:\n%s", want, logs)
		}
	}
}

// TestPVEGuestLinkRejections covers the refusals: no Origin (CSRF), a
// foreign Origin, no web session, no privileged session (not admin), the
// executor status unreadable, malformed fields, unknown targets and
// duplicates. None of them creates a link.
func TestPVEGuestLinkRejections(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-web", "aa:bb:cc:dd:ee:01", "10.77.10.101"),
		agentGuest(102, 1, "vm-other", "aa:bb:cc:dd:ee:02", "10.77.10.102"))
	e.host("web1", "Web one", "10.77.10.101")
	form := url.Values{"vmid": {"101"}, "generation": {"1"}, "host": {"web1"}}
	path := "/pve/" + linkRemote + "/links"

	for _, tc := range []struct {
		name   string
		origin string
		cookie *http.Cookie
		want   int
	}{
		{"no origin", "", e.cookie, http.StatusForbidden},
		{"null origin", "null", e.cookie, http.StatusForbidden},
		{"foreign origin", "https://evil.example.org", e.cookie, http.StatusForbidden},
		{"no session", pveOrigin, nil, http.StatusUnauthorized},
	} {
		if code, body, _ := e.do(http.MethodPost, path, tc.origin, tc.cookie, form); code != tc.want {
			t.Errorf("%s: link = %d, want %d\n%s", tc.name, code, tc.want, body)
		}
		if code, body, _ := e.do(http.MethodPost, path+"/remove", tc.origin, tc.cookie,
			url.Values{"vmid": {"101"}, "generation": {"1"}, "reason": {"x"}}); code != tc.want {
			t.Errorf("%s: unlink = %d, want %d\n%s", tc.name, code, tc.want, body)
		}
	}

	e.status.set(false, nil)
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusForbidden || !strings.Contains(body, "privileged session") {
		t.Errorf("not admin: link = %d %q, want 403 naming the privileged session", code, body)
	}
	if code, _, _ := e.unlink("101", "1", "x"); code != http.StatusForbidden {
		t.Errorf("not admin: unlink = %d, want 403", code)
	}
	e.status.set(false, errors.New("executor down"))
	if code, _, _ := e.link("101", "1", "web1"); code != http.StatusForbidden {
		t.Errorf("status unreadable: link = %d, want 403 (fail closed)", code)
	}
	e.status.set(true, nil)

	for _, tc := range []struct {
		name            string
		vmid, gen, host string
		want            int
	}{
		{"vmid not a number", "x", "1", "web1", http.StatusBadRequest},
		{"generation missing", "101", "", "web1", http.StatusBadRequest},
		{"host malformed", "101", "1", "<script>", http.StatusBadRequest},
		{"host unknown", "101", "1", "nope", http.StatusNotFound},
		{"guest unknown", "999", "1", "web1", http.StatusNotFound},
		{"stale generation", "101", "7", "web1", http.StatusNotFound},
	} {
		if code, body, _ := e.link(tc.vmid, tc.gen, tc.host); code != tc.want {
			t.Errorf("%s: link = %d, want %d\n%s", tc.name, code, tc.want, body)
		}
	}
	if code, body, _ := e.unlink("101", "1", strings.Repeat("x", pveinventory.MaxUnlinkReasonLen+1)); code != http.StatusBadRequest {
		t.Errorf("long reason: unlink = %d, want 400\n%s", code, body)
	}
	if code, body, _ := e.unlink("101", "1", "bad\x00reason"); code != http.StatusBadRequest {
		t.Errorf("control char reason: unlink = %d, want 400\n%s", code, body)
	}
	if code, body, _ := e.unlink("101", "1", "nothing linked"); code != http.StatusNotFound {
		t.Errorf("unlink without link = %d, want 404\n%s", code, body)
	}
	if code, body, _ := e.do(http.MethodPost, "/pve/unknown-remote/links", pveOrigin, e.cookie, form); code != http.StatusNotFound {
		t.Errorf("unknown remote = %d, want 404\n%s", code, body)
	}
	if _, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("a rejected request created a link: %v", err)
	}
	if strings.Contains(e.logs.String(), "pve_guest_linked") {
		t.Errorf("a rejected request wrote a link audit line")
	}

	// Duplicates: the guest is linked, and the host cannot be linked to a
	// second guest.
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusConflict {
		t.Errorf("second link of the guest = %d, want 409\n%s", code, body)
	}
	if code, body, _ := e.link("102", "1", "web1"); code != http.StatusConflict {
		t.Errorf("host linked to a second guest = %d, want 409\n%s", code, body)
	}
}

// TestPVEGuestLinkConflictShownAndConfirmed checks that a cloned MAC and an
// IP on two managed hosts are shown, and that linking a conflicting
// candidate needs the explicit review confirmation.
func TestPVEGuestLinkConflictShownAndConfirmed(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"),
		agentGuest(102, 1, "vm-b", "aa:bb:cc:dd:ee:01", "10.77.10.120"))
	e.host("web1", "Web one", "10.77.10.101")
	e.host("web2", "Web two", "10.77.10.101")

	body := e.page()
	for _, want := range []string{
		"conflict",
		"MAC aa:bb:cc:dd:ee:01 is present on this guest and on guest 102 (gen 1)",
		"IP 10.77.10.101 is an endpoint of 2 managed hosts",
		`name="confirm_conflict"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("conflict view misses %q", want)
		}
	}
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusConflict || !strings.Contains(body, "conflict") {
		t.Errorf("conflicting link without confirmation = %d %q, want 409", code, body)
	}
	if _, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("unconfirmed conflicting link was created: %v", err)
	}
	if code, body, _ := e.link("101", "1", "web1", "confirm_conflict", "1"); code != http.StatusSeeOther {
		t.Fatalf("confirmed link = %d\n%s", code, body)
	}
	if !strings.Contains(e.logs.String(), "conflict_confirmed=true") {
		t.Errorf("audit line does not record the confirmed conflict:\n%s", e.logs.String())
	}
}

// TestPVEGuestLinkHostileTextEscaped checks that hostile guest names and
// host display names are rendered as text.
func TestPVEGuestLinkHostileTextEscaped(t *testing.T) {
	e := newLinkEnv(t)
	const hostileGuest = `<script>alert(1)</script>`
	const hostileHost = `<img src=x onerror=alert(2)>`
	e.guests(1, agentGuest(101, 1, hostileGuest, "aa:bb:cc:dd:ee:01", "10.77.10.101"),
		agentGuest(102, 1, "vm-two", "aa:bb:cc:dd:ee:02", "10.77.10.102"))
	e.host("web1", hostileHost, "10.77.10.101")
	e.host("web2", hostileHost, "10.77.10.102")
	if code, body, _ := e.link("102", "1", "web2"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	body := e.page()
	for _, bad := range []string{hostileGuest, hostileHost} {
		if strings.Contains(body, bad) {
			t.Errorf("hostile text rendered raw: %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(2)&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("escaped text %q missing", want)
		}
	}
}

// TestPVEGuestVMIDReuseNoticeShown checks that a link of an older
// incarnation of a reused VMID is shown as a notice on the new guest,
// never applied to it, and can be released with "Lösen".
func TestPVEGuestVMIDReuseNoticeShown(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-old", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	e.guests(2, agentGuest(101, 2, "vm-new", "aa:bb:cc:dd:ee:09", "10.77.10.101"))

	body := e.page()
	for _, want := range []string{
		"VMID 101 was reused",
		"incarnation 1",
		"incarnation 2",
		`name="generation" value="1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("reuse view misses %q", want)
		}
	}
	if strings.Contains(body, "Linked to") {
		t.Errorf("the old link is shown as the new guest's link")
	}
	if _, err := e.pve.GetLink(context.Background(), linkRemote, 101, 2); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("new incarnation linked automatically: %v", err)
	}
	if code, body, _ := e.unlink("101", "1", "vmid reused"); code != http.StatusSeeOther {
		t.Fatalf("unlink old incarnation = %d\n%s", code, body)
	}
	if strings.Contains(e.page(), "VMID 101 was reused") {
		t.Errorf("reuse notice still shown after the old link was released")
	}
}

// TestPVEGuestLinkShowsHostInChart checks that a link created on the PVE
// page shows the managed host inside the guest box of the inventory chart.
func TestPVEGuestLinkShowsHostInChart(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-web", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")

	chart := func() string {
		code, body, _ := e.do(http.MethodGet, "/inventory/chart", "", e.cookie, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /inventory/chart = %d\n%s", code, body)
		}
		return body
	}
	if box := guestBox(t, chart(), "vm-web"); strings.Contains(box, "web1") {
		t.Fatalf("unlinked guest box names a host:\n%s", box)
	}
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	box := guestBox(t, chart(), "vm-web")
	if !strings.Contains(box, `class="chart__ghost"`) || !strings.Contains(box, "web1") {
		t.Errorf("linked guest box does not show the host:\n%s", box)
	}
}

// TestPVEGuestLinkOnlyByPrivilegedHolder checks that the executor-wide
// privileged session lets only the web session that opened it link and
// unlink: another logged-in user, a second web session of the same
// credential, a session reopened outside the web, an expired one and one
// ended by a web lock are refused with 403 and change nothing.
func TestPVEGuestLinkOnlyByPrivilegedHolder(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-web", "aa:bb:cc:dd:ee:01", "10.77.10.101"),
		agentGuest(102, 1, "vm-db", "aa:bb:cc:dd:ee:02", "10.77.10.102"))
	e.host("web1", "Web one", "10.77.10.101")
	e.host("db1", "DB one", "10.77.10.102")
	bob := e.session("cred-bob", "bob")
	alice2 := e.session("cred-alice", "alice")

	refused := func(name string, c *http.Cookie) {
		t.Helper()
		if code, body := e.linkAs(c, "102", "1", "db1"); code != http.StatusForbidden || !strings.Contains(body, "privileged session") {
			t.Errorf("%s: link = %d %q, want 403 naming the privileged session", name, code, body)
		}
		if code, body := e.unlinkAs(c, "101", "1", "x"); code != http.StatusForbidden {
			t.Errorf("%s: unlink = %d, want 403\n%s", name, code, body)
		}
	}

	// Alice opened the privileged session: she links.
	if code, body := e.linkAs(e.cookie, "101", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("holder: link = %d, want 303\n%s", code, body)
	}
	// Bob is logged in while alice holds the session: refused, and his page
	// does not offer the link controls.
	refused("other user", bob)
	code, body, _ := e.do(http.MethodGet, "/pve/"+linkRemote, "", bob, nil)
	if code != http.StatusOK || !strings.Contains(body, "Linking and releasing need an open privileged session.") {
		t.Errorf("other user's page = %d, want the not-admin note", code)
	}
	if !strings.Contains(e.page(), `action="/pve/remote-a/links"`) {
		t.Errorf("holder's page does not offer the link controls")
	}
	// A second web session of alice's credential did not open it.
	refused("second session of the holder's credential", alice2)

	// The executor session was reopened outside the web (new expiry).
	exp := e.status.expiry
	e.status.setExpiry(exp + 60)
	refused("session reopened elsewhere", e.cookie)
	e.status.setExpiry(exp)
	if code, body := e.unlinkAs(e.cookie, "101", "1", "check"); code != http.StatusSeeOther {
		t.Fatalf("holder: unlink = %d, want 303\n%s", code, body)
	}

	// Bob opens his own privileged session: now he holds it, alice does not.
	e.status.setExpiry(exp + 120)
	e.openPrivileged(bob)
	refused("previous holder", e.cookie)
	if code, body := e.linkAs(bob, "102", "1", "db1"); code != http.StatusSeeOther {
		t.Fatalf("new holder: link = %d, want 303\n%s", code, body)
	}

	// A web lock ends the holder even while the executor still reports the
	// session (the status is stale here on purpose).
	if code := e.postJSON("/executor/lock", `{}`, alice2); code != http.StatusOK {
		t.Fatalf("lock = %d", code)
	}
	refused("after a web lock", bob)

	// Expiry: the holder ends when the executor expiry passes.
	e.status.setExpiry(e.clk.now().Add(time.Minute).Unix())
	e.openPrivileged(bob)
	if code, body := e.unlinkAs(bob, "102", "1", "check"); code != http.StatusSeeOther {
		t.Fatalf("holder before expiry: unlink = %d, want 303\n%s", code, body)
	}
	e.clk.add(time.Minute)
	refused("after expiry", bob)

	if logs := e.logs.String(); strings.Count(logs, "kind=pve_guest_linked") != 2 || strings.Count(logs, "kind=pve_guest_unlinked") != 2 {
		t.Errorf("want exactly the holders' two links and two unlinks audited:\n%s", logs)
	}
	if l, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Errorf("guest 101 link = %+v, %v; want released", l, err)
	}
}
