// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const sessionHeader = "X-Test-Session"

func testSession(r *http.Request) (string, bool) {
	s := r.Header.Get(sessionHeader)
	return s, s != ""
}

// chartTree is a tree with node pve1 (remote-a) holding guest 101 at
// generation 3 linked to host web01, and node dup on two remotes.
func chartTree() pveinventory.Tree {
	return pveinventory.Tree{Roots: []pveinventory.Box{
		{Kind: pveinventory.KindPVENode, Name: "pve1", RemoteID: "remote-a", Children: []pveinventory.Box{
			{Kind: pveinventory.KindGuest, Name: "vm", VMID: 101, Generation: 3, HostID: "web01"},
			{Kind: pveinventory.KindGuest, Name: "unlinked", VMID: 102, Generation: 1},
		}},
		{Kind: pveinventory.KindPVENode, Name: "dup", RemoteID: "remote-a"},
		{Kind: pveinventory.KindPVENode, Name: "dup", RemoteID: "remote-b"},
	}}
}

type handlerRig struct {
	*rig
	h   *Handler
	srv *httptest.Server
}

func newHandlerRig(t *testing.T, leases ...pvecollect.TelemetryLease) *handlerRig {
	t.Helper()
	r := newRig(t, leases...)
	h, err := New(Options{
		Hub:     r.hub,
		Session: testSession,
		Leases:  func(context.Context) ([]pvecollect.TelemetryLease, error) { return leases, nil },
		Tree:    func(context.Context) (pveinventory.Tree, error) { return chartTree(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &handlerRig{rig: r, h: h, srv: srv}
}

// stream is an open SSE connection.
type stream struct {
	resp   *http.Response
	sc     *bufio.Scanner
	viewer string
	cancel context.CancelFunc
}

func openStream(t *testing.T, base, session string) *stream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+EventsPath, nil)
	req.Header.Set(sessionHeader, session)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		resp.Body.Close()
		t.Fatalf("events status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type = %q", ct)
	}
	s := &stream{resp: resp, sc: bufio.NewScanner(resp.Body), cancel: cancel}
	t.Cleanup(s.close)
	name, data := s.next(t)
	if name != "hello" {
		t.Fatalf("first event = %q, want hello", name)
	}
	var hello struct {
		Viewer string `json:"viewer"`
		Renew  int    `json:"renew"`
	}
	if err := json.Unmarshal([]byte(data), &hello); err != nil || !validViewerID(hello.Viewer) || hello.Renew != 10 {
		t.Fatalf("hello = %s (%v)", data, err)
	}
	s.viewer = hello.Viewer
	return s
}

func (s *stream) close() {
	s.cancel()
	s.resp.Body.Close()
}

// next returns the next event's name and data (comments skipped).
func (s *stream) next(t *testing.T) (string, string) {
	t.Helper()
	type ev struct{ name, data string }
	got := make(chan ev, 1)
	go func() {
		var e ev
		for s.sc.Scan() {
			line := s.sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				e.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				e.data = strings.TrimPrefix(line, "data: ")
			case line == "" && e.name != "":
				got <- e
				return
			}
		}
		got <- ev{}
	}()
	select {
	case e := <-got:
		return e.name, e.data
	case <-time.After(5 * time.Second):
		t.Fatal("no event within 5 s")
		return "", ""
	}
}

type targetsResp struct {
	Granted []string `json:"granted"`
	Denied  []string `json:"denied"`
}

func postTargets(t *testing.T, base, session, body string) (int, targetsResp) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+TargetsPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.Header.Set(sessionHeader, session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out targetsResp
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

func boxesBody(viewer string, boxes ...string) string {
	return `{"viewer":"` + viewer + `","boxes":[` + strings.Join(boxes, ",") + `]}`
}

func TestLiveEndpointsRequireLogin(t *testing.T) {
	c := newClock()
	hr := newHandlerRig(t, lease("g1", true, c, nodeTarget("remote-a", "pve1")))
	resp, err := http.Get(hr.srv.URL + EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("events without session = %d, want 401", resp.StatusCode)
	}
	code, _ := postTargets(t, hr.srv.URL, "", boxesBody(mustViewer(t), `{"kind":"node","name":"pve1"}`))
	if code != http.StatusUnauthorized {
		t.Fatalf("targets without session = %d, want 401", code)
	}
}

func TestDefaultSessionRequiresWebSession(t *testing.T) {
	r := newRig(t)
	h, err := New(Options{Hub: r.hub})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.Events(rec, httptest.NewRequest(http.MethodGet, EventsPath, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("events without web session = %d, want 401", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.Targets(rec, httptest.NewRequest(http.MethodPost, TargetsPath, strings.NewReader("{}")))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("targets without web session = %d, want 401", rec.Code)
	}
}

func TestStreamDeliversSanitizedLiveValues(t *testing.T) {
	c := newClock()
	tgt := nodeTarget("remote-a", "pve1")
	hr := newHandlerRig(t, lease("g1", true, c, tgt))
	s := openStream(t, hr.srv.URL, "sess-a")
	code, out := postTargets(t, hr.srv.URL, "sess-a", boxesBody(s.viewer, `{"kind":"node","name":"pve1"}`))
	if code != http.StatusOK || !slices.Equal(out.Granted, []string{"node:pve1"}) {
		t.Fatalf("targets = %d %+v", code, out)
	}
	hr.sched.RunOnce(context.Background())
	name, data := s.next(t)
	if name != "value" {
		t.Fatalf("event = %q, want value", name)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 || raw["id"] != "node:pve1" || raw["metric"] != "cpu" || raw["value"] != 0.42 {
		t.Fatalf("value payload = %s", data)
	}
	for _, leak := range []string{"remote-a", "abab", "g1"} {
		if strings.Contains(data, leak) {
			t.Fatalf("payload leaks %q: %s", leak, data)
		}
	}
}

func TestTargetsOfAnotherSessionAreGone(t *testing.T) {
	c := newClock()
	hr := newHandlerRig(t, lease("g1", true, c, nodeTarget("remote-a", "pve1")))
	s := openStream(t, hr.srv.URL, "sess-a")
	body := boxesBody(s.viewer, `{"kind":"node","name":"pve1"}`)
	if code, _ := postTargets(t, hr.srv.URL, "sess-b", body); code != http.StatusGone {
		t.Fatalf("foreign session = %d, want 410", code)
	}
	if code, _ := postTargets(t, hr.srv.URL, "sess-a", boxesBody(mustViewer(t))); code != http.StatusGone {
		t.Fatalf("unknown viewer = %d, want 410", code)
	}
	hr.sched.RunOnce(context.Background())
	if n := hr.reader.liveReads(); n != 0 {
		t.Fatalf("live reads = %d, want 0", n)
	}
}

func TestTargetsResolveOnlyLeasedTargets(t *testing.T) {
	c := newClock()
	hr := newHandlerRig(t,
		lease("g1", true, c,
			nodeTarget("remote-a", "pve1"),
			guestTarget("remote-a", "pve1", 102, 7), // generation 7 ≠ tree's 1
			nodeTarget("remote-a", "dup"),
			nodeTarget("remote-b", "pve1"), // same name, other remote
			hostTarget("web01"),
		),
		lease("g2", false, c, guestTarget("remote-a", "pve1", 101, 3)), // history only
	)
	s := openStream(t, hr.srv.URL, "s")
	code, out := postTargets(t, hr.srv.URL, "s", boxesBody(s.viewer,
		`{"kind":"node","name":"pve1"}`,
		`{"kind":"guest","node":"pve1","vmid":101}`, // via link to web01
		`{"kind":"guest","node":"pve1","vmid":102}`,
		`{"kind":"guest","node":"pve1","vmid":103}`, // not in tree
		`{"kind":"node","name":"dup"}`,              // ambiguous
		`{"kind":"node","name":"pve9"}`,             // not leased
		`{"kind":"host","id":"web01"}`,
		`{"kind":"host","id":"db01"}`,             // not leased
		`{"kind":"node","name":"bad name"}`,       // malformed: dropped
		`{"kind":"guest","node":"pve1","vmid":5}`, // malformed: dropped
		`{"kind":"guest","node":"pve1"}`,          // malformed: dropped
		`{"kind":"remote","name":"remote-a"}`,     // unknown kind: dropped
	))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	slices.Sort(out.Granted)
	slices.Sort(out.Denied)
	if want := []string{"guest:pve1:101", "host:web01", "node:pve1"}; !slices.Equal(out.Granted, want) {
		t.Fatalf("granted = %v, want %v", out.Granted, want)
	}
	if want := []string{"guest:pve1:102", "guest:pve1:103", "host:db01", "node:dup", "node:pve9"}; !slices.Equal(out.Denied, want) {
		t.Fatalf("denied = %v, want %v", out.Denied, want)
	}
	// The node box is bound to remote-a: only that node target is read.
	hr.sched.RunOnce(context.Background())
	hr.reader.mu.Lock()
	defer hr.reader.mu.Unlock()
	for _, rd := range hr.reader.reads {
		if rd.Live && rd.Target.RemoteID == "remote-b" {
			t.Fatalf("live read of the other remote's node: %+v", rd.Target)
		}
	}
}

func TestTargetsWithoutTreeResolveNoPVEBoxes(t *testing.T) {
	c := newClock()
	leases := []pvecollect.TelemetryLease{lease("g1", true, c, nodeTarget("remote-a", "pve1"), hostTarget("web01"))}
	r := newRig(t, leases...)
	h, err := New(Options{Hub: r.hub, Session: testSession,
		Leases: func(context.Context) ([]pvecollect.TelemetryLease, error) { return leases, nil },
		Tree:   func(context.Context) (pveinventory.Tree, error) { return pveinventory.Tree{}, errors.New("db down") },
	})
	if err != nil {
		t.Fatal(err)
	}
	v := mustViewer(t)
	if _, err := r.hub.Add(v, "s"); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, TargetsPath, strings.NewReader(boxesBody(v, `{"kind":"node","name":"pve1"}`, `{"kind":"host","id":"web01"}`)))
	req.Header.Set(sessionHeader, "s")
	h.Targets(rec, req)
	var out targetsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Granted, []string{"host:web01"}) || !slices.Equal(out.Denied, []string{"node:pve1"}) {
		t.Fatalf("without tree: %+v", out)
	}
}

func TestTargetsRejectsMalformedBodies(t *testing.T) {
	c := newClock()
	hr := newHandlerRig(t, lease("g1", true, c, nodeTarget("remote-a", "pve1")))
	s := openStream(t, hr.srv.URL, "s")
	many := make([]string, maxViewerBoxes+1)
	for i := range many {
		many[i] = `{"kind":"node","name":"pve1"}`
	}
	for name, body := range map[string]string{
		"not json":       "{",
		"bad viewer":     boxesBody("../../etc"),
		"too many boxes": boxesBody(s.viewer, many...),
		"oversized":      boxesBody(s.viewer, `{"kind":"node","name":"`+strings.Repeat("a", maxTargetsBodyBytes)+`"}`),
	} {
		if code, _ := postTargets(t, hr.srv.URL, "s", body); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, TargetsPath, nil)
	req.Header.Set(sessionHeader, "s")
	hr.h.Targets(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET targets = %d, want 405", rec.Code)
	}
}

func TestDisconnectedStreamReleasesTargets(t *testing.T) {
	h, sched, _ := newRecHub(t)
	hd, err := New(Options{Hub: h, Session: testSession,
		Leases: func(context.Context) ([]pvecollect.TelemetryLease, error) {
			return []pvecollect.TelemetryLease{{OnDemand: true, Targets: []pvecollect.TelemetryTarget{hostTarget("web01")}}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	hd.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	s := openStream(t, srv.URL, "s")
	if code, out := postTargets(t, srv.URL, "s", boxesBody(s.viewer, `{"kind":"host","id":"web01"}`)); code != http.StatusOK || len(out.Granted) != 1 {
		t.Fatalf("targets = %d %+v", code, out)
	}
	if n := sched.activeCount(s.viewer); n != 1 {
		t.Fatalf("requested = %d, want 1", n)
	}
	s.close()
	deadline := time.Now().Add(5 * time.Second)
	for sched.activeCount(s.viewer) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("targets still requested 5 s after disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _ := postTargets(t, srv.URL, "s", boxesBody(s.viewer)); code != http.StatusGone {
		t.Fatalf("targets after disconnect = %d, want 410", code)
	}
}

func viewerCount(h *Hub) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.viewers)
}

// recheckRig serves a handler whose Recheck answers from valid/expires.
type recheckRig struct {
	hub     *Hub
	sched   *recSched
	hd      *Handler
	srv     *httptest.Server
	valid   atomic.Bool
	expires atomic.Pointer[time.Time]
}

func newRecheckRig(t *testing.T, recheck bool, every, life time.Duration) *recheckRig {
	t.Helper()
	h, sched, _ := newRecHub(t)
	rr := &recheckRig{hub: h, sched: sched}
	rr.valid.Store(true)
	rr.expires.Store(&time.Time{})
	o := Options{Hub: h, Session: testSession,
		Leases: func(context.Context) ([]pvecollect.TelemetryLease, error) {
			return []pvecollect.TelemetryLease{{OnDemand: true, Targets: []pvecollect.TelemetryTarget{hostTarget("web01")}}}, nil
		},
	}
	if recheck {
		o.Recheck = func(context.Context, *http.Request) (time.Time, bool) {
			return *rr.expires.Load(), rr.valid.Load()
		}
	}
	hd, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	hd.recheckEvery, hd.maxLifetime = every, life
	mux := http.NewServeMux()
	hd.Register(mux)
	rr.hd, rr.srv = hd, httptest.NewServer(mux)
	t.Cleanup(rr.srv.Close)
	return rr
}

// streamEnds waits until the server ends the stream and the viewer's
// slot and targets are freed.
func (rr *recheckRig) streamEnds(t *testing.T, s *stream) {
	t.Helper()
	if name, _ := s.next(t); name != "" {
		t.Fatalf("stream delivered %q instead of ending", name)
	}
	deadline := time.Now().Add(5 * time.Second)
	for viewerCount(rr.hub) != 0 || rr.sched.activeCount(s.viewer) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("after the stream ended: %d viewers, %d targets", viewerCount(rr.hub), rr.sched.activeCount(s.viewer))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Logout (or idle expiry) ends an open stream at the next re-check and
// frees its slot and targets.
func TestLogoutEndsOpenStream(t *testing.T) {
	rr := newRecheckRig(t, true, 50*time.Millisecond, time.Hour)
	s := openStream(t, rr.srv.URL, "s")
	if code, out := postTargets(t, rr.srv.URL, "s", boxesBody(s.viewer, `{"kind":"host","id":"web01"}`)); code != http.StatusOK || len(out.Granted) != 1 {
		t.Fatalf("targets = %d %+v", code, out)
	}
	// Still valid: the stream survives several re-checks.
	time.Sleep(200 * time.Millisecond)
	if viewerCount(rr.hub) != 1 {
		t.Fatal("stream ended while the session was valid")
	}
	rr.valid.Store(false)
	rr.streamEnds(t, s)
}

// A stream ends at its session's absolute expiry.
func TestStreamEndsAtSessionExpiry(t *testing.T) {
	rr := newRecheckRig(t, true, time.Hour, time.Hour)
	exp := time.Now().Add(300 * time.Millisecond)
	rr.expires.Store(&exp)
	s := openStream(t, rr.srv.URL, "s")
	rr.streamEnds(t, s)
}

// A stream ends after its maximum lifetime (the client reconnects).
func TestStreamLifetimeIsCapped(t *testing.T) {
	if maxStreamLifetime > time.Hour || maxStreamLifetime <= 0 {
		t.Fatalf("maxStreamLifetime = %s", maxStreamLifetime)
	}
	rr := newRecheckRig(t, false, time.Hour, 300*time.Millisecond)
	s := openStream(t, rr.srv.URL, "s")
	rr.streamEnds(t, s)
}

// A stream is refused when the re-check already fails on open.
func TestStreamRefusedWhenRecheckFails(t *testing.T) {
	rr := newRecheckRig(t, true, time.Hour, time.Hour)
	rr.valid.Store(false)
	req, _ := http.NewRequest(http.MethodGet, rr.srv.URL+EventsPath, nil)
	req.Header.Set(sessionHeader, "s")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || viewerCount(rr.hub) != 0 {
		t.Fatalf("events with a gone session = %d (%d viewers)", resp.StatusCode, viewerCount(rr.hub))
	}
}

func TestPeekSessionUsesTheStreamCookie(t *testing.T) {
	exp := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	var gotToken string
	recheck := PeekSession(func(_ context.Context, token string) (auth.Session, error) {
		gotToken = token
		if token != "tok" {
			return auth.Session{}, auth.ErrNoSession
		}
		return auth.Session{CredentialID: "c", ExpiresAt: exp}, nil
	})
	r := httptest.NewRequest(http.MethodGet, EventsPath, nil)
	if _, ok := recheck(context.Background(), r); ok {
		t.Fatal("no cookie accepted")
	}
	r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "gone"})
	if _, ok := recheck(context.Background(), r); ok || gotToken != "gone" {
		t.Fatalf("gone session accepted (token %q)", gotToken)
	}
	r = httptest.NewRequest(http.MethodGet, EventsPath, nil)
	r.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "tok"})
	if got, ok := recheck(context.Background(), r); !ok || !got.Equal(exp) {
		t.Fatalf("valid session = %v, %v", got, ok)
	}
}
