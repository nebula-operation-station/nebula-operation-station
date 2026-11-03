// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/session"
	static "github.com/nebula-operation-station/nebula-operation-station/web/static"
)

// The topbar session display (ADR 0007 E20) is computed on the server
// (internal/web/ui/session, run by GET /privileged/session) and only
// rendered by the session display section of web/static/nav.js (the one
// script every non-bare page loads). There is no JS test runner in this
// repository, so the browser side is covered structurally below: the
// tests fail when that code stops reading the server's view, starts
// deriving state from raw executor fields, drops the passive marker,
// the visibility pause, the sequence check, the input validation or the
// extend-once guard, or uses an HTML sink.

// TestPrivilegedSessionDisplayView covers the computed display in the
// poll answer: the server runs session.Display with its own clock and the
// state the client sent as ?prev=.
func TestPrivilegedSessionDisplayView(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	active := &fakeStatus{resp: &pb.GetStatusResponse{PrivilegedSessionActive: true, PrivilegedSessionExpiryUnix: now.Add(90 * time.Second).Unix()}}
	stale := &fakeStatus{resp: &pb.GetStatusResponse{PrivilegedSessionActive: true, PrivilegedSessionExpiryUnix: now.Add(-time.Second).Unix()}}
	none := &fakeStatus{resp: &pb.GetStatusResponse{}}
	down := &fakeStatus{err: errors.New("down")}
	type answer struct {
		Active     bool  `json:"active"`
		Available  bool  `json:"available"`
		ExpiryUnix int64 `json:"expiry_unix"`
		session.View
	}
	for _, tc := range []struct {
		name   string
		status *fakeStatus
		query  string
		want   answer
	}{
		{"active", active, "?prev=none", answer{true, true, now.Add(90 * time.Second).Unix(),
			session.View{State: "active", Label: "Session", RemainingSeconds: 90, Extendable: true, LowThresholdSeconds: 60}}},
		{"active past expiry fails closed", stale, "?prev=active", answer{true, true, now.Add(-time.Second).Unix(),
			session.View{State: "expired", Label: "Session expired", Extendable: true, LowThresholdSeconds: 60}}},
		{"gone after active is expired", none, "?prev=active", answer{false, true, 0,
			session.View{State: "expired", Label: "Session expired", Extendable: true, LowThresholdSeconds: 60}}},
		{"never opened is none", none, "?prev=unknown", answer{false, true, 0,
			session.View{State: "none", Label: "No session", LowThresholdSeconds: 60}}},
		{"missing prev is none", none, "", answer{false, true, 0,
			session.View{State: "none", Label: "No session", LowThresholdSeconds: 60}}},
		{"garbage prev is treated as unknown", none, "?prev=%3Cb%3Eactive", answer{false, true, 0,
			session.View{State: "none", Label: "No session", LowThresholdSeconds: 60}}},
		{"executor down is unknown", down, "?prev=active", answer{false, false, 0,
			session.View{State: "unknown", Label: "Session unavailable", LowThresholdSeconds: 60}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Status: tc.status, Now: func() time.Time { return now }}).Handler()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/privileged/session"+tc.query, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			var got answer
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// sessionDisplayMarker starts the session display section of nav.js.
const sessionDisplayMarker = "// --- Topbar privileged-session display (ADR 0007 E20)"

// sessionJS returns the session display section of nav.js.
func sessionJS(t *testing.T) string {
	t.Helper()
	b, err := static.FS.ReadFile("nav.js")
	if err != nil {
		t.Fatalf("read nav.js: %v", err)
	}
	i := strings.Index(string(b), sessionDisplayMarker)
	if i < 0 {
		t.Fatal("nav.js has no session display section")
	}
	return string(b[i:])
}

// TestSessionJSRendersTheServerView: the session display reads every field of
// session.View, knows exactly the server's state names, and never reads
// the raw executor fields (active, available, expiry_unix) a client-side
// state machine would need.
func TestSessionJSRendersTheServerView(t *testing.T) {
	js := sessionJS(t)
	vt := reflect.TypeOf(session.View{})
	for i := 0; i < vt.NumField(); i++ {
		tag := strings.Split(vt.Field(i).Tag.Get("json"), ",")[0]
		if !strings.Contains(js, "p."+tag) {
			t.Errorf("the session display does not read view field %q", tag)
		}
	}
	m := regexp.MustCompile(`const STATES = \[([^\]]*)\];`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("the session display has no STATES list")
	}
	var want []string
	for _, s := range []session.State{session.StateUnknown, session.StateNone, session.StateActive, session.StateExpired} {
		want = append(want, "'"+s.String()+"'")
	}
	if got := strings.Join(strings.Fields(strings.ReplaceAll(m[1], ",", " ")), ", "); got != strings.Join(want, ", ") {
		t.Errorf("the session display STATES = %s, want %s", got, strings.Join(want, ", "))
	}
	// The client-side fail-closed view carries the server's unknown label.
	if !strings.Contains(js, "label: '"+session.StateLabel(session.StateUnknown)+"'") {
		t.Errorf("the session display unknown view does not use label %q", session.StateLabel(session.StateUnknown))
	}
	for _, raw := range []string{"expiry_unix", "p.active", "p.available", ".active)", ".available)"} {
		if strings.Contains(js, raw) {
			t.Errorf("the session display reads the raw executor field %q; it must render the server view only", raw)
		}
	}
	// The poll answer is validated before it is used.
	if !strings.Contains(js, "next = parseView(await res.json());") {
		t.Error("the session display uses the poll answer without parseView")
	}
	for _, check := range []string{
		"typeof s !== 'string' || STATES.indexOf(s) < 0",
		"typeof l !== 'string'",
		"!Number.isInteger(r) || r < 0",
		"!Number.isInteger(t) || t < 0",
		"typeof x !== 'boolean'",
		"next = UNKNOWN; // fail closed",
	} {
		if !strings.Contains(js, check) {
			t.Errorf("the session display lacks the validation %q", check)
		}
	}
}

// TestSessionJSPollIsPassiveAndPausesWhenHidden: the background poll is
// marked with auth.PassiveHeader (so it is no activity), sends the shown
// state as prev, and does not run while the tab is hidden.
func TestSessionJSPollIsPassiveAndPausesWhenHidden(t *testing.T) {
	js := sessionJS(t)
	for _, want := range []string{
		"const PASSIVE_HEADER = '" + auth.PassiveHeader + "';",
		"headers: { [PASSIVE_HEADER]: '1' }",
		"fetch('/privileged/session?prev=' + encodeURIComponent(view.state)",
		"if (document.hidden || inFlight) return;",
		"document.addEventListener('visibilitychange'",
		"if (!document.hidden) {\n    poll();\n    startPolling();",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the session display lacks %q", want)
		}
	}
	// Exactly one fetch, and it is the marked poll.
	if n := strings.Count(js, "fetch("); n != 1 {
		t.Errorf("the session display has %d fetch calls, want 1 (the passive poll)", n)
	}
	// Timers only ever call the guarded background poll or the tick.
	for _, m := range regexp.MustCompile(`setInterval\((\w+)`).FindAllStringSubmatch(js, -1) {
		if m[1] != "backgroundPoll" && m[1] != "tick" {
			t.Errorf("the session display schedules %s on an interval; only backgroundPoll and tick may run on timers", m[1])
		}
	}
}

// TestSessionJSDropsStaleAnswersAndExtendsOnce: every poll takes a
// sequence number and its answer is dropped unless it is still the latest;
// the Extend click is guarded against a second flow and invalidates polls
// that are under way before it starts the assertion.
func TestSessionJSDropsStaleAnswersAndExtendsOnce(t *testing.T) {
	js := sessionJS(t)
	order := func(what string, parts ...string) {
		t.Helper()
		at := 0
		for _, p := range parts {
			i := strings.Index(js[at:], p)
			if i < 0 {
				t.Errorf("%s: %q missing or out of order", what, p)
				return
			}
			at += i + len(p)
		}
	}
	order("poll sequence check",
		"async function poll() {", "const mine = ++seq;", "await res.json()", "if (mine !== seq) return;", "apply(next);")
	order("extend once",
		"btn.addEventListener('click', async () => {", "if (inFlight) return;", "inFlight = true;", "seq++;",
		"const w = await loadWebAuthn();", "w.post('/privileged/begin')", "navigator.credentials.get(", "w.post('/privileged/finish'",
		"inFlight = false;", "if (ok) await poll();")
	if n := strings.Count(js, "w.post('/privileged/begin')"); n != 1 {
		t.Errorf("the session display starts %d assertion flows, want 1", n)
	}
}

// TestSessionJSIsCSPClean: textContent only, no HTML sinks, no dynamic
// code, no inline styles.
func TestSessionJSIsCSPClean(t *testing.T) {
	js := sessionJS(t)
	for _, bad := range []string{
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
		".style.", "setAttribute('on", "setAttribute(\"on", "javascript:",
	} {
		if strings.Contains(js, bad) {
			t.Errorf("the session display contains %q", bad)
		}
	}
}

// TestSessionDisplayOnEveryPage: every non-bare page, including pages
// whose own scripts do not include webauthn.js (Operations list, leases),
// carries the display element and nav.js;
// the bare login page carries neither. Pages without webauthn.js load it
// on the first Extend click, once.
func TestSessionDisplayOnEveryPage(t *testing.T) {
	plain := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	leases := leaseHandler(t, &fakeLeases{})
	for _, tc := range []struct {
		h    http.Handler
		path string
	}{
		{plain, "/dashboard"},
		{plain, "/operations"},
		{plain, "/settings"},
		{leases, "/leases"},
		{leases, "/leases/new"},
	} {
		body := getBody(t, tc.h, tc.path)
		if !strings.Contains(body, `<script src="/static/nav.js"></script>`) {
			t.Errorf("GET %s: nav.js not loaded", tc.path)
		}
		if !strings.Contains(body, `id="session-display"`) {
			t.Errorf("GET %s: no session display element", tc.path)
		}
	}
	login := getBody(t, plain, "/login")
	if strings.Contains(login, "/static/nav.js") || strings.Contains(login, `id="session-display"`) {
		t.Error("the bare login page must not carry the session display")
	}

	js := sessionJS(t)
	for _, want := range []string{
		"if (typeof nebulaWebAuthn !== 'undefined') return Promise.resolve(nebulaWebAuthn);",
		"s.src = '/static/webauthn.js';",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the session display lacks %q", want)
		}
	}
	if n := strings.Count(js, "await loadWebAuthn()"); n != 1 {
		t.Errorf("loadWebAuthn called %d times, want 1 (inside the guarded Extend flow)", n)
	}
}
