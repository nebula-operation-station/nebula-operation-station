// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const assistantOrigin = "https://nebula.example.org"

// bidiText wraps "evil" in a right-to-left override and its pop, written as
// escapes so the source holds no invisible format characters.
var bidiText = string(rune(0x202e)) + "evil" + string(rune(0x202c))

// fakeOpsStore is an in-memory AssistantOpsStore. It records every call so
// the tests can show that a route read or wrote nothing.
type fakeOpsStore struct {
	mu        sync.Mutex
	notes     []opsnotes.Note
	reads     int
	dismissed []int64
}

func (s *fakeOpsStore) List(context.Context) ([]opsnotes.Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return append([]opsnotes.Note(nil), s.notes...), nil
}

func (s *fakeOpsStore) Get(_ context.Context, id int64) (opsnotes.Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	for _, n := range s.notes {
		if n.ID == id {
			return n, nil
		}
	}
	return opsnotes.Note{}, fmt.Errorf("note %d: %w", id, opsnotes.ErrNotFound)
}

func (s *fakeOpsStore) Dismiss(_ context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.notes {
		if n.ID == id {
			s.notes[i].Dismissed = true
			s.dismissed = append(s.dismissed, id)
			return nil
		}
	}
	return fmt.Errorf("note %d: %w", id, opsnotes.ErrNotFound)
}

func (s *fakeOpsStore) Step(_ context.Context, noteID int64, index int) (opsnotes.Step, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	for _, n := range s.notes {
		if n.ID != noteID || index < 1 || index > len(n.Body.Steps) {
			continue
		}
		in := n.Body.Steps[index-1]
		return opsnotes.Step{NoteID: n.ID, Index: index, ActionID: in.ActionID, HostID: in.HostID, Why: in.Why}, true, nil
	}
	return opsnotes.Step{}, false, nil
}

func (s *fakeOpsStore) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// fakeCatalog is the server's view of hosts, actions and digests.
type fakeCatalog struct {
	hosts   map[string]bool
	actions map[string]string
	digests map[string]string
}

func (c *fakeCatalog) HostExists(id string) bool { return c.hosts[id] }

func (c *fakeCatalog) ActionFamily(id string) (string, bool) {
	fam, ok := c.actions[id]
	return fam, ok
}

func (c *fakeCatalog) CurrentDigest(_ opsnotes.Kind, ref string) (string, bool) {
	d, ok := c.digests[ref]
	return d, ok
}

// assistantUser is the logged-in user of a test request; "" means none.
type assistantUser struct{ name string }

func (u assistantUser) user(*http.Request) (string, bool) {
	return u.name, u.name != ""
}

func isAdminName(_ context.Context, user string) (bool, error) {
	return user == "root", nil
}

func newCatalog() *fakeCatalog {
	return &fakeCatalog{
		hosts:   map[string]bool{"h1": true},
		actions: map[string]string{"package.install_security": "os-update", "docker.update": "container-update"},
		digests: map[string]string{"fix:1": "d1"},
	}
}

func fixNote(id int64, created time.Time, snapshot string, body opsnotes.Body) opsnotes.Note {
	return opsnotes.Note{
		ID:        id,
		Kind:      opsnotes.KindFix,
		Ref:       "fix:1",
		Digest:    "d1",
		Body:      body,
		Snapshot:  snapshot,
		CreatedAt: created,
	}
}

const snapshotOpenSSL = `{"package":"openssl","version":"3.0.1","tier":"critical","score":9.5,"kev":true,"exposure":"public"}`

// assistantServer builds the UI with the given Ops configuration and
// returns its HTTP handler.
func assistantServer(t *testing.T, o *ui.AssistantOps, user assistantUser) http.Handler {
	t.Helper()
	if o != nil && o.User == nil {
		o.User = user.user
	}
	srv, err := newTestHandler(t, ui.Options{PublicOrigin: assistantOrigin, AssistantOps: o}).Server()
	if err != nil {
		t.Fatalf("Server: %v", err)
	}
	return srv.Handler
}

func assistantOps(store *fakeOpsStore, cat *fakeCatalog) *ui.AssistantOps {
	return &ui.AssistantOps{Store: store, IsAdmin: isAdminName, Catalog: cat}
}

func doAssistant(t *testing.T, h http.Handler, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The Ops tab is shown in the markup only for an admin; a non-admin gets
// the Help tab alone.
func TestAssistantPanelShowsOpsTabOnlyForAdmin(t *testing.T) {
	store := &fakeOpsStore{}
	cases := []struct {
		name    string
		user    assistantUser
		wantOps bool
	}{
		{"admin", assistantUser{"root"}, true},
		{"non-admin", assistantUser{"alice"}, false},
		{"anonymous", assistantUser{""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := assistantServer(t, assistantOps(store, newCatalog()), tc.user)
			rec := doAssistant(t, h, http.MethodGet, "/assistant/panel", nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /assistant/panel: %d", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `href="/assistant/help"`) {
				t.Errorf("Help tab missing for %s", tc.name)
			}
			hasOps := strings.Contains(body, `href="/assistant/ops"`)
			if hasOps != tc.wantOps {
				t.Errorf("Ops tab in markup = %v, want %v", hasOps, tc.wantOps)
			}
		})
	}
}

// Non-admins get 404 on every Ops route, and nothing is read or written.
func TestAssistantOpsRoutesAnswer404ForNonAdmin(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{Summary: "x"})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"alice"})
	origin := map[string]string{"Origin": assistantOrigin}
	cases := []struct {
		method, path string
		headers      map[string]string
	}{
		{http.MethodGet, "/assistant/ops", nil},
		{http.MethodGet, "/assistant/ops/notes/1", nil},
		{http.MethodPost, "/assistant/ops/notes/1/dismiss", origin},
	}
	for _, tc := range cases {
		rec := doAssistant(t, h, tc.method, tc.path, tc.headers)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s: status %d, want 404", tc.method, tc.path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "openssl") {
			t.Errorf("%s %s leaked a card to a non-admin", tc.method, tc.path)
		}
	}
	if len(store.dismissed) != 0 {
		t.Errorf("non-admin dismissed notes: %v", store.dismissed)
	}
}

// Without an Ops configuration the Ops routes answer 404 and the tab is not
// in the markup, even for an admin.
func TestAssistantOpsUnconfiguredAnswers404(t *testing.T) {
	h := assistantServer(t, nil, assistantUser{"root"})
	for _, path := range []string{"/assistant/ops", "/assistant/ops/notes/1"} {
		if rec := doAssistant(t, h, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", path, rec.Code)
		}
	}
	rec := doAssistant(t, h, http.MethodGet, "/assistant/panel", nil)
	if strings.Contains(rec.Body.String(), `href="/assistant/ops"`) {
		t.Error("Ops tab rendered without an Ops configuration")
	}
}

// Ops needs a store and an admin check; a configuration without them is an
// error at startup, not an open tab.
func TestAssistantOpsNeedsStoreAndAdminCheck(t *testing.T) {
	cases := []*ui.AssistantOps{
		{IsAdmin: isAdminName},
		{Store: &fakeOpsStore{}},
	}
	for i, o := range cases {
		if _, err := ui.New(ui.Options{PublicOrigin: assistantOrigin, AssistantOps: o}); err == nil {
			t.Errorf("case %d: ui.New accepted an incomplete AssistantOps", i)
		}
	}
}

// The Help tab serves every user, reads no notes and is searchable.
func TestAssistantHelpServesAllUsersAndReadsNoNotes(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{""})
	for _, path := range []string{"/assistant/help", "/assistant/help?q=backup", "/assistant/panel"} {
		rec := doAssistant(t, h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", path, rec.Code)
		}
	}
	if n := store.readCount(); n != 0 {
		t.Errorf("Help routes read the notes store %d times, want 0", n)
	}
}

// Model text is escaped and shown as text: markup, script and bidi
// controls never become elements or attributes.
func TestAssistantCardRendersModelTextAsEscapedText(t *testing.T) {
	const evil = `<script>alert(1)</script><img src=x onerror=alert(2)>`
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{
		Summary: evil,
		Urgency: bidiText,
		Steps:   []opsnotes.StepInput{{ActionID: "package.install_security", HostID: "h1", Why: evil}},
	})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	rec := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil)
	body := rec.Body.String()
	for _, bad := range []string{"<script>alert", "<img"} {
		if strings.Contains(body, bad) {
			t.Errorf("model text rendered as markup: found %q", bad)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped model text missing")
	}
	if !strings.Contains(body, bidiText) {
		t.Error("bidi text should appear as (escaped, unchanged) text")
	}
}

// Model text never becomes a link. Citations are links only when NOS maps
// them to a handbook section; anything else is plain text.
func TestAssistantModelTextIsNeverALink(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{
		Summary:     "see https://evil.example/x and javascript:alert(1)",
		Mitigations: []string{`<a href="https://evil.example/m">click</a>`},
		Citations:   []string{"javascript:alert(3)", "no-such-section"},
	})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
	for _, bad := range []string{`href="https://evil`, `href="javascript`, `href="no-such`} {
		if strings.Contains(body, bad) {
			t.Errorf("model text produced a link: %q", bad)
		}
	}
}

var stepLinkRE = regexp.MustCompile(`<a class="button" href="([^"]+)">`)

// Each step gets one GET link built by NOS; steps without a catalog action
// or without a known host get no button; mitigations are text only.
func TestAssistantStepButtons(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(5, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{
		Steps: []opsnotes.StepInput{
			{ActionID: "package.install_security", HostID: "h1", Why: "patch"},
			{ActionID: "docker.update", HostID: "h1", Why: "container"},
			{ActionID: "not.in.catalog", HostID: "h1", Why: "unknown action"},
			{ActionID: "package.install_security", HostID: "gone", Why: "unknown host"},
		},
		Mitigations: []string{"restrict the port at the firewall"},
	})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
	links := stepLinkRE.FindAllStringSubmatch(body, -1)
	want := []string{
		"/operations/new?suggestion=5.1",
		"/inventory/containers?host=h1&amp;suggestion=5.2",
	}
	if len(links) != len(want) {
		t.Fatalf("step buttons = %d, want %d: %v", len(links), len(want), links)
	}
	for i := range want {
		if links[i][1] != want[i] {
			t.Errorf("button %d href = %q, want %q", i, links[i][1], want[i])
		}
	}
	if !strings.Contains(body, "restrict the port at the firewall") {
		t.Error("mitigation text missing")
	}
	if strings.Contains(body, "not.in.catalog") && strings.Count(body, "No button") < 2 {
		t.Error("steps without catalog action or host should say there is no button")
	}
}

// A card whose digest is no longer current is marked outdated.
func TestAssistantCardOutdatedWhenDigestChanged(t *testing.T) {
	cat := newCatalog()
	cat.digests["fix:1"] = "d2"
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{})}}
	h := assistantServer(t, assistantOps(store, cat), assistantUser{"root"})
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
	if !strings.Contains(body, "outdated: findings changed") || !strings.Contains(body, "veraltet: Findings haben sich geändert") {
		t.Error("outdated marker missing")
	}
}

// The card carries the LLM label from ADR 0016 D8 in English and German.
func TestAssistantCardCarriesLLMLabel(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{Summary: "x"})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
	for _, label := range []string{
		"Generated by an LLM – unverified. NOS checked only that each step is a catalog action on this host.",
		"Von einem LLM erzeugt – ungeprüft. NOS hat nur geprüft, dass jeder Schritt eine Katalog-Aktion auf diesem Host ist.",
	} {
		if !strings.Contains(body, label) {
			t.Errorf("LLM label missing: %q", label)
		}
	}
	if !strings.Contains(body, "openssl") || !strings.Contains(body, "critical") {
		t.Error("What block should show the package and tier from the snapshot")
	}
}

// Ops has no run or propose control: the only form on the tab posts to
// the dismiss route, and no script is in the markup (strict CSP).
func TestAssistantOpsHasOnlyDismissPostAndNoScript(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{
		Steps: []opsnotes.StepInput{{ActionID: "package.install_security", HostID: "h1", Why: "x"}},
	})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	for _, path := range []string{"/assistant/panel", "/assistant/ops", "/assistant/ops/notes/1"} {
		body := doAssistant(t, h, http.MethodGet, path, nil).Body.String()
		if strings.Contains(strings.ToLower(body), "<script") && path != "/assistant/ops/notes/1" {
			t.Errorf("%s: inline script in the panel markup", path)
		}
		for _, bad := range []string{"onclick=", "onsubmit=", "propose", ">Run<"} {
			if strings.Contains(strings.ToLower(body), strings.ToLower(bad)) {
				t.Errorf("%s: found %q", path, bad)
			}
		}
		// Forms of the shared layout (the header search) are not the panel's.
		for _, action := range regexp.MustCompile(`<form[^>]*action="(/assistant[^"]*)"`).FindAllStringSubmatch(body, -1) {
			if action[1] != "/assistant/ops/notes/1/dismiss" && action[1] != "/assistant/help" {
				t.Errorf("%s: form posts to %q", path, action[1])
			}
		}
	}
}

// Dismiss hides the note and changes nothing else; a plain form post goes
// back to /help and an htmx request gets an empty answer.
func TestAssistantDismissOnlyHides(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})

	rec := doAssistant(t, h, http.MethodPost, "/assistant/ops/notes/1/dismiss", map[string]string{"Origin": assistantOrigin})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/help" {
		t.Errorf("plain dismiss: %d %q, want 303 /help", rec.Code, rec.Header().Get("Location"))
	}
	if len(store.dismissed) != 1 || store.dismissed[0] != 1 {
		t.Fatalf("dismissed = %v, want [1]", store.dismissed)
	}
	// The card is hidden from the tab afterwards.
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
	if strings.Contains(body, "Fix suggestion 1") {
		t.Error("dismissed card still shown")
	}

	store.notes = append(store.notes, fixNote(2, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{}))
	rec = doAssistant(t, h, http.MethodPost, "/assistant/ops/notes/2/dismiss", map[string]string{"Origin": assistantOrigin, "HX-Request": "true"})
	if rec.Code != http.StatusOK {
		t.Errorf("htmx dismiss: %d, want 200", rec.Code)
	}
}

func TestAssistantDismissUnknownNoteIs404(t *testing.T) {
	h := assistantServer(t, assistantOps(&fakeOpsStore{}, newCatalog()), assistantUser{"root"})
	rec := doAssistant(t, h, http.MethodPost, "/assistant/ops/notes/99/dismiss", map[string]string{"Origin": assistantOrigin})
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}

// Cross-origin dismiss is refused by the security middleware (CSRF).
func TestAssistantDismissNeedsSameOrigin(t *testing.T) {
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	rec := doAssistant(t, h, http.MethodPost, "/assistant/ops/notes/1/dismiss", map[string]string{"Origin": "https://evil.example"})
	if rec.Code == http.StatusSeeOther || len(store.dismissed) != 0 {
		t.Errorf("cross-origin dismiss accepted: %d, dismissed %v", rec.Code, store.dismissed)
	}
}

// Fix cards sort by tier, then score; dismissed and superseded notes and
// summaries are not cards.
func TestAssistantCardsOrderAndFilter(t *testing.T) {
	now := time.Unix(100, 0)
	low := fixNote(1, now, `{"package":"low-pkg","tier":"low","score":1}`, opsnotes.Body{})
	crit := fixNote(2, now, `{"package":"crit-pkg","tier":"critical","score":3}`, opsnotes.Body{})
	critHigher := fixNote(3, now, `{"package":"crit-high-pkg","tier":"critical","score":8}`, opsnotes.Body{})
	superseded := fixNote(4, now, `{"package":"old-pkg","tier":"critical","score":9}`, opsnotes.Body{})
	superseded.Superseded = true
	dismissed := fixNote(5, now, `{"package":"gone-pkg","tier":"critical","score":9}`, opsnotes.Body{})
	dismissed.Dismissed = true
	sum := opsnotes.Note{ID: 6, Kind: opsnotes.KindSummary, Ref: "sum", Body: opsnotes.Body{Text: "Two critical."}, CreatedAt: now}
	store := &fakeOpsStore{notes: []opsnotes.Note{low, crit, critHigher, superseded, dismissed, sum}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()

	order := []string{"crit-high-pkg", "crit-pkg", "low-pkg"}
	last := -1
	for _, name := range order {
		i := strings.Index(body, name)
		if i < 0 {
			t.Fatalf("card for %s missing", name)
		}
		if i < last {
			t.Errorf("%s is out of order", name)
		}
		last = i
	}
	for _, name := range []string{"old-pkg", "gone-pkg"} {
		if strings.Contains(body, name) {
			t.Errorf("%s should not be shown", name)
		}
	}
	if !strings.Contains(body, "Two critical.") {
		t.Error("summary text missing")
	}
}

func TestAssistantOpsEmptyStates(t *testing.T) {
	cases := []struct {
		name   string
		status *ui.AssistantOpsStatus
		want   string
	}{
		{"no suggestion yet", &ui.AssistantOpsStatus{Enabled: true}, "No suggestion yet."},
		{"agent switched off", &ui.AssistantOpsStatus{Enabled: false}, "Agent switched off."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := assistantOps(&fakeOpsStore{}, newCatalog())
			st := *tc.status
			o.Status = func(context.Context) (ui.AssistantOpsStatus, error) { return st, nil }
			h := assistantServer(t, o, assistantUser{"root"})
			body := doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
			if !strings.Contains(body, tc.want) {
				t.Errorf("empty state %q missing", tc.want)
			}
		})
	}
}

// The detail page of one card is admin-only and shows only fix notes.
func TestAssistantNoteDetailPage(t *testing.T) {
	summary := opsnotes.Note{ID: 2, Kind: opsnotes.KindSummary, Body: opsnotes.Body{Text: "s"}}
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{}), summary}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	rec := doAssistant(t, h, http.MethodGet, "/assistant/ops/notes/1", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Fix suggestion 1") {
		t.Errorf("detail: %d", rec.Code)
	}
	if rec := doAssistant(t, h, http.MethodGet, "/assistant/ops/notes/2", nil); rec.Code != http.StatusNotFound {
		t.Errorf("summary as detail: %d, want 404", rec.Code)
	}
	if rec := doAssistant(t, h, http.MethodGet, "/assistant/ops/notes/x", nil); rec.Code != http.StatusNotFound {
		t.Errorf("bad id: %d, want 404", rec.Code)
	}
}
