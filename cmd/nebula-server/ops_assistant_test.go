// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const testAsstOrigin = "https://nebula.example.test"

// fakeAsstStore is the notes store of the Ops tab in memory.
type fakeAsstStore struct {
	notes     []opsnotes.Note
	questions []opsnotes.Question
}

var _ ui.AssistantOpsStore = (*fakeAsstStore)(nil)

func (s *fakeAsstStore) List(context.Context) ([]opsnotes.Note, error) { return s.notes, nil }

func (s *fakeAsstStore) Get(_ context.Context, id int64) (opsnotes.Note, error) {
	for _, n := range s.notes {
		if n.ID == id {
			return n, nil
		}
	}
	return opsnotes.Note{}, opsnotes.ErrNotFound
}

func (s *fakeAsstStore) Dismiss(context.Context, int64) error { return nil }

func (s *fakeAsstStore) Step(context.Context, int64, int) (opsnotes.Step, bool, error) {
	return opsnotes.Step{}, false, nil
}

func (s *fakeAsstStore) AskQuestion(_ context.Context, user, text string) (opsnotes.Question, error) {
	q := opsnotes.Question{ID: int64(len(s.questions) + 1), User: user, Text: text}
	s.questions = append(s.questions, q)
	return q, nil
}

func (s *fakeAsstStore) ListQuestions(_ context.Context, user string) ([]opsnotes.Question, error) {
	var out []opsnotes.Question
	for _, q := range s.questions {
		if q.User == user {
			out = append(out, q)
		}
	}
	return out, nil
}

// fakeAsstCatalog knows one host and one package action; the card's digest
// is current.
type fakeAsstCatalog struct{}

var _ ui.AssistantOpsCatalog = fakeAsstCatalog{}

func (fakeAsstCatalog) HostExists(hostID string) bool { return hostID == "web-1" }

func (fakeAsstCatalog) ActionFamily(actionID string) (string, bool) {
	if actionID == "pkg.update" {
		return "package-update", true
	}
	return "", false
}

func (fakeAsstCatalog) CurrentDigest(kind opsnotes.Kind, ref string) (string, bool) {
	if kind == opsnotes.KindFix && ref == "web-1/os" {
		return "digest-1", true
	}
	return "", false
}

// fakeAsstSettings reads the stored Enabled flag.
type fakeAsstSettings struct{ enabled bool }

func (s fakeAsstSettings) Get(context.Context) (opsconfig.Row, error) {
	return opsconfig.Row{Settings: opsconfig.Settings{Enabled: s.enabled}}, nil
}

// fakeAsstRuns is the last run the agent reported.
type fakeAsstRuns struct{ st api.OpsRunStatus }

func (r fakeAsstRuns) LastOpsStatus() (api.OpsRunStatus, bool) { return r.st, true }

// asstFixNote is a stored fix note with one step on web-1.
func asstFixNote(id int64) opsnotes.Note {
	return opsnotes.Note{
		ID: id, Kind: opsnotes.KindFix, Ref: "web-1/os", Digest: "digest-1",
		CreatedAt: time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC),
		Snapshot:  `{"package":"openssl","version":"3.0.1","tier":"critical","score":9.8,"kev":true,"exposure":"lan"}`,
		Body: opsnotes.Body{
			Summary: "Update openssl on web-1",
			Urgency: "this week",
			Steps:   []opsnotes.StepInput{{ActionID: "pkg.update", HostID: "web-1", Why: "fixes the advisory"}},
		},
	}
}

// asstWiring builds the wiring over the fakes. isAdmin is the server's rule;
// the session user is "alice" in every test.
func asstWiring(t *testing.T, store ui.AssistantOpsStore, isAdmin bool, touch func() bool) opsAssistantWiring {
	t.Helper()
	runs := &opsRunHolder{}
	runs.src = fakeAsstRuns{st: api.OpsRunStatus{
		ReceivedAt: time.Date(2026, 11, 25, 10, 30, 0, 0, time.UTC),
		Refusals:   []string{"schema"},
	}}
	return opsAssistantWiring{
		store:    store,
		isAdmin:  func(context.Context) bool { return isAdmin },
		catalog:  fakeAsstCatalog{},
		settings: fakeAsstSettings{enabled: true},
		runs:     runs,
		touch:    touch,
		user:     func(*http.Request) (string, bool) { return "alice", true },
	}
}

// asstHandler is the UI handler with the Ops tab wired from w.
func asstHandler(t *testing.T, w opsAssistantWiring) http.Handler {
	t.Helper()
	uh, err := ui.New(withOpsAssistant(ui.Options{PublicOrigin: testAsstOrigin}, w))
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	return uh.Handler()
}

func asstRequest(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Origin", testAsstOrigin)
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// An admin sees the stored fix note as a card whose step links to the
// operation form with suggestion=<note>.<step>, and sees the last run.
func TestOpsTabShowsFixCardLinkAndLastRunForAdmin(t *testing.T) {
	store := &fakeAsstStore{notes: []opsnotes.Note{asstFixNote(7)}}
	h := asstHandler(t, asstWiring(t, store, true, nil))
	rec := asstRequest(t, h, http.MethodGet, "/assistant/ops", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assistant/ops = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Update openssl on web-1",
		`/operations/new?suggestion=7.1`,
		"2026-11-25 10:30 UTC",
		"schema",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Ops tab lacks %q", want)
		}
	}
}

// A non-admin gets 404 on the Ops routes; no card is rendered.
func TestOpsTabAnswers404ForNonAdmin(t *testing.T) {
	store := &fakeAsstStore{notes: []opsnotes.Note{asstFixNote(7)}}
	h := asstHandler(t, asstWiring(t, store, false, nil))
	for _, path := range []string{"/assistant/ops", "/assistant/ops/notes/7", "/assistant/ops/questions"} {
		rec := asstRequest(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "openssl") {
			t.Errorf("GET %s leaked a card to a non-admin", path)
		}
	}
}

// A question is stored for the admin and the trigger file is replaced in the
// temporary state directory; the trigger carries no data.
func TestOpsQuestionIsStoredAndReplacesTriggerFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ops-trigger")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fakeAsstStore{}
	trig := newOpsTrigger(fakeAsstSettings{enabled: true}, path, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := asstHandler(t, asstWiring(t, store, true, trig.Touch))
	rec := asstRequest(t, h, http.MethodPost, "/assistant/ops/questions", "question=which+host+first%3F")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST questions = %d, want 303", rec.Code)
	}
	if len(store.questions) != 1 || store.questions[0].Text != "which host first?" || store.questions[0].User != "alice" {
		t.Fatalf("stored questions = %+v, want one from alice", store.questions)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("trigger file: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("trigger file holds %d bytes, want an empty file", len(got))
	}
}

// A trigger that cannot be touched does not lose the question: the agent then
// runs on its timer.
func TestOpsQuestionStoredWhenTriggerNotTouched(t *testing.T) {
	store := &fakeAsstStore{}
	trig := newOpsTrigger(fakeAsstSettings{enabled: true}, filepath.Join(t.TempDir(), "missing", "ops-trigger"),
		time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := asstHandler(t, asstWiring(t, store, true, trig.Touch))
	if rec := asstRequest(t, h, http.MethodPost, "/assistant/ops/questions", "question=hello"); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST questions = %d, want 303", rec.Code)
	}
	if len(store.questions) != 1 {
		t.Fatalf("stored %d questions, want 1", len(store.questions))
	}
}

// The trigger carries no data: a question's text never reaches the trigger
// path, and the status reflects the stored Enabled flag.
func TestOpsTriggerCarriesNoDataAndStatusReadsSettings(t *testing.T) {
	w := asstWiring(t, &fakeAsstStore{}, true, func() bool { return true })
	w.settings = fakeAsstSettings{enabled: false}
	st, err := w.status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled {
		t.Fatal("status Enabled = true, want the stored false")
	}
	if err := w.touchTrigger(); err != nil {
		t.Fatalf("touchTrigger = %v, want nil when the trigger was touched", err)
	}
	w.touch = func() bool { return false }
	if err := w.touchTrigger(); err != errOpsAssistantNotTouched {
		t.Fatalf("touchTrigger = %v, want the fixed text", err)
	}
}

// opsTokenCfg is an API config with the ops token (ops:read) and no other
// token; noOpsTokenCfg holds one inventory reader instead.
var (
	opsTokenCfg = serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{{
		Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken("ops-test-token"),
		Scopes: []string{serverconfig.ScopeOpsRead}}}}
	noOpsTokenCfg = serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{{
		Name: "reader", SHA256: "00", Scopes: []string{serverconfig.ScopeInventoryRead}}}}
)

// The Ops tab is wired only with the ops token: without it the wire function
// is not called, the UI options carry no Ops tab and the Ops routes answer 404.
// The gate is applyOpsAssistant, which main.go calls.
func TestOpsTabIsWiredOnlyWithOpsToken(t *testing.T) {
	wired := 0
	wire := func() (opsAssistantWiring, error) {
		wired++
		return asstWiring(t, &fakeAsstStore{}, true, nil), nil
	}
	opts, err := applyOpsAssistant(ui.Options{PublicOrigin: testAsstOrigin}, noOpsTokenCfg, wire)
	if err != nil {
		t.Fatal(err)
	}
	if opts.AssistantOps != nil || wired != 0 {
		t.Fatalf("without the ops token: Ops tab set=%v, wire calls=%d; want none", opts.AssistantOps != nil, wired)
	}
	uh, err := ui.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h := uh.Handler()
	for _, path := range []string{"/assistant/ops", "/assistant/ops/questions"} {
		if rec := asstRequest(t, h, http.MethodGet, path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
	if rec := asstRequest(t, h, http.MethodPost, "/assistant/ops/questions", "question=x"); rec.Code != http.StatusNotFound {
		t.Errorf("POST questions = %d, want 404", rec.Code)
	}

	opts, err = applyOpsAssistant(ui.Options{PublicOrigin: testAsstOrigin}, opsTokenCfg, wire)
	if err != nil {
		t.Fatal(err)
	}
	if opts.AssistantOps == nil || wired != 1 {
		t.Fatalf("with the ops token: Ops tab set=%v, wire calls=%d; want the tab and one call", opts.AssistantOps != nil, wired)
	}
}

// A wiring error stops the server start; it is not swallowed.
func TestOpsTabWiringErrorIsReturned(t *testing.T) {
	wantErr := errors.New("ops assistant: settings")
	_, err := applyOpsAssistant(ui.Options{}, opsTokenCfg, func() (opsAssistantWiring, error) {
		return opsAssistantWiring{}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("applyOpsAssistant = %v, want the wiring error", err)
	}
}

// opsAssistantSources counts the reads behind the Ops tab catalog: the
// inventory hosts and the projection's eligible groups.
type opsAssistantSources struct {
	hostReads, groupReads int
}

func (s *opsAssistantSources) hosts(context.Context) ([]inventory.Host, error) {
	s.hostReads++
	return []inventory.Host{{ID: "web-1"}}, nil
}

func (s *opsAssistantSources) groups(context.Context) ([]opsfacts.Group, error) {
	s.groupReads++
	return []opsfacts.Group{{Key: "web-1/os", Digest: "digest-1"}}, nil
}

// One render of the Ops tab reads the projection and the inventory once, however
// many cards it shows. A render after the snapshot's window reads them again.
func TestOpsTabReadsProjectionOncePerRender(t *testing.T) {
	const cards = 50
	var notes []opsnotes.Note
	for i := 1; i <= cards; i++ {
		notes = append(notes, asstFixNote(int64(i)))
	}
	src := &opsAssistantSources{}
	now := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	w := asstWiring(t, &fakeAsstStore{notes: notes}, true, nil)
	w.catalog = newOpsAssistantCatalog(src.hosts, src.groups, func() time.Time { return now })
	h := asstHandler(t, w)

	rec := asstRequest(t, h, http.MethodGet, "/assistant/ops", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /assistant/ops = %d, want 200", rec.Code)
	}
	if got := strings.Count(rec.Body.String(), "Update openssl on web-1"); got != cards {
		t.Fatalf("rendered %d cards, want %d", got, cards)
	}
	if src.groupReads != 1 || src.hostReads != 1 {
		t.Fatalf("one render: projection reads=%d, host reads=%d; want 1 and 1", src.groupReads, src.hostReads)
	}
	asstRequest(t, h, http.MethodGet, "/assistant/ops", "")
	if src.groupReads != 1 || src.hostReads != 1 {
		t.Fatalf("second render in the same window: projection reads=%d, host reads=%d; want 1 and 1",
			src.groupReads, src.hostReads)
	}
	now = now.Add(opsAssistantSnapshotMaxAge)
	asstRequest(t, h, http.MethodGet, "/assistant/ops", "")
	if src.groupReads != 2 || src.hostReads != 2 {
		t.Fatalf("render after the window: projection reads=%d, host reads=%d; want 2 and 2", src.groupReads, src.hostReads)
	}
}

// The production catalog answers from the same projection the ops API serves:
// the digest of a card the ops API issued is current, and the host check
// matches the inventory. No fake of the projection is involved.
func TestOpsAssistantCatalogMatchesOpsAPIDigest(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7001"))
	srcs := opsSources{Findings: env.svc.store, LastResults: opsWireLastResults(t, opsWireSim),
		Traffic: opsWireTraffic(t), Now: func() time.Time { return opsWireNow }}
	hosts := func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{{ID: "web01", DisplayName: "web01", Environment: inventory.EnvProd,
			Criticality: inventory.CriticalityHigh}}, nil
	}
	groups, err := newOpsAssistantGroups(srcs, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cat := newOpsAssistantCatalog(hosts, groups, time.Now)

	_, items := opsWorkItems(t, opsWireHandler(t, env.db, srcs, opsconfig.DataClassLab))
	var digest string
	for _, it := range items {
		if it["kind"] == "fix" && it["ref"] == "web01/os" {
			digest, _ = it["digest"].(string)
		}
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("work list has no fix digest for web01/os")
	}
	if cur, ok := cat.CurrentDigest(opsnotes.KindFix, "web01/os"); !ok || cur != digest {
		t.Errorf("CurrentDigest(web01/os) = %q, %v; want the work list digest %q", cur, ok, digest)
	}
	if _, ok := cat.CurrentDigest(opsnotes.KindFix, "web02/os"); ok {
		t.Error("CurrentDigest of an unknown ref reports a group")
	}
	if _, ok := cat.CurrentDigest(opsnotes.KindSummary, "web01/os"); ok {
		t.Error("CurrentDigest of a summary reports a group")
	}
	if !cat.HostExists("web01") {
		t.Error("HostExists(web01) = false, want the inventory host")
	}
	if cat.HostExists("web02") {
		t.Error("HostExists(web02) = true for a host not in the inventory")
	}
	if fam, ok := cat.ActionFamily("package.install_security"); !ok || fam == "" {
		t.Errorf("ActionFamily(package.install_security) = %q, %v; want a family", fam, ok)
	}
}

// A failed read of the inventory or the projection denies: HostExists is false
// (no step button) and CurrentDigest reports no group (card outdated).
func TestOpsAssistantCatalogFailedReadsDenyTheCard(t *testing.T) {
	failHosts := func(context.Context) ([]inventory.Host, error) { return nil, errors.New("store down") }
	failGroups := func(context.Context) ([]opsfacts.Group, error) { return nil, errors.New("store down") }
	cat := newOpsAssistantCatalog(failHosts, failGroups, time.Now)
	if cat.HostExists("web-1") {
		t.Error("HostExists after a failed read = true, want false")
	}
	if _, ok := cat.CurrentDigest(opsnotes.KindFix, "web-1/os"); ok {
		t.Error("CurrentDigest after a failed read reports a group")
	}
}

// The question text stays out of the server log: neither the stored question
// nor the trigger path logs it, whether the trigger was touched or not.
func TestOpsQuestionTextStaysOutOfTheLog(t *testing.T) {
	const secret = "secret-question-text-7f3a"
	for _, name := range []string{"touched", "not-touched"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ops-trigger")
			if name == "not-touched" {
				path = filepath.Join(t.TempDir(), "missing", "ops-trigger")
			}
			var logs bytes.Buffer
			lg := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			trig := newOpsTrigger(fakeAsstSettings{enabled: true}, path, time.Now, lg)
			store := &fakeAsstStore{}
			uh, err := ui.New(withOpsAssistant(ui.Options{PublicOrigin: testAsstOrigin, Log: lg},
				asstWiring(t, store, true, trig.Touch)))
			if err != nil {
				t.Fatal(err)
			}
			rec := asstRequest(t, uh.Handler(), http.MethodPost, "/assistant/ops/questions", "question="+secret)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("POST questions = %d, want 303", rec.Code)
			}
			if len(store.questions) != 1 {
				t.Fatalf("stored %d questions, want 1", len(store.questions))
			}
			if strings.Contains(logs.String(), secret) {
				t.Fatalf("server log holds the question text: %s", logs.String())
			}
		})
	}
}

// The run holder takes only an ops API handler that reports runs.
func TestOpsRunHolderIgnoresForeignHandlers(t *testing.T) {
	var h opsRunHolder
	h.set(nil)
	h.set(http.NotFoundHandler())
	if _, ok := h.last(); ok {
		t.Fatal("holder reports a run without a run reader")
	}
}
