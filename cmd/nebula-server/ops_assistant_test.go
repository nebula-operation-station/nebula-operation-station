// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
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

// Without the ops token nothing is wired: the Ops routes answer 404.
func TestOpsRoutesAnswer404WithoutOpsToken(t *testing.T) {
	uh, err := ui.New(ui.Options{PublicOrigin: testAsstOrigin})
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
