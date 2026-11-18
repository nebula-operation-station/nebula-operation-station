// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// fakeOpSuggestStore answers Step from a fixed map keyed by "<note>.<index>".
type fakeOpSuggestStore struct {
	steps map[string]opsnotes.Step
	calls int
}

func (f *fakeOpSuggestStore) Step(_ context.Context, noteID int64, index int) (opsnotes.Step, bool, error) {
	f.calls++
	s, ok := f.steps[strconv.FormatInt(noteID, 10)+"."+strconv.Itoa(index)]
	return s, ok, nil
}

// suggestHandler builds a handler with the fake operations, a notes store
// and an admin check that answers admin for every user.
func suggestHandler(t *testing.T, ops ui.Operations, st ui.OperationSuggestionStore, admin bool) http.Handler {
	t.Helper()
	o := ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web", DisplayName: "Web"}, {ID: "new"}}, nil
		},
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:x"}}, nil
		},
	}
	if st != nil {
		o.OperationSuggestions = &ui.OperationSuggestions{
			Store:   st,
			IsAdmin: func(context.Context, string) (bool, error) { return admin, nil },
		}
	}
	return newTestHandler(t, o).Handler()
}

func getPage(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestSuggestionPrefillOpensEmptyFormWithoutRunning(t *testing.T) {
	f := &fakeOps{}
	st := &fakeOpSuggestStore{steps: map[string]opsnotes.Step{"7.1": {NoteID: 7, Index: 1, ActionID: "core.facts", HostID: "web"}}}
	h := suggestHandler(t, f, st, true)
	// action=, host= and param= in the same URL are ignored.
	code, body := getPage(t, h, "/operations/new?suggestion=7.1&action=docker.stop&host=new&param=container=abc")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	for _, want := range []string{
		`name="suggestion" value="7.1"`,
		`value="core.facts" checked`,
		`value="web" checked`,
		"Aus einem Agenten-Vorschlag geöffnet. Diese Ausführung braucht eine Security-Key-Berührung.",
		"Opened from an agent suggestion. This execution needs a security-key touch.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, refuse := range []string{`value="docker.stop" checked`, `value="new" checked`, `value="abc"`, "planen", "Schedule"} {
		if strings.Contains(body, refuse) {
			t.Errorf("page contains %q", refuse)
		}
	}
	if len(f.createdCalls) != 0 || f.approved != "" {
		t.Fatalf("GET changed state: created %v approved %q", f.createdCalls, f.approved)
	}
}

func TestSuggestionPrefillRefusesWithFixedText(t *testing.T) {
	st := &fakeOpSuggestStore{steps: map[string]opsnotes.Step{"7.1": {NoteID: 7, ActionID: "core.facts", HostID: "web"}}}
	cases := []struct {
		name, path string
		store      ui.OperationSuggestionStore
		admin      bool
		lookups    int
	}{
		{"unknown step", "/operations/new?suggestion=7.9", st, true, 1},
		{"step zero", "/operations/new?suggestion=7.0", st, true, 0},
		{"step leading zero", "/operations/new?suggestion=7.01", st, true, 0},
		{"note leading zero", "/operations/new?suggestion=07.1", st, true, 0},
		{"plus sign", "/operations/new?suggestion=%2B7.1", st, true, 0},
		{"malformed", "/operations/new?suggestion=7", st, true, 0},
		{"sign", "/operations/new?suggestion=-7.1", st, true, 0},
		{"letters", "/operations/new?suggestion=x7.1", st, true, 0},
		{"non admin", "/operations/new?suggestion=7.1", st, false, 0},
		{"not configured", "/operations/new?suggestion=7.1", nil, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &fakeOpSuggestStore{steps: st.steps}
			var store ui.OperationSuggestionStore
			if tc.store != nil {
				store = s
			}
			f := &fakeOps{}
			code, body := getPage(t, suggestHandler(t, f, store, tc.admin), tc.path)
			if code != http.StatusNotFound || strings.Contains(body, "core.facts") {
				t.Fatalf("status %d body %q", code, body)
			}
			if s.calls != tc.lookups || len(f.createdCalls) != 0 {
				t.Fatalf("lookups %d (want %d), created %v", s.calls, tc.lookups, f.createdCalls)
			}
		})
	}
}

func TestSuggestionPrefillNeedsTheStepsActionAndHost(t *testing.T) {
	st := &fakeOpSuggestStore{steps: map[string]opsnotes.Step{
		"7.2": {NoteID: 7, Index: 2, ActionID: "no.such.action", HostID: "web"},
		"7.3": {NoteID: 7, Index: 3, ActionID: "core.facts", HostID: "gone"},
	}}
	h := suggestHandler(t, &fakeOps{}, st, true)
	for _, path := range []string{"/operations/new?suggestion=7.2", "/operations/new?suggestion=7.3"} {
		if code, _ := getPage(t, h, path); code != http.StatusNotFound {
			t.Fatalf("%s: status %d", path, code)
		}
	}
}

func TestCreateForwardsSuggestionReference(t *testing.T) {
	f := &fakeOps{}
	h := suggestHandler(t, f, nil, true)
	code, _ := postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web"],"suggestion":"7.1"}`)
	if code != http.StatusOK || f.plan.SuggestionRef != "7.1" {
		t.Fatalf("%d ref %q", code, f.plan.SuggestionRef)
	}
	// Without a reference nothing is marked here; the executor's match
	// (ADR 0016 D9) decides on the server side.
	code, _ = postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web"]}`)
	if code != http.StatusOK || f.plan.SuggestionRef != "" {
		t.Fatalf("%d ref %q", code, f.plan.SuggestionRef)
	}
}

func TestCreateRefusesUnknownSuggestion(t *testing.T) {
	f := &fakeOps{createErr: executions.ErrUnknownSuggestion}
	h := suggestHandler(t, f, nil, true)
	code, body := postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web"],"suggestion":"9.9"}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "unknown agent suggestion") {
		t.Fatalf("%d %s", code, body)
	}
}

func TestContainerPageRefusesSuggestionReference(t *testing.T) {
	h, _ := ctrHandler(t, false)
	for _, path := range []string{"/inventory/containers?suggestion=7.1", "/inventory/containers?host=web-01&suggestion="} {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
	}
	// Without the parameter the page is unchanged.
	if code, _ := getPage(t, h.Handler(), "/inventory/containers"); code != http.StatusOK {
		t.Fatalf("plain container page: status %d", code)
	}
}
