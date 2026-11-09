// SPDX-License-Identifier: AGPL-3.0-or-later

package jewels_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	store "github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/jewels"
)

const origin = "https://nebula.example.org"

type dir []jewels.Subject

func (d dir) Subjects(context.Context) ([]jewels.Subject, error) { return d, nil }

type env struct {
	h     http.Handler
	store *store.Store
	logs  *bytes.Buffer
	admin bool
}

func newEnv(t *testing.T, subjects dir) *env {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{logs: &bytes.Buffer{}, admin: true}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	e.store, err = store.New(db, slog.New(slog.NewJSONHandler(e.logs, nil)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	h, err := jewels.New(jewels.Options{
		Store:        e.store,
		Directory:    subjects,
		Authorize:    func(*http.Request) bool { return e.admin },
		User:         func(*http.Request) string { return "maintainer" },
		PublicOrigin: origin,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h.Handler()
	return e
}

func (e *env) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func (e *env) post(t *testing.T, path, origin string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) list(t *testing.T) []store.Jewel {
	t.Helper()
	l, err := e.store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

var lab = dir{
	{Node: "host:exec", Label: "executor"},
	{Node: "dev:fw", Label: "edge firewall"},
	{Node: "pve:n1", Label: "node one"},
}

func TestNewRequiresChecks(t *testing.T) {
	s := &store.Store{}
	ok := jewels.Options{Store: s, Directory: lab, Authorize: func(*http.Request) bool { return true },
		User: func(*http.Request) string { return "a" }, PublicOrigin: origin}
	if _, err := jewels.New(ok); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*jewels.Options){
		"no store":     func(o *jewels.Options) { o.Store = nil },
		"no directory": func(o *jewels.Options) { o.Directory = nil },
		"no authorize": func(o *jewels.Options) { o.Authorize = nil },
		"no user":      func(o *jewels.Options) { o.User = nil },
		"no origin":    func(o *jewels.Options) { o.PublicOrigin = "" },
	} {
		o := ok
		edit(&o)
		if _, err := jewels.New(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNonAdminIsRefused(t *testing.T) {
	e := newEnv(t, lab)
	e.admin = false
	if rec := e.get(t, "/vuln/jewels"); rec.Code != http.StatusForbidden {
		t.Errorf("GET = %d", rec.Code)
	}
	rec := e.post(t, "/vuln/jewels/mark", origin, url.Values{"node": {"host:exec"}, "role": {"executor_host"}, "impact": {"10"}})
	if rec.Code != http.StatusForbidden || len(e.list(t)) != 0 {
		t.Errorf("POST = %d, jewels = %v", rec.Code, e.list(t))
	}
}

func TestPostWithoutMatchingOriginIsRefused(t *testing.T) {
	e := newEnv(t, lab)
	form := url.Values{"node": {"host:exec"}, "role": {"executor_host"}, "impact": {"10"}}
	for _, o := range []string{"", "https://evil.example", "null", origin + "/"} {
		if rec := e.post(t, "/vuln/jewels/mark", o, form); rec.Code != http.StatusForbidden {
			t.Errorf("origin %q: %d", o, rec.Code)
		}
	}
	if len(e.list(t)) != 0 {
		t.Error("cross-origin mark stored")
	}
}

func TestConfirmStepOnlyPrefillsSuggestion(t *testing.T) {
	e := newEnv(t, lab)
	rec := e.get(t, "/vuln/jewels?node=dev%3Afw&role=firewall")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Confirm crown jewel", `name="impact"`, `value="10"`, "Suggested default weight for this role: 10", "only a suggestion"} {
		if !strings.Contains(body, want) {
			t.Errorf("confirm page misses %q", want)
		}
	}
	if len(e.list(t)) != 0 {
		t.Fatal("GET stored a jewel")
	}
	if strings.Contains(e.logs.String(), `"audit"`) {
		t.Error("GET wrote an audit line")
	}
}

func TestMarkNeedsExplicitWeight(t *testing.T) {
	e := newEnv(t, lab)
	for _, impact := range [][]string{nil, {""}, {"0"}, {"11"}, {"8.5"}, {"ten"}, {"100"}, {"8", "8"}} {
		form := url.Values{"node": {"pve:n1"}, "role": {"pve_node"}}
		if impact != nil {
			form["impact"] = impact
		}
		if rec := e.post(t, "/vuln/jewels/mark", origin, form); rec.Code != http.StatusBadRequest {
			t.Errorf("impact %q: %d", impact, rec.Code)
		}
	}
	if len(e.list(t)) != 0 {
		t.Fatal("jewel stored without a valid explicit weight")
	}
}

func TestMarkSavesAdminWeightAndAudits(t *testing.T) {
	e := newEnv(t, lab)
	rec := e.post(t, "/vuln/jewels/mark", origin, url.Values{"node": {"pve:n1"}, "role": {"pve_node"}, "impact": {"7"}, "reason": {"core"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/vuln/jewels?done=marked" {
		t.Fatalf("POST = %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	l := e.list(t)
	if len(l) != 1 || l[0].Impact != 7 || l[0].Role != store.RolePVENode || l[0].MarkedBy != "maintainer" {
		t.Fatalf("jewels = %+v", l)
	}
	logs := e.logs.String()
	for _, want := range []string{`"msg":"audit"`, `"kind":"crown_jewel_marked"`, `"user":"maintainer"`, `"suggested_impact":8`, `"suggestion_confirmed":false`} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit misses %s: %s", want, logs)
		}
	}
	body := e.get(t, "/vuln/jewels?done=marked").Body.String()
	for _, want := range []string{"Crown jewel saved.", "node one", "Proxmox node", "core"} {
		if !strings.Contains(body, want) {
			t.Errorf("page misses %q", want)
		}
	}
}

func TestMarkRejectsSubjectNotInInventory(t *testing.T) {
	e := newEnv(t, lab)
	for _, node := range []string{"host:other", "internet", "netbird", "unk:10.0.0.1"} {
		rec := e.post(t, "/vuln/jewels/mark", origin, url.Values{"node": {node}, "role": {"other"}, "impact": {"5"}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("node %q: %d", node, rec.Code)
		}
	}
	if len(e.list(t)) != 0 {
		t.Fatal("unknown subject stored")
	}
}

func TestPostFormLimits(t *testing.T) {
	e := newEnv(t, lab)
	req := httptest.NewRequest(http.MethodPost, "/vuln/jewels/mark", strings.NewReader(`{"node":"host:exec"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("JSON body: %d", rec.Code)
	}
	big := url.Values{"node": {"host:exec"}, "role": {"executor_host"}, "impact": {"10"}, "reason": {strings.Repeat("x", jewels.MaxFormBytes)}}
	if rec := e.post(t, "/vuln/jewels/mark", origin, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("big body: %d", rec.Code)
	}
	twice := url.Values{"node": {"host:exec", "dev:fw"}, "role": {"executor_host"}, "impact": {"10"}}
	if rec := e.post(t, "/vuln/jewels/mark", origin, twice); rec.Code != http.StatusBadRequest {
		t.Errorf("repeated node: %d", rec.Code)
	}
	long := url.Values{"node": {"host:exec"}, "role": {"executor_host"}, "impact": {"10"}, "reason": {strings.Repeat("x", store.MaxReasonBytes+1)}}
	if rec := e.post(t, "/vuln/jewels/mark", origin, long); rec.Code != http.StatusBadRequest {
		t.Errorf("long reason: %d", rec.Code)
	}
	if len(e.list(t)) != 0 {
		t.Fatal("rejected form stored")
	}
}

func TestUnmark(t *testing.T) {
	e := newEnv(t, lab)
	if rec := e.post(t, "/vuln/jewels/unmark", origin, url.Values{"node": {"host:exec"}}); rec.Code != http.StatusNotFound {
		t.Errorf("unmark unknown: %d", rec.Code)
	}
	e.post(t, "/vuln/jewels/mark", origin, url.Values{"node": {"host:exec"}, "role": {"executor_host"}, "impact": {"10"}})
	if rec := e.post(t, "/vuln/jewels/unmark", "https://evil.example", url.Values{"node": {"host:exec"}}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin unmark: %d", rec.Code)
	}
	rec := e.post(t, "/vuln/jewels/unmark", origin, url.Values{"node": {"host:exec"}, "reason": {"moved"}})
	if rec.Code != http.StatusSeeOther || len(e.list(t)) != 0 {
		t.Fatalf("unmark = %d, jewels = %v", rec.Code, e.list(t))
	}
	if !strings.Contains(e.logs.String(), `"kind":"crown_jewel_unmarked"`) {
		t.Error("unmark not audited")
	}
}

func TestHostileLabelsAreEscaped(t *testing.T) {
	hostile := `<script>alert(1)</script>"><img src=x onerror=alert(2)>`
	e := newEnv(t, dir{{Node: "host:evil", Label: hostile + "\x1b[31m"}})
	e.post(t, "/vuln/jewels/mark", origin, url.Values{"node": {"host:evil"}, "role": {"other"}, "impact": {"4"}, "reason": {hostile}})
	for _, target := range []string{"/vuln/jewels", "/vuln/jewels?node=host%3Aevil&role=other"} {
		body := e.get(t, target).Body.String()
		if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") || strings.Contains(body, "\x1b") {
			t.Errorf("%s renders hostile text unescaped", target)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s misses the escaped label", target)
		}
	}
}

func TestEntryClassesShownUnknownWithoutData(t *testing.T) {
	e := newEnv(t, lab)
	body := e.get(t, "/vuln/jewels").Body.String()
	for _, want := range []string{"Entry classes", "Internet", "NetBird peers", "unknown, not absent", "ADR 0010"} {
		if !strings.Contains(body, want) {
			t.Errorf("page misses %q", want)
		}
	}
}

func TestBadQueryAndUnknownConfirm(t *testing.T) {
	e := newEnv(t, lab)
	if rec := e.get(t, "/vuln/jewels?node=a&node=b"); rec.Code != http.StatusBadRequest {
		t.Errorf("repeated node: %d", rec.Code)
	}
	body := e.get(t, "/vuln/jewels?node=host%3Anope&role=nas").Body.String()
	if !strings.Contains(body, "Unknown subject") || strings.Contains(body, "Confirm crown jewel") {
		t.Error("confirm step for a subject not in the inventory")
	}
	body = e.get(t, "/vuln/jewels?node=host%3Aexec&role=router").Body.String()
	if !strings.Contains(body, "Unknown role") {
		t.Error("unknown role not reported")
	}
}

func TestChangeKeepsCurrentWeightInForm(t *testing.T) {
	e := newEnv(t, lab)
	e.post(t, "/vuln/jewels/mark", origin, url.Values{"node": {"pve:n1"}, "role": {"pve_node"}, "impact": {"3"}})
	body := e.get(t, "/vuln/jewels?node=pve%3An1&role=pve_node").Body.String()
	if !strings.Contains(body, `value="3"`) || !strings.Contains(body, "Current impact weight: 3") {
		t.Error("change form does not keep the current weight")
	}
}
