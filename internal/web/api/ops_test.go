// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
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
)

const (
	oaTok     = "ops-agent-token-0123456789abcdef"
	opsVulnTok = "vuln-token-0123456789abcdef-x"
	opsReadTok = "read-token-0123456789abcdef-xy"
	opsRemote  = "127.0.0.1:40000"
	opsHost    = "h-web01"
	opsHostIP  = "192.168.0.10"
	opsPrint   = "SHA256:abcdefFINGERPRINTxyz"
	opsUser    = "alice-admin"
	opsLogLine = "journal: sshd accepted password for alice-admin"
)

var opsT0 = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)

// fakeOpsSettings serves a fixed settings row.
type fakeOpsSettings struct {
	row opsconfig.Row
	err error
}

func (f *fakeOpsSettings) Get(context.Context) (opsconfig.Row, error) { return f.row, f.err }

// fakeOpsFacts serves fixed groups, fleet counts and host IDs.
type fakeOpsFacts struct {
	groups []opsfacts.Group
	fleet  opsfacts.ExternalProjection
	hosts  []string
	err    error
}

func (f *fakeOpsFacts) EligibleGroups(context.Context) ([]opsfacts.Group, error) {
	return f.groups, f.err
}
func (f *fakeOpsFacts) External(context.Context) (opsfacts.ExternalProjection, error) {
	return f.fleet, f.err
}
func (f *fakeOpsFacts) Hosts(context.Context) ([]string, error) { return f.hosts, f.err }

// labGroup builds one eligible group of host with one finding.
func labGroup(host, vuln string, tier opsfacts.Tier, kev bool, score int) opsfacts.Group {
	key := host + "/os"
	return opsfacts.Group{
		Key:    key,
		Digest: "d-" + host + "-" + vuln,
		Projection: opsfacts.LabProjection{
			Group:    key,
			Host:     opsfacts.LabHost{ID: host, Label: "Web 01", Environment: "lab", Criticality: "high"},
			Exposure: "internal",
			Findings: []opsfacts.LabFinding{{VulnID: vuln, Package: "openssl", Installed: "3.0.1", Fixed: "3.0.2",
				Tier: tier, Score: score, KEV: kev, Fix: opsfacts.FixStatus("fix_verified")}},
			Counts:     opsfacts.Counts{High: 1},
			Candidates: []opsfacts.Candidate{{Key: "c1", Action: "package.install_security", HostID: host}},
		},
	}
}

// opsEnv is the server side of the ops API: the mounted handler, the fakes,
// and a real notes store in a temporary directory.
type opsEnv struct {
	h        http.Handler
	settings *fakeOpsSettings
	facts    *fakeOpsFacts
	notes    *opsnotes.Store
	accepted []opsnotes.Note
	log      *bytes.Buffer
	now      time.Time
}

func oaTokens() []serverconfig.APIToken {
	return []serverconfig.APIToken{
		{Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken(oaTok),
			Scopes: []string{serverconfig.ScopeOpsRead, serverconfig.ScopeOpsNotesWrite}},
		{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(opsVulnTok),
			Scopes: []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite}},
		{Name: "reader", SHA256: api.HashToken(opsReadTok), Scopes: []string{serverconfig.ScopeInventoryRead}},
	}
}

func newOpsEnv(t *testing.T) *opsEnv {
	t.Helper()
	e := &opsEnv{now: opsT0, log: &bytes.Buffer{}}
	clock := func() time.Time { return e.now }
	// The notes store refuses a directory that is not private (0700).
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := opsnotes.Open(filepath.Join(dir, "notes.db"), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e.notes = st
	e.settings = &fakeOpsSettings{row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: true,
		BaseURL: "http://lab-llm.example.invalid/v1", Model: "qwen", DataClass: opsconfig.DataClassLab,
		Language: opsconfig.LanguageDE, Instructions: "Be brief."}, Version: 4}}
	e.facts = &fakeOpsFacts{hosts: []string{opsHost}}
	ops, err := api.NewOps(api.OpsOptions{
		Tokens:   oaTokens(),
		Settings: e.settings,
		Facts:    e.facts,
		Notes:    e.notes,
		OnNoteAccepted: func(n opsnotes.Note) {
			e.accepted = append(e.accepted, n)
		},
		CorePrompt: "core prompt v1",
		Log:        slog.New(slog.NewJSONHandler(e.log, nil)),
		Now:        clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	apiH, err := api.New(api.Options{Tokens: oaTokens(), Hosts: func(context.Context) ([]inventory.Host, error) { return nil, nil },
		Operations: fakeOps{}, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	e.h = api.MountOps(apiH, ops)
	return e
}

// resp is one answer: status and body.
type opsResp struct {
	code int
	body string
}

func opsDo(h http.Handler, method, path, tok, ctype, body string) opsResp {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = opsRemote
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return opsResp{code: rec.Code, body: rec.Body.String()}
}

func opsGet(h http.Handler, path, tok string) opsResp {
	return opsDo(h, http.MethodGet, path, tok, "", "")
}

func opsPost(h http.Handler, path, tok, body string) opsResp {
	return opsDo(h, http.MethodPost, path, tok, "application/json", body)
}

// workItems decodes the work list of a 200 answer.
func workItems(t *testing.T, r opsResp) []map[string]any {
	t.Helper()
	if r.code != http.StatusOK {
		t.Fatalf("work: status %d, body %s", r.code, r.body)
	}
	var v struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(r.body), &v); err != nil {
		t.Fatalf("work: %v in %s", err, r.body)
	}
	return v.Items
}

// noteBody is a fix note for group with a step on its own host.
func noteBody(ref, digest, action, host string) string {
	return fmt.Sprintf(`{"kind":"fix","ref":%q,"digest":%q,"summary":"Update openssl.","urgency":"soon",`+
		`"steps":[{"action_id":%q,"host_id":%q,"why":"fixes the finding"}],"mitigations":["Restrict port 443."]}`,
		ref, digest, action, host)
}

func TestOpsRoutesOnlyToTheOpsToken(t *testing.T) {
	e := newOpsEnv(t)
	for _, path := range []string{"/api/v1/ops/work", "/api/v1/ops/agent-config"} {
		if r := opsGet(e.h, path, opsVulnTok); r.code != http.StatusUnauthorized {
			t.Errorf("vuln token on %s: %d, want 401", path, r.code)
		}
		if r := opsGet(e.h, path, opsReadTok); r.code != http.StatusUnauthorized {
			t.Errorf("read token on %s: %d, want 401", path, r.code)
		}
		if r := opsGet(e.h, path, ""); r.code != http.StatusUnauthorized {
			t.Errorf("no token on %s: %d, want 401", path, r.code)
		}
	}
	if r := opsPost(e.h, "/api/v1/ops/notes", opsVulnTok, "{}"); r.code != http.StatusUnauthorized {
		t.Errorf("vuln token on notes: %d, want 401", r.code)
	}
}

func TestOpsTokenDoesNotReachOtherAPIs(t *testing.T) {
	e := newOpsEnv(t)
	for _, path := range []string{"/api/v1/hosts", "/api/v1/operations", "/api/v1/operations/x/logs",
		"/api/v1/vuln/inventory", "/api/v1/vuln/agent-config"} {
		r := opsGet(e.h, path, oaTok)
		if r.code == http.StatusOK {
			t.Errorf("ops token on %s: 200, want refused", path)
		}
	}
	if r := opsGet(e.h, "/api/v1/hosts", oaTok); r.code != http.StatusForbidden {
		t.Errorf("ops token on hosts: %d, want 403 (no inventory scope)", r.code)
	}
}

func TestOpsWrongScopeIsForbidden(t *testing.T) {
	e := newOpsEnv(t)
	readOnly := []serverconfig.APIToken{{Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken(oaTok),
		Scopes: []string{serverconfig.ScopeOpsRead}}}
	h, err := api.NewOps(api.OpsOptions{Tokens: readOnly, Settings: e.settings, Facts: e.facts, Notes: e.notes,
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	if r := opsPost(h, "/api/v1/ops/status", oaTok, `{"run_at":"2026-11-17T10:00:00Z"}`); r.code != http.StatusForbidden {
		t.Errorf("status with ops.read only: %d, want 403", r.code)
	}
	if r := opsPost(h, "/api/v1/ops/notes", oaTok, "{}"); r.code != http.StatusForbidden {
		t.Errorf("notes with ops.read only: %d, want 403", r.code)
	}
	writeOnly := []serverconfig.APIToken{{Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken(oaTok),
		Scopes: []string{serverconfig.ScopeOpsNotesWrite}}}
	h2, err := api.NewOps(api.OpsOptions{Tokens: writeOnly, Settings: e.settings, Facts: e.facts, Notes: e.notes,
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return e.now }})
	if err != nil {
		t.Fatal(err)
	}
	if r := opsGet(h2, "/api/v1/ops/work", oaTok); r.code != http.StatusForbidden {
		t.Errorf("work with ops.notes.write only: %d, want 403", r.code)
	}
}

func TestOpsAgentConfigServesSettingsAndPromptVersion(t *testing.T) {
	e := newOpsEnv(t)
	r := opsGet(e.h, "/api/v1/ops/agent-config", oaTok)
	if r.code != http.StatusOK {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(r.body), &v); err != nil {
		t.Fatal(err)
	}
	if v["enabled"] != true || v["data_class"] != opsconfig.DataClassLab || v["language"] != opsconfig.LanguageDE {
		t.Errorf("settings not served: %s", r.body)
	}
	if pv, _ := v["prompt_version"].(string); len(pv) != 64 {
		t.Errorf("prompt_version %q, want a sha256 hex", pv)
	}
	if v["version"] != float64(4) {
		t.Errorf("version %v, want 4", v["version"])
	}
	if strings.Contains(r.body, oaTok) {
		t.Error("agent config contains the token")
	}
}

func TestOpsAgentConfigPromptVersionChangesWithInstructions(t *testing.T) {
	e := newOpsEnv(t)
	first := opsPromptVersionOf(t, opsGet(e.h, "/api/v1/ops/agent-config", oaTok))
	e.settings.row.Instructions = "Be very brief."
	second := opsPromptVersionOf(t, opsGet(e.h, "/api/v1/ops/agent-config", oaTok))
	if first == second {
		t.Error("prompt_version did not change with the operator instructions")
	}
}

func opsPromptVersionOf(t *testing.T, r opsResp) string {
	t.Helper()
	var v struct {
		PromptVersion string `json:"prompt_version"`
	}
	if r.code != http.StatusOK {
		t.Fatalf("agent config: %d %s", r.code, r.body)
	}
	if err := json.Unmarshal([]byte(r.body), &v); err != nil {
		t.Fatal(err)
	}
	return v.PromptVersion
}

func TestOpsWorkDisabledIsEmpty(t *testing.T) {
	e := newOpsEnv(t)
	e.settings.row.Enabled = false
	e.facts.groups = []opsfacts.Group{labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, true, 90)}
	items := workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 0 {
		t.Errorf("disabled agent got %d items", len(items))
	}
}

func TestOpsWorkExternalServesOnlyFleetSummary(t *testing.T) {
	e := newOpsEnv(t)
	e.settings.row.DataClass = opsconfig.DataClassExternal
	e.facts.groups = []opsfacts.Group{labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, true, 90)}
	e.facts.fleet = opsfacts.ExternalProjection{Fleet: opsfacts.Counts{Critical: 1, High: 2, KEV: 1}}
	r := opsGet(e.h, "/api/v1/ops/work", oaTok)
	items := workItems(t, r)
	if len(items) != 1 || items[0]["kind"] != "summary" {
		t.Fatalf("external class: items %v, want one summary", items)
	}
	if _, has := items[0]["group"]; has {
		t.Error("external summary carries a group projection")
	}
	for _, leak := range []string{opsHost, "Web 01", "CVE-2026-0001", "openssl", "internal"} {
		if strings.Contains(r.body, leak) {
			t.Errorf("external work list contains %q: %s", leak, r.body)
		}
	}
}

func TestOpsWorkLabOrdersByTierKEVScoreAndCaps(t *testing.T) {
	e := newOpsEnv(t)
	e.facts.groups = []opsfacts.Group{
		labGroup("h-b", "CVE-2026-0002", opsfacts.TierHigh, false, 99),
		labGroup("h-a", "CVE-2026-0003", opsfacts.TierCritical, false, 70),
		labGroup("h-c", "CVE-2026-0004", opsfacts.TierCritical, true, 50),
		labGroup("h-d", "CVE-2026-0005", opsfacts.TierCritical, false, 80),
	}
	items := workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	var order []string
	for _, it := range items {
		if it["kind"] == "fix" {
			order = append(order, it["ref"].(string))
		}
	}
	want := []string{"h-c/os", "h-d/os", "h-a/os", "h-b/os"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order %v, want %v", order, want)
	}
	for i := 0; i < 30; i++ {
		e.facts.groups = append(e.facts.groups, labGroup(fmt.Sprintf("h-x%02d", i), "CVE-2026-1000", opsfacts.TierHigh, false, 10))
	}
	if n := len(workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))); n > api.MaxOpsWorkItems {
		t.Errorf("%d items, want at most %d", n, api.MaxOpsWorkItems)
	}
}

func TestOpsWorkDropsAnsweredDigest(t *testing.T) {
	e := newOpsEnv(t)
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	e.facts.groups = []opsfacts.Group{g}
	r := opsPost(e.h, "/api/v1/ops/notes", oaTok, noteBody(g.Key, g.Digest, "package.install_security", opsHost))
	if r.code != http.StatusCreated {
		t.Fatalf("note: %d %s", r.code, r.body)
	}
	for _, it := range workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok)) {
		if it["kind"] == "fix" {
			t.Errorf("answered group still due: %v", it)
		}
	}
	g.Digest = "changed"
	e.facts.groups = []opsfacts.Group{g}
	found := false
	for _, it := range workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok)) {
		found = found || it["kind"] == "fix"
	}
	if !found {
		t.Error("a changed digest must make the group due again")
	}
}

func TestOpsWorkCarriesNoAddressFingerprintUserOrLog(t *testing.T) {
	e := newOpsEnv(t)
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	g.Projection.Host.Label = "Web 01"
	e.facts.groups = []opsfacts.Group{g}
	r := opsGet(e.h, "/api/v1/ops/work", oaTok)
	for _, leak := range []string{opsHostIP, opsPrint, opsUser, opsLogLine, "ssh", "/etc/"} {
		if strings.Contains(r.body, leak) {
			t.Errorf("work list contains %q", leak)
		}
	}
}

func TestOpsNotesAcceptsCurrentDigestOnce(t *testing.T) {
	e := newOpsEnv(t)
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	e.facts.groups = []opsfacts.Group{g}
	body := noteBody(g.Key, g.Digest, "package.install_security", opsHost)
	r := opsPost(e.h, "/api/v1/ops/notes", oaTok, body)
	if r.code != http.StatusCreated {
		t.Fatalf("first note: %d %s", r.code, r.body)
	}
	if len(e.accepted) != 1 {
		t.Fatalf("OnNoteAccepted called %d times, want 1", len(e.accepted))
	}
	if r2 := opsPost(e.h, "/api/v1/ops/notes", oaTok, body); r2.code != http.StatusOK {
		t.Errorf("same note again: %d, want 200", r2.code)
	}
	if len(e.accepted) != 1 {
		t.Errorf("OnNoteAccepted called again for a no-op write")
	}
	stored, err := e.notes.List(context.Background())
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored notes %d (%v), want 1", len(stored), err)
	}
	if !strings.Contains(stored[0].Snapshot, "CVE-2026-0001") {
		t.Error("the server did not attach its own facts snapshot")
	}
}

func TestOpsNotesRejections(t *testing.T) {
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	tests := []struct {
		name     string
		body     string
		external bool
		code     int
	}{
		{"stale digest", noteBody(g.Key, "old-digest", "package.install_security", opsHost), false, http.StatusUnprocessableEntity},
		{"unknown action", noteBody(g.Key, g.Digest, "shell.exec", opsHost), false, http.StatusUnprocessableEntity},
		{"read-only action", noteBody(g.Key, g.Digest, "host.status", opsHost), false, http.StatusUnprocessableEntity},
		{"foreign host", noteBody(g.Key, g.Digest, "package.install_security", "h-other"), false, http.StatusUnprocessableEntity},
		{"unknown ref", noteBody("h-zzz/os", g.Digest, "package.install_security", opsHost), false, http.StatusUnprocessableEntity},
		{"parameters in a step", fmt.Sprintf(`{"kind":"fix","ref":%q,"digest":%q,"summary":"x","steps":[{"action_id":"package.install_security","host_id":%q,"parameters":{"pkg":"x"}}]}`,
			g.Key, g.Digest, opsHost), false, http.StatusBadRequest},
		{"unknown field", `{"kind":"fix","ref":"x","digest":"y","extra":1}`, false, http.StatusBadRequest},
		{"URL in text", fmt.Sprintf(`{"kind":"fix","ref":%q,"digest":%q,"summary":"see https://example.invalid/x"}`, g.Key, g.Digest), false, http.StatusBadRequest},
		{"control character", fmt.Sprintf(`{"kind":"fix","ref":%q,"digest":%q,"summary":"bad\u0007"}`, g.Key, g.Digest), false, http.StatusBadRequest},
		{"not JSON", "not json", false, http.StatusBadRequest},
		{"fix in external class", noteBody(g.Key, g.Digest, "package.install_security", opsHost), true, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpsEnv(t)
			e.facts.groups = []opsfacts.Group{g}
			if tc.external {
				e.settings.row.DataClass = opsconfig.DataClassExternal
			}
			r := opsPost(e.h, "/api/v1/ops/notes", oaTok, tc.body)
			if r.code != tc.code {
				t.Fatalf("status %d, want %d: %s", r.code, tc.code, r.body)
			}
			if len(e.accepted) != 0 {
				t.Error("a refused note reached OnNoteAccepted")
			}
			if n, _ := e.notes.List(context.Background()); len(n) != 0 {
				t.Errorf("a refused note was stored")
			}
		})
	}
}

func TestOpsNotesConflictIsRefused(t *testing.T) {
	e := newOpsEnv(t)
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	e.facts.groups = []opsfacts.Group{g}
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, noteBody(g.Key, g.Digest, "package.install_security", opsHost)); r.code != http.StatusCreated {
		t.Fatalf("first: %d", r.code)
	}
	other := strings.Replace(noteBody(g.Key, g.Digest, "package.install_security", opsHost), "fixes the finding", "other reason", 1)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, other); r.code != http.StatusConflict {
		t.Errorf("different body for the same digest: %d, want 409", r.code)
	}
}

func TestOpsNotesBodyLimitIsCheckedBeforeParsing(t *testing.T) {
	e := newOpsEnv(t)
	big := `{"kind":"fix","ref":"` + strings.Repeat("a", opsnotes.MaxNoteBytes) + `"}`
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, big); r.code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized note: %d, want 413", r.code)
	}
}

func TestOpsNotesNeedsJSONContent(t *testing.T) {
	e := newOpsEnv(t)
	if r := opsDo(e.h, http.MethodPost, "/api/v1/ops/notes", oaTok, "text/plain", "{}"); r.code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d, want 415", r.code)
	}
	if r := opsGet(e.h, "/api/v1/ops/notes", oaTok); r.code != http.StatusMethodNotAllowed {
		t.Errorf("GET notes: %d, want 405", r.code)
	}
}

func TestOpsNotesAcceptsSummaryOfTheDay(t *testing.T) {
	e := newOpsEnv(t)
	e.settings.row.DataClass = opsconfig.DataClassExternal
	e.facts.fleet = opsfacts.ExternalProjection{Fleet: opsfacts.Counts{High: 2}}
	items := workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))
	if len(items) != 1 {
		t.Fatalf("items %v", items)
	}
	ref, _ := items[0]["ref"].(string)
	digest, _ := items[0]["digest"].(string)
	body := fmt.Sprintf(`{"kind":"summary","ref":%q,"digest":%q,"text":"Two high findings."}`, ref, digest)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, body); r.code != http.StatusCreated {
		t.Fatalf("summary: %d %s", r.code, r.body)
	}
	if n := len(workItems(t, opsGet(e.h, "/api/v1/ops/work", oaTok))); n != 0 {
		t.Errorf("answered summary still due: %d items", n)
	}
	yesterday := fmt.Sprintf(`{"kind":"summary","ref":"2026-11-16","digest":%q,"text":"x"}`, digest)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, yesterday); r.code != http.StatusUnprocessableEntity {
		t.Errorf("summary for another day: %d, want 422", r.code)
	}
}

func TestOpsStatusRecordsOneRun(t *testing.T) {
	e := newOpsEnv(t)
	ok := `{"run_at":"2026-11-17T10:00:00Z","items_seen":3,"llm_calls":2,"discarded":1,"notes_written":2,"refusals":["llm_timeout"]}`
	if r := opsPost(e.h, "/api/v1/ops/status", oaTok, ok); r.code != http.StatusNoContent {
		t.Errorf("status: %d %s", r.code, r.body)
	}
	bad := []string{
		`{"run_at":"yesterday"}`,
		`{"run_at":"2026-11-17T10:00:00Z","items_seen":-1}`,
		`{"run_at":"2026-11-17T10:00:00Z","refusals":["because I said so"]}`,
		`{"run_at":"2026-11-17T10:00:00Z","refusals":["llm_timeout","llm_timeout","llm_timeout","llm_timeout","llm_timeout","llm_timeout","llm_timeout","llm_timeout","llm_timeout"]}`,
		`{"run_at":"2026-11-17T10:00:00Z","token":"x"}`,
	}
	for _, b := range bad {
		if r := opsPost(e.h, "/api/v1/ops/status", oaTok, b); r.code != http.StatusBadRequest {
			t.Errorf("status %s: %d, want 400", b, r.code)
		}
	}
	if strings.Contains(e.log.String(), "because I said so") {
		t.Error("audit log holds a refused reason text")
	}
}

func TestOpsNoRouteIsNotFound(t *testing.T) {
	e := newOpsEnv(t)
	if r := opsGet(e.h, "/api/v1/ops/nothing", oaTok); r.code != http.StatusNotFound {
		t.Errorf("unknown ops path: %d, want 404", r.code)
	}
}

func TestOpsAuditNeverHoldsNoteText(t *testing.T) {
	e := newOpsEnv(t)
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	e.facts.groups = []opsfacts.Group{g}
	body := strings.Replace(noteBody(g.Key, g.Digest, "package.install_security", opsHost), "Update openssl.", "SECRET-NOTE-TEXT-7731", 1)
	if r := opsPost(e.h, "/api/v1/ops/notes", oaTok, body); r.code != http.StatusCreated {
		t.Fatalf("note: %d %s", r.code, r.body)
	}
	if strings.Contains(e.log.String(), "SECRET-NOTE-TEXT-7731") {
		t.Error("audit log holds the note text")
	}
	if !strings.Contains(e.log.String(), `"kind":"api_read"`) && !strings.Contains(e.log.String(), `"kind":"ops_note"`) {
		t.Error("no audit entry for the note")
	}
}

// The ops handler never reaches the executor, SSH or a shell (ADR 0016 D2,
// D10): its files import none of those packages. Checked on the source, so
// a new import fails the build of this test.
func TestOpsFilesImportNoExecutorOrShell(t *testing.T) {
	forbidden := []string{"/executor", "/executorclient", "/executordb", "/sshtransport", "/hostrun",
		"/rpc", "/executions", "/vault", "os/exec", "/sshsig", "/permit", "/notify"}
	files, err := filepath.Glob("ops*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no ops source files: %v", err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(path, bad) {
					t.Errorf("%s imports %s", f, path)
				}
			}
		}
	}
}

// Errors from the sources must not leak as text to the agent.
func TestOpsSourceFailureIsGeneric(t *testing.T) {
	e := newOpsEnv(t)
	e.facts.err = errors.New("db path /var/lib/nebula/secret.db broke")
	r := opsGet(e.h, "/api/v1/ops/work", oaTok)
	if r.code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", r.code)
	}
	if strings.Contains(r.body, "secret.db") {
		t.Error("source error text reached the answer")
	}
}

// FuzzOpsNoteBody: no body makes the handler panic, leak or answer 5xx
// other than 502 (a source failure), and nothing reaches OnNoteAccepted
// without a successful store write.
func FuzzOpsNoteBody(f *testing.F) {
	g := labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)
	f.Add(noteBody(g.Key, g.Digest, "package.install_security", opsHost))
	f.Add(`{"kind":"fix"}`)
	f.Add(`{"kind":"fix","ref":"x","digest":"y","steps":[{"action_id":"a","host_id":"b"}]}`)
	f.Add(`{"kind":"summary","ref":"2026-11-17","digest":"x","text":"‮"}`)
	f.Add("\xff\xfe")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 2*opsnotes.MaxNoteBytes {
			t.Skip()
		}
		e := newOpsEnv(t)
		e.facts.groups = []opsfacts.Group{g}
		r := opsPost(e.h, "/api/v1/ops/notes", oaTok, body)
		switch r.code {
		case http.StatusCreated, http.StatusOK, http.StatusBadRequest, http.StatusForbidden,
			http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity,
			http.StatusUnsupportedMediaType, http.StatusTooManyRequests:
		default:
			t.Fatalf("status %d for %q: %s", r.code, body, r.body)
		}
		if r.code != http.StatusCreated && len(e.accepted) != 0 {
			t.Fatalf("refused (%d) note reached OnNoteAccepted", r.code)
		}
	})
}

// FuzzOpsQuery: the work list takes no query parameters; any query string
// gets a clean answer and never changes the list.
func FuzzOpsQuery(f *testing.F) {
	f.Add("")
	f.Add("limit=1000000")
	f.Add("kind=fix&ref=../../etc")
	f.Add("%zz=%")
	f.Fuzz(func(t *testing.T, q string) {
		e := newOpsEnv(t)
		e.facts.groups = []opsfacts.Group{labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)}
		plain := opsGet(e.h, "/api/v1/ops/work", oaTok)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ops/work", nil)
		req.URL.RawQuery = q
		req.RemoteAddr = opsRemote
		req.Header.Set("Authorization", "Bearer "+oaTok)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code >= 500 && rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d for query %q", rec.Code, q)
		}
		if rec.Code == http.StatusOK && rec.Body.String() != plain.body {
			t.Fatalf("query %q changed the work list", q)
		}
	})
}
