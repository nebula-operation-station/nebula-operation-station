// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficingest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

func TestParseSuggestionRefAcceptsOnlyPositivePairs(t *testing.T) {
	tests := []struct {
		ref string
		ok  bool
		id  int64
		idx int
	}{
		{"3.1", true, 3, 1},
		{"120.6", true, 120, 6},
		{"0.1", false, 0, 0},
		{"3.0", false, 0, 0},
		{"3.01", false, 0, 0},
		{"03.1", false, 0, 0},
		{"+3.1", false, 0, 0},
		{"3.-1", false, 0, 0},
		{"3.", false, 0, 0},
		{".1", false, 0, 0},
		{"x.1", false, 0, 0},
		{"31", false, 0, 0},
		{"", false, 0, 0},
		{"3.1.2", false, 0, 0},
	}
	for _, tc := range tests {
		id, idx, ok := parseSuggestionRef(tc.ref)
		if ok != tc.ok || id != tc.id || idx != tc.idx {
			t.Errorf("parseSuggestionRef(%q) = %d, %d, %v; want %d, %d, %v", tc.ref, id, idx, ok, tc.id, tc.idx, tc.ok)
		}
	}
}

func TestOpsNotesFileIsPrivateAndUnknownRefsAreNotSuggestions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := newOpsNotes(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	fi, err := os.Stat(filepath.Join(dir, opsNotesDir, opsNotesFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("notes file mode %v, want private (0600)", fi.Mode().Perm())
	}
	idx := opsSuggestions{notes: st}
	if _, _, _, ok := idx.Step("999.1"); ok {
		t.Error("an unknown note resolved as a suggestion")
	}
	if _, ok := idx.Match("os-update", "h-web01"); ok {
		t.Error("an empty store matched a suggestion")
	}
	if fam, ok := idx.Family("package.install_security"); !ok || fam != "os-update" {
		t.Errorf("Family of an allowlisted action: %q, %v", fam, ok)
	}
	if _, ok := idx.Family("shell.exec"); ok {
		t.Error("a non-allowlisted action has a family")
	}
}

func TestNoOpsTokenMeansNoOpsAPI(t *testing.T) {
	cfg := serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{
		{Name: "reader", SHA256: "00", Scopes: []string{serverconfig.ScopeInventoryRead}}}}
	h, err := newOpsAPI(cfg, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, opsSources{})
	if err != nil {
		t.Fatal(err)
	}
	if h != nil {
		t.Error("an ops API without an ops token")
	}
}

// opsWireSim is the apt simulation of web01: the open openssl finding of
// vtRecord has a verified Debian security update here.
const opsWireSim = "Inst openssl [3.0.15-1~deb12u1] (3.0.16-1~deb12u1 Debian-Security:12/stable-security [amd64])\n" +
	"Conf openssl (3.0.16-1~deb12u1 Debian-Security:12/stable-security [amd64])"

// opsWireLastResults returns a LastResults source with one package.list_updates
// result of web01, built as osdebian.ParseUpdates reads it (apt-simulate-v1).
func opsWireLastResults(t *testing.T, sim string) func(context.Context, string) (map[string]executions.LastResultRow, error) {
	t.Helper()
	// The candidate stanza gives the source package of the candidate version
	// (apt-cache show); without it the update is not verified.
	const cands = "Package: openssl\nVersion: 3.0.16-1~deb12u1\nSource: openssl\n\n"
	doc, err := json.Marshal(map[string]any{"format": "apt-simulate-v1", "mode": "upgrade",
		"simulate": base64.StdEncoding.EncodeToString([]byte(sim)), "reboot_required": false,
		"reboot_pkgs": "", "lists_mtime": 1791960000, "proxmox": false,
		"candidates": base64.StdEncoding.EncodeToString([]byte(cands))})
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, action string) (map[string]executions.LastResultRow, error) {
		if action != "package.list_updates" {
			return nil, nil
		}
		return map[string]executions.LastResultRow{"web01": {Result: doc, FinishedAt: opsWireNow.Add(-time.Hour)}}, nil
	}
}

// opsWireNow is the clock of the wired server: the listener facts below are
// fresh at this time.
var opsWireNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// opsWireTraffic returns the net.facts source of web01: one fresh stored result
// with a listening port, so the host is known to have listeners.
func opsWireTraffic(t *testing.T) trafficingest.Source {
	t.Helper()
	return opsListenerSource{ok: true, res: trafficingest.Result{
		ExecutionID: "e1", Host: "web01", Finished: opsWireNow.Add(-time.Minute),
		Data: opsNetFactsDoc(t, "tcp   LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"),
	}}
}

// opsWireHandler is the ops API as the server wires it: real notes store and
// settings row in db (server.db), the stored data class dataClass, and srcs as
// the projection's sources. One inventory host, web01.
func opsWireHandler(t *testing.T, db *sql.DB, srcs opsSources, dataClass string) http.Handler {
	t.Helper()
	notes, err := newOpsNotes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notes.Close() })
	settings, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	want := opsconfig.Settings{Enabled: true, BaseURL: "https://192.168.10.20:8080/v1", Model: "qwen",
		DataClass: dataClass, Language: opsconfig.LanguageDE}
	if _, err := settings.Save(context.Background(), "admin", want, 0, docChunkAudit{db: db}); err != nil {
		t.Fatal(err)
	}
	cfg := serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{{
		Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken(docChunkTok),
		Scopes: []string{serverconfig.ScopeOpsRead, serverconfig.ScopeOpsNotesWrite}}}}
	hosts := func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{{ID: "web01", DisplayName: "web01", Environment: inventory.EnvProd,
			Criticality: inventory.CriticalityHigh}}, nil
	}
	srcs.Now = func() time.Time { return opsWireNow }
	h, err := newOpsAPI(cfg, db, notes, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, srcs)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("newOpsAPI returned no handler for an ops token")
	}
	return h
}

// opsWorkItems decodes the work list of h and returns its items.
func opsWorkItems(t *testing.T, h http.Handler) (string, []map[string]any) {
	t.Helper()
	code, body := docChunkDo(h, http.MethodGet, api.OpsWorkPath, "")
	if code != http.StatusOK {
		t.Fatalf("work: %d %s", code, body)
	}
	var v struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("work: %v in %s", err, body)
	}
	return body, v.Items
}

// TestOpsWorkCarriesStoredOpenCriticalAsFixItem: an open critical finding
// stored for an inventory host reaches the lab work list as a fix item with
// its group digest and the verified update candidate; a fix note with that
// digest is accepted. In class external the same finding gives no fix item.
func TestOpsWorkCarriesStoredOpenCriticalAsFixItem(t *testing.T) {
	env := newVTEnv(t)
	env.startAndSubmit(t, opsCriticalRecord("CVE-2026-7001"))
	srcs := opsSources{Findings: env.svc.store, LastResults: opsWireLastResults(t, opsWireSim),
		Traffic: opsWireTraffic(t)}

	h := opsWireHandler(t, env.db, srcs, opsconfig.DataClassLab)
	body, items := opsWorkItems(t, h)
	var digest string
	for _, it := range items {
		if it["kind"] == "fix" && it["ref"] == "web01/os" {
			digest, _ = it["digest"].(string)
		}
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("work list has no fix item for web01/os with a sha256 digest: %s", body)
	}
	if !strings.Contains(body, `"package.install_security"`) {
		t.Fatalf("fix item has no package.install_security candidate: %s", body)
	}

	note := fmt.Sprintf(`{"kind":"fix","ref":"web01/os","digest":%q,"summary":"Sicherheitsupdate für openssl einspielen.","urgency":"hoch","steps":[{"action_id":"package.install_security","host_id":"web01","why":"CVE-2026-7001 ist offen."}]}`, digest)
	if code, b := docChunkDo(h, http.MethodPost, api.OpsNotesPath, note); code != http.StatusCreated {
		t.Fatalf("fix note: %d %s, want 201", code, b)
	}

	// The external server is its own database: each server.db holds one
	// settings row, so the class cannot be changed in place here.
	extEnv := newVTEnv(t)
	extEnv.startAndSubmit(t, opsCriticalRecord("CVE-2026-7001"))
	extSrcs := opsSources{Findings: extEnv.svc.store, LastResults: opsWireLastResults(t, opsWireSim),
		Traffic: opsWireTraffic(t)}
	ext := opsWireHandler(t, extEnv.db, extSrcs, opsconfig.DataClassExternal)
	extBody, extItems := opsWorkItems(t, ext)
	for _, it := range extItems {
		if it["kind"] == "fix" {
			t.Fatalf("class external carries a fix item: %s", extBody)
		}
	}
	var summaries int
	for _, it := range extItems {
		if it["kind"] == "summary" {
			summaries++
		}
	}
	if summaries != 1 {
		t.Fatalf("class external: %d summary items, want 1: %s", summaries, extBody)
	}
}

// TestOpsWorkWithoutStoredFindingsIsTheZeroSummary: a server with no package
// inventory (no finding stored) gives the day's summary with zero counters and
// status 200; no group and no question is due.
func TestOpsWorkWithoutStoredFindingsIsTheZeroSummary(t *testing.T) {
	env := newVTEnv(t)
	srcs := opsSources{Findings: env.svc.store, LastResults: opsWireLastResults(t, opsWireSim),
		Traffic: opsWireTraffic(t)}
	h := opsWireHandler(t, env.db, srcs, opsconfig.DataClassLab)
	body, items := opsWorkItems(t, h)
	if len(items) != 1 {
		t.Fatalf("items = %d, want exactly the summary: %s", len(items), body)
	}
	if items[0]["kind"] != "summary" {
		t.Fatalf("item kind = %v, want summary: %s", items[0]["kind"], body)
	}
	fleet, ok := items[0]["fleet"].(map[string]any)
	if !ok {
		t.Fatalf("summary has no fleet counters: %s", body)
	}
	for k, v := range fleet {
		if n, ok := v.(float64); !ok || n != 0 {
			t.Errorf("fleet counter %s = %v, want 0", k, v)
		}
	}
}
