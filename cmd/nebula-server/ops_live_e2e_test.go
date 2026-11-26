// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// End to end test of the ops agent without network (ADR 0016 D1-D8, D12): one
// process holds the production server parts, the agent is the real
// nebula-ops-agent binary and the LLM is an HTTP fake on loopback. The path is
// a stored critical finding, the fix note the agent posts, the suggestion
// card of the Ops tab and the operation form the card opens.
//
// What is real: the vulnerability store (newVTEnv), the notes store
// (newOpsNotes), the settings row (opsconfig.Store), the ops API (newOpsAPI and
// api.MountOps), the UI with the server's wiring (applyOpsAssistant,
// withOperationSuggestions), the HTTP chain (webServer with the security
// middleware), the agent binary with its config file and the HTTP client.
//
// What is replaced, and why: the NOS session gate (no WebAuthn login here; it
// admits a request with the session cookie only), the operations service (no
// executor here; any call into it panics and fails the test), the container
// preview and the listener facts are the fixtures of ops_test.go, and the
// host list is one inventory host. These are the stores and services outside
// this path; the path itself runs unchanged.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Fixed values of the live test. The tokens are test fixtures; only their
// hashes reach the server configuration.
const (
	opsLiveOrigin     = "https://nebula.example.test"
	opsLiveAgentTok   = "ops-live-agent-token-0123456789abcdef"
	opsLiveCVE        = "CVE-2026-7101"
	opsLiveSession    = "nos_session"
	opsLiveSessionVal = "admin-session"
	opsLiveHost       = "web01"
	opsLiveAction     = "package.install_security"
	opsLivePkg        = "nginx"
	opsLiveInstalled  = "1.22.1-9"
	opsLiveFixed      = "1.22.1-9+deb12u1"
	// opsLiveBuildTimeout and opsLiveRunTimeout bound the build and one run.
	opsLiveBuildTimeout = 60 * time.Second
	opsLiveRunTimeout   = 60 * time.Second
)

// opsLiveGate is the session check in front of the pages. It admits a request
// that carries the session cookie and nothing else; the real gate is the WebAuthn
// login, which needs an authenticator this test does not have.
type opsLiveGate struct{}

// Wrap refuses a request without the session cookie, so a bearer token alone
// gets no page.
func (opsLiveGate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(opsLiveSession); err != nil || c.Value != opsLiveSessionVal {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// opsLiveNoOps stands in for the operations service. The suggestion form and
// the Ops tab must not reach it; an unexpected call panics, which net/http
// turns into a failed request.
type opsLiveNoOps struct{ ui.Operations }

// Catalog is the built-in action catalog, as executions.Service.Catalog gives
// it without runbooks. The form reads the catalog to label the prefilled action.
func (opsLiveNoOps) Catalog(context.Context) ([]actions.Action, error) {
	return append([]actions.Action(nil), actions.Builtin...), nil
}

// opsLiveLLM is the LLM endpoint: an OpenAI compatible chat API on loopback.
type opsLiveLLM struct {
	t     *testing.T
	mu    sync.Mutex
	kinds []string
}

// opsLiveChatReq is the part of a chat request the fake reads.
type opsLiveChatReq struct {
	Messages []struct {
		Content string `json:"content"`
	} `json:"messages"`
	ResponseFormat struct {
		JSONSchema struct {
			Name string `json:"name"`
		} `json:"json_schema"`
	} `json:"response_format"`
}

// opsLiveFix is the fix object the fake answers with: it chooses c1 and cites
// d1, both of which the prompt must offer.
const opsLiveFix = `{"summary":"Sicherheitsupdate für nginx auf web01 einspielen; CVE-2026-7101 ist offen und in KEV gelistet.",` +
	`"urgency":"diese Woche","steps":[{"candidate":"c1","why":"Das Debian-Sicherheitsupdate schließt CVE-2026-7101."}],` +
	`"citations":["d1"]}`

// opsLiveSummary is the fleet summary the fake answers with.
const opsLiveSummary = `{"text":"Ein offener kritischer Befund auf web01."}`

// ServeHTTP answers one chat call. It checks the request: the prompt offers the
// candidate c1 with its fixed label and the citation key d1, and the call
// carries no bearer credential (the agent has no LLM credential here).
func (l *opsLiveLLM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
		l.t.Errorf("LLM: %s %s, want POST /v1/chat/completions", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		l.t.Errorf("LLM: request carries an Authorization header, want none")
	}
	var req opsLiveChatReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || len(req.Messages) == 0 {
		l.t.Errorf("LLM: request body does not decode: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	prompt := req.Messages[0].Content
	name := req.ResponseFormat.JSONSchema.Name
	l.mu.Lock()
	l.kinds = append(l.kinds, name)
	l.mu.Unlock()
	var content string
	switch name {
	case "ops_fix":
		label, _ := opsfacts.Label(opsLiveAction)
		if !strings.Contains(prompt, "c1: "+label) {
			l.t.Errorf("LLM: fix prompt lacks the candidate line c1 with label %q", label)
		}
		if !strings.Contains(prompt, opsLiveHost) || !strings.Contains(prompt, opsLiveCVE) {
			l.t.Errorf("LLM: fix prompt lacks the host or the vulnerability ID")
		}
		if !strings.Contains(prompt, "d1") {
			l.t.Errorf("LLM: fix prompt lacks the documentation key d1")
		}
		content = opsLiveFix
	case "ops_summary":
		content = opsLiveSummary
	default:
		l.t.Errorf("LLM: unexpected schema %q", name)
		http.Error(w, "unexpected schema", http.StatusBadRequest)
		return
	}
	body, err := json.Marshal(map[string]any{"choices": []any{map[string]any{
		"index": 0, "finish_reason": "stop",
		"message": map[string]any{"role": "assistant", "content": content},
	}}})
	if err != nil {
		l.t.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// count returns the number of calls of schema name so far.
func (l *opsLiveLLM) count(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, k := range l.kinds {
		if k == name {
			n++
		}
	}
	return n
}

// total returns the number of all calls so far.
func (l *opsLiveLLM) total() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.kinds)
}

// opsLiveRecord is a critical open finding of nginx on web01: a KEV entry with
// a fixed version newer than the installed one. nginx is named in the handbook,
// so the documentation search of the agent finds a chunk for it (d1).
func opsLiveRecord(cve string) map[string]any {
	r := opsCriticalRecord(cve)
	r["component"] = map[string]any{"source_package": opsLivePkg, "source_version": opsLiveInstalled}
	r["fix"] = map[string]any{"state": "fixed", "version": opsLiveFixed}
	return r
}

// opsLiveInventory is the vulnerability agent's inventory of web01 with nginx
// as its one package. The shared test inventory (vtInventory) lists only
// openssl, and openssl is not named in the handbook, so no documentation chunk
// would match it.
type opsLiveInventory struct{ at time.Time }

// VulnSnapshot returns the one snapshot the run starts from.
func (i opsLiveInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
	if id != "" && id != "snap-1" {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	return api.VulnSnapshot{ID: "snap-1", Generation: 1, TakenAt: i.at, Subjects: []api.VulnSubject{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: opsLiveHost}, Ecosystem: "debian:bookworm", Complete: true,
			Kernel: &api.VulnKernel{Release: "6.1.0-28-amd64", Source: "linux", SourceVersion: "6.1.119-1"},
			Components: []api.VulnComponent{{Source: opsLivePkg, SourceVersion: opsLiveInstalled,
				Binaries: []api.VulnBinary{{Name: opsLivePkg, Version: opsLiveInstalled, Arch: "amd64"}}}}},
	}}, nil
}

// opsLiveVulnEnv is newVTEnv with the live inventory behind the vulnerability
// agent API: the store, the clock and the database are the same.
func opsLiveVulnEnv(t *testing.T) *vtEnv {
	t.Helper()
	env := newVTEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tok := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vtToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"192.0.2.10"}}
	vh, err := newVulnAPI(serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{tok}},
		env.svc, opsLiveInventory{at: env.clk.Now().Add(-time.Minute)}, vtAgentCfg{}, log)
	if err != nil || vh == nil {
		t.Fatalf("newVulnAPI = %v, %v", vh, err)
	}
	readOnly := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "read-only api", http.StatusTeapot) })
	env.api = api.Mount(readOnly, vh)
	return env
}

// opsLiveLastResults returns the stored update list of web01 in which the nginx
// fix is a verified Debian security update (apt-simulate-v1, as
// osdebian.ParseUpdates reads it).
func opsLiveLastResults(t *testing.T) func(context.Context, string) (map[string]executions.LastResultRow, error) {
	t.Helper()
	sim := "Inst " + opsLivePkg + " [" + opsLiveInstalled + "] (" + opsLiveFixed +
		" Debian-Security:12/stable-security [amd64])\n" +
		"Conf " + opsLivePkg + " (" + opsLiveFixed + " Debian-Security:12/stable-security [amd64])"
	cands := "Package: " + opsLivePkg + "\nVersion: " + opsLiveFixed + "\nSource: " + opsLivePkg + "\n\n"
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
		return map[string]executions.LastResultRow{opsLiveHost: {Result: doc, FinishedAt: opsWireNow.Add(-time.Hour)}}, nil
	}
}

// opsLiveBuildAgent builds ./cmd/nebula-ops-agent of the module with the go
// tool. The build runs without the module proxy and without cgo.
func opsLiveBuildAgent(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is needed to build the agent: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), opsLiveBuildTimeout)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "nebula-ops-agent")
	cmd := exec.CommandContext(ctx, goTool, "build", "-o", bin, "./cmd/nebula-ops-agent")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/nebula-ops-agent: %v\n%s", err, out)
	}
	return bin
}

// opsLiveRunAgent runs the agent once with cfgFile. The agent gets an empty
// environment (no proxy variables, no credentials) and its combined output is
// returned for the checks.
func opsLiveRunAgent(t *testing.T, bin, cfgFile string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), opsLiveRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-config", cfgFile, "run")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agent run: %v\n%s", err, out)
	}
	return string(out)
}

// TestOpsAgentEndToEndWithoutNetwork runs the whole path on loopback: a stored
// critical finding becomes a fix note by the agent binary, the Ops tab shows
// the suggestion card, and the card's link opens the prefilled operation form.
func TestOpsAgentEndToEndWithoutNetwork(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dataDir := t.TempDir()

	// The real vulnerability store, one critical open finding on web01. The
	// record is a KEV entry with a fixed version newer than the installed one.
	env := opsLiveVulnEnv(t)
	env.startAndSubmit(t, opsLiveRecord(opsLiveCVE))

	// The settings row: on, lab class, the fake LLM on loopback over plain http.
	llm := &opsLiveLLM{t: t}
	llmSrv := httptest.NewServer(llm)
	t.Cleanup(llmSrv.Close)
	settings, err := opsconfig.NewStore(env.db, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	want := opsconfig.Settings{Enabled: true, BaseURL: llmSrv.URL + "/v1", Model: "fake-model",
		AllowPlainHTTP: true, DataClass: opsconfig.DataClassLab, Language: opsconfig.LanguageDE}
	if _, err := settings.Save(ctx, "admin", want, 0, docChunkAudit{db: env.db}); err != nil {
		t.Fatal(err)
	}

	notes, err := newOpsNotes(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = notes.Close() })

	// The inventory has one host. The sources are the production ones, with the
	// stored update list and listener facts of ops_test.go.
	hosts := func(context.Context) ([]inventory.Host, error) {
		return []inventory.Host{{ID: opsLiveHost, DisplayName: opsLiveHost, Environment: inventory.EnvProd,
			Criticality: inventory.CriticalityHigh}}, nil
	}
	srcs := opsSources{Findings: env.svc.store, LastResults: opsLiveLastResults(t),
		Traffic: opsWireTraffic(t), Now: func() time.Time { return opsWireNow }}

	cfg := serverconfig.APIConfig{Enabled: true, Tokens: []serverconfig.APIToken{{
		Name: serverconfig.DefaultOpsTokenName, SHA256: api.HashToken(opsLiveAgentTok),
		Scopes:          []string{serverconfig.ScopeOpsRead, serverconfig.ScopeOpsNotesWrite},
		SourceAddresses: []string{"127.0.0.1"}}}}
	oh, err := newOpsAPI(cfg, env.db, notes, hosts, log, nil, srcs)
	if err != nil || oh == nil {
		t.Fatalf("newOpsAPI = %v, %v", oh, err)
	}

	// The UI with the server's wiring: the Ops tab and the suggestion form, the
	// admin rule of the server, and the session user of the tab.
	isAdmin := func(context.Context) bool { return true }
	runs := &opsRunHolder{}
	uiOpts := withOperationSuggestions(ui.Options{PublicOrigin: opsLiveOrigin, Log: log, Hosts: hosts,
		Operations: opsLiveNoOps{}}, notes, isAdmin)
	uiOpts, err = applyOpsAssistant(uiOpts, cfg, func() (opsAssistantWiring, error) {
		w, err := wireOpsAssistant(env.db, notes, isAdmin, srcs, hosts, runs, func() bool { return true }, log)
		w.user = func(*http.Request) (string, bool) { return "alice", true }
		return w, err
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ui.New(uiOpts)
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	runs.set(oh)

	// The HTTP chain of the server: security middleware, the session gate for the
	// pages, the ops API under its prefix. The read-only API is not part of this
	// path and answers 418 if reached.
	readOnly := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "read-only api", http.StatusTeapot)
	})
	srv, err := webServer(opsLiveOrigin, opsLiveGate{}, h.Handler(), api.MountOps(readOnly, oh))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	// The agent: its own files, the token in a 0600 file, a 0700 state dir.
	bin := opsLiveBuildAgent(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(opsLiveAgentTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgBytes, err := json.Marshal(map[string]string{"nos_base_url": ts.URL, "nos_token_file": tokenFile,
		"state_dir": stateDir})
	if err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgFile, cfgBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// First run: one fix call for the group (c1, d1), the summary call of the day,
	// the note stored (201, no Origin header from the agent) and the status reported.
	start := time.Now()
	out := opsLiveRunAgent(t, bin, cfgFile)
	if strings.Contains(out, opsLiveAgentTok) {
		t.Fatal("agent output contains the agent token")
	}
	if got := llm.count("ops_fix"); got != 1 {
		t.Fatalf("first run: %d fix calls, want 1; agent output:\n%s", got, out)
	}
	fixCalls := llm.count("ops_fix")
	firstTotal := llm.total()
	// The run may also answer the day's summary: one more call, never more.
	if got := llm.count("ops_summary"); got > 1 || firstTotal != fixCalls+got {
		t.Fatalf("first run: %d summary calls, %d calls in total; want at most one summary", got, firstTotal)
	}

	all, err := notes.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fix *opsnotes.Note
	for i := range all {
		if all[i].Kind == opsnotes.KindFix && all[i].Ref == opsLiveHost+"/os" {
			fix = &all[i]
		}
	}
	if fix == nil {
		t.Fatalf("no stored fix note for %s/os after the run; notes %+v", opsLiveHost, all)
	}
	step, ok, err := notes.Step(ctx, fix.ID, 1)
	if err != nil || !ok || step.ActionID != opsLiveAction || step.HostID != opsLiveHost {
		t.Fatalf("stored step 1 = %+v, %v, %v; want %s on %s", step, ok, err, opsLiveAction, opsLiveHost)
	}
	st, ok := runs.last()
	if !ok || st.LLMCalls < 1 {
		t.Fatalf("status of the run not reported: %+v, %v", st, ok)
	}

	// The Ops tab shows the card with host, step and the link to the form.
	adminReq := func(method, path string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: opsLiveSession, Value: opsLiveSessionVal})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(b)
	}
	code, card := adminReq(http.MethodGet, "/assistant/ops")
	if code != http.StatusOK {
		t.Fatalf("GET /assistant/ops as admin: %d", code)
	}
	ref := strconv.FormatInt(fix.ID, 10) + ".1"
	for _, want := range []string{opsLiveHost, "suggestion=" + ref} {
		if !strings.Contains(card, want) {
			t.Fatalf("suggestion card lacks %q", want)
		}
	}

	// The link opens the prefilled form with the banner.
	code, form := adminReq(http.MethodGet, "/operations/new?suggestion="+ref)
	if code != http.StatusOK {
		t.Fatalf("GET /operations/new?suggestion=%s as admin: %d", ref, code)
	}
	for _, want := range []string{"Opened from an agent suggestion", `name="suggestion" value="` + ref + `"`,
		opsLiveAction} {
		if !strings.Contains(form, want) {
			t.Fatalf("suggestion form lacks %q", want)
		}
	}

	// The agent token reaches none of the pages.
	for _, path := range []string{"/assistant/ops", "/operations/new?suggestion=" + ref} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+opsLiveAgentTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK || strings.Contains(string(b), "Opened from an agent suggestion") ||
			strings.Contains(string(b), "suggestion=") {
			t.Fatalf("agent token reached %s: %d", path, resp.StatusCode)
		}
	}

	// Second run: the group's digest is answered, so the group makes no call. The
	// summary of the day may stay answered too, so only the fix count is fixed.
	opsLiveRunAgent(t, bin, cfgFile)
	if got := llm.count("ops_fix"); got != fixCalls {
		t.Fatalf("second run: %d fix calls, want %d (digest answered)", got, fixCalls)
	}
	if got := llm.total(); got != firstTotal {
		t.Fatalf("second run: %d LLM calls, want 0 (every item answered)", got-firstTotal)
	}
	if elapsed := time.Since(start); elapsed > 90*time.Second {
		t.Fatalf("two runs took %s, want under 90s", elapsed)
	}
}
