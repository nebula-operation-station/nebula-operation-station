// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// End-to-end tests: a fake feed origin and a fake LLM on loopback TLS,
// and the real NOS vuln API (api.VulnHandler on a vulnstore in a
// temporary directory) behind an httptest TLS server. Synthetic data and
// synthetic credentials only.

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

const (
	testToken  = "nos-test-token-0123456789abcdef"
	testAPIKey = "llm-test-key-fedcba9876543210"
	testCVE    = "CVE-2026-1000"
)

// Feed fixtures: openssl on bookworm is fixed in 3.0.15-1~deb12u1.
const (
	dsaList     = "[10 Nov 2026] DSA-6001-1 openssl - security update\n\t{" + testCVE + "}\n\t[bookworm] - openssl 3.0.15-1~deb12u1\n"
	trackerJSON = `{"openssl":{"` + testCVE + `":{"releases":{"bookworm":{"status":"resolved","fixed_version":"3.0.15-1~deb12u1","urgency":"high"}}}}}`
	kevJSON     = `{"catalogVersion":"2026.11.10","dateReleased":"2026-11-10T06:00:00Z","count":1,"vulnerabilities":[` +
		`{"cveID":"` + testCVE + `","vendorProject":"OpenSSL","product":"OpenSSL","vulnerabilityName":"Test","dateAdded":"2026-11-09"}]}`
)

// feedServer serves the fixture feeds; status overrides a path's answer.
type feedServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status map[string]int
}

func newFeedServer(t *testing.T) *feedServer {
	t.Helper()
	fs := &feedServer{status: map[string]int{}}
	bodies := map[string]string{"/dsa": dsaList, "/tracker": trackerJSON, "/kev": kevJSON}
	fs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		st := fs.status[r.URL.Path]
		fs.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			return
		}
		b, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, b)
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) fail(path string, status int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.status[path] = status
}

// feeds returns the table entries of the fixture feeds, pointed at fs.
func (fs *feedServer) feeds(t *testing.T) []vulnfeed.Feed {
	t.Helper()
	var out []vulnfeed.Feed
	for name, path := range map[string]string{"debian-tracker": "/tracker", "debian-dsa": "/dsa", "cisa-kev": "/kev"} {
		f, ok := vulnfeed.FeedByName(name)
		if !ok {
			t.Fatalf("feed %s not in the table", name)
		}
		f.URL = fs.srv.URL + path
		if name == "debian-tracker" {
			f.ProxyCompanions = []string{"debian-dsa"}
		}
		out = append(out, f)
	}
	return out
}

func (fs *feedServer) fetcher(t *testing.T) *vulnfeed.Fetcher {
	t.Helper()
	al, err := vulnfeed.NewAllowlist([]string{fs.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(fs.srv.Certificate())
	f, err := vulnfeed.NewFetcher(vulnfeed.FetcherConfig{Allowlist: al, RootCAs: pool, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// fakeAgentSettings is the NOS-side store of the LLM settings.
type fakeAgentSettings struct {
	mu  sync.Mutex
	cfg vulnstore.AgentConfig
}

func (f *fakeAgentSettings) AgentConfig(context.Context) (vulnstore.AgentConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, nil
}

type fakeInventory struct{ snap api.VulnSnapshot }

func (f *fakeInventory) VulnSnapshot(_ context.Context, id string) (api.VulnSnapshot, error) {
	if id != "" && id != f.snap.ID {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	return f.snap, nil
}

type unconfirmed struct{}

func (unconfirmed) Classify(context.Context, vulnstore.Finding) (vulnstore.Class, error) {
	return vulnstore.ClassUnconfirmed, nil
}

var testSources = []vulnstore.Source{
	{ID: "debian-tracker", MaxAge: 72 * time.Hour},
	{ID: "dsa", MaxAge: 72 * time.Hour},
	{ID: "kev", MaxAge: 72 * time.Hour},
}

// nosServer is the real vuln API with request capture.
type nosServer struct {
	srv      *httptest.Server
	settings *fakeAgentSettings
	caFile   string
	tokFile  string
	mu       sync.Mutex
	posts    []string
	batches  [][]byte
	reqs     map[string]int
}

func newNOS(t *testing.T) *nosServer {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := func() time.Time { return t0 }
	st, err := vulnstore.New(db, vulnstore.Config{Sources: testSources, Classifier: unconfirmed{}, Now: now,
		Tier: func(vulnstore.Subject, vulnfinding.Record) vulnstore.Tier { return vulnstore.TierMedium }})
	if err != nil {
		t.Fatal(err)
	}
	inv := &fakeInventory{snap: api.VulnSnapshot{ID: "inv-1", Generation: 3, TakenAt: t0.Add(-time.Hour), Subjects: []api.VulnSubject{
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "web01"}, Ecosystem: "debian:bookworm", Complete: true,
			Components: []api.VulnComponent{
				{Source: "openssl", SourceVersion: "3.0.11-1~deb12u2", Binaries: []api.VulnBinary{{Name: "libssl3", Version: "3.0.11-1~deb12u2", Arch: "amd64"}}},
				{Source: "bash", SourceVersion: "5.2.15-2", Binaries: []api.VulnBinary{{Name: "bash", Version: "5.2.15-2+b7", Arch: "amd64"}}},
			}},
		{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: "odd01"}, Ecosystem: "plan9:4", Complete: true,
			Components: []api.VulnComponent{{Source: "rc", SourceVersion: "1.0", Binaries: []api.VulnBinary{{Name: "rc", Version: "1.0", Arch: "amd64"}}}}},
	}}}
	tok := serverconfig.APIToken{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(testToken),
		Scopes: []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite}, SourceAddresses: []string{"127.0.0.1"}}
	h, err := api.NewVuln(api.VulnOptions{Tokens: []serverconfig.APIToken{tok}, Inventory: inv, Store: st, Sources: testSources,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	settings := &fakeAgentSettings{cfg: vulnstore.DefaultAgentConfig()}
	full, err := h.WithAgentConfig(api.AgentConfigOptions{Source: settings, CorePrompt: agent.CorePrompt})
	if err != nil {
		t.Fatal(err)
	}
	n := &nosServer{settings: settings, reqs: map[string]int{}}
	n.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		n.reqs[r.Method+" "+r.URL.Path]++
		if r.Method == http.MethodPost {
			n.posts = append(n.posts, r.URL.Path)
			if strings.HasSuffix(r.URL.Path, "/findings") {
				n.batches = append(n.batches, body)
			}
		}
		n.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		full.ServeHTTP(w, r)
	}))
	t.Cleanup(n.srv.Close)
	n.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(n.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: n.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	n.tokFile = writeSecret(t, "token", testToken+"\n")
	return n
}

func (n *nosServer) setLLM(enabled bool, baseURL, model string) {
	n.settings.mu.Lock()
	defer n.settings.mu.Unlock()
	n.settings.cfg.LLMEnabled, n.settings.cfg.LLMBaseURL, n.settings.cfg.LLMModel = enabled, baseURL, model
	n.settings.cfg.Version++
}

func (n *nosServer) postCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.posts)
}

func (n *nosServer) count(key string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.reqs[key]
}

// sentRecords returns every finding record NOS received.
func (n *nosServer) sentRecords(t *testing.T) []vulnfinding.Record {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []vulnfinding.Record
	for _, b := range n.batches {
		var bj struct {
			Findings []vulnfinding.Record `json:"findings"`
		}
		if err := json.Unmarshal(b, &bj); err != nil {
			t.Fatal(err)
		}
		out = append(out, bj.Findings...)
	}
	return out
}

func writeSecret(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeLLM is an OpenAI-compatible endpoint that answers every call with a
// submit_assessment and records the Authorization header it got.
type fakeLLM struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls int
	auth  []string
	model []string
}

func newFakeLLM(t *testing.T) *fakeLLM {
	t.Helper()
	f := &fakeLLM{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.calls++
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.model = append(f.model, req.Model)
		f.mu.Unlock()
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		args := `{"text":"Backport not present; upgrade openssl.","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"tracker fixed version is newer"}`
		resp := map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": nil, "tool_calls": []any{
				map[string]any{"id": "call-1", "type": "function", "function": map[string]any{"name": "submit_assessment", "arguments": args}},
			}}}},
			"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 20},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLLM) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// env is one agent installation against the fakes.
type env struct {
	feeds *feedServer
	nos   *nosServer
	llm   *fakeLLM
	dir   string
	logs  *bytes.Buffer
	out   *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return &env{feeds: newFeedServer(t), nos: newNOS(t), llm: newFakeLLM(t), dir: t.TempDir(),
		logs: &bytes.Buffer{}, out: &bytes.Buffer{}}
}

func (e *env) config(t *testing.T) Config {
	t.Helper()
	nc, err := nosclient.New(nosclient.Config{BaseURL: e.nos.srv.URL, TokenFile: e.nos.tokFile, CAFile: e.nos.caFile,
		Now: func() time.Time { return t0 }, Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	ac, err := NewHTTPAgentConfig(AgentConfigOptions{BaseURL: e.nos.srv.URL, TokenFile: e.nos.tokFile, CAFile: e.nos.caFile})
	if err != nil {
		t.Fatal(err)
	}
	llmTransport := e.llm.srv.Client().Transport
	return Config{
		DataDir: e.dir, Feeds: e.feeds.feeds(t), Fetcher: e.feeds.fetcher(t), NOS: nc, AgentConfig: ac,
		LLM: LLMConfig{
			// The local endpoint is never reached in these tests: NOS serves
			// the URL unless a test says otherwise.
			BaseURL: "https://llm.invalid/v1", Model: "local-model", APIKeyFile: writeSecret(t, "llm.key", testAPIKey+"\n"),
			ContextWindow: 65536, Language: agent.LanguageEN,
		},
		NewLLM: func(c agent.ClientConfig) (agent.LLM, error) {
			c.Transport = llmTransport
			return agent.NewHTTPClient(c)
		},
		Out:    e.out,
		Logger: slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    func() time.Time { return t0 },
	}
}

func (e *env) runner(t *testing.T, mutate ...func(*Config)) *Runner {
	t.Helper()
	cfg := e.config(t)
	for _, m := range mutate {
		m(&cfg)
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) assertNoSecrets(t *testing.T) {
	t.Helper()
	ev, _ := os.ReadFile(latestEvidence(t, e.dir))
	for name, s := range map[string]string{"log": e.logs.String(), "stdout": e.out.String(), "evidence": string(ev)} {
		if strings.Contains(s, testToken) || strings.Contains(s, testAPIKey) {
			t.Errorf("%s holds a secret", name)
		}
	}
}

func latestEvidence(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, evidenceDir))
	if err != nil || len(ents) == 0 {
		t.Fatalf("no evidence written: %v", err)
	}
	return filepath.Join(dir, evidenceDir, ents[len(ents)-1].Name())
}

func sourceByFeed(rep *Report, feed string) SourceEvidence {
	for _, s := range rep.Sources {
		if s.Feed == feed {
			return s
		}
	}
	return SourceEvidence{}
}

func TestRunSyncsMatchesAssessesAndSubmits(t *testing.T) {
	e := newEnv(t)
	e.nos.setLLM(true, e.llm.srv.URL+"/v1", "nos-model")
	rep, err := e.runner(t).Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// Phase 1: every fixture feed synced with its content date.
	for _, f := range []string{"debian-dsa", "debian-tracker", "cisa-kev"} {
		s := sourceByFeed(rep, f)
		if s.Status != SourceUpdated || !strings.HasPrefix(s.SnapshotID, "sha256:") || s.ContentDate.IsZero() {
			t.Errorf("feed %s evidence = %+v", f, s)
		}
	}
	if d := sourceByFeed(rep, "debian-tracker").ContentDate; !d.Equal(time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("tracker proxy date = %v, want the DSA list date", d)
	}
	// Phases 2 and 3.
	if rep.InventorySnapshotID != "inv-1" || rep.Subjects != 2 || rep.Findings != 1 {
		t.Fatalf("report = %+v", rep)
	}
	// Phase 4: the URL and model NOS serves, the key from the local file.
	if !rep.LLM.Enabled || rep.LLM.Origin != "nos" || rep.LLM.Assessed != 1 {
		t.Errorf("llm evidence = %+v", rep.LLM)
	}
	e.llm.mu.Lock()
	if len(e.llm.auth) == 0 || e.llm.auth[0] != "Bearer "+testAPIKey || e.llm.model[0] != "nos-model" {
		t.Errorf("llm calls: auth ok=%v model=%v", len(e.llm.auth) > 0 && e.llm.auth[0] == "Bearer "+testAPIKey, e.llm.model)
	}
	e.llm.mu.Unlock()
	// Phase 5: start, one batch, complete, in that order.
	e.nos.mu.Lock()
	posts := append([]string(nil), e.nos.posts...)
	e.nos.mu.Unlock()
	if len(posts) != 3 || posts[0] != "/api/v1/vuln/runs" || !strings.HasSuffix(posts[1], "/findings") || !strings.HasSuffix(posts[2], "/complete") {
		t.Fatalf("NOS posts = %v", posts)
	}
	recs := e.nos.sentRecords(t)
	if len(recs) != 1 {
		t.Fatalf("records sent = %d", len(recs))
	}
	r := recs[0]
	if r.Vuln.ID != testCVE || r.Fix.State != vulnfinding.FixFixed || r.Fix.Version != "3.0.15-1~deb12u1" ||
		r.Scores.KEV == nil || r.Assessment.Text == "" || !r.Assessment.BackportChecked {
		t.Errorf("record = %+v", r)
	}
	if strings.Contains(e.logs.String(), "tracker fixed version is newer") || strings.Contains(string(mustJSON(t, recs)), "rationale") {
		t.Error("rationale left the local audit path")
	}
	// The host with an unknown ecosystem is a coverage gap and not named.
	if rep.Gaps == 0 || rep.SubjectsCovered != 1 || rep.Completion == nil || rep.RunID == "" {
		t.Errorf("coverage: gaps=%d covered=%d completion=%v", rep.Gaps, rep.SubjectsCovered, rep.Completion)
	}
	if rep.Degraded() {
		t.Errorf("clean run reported degraded: %+v", rep)
	}
	var stored Report
	b, err := os.ReadFile(latestEvidence(t, e.dir))
	if err != nil || json.Unmarshal(b, &stored) != nil || stored.RunID != rep.RunID || len(stored.RunSources) == 0 {
		t.Errorf("evidence file: %v %+v", err, stored)
	}
	e.assertNoSecrets(t)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDryRunPrintsRecordsAndSubmitsNothing(t *testing.T) {
	e := newEnv(t)
	rep, err := e.runner(t).Run(context.Background(), ModeDryRun)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if n := e.nos.postCount(); n != 0 {
		t.Errorf("dry run sent %d POST requests to NOS", n)
	}
	if e.nos.count("GET /api/v1/vuln/inventory") == 0 {
		t.Error("dry run did not read the export")
	}
	lines := strings.Split(strings.TrimSpace(e.out.String()), "\n")
	if len(lines) != 1 || rep.Printed != 1 || rep.RunID != "" {
		t.Fatalf("printed %d lines, report printed=%d run=%q", len(lines), rep.Printed, rep.RunID)
	}
	f, err := vulnfinding.ParseRecord([]byte(lines[0]))
	if err != nil || f.Record.Vuln.ID != testCVE {
		t.Errorf("printed record: %v %+v", err, f.Record)
	}
	if e.llm.callCount() != 0 {
		t.Error("disabled assessor called the LLM")
	}
	e.assertNoSecrets(t)
}

func TestSyncOnlyNeverContactsNOS(t *testing.T) {
	e := newEnv(t)
	rep, err := e.runner(t).Run(context.Background(), ModeSyncOnly)
	if err != nil {
		t.Fatalf("sync-only: %v", err)
	}
	e.nos.mu.Lock()
	n := len(e.nos.reqs)
	e.nos.mu.Unlock()
	if n != 0 || rep.InventorySnapshotID != "" || len(rep.Sources) != 3 {
		t.Errorf("sync-only: NOS requests %d, report %+v", n, rep)
	}
}

func TestFeedFailureKeepsPreviousSnapshotAndRunGoesOn(t *testing.T) {
	e := newEnv(t)
	if _, err := e.runner(t).Run(context.Background(), ModeSyncOnly); err != nil {
		t.Fatal(err)
	}
	first, _ := e.runner(t).store.Load("cisa-kev")
	e.feeds.fail("/kev", http.StatusInternalServerError)
	rep, err := e.runner(t).Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	s := sourceByFeed(rep, "cisa-kev")
	if s.Status != SourceFailed || s.Error == "" || s.SnapshotID != first.SnapshotID() {
		t.Errorf("kev evidence = %+v, want failed with the previous snapshot", s)
	}
	if !rep.Degraded() || rep.Completion == nil {
		t.Errorf("degraded=%v completion=%v", rep.Degraded(), rep.Completion)
	}
	if recs := e.nos.sentRecords(t); len(recs) != 1 || recs[0].Scores.KEV == nil {
		t.Errorf("previous KEV snapshot not used: %+v", recs)
	}
}

func TestServedLLMURLIsRevalidated(t *testing.T) {
	for name, u := range map[string]string{
		"userinfo": "https://user:pw@127.0.0.1/v1",
		"fragment": "https://127.0.0.1/v1#x",
		"query":    "https://127.0.0.1/v1?x=1",
		"scheme":   "ftp://127.0.0.1/v1",
		"plain":    "http://127.0.0.1/v1",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.nos.setLLM(true, u, "nos-model")
			rep, err := e.runner(t).Run(context.Background(), ModeRun)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if rep.LLM.Enabled || rep.LLM.Assessed != 0 || e.llm.callCount() != 0 {
				t.Errorf("refused URL used: %+v, calls %d", rep.LLM, e.llm.callCount())
			}
			recs := e.nos.sentRecords(t)
			if len(recs) != 1 || recs[0].Assessment.Text != "" {
				t.Errorf("finding not sent without text: %+v", recs)
			}
			if strings.Contains(e.logs.String(), "pw@") {
				t.Error("userinfo of the served URL logged")
			}
		})
	}
}

func TestLocalLLMSettingsApplyWhenNOSServesEmptyValues(t *testing.T) {
	e := newEnv(t)
	e.nos.setLLM(true, "", "")
	r := e.runner(t, func(c *Config) { c.LLM.BaseURL, c.LLM.Model = e.llm.srv.URL+"/v1", "local-model" })
	rep, err := r.Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatal(err)
	}
	e.llm.mu.Lock()
	defer e.llm.mu.Unlock()
	if rep.LLM.Assessed != 1 || len(e.llm.model) == 0 || e.llm.model[0] != "local-model" {
		t.Errorf("llm = %+v, models %v", rep.LLM, e.llm.model)
	}
}

func TestNOSDisablesAssessorOverLocalEnable(t *testing.T) {
	e := newEnv(t)
	e.nos.setLLM(false, e.llm.srv.URL+"/v1", "nos-model")
	r := e.runner(t, func(c *Config) { c.LLM.Enabled, c.LLM.BaseURL = true, e.llm.srv.URL+"/v1" })
	rep, err := r.Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatal(err)
	}
	if rep.LLM.Enabled || e.llm.callCount() != 0 {
		t.Errorf("assessor ran although NOS disabled it: %+v", rep.LLM)
	}
}

func TestAgentSettingsUnavailableFallsBackToLocal(t *testing.T) {
	e := newEnv(t)
	r := e.runner(t, func(c *Config) {
		c.AgentConfig = failingSettings{ErrNoRemoteSettings}
		c.LLM.Enabled, c.LLM.BaseURL = true, e.llm.srv.URL+"/v1"
	})
	rep, err := r.Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatal(err)
	}
	if rep.LLM.Origin != "local" || rep.LLM.Assessed != 1 {
		t.Errorf("llm = %+v", rep.LLM)
	}
}

type failingSettings struct{ err error }

func (f failingSettings) AgentConfig(context.Context) (RemoteLLM, error) { return RemoteLLM{}, f.err }

func TestExportFailureEndsRunBeforeAnyWrite(t *testing.T) {
	e := newEnv(t)
	r := e.runner(t, func(c *Config) {
		bad, err := nosclient.New(nosclient.Config{BaseURL: e.nos.srv.URL, TokenFile: writeSecret(t, "bad", "wrong-token\n"),
			CAFile: e.nos.caFile, MaxAttempts: 1})
		if err != nil {
			t.Fatal(err)
		}
		c.NOS = bad
	})
	rep, err := r.Run(context.Background(), ModeRun)
	if !errors.Is(err, ErrExport) || !errors.Is(err, nosclient.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	if e.nos.postCount() != 0 || rep.Error == "" {
		t.Errorf("posts %d, report error %q", e.nos.postCount(), rep.Error)
	}
}

func TestNoFeedSnapshotFailsRun(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/dsa", "/tracker", "/kev"} {
		e.feeds.fail(p, http.StatusServiceUnavailable)
	}
	_, err := e.runner(t).Run(context.Background(), ModeRun)
	if !errors.Is(err, ErrNoFeeds) || e.nos.postCount() != 0 {
		t.Fatalf("err = %v, posts %d", err, e.nos.postCount())
	}
}

func TestTamperedSnapshotIsLeftOut(t *testing.T) {
	e := newEnv(t)
	if _, err := e.runner(t).Run(context.Background(), ModeSyncOnly); err != nil {
		t.Fatal(err)
	}
	m, err := e.runner(t).store.Load("cisa-kev")
	if err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(e.dir, feedsDir, "objects", "cisa-kev", m.SHA256)
	if err := os.WriteFile(obj, []byte(strings.Replace(kevJSON, "2026-11-09", "2026-11-01", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	e.feeds.fail("/kev", http.StatusNotModified)
	rep, err := e.runner(t).Run(context.Background(), ModeRun)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range rep.RunSources {
		if s.SourceID == "kev" {
			t.Error("tampered KEV snapshot named at run start")
		}
	}
	if recs := e.nos.sentRecords(t); len(recs) != 1 || recs[0].Scores.KEV != nil {
		t.Errorf("tampered KEV data used: %+v", recs)
	}
}

func TestConfigRejected(t *testing.T) {
	e := newEnv(t)
	tests := map[string]func(*Config){
		"relative data dir":     func(c *Config) { c.DataDir = "data" },
		"no fetcher":            func(c *Config) { c.Fetcher = nil },
		"assess phase too long": func(c *Config) { c.AssessPhaseMax = 5 * time.Hour },
		"context window small": func(c *Config) {
			c.LLM.Enabled, c.LLM.ContextWindow = true, agent.DefaultMaxPromptTokens+agent.DefaultMaxOutputTokens
		},
		"enabled without model": func(c *Config) { c.LLM.Enabled, c.LLM.Model = true, "" },
		"local url userinfo":    func(c *Config) { c.LLM.BaseURL = "https://u:p@llm.lab/v1" },
		"local plain http":      func(c *Config) { c.LLM.BaseURL = "http://llm.lab/v1" },
		"limits invalid":        func(c *Config) { c.LLM.Limits = agent.Limits{MaxToolSteps: 99} },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := e.config(t)
			mut(&cfg)
			if _, err := New(cfg); !errors.Is(err, ErrConfig) {
				t.Errorf("New = %v, want ErrConfig", err)
			}
		})
	}
	cfg := e.config(t)
	cfg.NOS = nil
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), ModeDryRun); !errors.Is(err, ErrConfig) {
		t.Errorf("dry run without NOS = %v", err)
	}
}

func TestHTTPAgentConfigRejectsBadAnswers(t *testing.T) {
	tok := writeSecret(t, "token", testToken)
	for name, h := range map[string]http.HandlerFunc{
		"not json":     func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") },
		"no enabled":   jsonAnswer(`{"llm_base_url":""}`),
		"long model":   jsonAnswer(`{"llm_enabled":true,"llm_model":"` + strings.Repeat("m", MaxLLMModelBytes+1) + `"}`),
		"bad language": jsonAnswer(`{"llm_enabled":true,"language":"fr"}`),
		"too large":    jsonAnswer(`{"llm_enabled":true,"operator_instructions":"` + strings.Repeat("a", MaxAgentConfigBytes) + `"}`),
		"status 500":   func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.invalid/", http.StatusFound)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(h)
			defer srv.Close()
			c, err := NewHTTPAgentConfig(AgentConfigOptions{BaseURL: srv.URL, TokenFile: tok, CAFile: writeCA(t, srv)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.AgentConfig(context.Background())
			if err == nil {
				t.Fatal("bad answer accepted")
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(fmtAll(c), testToken) {
				t.Error("token in error or printed client")
			}
		})
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	c, err := NewHTTPAgentConfig(AgentConfigOptions{BaseURL: srv.URL, TokenFile: tok, CAFile: writeCA(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AgentConfig(context.Background()); !errors.Is(err, ErrNoRemoteSettings) {
		t.Errorf("404 = %v, want ErrNoRemoteSettings", err)
	}
	if _, err := NewHTTPAgentConfig(AgentConfigOptions{BaseURL: "http://nos.lab", TokenFile: tok}); err == nil {
		t.Error("plain http NOS URL accepted")
	}
	loose := writeSecret(t, "loose", testToken)
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPAgentConfig(AgentConfigOptions{BaseURL: srv.URL, TokenFile: loose}); !errors.Is(err, nosclient.ErrTokenFilePermissions) {
		t.Errorf("world-readable token file = %v", err)
	}
}

func fmtAll(c *HTTPAgentConfig) string {
	var b bytes.Buffer
	slog.New(slog.NewJSONHandler(&b, nil)).Info("x", "token", c.token)
	b.WriteString(c.token.String())
	j, _ := json.Marshal(c.token)
	b.Write(j)
	return b.String()
}

func jsonAnswer(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return writeSecret(t, "ca.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
}

func TestValidateLLMURL(t *testing.T) {
	good := []string{"https://llm.lab/v1", "https://10.0.0.5:11434/v1"}
	for _, u := range good {
		if err := ValidateLLMURL(u, false); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if err := ValidateLLMURL("http://10.0.0.5:11434/v1", true); err != nil {
		t.Errorf("plain http with permission: %v", err)
	}
	bad := []string{"", "http://10.0.0.5/v1", "https://u@llm.lab/v1", "https://llm.lab/v1#f", "https://llm.lab/v1?q",
		"https:///v1", "file:///etc/passwd", "https://llm.lab/\x7f", "https://" + strings.Repeat("a", MaxLLMURLBytes) + "/"}
	for _, u := range bad {
		if err := ValidateLLMURL(u, false); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}
