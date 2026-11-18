// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	testAPIToken = "nos_ops-agent-e2e-token"
	testDigest   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fixReply     = `{"summary":"openssl ist veraltet.","urgency":"heute",` +
		`"steps":[{"candidate":"c1","why":"behebt CVE-2026-0001"},{"candidate":"c7","why":"erfunden"}],` +
		`"mitigations":[{"text":"Port 443 im Firewall-Dienst einschränken."}],"citations":[]}`
)

// fakeNOS serves the four ops endpoints on loopback and records notes and status.
type fakeNOS struct {
	mu       sync.Mutex
	llmURL   string
	notes    []map[string]any
	statuses []map[string]any
	paths    []string
}

func (f *fakeNOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer "+testAPIToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/ops/agent-config":
		_, _ = io.WriteString(w, `{"enabled":true,"llm_base_url":"`+f.llmURL+`","llm_model":"qwen",`+
			`"allow_plain_http":true,"data_class":"lab","language":"de","operator_instructions":"Knapp.","prompt_version":"p","version":1}`)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/ops/work":
		_, _ = io.WriteString(w, `{"items":[{"kind":"fix","ref":"h1:os","digest":"`+testDigest+`","group":{`+
			`"group":"h1:os","host":{"id":"h1","label":"web-01","environment":"lab","criticality":"high"},`+
			`"exposure":"lan","ports":[{"number":443,"protocol":"tcp"}],"ports_omitted":0,`+
			`"findings":[{"vuln_id":"CVE-2026-0001","package":"openssl","installed":"3.0.1","fixed":"3.0.2",`+
			`"tier":"critical","score":90,"kev":true,"fix_status":"no_fix_yet"}],`+
			`"omitted":{"critical":0,"high":0,"medium":0,"low":0,"kev":0},`+
			`"counts":{"critical":1,"high":0,"medium":0,"low":0,"kev":1},`+
			`"candidates":[{"key":"c1","action":"package.install_security","host_id":"h1","label":"Sicherheitsupdates installieren"}]`+
			`}}]}`)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/ops/notes":
		var n map[string]any
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.notes = append(f.notes, n)
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/ops/status":
		var s map[string]any
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.statuses = append(f.statuses, s)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// fakeLLM answers chat calls on loopback with the given content and counts them.
func fakeLLM(t *testing.T, content string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": content}}}})
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeEnv writes the token, the state directory and the config file.
func writeEnv(t *testing.T, nosURL string) string {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(testAPIToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, err := json.Marshal(Config{NOSBaseURL: nosURL, NOSTokenFile: tok, StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestGoldenRunPostsOnlyValidatedMappedNote runs the real binary wiring against
// a fake NOS and a fake LLM on loopback. The model's invented candidate c7 is
// dropped, the action and host come from the server's candidate, and the
// stderr log carries no text from the prompt or the answer.
func TestGoldenRunPostsOnlyValidatedMappedNote(t *testing.T) {
	var llmCalls atomic.Int32
	llm := fakeLLM(t, "Hier die Antwort:\n<think>c7?</think>\n"+fixReply+"\nDanke.", &llmCalls)
	nos := &fakeNOS{llmURL: llm.URL + "/v1"}
	srv := httptest.NewServer(nos)
	t.Cleanup(srv.Close)
	cfgPath := writeEnv(t, srv.URL)

	var stderr bytes.Buffer
	code := realMain([]string{"-config", cfgPath, "run"}, &stderr)
	nos.mu.Lock()
	defer nos.mu.Unlock()
	if code != 0 {
		t.Fatalf("exit %d; log: %s", code, stderr.String())
	}
	if n := llmCalls.Load(); n != 1 {
		t.Fatalf("llm calls %d, want 1", n)
	}
	if len(nos.notes) != 1 {
		t.Fatalf("notes %d, want 1", len(nos.notes))
	}
	steps, _ := nos.notes[0]["steps"].([]any)
	if len(steps) != 1 {
		t.Fatalf("steps %v: the invented candidate must be dropped", nos.notes[0]["steps"])
	}
	step := steps[0].(map[string]any)
	if step["action_id"] != "package.install_security" || step["host_id"] != "h1" {
		t.Errorf("step %v: action and host must come from the server candidate", step)
	}
	if len(nos.statuses) != 1 || nos.statuses[0]["discarded"] != float64(1) {
		t.Errorf("status %v, want one run with one discarded step", nos.statuses)
	}
	for _, secret := range []string{"openssl ist veraltet", "web-01", "CVE-2026-0001", testAPIToken} {
		if strings.Contains(stderr.String(), secret) {
			t.Errorf("log carries %q", secret)
		}
	}
}

// TestLabRuleRefusesPublicLLMAddress: a lab-class settings row that names a
// public address gives a status refusal, no call and no note; exit 0.
func TestLabRuleRefusesPublicLLMAddress(t *testing.T) {
	nos := &fakeNOS{llmURL: "https://8.8.8.8/v1"}
	srv := httptest.NewServer(nos)
	t.Cleanup(srv.Close)
	cfgPath := writeEnv(t, srv.URL)
	var stderr bytes.Buffer
	code := realMain([]string{"-config", cfgPath, "run"}, &stderr)
	nos.mu.Lock()
	defer nos.mu.Unlock()
	if code != 0 {
		t.Fatalf("exit %d; log: %s", code, stderr.String())
	}
	if len(nos.notes) != 0 || len(nos.statuses) != 1 {
		t.Fatalf("notes %d statuses %d", len(nos.notes), len(nos.statuses))
	}
	if !strings.Contains(strings.Join(anyStrings(nos.statuses[0]["refusals"]), ","), "llm_refused_lab_rule") {
		t.Errorf("status %v, want llm_refused_lab_rule", nos.statuses[0])
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestUsageAndExitCodes(t *testing.T) {
	var stderr bytes.Buffer
	for _, args := range [][]string{{}, {"-config", "/x", "stop"}, {"-bogus"}} {
		if code := realMain(args, &stderr); code != 2 {
			t.Errorf("args %v: exit %d, want 2", args, code)
		}
	}
	// A missing or relative config is a failed run, not a usage error.
	for _, args := range [][]string{{"run"}, {"-config", "relative.json", "run"}} {
		if code := realMain(args, &stderr); code != 1 {
			t.Errorf("args %v: exit %d, want 1", args, code)
		}
	}
}

func TestLoadConfigRefusesBadFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	valid := `{"nos_base_url":"https://127.0.0.1:8443","nos_token_file":"/etc/x/token","state_dir":"/var/lib/x"}`
	cases := map[string]string{
		"unknown field":  `{"nos_base_url":"https://a","nos_token_file":"/t","state_dir":"/s","extra":1}`,
		"trailing":       valid + ` {}`,
		"relative state": `{"nos_base_url":"https://a","nos_token_file":"/t","state_dir":"s"}`,
		"no base url":    `{"nos_token_file":"/t","state_dir":"/s"}`,
		"relative ca":    `{"nos_base_url":"https://a","nos_token_file":"/t","state_dir":"/s","nos_ca_file":"ca.pem"}`,
		"not json":       `{`,
	}
	for name, body := range cases {
		if _, err := LoadConfig(write(strings.ReplaceAll(name, " ", "-")+".json", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadConfig(write("ok.json", valid)); err != nil {
		t.Errorf("valid config refused: %v", err)
	}
}
