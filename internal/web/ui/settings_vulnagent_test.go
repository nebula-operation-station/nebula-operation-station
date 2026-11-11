// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

type fakeVulnAgent struct {
	mu         sync.Mutex
	cfg        vulnstore.AgentConfig
	core       string
	maintainer bool
	getErr     error
	commitErr  error
	challenges int
	begun      []ui.VulnAgentChange
	committed  []ui.VulnAgentChange
	assertions []string
}

func (f *fakeVulnAgent) VulnAgentConfig(context.Context) (vulnstore.AgentConfig, error) {
	return f.cfg, f.getErr
}

func (f *fakeVulnAgent) VulnAgentCorePrompt() string { return f.core }

func (f *fakeVulnAgent) VulnMaintainer(context.Context, string) (bool, error) {
	return f.maintainer, nil
}

func (f *fakeVulnAgent) BeginVulnAgentChange(_ context.Context, _ string, c ui.VulnAgentChange) (ui.VulnChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, c)
	f.challenges++
	return ui.VulnChallenge{ID: fmt.Sprintf("agent-challenge-%06d", f.challenges), Options: []byte(`{"publicKey":{"challenge":"AAAA"}}`)}, nil
}

func (f *fakeVulnAgent) CommitVulnAgentChange(_ context.Context, _ string, _ string, c ui.VulnAgentChange, assertion []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.commitErr != nil {
		return f.commitErr
	}
	f.committed = append(f.committed, c)
	f.assertions = append(f.assertions, string(assertion))
	return nil
}

func agentFixture(maintainer bool) *fakeVulnAgent {
	return &fakeVulnAgent{maintainer: maintainer, core: "You assess findings. <script>alert('core')</script>",
		cfg: vulnstore.AgentConfig{AgentSettings: vulnstore.AgentSettings{LLMEnabled: true, LLMBaseURL: "http://llm.lab:11434/v1",
			LLMModel: "qwen3.5-9b-64k", Language: "de", OperatorInstructions: "Prefer <b>Debian</b> trackers."},
			UpdatedBy: "admin", UpdatedAt: vulnNow.Add(-time.Hour), Version: 4}}
}

func agentHandler(t *testing.T, f *fakeVulnAgent) http.Handler {
	t.Helper()
	return newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, VulnAgent: f, Now: func() time.Time { return vulnNow }}).Handler()
}

func agentBody(mod func(m map[string]any)) string {
	m := map[string]any{"llm_enabled": true, "llm_base_url": "http://llm.lab:11434/v1", "llm_model": "llama3.1-8b",
		"operator_instructions": "Be brief.", "language": "en", "base_version": 4, "confirm_url_change": false}
	if mod != nil {
		mod(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

const (
	agentBegin  = "/settings/vuln-agent/begin"
	agentCommit = "/settings/vuln-agent/commit"
)

func TestVulnAgentSettingsHiddenWithoutBackend(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin}).Handler()
	if body := getBody(t, h, "/settings"); strings.Contains(body, "vuln-agent-form") {
		t.Fatal("settings page shows the agent section without a backend")
	}
	for _, p := range []string{agentBegin, agentCommit} {
		if code, _ := vulnPost(t, h, p, `{}`); code != http.StatusNotFound {
			t.Errorf("POST %s without backend = %d, want 404", p, code)
		}
	}
}

func TestVulnAgentSettingsRenderedAsTextWithSecurityHints(t *testing.T) {
	f := agentFixture(true)
	body := getBody(t, agentHandler(t, f), "/settings")
	for _, want := range []string{
		"Vulnerability agent – LLM", `id="vuln-agent-form"`, `value="http://llm.lab:11434/v1"`, `value="qwen3.5-9b-64k"`,
		`placeholder="` + vulnstore.AgentLLMURLPlaceholder + `"`, `data-version="4"`,
		"sends finding context", "security-relevant", "API key",
		"Prefer &lt;b&gt;Debian&lt;/b&gt; trackers.", "&lt;script&gt;alert(&#39;core&#39;)&lt;/script&gt;",
		`id="vuln-agent-submit"`, `<option value="de" selected>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(") || strings.Contains(body, "<b>Debian") {
		t.Fatal("untrusted text rendered as HTML")
	}
}

func TestVulnAgentSettingsReadOnlyAndForbiddenForNonAdmin(t *testing.T) {
	f := agentFixture(false)
	h := agentHandler(t, f)
	body := getBody(t, h, "/settings")
	if strings.Contains(body, `id="vuln-agent-submit"`) {
		t.Error("non-admin sees the save button")
	}
	if !strings.Contains(body, "Only the maintainer") {
		t.Error("non-admin is not told why the section is read-only")
	}
	if code, _ := vulnPost(t, h, agentBegin, agentBody(nil)); code != http.StatusForbidden {
		t.Errorf("begin as non-admin = %d, want 403", code)
	}
	if code, _ := vulnPost(t, h, agentCommit, `{"id":"agent-challenge-000001","assertion":{"id":"cred"}}`); code != http.StatusForbidden {
		t.Errorf("commit as non-admin = %d, want 403", code)
	}
	if len(f.begun)+len(f.committed) != 0 {
		t.Fatal("backend reached for a non-admin")
	}
}

func TestVulnAgentSettingsNeedFreshSingleUseAssertion(t *testing.T) {
	f := agentFixture(true)
	h := agentHandler(t, f)
	code, out := vulnPost(t, h, agentBegin, agentBody(nil))
	if code != http.StatusOK {
		t.Fatalf("begin = %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if id == "" || out["options"] == nil {
		t.Fatalf("begin answer %v", out)
	}
	for _, body := range []string{`{"id":"` + id + `"}`, `{"id":"` + id + `","assertion":null}`} {
		if code, _ := vulnPost(t, h, agentCommit, body); code != http.StatusForbidden {
			t.Errorf("commit %s = %d, want 403", body, code)
		}
	}
	if len(f.committed) != 0 {
		t.Fatal("change committed without an assertion")
	}
	if code, out := vulnPost(t, h, agentCommit, `{"id":"`+id+`","assertion":{"id":"cred"}}`); code != http.StatusOK {
		t.Fatalf("commit = %d %v", code, out)
	}
	if len(f.committed) != 1 || f.committed[0] != f.begun[0] || f.assertions[0] != `{"id":"cred"}` {
		t.Fatalf("committed %+v (begun %+v), assertions %v", f.committed, f.begun, f.assertions)
	}
	want := vulnstore.AgentSettings{LLMEnabled: true, LLMBaseURL: "http://llm.lab:11434/v1", LLMModel: "llama3.1-8b", OperatorInstructions: "Be brief.", Language: "en"}
	if f.committed[0].Settings != want || f.committed[0].BaseVersion != 4 {
		t.Fatalf("committed change %+v", f.committed[0])
	}
	if code, _ := vulnPost(t, h, agentCommit, `{"id":"`+id+`","assertion":{"id":"cred"}}`); code != http.StatusNotFound {
		t.Errorf("replayed commit = %d, want 404", code)
	}
	// A begun change expires.
	now := vulnNow
	h2 := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, VulnAgent: f, Now: func() time.Time { return now }}).Handler()
	_, out = vulnPost(t, h2, agentBegin, agentBody(nil))
	now = now.Add(6 * time.Minute)
	if code, _ := vulnPost(t, h2, agentCommit, `{"id":"`+out["id"].(string)+`","assertion":{"id":"cred"}}`); code != http.StatusNotFound {
		t.Errorf("expired commit = %d, want 404", code)
	}
}

func TestVulnAgentSettingsRejectInvalidInput(t *testing.T) {
	for name, mod := range map[string]func(m map[string]any){
		"javascript url": func(m map[string]any) { m["llm_base_url"] = "javascript:alert(1)"; m["confirm_url_change"] = true },
		"file url":       func(m map[string]any) { m["llm_base_url"] = "file:///etc/shadow"; m["confirm_url_change"] = true },
		"userinfo":       func(m map[string]any) { m["llm_base_url"] = "http://u:p@llm.lab/v1"; m["confirm_url_change"] = true },
		"fragment":       func(m map[string]any) { m["llm_base_url"] = "http://llm.lab/v1#frag"; m["confirm_url_change"] = true },
		"query":          func(m map[string]any) { m["llm_base_url"] = "http://llm.lab/v1?x=1"; m["confirm_url_change"] = true },
		"overlong url": func(m map[string]any) {
			m["llm_base_url"] = "http://llm.lab/" + strings.Repeat("a", vulnstore.MaxAgentLLMURL)
			m["confirm_url_change"] = true
		},
		"model":         func(m map[string]any) { m["llm_model"] = strings.Repeat("m", vulnstore.MaxAgentLLMModel+1) },
		"model control": func(m map[string]any) { m["llm_model"] = "a\u0000b" },
		"language":      func(m map[string]any) { m["language"] = "fr" },
		"operator long": func(m map[string]any) {
			m["operator_instructions"] = strings.Repeat("x", vulnstore.MaxAgentOperatorText+1)
		},
		"operator ctrl":  func(m map[string]any) { m["operator_instructions"] = "a\u001bb" },
		"unknown field":  func(m map[string]any) { m["api_key"] = "sk-123" },
		"negative base":  func(m map[string]any) { m["base_version"] = -1 },
		"missing enable": func(m map[string]any) { delete(m, "llm_enabled") },
	} {
		t.Run(name, func(t *testing.T) {
			f := agentFixture(true)
			code, out := vulnPost(t, agentHandler(t, f), agentBegin, agentBody(mod))
			if code != http.StatusBadRequest {
				t.Fatalf("status %d %v, want 400", code, out)
			}
			if msg, _ := out["error"].(string); msg == "" || strings.Contains(msg, "sk-123") || strings.Contains(msg, "javascript") {
				t.Fatalf("error message %q", msg)
			}
			if len(f.begun) != 0 {
				t.Fatal("backend reached with invalid input")
			}
		})
	}
}

func TestVulnAgentSettingsURLChangeNeedsExplicitConfirmation(t *testing.T) {
	f := agentFixture(true)
	h := agentHandler(t, f)
	changed := func(confirm bool) string {
		return agentBody(func(m map[string]any) { m["llm_base_url"] = "https://other.lab/v1"; m["confirm_url_change"] = confirm })
	}
	code, out := vulnPost(t, h, agentBegin, changed(false))
	if code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "security-relevant") {
		t.Fatalf("unconfirmed URL change = %d %v", code, out)
	}
	if code, _ := vulnPost(t, h, agentBegin, changed(true)); code != http.StatusOK {
		t.Fatalf("confirmed URL change = %d", code)
	}
	if len(f.begun) != 1 || !f.begun[0].URLChanged {
		t.Fatalf("begun %+v", f.begun)
	}
	// Clearing the URL is a change too.
	if code, _ := vulnPost(t, h, agentBegin, agentBody(func(m map[string]any) { m["llm_base_url"] = "" })); code != http.StatusBadRequest {
		t.Fatalf("unconfirmed URL removal = %d", code)
	}
	// An unchanged URL needs no confirmation.
	if code, _ := vulnPost(t, h, agentBegin, agentBody(nil)); code != http.StatusOK {
		t.Fatalf("unchanged URL = %d", code)
	}
}

func TestVulnAgentSettingsStaleVersionAndBackendErrors(t *testing.T) {
	f := agentFixture(true)
	h := agentHandler(t, f)
	if code, _ := vulnPost(t, h, agentBegin, agentBody(func(m map[string]any) { m["base_version"] = 3 })); code != http.StatusConflict {
		t.Fatalf("stale base version = %d, want 409", code)
	}
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ui.ErrVulnAssertionRefused, http.StatusForbidden},
		{vulnstore.ErrAgentConfigConflict, http.StatusConflict},
		{vulnstore.ErrInvalidInput, http.StatusBadRequest},
		{errors.New("audit log /var/lib/nebula/audit.log: disk full"), http.StatusBadGateway},
	} {
		f.commitErr = tc.err
		_, out := vulnPost(t, h, agentBegin, agentBody(nil))
		code, out := vulnPost(t, h, agentCommit, `{"id":"`+out["id"].(string)+`","assertion":{"id":"cred"}}`)
		if code != tc.want || strings.Contains(fmt.Sprint(out), "audit.log") {
			t.Errorf("%v: %d %v, want %d", tc.err, code, out, tc.want)
		}
	}
	f.getErr = errors.New("db")
	if code, _ := vulnPost(t, h, agentBegin, agentBody(nil)); code != http.StatusBadGateway {
		t.Fatalf("config read error = %d", code)
	}
	if body := getBody(t, h, "/settings"); !strings.Contains(body, "could not be loaded") {
		t.Fatal("page hides the read error")
	}
}

func TestVulnAgentChangeDigestCoversEveryField(t *testing.T) {
	base := ui.VulnAgentChange{Settings: vulnstore.AgentSettings{LLMEnabled: true, LLMBaseURL: "http://a/v1", LLMModel: "m",
		OperatorInstructions: "o", Language: "de"}, BaseVersion: 1}
	seen := map[string]bool{base.Digest(): true}
	for _, mod := range []func(c *ui.VulnAgentChange){
		func(c *ui.VulnAgentChange) { c.Settings.LLMEnabled = false },
		func(c *ui.VulnAgentChange) { c.Settings.LLMBaseURL = "http://b/v1" },
		func(c *ui.VulnAgentChange) { c.Settings.LLMModel = "n" },
		func(c *ui.VulnAgentChange) { c.Settings.OperatorInstructions = "p" },
		func(c *ui.VulnAgentChange) { c.Settings.Language = "en" },
		func(c *ui.VulnAgentChange) { c.BaseVersion = 2 },
		func(c *ui.VulnAgentChange) { c.URLChanged = true },
	} {
		c := base
		mod(&c)
		d := c.Digest()
		if seen[d] {
			t.Fatalf("digest does not cover %+v", c)
		}
		seen[d] = true
	}
}

func TestVulnAgentSettingsCSPAndCSRFThroughMiddleware(t *testing.T) {
	f := agentFixture(true)
	u := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, VulnAgent: f, Now: func() time.Time { return vulnNow }})
	srv, err := u.Server()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	res, err := http.Get(ts.URL + "/settings")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings = %d", res.StatusCode)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP = %q", csp)
	}
	if regexp.MustCompile(`<script>|<script [^>]*>[^<]`).Match(b) {
		t.Error("settings page has an inline script")
	}
	for _, tc := range []struct {
		name, origin, ctype string
		want                int
	}{
		{"no origin", "", "application/json", http.StatusForbidden},
		{"foreign origin", "https://evil.example", "application/json", http.StatusForbidden},
		{"form post", leaseOrigin, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"same origin json", leaseOrigin, "application/json", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, ts.URL+agentBegin, strings.NewReader(agentBody(nil)))
			req.Header.Set("Content-Type", tc.ctype)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != tc.want {
				t.Errorf("status %d, want %d", res.StatusCode, tc.want)
			}
		})
	}
	if len(f.begun) != 1 {
		t.Errorf("backend saw %d begins, want 1", len(f.begun))
	}
	// The template carries no inline script, style or handler.
	tpl, err := os.ReadFile(filepath.Join(repoRoot, "web", "templates", "settings.html"))
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`(?i)<script>|<style|\sstyle=|\son[a-z]+=|javascript:|safeHTML`).Find(tpl); m != nil {
		t.Errorf("settings.html contains %q", m)
	}
}
