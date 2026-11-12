// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

type fakeAgentCfg struct {
	cfg   vulnstore.AgentConfig
	err   error
	calls int
}

func (f *fakeAgentCfg) AgentConfig(context.Context) (vulnstore.AgentConfig, error) {
	f.calls++
	return f.cfg, f.err
}

const testCorePrompt = "You are the NOS vulnerability assessor."

func agentCfgEnv(t *testing.T, src *fakeAgentCfg, tokens ...serverconfig.APIToken) (*venv, http.Handler) {
	t.Helper()
	e := newVulnEnv(t, tokens...)
	h, err := e.h.WithAgentConfig(api.AgentConfigOptions{Source: src, CorePrompt: testCorePrompt})
	if err != nil {
		t.Fatal(err)
	}
	return e, h
}

func agentCfgDo(h http.Handler, method, tok, remote, path string) resp {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remote
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return resp{code: rec.Code, body: rec.Body.String(), hdr: rec.Header()}
}

func storedAgentCfg() vulnstore.AgentConfig {
	return vulnstore.AgentConfig{AgentSettings: vulnstore.AgentSettings{LLMEnabled: true, LLMBaseURL: "http://192.168.0.26:11434/v1",
		LLMModel: "qwen3.5-9b-64k", OperatorInstructions: "Be brief.", Language: "en"},
		UpdatedBy: "admin", UpdatedAt: time.Unix(1, 0), Version: 3}
}

func TestAgentConfigServedToVulnTokenWithoutSecrets(t *testing.T) {
	src := &fakeAgentCfg{cfg: storedAgentCfg()}
	_, h := agentCfgEnv(t, src)
	r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath)
	if r.code != http.StatusOK {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	if r.hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", r.hdr.Get("Cache-Control"))
	}
	got := r.json(t)
	want := map[string]any{
		"llm_enabled": true, "llm_base_url": "http://192.168.0.26:11434/v1", "llm_model": "qwen3.5-9b-64k",
		"operator_instructions": "Be brief.", "language": "en", "version": float64(3),
		"prompt_version": vulnstore.AgentPromptVersion(testCorePrompt, "Be brief."),
	}
	if len(got) != len(want) {
		t.Errorf("fields %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	for _, bad := range []string{"key", "secret", "token", "password", "updated_by"} {
		if strings.Contains(strings.ToLower(r.body), bad) {
			t.Errorf("response mentions %q: %s", bad, r.body)
		}
	}
}

func TestAgentConfigRefusesWithoutScopeTokenOrAddress(t *testing.T) {
	src := &fakeAgentCfg{cfg: storedAgentCfg()}
	_, h := agentCfgEnv(t, src)
	for _, tc := range []struct {
		name, tok, remote, method string
		want                      int
	}{
		{"no token", "", hermesAddr, http.MethodGet, http.StatusUnauthorized},
		{"wrong token", "nos_other", hermesAddr, http.MethodGet, http.StatusUnauthorized},
		{"inventory token", invTok, hermesAddr, http.MethodGet, http.StatusUnauthorized},
		{"foreign address", vulnTok, "198.51.100.7:1234", http.MethodGet, http.StatusForbidden},
		{"post", vulnTok, hermesAddr, http.MethodPost, http.StatusMethodNotAllowed},
		{"put", vulnTok, hermesAddr, http.MethodPut, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if r := agentCfgDo(h, tc.method, tc.tok, tc.remote, api.AgentConfigPath); r.code != tc.want {
				t.Fatalf("status %d, want %d: %s", r.code, tc.want, r.body)
			}
		})
	}
	if src.calls != 0 {
		t.Fatalf("source read %d times for refused requests", src.calls)
	}
	// A vuln token without vuln.inventory.read is refused.
	srcW := &fakeAgentCfg{cfg: storedAgentCfg()}
	_, hw := agentCfgEnv(t, srcW, vulnToken(serverconfig.ScopeVulnFindingsWrite))
	if r := agentCfgDo(hw, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath); r.code != http.StatusForbidden {
		t.Fatalf("write-only token: status %d, want 403", r.code)
	}
	if srcW.calls != 0 {
		t.Fatal("source read for a token without the scope")
	}
}

func TestAgentConfigDelegatesOtherVulnPaths(t *testing.T) {
	_, h := agentCfgEnv(t, &fakeAgentCfg{cfg: storedAgentCfg()})
	if r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.VulnPrefix+"inventory"); r.code != http.StatusOK {
		t.Fatalf("inventory through the wrapper: %d %s", r.code, r.body)
	}
	if r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath+"/x"); r.code != http.StatusNotFound {
		t.Fatalf("sub path: %d", r.code)
	}
}

func TestAgentConfigStoreErrorsAndInvalidRowsAreNotServed(t *testing.T) {
	src := &fakeAgentCfg{err: errors.New("db locked: /var/lib/nebula/server.db")}
	_, h := agentCfgEnv(t, src)
	r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath)
	if r.code != http.StatusBadGateway || strings.Contains(r.body, "server.db") {
		t.Fatalf("store error: %d %s", r.code, r.body)
	}
	bad := storedAgentCfg()
	bad.LLMBaseURL = "javascript:alert(1)"
	src.err, src.cfg = nil, bad
	r = agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath)
	if r.code != http.StatusInternalServerError || strings.Contains(r.body, "javascript") {
		t.Fatalf("invalid stored row: %d %s", r.code, r.body)
	}
}

func TestAgentConfigRateLimited(t *testing.T) {
	_, h := agentCfgEnv(t, &fakeAgentCfg{cfg: storedAgentCfg()})
	for i := range api.MaxAgentConfigRequests {
		if r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath); r.code != http.StatusOK {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath)
	if r.code != http.StatusTooManyRequests || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d %v", r.code, r.hdr)
	}
}

// Requests with another token never count against the vuln token's
// budget: they are refused before the rate limit, which is per token.
func TestAgentConfigRateLimitIsPerToken(t *testing.T) {
	_, h := agentCfgEnv(t, &fakeAgentCfg{cfg: storedAgentCfg()})
	for i := range 2 * api.MaxAgentConfigRequests {
		if r := agentCfgDo(h, http.MethodGet, invTok, hermesAddr, api.AgentConfigPath); r.code != http.StatusUnauthorized {
			t.Fatalf("other token request %d: %d", i, r.code)
		}
	}
	for i := range api.MaxAgentConfigRequests {
		if r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath); r.code != http.StatusOK {
			t.Fatalf("vuln token request %d after other token's requests: %d", i, r.code)
		}
	}
	if r := agentCfgDo(h, http.MethodGet, vulnTok, hermesAddr, api.AgentConfigPath); r.code != http.StatusTooManyRequests {
		t.Fatalf("vuln token over its own limit: %d", r.code)
	}
}

func TestWithAgentConfigNeedsSource(t *testing.T) {
	e := newVulnEnv(t)
	if _, err := e.h.WithAgentConfig(api.AgentConfigOptions{}); err == nil {
		t.Fatal("nil source accepted")
	}
}
