// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testKey is a synthetic bearer token, not a real secret.
const testKey = "test-token-not-a-secret"

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHTTPClientSendsToolRequestAndParsesToolCalls(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			http.Error(w, "bad path", http.StatusNotFound)
			return
		}
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"free text","tool_calls":[
			{"id":"c1","type":"function","function":{"name":"kev_epss","arguments":"{\"vuln_id\":\"CVE-2026-0001\"}"}},
			{"id":"c2","type":"function","function":{"name":"exposure","arguments":{"finding_key":"x"}}}]}}],
			"usage":{"prompt_tokens":120,"completion_tokens":7}}`)
	}))
	defer srv.Close()
	c, err := NewHTTPClient(ClientConfig{BaseURL: srv.URL + "/v1", Model: "qwen3:14b", APIKeyFile: writeKeyFile(t, testKey+"\n"),
		Timeout: 5 * time.Second, Transport: srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Complete(context.Background(), Request{
		Messages:  []Message{{Role: "system", Content: "s"}, {Role: "user", Content: "u"}},
		Tools:     ToolDefinitions(),
		MaxTokens: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer "+testKey {
		t.Fatalf("authorization header %q", auth)
	}
	if got["parallel_tool_calls"] != false || got["stream"] != false || got["max_tokens"] != float64(1024) || got["model"] != "qwen3:14b" {
		t.Fatalf("request fields: %v", got)
	}
	if tl, _ := got["tools"].([]any); len(tl) != 7 {
		t.Fatalf("request carries %d tools", len(tl))
	}
	if len(resp.ToolCalls) != 2 || resp.ToolCalls[0].Name != ToolKEVEPSS || resp.ToolCalls[0].Arguments != `{"vuln_id":"CVE-2026-0001"}` ||
		resp.ToolCalls[1].Arguments != `{"finding_key":"x"}` {
		t.Fatalf("tool calls: %+v", resp.ToolCalls)
	}
	if resp.Usage == nil || resp.Usage.PromptTokens != 120 || resp.Usage.CompletionTokens != 7 {
		t.Fatalf("usage: %+v", resp.Usage)
	}
}

func TestHTTPClientFailuresHideKeyAndBody(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "upstream says "+testKey, http.StatusInternalServerError)
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://203.0.113.9/v1/chat/completions", http.StatusTemporaryRedirect)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+strings.Repeat("a", MaxLLMResponseBytes)+`"}}]}`)
		},
		"malformed": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"choices":`) },
		"no choice": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"choices":[]}`) },
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(h)
			defer srv.Close()
			c, err := NewHTTPClient(ClientConfig{BaseURL: srv.URL, Model: "m", APIKeyFile: writeKeyFile(t, testKey),
				Timeout: 5 * time.Second, Transport: srv.Client().Transport})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Complete(context.Background(), Request{MaxTokens: 1})
			if !errors.Is(err, ErrLLM) {
				t.Fatalf("err = %v, want ErrLLM", err)
			}
			if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "upstream") {
				t.Fatalf("error leaks key or body: %v", err)
			}
		})
	}
}

func TestHTTPClientHonoursContextDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	c, err := NewHTTPClient(ClientConfig{BaseURL: srv.URL, Model: "m", AllowPlainHTTP: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Complete(ctx, Request{MaxTokens: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("call outlived its context")
	}
}

func TestHTTPClientConfigRejected(t *testing.T) {
	key := writeKeyFile(t, testKey)
	cases := map[string]ClientConfig{
		"plain http not allowed": {BaseURL: "http://127.0.0.1:11434/v1", Model: "m", Timeout: time.Second},
		"key over plain http":    {BaseURL: "http://127.0.0.1:11434/v1", Model: "m", APIKeyFile: key, AllowPlainHTTP: true, Timeout: time.Second},
		"userinfo":               {BaseURL: "https://u:p@127.0.0.1/v1", Model: "m", Timeout: time.Second},
		"query":                  {BaseURL: "https://127.0.0.1/v1?x=1", Model: "m", Timeout: time.Second},
		"scheme":                 {BaseURL: "file:///etc/passwd", Model: "m", Timeout: time.Second},
		"no model":               {BaseURL: "https://127.0.0.1/v1", Timeout: time.Second},
		"model space":            {BaseURL: "https://127.0.0.1/v1", Model: "a b", Timeout: time.Second},
		"timeout zero":           {BaseURL: "https://127.0.0.1/v1", Model: "m"},
		"timeout over max":       {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: HardMaxLLMCallTimeout + 1},
		"empty key file":         {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, APIKeyFile: writeKeyFile(t, "\n")},
		"two-line key file":      {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, APIKeyFile: writeKeyFile(t, "a\nb")},
		"oversized key file":     {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, APIKeyFile: writeKeyFile(t, strings.Repeat("k", MaxAPIKeyFileBytes+1))},
	}
	for name, cfg := range cases {
		if _, err := NewHTTPClient(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		} else if strings.Contains(err.Error(), testKey) {
			t.Errorf("%s: error leaks key", name)
		}
	}
	if _, err := NewHTTPClient(ClientConfig{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, APIKeyFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("missing key file accepted")
	}
	c, err := NewHTTPClient(ClientConfig{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := c.http.Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatal("default transport consults proxy variables")
	}
}
