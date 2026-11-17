// SPDX-License-Identifier: AGPL-3.0-or-later

package llmclient

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
	"syscall"
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

// tlsClient is a client for a TLS test server, with its roots trusted.
func tlsClient(t *testing.T, srv *httptest.Server, key string) *Client {
	t.Helper()
	c, err := New(Options{BaseURL: srv.URL + "/v1", Model: "m", CredentialFile: key, Timeout: 5 * time.Second,
		LabOnly: true, Network: Network{RootCAs: poolOf(srv)}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKeyFileRejectedUnlessOwnerOnly(t *testing.T) {
	cases := map[string]struct {
		mode os.FileMode
		ok   bool
	}{
		"0600": {0o600, true},
		"0400": {0o400, true},
		"0640": {0o640, false},
		"0644": {0o644, false},
		"0604": {0o604, false},
		"0660": {0o660, false},
		"0610": {0o610, false},
		"0601": {0o601, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeKeyFile(t, testKey+"\n")
			if err := os.Chmod(p, c.mode); err != nil {
				t.Fatal(err)
			}
			_, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: p})
			if c.ok {
				if err != nil {
					t.Fatalf("mode %v rejected: %v", c.mode, err)
				}
				return
			}
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("mode %v: err = %v, want ErrConfig", c.mode, err)
			}
			if strings.Contains(err.Error(), testKey) {
				t.Fatal("error leaks key")
			}
		})
	}
}

func TestKeyFileMustBeRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: dir})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("directory as key file: err = %v, want ErrConfig", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: missing}); err == nil {
		t.Error("missing key file accepted")
	}
}

// A FIFO without a writer must be rejected at once: a blocking open would
// hang the run before the regular-file check could fire.
func TestKeyFileFIFORejectedWithoutBlocking(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: p})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("FIFO as key file: err = %v, want ErrConfig", err)
		}
	case <-time.After(5 * time.Second):
		// Unblock the stuck open so the goroutine can finish.
		if w, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("New blocked on a FIFO key file")
	}
}

func TestChatSendsToolRequestAndParsesToolCalls(t *testing.T) {
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
	keyFile := writeKeyFile(t, testKey+"\n")
	c := tlsClient(t, srv, keyFile)
	tools := []Tool{
		{Name: "kev_epss", Description: "d", Parameters: json.RawMessage(`{"type":"object"}`)},
		{Name: "exposure", Description: "e", Parameters: json.RawMessage(`{"type":"object"}`)},
	}
	resp, err := c.Chat(context.Background(), Request{
		Messages:  []Message{{Role: "system", Content: "s"}, {Role: "user", Content: "u"}},
		Tools:     tools,
		MaxTokens: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer "+testKey {
		t.Fatalf("authorization header %q", auth)
	}
	if got["parallel_tool_calls"] != false || got["stream"] != false || got["max_tokens"] != float64(1024) || got["model"] != "m" {
		t.Fatalf("request fields: %v", got)
	}
	if tl, _ := got["tools"].([]any); len(tl) != 2 {
		t.Fatalf("request carries %d tools", len(tl))
	}
	if _, ok := got["response_format"]; ok {
		t.Fatal("response_format sent without a schema")
	}
	if len(resp.ToolCalls) != 2 || resp.ToolCalls[0].Name != "kev_epss" || resp.ToolCalls[0].Arguments != `{"vuln_id":"CVE-2026-0001"}` ||
		resp.ToolCalls[1].Arguments != `{"finding_key":"x"}` {
		t.Fatalf("tool calls: %+v", resp.ToolCalls)
	}
	if resp.Content != "free text" {
		t.Fatalf("content %q", resp.Content)
	}
	if resp.Usage == nil || resp.Usage.PromptTokens != 120 || resp.Usage.CompletionTokens != 7 {
		t.Fatalf("usage: %+v", resp.Usage)
	}
}

func TestChatSendsJSONSchema(t *testing.T) {
	var got map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"ok\":true}"}}]}`)
	}))
	defer srv.Close()
	c := tlsClient(t, srv, "")
	schema := json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}}}`)
	resp, err := c.Chat(context.Background(), Request{MaxTokens: 8,
		JSONSchema: &JSONSchema{Name: "answer", Schema: schema, Strict: true}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != `{"ok":true}` {
		t.Fatalf("content %q", resp.Content)
	}
	rf, ok := got["response_format"].(map[string]any)
	if !ok || rf["type"] != "json_schema" {
		t.Fatalf("response_format: %v", got["response_format"])
	}
	js, _ := rf["json_schema"].(map[string]any)
	if js["name"] != "answer" || js["strict"] != true {
		t.Fatalf("json_schema: %v", js)
	}
	if s, _ := js["schema"].(map[string]any); s["type"] != "object" {
		t.Fatalf("schema: %v", js["schema"])
	}
}

func TestChatRefusesBadJSONSchema(t *testing.T) {
	c, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*JSONSchema{
		"no name":      {Schema: json.RawMessage(`{}`)},
		"long name":    {Name: strings.Repeat("n", MaxSchemaNameBytes+1), Schema: json.RawMessage(`{}`)},
		"not json":     {Name: "a", Schema: json.RawMessage(`{`)},
		"not object":   {Name: "a", Schema: json.RawMessage(`[]`)},
		"no schema":    {Name: "a"},
		"schema large": {Name: "a", Schema: json.RawMessage(`{"x":"` + strings.Repeat("x", MaxSchemaBytes) + `"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Chat(context.Background(), Request{JSONSchema: s}); !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v, want ErrConfig", err)
			}
		})
	}
}

func TestNegativeWireUsageIsClampedToZero(t *testing.T) {
	resp, err := decodeResponse([]byte(`{"choices":[{"message":{"content":"x"}}],
		"usage":{"prompt_tokens":-9223372036854775808,"completion_tokens":-5}}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Usage == nil || resp.Usage.PromptTokens != 0 || resp.Usage.CompletionTokens != 0 {
		t.Fatalf("usage: %+v", resp.Usage)
	}
	resp, err = decodeResponse([]byte(`{"choices":[{"message":{"content":"x"}}]}`))
	if err != nil || resp.Usage != nil {
		t.Fatalf("missing usage decoded as %+v, %v", resp.Usage, err)
	}
}

func TestChatFailuresHideKeyAndBody(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "upstream says "+testKey, http.StatusInternalServerError)
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://203.0.113.9/v1/chat/completions", http.StatusTemporaryRedirect)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+strings.Repeat("a", MaxResponseBytes)+`"}}]}`)
		},
		"malformed": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"choices":`) },
		"no choice": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"choices":[]}`) },
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(h)
			defer srv.Close()
			c := tlsClient(t, srv, writeKeyFile(t, testKey))
			_, err := c.Chat(context.Background(), Request{MaxTokens: 1})
			if !errors.Is(err, ErrCall) {
				t.Fatalf("err = %v, want ErrCall", err)
			}
			if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "upstream") {
				t.Fatalf("error leaks key or body: %v", err)
			}
		})
	}
}

func TestChatHonoursContextDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	c, err := New(Options{BaseURL: srv.URL, Model: "m", AllowPlainHTTP: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Chat(ctx, Request{MaxTokens: 1}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("call outlived its context")
	}
}

// longBaseURL is a valid https base URL of exactly n bytes.
func longBaseURL(n int) string {
	const prefix = "https://127.0.0.1/"
	return prefix + strings.Repeat("v", n-len(prefix))
}

// paddedResponse is a valid chat-completions body of exactly n bytes:
// one tool call, then JSON whitespace.
func paddedResponse(n int) string {
	const body = `{"choices":[{"message":{"tool_calls":[{"id":"c1","type":"function","function":{"name":"kev_epss","arguments":"{}"}}]}}]}`
	return body + strings.Repeat(" ", n-len(body))
}

func TestChatResponseSizeLimit(t *testing.T) {
	for _, tc := range []struct {
		size int
		ok   bool
	}{{MaxResponseBytes, true}, {MaxResponseBytes + 1, false}} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, paddedResponse(tc.size))
		}))
		c := tlsClient(t, srv, "")
		resp, err := c.Chat(context.Background(), Request{MaxTokens: 1})
		srv.Close()
		switch {
		case tc.ok && (err != nil || len(resp.ToolCalls) != 1):
			t.Errorf("valid body of %d bytes: %+v %v", tc.size, resp, err)
		case !tc.ok && !errors.Is(err, ErrCall):
			t.Errorf("body of %d bytes (over the limit): err = %v, want ErrCall", tc.size, err)
		}
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	key := writeKeyFile(t, testKey)
	cases := map[string]Options{
		"plain http not allowed": {BaseURL: "http://127.0.0.1:11434/v1", Model: "m", Timeout: time.Second},
		"key over plain http":    {BaseURL: "http://127.0.0.1:11434/v1", Model: "m", CredentialFile: key, AllowPlainHTTP: true, Timeout: time.Second},
		"userinfo":               {BaseURL: "https://u:p@127.0.0.1/v1", Model: "m", Timeout: time.Second},
		"query":                  {BaseURL: "https://127.0.0.1/v1?x=1", Model: "m", Timeout: time.Second},
		"scheme":                 {BaseURL: "file:///etc/passwd", Model: "m", Timeout: time.Second},
		"no model":               {BaseURL: "https://127.0.0.1/v1", Timeout: time.Second},
		"model space":            {BaseURL: "https://127.0.0.1/v1", Model: "a b", Timeout: time.Second},
		"timeout zero":           {BaseURL: "https://127.0.0.1/v1", Model: "m"},
		"timeout over max":       {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: HardMaxTimeout + 1},
		"empty key file":         {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: writeKeyFile(t, "\n")},
		"two-line key file":      {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: writeKeyFile(t, "a\nb")},
		"oversized key file":     {BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: writeKeyFile(t, strings.Repeat("k", MaxAPIKeyFileBytes+1))},
		"model too long":         {BaseURL: "https://127.0.0.1/v1", Model: strings.Repeat("m", MaxModelBytes+1), Timeout: time.Second},
		"base url too long":      {BaseURL: longBaseURL(MaxBaseURLBytes + 1), Model: "m", Timeout: time.Second},
	}
	for name, o := range cases {
		if _, err := New(o); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v", name, err)
		} else if strings.Contains(err.Error(), testKey) {
			t.Errorf("%s: error leaks key", name)
		}
	}
	// The same values at their limits are accepted, so the rejections above
	// are the size checks.
	if _, err := New(Options{BaseURL: longBaseURL(MaxBaseURLBytes), Model: strings.Repeat("m", MaxModelBytes), Timeout: time.Second}); err != nil {
		t.Fatalf("model and base url at their limits rejected: %v", err)
	}
}

func TestNewUsesProxyFreeTransport(t *testing.T) {
	c, err := New(Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := c.http.Transport.(*http.Transport); !ok || tr.Proxy != nil || tr.DialContext != nil {
		t.Fatalf("default transport: %T proxy/dial set", c.http.Transport)
	}
}

func TestCheckEndpointNoopWithoutLabOnly(t *testing.T) {
	if err := CheckEndpoint(context.Background(), Options{BaseURL: "https://203.0.113.7/v1"}); err != nil {
		t.Fatalf("lab-only off: %v", err)
	}
}
