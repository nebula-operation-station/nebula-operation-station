// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testAPIToken = "nos_ops-agent-test-token"

// newTestClient starts a loopback server with handler and a client for it.
func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(testAPIToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{BaseURL: srv.URL, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBaseURLRefusedUnlessHTTPSOrLoopback(t *testing.T) {
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(testAPIToken), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://nos.lab.example:8443": true,
		"https://192.168.1.10:8443":    true,
		"http://127.0.0.1:8080":        true,
		"http://[::1]:8080":            true,
		"http://192.168.1.10:8080":     false,
		"http://nos.lab.example":       false,
		"https://nos.lab.example/api":  false,
		"https://nos.lab.example?x=1":  false,
		"https://user@nos.lab.example": false,
		"ftp://127.0.0.1":              false,
		"":                             false,
	}
	for raw, ok := range cases {
		_, err := New(Config{BaseURL: raw, TokenFile: tok})
		if ok && err != nil {
			t.Errorf("%q: %v, want accepted", raw, err)
		}
		if !ok && !errors.Is(err, ErrBaseURL) {
			t.Errorf("%q: %v, want ErrBaseURL", raw, err)
		}
	}
}

// TestBaseURLErrorsNeverCarryTheURL: a refused base URL may hold credentials;
// neither its text nor its parts may reach the error that the journal logs.
func TestBaseURLErrorsNeverCarryTheURL(t *testing.T) {
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte(testAPIToken), 0o600); err != nil {
		t.Fatal(err)
	}
	const secret = "s3cret-pass"
	cases := []string{
		"https://ops:" + secret + "@nos.lab.example",
		"http://ops:" + secret + "@192.168.1.10:8080",
		"https://nos.lab.example/api?token=" + secret,
		"https://nos.lab.example/" + secret + "#frag",
		"ftp://ops:" + secret + "@127.0.0.1",
		"https://[" + secret + "/",
		"https://nos lab " + secret,
	}
	for _, raw := range cases {
		_, err := New(Config{BaseURL: raw, TokenFile: tok})
		if !errors.Is(err, ErrBaseURL) {
			t.Fatalf("%q: %v, want ErrBaseURL", raw, err)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "nos.lab.example") {
			t.Errorf("error carries the configured URL: %v", err)
		}
	}
}

func TestSendsBearerTokenAndDecodesConfig(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testAPIToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != agentConfigPath || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"enabled":true,"llm_base_url":"http://10.0.0.5:8000/v1","llm_model":"m",` +
			`"allow_plain_http":true,"data_class":"lab","language":"de","operator_instructions":"","prompt_version":"p","version":3}`))
	})
	cfg, err := c.AgentConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.DataClass != "lab" || cfg.Version != 3 {
		t.Fatalf("config %+v", cfg)
	}
}

func TestAnswersAreStrictlyDecoded(t *testing.T) {
	bodies := map[string]string{
		"unknown field": `{"items":[],"extra":1}`,
		"trailing":      `{"items":[]} {}`,
		"not json":      `<html>`,
		"invalid utf8":  "{\"items\":[],\"x\":\"\xff\"}",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
			if _, err := c.Work(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Work: %v, want ErrProtocol", err)
			}
		})
	}
}

func TestOversizedAnswerRefused(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[],"pad":"` + strings.Repeat("a", MaxWorkBytes) + `"}`))
	})
	if _, err := c.Work(context.Background()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Work: %v, want ErrTooLarge", err)
	}
}

func TestNotePostStatusMapping(t *testing.T) {
	cases := map[int]error{
		http.StatusCreated:             nil,
		http.StatusConflict:            ErrNoteRejected,
		http.StatusUnprocessableEntity: ErrNoteRejected,
		http.StatusForbidden:           ErrForbidden,
		http.StatusUnauthorized:        ErrUnauthorized,
		http.StatusInternalServerError: ErrUnavailable,
	}
	for code, want := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != notesPath || r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("path %s content type %q", r.URL.Path, r.Header.Get("Content-Type"))
			}
			w.WriteHeader(code)
		})
		err := c.PostNote(context.Background(), Draft{Kind: "summary", Ref: "2026-11-18", Digest: strings.Repeat("a", 64), Text: "x"})
		if want == nil && err != nil {
			t.Errorf("code %d: %v, want nil", code, err)
		}
		if want != nil && !errors.Is(err, want) {
			t.Errorf("code %d: %v, want %v", code, err, want)
		}
		if err != nil && strings.Contains(err.Error(), testAPIToken) {
			t.Errorf("code %d: error carries the token: %v", code, err)
		}
	}
}

func TestStatusPostNeverPrintsToken(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	err := c.PostStatus(context.Background(), Status{RunAt: "2026-11-18T10:00:00Z", Refusals: []string{"llm_timeout"}})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("PostStatus: %v, want ErrRejected", err)
	}
	if strings.Contains(err.Error(), testAPIToken) {
		t.Fatalf("error carries the token: %v", err)
	}
}

func TestTokenValueNeverPrints(t *testing.T) {
	var tok Token
	tok.value = testAPIToken
	for _, s := range []string{tok.String(), tok.GoString()} {
		if strings.Contains(s, testAPIToken) {
			t.Fatalf("printed %q", s)
		}
	}
}
