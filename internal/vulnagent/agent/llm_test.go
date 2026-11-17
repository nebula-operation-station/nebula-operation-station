// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/llmclient"
)

// The client itself is tested in internal/llmclient. These tests pin what
// this package adds: the error texts and sentinels the assessor reports.

func TestNewLLMRefusalKeepsAgentSentinelAndText(t *testing.T) {
	_, err := NewLLM(llmclient.Options{BaseURL: "https://127.0.0.1/v1", Timeout: time.Second})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v, want ErrInvalidConfig", err)
	}
	if want := "llm model: vulnagent/agent: invalid configuration"; err.Error() != want {
		t.Fatalf("text = %q, want %q", err.Error(), want)
	}
}

func TestNewLLMKeyFileErrorKeepsText(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing")
	_, err := NewLLM(llmclient.Options{BaseURL: "https://127.0.0.1/v1", Model: "m", Timeout: time.Second, CredentialFile: p})
	if err == nil || !strings.HasPrefix(err.Error(), "open llm api key file: ") || errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing key file: err = %v", err)
	}
}

func TestLLMCallFailureKeepsAgentSentinelAndText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream says secret", http.StatusInternalServerError)
	}))
	defer srv.Close()
	llm, err := NewLLM(llmclient.Options{LabOnly: true, BaseURL: srv.URL, Model: "m", AllowPlainHTTP: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = llm.Complete(context.Background(), Request{MaxTokens: 1})
	if !errors.Is(err, ErrLLM) {
		t.Fatalf("err = %v, want ErrLLM", err)
	}
	if want := "llm call: status 500: vulnagent/agent: llm call failed"; err.Error() != want {
		t.Fatalf("text = %q, want %q", err.Error(), want)
	}
}

func TestLLMCallPassesContextErrorThrough(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	llm, err := NewLLM(llmclient.Options{LabOnly: true, BaseURL: srv.URL, Model: "m", AllowPlainHTTP: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = llm.Complete(ctx, Request{MaxTokens: 1})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLLM) {
		t.Fatalf("err = %v, want the context deadline without ErrLLM", err)
	}
	if err.Error() != "llm call: context deadline exceeded" {
		t.Fatalf("text = %q", err.Error())
	}
}

func TestEncodedToolsMatchWireShape(t *testing.T) {
	defs := []ToolDef{{Name: "n", Description: "d", Parameters: []byte(`{"type":"object"}`)}}
	got := encodeTools(defs)
	if len(got) != 1 || got[0].Type != "function" || got[0].Function.Name != "n" || got[0].Function.Description != "d" {
		t.Fatalf("encodeTools = %+v", got)
	}
}
