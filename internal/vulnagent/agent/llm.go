// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client limits.
const (
	// MaxLLMResponseBytes bounds one chat-completions response body.
	MaxLLMResponseBytes = 1 << 20
	// MaxAPIKeyFileBytes bounds the API key file.
	MaxAPIKeyFileBytes = 4 << 10
	// MaxModelBytes bounds the model name.
	MaxModelBytes = 128
	// MaxBaseURLBytes bounds the base URL.
	MaxBaseURLBytes = 512
)

// ErrLLM reports a failed LLM call. Its messages never hold the API key,
// the response body or model text.
var ErrLLM = errors.New("vulnagent/agent: llm call failed")

// Message is one chat message.
type Message struct {
	// Role is system, user, assistant or tool.
	Role string
	// Content is the message text.
	Content string
	// ToolCalls are the assistant's kept tool calls.
	ToolCalls []ToolCall
	// ToolCallID links a tool result to its call.
	ToolCallID string
}

// ToolCall is one tool call returned by the model.
type ToolCall struct {
	// ID is the call ID.
	ID string
	// Name is the tool name.
	Name string
	// Arguments is the raw JSON argument string.
	Arguments string
}

// Request is one chat-completions request.
type Request struct {
	// Messages is the history.
	Messages []Message
	// Tools are the tool definitions.
	Tools []ToolDef
	// MaxTokens is the max_tokens of the call.
	MaxTokens int
}

// Usage is the token usage an endpoint reports.
type Usage struct {
	// PromptTokens is the reported prompt token count.
	PromptTokens int64
	// CompletionTokens is the reported completion token count.
	CompletionTokens int64
}

// Response is the first choice of a chat-completions answer.
type Response struct {
	// Content is free model text (always discarded by the loop).
	Content string
	// ToolCalls are the returned tool calls in response order.
	ToolCalls []ToolCall
	// Usage is nil when the endpoint reported none.
	Usage *Usage
}

// LLM is a chat-completions endpoint with tool calling.
type LLM interface {
	// Complete makes one call.
	Complete(ctx context.Context, req Request) (Response, error)
}

// ClientConfig configures an HTTPClient.
type ClientConfig struct {
	// BaseURL is the OpenAI-compatible base, e.g. "https://llm.lab/v1";
	// "/chat/completions" is appended.
	BaseURL string
	// Model is the model name.
	Model string
	// APIKeyFile is an optional file holding the bearer token.
	APIKeyFile string
	// AllowPlainHTTP permits an http base URL (then no API key may be set).
	AllowPlainHTTP bool
	// Timeout bounds one call (1 .. HardMaxLLMCallTimeout).
	Timeout time.Duration
	// Transport overrides the HTTP transport (tests); nil uses a
	// transport without proxy.
	Transport http.RoundTripper
}

// HTTPClient is an OpenAI-compatible chat-completions client. It sends no
// streaming request, follows no redirect and ignores proxy variables.
type HTTPClient struct {
	endpoint string
	model    string
	apiKey   string
	http     *http.Client
}

// NewHTTPClient validates cfg and reads the API key file.
func NewHTTPClient(cfg ClientConfig) (*HTTPClient, error) {
	u, err := validateBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Model == "" || len(cfg.Model) > MaxModelBytes || !printableASCII(cfg.Model) {
		return nil, fmt.Errorf("llm model: %w", ErrInvalidConfig)
	}
	if cfg.Timeout < 1 || cfg.Timeout > HardMaxLLMCallTimeout {
		return nil, fmt.Errorf("llm timeout outside 1ns..%s: %w", HardMaxLLMCallTimeout, ErrInvalidConfig)
	}
	var key string
	if cfg.APIKeyFile != "" {
		if key, err = readAPIKey(cfg.APIKeyFile); err != nil {
			return nil, err
		}
	}
	if u.Scheme == "http" {
		if !cfg.AllowPlainHTTP {
			return nil, fmt.Errorf("llm base url: plain http not allowed: %w", ErrInvalidConfig)
		}
		if key != "" {
			return nil, fmt.Errorf("llm base url: api key over plain http refused: %w", ErrInvalidConfig)
		}
	}
	tr := cfg.Transport
	if tr == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		tr = t
	}
	return &HTTPClient{
		endpoint: strings.TrimSuffix(u.String(), "/") + "/chat/completions",
		model:    cfg.Model,
		apiKey:   key,
		http: &http.Client{
			Transport:     tr,
			Timeout:       cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func validateBaseURL(s string) (*url.URL, error) {
	if s == "" || len(s) > MaxBaseURLBytes || !printableASCII(s) {
		return nil, fmt.Errorf("llm base url: %w", ErrInvalidConfig)
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("llm base url: must be http(s) with host, no userinfo, query or fragment: %w", ErrInvalidConfig)
	}
	return u, nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// readAPIKey reads a bearer token: one line of printable ASCII from a
// regular file that neither group nor others can access (mode 0600 or
// 0400), like the NOS token file.
func readAPIKey(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open llm api key file: %w", errors.Unwrap(err))
	}
	defer f.Close()
	// Stat the opened file, not the path, so the checked file is the read
	// one.
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat llm api key file: %w", ErrInvalidConfig)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("llm api key file (mode %v) must be a regular file with mode 0600 or 0400: %w", fi.Mode(), ErrInvalidConfig)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxAPIKeyFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("read llm api key file: %w", ErrInvalidConfig)
	}
	if len(b) > MaxAPIKeyFileBytes {
		return "", fmt.Errorf("llm api key file larger than %d bytes: %w", MaxAPIKeyFileBytes, ErrInvalidConfig)
	}
	key := strings.TrimRight(string(b), "\r\n")
	if key == "" || !printableASCII(key) {
		return "", fmt.Errorf("llm api key file: empty or not one line of printable ASCII: %w", ErrInvalidConfig)
	}
	return key, nil
}

// Wire format (OpenAI chat completions).
type (
	wireFunction struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	}
	wireToolCall struct {
		ID       string       `json:"id"`
		Type     string       `json:"type"`
		Function wireFunction `json:"function"`
	}
	wireMessage struct {
		Role       string         `json:"role"`
		Content    string         `json:"content"`
		ToolCalls  []wireToolCall `json:"tool_calls,omitempty"`
		ToolCallID string         `json:"tool_call_id,omitempty"`
	}
	wireToolDef struct {
		Type     string `json:"type"`
		Function struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
		} `json:"function"`
	}
	wireRequest struct {
		Model             string        `json:"model"`
		Messages          []wireMessage `json:"messages"`
		Tools             []wireToolDef `json:"tools"`
		MaxTokens         int           `json:"max_tokens"`
		Temperature       float64       `json:"temperature"`
		Stream            bool          `json:"stream"`
		ParallelToolCalls bool          `json:"parallel_tool_calls"`
	}
	wireResponse struct {
		Choices []struct {
			Message struct {
				Content   *string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
)

// encodeMessages converts the history to the wire format.
func encodeMessages(msgs []Message) []wireMessage {
	out := make([]wireMessage, len(msgs))
	for i, m := range msgs {
		w := wireMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID}
		for _, c := range m.ToolCalls {
			w.ToolCalls = append(w.ToolCalls, wireToolCall{ID: c.ID, Type: "function", Function: wireFunction{c.Name, c.Arguments}})
		}
		out[i] = w
	}
	return out
}

func encodeTools(defs []ToolDef) []wireToolDef {
	out := make([]wireToolDef, len(defs))
	for i, d := range defs {
		out[i].Type = "function"
		out[i].Function.Name = d.Name
		out[i].Function.Description = d.Description
		out[i].Function.Parameters = d.Parameters
	}
	return out
}

// Complete makes one non-streaming chat-completions call with
// parallel_tool_calls = false.
func (c *HTTPClient) Complete(ctx context.Context, req Request) (Response, error) {
	body, err := json.Marshal(wireRequest{
		Model: c.model, Messages: encodeMessages(req.Messages), Tools: encodeTools(req.Tools),
		MaxTokens: req.MaxTokens, Temperature: 0, Stream: false, ParallelToolCalls: false,
	})
	if err != nil {
		return Response{}, fmt.Errorf("encode request: %w", err)
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", ErrLLM)
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		hr.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, fmt.Errorf("llm call: %w", ctx.Err())
		}
		return Response{}, fmt.Errorf("llm call: transport error: %w", ErrLLM)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("llm call: status %d: %w", resp.StatusCode, ErrLLM)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxLLMResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("llm call: read response: %w", ErrLLM)
	}
	if len(data) > MaxLLMResponseBytes {
		return Response{}, fmt.Errorf("llm call: response larger than %d bytes: %w", MaxLLMResponseBytes, ErrLLM)
	}
	return decodeResponse(data)
}

// decodeResponse parses the first choice. Arguments may arrive as a JSON
// string (OpenAI) or as an object (some compatible servers); an object is
// kept as its raw JSON text.
func decodeResponse(data []byte) (Response, error) {
	var w wireResponse
	if err := json.Unmarshal(data, &w); err != nil {
		return Response{}, fmt.Errorf("llm call: malformed response: %w", ErrLLM)
	}
	if len(w.Choices) == 0 {
		return Response{}, fmt.Errorf("llm call: no choice: %w", ErrLLM)
	}
	m := w.Choices[0].Message
	var out Response
	if m.Content != nil {
		out.Content = *m.Content
	}
	for _, tc := range m.ToolCalls {
		args := string(tc.Function.Arguments)
		var s string
		if len(tc.Function.Arguments) > 0 && tc.Function.Arguments[0] == '"' {
			if err := json.Unmarshal(tc.Function.Arguments, &s); err != nil {
				return Response{}, fmt.Errorf("llm call: malformed tool arguments: %w", ErrLLM)
			}
			args = s
		}
		out.ToolCalls = append(out.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: args})
	}
	if w.Usage != nil {
		out.Usage = &Usage{PromptTokens: max(w.Usage.PromptTokens, 0), CompletionTokens: max(w.Usage.CompletionTokens, 0)}
	}
	return out, nil
}
