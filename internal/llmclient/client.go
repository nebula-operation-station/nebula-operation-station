// SPDX-License-Identifier: AGPL-3.0-or-later

package llmclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Client limits, named next to the code that enforces them.
const (
	// MaxResponseBytes bounds one chat-completions response body. It is
	// checked before the body is parsed.
	MaxResponseBytes = 1 << 20
	// MaxAPIKeyFileBytes bounds the credential file.
	MaxAPIKeyFileBytes = 4 << 10
	// MaxModelBytes bounds the model name.
	MaxModelBytes = 128
	// MaxBaseURLBytes bounds the base URL.
	MaxBaseURLBytes = 512
	// MaxSchemaBytes bounds a JSON schema sent with a request.
	MaxSchemaBytes = 16 << 10
	// MaxSchemaNameBytes bounds the name of a JSON schema.
	MaxSchemaNameBytes = 64
	// HardMaxTimeout caps Options.Timeout.
	HardMaxTimeout = 300 * time.Second
)

// Sentinels for errors.Is. An *Error matches one of them through Is; the
// text of an *Error is the caller-facing message and never includes the
// sentinel text, so callers choose their own suffix.
var (
	// ErrConfig: the options are refused; no connection was made.
	ErrConfig = errors.New("llmclient: invalid configuration")
	// ErrCall: a chat call failed (transport, status, size or format).
	ErrCall = errors.New("llmclient: call failed")
	// ErrNotLabAddress: the endpoint is, or resolves to, an address outside
	// the lab networks; no connection was made.
	ErrNotLabAddress = errors.New("llmclient: endpoint is not a lab address")
)

// Error is a refused configuration or a failed call. Error returns the
// message only; it never holds a credential, a request or response body.
type Error struct {
	msg   string
	kind  error
	cause error
}

// Error returns the message.
func (e *Error) Error() string { return e.msg }

// Unwrap returns the underlying cause, if any (for example a context error).
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is the sentinel kind of this error.
func (e *Error) Is(target error) bool { return e.kind != nil && target == e.kind }

func cfgErr(msg string) error  { return &Error{msg: msg, kind: ErrConfig} }
func callErr(msg string) error { return &Error{msg: msg, kind: ErrCall} }

// Message is one chat message.
type Message struct {
	// Role is system, user, assistant or tool.
	Role string
	// Content is the message text.
	Content string
	// ToolCalls are the calls an assistant message made.
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

// Tool is one tool definition offered to the model.
type Tool struct {
	// Name is the tool name.
	Name string
	// Description is the tool description.
	Description string
	// Parameters is the JSON schema of the arguments.
	Parameters json.RawMessage
}

// JSONSchema asks the endpoint for an answer that matches Schema.
type JSONSchema struct {
	// Name labels the schema (1..MaxSchemaNameBytes printable ASCII).
	Name string
	// Schema is a JSON object of at most MaxSchemaBytes.
	Schema json.RawMessage
	// Strict asks the endpoint to enforce the schema exactly.
	Strict bool
}

// Request is one chat call.
type Request struct {
	// Messages is the history.
	Messages []Message
	// Tools are optional tool definitions.
	Tools []Tool
	// MaxTokens is the max_tokens of the call.
	MaxTokens int
	// JSONSchema, when set, requests a response in that shape.
	JSONSchema *JSONSchema
}

// Usage is the token usage an endpoint reports.
type Usage struct {
	// PromptTokens is the reported prompt token count, never negative.
	PromptTokens int64
	// CompletionTokens is the reported completion token count, never negative.
	CompletionTokens int64
}

// Response is the first choice of a chat-completions answer.
type Response struct {
	// Content is the message text.
	Content string
	// ToolCalls are the returned tool calls in response order.
	ToolCalls []ToolCall
	// Usage is nil when the endpoint reported none.
	Usage *Usage
}

// Options configures a Client.
type Options struct {
	// BaseURL is the OpenAI-compatible base, e.g. "https://llm.lab/v1";
	// "/chat/completions" is appended.
	BaseURL string
	// Model is the model name.
	Model string
	// CredentialFile is an optional file holding the bearer token.
	CredentialFile string
	// AllowPlainHTTP permits an http base URL. It is refused together
	// with a credential.
	AllowPlainHTTP bool
	// Timeout bounds one call (1ns .. HardMaxTimeout).
	Timeout time.Duration
	// LabOnly selects the lab-only dialer: every connection goes to a lab
	// address, checked after DNS resolution.
	LabOnly bool
	// LabNetworks are extra lab networks, see ParseNetworks. Used with LabOnly.
	LabNetworks []netip.Prefix
	// UnixSocket, with LabOnly, is the absolute path of a Unix socket every
	// connection goes to instead of the endpoint's address.
	UnixSocket string
	// Network overrides resolver, dialer and TLS roots; the zero value uses
	// the system resolver, a plain TCP dialer and the system roots.
	Network Network
}

// Client is an OpenAI-compatible chat-completions client. It sends no
// streaming request, follows no redirect and ignores proxy variables.
type Client struct {
	endpoint string
	model    string
	apiKey   string
	http     *http.Client
}

// New validates opts and reads the credential file.
func New(opts Options) (*Client, error) {
	u, err := validateBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	if opts.Model == "" || len(opts.Model) > MaxModelBytes || !printableASCII(opts.Model) {
		return nil, cfgErr("llm model")
	}
	if opts.Timeout < 1 || opts.Timeout > HardMaxTimeout {
		return nil, cfgErr(fmt.Sprintf("llm timeout outside 1ns..%s", HardMaxTimeout))
	}
	if opts.UnixSocket != "" && !opts.LabOnly {
		return nil, cfgErr("llm unix socket requires the lab-only dialer")
	}
	var key string
	if opts.CredentialFile != "" {
		if key, err = readAPIKey(opts.CredentialFile); err != nil {
			return nil, err
		}
	}
	if u.Scheme == "http" {
		if !opts.AllowPlainHTTP {
			return nil, cfgErr("llm base url: plain http not allowed")
		}
		if key != "" {
			return nil, cfgErr("llm base url: api key over plain http refused")
		}
	}
	return &Client{
		endpoint: strings.TrimSuffix(u.String(), "/") + "/chat/completions",
		model:    opts.Model,
		apiKey:   key,
		http: &http.Client{
			Transport:     newTransport(opts),
			Timeout:       opts.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// CheckEndpoint resolves the endpoint of opts once and refuses it unless
// every address is a lab address (or the Unix socket is configured). A
// client's dialer repeats the check on every connection, so a later DNS
// change is refused too. Only the endpoint is checked here; no credential is
// read.
func CheckEndpoint(ctx context.Context, opts Options) error {
	if !opts.LabOnly {
		return nil
	}
	d := newLabDialer(opts)
	if d.socket != "" {
		return nil
	}
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return errors.New("llm base url: does not parse")
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	_, _, err = d.resolve(ctx, net.JoinHostPort(u.Hostname(), port))
	return err
}

func validateBaseURL(s string) (*url.URL, error) {
	if s == "" || len(s) > MaxBaseURLBytes || !printableASCII(s) {
		return nil, cfgErr("llm base url")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, cfgErr("llm base url: must be http(s) with host, no userinfo, query or fragment")
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

// newTransport is the only transport of a Client: no proxy, verified TLS
// from TLS 1.2, and, with LabOnly, the lab-only dialer.
func newTransport(opts Options) *http.Transport {
	t := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.Network.RootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if opts.LabOnly {
		t.DialContext = newLabDialer(opts).dial
	}
	return t
}

// readAPIKey reads a bearer token: one line of printable ASCII from a
// regular file that neither group nor others can access (mode 0600 or
// 0400), like the NOS token file. The open is non-blocking, so a FIFO or
// device at the path is rejected by the regular-file check instead of
// hanging in open(); for a regular file the flag has no effect.
func readAPIKey(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return "", &Error{msg: "open llm api key file: " + pe.Err.Error()}
		}
		return "", &Error{msg: "open llm api key file"}
	}
	defer f.Close()
	// Stat the opened file, not the path, so the checked file is the read
	// one.
	fi, err := f.Stat()
	if err != nil {
		return "", cfgErr("stat llm api key file")
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return "", cfgErr(fmt.Sprintf("llm api key file (mode %v) must be a regular file with mode 0600 or 0400", fi.Mode()))
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxAPIKeyFileBytes+1))
	if err != nil {
		return "", cfgErr("read llm api key file")
	}
	if len(b) > MaxAPIKeyFileBytes {
		return "", cfgErr(fmt.Sprintf("llm api key file larger than %d bytes", MaxAPIKeyFileBytes))
	}
	key := strings.TrimRight(string(b), "\r\n")
	if key == "" || !printableASCII(key) {
		return "", cfgErr("llm api key file: empty or not one line of printable ASCII")
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
	wireResponseFormat struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Schema json.RawMessage `json:"schema"`
			Strict bool            `json:"strict"`
		} `json:"json_schema"`
	}
	wireRequest struct {
		Model             string              `json:"model"`
		Messages          []wireMessage       `json:"messages"`
		Tools             []wireToolDef       `json:"tools"`
		MaxTokens         int                 `json:"max_tokens"`
		Temperature       float64             `json:"temperature"`
		Stream            bool                `json:"stream"`
		ParallelToolCalls bool                `json:"parallel_tool_calls"`
		ResponseFormat    *wireResponseFormat `json:"response_format,omitempty"`
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

// validateSchema checks a JSON schema before it is sent.
func validateSchema(s *JSONSchema) error {
	if s.Name == "" || len(s.Name) > MaxSchemaNameBytes || !printableASCII(s.Name) {
		return cfgErr("llm json schema name")
	}
	if len(s.Schema) == 0 || len(s.Schema) > MaxSchemaBytes || !json.Valid(s.Schema) || s.Schema[0] != '{' {
		return cfgErr("llm json schema: not a JSON object within the size limit")
	}
	return nil
}

// Chat makes one non-streaming chat-completions call with
// parallel_tool_calls = false. Errors are *Error values: ErrConfig for a
// refused request, ErrCall for a failed call, ErrNotLabAddress for a refused
// endpoint, or the context error.
func (c *Client) Chat(ctx context.Context, req Request) (Response, error) {
	w := wireRequest{
		Model: c.model, Messages: encodeMessages(req.Messages), Tools: encodeTools(req.Tools),
		MaxTokens: req.MaxTokens, Temperature: 0, Stream: false, ParallelToolCalls: false,
	}
	if req.JSONSchema != nil {
		if err := validateSchema(req.JSONSchema); err != nil {
			return Response{}, err
		}
		rf := &wireResponseFormat{Type: "json_schema"}
		rf.JSONSchema.Name = req.JSONSchema.Name
		rf.JSONSchema.Schema = req.JSONSchema.Schema
		rf.JSONSchema.Strict = req.JSONSchema.Strict
		w.ResponseFormat = rf
	}
	body, err := json.Marshal(w)
	if err != nil {
		return Response{}, &Error{msg: "encode request: " + err.Error(), cause: err}
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{}, callErr("build request")
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		hr.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, &Error{msg: "llm call: " + ctx.Err().Error(), cause: ctx.Err()}
		}
		return Response{}, callErr("llm call: transport error")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Response{}, callErr(fmt.Sprintf("llm call: status %d", resp.StatusCode))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return Response{}, callErr("llm call: read response")
	}
	if len(data) > MaxResponseBytes {
		return Response{}, callErr(fmt.Sprintf("llm call: response larger than %d bytes", MaxResponseBytes))
	}
	return decodeResponse(data)
}

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

func encodeTools(defs []Tool) []wireToolDef {
	out := make([]wireToolDef, len(defs))
	for i, d := range defs {
		out[i].Type = "function"
		out[i].Function.Name = d.Name
		out[i].Function.Description = d.Description
		out[i].Function.Parameters = d.Parameters
	}
	return out
}

// decodeResponse parses the first choice. Arguments may arrive as a JSON
// string (OpenAI) or as an object (some compatible servers); an object is
// kept as its raw JSON text.
func decodeResponse(data []byte) (Response, error) {
	var w wireResponse
	if err := json.Unmarshal(data, &w); err != nil {
		return Response{}, callErr("llm call: malformed response")
	}
	if len(w.Choices) == 0 {
		return Response{}, callErr("llm call: no choice")
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
				return Response{}, callErr("llm call: malformed tool arguments")
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
