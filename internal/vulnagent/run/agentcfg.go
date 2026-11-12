// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
)

// Agent settings read (A1.8).
const (
	// AgentConfigPath is the NOS path of the agent settings.
	AgentConfigPath = "/api/v1/vuln/agent-config"
	// MaxAgentConfigBytes bounds the answer.
	MaxAgentConfigBytes = 64 << 10
	// agentConfigTimeout bounds the request.
	agentConfigTimeout = 60 * time.Second
)

// secret holds a credential; every way of printing it yields a
// placeholder.
type secret struct{ v string }

func (secret) String() string               { return "[REDACTED]" }
func (secret) GoString() string             { return "[REDACTED]" }
func (secret) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, "[REDACTED]") }
func (secret) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }
func (secret) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// HTTPAgentConfig reads the LLM settings from NOS with the agent token.
type HTTPAgentConfig struct {
	endpoint string
	token    secret
	http     *http.Client
}

// AgentConfigOptions configure NewHTTPAgentConfig; the values are those of
// nosclient.Config.
type AgentConfigOptions struct {
	BaseURL   string
	TokenFile string
	CAFile    string
}

// NewHTTPAgentConfig builds the settings reader. The token file passes
// nosclient's checks (mode, size, printable ASCII) before it is read.
func NewHTTPAgentConfig(o AgentConfigOptions) (*HTTPAgentConfig, error) {
	u, err := url.Parse(o.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("agent settings: base URL must be https://host[:port]: %w", ErrConfig)
	}
	if _, err := nosclient.LoadToken(o.TokenFile); err != nil {
		return nil, fmt.Errorf("agent settings: %w", err)
	}
	tok, err := readToken(o.TokenFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pool, err := loadCA(o.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	return &HTTPAgentConfig{
		endpoint: (&url.URL{Scheme: "https", Host: u.Host, Path: AgentConfigPath}).String(),
		token:    tok,
		http: &http.Client{
			Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true,
				TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: agentConfigTimeout},
			Timeout: agentConfigTimeout,
			// The token never follows a redirect.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// readToken reads the token file that nosclient.LoadToken accepted.
func readToken(path string) (secret, error) {
	f, err := os.Open(path)
	if err != nil {
		return secret{}, fmt.Errorf("agent settings: open token file: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, nosclient.MaxTokenBytes+2))
	if err != nil {
		return secret{}, fmt.Errorf("agent settings: read token file: %w", err)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" || len(s) > nosclient.MaxTokenBytes || !printableASCII(s) {
		return secret{}, fmt.Errorf("agent settings: %w", nosclient.ErrTokenMalformed)
	}
	return secret{v: s}, nil
}

func loadCA(path string) (*x509.CertPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("agent settings: load CA: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, nosclient.MaxCAFileBytes+1))
	if err != nil || len(b) > nosclient.MaxCAFileBytes {
		return nil, fmt.Errorf("agent settings: load CA %s: unreadable or too large: %w", path, ErrConfig)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("agent settings: load CA %s: no PEM certificate: %w", path, ErrConfig)
	}
	return pool, nil
}

type agentConfigJSON struct {
	LLMEnabled           *bool  `json:"llm_enabled"`
	LLMBaseURL           string `json:"llm_base_url"`
	LLMModel             string `json:"llm_model"`
	OperatorInstructions string `json:"operator_instructions"`
	Language             string `json:"language"`
	PromptVersion        string `json:"prompt_version"`
	Version              int64  `json:"version"`
}

// AgentConfig implements AgentConfigSource. The answer is untrusted: it is
// size-bounded and shape-checked here; the URL and model are validated
// again by the run before use. A 404 means an older NOS without the
// endpoint (ErrNoRemoteSettings).
func (c *HTTPAgentConfig) AgentConfig(ctx context.Context) (RemoteLLM, error) {
	ctx, cancel := context.WithTimeout(ctx, agentConfigTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return RemoteLLM{}, fmt.Errorf("agent settings: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.v)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return RemoteLLM{}, fmt.Errorf("agent settings: %s", c.redact(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxAgentConfigBytes+1))
	if err != nil {
		return RemoteLLM{}, fmt.Errorf("agent settings: read answer: %s", c.redact(err.Error()))
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return RemoteLLM{}, ErrNoRemoteSettings
	case resp.StatusCode != http.StatusOK:
		return RemoteLLM{}, fmt.Errorf("agent settings: HTTP %d", resp.StatusCode)
	}
	if len(body) > MaxAgentConfigBytes {
		return RemoteLLM{}, fmt.Errorf("agent settings: answer over %d bytes", MaxAgentConfigBytes)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" || !utf8.Valid(body) {
		return RemoteLLM{}, errors.New("agent settings: answer is not UTF-8 JSON")
	}
	var j agentConfigJSON
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&j); err != nil || dec.More() || j.LLMEnabled == nil {
		return RemoteLLM{}, errors.New("agent settings: malformed answer")
	}
	if len(j.LLMBaseURL) > MaxLLMURLBytes || len(j.LLMModel) > MaxLLMModelBytes || len(j.OperatorInstructions) > agent.MaxOperatorInstructionsBytes ||
		(j.Language != "" && j.Language != "de" && j.Language != "en") || j.Version < 0 {
		return RemoteLLM{}, errors.New("agent settings: value out of bounds")
	}
	return RemoteLLM{Enabled: *j.LLMEnabled, BaseURL: j.LLMBaseURL, Model: j.LLMModel,
		OperatorInstructions: j.OperatorInstructions, Language: j.Language, Version: j.Version}, nil
}

func (c *HTTPAgentConfig) redact(s string) string {
	if c.token.v == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token.v, "[REDACTED]")
}
