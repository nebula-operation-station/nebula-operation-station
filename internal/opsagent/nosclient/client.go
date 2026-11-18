// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"
	"unicode/utf8"
)

// API paths of the ops API (ADR 0016 D2, internal/web/api OpsPrefix).
const (
	opsPrefix       = "/api/v1/ops/"
	agentConfigPath = opsPrefix + "agent-config"
	workPath        = opsPrefix + "work"
	notesPath       = opsPrefix + "notes"
	statusPath      = opsPrefix + "status"
)

// Limits on server answers and requests, named next to their use.
const (
	// MaxConfigBytes bounds the agent-config answer.
	MaxConfigBytes = 16 << 10
	// MaxWorkBytes bounds the work list: at most 20 items of 32 KiB each,
	// plus framing.
	MaxWorkBytes = 1 << 20
	// MaxNoteReplyBytes bounds the answer to a note post.
	MaxNoteReplyBytes = 4 << 10
	// MaxNoteRequestBytes bounds one note post; the server refuses more.
	MaxNoteRequestBytes = 64 << 10
	// MaxStatusRequestBytes bounds one status post.
	MaxStatusRequestBytes = 4 << 10
	// requestTimeout bounds one request to the NOS API.
	requestTimeout = 30 * time.Second
)

// Sentinel errors callers branch on.
var (
	// ErrUnauthorized: the server refused the token (401).
	ErrUnauthorized = errors.New("token refused")
	// ErrForbidden: the token lacks the scope or the source address (403).
	ErrForbidden = errors.New("forbidden")
	// ErrNoteRejected: the server refused a note (400, 404, 409, 422).
	ErrNoteRejected = errors.New("note rejected")
	// ErrRejected: the server refused a request as malformed.
	ErrRejected = errors.New("request rejected")
	// ErrUnavailable: the server failed (5xx) or was unreachable.
	ErrUnavailable = errors.New("server unavailable")
	// ErrTooLarge: an answer or request exceeds its limit.
	ErrTooLarge = errors.New("exceeds a limit")
	// ErrProtocol: the server's answer breaks the API contract.
	ErrProtocol = errors.New("protocol violation")
	// ErrBaseURL: the configured base URL is refused.
	ErrBaseURL = errors.New("base url refused")
)

// Config configures a Client.
type Config struct {
	// BaseURL is the NOS API base without path. It is https, or http with
	// a loopback IP literal (the agent runs on the NOS host, ADR 0016 D13).
	BaseURL string
	// TokenFile holds the API bearer token (mode 0600 or 0400).
	TokenFile string
	// CAFile, when set, is a PEM file with the only CA certificates the
	// server certificate is verified against (pinned CA). Verification is
	// never turned off.
	CAFile string
	// Transport overrides the HTTP transport; nil uses a default transport
	// that ignores proxy variables and follows no redirect. Tests use it.
	Transport http.RoundTripper
}

// MaxCAFileBytes bounds the pinned CA file.
const MaxCAFileBytes = 1 << 20

// Client talks to the four ops endpoints. It holds the token only as a
// Token value, which never prints.
type Client struct {
	base  string
	token Token
	http  *http.Client
}

// New validates cfg and reads the token file.
func New(cfg Config) (*Client, error) {
	base, err := checkBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	tok, err := LoadToken(cfg.TokenFile)
	if err != nil {
		return nil, err
	}
	rt := cfg.Transport
	if rt == nil {
		roots, err := pinnedRoots(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		rt = &http.Transport{
			DialContext:         (&net.Dialer{Timeout: requestTimeout}).DialContext,
			TLSHandshakeTimeout: requestTimeout,
			DisableKeepAlives:   true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		}
	}
	return &Client{
		base:  base,
		token: tok,
		http: &http.Client{
			Transport:     rt,
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// pinnedRoots returns the pinned CA pool from a PEM file, or nil (the system
// pool) when no file is named.
func pinnedRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ca file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read ca file: %w", err)
	}
	if len(raw) > MaxCAFileBytes {
		return nil, fmt.Errorf("ca file: %w", ErrTooLarge)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("ca file holds no certificate")
	}
	return pool, nil
}

// checkBaseURL accepts https URLs and http URLs whose host is a loopback IP
// literal, without path, query or credentials. Its errors never carry the
// configured URL: a refused URL may hold credentials, and the error reaches
// the journal. (url.Parse errors embed the URL, so they are not wrapped.)
func checkBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("nos base url does not parse: %w", ErrBaseURL)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("nos base url has userinfo, path, query or fragment, or no host: %w", ErrBaseURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		a, err := netip.ParseAddr(u.Hostname())
		if err != nil || !a.IsLoopback() {
			return "", fmt.Errorf("nos base url: plain http only to a loopback address: %w", ErrBaseURL)
		}
	default:
		return "", fmt.Errorf("nos base url: scheme must be https: %w", ErrBaseURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// AgentConfig is the settings answer of GET agent-config.
type AgentConfig struct {
	Enabled              bool   `json:"enabled"`
	LLMBaseURL           string `json:"llm_base_url"`
	LLMModel             string `json:"llm_model"`
	AllowPlainHTTP       bool   `json:"allow_plain_http"`
	DataClass            string `json:"data_class"`
	Language             string `json:"language"`
	OperatorInstructions string `json:"operator_instructions"`
	PromptVersion        string `json:"prompt_version"`
	Version              int64  `json:"version"`
}

// Counts are per-tier counters of findings.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	KEV      int `json:"kev"`
}

// Host is the host part of a lab group.
type Host struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Environment string `json:"environment"`
	Criticality string `json:"criticality"`
}

// Finding is one finding of a lab group.
type Finding struct {
	VulnID    string `json:"vuln_id"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed,omitempty"`
	Tier      string `json:"tier"`
	Score     int    `json:"score"`
	KEV       bool   `json:"kev"`
	Fix       string `json:"fix_status"`
}

// Port is one listening port.
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
}

// Candidate is one step the server offers for a group.
type Candidate struct {
	Key    string `json:"key"`
	Action string `json:"action"`
	HostID string `json:"host_id"`
	Label  string `json:"label"`
}

// Group is the lab projection of one finding group (class lab only).
type Group struct {
	Group        string      `json:"group"`
	Host         Host        `json:"host"`
	Exposure     string      `json:"exposure"`
	Ports        []Port      `json:"ports"`
	PortsOmitted int         `json:"ports_omitted"`
	Findings     []Finding   `json:"findings"`
	Omitted      Counts      `json:"omitted"`
	Counts       Counts      `json:"counts"`
	Candidates   []Candidate `json:"candidates"`
}

// WorkItem is one due item of the work list.
type WorkItem struct {
	Kind   string  `json:"kind"`
	Ref    string  `json:"ref"`
	Digest string  `json:"digest"`
	Group  *Group  `json:"group,omitempty"`
	Fleet  *Counts `json:"fleet,omitempty"`
}

// Draft is a note as the agent posts it. It carries only the fields the
// server accepts for the kind; the server rejects unknown fields.
type Draft struct {
	Kind        string   `json:"kind"`
	Ref         string   `json:"ref"`
	Digest      string   `json:"digest"`
	Summary     string   `json:"summary,omitempty"`
	Text        string   `json:"text,omitempty"`
	Urgency     string   `json:"urgency,omitempty"`
	Steps       []Step   `json:"steps,omitempty"`
	Mitigations []string `json:"mitigations,omitempty"`
	Citations   []string `json:"citations,omitempty"`
}

// Step is one step of a fix note: a catalog action on a host.
type Step struct {
	ActionID string `json:"action_id"`
	HostID   string `json:"host_id"`
	Why      string `json:"why,omitempty"`
}

// Status is the agent's last-run report.
type Status struct {
	RunAt        string   `json:"run_at"`
	ItemsSeen    int      `json:"items_seen"`
	LLMCalls     int      `json:"llm_calls"`
	Discarded    int      `json:"discarded"`
	NotesWritten int      `json:"notes_written"`
	Refusals     []string `json:"refusals"`
}

// AgentConfig reads the settings (GET agent-config).
func (c *Client) AgentConfig(ctx context.Context) (AgentConfig, error) {
	var out AgentConfig
	if err := c.get(ctx, agentConfigPath, MaxConfigBytes, &out); err != nil {
		return AgentConfig{}, err
	}
	return out, nil
}

// Work reads the due items (GET work).
func (c *Client) Work(ctx context.Context) ([]WorkItem, error) {
	var out struct {
		Items []WorkItem `json:"items"`
	}
	if err := c.get(ctx, workPath, MaxWorkBytes, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// PostNote posts one note (POST notes). A refused note gives ErrNoteRejected.
func (c *Client) PostNote(ctx context.Context, d Draft) error {
	body, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("encode note: %w", ErrProtocol)
	}
	if len(body) > MaxNoteRequestBytes {
		return fmt.Errorf("note request: %w", ErrTooLarge)
	}
	return c.post(ctx, notesPath, body, MaxNoteReplyBytes, nil)
}

// PostStatus posts the last-run report (POST status).
func (c *Client) PostStatus(ctx context.Context, s Status) error {
	body, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode status: %w", ErrProtocol)
	}
	if len(body) > MaxStatusRequestBytes {
		return fmt.Errorf("status request: %w", ErrTooLarge)
	}
	return c.post(ctx, statusPath, body, MaxNoteReplyBytes, nil)
}

// get reads one JSON answer of at most limit bytes into out.
func (c *Client) get(ctx context.Context, path string, limit int64, out any) error {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return c.do(req, path, limit, out)
}

// post sends one JSON body; a 204 or an empty answer is success.
func (c *Client) post(ctx context.Context, path string, body []byte, limit int64, out any) error {
	req, err := c.newRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, path, limit, out)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, ErrRejected)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.value)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// do runs req. The error text names the path and the status only; it never
// carries the answer body, the token or any request content.
func (c *Client) do(req *http.Request, path string, limit int64, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", path, ErrUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %d: %w", path, resp.StatusCode, statusKind(resp.StatusCode, req.Method, path))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("%s: %w", path, ErrUnavailable)
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("%s: %w", path, ErrTooLarge)
	}
	if out == nil {
		return nil
	}
	if len(raw) == 0 {
		return fmt.Errorf("%s: empty answer: %w", path, ErrProtocol)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("%s: %w", path, ErrProtocol)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%s: decode answer: %w", path, ErrProtocol)
	}
	if dec.More() {
		return fmt.Errorf("%s: trailing data: %w", path, ErrProtocol)
	}
	return nil
}

func statusKind(code int, method, path string) error {
	switch {
	case code == http.StatusUnauthorized:
		return ErrUnauthorized
	case code == http.StatusForbidden:
		return ErrForbidden
	case code == http.StatusRequestEntityTooLarge:
		return ErrTooLarge
	case code == http.StatusBadRequest || code == http.StatusUnprocessableEntity ||
		code == http.StatusConflict || code == http.StatusNotFound:
		if path == notesPath && method == http.MethodPost {
			return ErrNoteRejected
		}
		return ErrRejected
	case code >= 500:
		return ErrUnavailable
	default:
		return ErrProtocol
	}
}
