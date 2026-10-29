// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed, read-only client for the Proxmox VE API
// (ADR 0006, phase 1 read path). It enumerates cluster nodes and QEMU/LXC
// guests, reads guest configurations with secret fields removed, and
// queries the QEMU guest agent (interfaces, OS info, filesystems).
//
// The client performs GET requests only and never issues mutation
// endpoints. TLS trust and certificate pinning are the caller's
// responsibility: the client takes a ready *http.Client and a base URL.
// It never logs request headers or response bodies.
//
// The response types (Node, Guest, GuestConfig, agent results) are
// defined locally in this package.
//
// TODO(pvecontract): internal/pvecontract does not exist yet; when it is
// introduced, move the shared PVE wire types there and switch this
// package to use them.
package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// Response and result limits (ADR 0006, phase 1 read path).
const (
	// MaxResponseBytes is the maximum decoded size of one API response
	// (1 MiB).
	MaxResponseBytes = 1 << 20
	// MaxObjectsPerPage is the maximum number of objects accepted from
	// one list endpoint (nodes, guests).
	MaxObjectsPerPage = 1000
	// MaxGuestsPerRemote is the maximum number of guests accepted per
	// enumeration of one remote.
	MaxGuestsPerRemote = 10000
	// MaxInterfacesPerGuest is the maximum number of guest-agent
	// interfaces accepted per guest.
	MaxInterfacesPerGuest = 128
	// MaxFilesystemsPerGuest is the maximum number of guest-agent
	// filesystems accepted per guest.
	MaxFilesystemsPerGuest = 128
	// MaxTextFieldBytes is the maximum size of one text field taken from
	// a response. Longer values are truncated and the result is marked.
	MaxTextFieldBytes = 4096
	// MaxConfigExtras is the maximum number of untyped non-secret
	// config keys kept in GuestConfig.Extras.
	MaxConfigExtras = 128
	// MaxErrorMessageBytes bounds sanitized error text from responses.
	MaxErrorMessageBytes = 512
	// defaultCallTimeout bounds every API call (ADR 0006: 10 s connect /
	// 30 s request).
	defaultCallTimeout = 30 * time.Second
)

// apiRoot is the Proxmox VE JSON API root appended to the base URL.
const apiRoot = "/api2/json"

// ErrAgentUnavailable reports that the guest agent is not running or not
// reachable. Callers should display it as "unavailable", not as a failure.
var ErrAgentUnavailable = errors.New("pveapi: guest agent unavailable")

// ErrResponseTooLarge reports a response larger than MaxResponseBytes.
var ErrResponseTooLarge = errors.New("pveapi: response exceeds size limit")

// TokenSupplier returns the value of the Authorization header for each
// request, e.g. "PVEAPIToken=nos@pve!inventory=<value>". It must not store
// or log the token anywhere else.
type TokenSupplier func(ctx context.Context) (string, error)

// Client is a read-only Proxmox VE API client. It is safe for concurrent
// use.
type Client struct {
	base    string
	http    *http.Client
	token   TokenSupplier
	timeout time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-call timeout (default 30 s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// New creates a Client for the PVE API at base (e.g.
// "https://pve.example:8006"). hc must already carry the TLS trust and
// pinning policy; token supplies the Authorization header value for each
// request.
func New(base string, hc *http.Client, token TokenSupplier, opts ...Option) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("pveapi: base URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("pveapi: base URL %q must be a plain http(s) host", base)
	}
	if hc == nil {
		return nil, errors.New("pveapi: nil *http.Client")
	}
	if token == nil {
		return nil, errors.New("pveapi: nil token supplier")
	}
	c := &Client{
		base:    u.Scheme + "://" + u.Host,
		http:    hc,
		token:   token,
		timeout: defaultCallTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// StatusError is a non-2xx PVE API response. Message is sanitized and
// bounded; it is untrusted text and must be rendered as text only.
type StatusError struct {
	Path    string
	Code    int
	Message string
}

// Error implements the error interface.
func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("pveapi: GET %s: HTTP %d", e.Path, e.Code)
	}
	return fmt.Sprintf("pveapi: GET %s: HTTP %d: %s", e.Path, e.Code, e.Message)
}

// do performs a GET against the PVE API and returns the decoded "data"
// field of the response envelope. It is the only place in the package that
// talks to the network; it never logs the request or the response.
func (c *Client) do(ctx context.Context, path string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	tok, err := c.token(ctx)
	if err != nil {
		return nil, fmt.Errorf("pveapi: token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+apiRoot+path, nil)
	if err != nil {
		return nil, fmt.Errorf("pveapi: request %s: %w", path, err)
	}
	req.Header.Set("Authorization", tok)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pveapi: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pveapi: GET %s: %w", path, err)
	}
	if len(body) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: %s", ErrResponseTooLarge, path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiStatusError(path, resp.StatusCode, body)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("pveapi: decode %s: %w", path, err)
	}
	if len(env.Data) == 0 {
		return nil, fmt.Errorf("pveapi: GET %s: empty data", path)
	}
	return env.Data, nil
}

// apiStatusError builds a StatusError from a non-2xx PVE response body.
// PVE answers with either {"error": "..."} or
// {"errors": {"<endpoint>": "..."}}.
func apiStatusError(path string, code int, body []byte) error {
	var env struct {
		Error  string            `json:"error"`
		Errors map[string]string `json:"errors"`
	}
	msg := ""
	if err := json.Unmarshal(body, &env); err == nil {
		if env.Error != "" {
			msg = env.Error
		} else {
			for _, v := range env.Errors {
				msg = v
				break
			}
		}
	}
	return &StatusError{Path: path, Code: code, Message: sanitizeText(msg, MaxErrorMessageBytes)}
}

// sanitizeText makes untrusted response text safe to carry in errors and
// results: it fixes invalid UTF-8, strips control characters and
// truncates to at most max bytes.
func sanitizeText(s string, max int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7F {
			continue
		}
		b.WriteRune(r)
	}
	s = b.String()
	const ellipsis = "…"
	if len(s) > max {
		cut := max - len(ellipsis)
		if cut < 0 {
			cut = 0
		}
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + ellipsis
	}
	return s
}

// sanitizeStrings sanitizes each element of a bounded string list; at most
// n elements are kept, each at most max bytes.
func sanitizeStrings(in []string, n, max int) []string {
	if len(in) > n {
		in = in[:n]
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = sanitizeText(s, max)
	}
	return out
}
