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
	"bytes"
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
	// HTTP is the transport. Required.
	HTTP *http.Client
	// BaseURL is the PVE API root, e.g.
	// "https://pve.example:8006/api2/json". Required.
	BaseURL string
	// Token supplies the value of the Authorization header for each call
	// (e.g. "PVEAPIToken=user!realm!token"). Required. Its error value must
	// not contain the token.
	Token func(ctx context.Context) (string, error)
	// Timeout bounds each API call. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxBody caps the decoded response size in bytes. Zero means
	// DefaultMaxBody.
	MaxBody int64
	base    string
	http    *http.Client
	token   TokenSupplier
	timeout time.Duration
	// RequestTimeout bounds storage and snapshot requests; zero uses the client timeout.
	RequestTimeout time.Duration
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
// field of the response envelope for inventory and guest-agent calls.
// It never logs the request or the response.
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
// PVE supplies "message" and optional field-specific "errors"; older
// envelopes with "error" are also accepted.
func apiStatusError(path string, code int, body []byte) error {
	var env struct {
		Message string            `json:"message"`
		Error   string            `json:"error"`
		Errors  map[string]string `json:"errors"`
	}
	msg := ""
	if err := json.Unmarshal(body, &env); err == nil {
		if env.Message != "" {
			msg = env.Message
		} else if env.Error != "" {
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

// Identity and record limits.
const (
	// MaxNodeNameBytes bounds a PVE node name.
	MaxNodeNameBytes = 253
	// MaxRefBytes bounds short machine references (storage id).
	MaxRefBytes = 64
	// MaxSnapshotNameBytes bounds a guest snapshot name.
	MaxSnapshotNameBytes = 255
	// MaxStoragesPerRemote bounds storages per remote.
	MaxStoragesPerRemote = 64
	// MaxSnapshotsPerGuest bounds snapshots per guest.
	MaxSnapshotsPerGuest = 256
	// MaxContentTypes bounds content types per storage.
	MaxContentTypes = 16
	// MaxStorageFormatBytes bounds a storage volume format name.
	MaxStorageFormatBytes = 32
	// MaxSnapTimeUnix bounds a snapshot time in Unix seconds (year ~5138).
	MaxSnapTimeUnix = 1e11
)

// PVE VMID range: 100 to 9,999,999,999 (exceeds uint32).
const (
	// MinVMID is the lowest valid PVE VMID.
	MinVMID = 100
	// MaxVMID is the highest valid PVE VMID.
	MaxVMID = 9999999999
)

// DefaultRequestTimeout bounds a single API request (ADR 0006: 10 s connect
// / 30 s request). The connect phase is configured on the injected
// http.Client.
const DefaultRequestTimeout = 30 * time.Second

// Unavailability reasons. They form a closed set so errors never carry
// response body or header content.
const (
	// ReasonTransport covers network-level failures.
	ReasonTransport = "transport"
	// ReasonTimeout covers per-call request timeouts.
	ReasonTimeout = "timeout"
	// ReasonHTTPError covers non-200 HTTP responses; see UnavailableError.Status.
	ReasonHTTPError = "http_error"
	// ReasonNoToken covers token supplier failures.
	ReasonNoToken = "no_token"
	// ReasonOversize covers responses larger than MaxResponseBytes.
	ReasonOversize = "response_oversize"
	// ReasonInvalidUTF8 covers non-UTF-8 response bodies.
	ReasonInvalidUTF8 = "invalid_utf8"
	// ReasonInvalidJSON covers undecodable JSON.
	ReasonInvalidJSON = "invalid_json"
	// ReasonSchema covers decoded values that fail validation.
	ReasonSchema = "schema"
)

// ErrUnavailable indicates that a dataset could not be read at all. Check
// the concrete *UnavailableError for the reason and HTTP status.
var ErrUnavailable = errors.New("pveapi: dataset unavailable")

// UnavailableError is a fixed-reason unavailability report. It never
// contains response body, header or token content.
type UnavailableError struct {
	// Endpoint is the API path that was read, e.g. "/nodes/n1/storage".
	Endpoint string
	// Reason is one of the Reason* constants.
	Reason string
	// Status is the HTTP status for ReasonHTTPError, 0 otherwise.
	Status int
}

// Error implements error.
func (e *UnavailableError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("pveapi: %s unavailable: %s (http %d)", e.Endpoint, e.Reason, e.Status)
	}
	return fmt.Sprintf("pveapi: %s unavailable: %s", e.Endpoint, e.Reason)
}

// Is makes errors.Is(err, ErrUnavailable) true for every UnavailableError.
func (e *UnavailableError) Is(target error) bool {
	return target == ErrUnavailable
}

// NewClient returns a read-only client for baseURL. httpClient must be
// non-nil and should configure a ~10 s dial timeout for the connect phase
// (ADR 0006). token must be non-nil. baseURL must be an absolute http or
// https URL.
func NewClient(httpClient *http.Client, baseURL string, token TokenSupplier) (*Client, error) {
	if httpClient == nil {
		return nil, errors.New("pveapi: httpClient is nil")
	}
	if token == nil {
		return nil, errors.New("pveapi: token supplier is nil")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("pveapi: parse base url: %w", err)
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("pveapi: base url %q must be an absolute http(s) URL", baseURL)
	}
	timeout := DefaultRequestTimeout
	// Keep the caller's transport and timeouts, but never forward credentials
	// to a redirect destination, including another port on the same host.
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{http: &client, base: strings.TrimRight(u.String(), "/"), timeout: timeout, token: token, RequestTimeout: timeout}, nil
}

// get performs a GET request against the remote and decodes the JSON body
// into out. Failures are reported as *UnavailableError with a fixed reason;
// caller context cancellation is returned unchanged.
func (c *Client) get(ctx context.Context, path string, out any) error {
	timeout := c.RequestTimeout
	if timeout <= 0 {
		timeout = c.timeout
		if timeout <= 0 {
			timeout = DefaultRequestTimeout
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return err
	}

	u, err := url.JoinPath(c.base, path)
	if err != nil {
		return fmt.Errorf("pveapi: build url: %w", err)
	}

	tok, err := c.token(ctx)
	if err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonNoToken}
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonTransport}
	}
	req.Header.Set("Authorization", tok)

	resp, err := c.http.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if reqCtx.Err() == context.DeadlineExceeded {
			return &UnavailableError{Endpoint: path, Reason: ReasonTimeout}
		}
		return &UnavailableError{Endpoint: path, Reason: ReasonTransport}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &UnavailableError{Endpoint: path, Reason: ReasonHTTPError, Status: resp.StatusCode}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonTransport}
	}
	if len(body) > MaxResponseBytes {
		return &UnavailableError{Endpoint: path, Reason: ReasonOversize}
	}
	if !utf8.Valid(body) {
		return &UnavailableError{Endpoint: path, Reason: ReasonInvalidUTF8}
	}
	// Unknown fields are dropped deliberately (ADR 0006); PVE 8 and 9
	// responses differ in extra fields, so decoding is not strict here.
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonInvalidJSON}
	}
	if len(envelope.Data) == 0 || bytes.Equal(envelope.Data, []byte("null")) {
		return schemaErr(path)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		if errors.Is(err, errRecordSchema) {
			return schemaErr(path)
		}
		return &UnavailableError{Endpoint: path, Reason: ReasonInvalidJSON}
	}
	return nil
}

var errRecordSchema = errors.New("pveapi: invalid record page")

// recordPage decodes at most MaxObjectsPerPage records, one at a time,
// retaining only the caller's record limit. Excluded pseudo-records still
// count toward the page limit, but not the result limit or completeness.
type recordPage[T any] struct {
	records  []T
	limit    int
	include  func(T) bool
	complete bool
}

// UnmarshalJSON implements bounded record-array decoding.
func (p *recordPage[T]) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('[') {
		return errRecordSchema
	}
	p.records = make([]T, 0, min(p.limit, MaxObjectsPerPage))
	p.complete = true
	for count := 0; dec.More(); count++ {
		if count >= MaxObjectsPerPage {
			return errRecordSchema
		}
		var record T
		if err := dec.Decode(&record); err != nil {
			return err
		}
		if p.include != nil && !p.include(record) {
			continue
		}
		if len(p.records) < p.limit {
			p.records = append(p.records, record)
		} else {
			p.complete = false
		}
	}
	_, err = dec.Token()
	return err
}

// schemaErr wraps a validation failure as a fixed-reason unavailability.
func schemaErr(path string) error {
	return &UnavailableError{Endpoint: path, Reason: ReasonSchema}
}

// validNodeName validates a PVE node name: 1..MaxNodeNameBytes bytes of
// [a-z0-9_-].
func validNodeName(node string) error {
	if node == "" || len(node) > MaxNodeNameBytes {
		return fmt.Errorf("pveapi: invalid node name (length %d)", len(node))
	}
	for i := 0; i < len(node); i++ {
		ch := node[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return fmt.Errorf("pveapi: invalid node name %q", node)
		}
	}
	return nil
}

// validStorageID validates a PVE storage id: 1..MaxRefBytes bytes of
// [a-zA-Z0-9_-].
func validStorageID(id string) error {
	if id == "" || len(id) > MaxRefBytes {
		return fmt.Errorf("pveapi: invalid storage id (length %d)", len(id))
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return fmt.Errorf("pveapi: invalid storage id %q", id)
		}
	}
	return nil
}

// validSnapshotName validates a PVE snapshot name: 1..MaxSnapshotNameBytes
// bytes of [a-zA-Z0-9._-].
func validSnapshotName(name string) error {
	if name == "" || len(name) > MaxSnapshotNameBytes {
		return fmt.Errorf("pveapi: invalid snapshot name (length %d)", len(name))
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
			ch == '_' || ch == '-' || ch == '.') {
			return fmt.Errorf("pveapi: invalid snapshot name %q", name)
		}
	}
	return nil
}

// validGuestKind validates the guest API family: "qemu" or "lxc".
func validGuestKind(kind string) error {
	if kind != "qemu" && kind != "lxc" {
		return fmt.Errorf("pveapi: invalid guest kind %q", kind)
	}
	return nil
}

// validVMID validates a PVE VMID in [MinVMID, MaxVMID].
func validVMID(vmid int64) error {
	if vmid < MinVMID || vmid > MaxVMID {
		return fmt.Errorf("pveapi: invalid vmid %d", vmid)
	}
	return nil
}
