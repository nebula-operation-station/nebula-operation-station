// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed client for the Proxmox VE API
// (ADR 0006, phase 1 read path). It enumerates cluster nodes and QEMU/LXC
// guests, reads guest configurations with secret fields removed, and
// queries the QEMU guest agent (interfaces, OS info, filesystems).
//
// Client performs GET requests only and never issues mutation endpoints.
// The only mutations live on the separate Writer type (ADR 0008 PV-02):
// a closed allowlist of typed provisioning calls (full clone, allowlisted
// config set, disk resize, start, checksummed download-url, template
// conversion) plus task status. TLS trust and certificate pinning are the
// caller's responsibility: both types take a ready *http.Client and a base
// URL. Neither logs request headers or response bodies.
//
// Reader-specific response types are defined locally; shared capability
// and backup observation types use internal/pvecontract.
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

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
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
)

// apiRoot is the Proxmox VE JSON API root appended to the base URL.
const apiRoot = "/api2/json"

// ErrAgentUnavailable reports that the guest agent is not running or not
// reachable. Callers should display it as "unavailable", not as a failure.
var ErrAgentUnavailable = errors.New("pveapi: guest agent unavailable")

// ErrResponseTooLarge reports a response larger than the client's limit
// (MaxBody, else DefaultMaxBody; the backup default for ReadBackups).
var ErrResponseTooLarge = errors.New("pveapi: response exceeds size limit")

// TokenSupplier returns the value of the Authorization header for each
// request, e.g. "PVEAPIToken=nos@pve!inventory=<value>". It must not store
// or log the token anywhere else.
type TokenSupplier func(ctx context.Context) (string, error)

// Client is a read-only Proxmox VE API client. It is safe for concurrent
// use once constructed; do not change its fields while calls are running.
//
// Every read method (inventory, config, guest agent, storage, snapshots,
// cluster, HA, tasks, hardware, backups) uses the same four connection
// fields below. NewClient, New and NewBackupClient fill them; a literal
// &Client{HTTP: ..., BaseURL: ..., Token: ...} is equivalent. A Client
// missing HTTP, BaseURL or Token fails every call with ErrIncompleteClient.
//
// Guest config reads (GetQemuConfig, GetLxcConfig) use PVE's default
// GET .../config view, which has pending changes applied; they do not send
// current=1. The default view is what PVE shows as the guest's
// configuration and what takes effect on the next guest start. Neither view
// alone lists both a pending removal and a pending addition, so callers
// that gate risky actions on config facts must not assume either view is
// complete; PVE's own migrate and backup checks evaluate both sections.
type Client struct {
	// HTTP is the transport. Required. It must carry the remote's TLS trust
	// and pinning policy. Its redirect policy is ignored: the client never
	// follows redirects, so credentials never reach another destination.
	HTTP *http.Client
	// BaseURL is the PVE API root including "/api2/json", e.g.
	// "https://pve.example:8006/api2/json". Required.
	BaseURL string
	// Token supplies the value of the Authorization header for each call
	// (e.g. "PVEAPIToken=user@realm!token=<value>"). Required. Its error
	// value must not contain the token.
	Token TokenSupplier
	// Timeout bounds each API call. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxBody caps the response size in bytes. Zero means DefaultMaxBody.
	// Reads with a smaller fixed per-endpoint limit keep that limit.
	MaxBody int64
}

// ErrIncompleteClient reports a Client without HTTP, BaseURL or Token.
var ErrIncompleteClient = errors.New("pveapi: incomplete client")

// ready reports whether c has every connection field set.
func (c *Client) ready() error {
	if c == nil || c.HTTP == nil || c.BaseURL == "" || c.Token == nil {
		return ErrIncompleteClient
	}
	return nil
}

// callTimeout returns the per-call timeout.
func (c *Client) callTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// maxBody returns the response size limit of the general read methods.
func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return DefaultMaxBody
}

// backupMaxBody returns the response size limit of ReadBackups, whose
// listings are larger: MaxBody when set, else the backup default. The
// limit does not depend on which constructor built the client.
func (c *Client) backupMaxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return defaultMaxResponseBytes
}

// endpoint returns the absolute URL for an API path below BaseURL. path
// may carry an already encoded query.
func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.BaseURL, "/") + path
}

// send performs req with a copy of c.HTTP that never follows redirects.
// The copy leaves the caller's client and its redirect policy untouched.
func (c *Client) send(req *http.Request) (*http.Response, error) {
	hc := *c.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return hc.Do(req)
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-call timeout (default 30 s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.Timeout = d
		}
	}
}

// New creates a Client for the PVE API at base (e.g.
// "https://pve.example:8006"), without the "/api2/json" root, which New
// appends. It is NewClient for a plain host URL. hc must already carry the
// TLS trust and pinning policy; token supplies the Authorization header
// value for each request.
func New(base string, hc *http.Client, token TokenSupplier, opts ...Option) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("pveapi: base URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("pveapi: base URL %q must be a plain http(s) host", base)
	}
	c, err := NewClient(hc, u.Scheme+"://"+u.Host+apiRoot, token)
	if err != nil {
		return nil, err
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
	if err := c.ready(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.callTimeout())
	defer cancel()

	tok, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("pveapi: token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path), nil)
	if err != nil {
		return nil, fmt.Errorf("pveapi: request %s: %w", path, err)
	}
	req.Header.Set("Authorization", tok)

	resp, err := c.send(req)
	if err != nil {
		return nil, fmt.Errorf("pveapi: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	limit := c.maxBody()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("pveapi: GET %s: %w", path, err)
	}
	if int64(len(body)) > limit {
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

// Identity and record limits.
const (
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
	// ReasonOversize covers responses larger than the client's body limit.
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

// NewClient returns a read-only client for baseURL, the PVE API root
// including "/api2/json" (e.g. "https://pve.example:8006/api2/json").
// httpClient must be non-nil and should configure a ~10 s dial timeout for
// the connect phase (ADR 0006). token must be non-nil. baseURL must be an
// absolute http or https URL. The returned client serves every read method
// with the default timeout and size limit.
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
	// Redirects are refused per request (Client.send), so the caller's
	// client is kept as is and credentials never reach a redirect target.
	return &Client{HTTP: httpClient, BaseURL: strings.TrimRight(u.String(), "/"), Token: token, Timeout: DefaultRequestTimeout}, nil
}

// get performs a GET request against the remote and decodes the JSON body
// into out. Failures are reported as *UnavailableError with a fixed reason;
// caller context cancellation is returned unchanged.
func (c *Client) get(ctx context.Context, path string, out any) error {
	if err := c.ready(); err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.callTimeout())
	defer cancel()

	if err := ctx.Err(); err != nil {
		return err
	}

	u, err := url.JoinPath(strings.TrimRight(c.BaseURL, "/"), path)
	if err != nil {
		return fmt.Errorf("pveapi: build url: %w", err)
	}

	tok, err := c.Token(ctx)
	if err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonNoToken}
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonTransport}
	}
	req.Header.Set("Authorization", tok)

	resp, err := c.send(req)
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

	limit := c.maxBody()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return &UnavailableError{Endpoint: path, Reason: ReasonTransport}
	}
	if int64(len(body)) > limit {
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

// validNodeName validates a PVE node name used in a request path: one
// pvecontract node label. The case is kept, because PVE API paths are
// case-sensitive.
func validNodeName(node string) error {
	if !pvecontract.ValidNodeLabel(node) {
		return fmt.Errorf("pveapi: invalid node name (length %d)", len(node))
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
