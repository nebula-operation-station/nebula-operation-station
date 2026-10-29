// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed, read-only client for the Proxmox VE HTTP API
// (ADR 0006, tickets P1-08/P1-09).
//
// The client performs GET requests only. Every response is untrusted input:
// it is size-limited, UTF-8 validated, JSON decoded and schema-checked,
// unknown fields are dropped, and no header or body content ever appears in
// returned errors. A dataset that cannot be read at all is reported as
// ErrUnavailable with a fixed reason; an empty list is an empty result,
// never an error.
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

// Document limits (ADR 0006, "Phase 1 read path and stored observations"):
// 1 MiB decoded per response, 1,000 objects per page, 4 KiB per text field.
const (
	// MaxResponseBytes bounds one decoded PVE API response.
	MaxResponseBytes = 1 << 20
	// MaxObjectsPerPage bounds record lists in one response page.
	MaxObjectsPerPage = 1000
	// MaxTextFieldBytes bounds any decoded string field.
	MaxTextFieldBytes = 4 << 10
)

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

// TokenSupplier returns the value for the Authorization header of one
// request, e.g. "PVEAPIToken=nos@pam!<token>". The returned value is a
// credential: it must never be logged or returned in errors.
type TokenSupplier func(ctx context.Context) (string, error)

// Client is a typed, read-only Proxmox VE API client. It is safe for
// concurrent use.
type Client struct {
	http *http.Client
	// baseURL is the remote's API base, e.g. "https://pve.example:8006".
	baseURL string
	// token supplies the Authorization header value per request.
	token TokenSupplier
	// RequestTimeout bounds one request; zero uses DefaultRequestTimeout.
	RequestTimeout time.Duration
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
	return &Client{http: &client, baseURL: strings.TrimRight(u.String(), "/"), token: token, RequestTimeout: timeout}, nil
}

// get performs a GET request against the remote and decodes the JSON body
// into out. Failures are reported as *UnavailableError with a fixed reason;
// caller context cancellation is returned unchanged.
func (c *Client) get(ctx context.Context, path string, out any) error {
	timeout := c.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return err
	}

	u, err := url.JoinPath(c.baseURL, path)
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
