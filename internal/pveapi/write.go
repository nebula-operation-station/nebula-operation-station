// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Writer is the typed Proxmox VE mutation client for guest provisioning
// (ADR 0008, PV-02). It is a separate type from the read-only Client so that
// read paths can never issue a mutation, and so that callers construct it
// only with the PVE action token.
//
// Writer exposes a closed allowlist of operations: full clone, an
// allowlisted config set, disk resize, start, storage download-url with a
// mandatory SHA-256 checksum, template conversion and task status. Every
// method takes typed, validated arguments; there is no URL, raw API path or
// free-form parameter input. Every mutation returns the validated UPID of
// the PVE task it started.
//
// Errors never contain request values (in particular no cloud-init
// password), response bodies, headers or the token. Writer never logs.
// It is safe for concurrent use.
type Writer struct {
	base    string
	http    *http.Client
	token   TokenSupplier
	timeout time.Duration
}

// Write limits, named next to the code that enforces them.
const (
	// MaxWriteResponseBytes bounds one write or task-status response. A
	// UPID envelope is far below this; anything larger is hostile.
	MaxWriteResponseBytes = 64 << 10
	// maxErrorParams bounds the parameter names kept from a PVE 400 error.
	maxErrorParams = 32
)

// ErrInvalidArgument reports a write argument that failed validation. The
// wrapping error names the field but never its value.
var ErrInvalidArgument = errors.New("pveapi: invalid argument")

// ErrWriteFailed is matched (errors.Is) by every *WriteError.
var ErrWriteFailed = errors.New("pveapi: write failed")

// WriteError is a fixed-reason failure of a write or task-status call. It
// never contains request values, response bodies, headers or the token.
type WriteError struct {
	// Op is the operation name, e.g. "clone" or "start".
	Op string
	// Reason is one of the Reason* constants.
	Reason string
	// Status is the HTTP status for ReasonHTTPError, 0 otherwise.
	Status int
	// Params lists request parameter names PVE rejected (HTTP 400), sorted.
	// Only names that were actually sent are kept.
	Params []string
	// cause is a context error, kept so errors.Is(err, context.Canceled)
	// works. It carries no response content.
	cause error
}

// Error implements error.
func (e *WriteError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "pveapi: %s failed: %s", e.Op, e.Reason)
	if e.Status != 0 {
		fmt.Fprintf(&b, " (http %d)", e.Status)
	}
	if len(e.Params) > 0 {
		fmt.Fprintf(&b, " [params: %s]", strings.Join(e.Params, ","))
	}
	return b.String()
}

// Is makes errors.Is(err, ErrWriteFailed) true for every WriteError.
func (e *WriteError) Is(target error) bool { return target == ErrWriteFailed }

// Unwrap returns the context error that ended the call, if any.
func (e *WriteError) Unwrap() error { return e.cause }

// OutcomeUnknown reports whether the request may have reached PVE and
// started a task although no valid UPID was returned (transport failure,
// timeout, or a 200 response that failed validation). Callers must then
// reconcile through the task list and never redispatch blindly (ADR 0008).
// An HTTP error status or a missing token means PVE did not start a task.
func (e *WriteError) OutcomeUnknown() bool {
	return e.Reason != ReasonHTTPError && e.Reason != ReasonNoToken
}

// NewWriter creates a Writer for the PVE API at base (e.g.
// "https://pve.example:8006", scheme and host only). hc must already carry
// the TLS trust and pinning policy; it is copied and never follows
// redirects. token supplies the Authorization header (the PVE action
// token). timeout bounds each call; zero means DefaultRequestTimeout.
func NewWriter(base string, hc *http.Client, token TokenSupplier, timeout time.Duration) (*Writer, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("pveapi: writer base URL does not parse")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("pveapi: writer base URL must be a plain http(s) scheme and host")
	}
	if hc == nil {
		return nil, errors.New("pveapi: nil *http.Client")
	}
	if token == nil {
		return nil, errors.New("pveapi: nil token supplier")
	}
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	client := *hc
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Writer{base: u.Scheme + "://" + u.Host, http: &client, token: token, timeout: timeout}, nil
}

// writeRequest is one allowlisted PVE call.
type writeRequest struct {
	op     string
	method string
	// path is built only from validated, escaped components.
	path string
	form url.Values
}

// call performs one request and returns the "data" member of the response
// envelope. It enforces the response size limit and UTF-8, and maps every
// failure to a fixed-reason *WriteError.
func (w *Writer) call(ctx context.Context, r writeRequest) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	tok, err := w.token(reqCtx)
	if err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonNoToken}
	}
	var body io.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	}
	req, err := http.NewRequestWithContext(reqCtx, r.method, w.base+apiRoot+r.path, body)
	if err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonTransport}
	}
	req.Header.Set("Authorization", tok)
	req.Header.Set("Accept", "application/json")
	if r.form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := w.http.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, &WriteError{Op: r.op, Reason: ReasonTransport, cause: cerr}
		}
		if errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, &WriteError{Op: r.op, Reason: ReasonTimeout, cause: context.DeadlineExceeded}
		}
		return nil, &WriteError{Op: r.op, Reason: ReasonTransport}
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxWriteResponseBytes+1))
	if resp.StatusCode != http.StatusOK {
		e := &WriteError{Op: r.op, Reason: ReasonHTTPError, Status: resp.StatusCode}
		if resp.StatusCode == http.StatusBadRequest && readErr == nil && len(raw) <= MaxWriteResponseBytes {
			e.Params = rejectedParams(raw, r.form)
		}
		return nil, e
	}
	if readErr != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonTransport}
	}
	if len(raw) > MaxWriteResponseBytes {
		return nil, &WriteError{Op: r.op, Reason: ReasonOversize}
	}
	if !utf8.Valid(raw) {
		return nil, &WriteError{Op: r.op, Reason: ReasonInvalidUTF8}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonInvalidJSON}
	}
	if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return nil, &WriteError{Op: r.op, Reason: ReasonSchema}
	}
	return env.Data, nil
}

// rejectedParams extracts the parameter names from a PVE 400 body
// ({"errors":{"<param>":"<message>"}}). Messages are dropped because PVE may
// echo submitted values; names are kept only if they were sent.
func rejectedParams(raw []byte, sent url.Values) []string {
	if !utf8.Valid(raw) {
		return nil
	}
	var env struct {
		Errors map[string]json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	var out []string
	for k := range env.Errors {
		if _, ok := sent[k]; ok && len(out) < maxErrorParams {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// dispatch performs a mutation and validates the returned UPID: it must
// parse, name the requested node, have the expected task type and, when
// wantID is set, the expected target id.
func (w *Writer) dispatch(ctx context.Context, r writeRequest, node, wantType, wantID string) (string, error) {
	data, err := w.call(ctx, r)
	if err != nil {
		return "", err
	}
	var upid string
	if err := json.Unmarshal(data, &upid); err != nil {
		return "", &WriteError{Op: r.op, Reason: ReasonSchema}
	}
	task, err := parseUPID(upid)
	if err != nil || task.Node != node || task.Type != wantType || (wantID != "" && task.ID != wantID) {
		return "", &WriteError{Op: r.op, Reason: ReasonSchema}
	}
	return upid, nil
}

// invalid builds an ErrInvalidArgument error naming the field only.
func invalid(op, field string) error {
	return fmt.Errorf("pveapi: %s: %w: %s", op, ErrInvalidArgument, field)
}
