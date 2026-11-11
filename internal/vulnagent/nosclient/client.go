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
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// API paths (internal/web/api VulnPrefix).
const (
	vulnPrefix    = "/api/v1/vuln/"
	inventoryPath = vulnPrefix + "inventory"
	runsPath      = vulnPrefix + "runs"
)

// Client limits and timing.
const (
	// MaxCAFileBytes bounds the pinned CA file.
	MaxCAFileBytes = 1 << 20
	// DefaultMaxAttempts is how often one request is tried in total.
	DefaultMaxAttempts = 5
	// maxBackoff caps the wait between retries without Retry-After.
	maxBackoff = 30 * time.Second
	// firstBackoff is the first wait between retries without Retry-After.
	firstBackoff = time.Second
	// maxRetryAfter is the longest Retry-After the client waits for; the
	// longest server window is the export window (one hour).
	maxRetryAfter = ExportWindow + time.Minute
	// requestTimeout bounds one request other than complete.
	requestTimeout = 60 * time.Second
	// completeTimeout bounds one complete request; the server gives a
	// complete five minutes.
	completeTimeout = 6 * time.Minute
	// maxResultBytes bounds a run start, batch or complete response.
	maxResultBytes = 256 << 10
	// maxErrorMessage bounds the server message kept in a StatusError.
	maxErrorMessage = 256
)

// Sentinel errors callers branch on. A StatusError wraps one of them.
var (
	// ErrUnauthorized: the server refused the token (401).
	ErrUnauthorized = errors.New("token refused")
	// ErrForbidden: the token lacks the scope or the source address (403).
	ErrForbidden = errors.New("forbidden")
	// ErrRateLimited: the server's rate limit or the concurrent run limit
	// was reached (429).
	ErrRateLimited = errors.New("rate limited")
	// ErrSnapshotGone: the inventory snapshot is no longer available;
	// export again from the start.
	ErrSnapshotGone = errors.New("inventory snapshot no longer available")
	// ErrConflict: the server refused a state change (409), for example a
	// batch repeated with a different body or a run it no longer holds.
	ErrConflict = errors.New("conflict")
	// ErrTooLarge: a body exceeds a limit (413, or caught before sending).
	ErrTooLarge = errors.New("exceeds a limit")
	// ErrRejected: the server rejected the request as malformed (400, 422).
	ErrRejected = errors.New("rejected")
	// ErrUnavailable: the server is unavailable (5xx) after all attempts.
	ErrUnavailable = errors.New("server unavailable")
	// ErrProtocol: the server's answer breaks the API contract.
	ErrProtocol = errors.New("protocol violation")
	// ErrCertificate: the server certificate failed verification against
	// the pinned CA or the system pool. It is not retried.
	ErrCertificate = errors.New("server certificate not trusted")
)

// StatusError is a non-success HTTP answer. Message is the server's error
// text, cut, reduced to printable characters and with the token removed.
type StatusError struct {
	Op         string
	Status     int
	Message    string
	RetryAfter time.Duration
	kind       error
}

// Error implements error.
func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.Op, e.Status, e.Message)
}

// Unwrap returns the sentinel for the status.
func (e *StatusError) Unwrap() error { return e.kind }

func statusKind(code int) error {
	switch {
	case code == http.StatusUnauthorized:
		return ErrUnauthorized
	case code == http.StatusForbidden:
		return ErrForbidden
	case code == http.StatusTooManyRequests:
		return ErrRateLimited
	case code == http.StatusGone:
		return ErrSnapshotGone
	case code == http.StatusConflict:
		return ErrConflict
	case code == http.StatusRequestEntityTooLarge:
		return ErrTooLarge
	case code == http.StatusBadRequest || code == http.StatusUnprocessableEntity:
		return ErrRejected
	case code >= 500:
		return ErrUnavailable
	default:
		return ErrProtocol
	}
}

// Config configures a Client.
type Config struct {
	// BaseURL is the NOS server, https only, without path, query or
	// credentials, for example "https://nos.lab.example:8443".
	BaseURL string
	// TokenFile holds the bearer token (mode 0600 or 0400).
	TokenFile string
	// CAFile, when set, is a PEM file with the only CA certificates the
	// server certificate is verified against (pinned CA). When empty, the
	// system pool is used. Verification cannot be turned off.
	CAFile string
	// MaxAttempts is how often one request is tried in total; zero means
	// DefaultMaxAttempts.
	MaxAttempts int
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// Sleep waits for d or until ctx ends. Defaults to a timer.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client talks to the NOS vulnerability API. It is safe for concurrent use.
type Client struct {
	base        *url.URL
	token       Token
	http        *http.Client
	maxAttempts int
	now         func() time.Time
	sleep       func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	export rateWindow
	write  rateWindow
}

// New returns a Client. It loads the token and the pinned CA now, so a
// misconfiguration fails at start.
func New(cfg Config) (*Client, error) {
	base, err := parseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	tok, err := LoadToken(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("nosclient: %w", err)
	}
	tlsCfg, err := tlsConfig(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("nosclient: %w", err)
	}
	c := &Client{
		base:  base,
		token: tok,
		http: &http.Client{
			Transport: &http.Transport{
				// No proxy: the token goes to the configured server only.
				Proxy:                 nil,
				TLSClientConfig:       tlsCfg,
				ForceAttemptHTTP2:     true,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: completeTimeout,
				MaxIdleConns:          4,
				IdleConnTimeout:       90 * time.Second,
			},
			// Never follow a redirect: the token must not go elsewhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		maxAttempts: cfg.MaxAttempts,
		now:         cfg.Now,
		sleep:       cfg.Sleep,
		export:      rateWindow{span: ExportWindow, max: MaxExportRequests},
		write:       rateWindow{span: WriteWindow, max: MaxWriteRequests},
	}
	if c.maxAttempts <= 0 {
		c.maxAttempts = DefaultMaxAttempts
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	return c, nil
}

func parseBaseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("nosclient: base URL does not parse")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("nosclient: base URL must be https://host[:port] without path, query or credentials")
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
}

// tlsConfig verifies the server against the pinned CA file or, without
// one, the system pool. InsecureSkipVerify is never set.
func tlsConfig(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile == "" {
		return cfg, nil
	}
	f, err := os.Open(caFile)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	defer f.Close()
	pem, err := io.ReadAll(io.LimitReader(f, MaxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("load CA %s: %w", caFile, err)
	}
	if len(pem) > MaxCAFileBytes {
		return nil, fmt.Errorf("load CA %s: file larger than %d bytes", caFile, MaxCAFileBytes)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("load CA %s: no PEM certificate found", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// rateWindow mirrors the server's sliding window so that the client waits
// instead of running into 429.
type rateWindow struct {
	span  time.Duration
	max   int
	times []time.Time
}

// reserve records a request at now if the window has room and otherwise
// returns how long to wait.
func (rw *rateWindow) reserve(now time.Time) time.Duration {
	cut := now.Add(-rw.span)
	i := 0
	for i < len(rw.times) && !rw.times[i].After(cut) {
		i++
	}
	rw.times = rw.times[i:]
	if len(rw.times) >= rw.max {
		return rw.times[0].Sub(cut) + time.Millisecond
	}
	rw.times = append(rw.times, now)
	return 0
}

// retryPolicy says which failures a request may be retried after.
type retryPolicy struct {
	// transport: retry after a transport error. Only for requests the
	// server treats as idempotent.
	transport bool
	// status: retry after these statuses.
	status func(code int) bool
}

// retryIdempotent retries transport errors, 429 and 5xx: for the export
// (a read), batches (idempotent by run ID and batch_seq with the same
// body) and complete (idempotent by run ID).
var retryIdempotent = retryPolicy{transport: true, status: func(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code != http.StatusNotImplemented)
}}

// retryStart retries a run start only after an answer that says no run was
// created (429 and 503). A transport error is not retried: the run may
// exist, and a second start would take the second concurrent run slot.
var retryStart = retryPolicy{status: func(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable
}}

type request struct {
	op      string
	method  string
	path    string
	query   url.Values
	body    []byte
	limit   int64
	window  *rateWindow
	retry   retryPolicy
	timeout time.Duration
	// okStatus is the expected success status.
	okStatus int
	// keepStatus are non-success statuses whose JSON body is returned to
	// the caller (with a StatusError) instead of being reduced to the
	// message.
	keepStatus int
}

// do sends one request with retries and returns the response body of a
// success. On a keepStatus answer it returns the body and the StatusError.
func (c *Client) do(ctx context.Context, rq request) ([]byte, error) {
	backoff := firstBackoff
	var last error
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		if err := c.waitWindow(ctx, rq.window); err != nil {
			return nil, fmt.Errorf("%s: %w", rq.op, err)
		}
		body, wait, err := c.once(ctx, rq)
		if err == nil {
			return body, nil
		}
		var se *StatusError
		retry := false
		switch {
		case errors.As(err, &se):
			retry = rq.retry.status != nil && rq.retry.status(se.Status)
			if se.Status == rq.keepStatus && rq.keepStatus != 0 {
				return body, err
			}
		case errors.Is(err, ErrProtocol), errors.Is(err, ErrCertificate):
			retry = false
		default:
			retry = rq.retry.transport
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", rq.op, ctx.Err())
		}
		last = err
		if !retry || attempt == c.maxAttempts {
			break
		}
		if wait == 0 {
			wait = backoff
			backoff = min(backoff*2, maxBackoff)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, fmt.Errorf("%s: %w (after %w)", rq.op, err, last)
		}
	}
	return nil, last
}

// waitWindow waits until the client-side window has room.
func (c *Client) waitWindow(ctx context.Context, w *rateWindow) error {
	if w == nil {
		return nil
	}
	for {
		c.mu.Lock()
		d := w.reserve(c.now())
		c.mu.Unlock()
		if d == 0 {
			return nil
		}
		if err := c.sleep(ctx, d); err != nil {
			return fmt.Errorf("wait for rate window: %w", err)
		}
	}
}

// once sends one attempt. It returns the body of a success (or of a
// keepStatus answer), the server's Retry-After and the error.
func (c *Client) once(ctx context.Context, rq request) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, rq.timeout)
	defer cancel()
	u := *c.base
	u.Path = rq.path
	u.RawQuery = rq.query.Encode()
	var rd io.Reader
	if rq.body != nil {
		rd = bytes.NewReader(rq.body)
	}
	req, err := http.NewRequestWithContext(ctx, rq.method, u.String(), rd)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: build request: %w", rq.op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.value)
	req.Header.Set("Accept", "application/json")
	if rq.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// url.Error quotes the URL, which never carries the token; redact
		// anyway in case a lower layer quotes a header.
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			return nil, 0, fmt.Errorf("%s: %w: %s", rq.op, ErrCertificate, c.token.redact(err.Error()))
		}
		return nil, 0, fmt.Errorf("%s: %s", rq.op, c.token.redact(err.Error()))
	}
	defer resp.Body.Close()
	limit := rq.limit
	if resp.StatusCode != rq.okStatus && resp.StatusCode != rq.keepStatus {
		limit = maxErrorMessage * 16
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: read response: %s", rq.op, c.token.redact(err.Error()))
	}
	wait := retryAfter(resp.Header.Get("Retry-After"))
	if resp.StatusCode == rq.okStatus {
		if int64(len(body)) > limit {
			return nil, 0, fmt.Errorf("%s: response larger than %d bytes: %w", rq.op, limit, ErrProtocol)
		}
		if !jsonResponse(resp) {
			return nil, 0, fmt.Errorf("%s: response is not JSON: %w", rq.op, ErrProtocol)
		}
		return body, 0, nil
	}
	se := &StatusError{Op: rq.op, Status: resp.StatusCode, Message: c.errorMessage(body), RetryAfter: wait, kind: statusKind(resp.StatusCode)}
	if resp.StatusCode == rq.keepStatus && int64(len(body)) <= limit && jsonResponse(resp) {
		return body, wait, se
	}
	return nil, wait, se
}

func jsonResponse(resp *http.Response) bool {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// retryAfter parses a Retry-After in seconds; anything else or a value
// above maxRetryAfter is ignored (the caller backs off instead).
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return 0
	}
	d := time.Duration(n) * time.Second
	if d > maxRetryAfter {
		return maxRetryAfter
	}
	return d
}

// errorMessage extracts the server's {"error": "..."} text, cut to
// maxErrorMessage bytes, printable only and with the token removed.
func (c *Client) errorMessage(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		return "(no message)"
	}
	return c.token.redact(cleanText(e.Error, maxErrorMessage))
}

// cleanText keeps valid, printable runes of s up to max bytes.
func cleanText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decodeJSON decodes body into v, rejecting unknown fields when strict.
func decodeJSON(op string, body []byte, v any, strict bool) error {
	if !utf8.Valid(body) {
		return fmt.Errorf("%s: response is not UTF-8: %w", op, ErrProtocol)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: decode response: %w", op, ErrProtocol)
	}
	if dec.More() {
		return fmt.Errorf("%s: trailing data in response: %w", op, ErrProtocol)
	}
	return nil
}
