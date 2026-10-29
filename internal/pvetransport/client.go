// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pvetransport provides the pinned HTTPS transport for Proxmox VE
// remotes (ADR 0006, "Remote identity and TLS trust").
//
// A remote is one PVE cluster (or standalone host) with an ordered list of
// admin-approved HTTPS endpoints. Trust is pinned, never ambient: every
// connection verifies the served certificate against either the pinned
// cluster CA (pve-root-ca) or a pinned leaf certificate fingerprint, plus
// validity and the endpoint's DNS/IP SAN. The system root store is never
// consulted.
//
// Failover follows the ADR: only connection failures and timeouts move the
// request to the next endpoint. A trust mismatch (ErrTrustMismatch) is
// terminal and stops all endpoints, as do redirects, which are refused
// outright (ErrRedirect). Environment proxies are ignored (Proxy: nil).
//
// Credentials are never transmitted before trust is verified. The
// Authorization header is computed before the attempt, but the request —
// header bytes included — is written to the endpoint only after the TLS
// handshake, which performs the pin verification, has succeeded. If the
// pin does not match, the handshake fails with ErrTrustMismatch and
// nothing, including credentials, is sent to the endpoint.
package pvetransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Sentinel errors returned by the transport.
var (
	// ErrNoEndpoints is returned by NewClient and NewRoundTripper when
	// the endpoint list is empty.
	ErrNoEndpoints = errors.New("pvetransport: no endpoints configured")

	// ErrRedirect is returned when the server responds with a redirect.
	// Redirects are always refused: they could move a request (and its
	// credentials) to an unapproved origin.
	ErrRedirect = errors.New("pvetransport: redirect refused")

	// ErrRequestTooLarge is returned when the request body exceeds
	// Options.MaxRequestBytes.
	ErrRequestTooLarge = errors.New("pvetransport: request body exceeds limit")

	// ErrResponseTooLarge is returned when the response body exceeds
	// Options.MaxResponseBytes.
	ErrResponseTooLarge = errors.New("pvetransport: response body exceeds limit")
)

// Defaults for Options fields left zero.
const (
	defaultAttemptTimeout   = 30 * time.Second
	defaultDialTimeout      = 10 * time.Second
	defaultMaxResponseBytes = int64(32 << 20)
	defaultMaxRequestBytes  = int64(16 << 20)
)

// Options configures the transport for one remote.
type Options struct {
	// Trust is the pinned trust. Exactly one pin must be set.
	Trust Trust

	// Endpoints is the ordered list of admin-approved HTTPS origins.
	// The request is sent to Endpoints[0] and fails over in order, only
	// on connection errors and timeouts.
	Endpoints []*url.URL

	// Auth returns the value for the Authorization header, if any. The
	// header is written to the endpoint only after the TLS handshake
	// has verified the pinned trust, so credentials are never
	// transmitted before trust is established. A nil Auth sends no
	// Authorization header.
	Auth func(ctx context.Context) (string, error)

	// Timeout bounds one endpoint attempt: dial, handshake and the
	// request up to the response headers. Default 30s.
	Timeout time.Duration

	// DialTimeout bounds the TCP dial of one attempt. Default 10s.
	DialTimeout time.Duration

	// MaxResponseBytes limits the response body size. Reads beyond the
	// limit fail with ErrResponseTooLarge. 0 uses the default of 32 MiB.
	MaxResponseBytes int64

	// MaxRequestBytes limits the request body size. Requests whose
	// ContentLength exceeds the limit are refused with
	// ErrRequestTooLarge before any endpoint is contacted. 0 uses the
	// default of 16 MiB.
	MaxRequestBytes int64

	// Now is the clock used for certificate expiry checks. Default
	// time.Now.
	Now func() time.Time
}

// ParseEndpoint parses an admin-approved endpoint origin. Only https URLs
// with a host are accepted.
func ParseEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("pvetransport: parse endpoint %q: %w", raw, err)
	}
	if err := checkEndpoint(u); err != nil {
		return nil, fmt.Errorf("pvetransport: endpoint %q: %w", raw, err)
	}
	return u, nil
}

func checkEndpoint(u *url.URL) error {
	if u.Scheme != "https" {
		return errors.New("must be https")
	}
	if u.Hostname() == "" {
		return errors.New("has no host")
	}
	return nil
}

// NewRoundTripper builds an http.RoundTripper for one remote. See the
// package documentation for the trust, failover, redirect, proxy and
// credential rules it enforces.
func NewRoundTripper(opts Options) (http.RoundTripper, error) {
	return newRoundTripper(opts)
}

// NewClient builds an *http.Client for one remote. The client refuses
// redirects (ErrRedirect) and uses the pinned-trust RoundTripper from
// NewRoundTripper. Callers should pass request URLs whose path and query
// are the PVE API path; the host is taken from the endpoint list and may
// change on failover.
func NewClient(opts Options) (*http.Client, error) {
	rt, err := newRoundTripper(opts)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: rt,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}, nil
}

func newRoundTripper(opts Options) (*roundTripper, error) {
	if err := opts.Trust.Validate(); err != nil {
		return nil, err
	}
	if len(opts.Endpoints) == 0 {
		return nil, ErrNoEndpoints
	}
	for _, u := range opts.Endpoints {
		if u == nil {
			return nil, errors.New("pvetransport: nil endpoint")
		}
		if err := checkEndpoint(u); err != nil {
			return nil, fmt.Errorf("pvetransport: endpoint %q: %w", u, err)
		}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultAttemptTimeout
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = defaultMaxResponseBytes
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = defaultMaxRequestBytes
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	rt := &roundTripper{opts: opts}
	for _, u := range opts.Endpoints {
		rt.endpoints = append(rt.endpoints, newEndpointConn(u, opts))
	}
	return rt, nil
}

// newEndpointConn builds the transport for one endpoint. Connections are
// dialed and TLS-handshaked by dialAndVerify, which runs the pin
// verification inside the handshake; the transport reuses the verified
// connection as-is (DialTLSContext), so the standard transport never
// performs or skips verification on its own.
func newEndpointConn(u *url.URL, opts Options) *endpointConn {
	host := u.Hostname()
	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	return &endpointConn{
		url: u,
		transport: &http.Transport{
			Proxy:               nil, // never use environment proxies
			ForceAttemptHTTP2:   false,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
			DialContext:         dialer.DialContext,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialAndVerify(ctx, dialer, u.Host, opts.Trust.TLSConfig(host, opts.Now))
			},
		},
	}
}

// dialAndVerify dials endpoint and performs the TLS handshake, which
// verifies the pinned trust. On failure the connection is closed and the
// error is returned: trust failures carry ErrTrustMismatch, protocol-level
// handshake failures are wrapped in handshakeError so failover can treat
// them as connection errors.
func dialAndVerify(ctx context.Context, dialer *net.Dialer, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		if errors.Is(err, ErrTrustMismatch) {
			return nil, err // trust failure: terminal
		}
		return nil, &handshakeError{err: err}
	}
	return tlsConn, nil
}

// handshakeError marks a TLS handshake failure that is not a trust
// verification failure (protocol error, peer reset during handshake).
// These are connection-level failures that allow failover.
type handshakeError struct{ err error }

func (e *handshakeError) Error() string {
	return "pvetransport: tls handshake: " + e.err.Error()
}

func (e *handshakeError) Unwrap() error { return e.err }

// roundTripper sends a request to the remote's endpoints in order,
// failing over only on connection errors and timeouts.
type roundTripper struct {
	opts      Options
	endpoints []*endpointConn
}

// endpointConn is one endpoint with its own transport.
type endpointConn struct {
	url       *url.URL
	transport *http.Transport
}

// RoundTrip implements http.RoundTripper.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("pvetransport: request has no URL")
	}
	attempts := rt.endpoints
	if req.Body != nil && req.GetBody == nil && len(attempts) > 1 {
		// A body that cannot be replayed is sent to the first endpoint
		// only; failover would send it twice.
		attempts = attempts[:1]
	}
	var firstErr error
	for _, ec := range attempts {
		resp, err := rt.attempt(req, ec)
		if err == nil {
			resp.Body = newLimitedBody(resp.Body, rt.opts.MaxResponseBytes, ErrResponseTooLarge)
			return resp, nil
		}
		if errors.Is(err, ErrTrustMismatch) || errors.Is(err, ErrRedirect) {
			// Terminal: no failover after a trust failure or a
			// refused redirect.
			return nil, err
		}
		if firstErr == nil {
			firstErr = err
		}
		if !isConnectionError(err) {
			// Anything that is not a connection failure or timeout is
			// terminal.
			return nil, err
		}
	}
	return nil, fmt.Errorf("pvetransport: all %d endpoints failed: %w", len(attempts), firstErr)
}

// attempt sends the request to one endpoint. The Authorization header is
// attached to the request before the transport is invoked, but the
// transport writes the request only after the TLS handshake — which
// verifies the pinned trust — has succeeded, so credentials are never
// transmitted to an endpoint that failed pin verification.
func (rt *roundTripper) attempt(req *http.Request, ec *endpointConn) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), rt.opts.Timeout)
	defer cancel()

	attemptReq := req.Clone(ctx)
	target := &url.URL{
		Scheme:   "https",
		Host:     ec.url.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}
	if target.Path == "" {
		target.Path = "/"
	}
	attemptReq.URL = target
	attemptReq.Host = ec.url.Host

	if req.Body != nil {
		body, err := rt.requestBody(req)
		if err != nil {
			return nil, err
		}
		attemptReq.Body = body
	}

	if rt.opts.Auth != nil {
		auth, err := rt.opts.Auth(ctx)
		if err != nil {
			return nil, err
		}
		if auth != "" {
			if attemptReq.Header == nil {
				attemptReq.Header = make(http.Header)
			}
			attemptReq.Header.Set("Authorization", auth)
		}
	}

	return ec.transport.RoundTrip(attemptReq)
}

// requestBody returns a fresh, size-limited copy of the request body.
func (rt *roundTripper) requestBody(req *http.Request) (io.ReadCloser, error) {
	var src io.ReadCloser
	var err error
	if req.GetBody != nil {
		src, err = req.GetBody()
	} else {
		src = req.Body
	}
	if err != nil {
		return nil, fmt.Errorf("pvetransport: get request body: %w", err)
	}
	limit := rt.opts.MaxRequestBytes
	if req.ContentLength > limit {
		src.Close()
		return nil, fmt.Errorf("%w: %d bytes > limit %d", ErrRequestTooLarge, req.ContentLength, limit)
	}
	return newLimitedBody(src, limit, ErrRequestTooLarge), nil
}

// isConnectionError reports whether err is a connection-level failure (dial
// failure, reset, timeout, TLS protocol error) that allows failover to the
// next endpoint. Trust mismatches, refused redirects and anything else are
// terminal.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTrustMismatch) || errors.Is(err, ErrRedirect) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false // trust failure: terminal
	}
	var hsErr *handshakeError
	if errors.As(err, &hsErr) {
		return true // TLS protocol failure: connection error
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isConnectionError(urlErr.Err)
	}
	return false
}

// limitedBody reads at most limit bytes from rc; a body that continues
// past the limit fails with tooLarge.
type limitedBody struct {
	rc       io.ReadCloser
	r        *bufio.Reader
	limit    int64
	count    int64
	tooLarge error
	checked  bool
	checkErr error
}

func newLimitedBody(rc io.ReadCloser, limit int64, tooLarge error) *limitedBody {
	return &limitedBody{rc: rc, r: bufio.NewReader(rc), limit: limit, tooLarge: tooLarge}
}

// Read implements io.Reader.
func (l *limitedBody) Read(p []byte) (int, error) {
	if l.count >= l.limit {
		return 0, l.exceeded()
	}
	if int64(len(p)) > l.limit-l.count {
		p = p[:l.limit-l.count]
	}
	n, err := l.r.Read(p)
	l.count += int64(n)
	return n, err
}

// exceeded reports whether the body continues past the limit. A body that
// ends exactly at the limit passes through as io.EOF.
func (l *limitedBody) exceeded() error {
	if l.checked {
		return l.checkErr
	}
	l.checked = true
	if _, err := l.r.Peek(1); err == nil {
		l.checkErr = fmt.Errorf("%w: body exceeds %d bytes", l.tooLarge, l.limit)
	} else if errors.Is(err, io.EOF) {
		l.checkErr = io.EOF
	} else {
		l.checkErr = err
	}
	return l.checkErr
}

// Close implements io.Closer.
func (l *limitedBody) Close() error { return l.rc.Close() }
