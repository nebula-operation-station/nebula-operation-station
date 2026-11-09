// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
)

// Transport limits (ADR 0010 D3).
const (
	// DialTimeout bounds TCP connect plus TLS handshake.
	DialTimeout = 10 * time.Second
	// RequestTimeout bounds one request including reading the body.
	RequestTimeout = 60 * time.Second
	// MaxKeyLength bounds the API key accepted from the vault.
	MaxKeyLength = 1024
	// maxResponseHeaderBytes bounds the response header block.
	maxResponseHeaderBytes = 64 << 10
	// maxServerNameLength bounds Options.ServerName (DNS name limit).
	maxServerNameLength = 253
)

// XML limits for PAN-OS responses (ADR 0010 D3 "Parse limits"). ND-04 owns
// these values; they are repeated here as named constants until the
// netdevcontract package exists and must stay equal to it.
const (
	// MaxXMLDepth is the maximum element nesting depth.
	MaxXMLDepth = 64
	// MaxXMLElements is the maximum number of elements per response.
	MaxXMLElements = 500_000
	// MaxXMLTextBytes is the maximum text length of one element or
	// attribute value.
	MaxXMLTextBytes = 4 << 10
	// maxAPICodeLength bounds the numeric code kept from an error response.
	maxAPICodeLength = 6
)

// apiPath is the fixed XML API path; requests never carry a query.
const apiPath = "/api/"

// Sentinel errors returned by the client.
var (
	// ErrTrustMismatch is pvetransport.ErrTrustMismatch: the served
	// certificate does not match the pinned trust. Terminal; the device
	// must be blocked.
	ErrTrustMismatch = pvetransport.ErrTrustMismatch

	// ErrAddressRefused is returned when the endpoint is not an allowed
	// internal management address.
	ErrAddressRefused = errors.New("panapi: endpoint address refused")

	// ErrRedirect is returned when the device answers with a redirect.
	ErrRedirect = errors.New("panapi: redirect refused")

	// ErrResponseTooLarge is returned when a response exceeds its cap.
	ErrResponseTooLarge = errors.New("panapi: response exceeds limit")

	// ErrXMLLimit is returned when a response exceeds an XML depth,
	// element or text limit.
	ErrXMLLimit = errors.New("panapi: response exceeds XML limit")

	// ErrMalformedResponse is returned for a response that is not
	// well-formed UTF-8 XML with a <response> root and known status.
	ErrMalformedResponse = errors.New("panapi: malformed response")

	// ErrHTTPStatus is returned for an unexpected HTTP status code.
	ErrHTTPStatus = errors.New("panapi: unexpected HTTP status")

	// ErrUnauthorized is returned for HTTP 401 or 403: the key is invalid,
	// expired or lacks the role permission.
	ErrUnauthorized = errors.New("panapi: unauthorized")

	// ErrAPIStatus is returned when the device reports status="error".
	// Use errors.As with *APIError for the numeric code.
	ErrAPIStatus = errors.New("panapi: device reported an error")

	// ErrInvalidKey is returned when the API key is empty, too long or
	// contains bytes that cannot be sent in a header. The error never
	// contains the key.
	ErrInvalidKey = errors.New("panapi: invalid API key")

	// ErrKeyUnavailable is returned when Options.Key fails. No request is
	// sent.
	ErrKeyUnavailable = errors.New("panapi: API key unavailable")

	// ErrInvalidOptions is returned by New for invalid options.
	ErrInvalidOptions = errors.New("panapi: invalid options")
)

// APIError is a PAN-OS status="error" response. Only the numeric code is
// kept; the message and the rest of the body are discarded unread.
type APIError struct {
	// Code is the response's code attribute if it is all digits, else "".
	Code string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Code == "" {
		return ErrAPIStatus.Error()
	}
	return ErrAPIStatus.Error() + " (code " + e.Code + ")"
}

// Unwrap makes errors.Is(err, ErrAPIStatus) true.
func (e *APIError) Unwrap() error { return ErrAPIStatus }

// Options configures a Client for one PAN-OS device.
type Options struct {
	// Endpoint is the management interface address as an IP literal and
	// port. It is dialled as is; DNS is never consulted.
	Endpoint netip.AddrPort

	// ServerName is the name expected in the certificate's DNS SAN. Empty
	// means the IP SAN of Endpoint is checked.
	ServerName string

	// Trust is the pinned trust (leaf fingerprint or issuing CA).
	Trust pvetransport.Trust

	// Key returns the API key. It is called once per request, after the
	// address check; the key is placed in the X-PAN-KEY header only.
	Key func(ctx context.Context) (string, error)

	// Logger receives one debug record per request (operation, HTTP
	// status, byte count, duration). Nil discards. Keys, bodies and
	// xpaths are never logged.
	Logger *slog.Logger

	// Now is the clock for certificate validity. Default time.Now.
	Now func() time.Time
}

// Response is a successful, limit-checked XML API response.
type Response struct {
	// Body is the complete response document (UTF-8, within the XML
	// limits, root <response status="success">). It is untrusted device
	// data; parsing it is ND-09.
	Body []byte
}

// Client is a read-only XML API client for one device. It is safe for
// concurrent use; requests are serialized (one in flight per device).
type Client struct {
	endpoint  netip.AddrPort
	key       func(ctx context.Context) (string, error)
	logger    *slog.Logger
	http      *http.Client
	transport *http.Transport
	sem       chan struct{}

	// Overridable only from tests in this package.
	checkAddr      func(netip.Addr) error
	dialTimeout    time.Duration
	requestTimeout time.Duration
}

// New validates opts and builds a Client. The endpoint must pass
// CheckManagementAddr now and again before every dial.
func New(opts Options) (*Client, error) {
	return newClient(opts, CheckManagementAddr)
}

// newClient is New with an injectable address check; only tests in this
// package pass anything other than CheckManagementAddr (loopback servers).
func newClient(opts Options, checkAddr func(netip.Addr) error) (*Client, error) {
	if err := opts.Trust.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	if !opts.Endpoint.IsValid() || opts.Endpoint.Port() == 0 {
		return nil, fmt.Errorf("%w: endpoint must be an IP literal with a port", ErrInvalidOptions)
	}
	if opts.Endpoint.Addr().Zone() != "" {
		return nil, fmt.Errorf("%w: endpoint must not carry a zone", ErrInvalidOptions)
	}
	if opts.Key == nil {
		return nil, fmt.Errorf("%w: no key source", ErrInvalidOptions)
	}
	if err := checkServerName(opts.ServerName); err != nil {
		return nil, err
	}
	if err := checkAddr(opts.Endpoint.Addr()); err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	sanHost := opts.ServerName
	if sanHost == "" {
		sanHost = opts.Endpoint.Addr().Unmap().String()
	}
	c := &Client{
		endpoint:       opts.Endpoint,
		key:            opts.Key,
		logger:         logger,
		sem:            make(chan struct{}, 1),
		checkAddr:      checkAddr,
		dialTimeout:    DialTimeout,
		requestTimeout: RequestTimeout,
	}
	tlsConfig := opts.Trust.TLSConfig(sanHost, opts.Now)
	c.transport = &http.Transport{
		Proxy:                  nil, // never use environment proxies
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("panapi: plain-text dial refused")
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return c.dialTLS(ctx, tlsConfig.Clone())
		},
	}
	c.http = &http.Client{
		Transport: c.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}
	return c, nil
}

// dialTLS dials the fixed endpoint and runs the pinned TLS handshake. The
// address argument of the transport is ignored: the client only ever dials
// its own IP literal, re-checked here at every dial.
func (c *Client) dialTLS(ctx context.Context, cfg *tls.Config) (net.Conn, error) {
	if err := c.checkAddr(c.endpoint.Addr()); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()
	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", c.endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("panapi: dial: %w", err)
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if strings.HasPrefix(err.Error(), "tls: failed to parse certificate from server: ") {
			return nil, fmt.Errorf("%w: unparseable certificate", ErrTrustMismatch)
		}
		return nil, fmt.Errorf("panapi: tls handshake: %w", err)
	}
	return conn, nil
}

// Close releases idle connections.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
}

// Do sends one read-only request and returns the limit-checked response.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	if !req.valid() {
		return nil, ErrInvalidRequest
	}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("panapi: %s: wait for device slot: %w", req.label, ctx.Err())
	}
	defer func() { <-c.sem }()

	start := time.Now()
	resp, status, n, err := c.do(ctx, req)
	attrs := []slog.Attr{
		slog.String("op", req.label),
		slog.Int("http_status", status),
		slog.Int("bytes", n),
		slog.Duration("duration", time.Since(start)),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", errorClass(err)))
	}
	c.logger.LogAttrs(ctx, slog.LevelDebug, "panapi request", attrs...)
	if err != nil {
		return nil, fmt.Errorf("panapi: %s: %w", req.label, err)
	}
	return resp, nil
}

func (c *Client) do(ctx context.Context, req Request) (*Response, int, int, error) {
	if err := c.checkAddr(c.endpoint.Addr()); err != nil {
		return nil, 0, 0, err
	}
	key, err := c.key(ctx)
	if err != nil {
		// The key source (executor vault) never puts secrets into its
		// errors (AGENTS.md rule 7); it is wrapped so callers can tell a
		// locked vault apart.
		return nil, 0, 0, fmt.Errorf("%w: %w", ErrKeyUnavailable, err)
	}
	if err := checkKey(key); err != nil {
		return nil, 0, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()
	// The URL is fixed: endpoint literal plus apiPath, no query. The
	// request parameters travel in the POST body, the key in a header.
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.endpoint.String()+apiPath, strings.NewReader(req.body()))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("build request: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.Header.Set("Accept", "application/xml")
	hreq.Header.Set("User-Agent", "nebula-operation-station")
	hreq.Header.Set("X-PAN-KEY", key)

	hresp, err := c.http.Do(hreq)
	if err != nil {
		return nil, 0, 0, sanitizeTransportError(err)
	}
	defer hresp.Body.Close()
	status := hresp.StatusCode
	switch {
	case status >= 300 && status < 400:
		return nil, status, 0, ErrRedirect
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, status, 0, fmt.Errorf("%w: HTTP %d", ErrUnauthorized, status)
	case status != http.StatusOK:
		return nil, status, 0, fmt.Errorf("%w: HTTP %d", ErrHTTPStatus, status)
	}
	data, err := io.ReadAll(io.LimitReader(hresp.Body, req.maxBytes+1))
	if err != nil {
		return nil, status, len(data), fmt.Errorf("read body: %w", sanitizeTransportError(err))
	}
	if int64(len(data)) > req.maxBytes {
		return nil, status, len(data), fmt.Errorf("%w: more than %d bytes", ErrResponseTooLarge, req.maxBytes)
	}
	if err := checkResponse(data); err != nil {
		return nil, status, len(data), err
	}
	return &Response{Body: data}, status, len(data), nil
}

// sanitizeTransportError keeps the sentinel chain of a transport error but
// drops the *url.Error wrapper that net/http adds; the URL holds no key,
// but errors stay free of request details.
func sanitizeTransportError(err error) error {
	if errors.Is(err, ErrRedirect) {
		return ErrRedirect
	}
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}

// errorClass maps an error to a fixed label for logs.
func errorClass(err error) string {
	for _, s := range []struct {
		err   error
		label string
	}{
		{ErrTrustMismatch, "trust_mismatch"},
		{ErrAddressRefused, "address_refused"},
		{ErrRedirect, "redirect"},
		{ErrResponseTooLarge, "too_large"},
		{ErrXMLLimit, "xml_limit"},
		{ErrMalformedResponse, "malformed"},
		{ErrUnauthorized, "unauthorized"},
		{ErrHTTPStatus, "http_status"},
		{ErrAPIStatus, "api_error"},
		{ErrInvalidKey, "invalid_key"},
		{ErrKeyUnavailable, "key_unavailable"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
	} {
		if errors.Is(err, s.err) {
			return s.label
		}
	}
	return "transport"
}

// CheckManagementAddr refuses every address that is not a private
// (RFC 1918 or RFC 4193) unicast address: public, loopback, link-local,
// multicast and unspecified addresses are refused (ADR 0010 D1). IPv4-mapped
// IPv6 addresses are checked as IPv4.
func CheckManagementAddr(a netip.Addr) error {
	a = a.Unmap()
	if !a.IsValid() || !a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return fmt.Errorf("%w: %s is not a private management address", ErrAddressRefused, a)
	}
	return nil
}

func checkServerName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > maxServerNameLength {
		return fmt.Errorf("%w: server name too long", ErrInvalidOptions)
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%w: server name must be a DNS name; use Endpoint for addresses", ErrInvalidOptions)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: invalid server name", ErrInvalidOptions)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("%w: invalid server name", ErrInvalidOptions)
			}
		}
	}
	return nil
}

// checkKey refuses keys that cannot be sent as a header value. The error
// never contains the key or any part of it.
func checkKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: empty", ErrInvalidKey)
	}
	if len(key) > MaxKeyLength {
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidKey, MaxKeyLength)
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7e {
			return fmt.Errorf("%w: disallowed byte", ErrInvalidKey)
		}
	}
	return nil
}

// checkResponse verifies that data is a well-formed UTF-8 XML document
// within the XML limits whose root is <response status="success">. It never
// puts response content into an error.
func checkResponse(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrMalformedResponse)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	// CharsetReader stays nil: a document declaring a non-UTF-8 encoding
	// is refused by the decoder.
	var (
		depth    int
		elements int
		text     []int // text bytes per open element
		rootSeen bool
		rootDone bool
		status   string
		code     string
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var serr *xml.SyntaxError
			if errors.As(err, &serr) {
				return fmt.Errorf("%w: XML syntax error at line %d", ErrMalformedResponse, serr.Line)
			}
			return fmt.Errorf("%w: XML decode failed", ErrMalformedResponse)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if rootDone {
				return fmt.Errorf("%w: content after the root element", ErrMalformedResponse)
			}
			depth++
			elements++
			if depth > MaxXMLDepth {
				return fmt.Errorf("%w: nesting deeper than %d", ErrXMLLimit, MaxXMLDepth)
			}
			if elements > MaxXMLElements {
				return fmt.Errorf("%w: more than %d elements", ErrXMLLimit, MaxXMLElements)
			}
			if len(t.Name.Local)+len(t.Name.Space) > MaxXMLTextBytes {
				return fmt.Errorf("%w: element name longer than %d bytes", ErrXMLLimit, MaxXMLTextBytes)
			}
			for _, a := range t.Attr {
				if len(a.Value) > MaxXMLTextBytes || len(a.Name.Local)+len(a.Name.Space) > MaxXMLTextBytes {
					return fmt.Errorf("%w: attribute longer than %d bytes", ErrXMLLimit, MaxXMLTextBytes)
				}
			}
			text = append(text, 0)
			if !rootSeen {
				rootSeen = true
				if t.Name.Local != "response" || t.Name.Space != "" {
					return fmt.Errorf("%w: root is not <response>", ErrMalformedResponse)
				}
				for _, a := range t.Attr {
					switch {
					case a.Name.Space == "" && a.Name.Local == "status":
						status = a.Value
					case a.Name.Space == "" && a.Name.Local == "code":
						code = a.Value
					}
				}
			}
		case xml.EndElement:
			depth--
			text = text[:len(text)-1]
			if depth == 0 {
				rootDone = true
			}
		case xml.CharData:
			if depth == 0 {
				if len(bytes.TrimSpace(t)) != 0 {
					return fmt.Errorf("%w: text outside the root element", ErrMalformedResponse)
				}
				continue
			}
			text[len(text)-1] += len(t)
			if text[len(text)-1] > MaxXMLTextBytes {
				return fmt.Errorf("%w: element text longer than %d bytes", ErrXMLLimit, MaxXMLTextBytes)
			}
		case xml.Directive:
			return fmt.Errorf("%w: XML directive (DOCTYPE) refused", ErrMalformedResponse)
		case xml.ProcInst:
			if t.Target != "xml" || rootSeen {
				return fmt.Errorf("%w: processing instruction refused", ErrMalformedResponse)
			}
		case xml.Comment:
			// ignored
		}
	}
	if !rootDone {
		return fmt.Errorf("%w: no root element", ErrMalformedResponse)
	}
	switch status {
	case "success":
		return nil
	case "error":
		return &APIError{Code: numericCode(code)}
	}
	return fmt.Errorf("%w: unknown response status", ErrMalformedResponse)
}

// numericCode keeps an API code only if it is a short run of digits.
func numericCode(code string) string {
	if code == "" || len(code) > maxAPICodeLength {
		return ""
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return ""
		}
	}
	return code
}
