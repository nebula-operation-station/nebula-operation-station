// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Fetch limits and timeouts.
const (
	// DefaultFetchTimeout bounds one whole request including the body.
	DefaultFetchTimeout = 30 * time.Minute
	// dialTimeout bounds the TCP connect.
	dialTimeout = 15 * time.Second
	// tlsHandshakeTimeout bounds the TLS handshake.
	tlsHandshakeTimeout = 15 * time.Second
	// responseHeaderTimeout bounds the wait for response headers.
	responseHeaderTimeout = 60 * time.Second
	// maxResponseHeaderBytes caps response headers.
	maxResponseHeaderBytes = 64 << 10
	// MaxRedirects is the number of same-origin redirects followed.
	MaxRedirects = 3
	// MaxValidatorBytes caps a stored ETag or Last-Modified value.
	MaxValidatorBytes = 256
)

// Fetch errors.
var (
	// ErrTooLarge: the body exceeds the feed's size cap.
	ErrTooLarge = errors.New("vulnfeed: response exceeds size limit")
	// ErrRedirectRefused: a redirect leaves the request's origin or the
	// redirect limit is exceeded.
	ErrRedirectRefused = errors.New("vulnfeed: redirect refused")
	// ErrHTTPStatus: the response status is not 200 (or a solicited 304).
	ErrHTTPStatus = errors.New("vulnfeed: unexpected HTTP status")
)

// Validators are the conditional-request validators of a previous fetch.
// They are server metadata, never a content date.
type Validators struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// FetchResult describes a completed fetch.
type FetchResult struct {
	// NotModified: the server answered 304 to a conditional request;
	// nothing was written.
	NotModified bool
	// Validators of the response (sanitised; empty when absent or invalid).
	Validators Validators
	// Bytes is the number of body bytes written.
	Bytes int64
}

// FetcherConfig configures a Fetcher.
type FetcherConfig struct {
	// Allowlist of origins. Required.
	Allowlist *Allowlist
	// RootCAs verifies server certificates; nil uses the system roots.
	RootCAs *x509.CertPool
	// Timeout bounds one request including the body; zero means
	// DefaultFetchTimeout.
	Timeout time.Duration
}

// Fetcher downloads feed files from allowlisted origins only.
type Fetcher struct {
	allow     *Allowlist
	client    *http.Client
	transport *http.Transport
}

// NewFetcher builds a Fetcher. The transport ignores proxy environment
// variables, verifies TLS, and its dialer refuses any address that is not
// an allowlisted origin (second layer behind the URL check).
func NewFetcher(cfg FetcherConfig) (*Fetcher, error) {
	if cfg.Allowlist == nil {
		return nil, fmt.Errorf("new fetcher: allowlist required: %w", ErrOriginNotAllowed)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	allow := cfg.Allowlist
	dialer := &net.Dialer{Timeout: dialTimeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !allow.allowsAddr(addr) {
				return nil, fmt.Errorf("dial %s: %w", addr, ErrOriginNotAllowed)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		IdleConnTimeout:        90 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return fmt.Errorf("more than %d redirects: %w", MaxRedirects, ErrRedirectRefused)
			}
			first, ok1 := originOfURL(via[0].URL)
			next, ok2 := originOfURL(req.URL)
			if !ok1 || !ok2 || first != next || !allow.Allows(req.URL) {
				return fmt.Errorf("redirect to another origin: %w", ErrRedirectRefused)
			}
			return nil
		},
	}
	return &Fetcher{allow: allow, client: client, transport: tr}, nil
}

// Fetch downloads rawURL into dst, writing at most maxBytes. A declared
// Content-Length above maxBytes is rejected before the body is read; a
// longer body without one fails with ErrTooLarge once the cap is passed
// (the caller discards what dst received). prev, if set, makes the
// request conditional; a 304 is accepted only then.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string, maxBytes int64, prev Validators, dst io.Writer) (FetchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch: parse URL: %w", ErrOriginNotAllowed)
	}
	if !f.allow.Allows(u) {
		return FetchResult{}, fmt.Errorf("fetch %s: %w", redacted(u), ErrOriginNotAllowed)
	}
	if maxBytes <= 0 {
		return FetchResult{}, fmt.Errorf("fetch %s: no size limit: %w", redacted(u), ErrTooLarge)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch %s: build request: %w", redacted(u), err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "nebula-vuln-agent")
	prev = sanitizeValidators(prev.ETag, prev.LastModified)
	conditional := prev != (Validators{})
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch %s: %w", redacted(u), unwrapURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified && conditional:
		return FetchResult{NotModified: true, Validators: prev}, nil
	case resp.StatusCode != http.StatusOK:
		return FetchResult{}, fmt.Errorf("fetch %s: status %d: %w", redacted(u), resp.StatusCode, ErrHTTPStatus)
	}
	if resp.ContentLength > maxBytes {
		return FetchResult{}, fmt.Errorf("fetch %s: declared %d bytes, cap %d: %w", redacted(u), resp.ContentLength, maxBytes, ErrTooLarge)
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch %s: read body: %w", redacted(u), err)
	}
	// One more byte means the cap was exceeded.
	var probe [1]byte
	if m, _ := io.ReadFull(resp.Body, probe[:]); m > 0 {
		return FetchResult{}, fmt.Errorf("fetch %s: body exceeds cap %d: %w", redacted(u), maxBytes, ErrTooLarge)
	}
	return FetchResult{Validators: sanitizeValidators(resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")), Bytes: n}, nil
}

// unwrapURLError drops *url.Error, whose message repeats the full URL,
// while keeping the wrapped cause for errors.Is.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// redacted returns the URL without credentials, query or fragment.
func redacted(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.Fragment = ""
	return c.String()
}

// sanitizeValidators keeps only bounded, printable ASCII validators and a
// Last-Modified that parses as an HTTP date (re-formatted).
func sanitizeValidators(etag, lastModified string) Validators {
	var v Validators
	if printableASCII(etag) {
		v.ETag = etag
	}
	if printableASCII(lastModified) {
		if t, err := http.ParseTime(lastModified); err == nil {
			v.LastModified = t.UTC().Format(http.TimeFormat)
		}
	}
	return v
}

// printableASCII reports a non-empty string of at most MaxValidatorBytes
// bytes in 0x20..0x7e.
func printableASCII(s string) bool {
	if s == "" || len(s) > MaxValidatorBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
