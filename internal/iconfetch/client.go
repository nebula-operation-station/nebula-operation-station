// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Limits and fixed request properties.
const (
	// MaxRedirects is the number of redirects followed; each target is
	// re-validated with ValidateURL.
	MaxRedirects = 3
	// MaxBodyBytes caps an icon body; a larger body is an error, not a
	// truncated icon.
	MaxBodyBytes = 256 << 10
	// TotalTimeout bounds a whole fetch: every connection, redirect and
	// the body read.
	TotalTimeout = 10 * time.Second
	// UserAgent is the only identifying header sent.
	UserAgent = "nebula-operation-station-iconfetch"

	// connectTimeout bounds one TCP connect.
	connectTimeout = 5 * time.Second
	// tlsHandshakeTimeout bounds one TLS handshake.
	tlsHandshakeTimeout = 5 * time.Second
	// maxResponseHeaderBytes bounds the response headers.
	maxResponseHeaderBytes = 16 << 10
)

// Sentinel errors callers can branch on (besides ErrURL and ErrAddress).
var (
	// ErrTooManyRedirects means more than MaxRedirects redirects.
	ErrTooManyRedirects = errors.New("icon fetch: too many redirects")
	// ErrBodyTooLarge means the body exceeded MaxBodyBytes.
	ErrBodyTooLarge = errors.New("icon fetch: body too large")
	// ErrStatus means the final response status was not 200.
	ErrStatus = errors.New("icon fetch: unexpected status")
)

// Config configures a Client.
type Config struct {
	// Allow is the host allowlist; empty means DefaultAllowlist.
	Allow []string
	// Resolver resolves icon hosts; nil means net.DefaultResolver.
	Resolver Resolver
}

// Client fetches icons over HTTPS under the iconfetch policy. It is safe
// for concurrent use.
type Client struct {
	hc    *http.Client
	allow []string
}

// options are the test seams: the raw connect function (production dials
// the checked IP), the trusted roots (nil = system roots) and the total
// timeout.
type options struct {
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	rootCAs *x509.CertPool
	timeout time.Duration
}

// New returns a Client with the production limits.
func New(cfg Config) *Client {
	return newClient(cfg, options{
		dial:    (&net.Dialer{Timeout: connectTimeout}).DialContext,
		timeout: TotalTimeout,
	})
}

func newClient(cfg Config, o options) *Client {
	allow := append([]string(nil), cfg.Allow...)
	res := cfg.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	d := &dialer{resolver: res, allow: allow, dial: o.dial}
	tr := &http.Transport{
		Proxy:                  nil, // never honour HTTPS_PROXY: the proxy would resolve and connect unchecked
		DialContext:            d.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.rootCAs},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  o.timeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DisableKeepAlives:      true, // every connection resolves and checks again
		DisableCompression:     true, // the body cap applies to the bytes on the wire
	}
	hc := &http.Client{
		Transport: tr,
		Timeout:   o.timeout,
		Jar:       nil, // no cookies
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return ErrTooManyRedirects
			}
			if _, err := ValidateURL(req.URL.String(), allow); err != nil {
				return fmt.Errorf("redirect: %w", err)
			}
			req.Header.Del("Authorization")
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Cookie")
			return nil
		},
	}
	return &Client{hc: hc, allow: allow}
}

// Fetch validates rawURL, fetches it and returns the body. Only status 200
// is accepted; the body must not exceed MaxBodyBytes. The body is
// untrusted bytes; the caller must validate it as an image.
func (c *Client) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := ValidateURL(rawURL, c.allow)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.hc.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("icon fetch %s: build request: %w", u.Host, err)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "image/*")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("icon fetch %s: %w", u.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", ErrStatus, resp.StatusCode)
	}
	if resp.ContentLength > MaxBodyBytes {
		return nil, fmt.Errorf("%w: content length %d exceeds %d", ErrBodyTooLarge, resp.ContentLength, MaxBodyBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("icon fetch %s: read body: %w", u.Host, err)
	}
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, MaxBodyBytes)
	}
	return body, nil
}
