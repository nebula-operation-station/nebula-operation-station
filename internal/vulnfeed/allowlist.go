// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrOriginNotAllowed reports a URL, redirect or connection outside the
// origin allowlist.
var ErrOriginNotAllowed = errors.New("vulnfeed: origin not allowlisted")

// MaxAllowlistOrigins bounds the allowlist size.
const MaxAllowlistOrigins = 64

// Allowlist is a set of exact origins (scheme "https", lower-case host,
// explicit port). Matching is exact; no wildcard, suffix or IP mapping.
type Allowlist struct {
	origins map[string]bool // "https://host:port"
	addrs   map[string]bool // "host:port" for the dialer check
}

// OriginOf returns the canonical origin "https://host:port" of an https
// URL. Other schemes, credentials and empty hosts are rejected.
func OriginOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse origin: %w", ErrOriginNotAllowed)
	}
	o, ok := originOfURL(u)
	if !ok {
		return "", fmt.Errorf("origin of %s URL: %w", u.Scheme, ErrOriginNotAllowed)
	}
	return o, nil
}

// originOfURL canonicalises u's origin; ok is false for anything but a
// credential-free https URL with a host.
func originOfURL(u *url.URL) (string, bool) {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return "https://" + net.JoinHostPort(host, port), true
}

// NewAllowlist builds an allowlist from https origins or URLs.
func NewAllowlist(origins []string) (*Allowlist, error) {
	if len(origins) == 0 || len(origins) > MaxAllowlistOrigins {
		return nil, fmt.Errorf("allowlist: %d origins: %w", len(origins), ErrOriginNotAllowed)
	}
	a := &Allowlist{origins: map[string]bool{}, addrs: map[string]bool{}}
	for _, raw := range origins {
		o, err := OriginOf(raw)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry: %w", err)
		}
		a.origins[o] = true
		a.addrs[strings.TrimPrefix(o, "https://")] = true
	}
	return a, nil
}

// Allows reports whether u's origin is on the allowlist.
func (a *Allowlist) Allows(u *url.URL) bool {
	o, ok := originOfURL(u)
	return ok && a.origins[o]
}

// allowsAddr reports whether a dial address "host:port" belongs to an
// allowlisted origin.
func (a *Allowlist) allowsAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return a.addrs[net.JoinHostPort(strings.ToLower(host), port)]
}
