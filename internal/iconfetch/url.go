// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iconfetch fetches service icons from a small allowlist of public
// HTTPS sources (ADR 0009 D6, TM07). Every URL, including every redirect
// target, must pass ValidateURL; the client resolves host names itself,
// refuses internal addresses and connects only to the address it checked,
// so a DNS answer that changes between check and connect (rebinding) cannot
// reach an internal service.
package iconfetch

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netpolicy"
)

// MaxURLLen bounds an icon URL before it is parsed.
const MaxURLLen = 2048

// maxHostLen is the RFC 1123 maximum for a host name.
const maxHostLen = 253

// defaultAllowlist is the set of icon hosts used when no allowlist is
// given. It is unexported so no package can widen it at runtime;
// DefaultAllowlist returns a copy.
var defaultAllowlist = []string{
	"avatars.githubusercontent.com",
	"upload.wikimedia.org",
}

// DefaultAllowlist returns a copy of the icon hosts used when no allowlist
// is given.
func DefaultAllowlist() []string {
	return append([]string(nil), defaultAllowlist...)
}

// ErrURL marks an icon URL that violates the URL policy.
var ErrURL = errors.New("icon URL rejected")

// ValidateURL checks raw against the icon URL policy and returns the parsed
// URL with a lower-cased host and without the default port. The policy:
// scheme https only; port empty or 443; no user info; no fragment; no IP
// literal in any form; the host must be a strict ASCII host name that is
// exactly (case-insensitively) on allow. An empty allow means
// DefaultAllowlist.
func ValidateURL(raw string, allow []string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > MaxURLLen {
		return nil, fmt.Errorf("%w: length must be 1-%d bytes", ErrURL, MaxURLLen)
	}
	if !utf8.ValidString(raw) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrURL)
	}
	for _, r := range raw {
		// Control characters, spaces, backslashes and non-ASCII runes have
		// no place in an icon URL and are where parsers disagree.
		if r <= 0x20 || r >= 0x7f || r == '\\' {
			return nil, fmt.Errorf("%w: contains a control, space, backslash or non-ASCII character", ErrURL)
		}
	}
	if strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%w: fragments are not allowed", ErrURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrURL, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme must be https", ErrURL)
	}
	if u.Opaque != "" || u.User != nil || strings.Contains(u.Host, "@") {
		return nil, fmt.Errorf("%w: user info and opaque URLs are not allowed", ErrURL)
	}
	host := u.Hostname()
	port := u.Port()
	switch {
	case u.Host == host:
	case u.Host == host+":443" && port == "443":
	default:
		return nil, fmt.Errorf("%w: port must be empty or 443", ErrURL)
	}
	if host == "" || len(host) > maxHostLen {
		return nil, fmt.Errorf("%w: host must be 1-%d characters", ErrURL, maxHostLen)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, fmt.Errorf("%w: IP literals are not allowed", ErrURL)
	}
	if !netpolicy.IsHostname(host) {
		return nil, fmt.Errorf("%w: host must be a DNS name, not an IP literal", ErrURL)
	}
	// url.Parse decodes percent-escapes in the host. Require that the raw
	// authority is literally the host (and optional :443), so what was
	// checked is exactly what was written.
	lowerRaw := strings.ToLower(raw)
	rest, ok := strings.CutPrefix(lowerRaw, "https://"+strings.ToLower(u.Host))
	if !ok || (rest != "" && rest[0] != '/' && rest[0] != '?') {
		return nil, fmt.Errorf("%w: authority must be a plain host name", ErrURL)
	}
	host = strings.ToLower(host)
	if !onAllowlist(host, allow) {
		return nil, fmt.Errorf("%w: host %s is not on the icon allowlist", ErrURL, host)
	}
	u.Host = host
	u.RawFragment = ""
	u.Fragment = ""
	return u, nil
}

// onAllowlist reports whether the lower-cased host is exactly on allow
// (DefaultAllowlist when allow is empty).
func onAllowlist(host string, allow []string) bool {
	if len(allow) == 0 {
		allow = defaultAllowlist
	}
	for _, a := range allow {
		if strings.ToLower(a) == host {
			return true
		}
	}
	return false
}
