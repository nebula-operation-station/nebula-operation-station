// SPDX-License-Identifier: AGPL-3.0-or-later

package registrypull

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// This file holds the HTTP side of a pull: the request allowlist enforced
// in the transport, the redirect policy, the dial guard and the auth flow.
//
//   - Every request is a GET. On the registry origin only
//     /v2/<approved repository>/manifests/<digest> and .../blobs/<digest>
//     are allowed; on the token realm only the exact realm path; on a blob
//     host any path, but never with an Authorization header.
//   - The Basic credential goes only to the realm (token auth) or to the
//     registry origin (basic auth); a bearer token only to the registry
//     origin. Requests carrying anything else are refused before they leave.
//   - Only blob requests follow redirects, at most MaxRedirects, and only to
//     the registry origin or a configured blob host. Authorization is
//     removed on every hop that leaves the registry origin.

// newHTTPClient builds the guarded HTTP client of p.
func (p *Puller) newHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: p.checkRedirect,
		Transport: &guardTransport{p: p, base: &http.Transport{
			Proxy:                 nil, // no proxies (ADR 0006)
			DialContext:           p.dialContext,
			ForceAttemptHTTP2:     false,
			DisableCompression:    true, // digests are over the raw bytes
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       idleConnTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.roots},
		}},
	}
}

// originOf returns the lower-case scheme://host[:port] of u.
func originOf(u *url.URL) string {
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// parseOrigin accepts an exact lower-case HTTPS origin without path, query,
// fragment or user information.
func parseOrigin(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || originOf(u) != s {
		return nil, fmt.Errorf("%w: %q is not an exact lower-case HTTPS origin", ErrInvalidOptions, s)
	}
	return u, nil
}

// guardTransport enforces the request allowlist on every exchange,
// including redirect hops and the token request.
type guardTransport struct {
	p    *Puller
	base http.RoundTripper
}

// RoundTrip refuses requests outside the allowlist before they are sent.
func (t *guardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.p.allowRequest(req); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// allowRequest is the transport-level allowlist.
func (p *Puller) allowRequest(req *http.Request) error {
	u := req.URL
	if req.Method != http.MethodGet || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: only HTTPS GET requests", ErrRequestNotAllowed)
	}
	authz := req.Header.Get("Authorization")
	origin := originOf(u)
	if p.realm != nil && origin == originOf(p.realm) && u.EscapedPath() == p.realm.EscapedPath() {
		if authz != "" && !strings.HasPrefix(authz, "Basic ") {
			return fmt.Errorf("%w: the token realm takes only the Basic credential", ErrRequestNotAllowed)
		}
		return nil
	}
	if origin == p.registry {
		switch {
		case authz == "":
		case strings.HasPrefix(authz, "Basic ") && p.reg.Mode == registryAuthBasic:
		case strings.HasPrefix(authz, "Bearer ") && p.reg.Mode == registryAuthToken:
		default:
			return fmt.Errorf("%w: authorization not allowed for this registry", ErrRequestNotAllowed)
		}
		if u.RawQuery != "" || u.ForceQuery || !p.allowedAPIPath(u.Path) || u.EscapedPath() != u.Path {
			return fmt.Errorf("%w: %s is not an approved manifest or blob path", ErrRequestNotAllowed, origin)
		}
		return nil
	}
	if slices.Contains(p.blobHosts, origin) {
		if authz != "" {
			return fmt.Errorf("%w: no authorization for blob host %s", ErrRequestNotAllowed, origin)
		}
		return nil
	}
	return fmt.Errorf("%w: origin %s", ErrRequestNotAllowed, origin)
}

// allowedAPIPath reports whether path is /v2/<approved repo>/manifests/<d>
// or /v2/<approved repo>/blobs/<d> with a valid digest d.
func (p *Puller) allowedAPIPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/v2/")
	if !ok {
		return false
	}
	for _, kind := range []string{"/manifests/", "/blobs/"} {
		i := strings.LastIndex(rest, kind)
		if i <= 0 {
			continue
		}
		if slices.Contains(p.reg.Repositories, rest[:i]) {
			if _, err := parseDigest(rest[i+len(kind):]); err == nil {
				return true
			}
		}
	}
	return false
}

// checkRedirect lets only blob requests redirect, to the registry origin or
// a configured blob host, and strips Authorization when leaving the
// registry origin.
func (p *Puller) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || len(via) > MaxRedirects {
		return fmt.Errorf("%w: more than %d redirects", ErrRedirectNotAllowed, MaxRedirects)
	}
	first := via[0]
	if originOf(first.URL) != p.registry || !strings.Contains(first.URL.Path, "/blobs/") {
		return fmt.Errorf("%w: only blob requests may redirect", ErrRedirectNotAllowed)
	}
	target := originOf(req.URL)
	if req.URL.Scheme != "https" || req.URL.User != nil {
		return fmt.Errorf("%w: redirect to a non-HTTPS URL", ErrRedirectNotAllowed)
	}
	if target != p.registry {
		if !slices.Contains(p.blobHosts, target) {
			return fmt.Errorf("%w: %s is not an approved blob host", ErrRedirectNotAllowed, target)
		}
		req.Header.Del("Authorization")
	}
	return nil
}

// dialContext refuses loopback, link-local and unspecified addresses and,
// unless the registry is approved for them, private addresses.
func (p *Puller) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("registrypull: dial: %w", err)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("registrypull: resolve %s: %w", host, err)
	}
	var dialer net.Dialer
	lastErr := fmt.Errorf("registrypull: no addresses for %s", host)
	for _, ipa := range ips {
		ip := ipa.IP
		if (ip.IsLoopback() && !p.allowLoopback) || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
			ip.IsMulticast() || (ip.IsPrivate() && !p.reg.AllowPrivateNetwork) {
			return nil, fmt.Errorf("registrypull: %s: %w", host, ErrPrivateAddress)
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// cleanErr removes the request URL from a client error. A blob host URL may
// carry a signed query; only the wrapped cause is kept.
func cleanErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// session is the auth state of one pull. The bearer token never leaves it.
type session struct {
	p     *Puller
	repo  string
	basic string // "Basic ..." value; never logged or returned
	token string // bearer token of this pull; never logged or returned
}

// clear drops the session's secrets.
func (s *session) clear() {
	s.basic, s.token = "", ""
}

// basicAuth builds the Basic Authorization value of cred.
func basicAuth(username string, secret []byte) string {
	buf := make([]byte, 0, len(username)+1+len(secret))
	buf = append(buf, username...)
	buf = append(buf, ':')
	buf = append(buf, secret...)
	out := "Basic " + base64.StdEncoding.EncodeToString(buf)
	clear(buf)
	return out
}

// get performs one authenticated GET of /v2/<repo>/<kind>/<digest> and
// returns a 200 response. what names the object in errors.
func (s *session) get(ctx context.Context, kind, digest, accept, what string) (*http.Response, error) {
	u := s.p.registry + "/v2/" + s.repo + "/" + kind + "/" + digest
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("registrypull: %s: %w", what, err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		switch {
		case s.p.reg.Mode == registryAuthBasic:
			req.Header.Set("Authorization", s.basic)
		case s.token != "":
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := s.p.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("registrypull: fetch %s: %w", what, cleanErr(err))
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return resp, nil
		case http.StatusUnauthorized:
			challenge := resp.Header.Get("WWW-Authenticate")
			drain(resp)
			// One token exchange per request: the first one of the pull, or
			// a refresh when a long pull outlived the token. A second 401
			// for the same request is final.
			if s.p.reg.Mode != registryAuthToken || attempt > 0 {
				return nil, fmt.Errorf("%w: %s: status 401", ErrCredentialRejected, what)
			}
			if err := s.p.checkChallenge(challenge); err != nil {
				return nil, fmt.Errorf("registrypull: %s: %w", what, err)
			}
			s.token = ""
			if err := s.fetchToken(ctx); err != nil {
				return nil, err
			}
			continue
		case http.StatusForbidden:
			drain(resp)
			return nil, fmt.Errorf("%w: %s: status 403", ErrCredentialRejected, what)
		case http.StatusNotFound:
			drain(resp)
			return nil, fmt.Errorf("%w: %s", ErrNotFound, what)
		case http.StatusTooManyRequests:
			drain(resp)
			return nil, fmt.Errorf("%w: %s", ErrRateLimited, what)
		default:
			drain(resp)
			return nil, fmt.Errorf("%w: %s: unexpected status %d", ErrBadResponse, what, resp.StatusCode)
		}
	}
	return nil, fmt.Errorf("%w: %s: still unauthorized after token exchange", ErrCredentialRejected, what)
}

// drain closes a response body after discarding a bounded remainder so the
// connection can be reused.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}

// fetchToken exchanges the Basic credential at the approved realm for a
// pull-scoped bearer token of s.repo.
func (s *session) fetchToken(ctx context.Context) error {
	q := url.Values{}
	q.Set("scope", "repository:"+s.repo+":pull")
	if s.p.reg.Service != "" {
		q.Set("service", s.p.reg.Service)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.p.realm.String()+"?"+q.Encode(), nil)
	if err != nil {
		return fmt.Errorf("registrypull: token request: %w", err)
	}
	req.Header.Set("Authorization", s.basic)
	resp, err := s.p.http.Do(req)
	if err != nil {
		return fmt.Errorf("registrypull: token request: %w", cleanErr(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: the token realm refused the credential (status %d)", ErrCredentialRejected, resp.StatusCode)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: token realm", ErrRateLimited)
	default:
		return fmt.Errorf("%w: token realm: unexpected status %d", ErrBadResponse, resp.StatusCode)
	}
	if resp.ContentLength > MaxTokenResponseBytes {
		return fmt.Errorf("%w: token response", ErrTooLarge)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenResponseBytes+1))
	if err != nil {
		return fmt.Errorf("registrypull: token response: %w", err)
	}
	if len(body) > MaxTokenResponseBytes {
		return fmt.Errorf("%w: token response", ErrTooLarge)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return fmt.Errorf("%w: token response is not JSON", ErrBadResponse)
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if tok == "" || len(tok) > MaxTokenLen || !tokenChars(tok) {
		return fmt.Errorf("%w: token response has no usable token", ErrBadResponse)
	}
	s.token = tok
	return nil
}

// tokenChars reports whether tok is visible ASCII without spaces.
func tokenChars(tok string) bool {
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] > '~' {
			return false
		}
	}
	return true
}

// checkChallenge requires a Bearer challenge naming exactly the approved
// realm and, when it names one, the approved service. A challenge never
// selects where the credential goes.
func (p *Puller) checkChallenge(h string) error {
	if len(h) > MaxChallengeLen {
		return fmt.Errorf("%w: challenge too long", ErrRealmNotApproved)
	}
	scheme, params, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return fmt.Errorf("%w: not a bearer challenge", ErrRealmNotApproved)
	}
	attrs, err := parseChallengeParams(params)
	if err != nil {
		return err
	}
	if attrs["realm"] != p.realm.String() {
		return fmt.Errorf("%w: realm differs from the approved realm", ErrRealmNotApproved)
	}
	if svc, ok := attrs["service"]; ok && svc != p.reg.Service {
		return fmt.Errorf("%w: service differs from the approved service", ErrRealmNotApproved)
	}
	return nil
}

// parseChallengeParams parses comma-separated key="value" pairs (RFC 7235
// auth-params, quoted values without escapes). Duplicate keys are refused.
func parseChallengeParams(s string) (map[string]string, error) {
	out := map[string]string{}
	bad := fmt.Errorf("%w: malformed challenge", ErrRealmNotApproved)
	s = strings.TrimSpace(s)
	for s != "" {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return nil, bad
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		s = strings.TrimSpace(s[eq+1:])
		var val string
		if strings.HasPrefix(s, `"`) {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				return nil, bad
			}
			val, s = s[1:1+end], s[2+end:]
		} else {
			end := strings.IndexByte(s, ',')
			if end < 0 {
				end = len(s)
			}
			val, s = strings.TrimSpace(s[:end]), s[end:]
		}
		if _, dup := out[key]; dup || key == "" || strings.ContainsAny(val, "\\") {
			return nil, bad
		}
		out[key] = val
		s = strings.TrimSpace(s)
		if s == "" {
			break
		}
		if s[0] != ',' {
			return nil, bad
		}
		s = strings.TrimSpace(s[1:])
	}
	return out, nil
}
