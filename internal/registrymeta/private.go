// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// This file holds the credentialed private registry metadata client (ADR
// 0006, ticket P1-32). It is meant for the executor only: the executor
// opens the credential from its vault for one read and passes it in; the
// client never stores it. Private reads add these rules on top of the
// public client's limits:
//
//   - the registry origin and, for token auth, the exact token realm URL
//     are administrator-approved; a WWW-Authenticate challenge that names
//     another realm or service is refused before any credential is sent;
//   - the credential goes only to the approved realm (token auth) or to the
//     registry origin (basic auth), never along a redirect: credentialed
//     requests follow no redirects at all;
//   - only manifest HEADs, tag list GETs and the token GET leave the
//     client, so no manifest body, config or layer is ever fetched;
//   - repositories are limited to an exact approved list;
//   - HTTPS is required even where tests allow loopback, and private
//     network addresses are dialled only for a registry approved for them.

// Sentinel errors of the private client.
var (
	// ErrCredentialRejected: the registry or token realm refused the
	// credential, or a private client was used without one.
	ErrCredentialRejected = errors.New("registrymeta: registry credential rejected or missing")
	// ErrRealmNotApproved: an authentication challenge names a realm or
	// service other than the approved one.
	ErrRealmNotApproved = errors.New("registrymeta: authentication challenge names an unapproved realm")
	// ErrOutOfScope: the repository is not in the approved repository scope.
	ErrOutOfScope = errors.New("registrymeta: repository is outside the approved scope")
	// ErrRequestNotAllowed: a request other than a manifest HEAD, tag list
	// GET or token GET was attempted by a private client.
	ErrRequestNotAllowed = errors.New("registrymeta: request type is not allowed for a private registry")
)

var errPrivateNeedsCredential = fmt.Errorf("%w: a private registry client needs a credential", ErrCredentialRejected)

// Private registry limits.
const (
	// MaxPrivateRepositories bounds the approved repository scope of one
	// private registry.
	MaxPrivateRepositories = 64
	// MaxUsernameLen bounds a credential user name.
	MaxUsernameLen = 255
	// MaxSecretLen bounds a credential password or personal access token.
	MaxSecretLen = 4096
	// MaxServiceLen bounds the token service parameter.
	MaxServiceLen = 255
	// MaxRealmLen bounds the approved token realm URL.
	MaxRealmLen = 512
	// MaxChallengeLen bounds a parsed WWW-Authenticate header.
	MaxChallengeLen = 4096
	// MaxCacheScopeLen bounds the caller's cache scope key.
	MaxCacheScopeLen = 256
)

// AuthMode is how a private registry authenticates.
type AuthMode string

// Supported auth modes. Anything else (credential helpers, OAuth refresh
// flows) is unsupported and stays unavailable (ADR 0006 open questions).
const (
	// AuthBasic sends HTTP Basic credentials to the registry origin.
	AuthBasic AuthMode = "basic"
	// AuthToken exchanges Basic credentials at the approved token realm for
	// a pull-scoped bearer token (OCI distribution token auth).
	AuthToken AuthMode = "token"
)

// PrivateRegistry is the administrator-approved description of one private
// registry. Every member is exact; nothing is derived from a host or a
// registry response.
type PrivateRegistry struct {
	// Registry is the exact HTTPS origin of the distribution API.
	Registry string
	// Mode is the auth mode.
	Mode AuthMode
	// Realm is the exact HTTPS token realm URL (origin and path) for
	// AuthToken; empty for AuthBasic.
	Realm string
	// Service is the exact token service parameter; it must equal the
	// challenge's service when the challenge names one.
	Service string
	// Repositories is the exact approved repository scope.
	Repositories []string
	// AllowPrivateNetwork permits dialling RFC 1918/ULA addresses for this
	// registry (ADR 0006: explicit executor-side allowlist). Loopback and
	// link-local addresses stay refused.
	AllowPrivateNetwork bool
}

// Validate checks r and returns the parsed realm URL (nil for basic auth).
func (r PrivateRegistry) Validate() (*url.URL, error) {
	u, err := parseOrigin(r.Registry)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.User != nil {
		return nil, fmt.Errorf("%w: a private registry needs an HTTPS origin", ErrOriginNotAllowed)
	}
	var realm *url.URL
	switch r.Mode {
	case AuthBasic:
		if r.Realm != "" || r.Service != "" {
			return nil, fmt.Errorf("%w: basic auth takes no realm or service", ErrRealmNotApproved)
		}
	case AuthToken:
		realm, err = parseRealm(r.Realm)
		if err != nil {
			return nil, err
		}
		if len(r.Service) > MaxServiceLen || !printable(r.Service) {
			return nil, fmt.Errorf("%w: invalid service", ErrRealmNotApproved)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported auth mode", ErrCredentialRejected)
	}
	if len(r.Repositories) == 0 || len(r.Repositories) > MaxPrivateRepositories {
		return nil, fmt.Errorf("%w: 1 to %d repositories", ErrOutOfScope, MaxPrivateRepositories)
	}
	seen := map[string]bool{}
	for _, repo := range r.Repositories {
		if err := validateRepo(repo); err != nil {
			return nil, err
		}
		if seen[repo] {
			return nil, fmt.Errorf("%w: repository listed twice", ErrOutOfScope)
		}
		seen[repo] = true
	}
	return realm, nil
}

// parseRealm accepts an exact HTTPS URL with a path and nothing else.
func parseRealm(s string) (*url.URL, error) {
	if s == "" || len(s) > MaxRealmLen || !printable(s) {
		return nil, fmt.Errorf("%w: invalid realm", ErrRealmNotApproved)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || !strings.HasPrefix(u.Path, "/") || u.String() != s {
		return nil, fmt.Errorf("%w: the realm must be an exact HTTPS URL without query", ErrRealmNotApproved)
	}
	return u, nil
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// Credential is one private registry credential. The executor opens it from
// its vault for a single read; the client never stores, logs or returns it.
type Credential struct {
	// Username is the account name.
	Username string
	// Secret is the password or personal access token.
	Secret []byte
}

// Validate checks the credential's shape without revealing it in errors.
func (c Credential) Validate() error {
	if c.Username == "" || len(c.Username) > MaxUsernameLen || strings.ContainsRune(c.Username, ':') || !printable(c.Username) {
		return fmt.Errorf("%w: invalid user name", ErrCredentialRejected)
	}
	if len(c.Secret) == 0 || len(c.Secret) > MaxSecretLen {
		return fmt.Errorf("%w: invalid secret", ErrCredentialRejected)
	}
	return nil
}

// ValidTag reports whether s is a valid registry tag.
func ValidTag(s string) bool { return len(s) <= MaxTagLen && tagRe.MatchString(s) }

// ValidDigest reports whether s is a valid content digest.
func ValidDigest(s string) bool { return len(s) <= MaxImageLen && digestRe.MatchString(s) }

func (c Credential) basic() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	buf := make([]byte, 0, len(c.Username)+1+len(c.Secret))
	buf = append(buf, c.Username...)
	buf = append(buf, ':')
	buf = append(buf, c.Secret...)
	out := "Basic " + base64.StdEncoding.EncodeToString(buf)
	clear(buf)
	return out, nil
}

// privateConfig is the credential behavior of a private Client.
type privateConfig struct {
	reg          PrivateRegistry
	registry     string // origin
	realm        *url.URL
	allowPrivate bool
}

// allowRequest is the transport-level allowlist of a private client: a
// manifest HEAD or tag list GET of an approved repository on the registry
// origin, or a GET of the exact token realm. Authorization headers may only
// go where the auth mode sends them.
func (p *privateConfig) allowRequest(req *http.Request) error {
	if req.URL.User != nil || req.URL.Fragment != "" {
		return ErrRequestNotAllowed
	}
	authz := req.Header.Get("Authorization")
	origin := originOf(req.URL)
	if p.realm != nil && origin == originOf(p.realm) && req.URL.EscapedPath() == p.realm.EscapedPath() {
		if req.Method != http.MethodGet || (authz != "" && !strings.HasPrefix(authz, "Basic ")) {
			return ErrRequestNotAllowed
		}
		return nil
	}
	if origin != p.registry || req.URL.RawQuery != "" && !strings.HasSuffix(req.URL.Path, "/tags/list") {
		return fmt.Errorf("%w: %s", ErrRequestNotAllowed, origin)
	}
	if strings.HasPrefix(authz, "Basic ") && p.reg.Mode != AuthBasic {
		return ErrRequestNotAllowed
	}
	if authz != "" && !strings.HasPrefix(authz, "Basic ") && !strings.HasPrefix(authz, "Bearer ") {
		return ErrRequestNotAllowed
	}
	path := req.URL.Path
	if !strings.HasPrefix(path, "/v2/") {
		return ErrRequestNotAllowed
	}
	rest := path[len("/v2/"):]
	switch req.Method {
	case http.MethodGet:
		repo, ok := strings.CutSuffix(rest, "/tags/list")
		if ok && slices.Contains(p.reg.Repositories, repo) {
			return nil
		}
	case http.MethodHead:
		i := strings.LastIndex(rest, "/manifests/")
		if i > 0 && slices.Contains(p.reg.Repositories, rest[:i]) && !strings.Contains(rest[i+len("/manifests/"):], "/") {
			return nil
		}
	}
	return ErrRequestNotAllowed
}

// PrivateOptions configures NewPrivateClient.
type PrivateOptions struct {
	// Registry is the approved registry description.
	Registry PrivateRegistry
	// RootCAs, when non-nil, replaces the system roots for TLS verification
	// (an administrator-supplied private CA). TLS is always verified.
	RootCAs *x509.CertPool
	// Now, Sleep, Jitter and Cache are as in Options.
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error
	Jitter func() time.Duration
	Cache  *Cache
	// AllowLoopback permits dialling loopback addresses. Test-only; HTTPS
	// stays required.
	AllowLoopback bool
}

// PrivateClient reads tag lists and manifest digests from one approved
// private registry with a caller-supplied credential. It never pulls
// manifests bodies, configs or layers, and it keeps the public client's
// per-registry budgets, response limits and caches.
type PrivateClient struct {
	c   *Client
	reg PrivateRegistry
}

// NewPrivateClient validates the registry description and returns a client.
func NewPrivateClient(o PrivateOptions) (*PrivateClient, error) {
	realm, err := o.Registry.Validate()
	if err != nil {
		return nil, err
	}
	reg := o.Registry
	reg.Repositories = slices.Clone(reg.Repositories)
	og := Origin{Registry: reg.Registry, Auth: reg.Registry, Service: reg.Service}
	if realm != nil {
		og.Auth, og.AuthPath = originOf(realm), realm.EscapedPath()
	}
	priv := &privateConfig{reg: reg, registry: reg.Registry, realm: realm, allowPrivate: reg.AllowPrivateNetwork}
	c, err := newClient(Options{
		Origins: []Origin{og}, Now: o.Now, Sleep: o.Sleep, Jitter: o.Jitter, Cache: o.Cache,
		AllowLoopback: o.AllowLoopback,
	}, priv, o.RootCAs)
	if err != nil {
		return nil, err
	}
	return &PrivateClient{c: c, reg: reg}, nil
}

// checkScope validates ref against the approved registry and repositories
// and returns the cache key prefix for cacheScope.
func (p *PrivateClient) checkScope(ref Ref, cacheScope string) (string, error) {
	if ref.Registry != p.reg.Registry {
		return "", fmt.Errorf("%w: %s", ErrOriginNotAllowed, ref.Registry)
	}
	if !slices.Contains(p.reg.Repositories, ref.Repository) {
		return "", ErrOutOfScope
	}
	if cacheScope == "" || len(cacheScope) > MaxCacheScopeLen || strings.Contains(cacheScope, "|") || !printable(cacheScope) {
		return "", fmt.Errorf("%w: invalid cache scope", ErrBadRef)
	}
	return "private|" + cacheScope + "|", nil
}

// TagDigest resolves a tag or digest pin with a manifest HEAD using cred.
// cacheScope identifies the credential scope and version (ADR 0006:
// private cache entries also key on them), so a rotated credential never
// reuses another version's results or failures.
func (p *PrivateClient) TagDigest(ctx context.Context, ref Ref, cred Credential, cacheScope string) (DigestResult, error) {
	prefix, err := p.checkScope(ref, cacheScope)
	if err != nil {
		return DigestResult{}, err
	}
	return p.c.tagDigest(ctx, ref, &cred, prefix)
}

// ListTags lists the tags of an approved repository using cred.
func (p *PrivateClient) ListTags(ctx context.Context, ref Ref, cred Credential, cacheScope string) (TagsResult, error) {
	prefix, err := p.checkScope(ref, cacheScope)
	if err != nil {
		return TagsResult{}, err
	}
	return p.c.listTags(ctx, ref, &cred, prefix)
}

// request performs one registry API request: anonymously with the public
// token flow when cred is nil, otherwise with the private auth flow.
func (c *Client) request(ctx context.Context, ref Ref, repo, method, u string, hdrs map[string]string, cred *Credential) (*http.Response, error) {
	if cred == nil {
		return c.doWithToken(ctx, ref, repo, method, u, hdrs)
	}
	if c.priv == nil {
		return nil, fmt.Errorf("%w: the public client takes no credential", ErrCredentialRejected)
	}
	basic, err := cred.basic()
	if err != nil {
		return nil, err
	}
	switch c.priv.reg.Mode {
	case AuthBasic:
		resp, err := c.doAuthz(ctx, method, u, basic, hdrs)
		if err != nil {
			return nil, fmt.Errorf("registrymeta: %s %s: %w", method, u, err)
		}
		return c.checkPrivateStatus(resp)
	case AuthToken:
		resp, err := c.doAuthz(ctx, method, u, "", hdrs)
		if err != nil {
			return nil, fmt.Errorf("registrymeta: %s %s: %w", method, u, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return c.checkPrivateStatus(resp)
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if err := c.priv.checkChallenge(challenge); err != nil {
			return nil, err
		}
		token, err := c.fetchTokenAuth(ctx, ref, repo, basic)
		if err != nil {
			return nil, err
		}
		resp, err = c.do(ctx, method, u, token, hdrs)
		if err != nil {
			return nil, fmt.Errorf("registrymeta: %s %s: %w", method, u, err)
		}
		return c.checkPrivateStatus(resp)
	}
	return nil, fmt.Errorf("%w: unsupported auth mode", ErrCredentialRejected)
}

// checkPrivateStatus maps refusals of a credentialed request.
func (c *Client) checkPrivateStatus(resp *http.Response) (*http.Response, error) {
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: %s", ErrRateLimited, originOf(resp.Request.URL))
	case http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: status %d", ErrCredentialRejected, resp.StatusCode)
	}
	return resp, nil
}

// checkChallenge requires a Bearer challenge whose realm is exactly the
// approved realm and whose service, when named, is the approved service.
// A challenge cannot select where the credential is sent.
func (p *privateConfig) checkChallenge(h string) error {
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
