// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by the registry metadata client.
var (
	// ErrOriginNotAllowed: the registry or redirect origin is not in the
	// approved allowlist.
	ErrOriginNotAllowed = errors.New("registrymeta: origin is not in the approved allowlist")
	// ErrPrivateAddress: the target resolved to a private, loopback or
	// link-local address (SSRF protection).
	ErrPrivateAddress = errors.New("registrymeta: private, loopback or link-local address")
	// ErrRedirectNotAllowed: a redirect or pagination link points to a
	// non-allowlisted origin or leaves the tags/list path.
	ErrRedirectNotAllowed = errors.New("registrymeta: redirect or pagination link to a non-allowlisted origin")
	// ErrResponseTooLarge: a response body exceeds MaxResponseBytes.
	ErrResponseTooLarge = errors.New("registrymeta: response exceeds the size limit")
	// ErrRateLimited: the registry answered 429 or is inside a backoff
	// pause.
	ErrRateLimited = errors.New("registrymeta: registry rate limit")
	// ErrNotFound: the registry reports the tag or digest as missing.
	ErrNotFound = errors.New("registrymeta: tag or digest not found")
	// ErrBadRef: an image reference or repository is invalid.
	ErrBadRef = errors.New("registrymeta: invalid image reference")
	// ErrBadResponse: a registry response is malformed or out of schema.
	ErrBadResponse = errors.New("registrymeta: malformed registry response")
)

// manifestMediaTypes are the manifest and index media types accepted for a
// manifest HEAD.
var manifestMediaTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

var (
	repoRe   = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	digestRe = regexp.MustCompile(`^[a-z0-9]+:[0-9a-f]{64,128}$`)
)

// Origin is one approved registry origin pair (ADR 0006: "administrator-
// approved HTTPS registry/auth origins"). Origins are compared exactly.
type Origin struct {
	// Registry is the exact origin of the distribution API, for example
	// "https://registry-1.docker.io".
	Registry string
	// Auth is the exact origin of the anonymous token endpoint, for example
	// "https://auth.docker.io".
	Auth string
	// AuthPath is the token endpoint path, for example "/token" (Docker
	// Hub, ghcr.io) or "/v2/auth" (quay.io). Empty means "/token".
	AuthPath string
	// Service, when non-empty, is sent as the "service" query parameter to
	// the token endpoint.
	Service string
	// DefaultNamespace, when non-empty, is prefixed to repositories without
	// a path segment (Docker Hub's "library").
	DefaultNamespace string
}

// Ref is an image reference for metadata lookup. The Registry must be an
// exact allowlist origin.
type Ref struct {
	// Registry is the exact allowlist origin, for example
	// "https://registry-1.docker.io".
	Registry string
	// Repository is the repository path, for example "library/nginx".
	Repository string
	// Tag is the tag name; empty when Digest is set.
	Tag string
	// Digest is a digest pin, for example "sha256:..."; empty when Tag is
	// set.
	Digest string
}

// ParseRef parses an image reference of the form
// "[http(s)://]host/repository[:tag|@digest]". The scheme defaults to
// https. The reference is validated; the registry is not checked against an
// allowlist here (the client does that).
func ParseRef(image string) (Ref, error) {
	if image == "" || len(image) > MaxImageLen {
		return Ref{}, fmt.Errorf("%w: empty or too long", ErrBadRef)
	}
	s := image
	scheme := "https://"
	if i := strings.Index(s, "://"); i > 0 {
		sc := s[:i]
		if sc != "http" && sc != "https" {
			return Ref{}, fmt.Errorf("%w: unsupported scheme %q", ErrBadRef, sc)
		}
		scheme = sc + "://"
		s = s[i+3:]
	}
	slash := strings.Index(s, "/")
	if slash <= 0 {
		return Ref{}, fmt.Errorf("%w: missing registry or repository", ErrBadRef)
	}
	host := s[:slash]
	rest := s[slash+1:]
	if host == "" || strings.ContainsAny(host, "/\\") {
		return Ref{}, fmt.Errorf("%w: invalid registry host %q", ErrBadRef, host)
	}
	ref := Ref{Registry: scheme + host}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		ref.Digest = rest[i+1:]
		rest = rest[:i]
		if !digestRe.MatchString(ref.Digest) {
			return Ref{}, fmt.Errorf("%w: invalid digest %q", ErrBadRef, ref.Digest)
		}
	} else if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		ref.Tag = rest[i+1:]
		rest = rest[:i]
		if len(ref.Tag) > MaxTagLen || !tagRe.MatchString(ref.Tag) {
			return Ref{}, fmt.Errorf("%w: invalid tag %q", ErrBadRef, ref.Tag)
		}
	}
	ref.Repository = rest
	if ref.Repository == "" {
		return Ref{}, fmt.Errorf("%w: missing repository", ErrBadRef)
	}
	if err := validateRepo(ref.Repository); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

func validateRepo(repo string) error {
	if len(repo) > MaxRepoLen {
		return fmt.Errorf("%w: repository too long", ErrBadRef)
	}
	if !repoRe.MatchString(repo) {
		return fmt.Errorf("%w: invalid repository %q", ErrBadRef, repo)
	}
	return nil
}

// Options configures NewClient.
type Options struct {
	// Origins is the administrator-approved allowlist. Required, non-empty.
	Origins []Origin
	// Now is the clock for cache TTLs, rate limiting and backoff. Default:
	// time.Now.
	Now func() time.Time
	// Sleep waits while the rate limiter waits. Default: a context-aware
	// sleep.
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter returns the random component added to a 429 backoff pause.
	// Default: uniform in [0, 1 min).
	Jitter func() time.Duration
	// AllowLoopback permits dials to loopback, private and link-local
	// addresses. Test-only escape hatch for httptest servers; production
	// must leave it false.
	AllowLoopback bool
	// Cache, when non-nil, stores results and failures. Default: a new
	// Cache.
	Cache *Cache
}

// Client performs anonymous public registry metadata lookups (tag lists and
// manifest digests) against an approved-origin allowlist. It never pulls
// image layers.
type Client struct {
	origins   []Origin
	byOrigin  map[string]Origin
	authOK    map[string]bool
	http      *http.Client
	cache     *Cache
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error
	jitter    func() time.Duration
	allowLoop bool

	mu       sync.Mutex
	regs     map[string]*regState
	inflight map[string]*call
}

// NewClient creates a Client. It fails closed on an empty or invalid
// allowlist.
func NewClient(o Options) (*Client, error) {
	if len(o.Origins) == 0 {
		return nil, fmt.Errorf("%w: the allowlist is empty", ErrOriginNotAllowed)
	}
	by := make(map[string]Origin, len(o.Origins))
	authOK := make(map[string]bool, len(o.Origins))
	for _, og := range o.Origins {
		if _, err := parseOrigin(og.Registry); err != nil {
			return nil, err
		}
		if _, err := parseOrigin(og.Auth); err != nil {
			return nil, err
		}
		if og.AuthPath == "" {
			og.AuthPath = "/token"
		}
		if !strings.HasPrefix(og.AuthPath, "/") {
			return nil, fmt.Errorf("%w: auth path %q must start with /", ErrOriginNotAllowed, og.AuthPath)
		}
		if _, dup := by[og.Registry]; dup {
			return nil, fmt.Errorf("%w: duplicate registry origin %q", ErrOriginNotAllowed, og.Registry)
		}
		by[og.Registry] = og
		authOK[og.Auth] = true
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	jitter := o.Jitter
	if jitter == nil {
		jitter = func() time.Duration { return rand.N[time.Duration](time.Minute) }
	}
	cache := o.Cache
	if cache == nil {
		cache = NewCache(now)
	}
	c := &Client{
		origins:   o.Origins,
		byOrigin:  by,
		authOK:    authOK,
		cache:     cache,
		now:       now,
		sleep:     sleep,
		jitter:    jitter,
		allowLoop: o.AllowLoopback,
		regs:      map[string]*regState{},
		inflight:  map[string]*call{},
	}
	c.http = &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return c.checkRedirect(req, via)
		},
		Transport: &http.Transport{
			Proxy:               nil, // no proxies (ADR 0006)
			DialContext:         c.dialContext,
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: MaxConcurrentPerRegistry,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	return c, nil
}

func parseOrigin(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: %q", ErrOriginNotAllowed, s)
	}
	return u, nil
}

// checkRedirect allows redirects only to allowlisted registry or auth
// origins, at most MaxRedirects times (ADR 0006: "no redirects/proxies";
// challenges and links cannot select arbitrary origins).
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return fmt.Errorf("%w: more than %d redirects", ErrRedirectNotAllowed, MaxRedirects)
	}
	o := originOf(req.URL)
	if _, ok := c.byOrigin[o]; ok {
		return nil
	}
	if c.authOK[o] {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrRedirectNotAllowed, o)
}

// dialContext resolves the target host and refuses to dial private,
// loopback or link-local addresses (SSRF protection). The connection is made
// to a resolved IP; TLS verification still applies to the original host
// name.
func (c *Client) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("registrymeta: resolve %s: %w", host, err)
	}
	var dialer net.Dialer
	var lastErr error
	for _, ipa := range ips {
		ip := ipa.IP
		if !c.allowLoop && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return nil, fmt.Errorf("registrymeta: %s: %w", host, ErrPrivateAddress)
		}
		var conn net.Conn
		conn, lastErr = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if lastErr == nil {
			return conn, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("registrymeta: no addresses for %s", host)
	}
	return nil, lastErr
}

// regState is the per-registry budget and backoff state.
type regState struct {
	last       time.Time // start time of the last request
	inflight   int       // in-flight requests
	pauseUntil time.Time // 429 backoff deadline
	backoffExp int       // consecutive 429 backoff exponent
}

// call is one in-flight coalesced lookup.
type call struct {
	done chan struct{}
}

func (c *Client) regLocked(reg string) *regState {
	st, ok := c.regs[reg]
	if !ok {
		st = &regState{}
		c.regs[reg] = st
	}
	return st
}

// acquire waits until the per-registry budget allows a new request start
// (one per second, two concurrent, ADR 0006) and registers it. It fails
// fast with ErrRateLimited while the registry is in a 429 backoff pause.
func (c *Client) acquire(ctx context.Context, reg string) error {
	for {
		c.mu.Lock()
		st := c.regLocked(reg)
		now := c.now()
		if now.Before(st.pauseUntil) {
			remaining := st.pauseUntil.Sub(now)
			c.mu.Unlock()
			return fmt.Errorf("%w: %s is paused for %s", ErrRateLimited, reg, remaining)
		}
		if st.inflight < MaxConcurrentPerRegistry && (st.last.IsZero() || !now.Before(st.last.Add(MinRequestInterval))) {
			st.inflight++
			st.last = now
			c.mu.Unlock()
			return nil
		}
		var wait time.Duration
		if st.inflight >= MaxConcurrentPerRegistry {
			wait = acquirePollInterval
		} else {
			wait = st.last.Add(MinRequestInterval).Sub(now)
			if wait < 0 {
				wait = 0
			}
		}
		c.mu.Unlock()
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// release unregisters an in-flight request.
func (c *Client) release(reg string) {
	c.mu.Lock()
	st := c.regLocked(reg)
	if st.inflight > 0 {
		st.inflight--
	}
	c.mu.Unlock()
}

// noteSuccess resets the 429 backoff exponent after a successful request.
func (c *Client) noteSuccess(reg string) {
	c.mu.Lock()
	st := c.regLocked(reg)
	st.backoffExp = 0
	c.mu.Unlock()
}

// noteRateLimit records a 429 and computes the next pause: exponential
// backoff from MinRateLimitPause, at least retryAfter when supplied, plus
// jitter (ADR 0006).
func (c *Client) noteRateLimit(reg string, retryAfter time.Duration) {
	c.mu.Lock()
	st := c.regLocked(reg)
	exp := st.backoffExp + 1
	if exp > maxBackoffShifts {
		exp = maxBackoffShifts
	}
	st.backoffExp = exp
	pause := MinRateLimitPause << (exp - 1)
	if pause > MaxBackoff {
		pause = MaxBackoff
	}
	if retryAfter > pause {
		pause = retryAfter
	}
	pause += c.jitter()
	st.pauseUntil = c.now().Add(pause)
	c.mu.Unlock()
}

// retryAfter parses a Retry-After header (delta-seconds or HTTP-date)
// against the injected clock.
func (c *Client) retryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if sec, err := strconv.Atoi(h); err == nil && sec >= 0 {
		return time.Duration(sec) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(c.now()); d > 0 {
			return d
		}
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
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

func originOf(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// readBounded reads at most MaxResponseBytes+1 bytes and rejects larger
// responses.
func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrResponseTooLarge, MaxResponseBytes)
	}
	return b, nil
}

// do issues one HTTP request with an optional bearer token.
func (c *Client) do(ctx context.Context, method, u, token string, hdrs map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.http.Do(req)
}

// fetchToken obtains an anonymous pull-scope token from the origin's token
// endpoint (Docker Hub, ghcr.io and quay.io all speak the OCI distribution
// auth flow).
func (c *Client) fetchToken(ctx context.Context, ref Ref, repo string) (string, error) {
	og := c.byOrigin[ref.Registry]
	q := url.Values{}
	q.Set("scope", "repository:"+repo+":pull")
	if og.Service != "" {
		q.Set("service", og.Service)
	}
	tu := og.Auth + og.AuthPath + "?" + q.Encode()
	if err := c.acquire(ctx, ref.Registry); err != nil {
		return "", err
	}
	defer c.release(ref.Registry)
	resp, err := c.do(ctx, http.MethodGet, tu, "", nil)
	if err != nil {
		return "", fmt.Errorf("registrymeta: token for %s: %w", repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		c.noteRateLimit(ref.Registry, c.retryAfter(resp.Header.Get("Retry-After")))
		return "", fmt.Errorf("%w: %s", ErrRateLimited, ref.Registry)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registrymeta: token endpoint for %s: unexpected status %d", repo, resp.StatusCode)
	}
	body, err := readBounded(resp.Body)
	if err != nil {
		return "", err
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return "", fmt.Errorf("registrymeta: token response for %s: %w", repo, ErrBadResponse)
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if tok == "" || len(tok) > MaxTokenLen {
		return "", fmt.Errorf("registrymeta: token for %s: %w", repo, ErrBadResponse)
	}
	return tok, nil
}

// doWithToken performs one registry API request, transparently fetching an
// anonymous token on 401 and applying the 429 backoff policy. The caller
// owns the returned response body.
func (c *Client) doWithToken(ctx context.Context, ref Ref, repo, method, u string, hdrs map[string]string) (*http.Response, error) {
	token := ""
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.acquire(ctx, ref.Registry); err != nil {
			return nil, err
		}
		resp, err := c.do(ctx, method, u, token, hdrs)
		c.release(ref.Registry)
		if err != nil {
			return nil, fmt.Errorf("registrymeta: %s %s: %w", method, u, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			c.noteRateLimit(ref.Registry, c.retryAfter(resp.Header.Get("Retry-After")))
			resp.Body.Close()
			return nil, fmt.Errorf("%w: %s", ErrRateLimited, ref.Registry)
		}
		if resp.StatusCode == http.StatusUnauthorized && token == "" {
			resp.Body.Close()
			t, terr := c.fetchToken(ctx, ref, repo)
			if terr != nil {
				return nil, terr
			}
			token = t
			continue
		}
		if resp.StatusCode < 300 {
			c.noteSuccess(ref.Registry)
		}
		return resp, nil
	}
	return nil, fmt.Errorf("registrymeta: %s: %w", u, ErrBadResponse)
}

// TagsResult is the outcome of ListTags.
type TagsResult struct {
	// Tags is the collected tag list, at most MaxTagsPerScan entries.
	Tags []string
	// Incomplete is true when the page or tag budget was exhausted before
	// the registry finished listing; such a list must be treated as
	// unknown, never "up to date" (ADR 0006).
	Incomplete bool
	// FromCache is true when the result came from the TTL cache.
	FromCache bool
}

// DigestResult is the outcome of TagDigest.
type DigestResult struct {
	// Digest is the manifest digest, for example "sha256:...".
	Digest string
	// FromCache is true when the result came from the TTL cache.
	FromCache bool
}

// ListTags returns the tag list of ref.Repository. It coalesces in-flight
// lookups and caches results (TTLTagList) and failures (TTLFailure).
func (c *Client) ListTags(ctx context.Context, ref Ref) (TagsResult, error) {
	repo, err := c.checkRef(ref)
	if err != nil {
		return TagsResult{}, err
	}
	ref.Repository = repo
	key := "tags|" + ref.Registry + "|" + repo
	if v, ok := c.cache.Get(key); ok {
		r := v.(TagsResult)
		r.FromCache = true
		return r, nil
	}
	if e, ok := c.cache.Get(key + "|err"); ok {
		return TagsResult{}, e.(error)
	}
	cl, shared := c.begin(key)
	if shared {
		<-cl.done
		return c.cachedTags(key)
	}
	res, err := c.fetchTags(ctx, ref, repo)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			c.cache.Set(key+"|err", err, TTLFailure)
		}
	} else {
		c.cache.Set(key, res, TTLTagList)
	}
	c.finish(key, cl)
	return res, err
}

func (c *Client) cachedTags(key string) (TagsResult, error) {
	if v, ok := c.cache.Get(key); ok {
		r := v.(TagsResult)
		r.FromCache = true
		return r, nil
	}
	if e, ok := c.cache.Get(key + "|err"); ok {
		return TagsResult{}, e.(error)
	}
	return TagsResult{}, fmt.Errorf("registrymeta: coalesced tag lookup finished without a result")
}

// TagDigest returns the manifest digest behind ref's tag, or the digest of
// the pinned digest, using a manifest HEAD. It never pulls the manifest
// body or any layer (ADR 0006). Tag results are cached for TTLSameTag,
// digest-pinned metadata for TTLDigest.
func (c *Client) TagDigest(ctx context.Context, ref Ref) (DigestResult, error) {
	repo, err := c.checkRef(ref)
	if err != nil {
		return DigestResult{}, err
	}
	ref.Repository = repo
	name := ref.Tag
	if ref.Digest != "" {
		name = ref.Digest
	}
	if name == "" {
		return DigestResult{}, fmt.Errorf("%w: a tag or digest is required", ErrBadRef)
	}
	key := "digest|" + ref.Registry + "|" + repo + "|" + name
	ttl := TTLSameTag
	if ref.Digest != "" {
		ttl = TTLDigest
	}
	if v, ok := c.cache.Get(key); ok {
		r := v.(DigestResult)
		r.FromCache = true
		return r, nil
	}
	if e, ok := c.cache.Get(key + "|err"); ok {
		return DigestResult{}, e.(error)
	}
	cl, shared := c.begin(key)
	if shared {
		<-cl.done
		return c.cachedDigest(key)
	}
	res, err := c.fetchDigest(ctx, ref, repo)
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			c.cache.Set(key+"|err", err, TTLFailure)
		}
	} else {
		c.cache.Set(key, res, ttl)
	}
	c.finish(key, cl)
	return res, err
}

func (c *Client) cachedDigest(key string) (DigestResult, error) {
	if v, ok := c.cache.Get(key); ok {
		r := v.(DigestResult)
		r.FromCache = true
		return r, nil
	}
	if e, ok := c.cache.Get(key + "|err"); ok {
		return DigestResult{}, e.(error)
	}
	return DigestResult{}, fmt.Errorf("registrymeta: coalesced digest lookup finished without a result")
}

// begin registers or joins an in-flight lookup for key.
func (c *Client) begin(key string) (*call, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.inflight[key]; ok {
		return cl, true
	}
	cl := &call{done: make(chan struct{})}
	c.inflight[key] = cl
	return cl, false
}

// finish removes the in-flight entry and wakes coalesced waiters.
func (c *Client) finish(key string, cl *call) {
	c.mu.Lock()
	delete(c.inflight, key)
	c.mu.Unlock()
	close(cl.done)
}

// checkRef validates the ref against the allowlist and normalizes the
// repository (default namespace), returning the wire repository.
func (c *Client) checkRef(ref Ref) (string, error) {
	og, ok := c.byOrigin[ref.Registry]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrOriginNotAllowed, ref.Registry)
	}
	repo := ref.Repository
	if og.DefaultNamespace != "" && !strings.Contains(repo, "/") {
		repo = og.DefaultNamespace + "/" + repo
	}
	if err := validateRepo(repo); err != nil {
		return "", err
	}
	return repo, nil
}

// fetchTags lists the tags of a repository, following Link pagination
// within the page and tag budgets.
func (c *Client) fetchTags(ctx context.Context, ref Ref, repo string) (TagsResult, error) {
	listPath := "/v2/" + repo + "/tags/list"
	urlStr := ref.Registry + listPath
	var (
		tags       []string
		incomplete bool
	)
	for i := 0; ; i++ {
		if i >= MaxPages {
			incomplete = true
			break
		}
		resp, err := c.doWithToken(ctx, ref, repo, http.MethodGet, urlStr, map[string]string{
			"Accept": "application/json",
		})
		if err != nil {
			return TagsResult{}, err
		}
		body, rerr := readBounded(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			return TagsResult{}, rerr
		}
		if resp.StatusCode != http.StatusOK {
			return TagsResult{}, fmt.Errorf("registrymeta: tag list for %s: unexpected status %d", repo, resp.StatusCode)
		}
		var pageData struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &pageData); err != nil {
			return TagsResult{}, fmt.Errorf("registrymeta: tag list for %s: %w", repo, ErrBadResponse)
		}
		for _, t := range pageData.Tags {
			if len(t) == 0 || len(t) > MaxTagLen || strings.ContainsAny(t, "/\\@") {
				return TagsResult{}, fmt.Errorf("registrymeta: tag list for %s: %w", repo, ErrBadResponse)
			}
			tags = append(tags, t)
			if len(tags) > MaxTagsPerScan {
				incomplete = true
				break
			}
		}
		if incomplete {
			break
		}
		next, ok := parseLinkNext(resp.Header.Get("Link"))
		if !ok {
			break
		}
		nextURL, err := c.resolveLink(ref.Registry, listPath, next)
		if err != nil {
			return TagsResult{}, err
		}
		urlStr = nextURL
	}
	if len(tags) > MaxTagsPerScan {
		tags = tags[:MaxTagsPerScan]
	}
	return TagsResult{Tags: tags, Incomplete: incomplete}, nil
}

// fetchDigest resolves the digest of a tag or digest pin with a manifest
// HEAD.
func (c *Client) fetchDigest(ctx context.Context, ref Ref, repo string) (DigestResult, error) {
	name := ref.Tag
	if ref.Digest != "" {
		name = ref.Digest
	}
	u := ref.Registry + "/v2/" + repo + "/manifests/" + name
	resp, err := c.doWithToken(ctx, ref, repo, http.MethodHead, u, map[string]string{
		"Accept": strings.Join(manifestMediaTypes, ", "),
	})
	if err != nil {
		return DigestResult{}, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return DigestResult{}, fmt.Errorf("%w: %s %s", ErrNotFound, repo, name)
	}
	if resp.StatusCode != http.StatusOK {
		return DigestResult{}, fmt.Errorf("registrymeta: manifest %s %s: unexpected status %d", repo, name, resp.StatusCode)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if !digestRe.MatchString(d) {
		return DigestResult{}, fmt.Errorf("registrymeta: manifest %s %s: %w", repo, name, ErrBadResponse)
	}
	return DigestResult{Digest: d}, nil
}

// resolveLink validates a pagination Link target: it must stay on the
// allowlisted registry origin and on the tags/list path (ADR 0006:
// pagination links cannot select arbitrary origins or private addresses).
func (c *Client) resolveLink(registry, listPath, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrRedirectNotAllowed, raw)
	}
	if !u.IsAbs() {
		base, err := url.Parse(registry)
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrRedirectNotAllowed, raw)
		}
		u.Scheme = base.Scheme
		u.Host = base.Host
	}
	if originOf(u) != registry {
		return "", fmt.Errorf("%w: %q", ErrRedirectNotAllowed, raw)
	}
	if u.Path != listPath {
		return "", fmt.Errorf("%w: %q", ErrRedirectNotAllowed, raw)
	}
	return u.String(), nil
}

// parseLinkNext extracts the rel="next" target from an RFC 5988 Link
// header.
func parseLinkNext(h string) (string, bool) {
	for _, part := range strings.Split(h, ",") {
		i := strings.Index(part, "<")
		if i < 0 {
			continue
		}
		j := strings.Index(part[i:], ">")
		if j < 0 {
			continue
		}
		j += i
		href := part[i+1 : j]
		if linkHasRel(part[j+1:], "next") {
			return href, true
		}
	}
	return "", false
}

func linkHasRel(params string, rel string) bool {
	for _, p := range strings.Split(params, ";") {
		p = strings.TrimSpace(p)
		eq := strings.Index(p, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(p[:eq]))
		val := strings.Trim(strings.TrimSpace(p[eq+1:]), `"`)
		if key == "rel" && strings.EqualFold(val, rel) {
			return true
		}
	}
	return false
}
