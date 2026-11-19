// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The tests in this file pin the redirect rules of the ADR 0006 amendment
// "registry metadata redirects" (2026-11-19): at most two redirects, only to
// the same origin (scheme, host and port), only for anonymous requests; never
// across hosts and never for a request carrying an Authorization header or
// token.

// redirectRuleClient returns a client whose allowlist holds every origin in
// origins, so a refusal in checkRedirect cannot be explained by the
// allowlist alone.
func redirectRuleClient(t *testing.T, origins ...string) *Client {
	t.Helper()
	var ogs []Origin
	for _, o := range origins {
		ogs = append(ogs, Origin{Registry: o, Auth: o, AuthPath: "/token"})
	}
	fc := newFakeClock()
	c, err := NewClient(Options{
		Origins: ogs, Now: fc.Now, Sleep: fc.Sleep,
		Jitter: func() time.Duration { return 0 }, AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func mustRequest(t *testing.T, method, u, authz string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	return req
}

// TestCheckRedirectRules exercises every rule of the amendment directly on
// checkRedirect, with all involved origins approved.
func TestCheckRedirectRules(t *testing.T) {
	const (
		reg     = "https://reg.example"
		regHTTP = "http://reg.example"
		regPort = "https://reg.example:8443"
		other   = "https://other.example"
		tags    = "/v2/repo/tags/list"
	)
	c := redirectRuleClient(t, reg, regHTTP, regPort, other)
	get := func(u string) *http.Request { return mustRequest(t, http.MethodGet, u, "") }
	for _, tc := range []struct {
		name  string
		via   []*http.Request
		req   *http.Request
		allow bool
	}{
		{"same origin tags list, first hop", []*http.Request{get(reg + tags)}, get(reg + tags + "?hop=1"), true},
		{"same origin tags list, second hop", []*http.Request{get(reg + tags), get(reg + tags + "?hop=1")}, get(reg + tags + "?hop=2"), true},
		{"same origin manifest HEAD", []*http.Request{mustRequest(t, http.MethodHead, reg+"/v2/repo/manifests/1.0", "")}, mustRequest(t, http.MethodHead, reg+"/v2/repo/manifests/1.0", ""), true},
		{"same origin token endpoint", []*http.Request{get(reg + "/token?scope=x")}, get(reg + "/token?scope=x&n=1"), true},
		{"third redirect", []*http.Request{get(reg + tags), get(reg + tags + "?hop=1"), get(reg + tags + "?hop=2")}, get(reg + tags + "?hop=3"), false},
		{"host change to approved origin", []*http.Request{get(reg + tags)}, get(other + tags), false},
		{"host change on second hop", []*http.Request{get(reg + tags), get(reg + tags + "?hop=1")}, get(other + tags), false},
		{"https to http downgrade, same host", []*http.Request{get(reg + tags)}, get(regHTTP + tags), false},
		{"port change, same host", []*http.Request{get(reg + tags)}, get(regPort + tags), false},
		{"token endpoint to other origin", []*http.Request{get(reg + "/token?scope=x")}, get(other + "/token?scope=x"), false},
		{"bearer token on original request", []*http.Request{mustRequest(t, http.MethodGet, reg+tags, "Bearer tok")}, get(reg + tags + "?hop=1"), false},
		{"bearer token on intermediate hop", []*http.Request{get(reg + tags), mustRequest(t, http.MethodGet, reg+tags+"?hop=1", "Bearer tok")}, get(reg + tags + "?hop=2"), false},
		{"authorization on redirect request", []*http.Request{get(reg + tags)}, mustRequest(t, http.MethodGet, reg+tags+"?hop=1", "Basic eDp5"), false},
		{"userinfo in target", []*http.Request{get(reg + tags)}, get("https://u:p@reg.example" + tags), false},
		{"other resource", []*http.Request{get(reg + tags)}, get(reg + "/v2/repo/blobs/sha256:abc"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.checkRedirect(tc.req, tc.via)
			if tc.allow && err != nil {
				t.Fatalf("redirect refused: %v", err)
			}
			if !tc.allow && !errors.Is(err, ErrRedirectNotAllowed) {
				t.Fatalf("want ErrRedirectNotAllowed, got %v", err)
			}
		})
	}
}

// TestAnonymousRedirectChainLimit follows zero, one and two same-origin
// redirects of an anonymous tag list and refuses the third; the target of the
// refused redirect is never requested.
func TestAnonymousRedirectChainLimit(t *testing.T) {
	for redirects := 0; redirects <= 3; redirects++ {
		t.Run(fmt.Sprintf("redirects=%d", redirects), func(t *testing.T) {
			var hits, maxHop atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				var hop int32
				_, _ = fmt.Sscan(r.URL.Query().Get("hop"), &hop)
				if hop > maxHop.Load() {
					maxHop.Store(hop)
				}
				if int(hop) < redirects {
					http.Redirect(w, r, fmt.Sprintf("/v2/repo/tags/list?hop=%d", hop+1), http.StatusFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": []string{"1.0.0"}})
			}))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())

			res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
			if redirects <= 2 {
				if err != nil {
					t.Fatalf("%d redirects must be followed: %v", redirects, err)
				}
				if len(res.Tags) != 1 || res.Tags[0] != "1.0.0" {
					t.Fatalf("unexpected result %+v", res)
				}
				if got := hits.Load(); got != int32(redirects+1) {
					t.Fatalf("server saw %d requests, want %d", got, redirects+1)
				}
				return
			}
			if !errors.Is(err, ErrRedirectNotAllowed) {
				t.Fatalf("third redirect: want ErrRedirectNotAllowed, got %v", err)
			}
			if got := maxHop.Load(); got != 2 {
				t.Fatalf("highest hop served = %d, want 2: the refused target must not be requested", got)
			}
		})
	}
}

// TestRedirectToOtherApprovedHostRefused refuses a redirect to another host
// even when that host is itself an approved registry origin.
func TestRedirectToOtherApprovedHostRefused(t *testing.T) {
	for _, path := range []string{"/v2/repo/tags/list", "/token"} {
		t.Run(path, func(t *testing.T) {
			var destHits atomic.Int32
			dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				destHits.Add(1)
			}))
			defer dest.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" || path != "/token" {
					http.Redirect(w, r, dest.URL+r.URL.RequestURI(), http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusUnauthorized) // forces the anonymous token request
			}))
			defer srv.Close()
			c := regressionRedirectClient(t, srv, dest, newFakeClock()) // both approved, auth path /token

			_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
			if !errors.Is(err, ErrRedirectNotAllowed) {
				t.Fatalf("want ErrRedirectNotAllowed, got %v", err)
			}
			if n := destHits.Load(); n != 0 {
				t.Fatalf("other host received %d requests", n)
			}
		})
	}
}

// TestAnonymousTokenRequestDoesNotFollowRedirect: once the anonymous flow
// carries a bearer token, a redirect is refused even to the same origin and
// path, so the token is never replayed.
func TestAnonymousTokenRequestDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok"})
		case r.URL.Query().Get("hop") != "":
			redirected.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": []string{"1.0.0"}})
		case r.Header.Get("Authorization") == "":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.Redirect(w, r, "/v2/repo/tags/list?hop=1", http.StatusFound)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock())

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("want ErrRedirectNotAllowed, got %v", err)
	}
	if n := redirected.Load(); n != 0 {
		t.Fatalf("redirect with a bearer token was followed %d times", n)
	}
}

// TestPrivateSameOriginRedirectIsNotFollowed: a credentialed client follows
// no redirect, not even to the same origin and resource.
func TestPrivateSameOriginRedirectIsNotFollowed(t *testing.T) {
	p := newPrivServer(t)
	p.redirect = p.srv.URL + "/v2/team/app/manifests/1.0.0"
	c := newPrivClient(t, p, p.registry(AuthToken), newFakeClock())
	_, err := c.TagDigest(context.Background(), Ref{Registry: p.srv.URL, Repository: "team/app", Tag: "1.0.0"}, goodCred(), "reg1/cred:1")
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("err = %v, want ErrRedirectNotAllowed", err)
	}
	n := 0
	for _, l := range p.log() {
		if strings.HasPrefix(l, "HEAD /v2/team/app/manifests/1.0.0 Bearer") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("credentialed manifest request sent %d times, want 1 (redirect not followed); log %q", n, p.log())
	}
}
