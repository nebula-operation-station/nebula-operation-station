// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// limitsDigest is a well-formed manifest digest served by the limit tests.
var limitsDigest = "sha256:" + strings.Repeat("a", 64)

// echoTagsHandler serves a tag list whose name matches the repository in the
// request path, so repositories of any valid length are accepted by the
// client's name check.
func echoTagsHandler(rec *recorder, tags ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if !strings.HasSuffix(r.URL.Path, "/tags/list") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/tags/list")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "tags": tags})
	}
}

// paddedTagsBody returns a valid tag list for repo whose body is exactly
// size bytes long.
func paddedTagsBody(t *testing.T, repo string, size int) []byte {
	t.Helper()
	prefix := `{"name":"` + repo + `","tags":["1.0.0"],"pad":"`
	suffix := `"}`
	pad := size - len(prefix) - len(suffix)
	if pad < 0 {
		t.Fatalf("size %d too small for the fixed JSON envelope", size)
	}
	return []byte(prefix + strings.Repeat("x", pad) + suffix)
}

// TestRedirectChainLimit pins the redirect budget at its limit and one
// beyond. checkRedirect refuses a redirect once the chain already holds
// MaxRedirects requests (the original request plus its redirects), so the
// chain may contain MaxRedirects-1 redirects: two today.
func TestRedirectChainLimit(t *testing.T) {
	for _, redirects := range []int{MaxRedirects - 1, MaxRedirects, MaxRedirects + 1} {
		t.Run(fmt.Sprintf("redirects=%d", redirects), func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.enter(r.Method, r.URL.Path)
				defer rec.leave()
				hop, _ := strconv.Atoi(r.URL.Query().Get("hop"))
				if hop < redirects {
					// Same origin and path, so only the hop counter changes.
					http.Redirect(w, r, fmt.Sprintf("/v2/repo/tags/list?hop=%d", hop+1), http.StatusFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": []string{"1.0.0"}})
			}))
			defer srv.Close()
			fc := newFakeClock()
			c := newTestClient(t, srv, fc)

			res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
			if redirects <= MaxRedirects-1 {
				if err != nil {
					t.Fatalf("chain of %d redirects must be followed: %v", redirects, err)
				}
				if len(res.Tags) != 1 || res.Tags[0] != "1.0.0" {
					t.Fatalf("unexpected result %+v", res)
				}
			} else if !errors.Is(err, ErrRedirectNotAllowed) {
				t.Fatalf("chain of %d redirects: want ErrRedirectNotAllowed, got %v", redirects, err)
			}
			if got := rec.count(""); got != MaxRedirects {
				t.Fatalf("server saw %d requests, want exactly MaxRedirects (%d)", got, MaxRedirects)
			}
		})
	}
}

// TestRepoLenLimit accepts a repository of exactly MaxRepoLen bytes and
// refuses one byte more before any request is sent.
func TestRepoLenLimit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int
		wantOK bool
	}{
		{"at limit", MaxRepoLen, true},
		{"one beyond", MaxRepoLen + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(echoTagsHandler(rec, "1.0.0"))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())
			repo := strings.Repeat("a", tc.length)

			_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: repo})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("repository of %d bytes must be accepted: %v", tc.length, err)
				}
				return
			}
			if !errors.Is(err, ErrBadRef) {
				t.Fatalf("repository of %d bytes: want ErrBadRef, got %v", tc.length, err)
			}
			if n := rec.count(""); n != 0 {
				t.Fatalf("an over-long repository must not reach the registry, got %d requests", n)
			}
		})
	}
}

// TestTagLenLimit accepts a tag of exactly MaxTagLen bytes and refuses one
// byte more, both as a requested tag and as a tag inside a tag list.
func TestTagLenLimit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int
		wantOK bool
	}{
		{"at limit", MaxTagLen, true},
		{"one beyond", MaxTagLen + 1, false},
	} {
		t.Run("requested "+tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.enter(r.Method, r.URL.Path)
				defer rec.leave()
				w.Header().Set("Docker-Content-Digest", limitsDigest)
			}))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())
			tag := strings.Repeat("a", tc.length)

			_, err := c.TagDigest(context.Background(), Ref{Registry: srv.URL, Repository: "repo", Tag: tag})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("tag of %d bytes must be accepted: %v", tc.length, err)
				}
				return
			}
			if !errors.Is(err, ErrBadRef) {
				t.Fatalf("tag of %d bytes: want ErrBadRef, got %v", tc.length, err)
			}
			if n := rec.count(""); n != 0 {
				t.Fatalf("an over-long tag must not reach the registry, got %d requests", n)
			}
		})
		t.Run("listed "+tc.name, func(t *testing.T) {
			srv := httptest.NewServer(echoTagsHandler(&recorder{}, strings.Repeat("a", tc.length)))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())

			_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("listed tag of %d bytes must be accepted: %v", tc.length, err)
				}
				return
			}
			if !errors.Is(err, ErrBadResponse) {
				t.Fatalf("listed tag of %d bytes: want ErrBadResponse, got %v", tc.length, err)
			}
		})
	}
}

// TestResponseBytesLimit accepts a tag list body of exactly
// MaxResponseBytes and rejects a body one byte larger.
func TestResponseBytesLimit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		wantOK bool
	}{
		{"at limit", MaxResponseBytes, true},
		{"one beyond", MaxResponseBytes + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			body := paddedTagsBody(t, "repo", tc.size)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.enter(r.Method, r.URL.Path)
				defer rec.leave()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			}))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())

			res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("body of %d bytes must be accepted: %v", tc.size, err)
				}
				if len(res.Tags) != 1 {
					t.Fatalf("unexpected result %+v", res)
				}
				return
			}
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("body of %d bytes: want ErrResponseTooLarge, got %v", tc.size, err)
			}
		})
	}
}

// TestRateLimitBackoffGrowthAndCap checks the 429 pause sequence: it doubles
// from MinRateLimitPause and stops at MaxBackoff (reached at the eighth
// consecutive 429). Each 429 is measured on its own: the fake clock is moved
// past the pause the previous 429 set, so an earlier, longer deadline cannot
// hide a smaller, zero or overflowed pause. Every pause must lie in
// (0, MaxBackoff]. A success restarts the sequence.
func TestRateLimitBackoffGrowthAndCap(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	reg := srv.URL

	// pauseAfterRateLimit records one 429 and returns the pause it set. It
	// then advances the clock past that pause, so the next 429 starts clean.
	pauseAfterRateLimit := func() time.Duration {
		c.noteRateLimit(reg, 0)
		c.mu.Lock()
		pause := c.regs[reg].pauseUntil.Sub(fc.Now())
		c.mu.Unlock()
		fc.Advance(pause + time.Second)
		return pause
	}
	checkRange := func(n int, got time.Duration) {
		t.Helper()
		if got <= 0 || got > MaxBackoff {
			t.Fatalf("429 #%d: pause = %s, want a pause in (0, %s]", n, got, MaxBackoff)
		}
	}

	want := []time.Duration{
		15 * time.Minute, // 1st: MinRateLimitPause
		30 * time.Minute,
		60 * time.Minute,
		2 * time.Hour,
		4 * time.Hour,
		8 * time.Hour,
		16 * time.Hour, // 7th: still below the cap
		MaxBackoff,     // 8th: 32 h would exceed 24 h, so the cap applies
		MaxBackoff,
	}
	for i, w := range want {
		got := pauseAfterRateLimit()
		checkRange(i+1, got)
		if got != w {
			t.Fatalf("429 #%d: pause = %s, want %s", i+1, got, w)
		}
	}

	// Well past maxBackoffShifts, so the exponent is clamped and every
	// further 429 must still be exactly the cap, never an overflowed shift.
	for i := 0; i < 1000; i++ {
		got := pauseAfterRateLimit()
		n := len(want) + i + 1
		checkRange(n, got)
		if got != MaxBackoff {
			t.Fatalf("429 #%d after the cap: pause = %s, want %s", n, got, MaxBackoff)
		}
	}
	c.mu.Lock()
	exp := c.regs[reg].backoffExp
	c.mu.Unlock()
	if exp != maxBackoffShifts {
		t.Fatalf("backoff exponent = %d, want it clamped at maxBackoffShifts (%d)", exp, maxBackoffShifts)
	}

	c.noteSuccess(reg)
	fc.Advance(MaxBackoff + time.Second) // let the old pause run out
	if got := pauseAfterRateLimit(); got != MinRateLimitPause {
		t.Fatalf("first 429 after a success: pause = %s, want %s", got, MinRateLimitPause)
	}
}

// TestSameTagAndDigestCacheTTL checks that a same-tag result is served from
// the cache until TTLSameTag and refetched at exactly that age, and that a
// digest-pinned result uses TTLDigest the same way.
func TestSameTagAndDigestCacheTTL(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  Ref
		ttl  time.Duration
		path string
	}{
		{
			name: "same tag",
			ref:  Ref{Repository: "repo", Tag: "1.0.0"},
			ttl:  TTLSameTag,
			path: "HEAD /v2/repo/manifests/1.0.0",
		},
		{
			name: "digest pin",
			ref:  Ref{Repository: "repo", Digest: limitsDigest},
			ttl:  TTLDigest,
			path: "HEAD /v2/repo/manifests/" + limitsDigest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.enter(r.Method, r.URL.Path)
				defer rec.leave()
				w.Header().Set("Docker-Content-Digest", limitsDigest)
			}))
			defer srv.Close()
			fc := newFakeClock()
			c := newTestClient(t, srv, fc)
			ref := tc.ref
			ref.Registry = srv.URL
			ctx := context.Background()

			if _, err := c.TagDigest(ctx, ref); err != nil {
				t.Fatalf("TagDigest: %v", err)
			}
			fc.Advance(tc.ttl - time.Second)
			res, err := c.TagDigest(ctx, ref)
			if err != nil {
				t.Fatalf("TagDigest (inside TTL): %v", err)
			}
			if !res.FromCache {
				t.Fatalf("result one second inside the TTL must come from the cache")
			}
			if n := rec.count(tc.path); n != 1 {
				t.Fatalf("inside the TTL: want 1 registry request, got %d", n)
			}

			fc.Advance(time.Second) // now exactly TTL old: expired
			res, err = c.TagDigest(ctx, ref)
			if err != nil {
				t.Fatalf("TagDigest (at TTL): %v", err)
			}
			if res.FromCache {
				t.Fatalf("result at exactly the TTL must be refetched")
			}
			if n := rec.count(tc.path); n != 2 {
				t.Fatalf("at the TTL: want a second registry request, got %d", n)
			}
		})
	}
}

// TestImageLenLimit accepts an image reference of exactly MaxImageLen bytes
// and refuses one byte more. The repository is kept at MaxRepoLen, so the
// length is set by the registry host.
func TestImageLenLimit(t *testing.T) {
	const repoLen = MaxRepoLen
	for _, tc := range []struct {
		name   string
		length int
		wantOK bool
	}{
		{"at limit", MaxImageLen, true},
		{"one beyond", MaxImageLen + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := strings.Repeat("h", tc.length-1-repoLen)
			image := host + "/" + strings.Repeat("a", repoLen)
			if len(image) != tc.length {
				t.Fatalf("test setup: image is %d bytes, want %d", len(image), tc.length)
			}

			ref, err := ParseRef(image)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("image of %d bytes must be accepted: %v", tc.length, err)
				}
				if ref.Repository != strings.Repeat("a", repoLen) {
					t.Fatalf("unexpected repository length %d", len(ref.Repository))
				}
				return
			}
			if !errors.Is(err, ErrBadRef) {
				t.Fatalf("image of %d bytes: want ErrBadRef, got %v", tc.length, err)
			}
		})
	}
}

// TestTokenLenLimit accepts an anonymous bearer token of exactly MaxTokenLen
// bytes and refuses one byte more. At the limit the token is used to fetch
// the tag list; beyond it the lookup fails before any authenticated request.
func TestTokenLenLimit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length int
		wantOK bool
	}{
		{"at limit", MaxTokenLen, true},
		{"one beyond", MaxTokenLen + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := strings.Repeat("t", tc.length)
			rec := &recorder{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.enter(r.Method, r.URL.Path)
				defer rec.leave()
				switch r.URL.Path {
				case "/token":
					_, _ = fmt.Fprintf(w, `{"token":%q}`, tok)
				case "/v2/repo/tags/list":
					if r.Header.Get("Authorization") != "Bearer "+tok {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"name":"repo","tags":["1.0.0"]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())

			res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("token of %d bytes must be accepted: %v", tc.length, err)
				}
				if len(res.Tags) != 1 {
					t.Fatalf("unexpected result %+v", res)
				}
				return
			}
			if !errors.Is(err, ErrBadResponse) {
				t.Fatalf("token of %d bytes: want ErrBadResponse, got %v", tc.length, err)
			}
			if n := rec.count("GET /v2/repo/tags/list"); n != 1 {
				t.Fatalf("an oversized token must not be used on the tag list, got %d tag list requests", n)
			}
		})
	}
}

// TestTagListTTLBoundary checks that a successful tag list is served from the
// cache one second inside TTLTagList and refetched at exactly TTLTagList.
func TestTagListTTLBoundary(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()
	ref := Ref{Registry: srv.URL, Repository: "repo"}
	const path = "GET /v2/repo/tags/list"

	if _, err := c.ListTags(ctx, ref); err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	fc.Advance(TTLTagList - time.Second)
	if _, err := c.ListTags(ctx, ref); err != nil {
		t.Fatalf("ListTags (inside TTL): %v", err)
	}
	if n := rec.count(path); n != 1 {
		t.Fatalf("one second inside TTLTagList: want the cache to serve (1 request), got %d", n)
	}

	fc.Advance(time.Second) // now exactly TTLTagList old: expired
	if _, err := c.ListTags(ctx, ref); err != nil {
		t.Fatalf("ListTags (at TTL): %v", err)
	}
	if n := rec.count(path); n != 2 {
		t.Fatalf("at exactly TTLTagList: want a refetch (2 requests), got %d", n)
	}
}

// TestFailureTTLBoundary checks that a failed tag list lookup is served from
// the failure cache one second inside TTLFailure and retried at exactly
// TTLFailure.
func TestFailureTTLBoundary(t *testing.T) {
	rec := &recorder{}
	var fails atomic.Bool
	fails.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if fails.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": []string{"1.0.0"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()
	ref := Ref{Registry: srv.URL, Repository: "repo"}
	const path = "GET /v2/repo/tags/list"

	if _, err := c.ListTags(ctx, ref); err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	fc.Advance(TTLFailure - time.Second)
	if _, err := c.ListTags(ctx, ref); err == nil {
		t.Fatal("one second inside TTLFailure: want the cached failure")
	}
	if n := rec.count(path); n != 1 {
		t.Fatalf("one second inside TTLFailure: want the failure cache to serve (1 request), got %d", n)
	}

	fc.Advance(time.Second) // now exactly TTLFailure old: expired
	fails.Store(false)
	res, err := c.ListTags(ctx, ref)
	if err != nil {
		t.Fatalf("ListTags at exactly TTLFailure: want a retry, got %v", err)
	}
	if len(res.Tags) != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
	if n := rec.count(path); n != 2 {
		t.Fatalf("at exactly TTLFailure: want a retry (2 requests), got %d", n)
	}
}
