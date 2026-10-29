// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefValidationPrecedesCacheAccess(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := newTestClient(t, srv, newFakeClock())
	ref := Ref{Registry: srv.URL, Repository: "repo", Tag: "missing"}
	if _, err := c.TagDigest(context.Background(), ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cache missing tag failure: %v", err)
	}
	for _, tc := range []struct{ tag, digest string }{
		{tag: "missing|err"},
		{tag: strings.Repeat("x", MaxTagLen+1)},
		{tag: "bad/tag"},
		{tag: "bad\xff"},
		{digest: "missing|err"},
		{digest: "sha256:" + strings.Repeat("a", 129)},
		{digest: strings.Repeat("a", MaxImageLen) + ":" + strings.Repeat("b", 64)},
		{tag: "valid", digest: "sha256:" + strings.Repeat("a", 64)},
	} {
		ref.Tag, ref.Digest = tc.tag, tc.digest
		if _, err := c.TagDigest(context.Background(), ref); !errors.Is(err, ErrBadRef) {
			t.Errorf("invalid tag/digest accepted: %v", err)
		}
		if _, err := c.ListTags(context.Background(), ref); !errors.Is(err, ErrBadRef) {
			t.Errorf("ListTags accepted invalid ref: %v", err)
		}
	}
	if n := rec.count(""); n != 1 {
		t.Fatalf("invalid references reached the network: %d requests", n)
	}
}

func TestRedirectRejectsNonMetadataResources(t *testing.T) {
	for _, source := range []string{"tags", "manifest", "token"} {
		for _, target := range []string{"/v2/repo/blobs/sha256:abc", "/v2/repo/manifests/latest", "/unrelated", "/v2/other/tags/list", "/v2/repo/tags%2flist"} {
			if source == "manifest" && target == "/v2/repo/manifests/latest" {
				continue // permitted manifest HEAD resource
			}
			t.Run(source+target, func(t *testing.T) {
				var hits atomic.Int32
				dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits.Add(1)
				}))
				defer dest.Close()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, dest.URL+target, http.StatusFound)
				}))
				defer srv.Close()
				c := regressionRedirectClient(t, srv, dest, newFakeClock())
				ref := Ref{Registry: srv.URL, Repository: "repo", Tag: "latest"}
				var err error
				switch source {
				case "tags":
					_, err = c.ListTags(context.Background(), ref)
				case "manifest":
					_, err = c.TagDigest(context.Background(), ref)
				case "token":
					_, err = c.fetchToken(context.Background(), ref, "repo")
				}
				if !errors.Is(err, ErrRedirectNotAllowed) {
					t.Fatalf("redirect accepted: %v", err)
				}
				if n := hits.Load(); n != 0 {
					t.Fatalf("forbidden resource received %d requests", n)
				}
			})
		}
	}
}

func regressionRedirectClient(t *testing.T, a, b *httptest.Server, fc *fakeClock) *Client {
	t.Helper()
	c, err := NewClient(Options{
		Origins: []Origin{{Registry: a.URL, Auth: a.URL}, {Registry: b.URL, Auth: b.URL}},
		Now:     fc.Now, Sleep: fc.Sleep, Jitter: func() time.Duration { return 0 }, AllowLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRequestSlotsHeldUntilBodyClosure(t *testing.T) {
	stalled := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-stalled:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stalled)
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	c.sleep = func(ctx context.Context, d time.Duration) error {
		if d == acquirePollInterval {
			return sleepCtx(ctx, d)
		}
		return fc.Sleep(ctx, d)
	}
	ref := Ref{Registry: srv.URL, Repository: "repo"}
	var responses []*http.Response
	for range MaxConcurrentPerRegistry {
		resp, err := c.doWithToken(context.Background(), ref, "repo", http.MethodGet, srv.URL+"/v2/repo/tags/list", nil)
		if err != nil {
			t.Fatal(err)
		}
		responses = append(responses, resp)
		defer resp.Body.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	resp, err := c.doWithToken(ctx, ref, "repo", http.MethodGet, srv.URL+"/v2/repo/tags/list", nil)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || hits.Load() != MaxConcurrentPerRegistry {
		t.Fatalf("stalled bodies exceeded cap: hits=%d err=%v", hits.Load(), err)
	}
	responses[0].Body.Close()
	responses[0].Body.Close()
	c.mu.Lock()
	inflight := c.regs[srv.URL].inflight
	c.mu.Unlock()
	if inflight != MaxConcurrentPerRegistry-1 {
		t.Fatalf("body closure released the wrong number of slots: %d", inflight)
	}
	resp, err = c.doWithToken(context.Background(), ref, "repo", http.MethodGet, srv.URL+"/v2/repo/tags/list", nil)
	if err != nil {
		t.Fatalf("closed body did not free its slot: %v", err)
	}
	resp.Body.Close()
}

func TestRedirectHopsUseDestinationBudgetAndBackoff(t *testing.T) {
	for _, mode := range []string{"interval", "paused", "full", "429", "remaining", "intermediateBudget"} {
		t.Run(mode, func(t *testing.T) {
			fc := newFakeClock()
			var hits atomic.Int32
			var arrived time.Time
			dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				arrived = fc.Now()
				if mode == "429" {
					w.Header().Set("Retry-After", "3600")
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				if mode == "remaining" {
					w.Header().Set("ratelimit-remaining", "0;w=21600")
				}
				_, _ = w.Write([]byte(`{"name":"repo","tags":[]}`))
			}))
			defer dest.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "intermediateBudget" {
					w.Header().Set("ratelimit-remaining", "0;w=21600")
				}
				http.Redirect(w, r, dest.URL+r.URL.Path, http.StatusFound)
			}))
			defer srv.Close()
			c := regressionRedirectClient(t, srv, dest, fc)
			start := fc.Now()
			c.mu.Lock()
			st := c.regLocked(dest.URL)
			st.last = start
			if mode == "paused" {
				st.pauseUntil = start.Add(time.Hour)
			}
			if mode == "full" {
				st.inflight = MaxConcurrentPerRegistry
			}
			c.mu.Unlock()
			c.sleep = func(ctx context.Context, d time.Duration) error {
				if d == acquirePollInterval {
					return sleepCtx(ctx, d)
				}
				return fc.Sleep(ctx, d)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := c.ListTags(ctx, Ref{Registry: srv.URL, Repository: "repo"})
			if mode == "full" {
				if !errors.Is(err, context.DeadlineExceeded) || hits.Load() != 0 {
					t.Fatalf("redirect bypassed destination concurrency cap: hits=%d err=%v", hits.Load(), err)
				}
				return
			}
			if mode == "paused" || mode == "429" {
				if !errors.Is(err, ErrRateLimited) {
					t.Fatalf("want rate limit: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if mode == "paused" {
				if hits.Load() != 0 {
					t.Fatal("paused destination received a request")
				}
				return
			}
			if arrived.Sub(start) < MinRequestInterval {
				t.Fatal("redirect bypassed destination request interval")
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if mode == "429" || mode == "remaining" {
				want := time.Hour
				if mode == "remaining" {
					want = 6 * time.Hour
				}
				if got := c.regs[dest.URL].pauseUntil.Sub(fc.Now()); got != want {
					t.Fatalf("destination pause=%s want=%s", got, want)
				}
				if !c.regs[srv.URL].pauseUntil.IsZero() {
					t.Fatal("destination limit charged to source")
				}
			}
			if mode == "intermediateBudget" && !c.regs[srv.URL].pauseUntil.After(fc.Now()) {
				t.Fatal("intermediate response budget ignored")
			}
		})
	}
}

func TestDockerHubBudgetHeaderParsing(t *testing.T) {
	for _, tc := range []struct {
		header string
		pause  time.Duration
	}{
		{header: "20;w=21600"},
		{header: "0;w=21600", pause: 6 * time.Hour},
		{header: " 0 ; w = 1200 ", pause: 20 * time.Minute},
		{header: "0;w=3600", pause: time.Hour},
		{header: ""},
		{header: "garbage"},
		{header: "-1;w=21600"},
		{header: "0"},
		{header: "0;w=0"},
		{header: "0;w=-1"},
		{header: "0;w=invalid"},
		{header: "0;w=9223372037"},
		{header: "0;w=18446744073709551616"},
		{header: "0;w=3600;w=21600"},
	} {
		t.Run(tc.header, func(t *testing.T) {
			fc := newFakeClock()
			c := &Client{now: fc.Now, regs: map[string]*regState{}}
			h := http.Header{}
			h.Set("ratelimit-remaining", tc.header)
			c.noteBudget("https://registry.example", h)
			st := c.regs["https://registry.example"]
			if tc.pause == 0 {
				if st != nil && !st.pauseUntil.IsZero() {
					t.Fatal("unexhausted or malformed budget created a pause")
				}
				return
			}
			if st == nil || st.pauseUntil != fc.Now().Add(tc.pause) {
				t.Fatalf("budget did not pause for %s: %+v", tc.pause, st)
			}
			// A shorter budget window must preserve an existing longer pause.
			h.Set("ratelimit-remaining", "0;w=1")
			c.noteBudget("https://registry.example", h)
			if st.pauseUntil != fc.Now().Add(tc.pause) {
				t.Fatal("shorter window shortened the active pause")
			}
		})
	}
}

func TestProductionOriginsRequireHTTPS(t *testing.T) {
	for _, og := range []Origin{
		{Registry: "http://registry.example", Auth: "https://auth.example"},
		{Registry: "https://registry.example", Auth: "http://auth.example"},
	} {
		if _, err := NewClient(Options{Origins: []Origin{og}}); !errors.Is(err, ErrOriginNotAllowed) {
			t.Fatalf("HTTP production origin accepted: %v", err)
		}
		if _, err := NewClient(Options{Origins: []Origin{og}, AllowLoopback: true}); err != nil {
			t.Fatalf("explicit test configuration rejected: %v", err)
		}
	}
}

func TestTagListRequiresResponseStructure(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `[]`, `{"name":"repo"}`, `{"tags":[]}`, `{"name":null,"tags":[]}`, `{"name":"other","tags":[]}`, `{"name":"repo","tags":{}}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())
			if _, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"}); !errors.Is(err, ErrBadResponse) {
				t.Fatalf("malformed structure accepted: %v", err)
			}
		})
	}
	for _, tags := range []string{`[]`, `null`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintf(w, `{"name":"repo","tags":%s}`, tags)
		}))
		c := newTestClient(t, srv, newFakeClock())
		_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
		srv.Close()
		if err != nil {
			t.Fatalf("valid empty tag list rejected: %v", err)
		}
	}
}

func TestCoalescedLookupHonorsCancellation(t *testing.T) {
	for _, kind := range []string{"tags", "digest"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(tagsHandler(&recorder{}, "latest"))
			defer srv.Close()
			c := newTestClient(t, srv, newFakeClock())
			key := "tags|" + srv.URL + "|repo"
			if kind == "digest" {
				key = "digest|" + srv.URL + "|repo|latest"
			}
			cl, _ := c.begin(key)
			defer c.finish(key, cl)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				ref := Ref{Registry: srv.URL, Repository: "repo", Tag: "latest"}
				var err error
				if kind == "tags" {
					_, err = c.ListTags(ctx, ref)
				} else {
					_, err = c.TagDigest(ctx, ref)
				}
				result <- err
			}()
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("want cancellation: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("coalesced caller ignored cancellation")
			}
			select {
			case <-cl.done:
				t.Fatal("canceling a follower finished the leader")
			default:
			}
		})
	}
}
