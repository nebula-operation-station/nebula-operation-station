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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorder records every request the test server receives and tracks the
// maximum observed concurrency.
type recorder struct {
	mu      sync.Mutex
	reqs    []string
	conc    int32
	maxConc int32
}

func (r *recorder) enter(method, path string) {
	r.mu.Lock()
	r.reqs = append(r.reqs, method+" "+path)
	r.mu.Unlock()
	c := atomic.AddInt32(&r.conc, 1)
	for {
		m := atomic.LoadInt32(&r.maxConc)
		if c <= m || atomic.CompareAndSwapInt32(&r.maxConc, m, c) {
			break
		}
	}
}

func (r *recorder) leave() {
	atomic.AddInt32(&r.conc, -1)
}

func (r *recorder) count(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, q := range r.reqs {
		if strings.HasPrefix(q, prefix) {
			n++
		}
	}
	return n
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reqs...)
}

func newTestClient(t *testing.T, srv *httptest.Server, fc *fakeClock) *Client {
	t.Helper()
	c, err := NewClient(Options{
		Origins:       []Origin{{Registry: srv.URL, Auth: srv.URL, AuthPath: "/token"}},
		Now:           fc.Now,
		Sleep:         fc.Sleep,
		Jitter:        func() time.Duration { return 0 },
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func tagsHandler(rec *recorder, tags ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if r.URL.Path != "/v2/repo/tags/list" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": tags})
	}
}

func TestParseRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		in      string
		reg     string
		repo    string
		tag     string
		digest  string
		wantErr error
	}{
		{in: "https://registry-1.docker.io/library/nginx:1.25", reg: "https://registry-1.docker.io", repo: "library/nginx", tag: "1.25"},
		{in: "registry-1.docker.io/library/nginx:1.25", reg: "https://registry-1.docker.io", repo: "library/nginx", tag: "1.25"},
		{in: "http://ghcr.io/owner/repo:2.0", reg: "http://ghcr.io", repo: "owner/repo", tag: "2.0"},
		{in: "ghcr.io/owner/repo", reg: "https://ghcr.io", repo: "owner/repo"},
		{in: "quay.io/org/app@" + digest, reg: "https://quay.io", repo: "org/app", digest: digest},
		{in: "example.com", wantErr: ErrBadRef},
		{in: "example.com/", wantErr: ErrBadRef},
		{in: "ftp://example.com/repo:1", wantErr: ErrBadRef},
		{in: "example.com/UPPER:1", wantErr: ErrBadRef},
		{in: "example.com/repo:bad tag", wantErr: ErrBadRef},
		{in: "example.com/repo@sha256:zzz", wantErr: ErrBadRef},
		{in: "example.com/repo@sha256:" + strings.Repeat("a", 63), wantErr: ErrBadRef},
		{in: "", wantErr: ErrBadRef},
	}
	for _, tc := range cases {
		ref, err := ParseRef(tc.in)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("ParseRef(%q): want %v, got %v", tc.in, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRef(%q): unexpected error %v", tc.in, err)
			continue
		}
		if ref.Registry != tc.reg || ref.Repository != tc.repo || ref.Tag != tc.tag || ref.Digest != tc.digest {
			t.Errorf("ParseRef(%q) = %+v, want reg=%s repo=%s tag=%s digest=%s", tc.in, ref, tc.reg, tc.repo, tc.tag, tc.digest)
		}
	}
}

func TestNewClientRejectsBadAllowlist(t *testing.T) {
	if _, err := NewClient(Options{}); !errors.Is(err, ErrOriginNotAllowed) {
		t.Errorf("empty allowlist: want ErrOriginNotAllowed, got %v", err)
	}
	if _, err := NewClient(Options{Origins: []Origin{{Registry: "not a url", Auth: "https://a.example"}}}); !errors.Is(err, ErrOriginNotAllowed) {
		t.Errorf("bad origin: want ErrOriginNotAllowed, got %v", err)
	}
	if _, err := NewClient(Options{Origins: []Origin{{Registry: "https://a.example", Auth: "https://a.example"}, {Registry: "https://a.example", Auth: "https://b.example"}}}); !errors.Is(err, ErrOriginNotAllowed) {
		t.Errorf("duplicate origin: want ErrOriginNotAllowed, got %v", err)
	}
}

func TestListTagsAnonymous(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0", "1.2.0"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()

	res, err := c.ListTags(ctx, Ref{Registry: srv.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if res.Incomplete || len(res.Tags) != 2 || res.Tags[0] != "1.0.0" || res.Tags[1] != "1.2.0" {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.FromCache {
		t.Fatal("first result must not come from the cache")
	}
	n := rec.count("GET /v2/repo/tags/list")
	res2, err := c.ListTags(ctx, Ref{Registry: srv.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags (cached): %v", err)
	}
	if !res2.FromCache {
		t.Fatal("second result must come from the cache")
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != n {
		t.Fatalf("cached call hit the network: %d -> %d requests", n, got)
	}
}

func TestListTagsTokenFlow(t *testing.T) {
	rec := &recorder{}
	var tokenScope, tokenService, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		switch r.URL.Path {
		case "/token":
			tokenScope = r.URL.Query().Get("scope")
			tokenService = r.URL.Query().Get("service")
			_, _ = w.Write([]byte(`{"token":"tok-1"}`))
		case "/v2/repo/tags/list":
			gotAuth = r.Header.Get("Authorization")
			if gotAuth != "Bearer tok-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "repo", "tags": []string{"1.0.0"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(res.Tags) != 1 || res.Tags[0] != "1.0.0" {
		t.Fatalf("unexpected result %+v", res)
	}
	if tokenScope != "repository:repo:pull" {
		t.Errorf("token scope = %q, want repository:repo:pull", tokenScope)
	}
	if tokenService != "" {
		t.Errorf("token service = %q, want empty", tokenService)
	}
	if gotAuth != "Bearer tok-1" {
		t.Errorf("retry Authorization = %q, want Bearer tok-1", gotAuth)
	}
}

func TestListTagsPagination(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if r.URL.Path != "/v2/repo/tags/list" {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Query().Get("n") {
		case "":
			w.Header().Set("Link", `</v2/repo/tags/list?n=2>; rel="next"`)
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"a", "b"}})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"c"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if res.Incomplete || len(res.Tags) != 3 || res.Tags[0] != "a" || res.Tags[1] != "b" || res.Tags[2] != "c" {
		t.Fatalf("unexpected result %+v", res)
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != 2 {
		t.Fatalf("expected 2 pages, got %d", got)
	}
}

func TestListTagsPaginationBudget(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if r.URL.Path != "/v2/repo/tags/list" {
			http.NotFound(w, r)
			return
		}
		n := r.URL.Query().Get("n")
		next := "1"
		if n != "" {
			next = fmt.Sprintf("%d", len(n)+1)
		}
		w.Header().Set("Link", fmt.Sprintf(`</v2/repo/tags/list?n=%s>; rel="next"`, next))
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"x"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if !res.Incomplete {
		t.Fatal("an endless tag list must be incomplete")
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != MaxPages {
		t.Fatalf("expected exactly MaxPages=%d requests, got %d", MaxPages, got)
	}
}

func TestListTagsTagBudget(t *testing.T) {
	rec := &recorder{}
	tags := make([]string, MaxTagsPerScan+1)
	for i := range tags {
		tags[i] = fmt.Sprintf("t%05d", i)
	}
	srv := httptest.NewServer(tagsHandler(rec, tags...))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	res, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if !res.Incomplete {
		t.Fatal("a list over the tag budget must be incomplete")
	}
	if len(res.Tags) != MaxTagsPerScan {
		t.Fatalf("expected MaxTagsPerScan=%d tags, got %d", MaxTagsPerScan, len(res.Tags))
	}
}

func TestListTagsOversizeResponse(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		_, _ = w.Write([]byte(strings.Repeat("a", MaxResponseBytes+1)))
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

func TestListTagsMalformedJSON(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("want ErrBadResponse, got %v", err)
	}
}

func TestListTagsBadTag(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "good", "bad/tag"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("want ErrBadResponse for a malformed tag, got %v", err)
	}
}

func TestOriginNotAllowed(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: "https://evil.example.com", Repository: "repo"})
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("want ErrOriginNotAllowed, got %v", err)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("no request may leave the client, got %d", n)
	}
}

func TestSSRFPrivateAddress(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0"))
	defer srv.Close()
	fc := newFakeClock()
	c, err := NewClient(Options{
		Origins:       []Origin{{Registry: srv.URL, Auth: srv.URL}},
		Now:           fc.Now,
		Sleep:         fc.Sleep,
		Jitter:        func() time.Duration { return 0 },
		AllowLoopback: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("want ErrPrivateAddress, got %v", err)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("no request may reach the private host, got %d", n)
	}
}

func TestRedirectRejected(t *testing.T) {
	recB := &recorder{}
	srvB := httptest.NewServer(tagsHandler(recB, "1.0.0"))
	defer srvB.Close()
	recA := &recorder{}
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recA.enter(r.Method, r.URL.Path)
		defer recA.leave()
		http.Redirect(w, r, srvB.URL+"/v2/repo/tags/list", http.StatusFound)
	}))
	defer srvA.Close()
	fc := newFakeClock()
	c := newTestClient(t, srvA, fc) // allowlist: srvA only

	_, err := c.ListTags(context.Background(), Ref{Registry: srvA.URL, Repository: "repo"})
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("want ErrRedirectNotAllowed, got %v", err)
	}
	if n := recB.count(""); n != 0 {
		t.Fatalf("the non-allowlisted target must not be reached, got %d requests", n)
	}
}

func TestRedirectAllowed(t *testing.T) {
	recB := &recorder{}
	srvB := httptest.NewServer(tagsHandler(recB, "1.0.0"))
	defer srvB.Close()
	recA := &recorder{}
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recA.enter(r.Method, r.URL.Path)
		defer recA.leave()
		http.Redirect(w, r, srvB.URL+"/v2/repo/tags/list", http.StatusFound)
	}))
	defer srvA.Close()
	fc := newFakeClock()
	c, err := NewClient(Options{
		Origins: []Origin{
			{Registry: srvA.URL, Auth: srvA.URL},
			{Registry: srvB.URL, Auth: srvB.URL},
		},
		Now:           fc.Now,
		Sleep:         fc.Sleep,
		Jitter:        func() time.Duration { return 0 },
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	res, err := c.ListTags(context.Background(), Ref{Registry: srvA.URL, Repository: "repo"})
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(res.Tags) != 1 || res.Tags[0] != "1.0.0" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestRedirectLoop(t *testing.T) {
	rec := &recorder{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		http.Redirect(w, r, srv.URL+"/v2/repo/tags/list", http.StatusFound)
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("want ErrRedirectNotAllowed for a redirect loop, got %v", err)
	}
}

func TestLinkForeignOrigin(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		w.Header().Set("Link", `<http://evil.example.com/v2/repo/tags/list>; rel="next"`)
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"a"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("want ErrRedirectNotAllowed for a foreign Link target, got %v", err)
	}
}

func TestLinkWrongPath(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		w.Header().Set("Link", `</v2/repo/blobs/sha256:abc>; rel="next"`)
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"a"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("want ErrRedirectNotAllowed for a Link off the tags/list path, got %v", err)
	}
}

func TestTagDigest(t *testing.T) {
	rec := &recorder{}
	var method, accept string
	digest := "sha256:" + strings.Repeat("b", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if r.URL.Path != "/v2/repo/manifests/1.0" {
			http.NotFound(w, r)
			return
		}
		method = r.Method
		accept = r.Header.Get("Accept")
		w.Header().Set("Docker-Content-Digest", digest)
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	res, err := c.TagDigest(context.Background(), Ref{Registry: srv.URL, Repository: "repo", Tag: "1.0"})
	if err != nil {
		t.Fatalf("TagDigest: %v", err)
	}
	if res.Digest != digest {
		t.Fatalf("digest = %q, want %q", res.Digest, digest)
	}
	if method != http.MethodHead {
		t.Fatalf("manifest lookup must be a HEAD, got %s", method)
	}
	if !strings.Contains(accept, "application/vnd.oci.image.index.v1+json") {
		t.Fatalf("Accept header missing the OCI index media type: %q", accept)
	}
}

func TestTagDigestRequiresTag(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.TagDigest(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrBadRef) {
		t.Fatalf("want ErrBadRef, got %v", err)
	}
}

func TestTagDigestNotFound(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		http.NotFound(w, r)
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.TagDigest(context.Background(), Ref{Registry: srv.URL, Repository: "repo", Tag: "1.0"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestTagDigestBadDigestHeader(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		w.Header().Set("Docker-Content-Digest", "garbage")
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.TagDigest(context.Background(), Ref{Registry: srv.URL, Repository: "repo", Tag: "1.0"})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("want ErrBadResponse for a malformed digest header, got %v", err)
	}
}

func TestNoLayerPulls(t *testing.T) {
	rec := &recorder{}
	digest := "sha256:" + strings.Repeat("c", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		switch {
		case r.URL.Path == "/token":
			_, _ = w.Write([]byte(`{"token":"tok"}`))
		case r.URL.Path == "/v2/repo/tags/list":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0"}})
		case r.URL.Path == "/v2/repo/manifests/1.0" && r.Method == http.MethodHead:
			w.Header().Set("Docker-Content-Digest", digest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()

	if _, err := c.ListTags(ctx, Ref{Registry: srv.URL, Repository: "repo"}); err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if _, err := c.TagDigest(ctx, Ref{Registry: srv.URL, Repository: "repo", Tag: "1.0"}); err != nil {
		t.Fatalf("TagDigest: %v", err)
	}
	for _, q := range rec.all() {
		if strings.Contains(q, "/blobs/") {
			t.Fatalf("a layer or blob request was made: %s", q)
		}
		if strings.HasPrefix(q, "GET /v2/repo/manifests/") {
			t.Fatalf("a manifest body (GET) was pulled: %s", q)
		}
	}
}

func TestCacheTTL(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()
	ref := Ref{Registry: srv.URL, Repository: "repo"}

	if _, err := c.ListTags(ctx, ref); err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if _, err := c.ListTags(ctx, ref); err != nil {
		t.Fatalf("ListTags (cached): %v", err)
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != 1 {
		t.Fatalf("expected 1 network request within the TTL, got %d", got)
	}
	fc.Advance(TTLTagList + time.Second)
	if _, err := c.ListTags(ctx, ref); err != nil {
		t.Fatalf("ListTags (after TTL): %v", err)
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != 2 {
		t.Fatalf("expected a refresh after the TTL, got %d requests", got)
	}
}

func TestFailureCached(t *testing.T) {
	rec := &recorder{}
	fails := int32(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if atomic.LoadInt32(&fails) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()
	ref := Ref{Registry: srv.URL, Repository: "repo"}

	_, err := c.ListTags(ctx, ref)
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	_, err2 := c.ListTags(ctx, ref)
	if err2 == nil || err2 != err {
		t.Fatalf("expected the identical cached failure, got %v", err2)
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != 1 {
		t.Fatalf("the cached failure must not hit the network, got %d requests", got)
	}
	fc.Advance(TTLFailure + time.Second)
	atomic.StoreInt32(&fails, 0)
	res, err := c.ListTags(ctx, ref)
	if err != nil {
		t.Fatalf("ListTags after failure TTL: %v", err)
	}
	if len(res.Tags) != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestCoalescing(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		time.Sleep(200 * time.Millisecond) // hold the in-flight slot
		if r.URL.Path != "/v2/repo/tags/list" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != 1 {
		t.Fatalf("coalesced lookups must produce exactly 1 request, got %d", got)
	}
}

func TestRateLimit429(t *testing.T) {
	rec := &recorder{}
	first := int32(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if r.URL.Path == "/v2/repo/tags/list" && atomic.CompareAndSwapInt32(&first, 1, 0) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()
	ref := Ref{Registry: srv.URL, Repository: "repo"}

	_, err := c.ListTags(ctx, ref)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	c.mu.Lock()
	pause := c.regs[srv.URL].pauseUntil.Sub(fc.Now())
	c.mu.Unlock()
	if pause != MinRateLimitPause {
		t.Fatalf("first pause = %s, want %s (Retry-After 30s is below the minimum)", pause, MinRateLimitPause)
	}
	_, err2 := c.ListTags(ctx, ref)
	if !errors.Is(err2, ErrRateLimited) {
		t.Fatalf("during the pause want ErrRateLimited, got %v", err2)
	}
	if got := rec.count("GET /v2/repo/tags/list"); got != 1 {
		t.Fatalf("the pause must not hit the network, got %d requests", got)
	}
	fc.Advance(MinRateLimitPause + time.Second)
	res, err := c.ListTags(ctx, ref)
	if err != nil {
		t.Fatalf("after the pause: %v", err)
	}
	if len(res.Tags) != 1 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestRateLimitRetryAfterHonored(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	c.mu.Lock()
	pause := c.regs[srv.URL].pauseUntil.Sub(fc.Now())
	c.mu.Unlock()
	if pause != time.Hour {
		t.Fatalf("pause = %s, want 1h (Retry-After wins over the minimum)", pause)
	}
}

func TestRateLimitExponentialBackoff(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()
	ref := Ref{Registry: srv.URL, Repository: "repo"}

	_, _ = c.ListTags(ctx, ref)
	c.mu.Lock()
	pause1 := c.regs[srv.URL].pauseUntil.Sub(fc.Now())
	c.mu.Unlock()
	fc.Advance(MinRateLimitPause + time.Second)
	_, _ = c.ListTags(ctx, ref)
	c.mu.Lock()
	pause2 := c.regs[srv.URL].pauseUntil.Sub(fc.Now())
	c.mu.Unlock()
	if pause1 != MinRateLimitPause {
		t.Fatalf("first pause = %s, want %s", pause1, MinRateLimitPause)
	}
	if pause2 != 2*MinRateLimitPause {
		t.Fatalf("second pause = %s, want %s", pause2, 2*MinRateLimitPause)
	}
}

func TestRequestInterval(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		switch r.URL.Path {
		case "/v2/repo-a/tags/list", "/v2/repo-b/tags/list":
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)
	ctx := context.Background()

	start := fc.Now()
	if _, err := c.ListTags(ctx, Ref{Registry: srv.URL, Repository: "repo-a"}); err != nil {
		t.Fatalf("ListTags repo-a: %v", err)
	}
	if _, err := c.ListTags(ctx, Ref{Registry: srv.URL, Repository: "repo-b"}); err != nil {
		t.Fatalf("ListTags repo-b: %v", err)
	}
	if d := fc.Now().Sub(start); d < MinRequestInterval {
		t.Fatalf("the second request must wait for the per-registry interval, waited %s", d)
	}
}

func TestConcurrencyCap(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		time.Sleep(1500 * time.Millisecond) // real time: requests overlap
		if strings.HasSuffix(r.URL.Path, "/tags/list") {
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	var wg sync.WaitGroup
	for _, repo := range []string{"repo-a", "repo-b", "repo-c"} {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			_, _ = c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: repo})
		}(repo)
	}
	wg.Wait()
	if m := atomic.LoadInt32(&rec.maxConc); m > MaxConcurrentPerRegistry {
		t.Fatalf("max concurrency = %d, want at most %d", m, MaxConcurrentPerRegistry)
	}
}

func TestDefaultNamespace(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		if r.URL.Path != "/v2/library/nginx/tags/list" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
	}))
	defer srv.Close()
	fc := newFakeClock()
	c, err := NewClient(Options{
		Origins:       []Origin{{Registry: srv.URL, Auth: srv.URL, DefaultNamespace: "library"}},
		Now:           fc.Now,
		Sleep:         fc.Sleep,
		Jitter:        func() time.Duration { return 0 },
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "nginx"}); err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	found := false
	for _, q := range rec.all() {
		if q == "GET /v2/library/nginx/tags/list" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the default namespace on the wire, got %v", rec.all())
	}
}

func TestTokenServiceParam(t *testing.T) {
	rec := &recorder{}
	var service string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		switch r.URL.Path {
		case "/token":
			service = r.URL.Query().Get("service")
			_, _ = w.Write([]byte(`{"token":"tok"}`))
		case "/v2/repo/tags/list":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": []string{"1.0.0"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fc := newFakeClock()
	c, err := NewClient(Options{
		Origins:       []Origin{{Registry: srv.URL, Auth: srv.URL, Service: "registry.docker.io"}},
		Now:           fc.Now,
		Sleep:         fc.Sleep,
		Jitter:        func() time.Duration { return 0 },
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"}); err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if service != "registry.docker.io" {
		t.Fatalf("token service = %q, want registry.docker.io", service)
	}
}

func TestTokenTooLarge(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.enter(r.Method, r.URL.Path)
		defer rec.leave()
		switch r.URL.Path {
		case "/token":
			_, _ = fmt.Fprintf(w, `{"token":"%s"}`, strings.Repeat("t", MaxTokenLen+1))
		case "/v2/repo/tags/list":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	_, err := c.ListTags(context.Background(), Ref{Registry: srv.URL, Repository: "repo"})
	if !errors.Is(err, ErrBadResponse) {
		t.Fatalf("want ErrBadResponse for an oversized token, got %v", err)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(tagsHandler(rec, "1.0.0"))
	defer srv.Close()
	fc := newFakeClock()
	c := newTestClient(t, srv, fc)

	if d := c.retryAfter("30"); d != 30*time.Second {
		t.Errorf("retryAfter(30) = %s, want 30s", d)
	}
	if d := c.retryAfter(""); d != 0 {
		t.Errorf("retryAfter(\"\") = %s, want 0", d)
	}
	if d := c.retryAfter("garbage"); d != 0 {
		t.Errorf("retryAfter(garbage) = %s, want 0", d)
	}
	future := fc.Now().Add(5 * time.Minute).UTC().Format(http.TimeFormat)
	if d := c.retryAfter(future); d != 5*time.Minute {
		t.Errorf("retryAfter(HTTP-date) = %s, want 5m", d)
	}
}
