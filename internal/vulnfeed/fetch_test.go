// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tlsServer starts a loopback TLS test server and returns it with a root
// pool that trusts it.
func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

// newTestFetcher builds a Fetcher allowing exactly the given servers.
func newTestFetcher(t *testing.T, pool *x509.CertPool, timeout time.Duration, srvs ...*httptest.Server) *Fetcher {
	t.Helper()
	origins := make([]string, len(srvs))
	for i, s := range srvs {
		origins[i] = s.URL
	}
	al, err := NewAllowlist(origins)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewFetcher(FetcherConfig{Allowlist: al, RootCAs: pool, Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFetchReadsBodyWithinLimit(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Errorf("Accept-Encoding %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Tue, 10 Nov 2026 08:00:00 GMT")
		_, _ = w.Write([]byte("hello"))
	})
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	res, err := f.Fetch(context.Background(), srv.URL+"/feed", 5, Validators{}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello" || res.Bytes != 5 || res.NotModified {
		t.Fatalf("got %q %+v", buf.String(), res)
	}
	if res.Validators.ETag != `"v1"` || res.Validators.LastModified != "Tue, 10 Nov 2026 08:00:00 GMT" {
		t.Fatalf("validators %+v", res.Validators)
	}
}

func TestFetchRejectsOffAllowlistURL(t *testing.T) {
	var hits atomic.Int32
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	other, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	f := newTestFetcher(t, pool, 0, srv)
	for _, u := range []string{
		other.URL + "/feed",
		strings.Replace(srv.URL, "https://", "http://", 1) + "/feed",
		strings.Replace(srv.URL, "https://", "https://user:pw@", 1) + "/feed",
		"ftp://127.0.0.1/feed",
	} {
		_, err := f.Fetch(context.Background(), u, 10, Validators{}, &bytes.Buffer{})
		if !errors.Is(err, ErrOriginNotAllowed) {
			t.Errorf("%s: %v, want ErrOriginNotAllowed", u, err)
		}
		if err != nil && strings.Contains(err.Error(), "pw") {
			t.Errorf("error leaks URL credentials: %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached a server", hits.Load())
	}
}

func TestFetchOversizeRejectedBeforeReading(t *testing.T) {
	const limit = 1024
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(limit+1))
		_, _ = w.Write(bytes.Repeat([]byte("a"), limit+1))
	})
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	_, err := f.Fetch(context.Background(), srv.URL, limit, Validators{}, &buf)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v, want ErrTooLarge", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("%d body bytes copied despite declared oversize", buf.Len())
	}
}

func TestFetchOversizeChunkedRejected(t *testing.T) {
	const limit = 1024
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length: flushing forces chunked encoding.
		for range 8 {
			_, _ = w.Write(bytes.Repeat([]byte("a"), limit/2))
			w.(http.Flusher).Flush()
		}
	})
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	_, err := f.Fetch(context.Background(), srv.URL, limit, Validators{}, &buf)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v, want ErrTooLarge", err)
	}
	if buf.Len() > limit {
		t.Fatalf("%d bytes written, cap %d", buf.Len(), limit)
	}
}

func TestFetchExactLimitAccepted(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte("a"), 64))
	})
	f := newTestFetcher(t, pool, 0, srv)
	res, err := f.Fetch(context.Background(), srv.URL, 64, Validators{}, &bytes.Buffer{})
	if err != nil || res.Bytes != 64 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestFetchRedirectOffAllowlistRefused(t *testing.T) {
	var otherHits atomic.Int32
	other, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		_, _ = w.Write([]byte("evil"))
	})
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/evil", http.StatusFound)
	})
	pool.AddCert(other.Certificate())
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	_, err := f.Fetch(context.Background(), srv.URL+"/feed", 1024, Validators{}, &buf)
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("%v, want ErrRedirectRefused", err)
	}
	if otherHits.Load() != 0 || buf.Len() != 0 {
		t.Fatalf("redirect target reached (%d hits, %d bytes)", otherHits.Load(), buf.Len())
	}
}

func TestFetchRedirectToOtherAllowlistedOriginRefused(t *testing.T) {
	// D4: no redirects to other origins, even allowlisted ones.
	var otherHits atomic.Int32
	other, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { otherHits.Add(1) })
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusMovedPermanently)
	})
	pool.AddCert(other.Certificate())
	f := newTestFetcher(t, pool, 0, srv, other)
	_, err := f.Fetch(context.Background(), srv.URL, 1024, Validators{}, &bytes.Buffer{})
	if !errors.Is(err, ErrRedirectRefused) || otherHits.Load() != 0 {
		t.Fatalf("%v (%d hits), want ErrRedirectRefused", err, otherHits.Load())
	}
}

func TestFetchRedirectDowngradeRefused(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+"/plain", http.StatusFound)
	})
	f := newTestFetcher(t, pool, 0, srv)
	_, err := f.Fetch(context.Background(), srv.URL, 1024, Validators{}, &bytes.Buffer{})
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("%v, want ErrRedirectRefused", err)
	}
}

func TestFetchSameOriginRedirectFollowedAndBounded(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			_, _ = w.Write([]byte("ok"))
		default:
			http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) // endless
		}
	})
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	if _, err := f.Fetch(context.Background(), srv.URL+"/a", 16, Validators{}, &buf); err != nil || buf.String() != "ok" {
		t.Fatalf("same-origin redirect: %q %v", buf.String(), err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"/loop", 16, Validators{}, &bytes.Buffer{}); !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("redirect loop: %v, want ErrRedirectRefused", err)
	}
}

func TestFetchConditionalNotModified(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` && r.Header.Get("If-Modified-Since") == "Tue, 10 Nov 2026 08:00:00 GMT" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("body"))
	})
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	res, err := f.Fetch(context.Background(), srv.URL, 16, Validators{ETag: `"v1"`, LastModified: "Tue, 10 Nov 2026 08:00:00 GMT"}, &buf)
	if err != nil || !res.NotModified || buf.Len() != 0 {
		t.Fatalf("%+v %v %q", res, err, buf.String())
	}
}

func TestFetchUnsolicitedNotModifiedRejected(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	f := newTestFetcher(t, pool, 0, srv)
	if _, err := f.Fetch(context.Background(), srv.URL, 16, Validators{}, &bytes.Buffer{}); !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("%v, want ErrHTTPStatus", err)
	}
}

func TestFetchHostileValidatorsDropped(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", strings.Repeat("e", MaxValidatorBytes+1))
		w.Header().Set("Last-Modified", "yesterday-ish")
		_, _ = w.Write([]byte("x"))
	})
	f := newTestFetcher(t, pool, 0, srv)
	res, err := f.Fetch(context.Background(), srv.URL, 16, Validators{}, &bytes.Buffer{})
	if err != nil || res.Validators != (Validators{}) {
		t.Fatalf("%+v %v", res.Validators, err)
	}
}

func TestFetchErrorStatusRejected(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-ish body", http.StatusInternalServerError)
	})
	f := newTestFetcher(t, pool, 0, srv)
	var buf bytes.Buffer
	_, err := f.Fetch(context.Background(), srv.URL, 1024, Validators{}, &buf)
	if !errors.Is(err, ErrHTTPStatus) || buf.Len() != 0 || strings.Contains(err.Error(), "secret-ish") {
		t.Fatalf("%v, buf %q", err, buf.String())
	}
}

func TestFetchUntrustedCertificateRejected(t *testing.T) {
	srv, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) })
	f := newTestFetcher(t, x509.NewCertPool(), 0, srv)
	if _, err := f.Fetch(context.Background(), srv.URL, 16, Validators{}, &bytes.Buffer{}); err == nil {
		t.Fatal("fetch from untrusted certificate succeeded")
	}
}

func TestFetchTimeout(t *testing.T) {
	release := make(chan struct{})
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	f := newTestFetcher(t, pool, 200*time.Millisecond, srv)
	start := time.Now()
	_, err := f.Fetch(context.Background(), srv.URL, 16, Validators{}, &bytes.Buffer{})
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout not enforced: %v after %v", err, time.Since(start))
	}
}

func TestFetcherIgnoresProxyEnvironment(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHits.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("direct")) })
	f := newTestFetcher(t, pool, 0, srv)
	if f.transport.Proxy != nil {
		t.Fatal("transport has a proxy function")
	}
	var buf bytes.Buffer
	if _, err := f.Fetch(context.Background(), srv.URL, 16, Validators{}, &buf); err != nil || buf.String() != "direct" {
		t.Fatalf("%q %v", buf.String(), err)
	}
	if proxyHits.Load() != 0 {
		t.Fatal("proxy saw a connection")
	}
}

func TestNewFetcherRequiresAllowlist(t *testing.T) {
	if _, err := NewFetcher(FetcherConfig{}); err == nil {
		t.Fatal("fetcher without allowlist accepted")
	}
}
