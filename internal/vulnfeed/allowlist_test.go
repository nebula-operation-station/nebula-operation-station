// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestOriginOfCanonicalises(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://example.com", "https://example.com:443"},
		{"https://example.com/path?q=1#f", "https://example.com:443"},
		{"https://Example.COM/x", "https://example.com:443"},
		{"HTTPS://example.com", "https://example.com:443"},
		{"https://example.com:443/", "https://example.com:443"},
		{"https://example.com:8443/", "https://example.com:8443"},
		{"https://127.0.0.1:1234", "https://127.0.0.1:1234"},
		{"https://[::1]/", "https://[::1]:443"},
	} {
		got, err := OriginOf(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("OriginOf(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestOriginOfRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"https://",
		"https:///path",
		"http://example.com",
		"ftp://example.com",
		"example.com",
		"https:example.com",
		"https://example.com./",
		"https://EXAMPLE.COM./",
		"https://user@example.com/",
		"https://user:pw@example.com/",
		"https://:@example.com/",
		"https://exa mple.com/",
		"https://example.com:notaport/",
	} {
		if o, err := OriginOf(in); !errors.Is(err, ErrOriginNotAllowed) {
			t.Errorf("OriginOf(%q) = %q, %v; want ErrOriginNotAllowed", in, o, err)
		}
	}
}

func TestNewAllowlistSizeLimits(t *testing.T) {
	if _, err := NewAllowlist(nil); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := NewAllowlist([]string{}); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("empty slice: %v", err)
	}
	many := make([]string, MaxAllowlistOrigins+1)
	for i := range many {
		many[i] = fmt.Sprintf("https://h%d.example", i)
	}
	if _, err := NewAllowlist(many); !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("oversized: %v", err)
	}
	if _, err := NewAllowlist(many[:MaxAllowlistOrigins]); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	for _, bad := range []string{"http://example.com", "https://u@example.com", "https://example.com.", ""} {
		if _, err := NewAllowlist([]string{"https://ok.example", bad}); !errors.Is(err, ErrOriginNotAllowed) {
			t.Errorf("entry %q: %v", bad, err)
		}
	}
}

func TestAllowlistMatchesCanonicalOrigins(t *testing.T) {
	al, err := NewAllowlist([]string{"https://Feeds.Example/data.json", "https://alt.example:8443"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"https://feeds.example/x", true},
		{"https://FEEDS.example/x", true},
		{"https://feeds.example:443/x", true},
		{"https://alt.example:8443/y", true},
		{"https://alt.example/y", false},        // default port is 443, not 8443
		{"https://feeds.example:8443/x", false}, // other port
		{"https://feeds.example./x", false},     // trailing dot
		{"https://u:p@feeds.example/x", false},  // userinfo
		{"http://feeds.example/x", false},       // scheme
		{"https://evil.feeds.example/x", false}, // no suffix match
		{"https://feeds.example.evil/x", false}, // no prefix match
		{"https://127.0.0.1/x", false},          // no IP mapping
	} {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := al.Allows(u); got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"feeds.example:443", true},
		{"FEEDS.EXAMPLE:443", true},
		{"alt.example:8443", true},
		{"feeds.example:80", false},
		{"feeds.example.:443", false},
		{"feeds.example", false},
		{"alt.example:443", false},
		{"127.0.0.1:443", false},
		{"", false},
	} {
		if got := al.allowsAddr(tc.addr); got != tc.want {
			t.Errorf("allowsAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// TestDialRefusesNonAllowlistedAddress bypasses the URL check in Fetch by
// using the fetcher's client directly: only the dialer's allowlist check
// stands between the request and the non-allowlisted server.
func TestDialRefusesNonAllowlistedAddress(t *testing.T) {
	var hits atomic.Int32
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {})
	other, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	pool.AddCert(other.Certificate())
	f := newTestFetcher(t, pool, 0, srv)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, other.URL+"/feed", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := f.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("dial to non-allowlisted address succeeded")
	}
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("%v, want ErrOriginNotAllowed", err)
	}
	if hits.Load() != 0 {
		t.Fatal("non-allowlisted server was reached")
	}
}

// TestDialRefusesRedirectWhenRedirectCheckBypassed disables the redirect
// policy so that a redirect to another origin reaches the transport; the
// dialer must still refuse it.
func TestDialRefusesRedirectWhenRedirectCheckBypassed(t *testing.T) {
	var hits atomic.Int32
	other, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("evil"))
	})
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/feed", http.StatusFound)
	})
	pool.AddCert(other.Certificate())
	f := newTestFetcher(t, pool, 0, srv)
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	var buf bytes.Buffer
	_, err := f.Fetch(context.Background(), srv.URL+"/feed", 1<<10, Validators{}, &buf)
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("%v, want ErrOriginNotAllowed", err)
	}
	if hits.Load() != 0 || buf.Len() != 0 {
		t.Fatal("redirect target was reached")
	}
}

// TestDialRefusesRewrittenDialAddress: a URL whose host is an allowlisted
// name but whose dial address is rewritten at the transport (here via a
// proxy setting, standing in for a resolver or configuration trick) to
// another host:port is refused at dial.
func TestDialRefusesRewrittenDialAddress(t *testing.T) {
	var hits atomic.Int32
	other, _ := tlsServer(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {})
	pool.AddCert(other.Certificate())
	f := newTestFetcher(t, pool, 0, srv)
	// The allowlisted URL passes Fetch's check; the transport is pointed at
	// the other server's address, as a hostile resolver or proxy would.
	otherURL, err := url.Parse(other.URL)
	if err != nil {
		t.Fatal(err)
	}
	f.transport.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: otherURL.Host})
	_, err = f.Fetch(context.Background(), srv.URL+"/feed", 1<<10, Validators{}, &bytes.Buffer{})
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("%v, want ErrOriginNotAllowed", err)
	}
	if hits.Load() != 0 {
		t.Fatal("rewritten dial address was reached")
	}
}
