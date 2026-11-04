// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	testAvatars = "avatars.githubusercontent.com"
	testWiki    = "upload.wikimedia.org"
	publicIP    = "140.82.112.3"
)

// funcResolver answers through fn.
type funcResolver struct {
	fn func(host string) ([]netip.Addr, error)
}

func (r funcResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r.fn(host)
}

// publicResolver answers every host with a public address.
var publicResolver = funcResolver{fn: func(string) ([]netip.Addr, error) { return addrs(publicIP), nil }}

// testCert returns a self-signed certificate for the default icon hosts
// and a pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "iconfetch test"},
		DNSNames:              []string{testAvatars, testWiki},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// harness is one loopback TLS server posing as the icon hosts, and a
// client whose dial function sends every checked address to that server.
type harness struct {
	srv    *httptest.Server
	client *Client
	mu     sync.Mutex
	dialed []string
}

func (h *harness) dialedAddrs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dialed...)
}

func newHarness(t *testing.T, handler http.Handler, res Resolver, timeout time.Duration) *harness {
	t.Helper()
	cert, pool := testCert(t)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h := &harness{srv: srv}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, err := netip.ParseAddrPort(addr); err != nil {
			t.Errorf("dial got %q, want a checked IP:port", addr)
		}
		h.mu.Lock()
		h.dialed = append(h.dialed, addr)
		h.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	h.client = newClient(Config{Resolver: res}, options{dial: dial, rootCAs: pool, timeout: timeout})
	return h
}

func TestFetchReturnsBodyWithFixedHeaders(t *testing.T) {
	var got http.Header
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		if r.Host != testAvatars {
			t.Errorf("Host = %q", r.Host)
		}
		_, _ = w.Write([]byte("PNGDATA"))
	}), publicResolver, time.Second)
	body, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/u/1?v=4")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(body) != "PNGDATA" {
		t.Fatalf("body = %q", body)
	}
	if ua := got.Get("User-Agent"); ua != UserAgent {
		t.Errorf("User-Agent = %q, want %q", ua, UserAgent)
	}
	for _, k := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if v := got.Get(k); v != "" {
			t.Errorf("header %s = %q, want none", k, v)
		}
	}
	if d := h.dialedAddrs(); len(d) != 1 || d[0] != publicIP+":443" {
		t.Errorf("dialed %v, want [%s:443]", d, publicIP)
	}
}

func TestFetchRejectsBadURLWithoutDialing(t *testing.T) {
	h := newHarness(t, http.NotFoundHandler(), publicResolver, time.Second)
	for _, raw := range []string{"http://avatars.githubusercontent.com/u/1", "https://127.0.0.1/", "https://evil.example/"} {
		if _, err := h.client.Fetch(context.Background(), raw); !errors.Is(err, ErrURL) {
			t.Errorf("Fetch(%q) = %v, want ErrURL", raw, err)
		}
	}
	if d := h.dialedAddrs(); len(d) != 0 {
		t.Fatalf("dialed %v", d)
	}
}

func TestFetchFollowsUpToThreeRedirects(t *testing.T) {
	// /r/N redirects N more times, alternating hosts, then serves the icon.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/r/3":
			http.Redirect(w, r, "https://upload.wikimedia.org/r/2", http.StatusFound)
		case "/r/2":
			http.Redirect(w, r, "/r/1", http.StatusMovedPermanently) // relative
		case "/r/1":
			http.Redirect(w, r, "https://avatars.githubusercontent.com:443/r/0", http.StatusTemporaryRedirect)
		case "/r/0":
			_, _ = w.Write([]byte("ok"))
		case "/r/4":
			http.Redirect(w, r, "/r/3", http.StatusFound)
		}
	})
	h := newHarness(t, handler, publicResolver, time.Second)
	body, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/r/3")
	if err != nil || string(body) != "ok" {
		t.Fatalf("three redirects: body %q, err %v", body, err)
	}
	if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/r/4"); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("four redirects: err %v, want ErrTooManyRedirects", err)
	}
}

func TestFetchRedirectIsRevalidated(t *testing.T) {
	cases := []struct {
		name, location string
	}{
		{"private ip", "https://10.0.0.1/a.png"},
		{"loopback ip", "https://127.0.0.1/a.png"},
		{"metadata ip", "https://169.254.169.254/latest/meta-data/"},
		{"decimal ip", "https://2130706433/a.png"},
		{"ipv6 loopback", "https://[::1]/a.png"},
		{"http downgrade", "http://avatars.githubusercontent.com/a.png"},
		{"other port", "https://avatars.githubusercontent.com:8443/a.png"},
		{"off allowlist", "https://evil.example/a.png"},
		{"userinfo", "https://avatars.githubusercontent.com@evil.example/a.png"},
		{"trailing dot", "https://avatars.githubusercontent.com./a.png"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/start" {
					t.Errorf("redirect to %q was followed", c.location)
				}
				w.Header().Set("Location", c.location)
				w.WriteHeader(http.StatusFound)
			}), publicResolver, time.Second)
			if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/start"); !errors.Is(err, ErrURL) {
				t.Fatalf("err %v, want ErrURL", err)
			}
			if d := h.dialedAddrs(); len(d) != 1 {
				t.Fatalf("dialed %v, want only the first connection", d)
			}
		})
	}
}

func TestFetchRedirectToHostResolvingPrivateIsRefused(t *testing.T) {
	res := funcResolver{fn: func(host string) ([]netip.Addr, error) {
		if host == testWiki {
			return addrs("192.168.1.10"), nil
		}
		return addrs(publicIP), nil
	}}
	h := newHarness(t, http.RedirectHandler("https://upload.wikimedia.org/x.png", http.StatusFound), res, time.Second)
	if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/start"); !errors.Is(err, ErrAddress) {
		t.Fatalf("err %v, want ErrAddress", err)
	}
	if d := h.dialedAddrs(); len(d) != 1 {
		t.Fatalf("dialed %v, want only the first connection", d)
	}
}

func TestFetchDNSRebindingIsRefused(t *testing.T) {
	// The resolver answers public first, then 127.0.0.1. Every connection
	// resolves and checks again and dials only the checked address, so the
	// second answer is refused rather than reaching loopback.
	res := &stubResolver{answers: [][]netip.Addr{addrs(publicIP), addrs("127.0.0.1")}}
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/again", http.StatusFound)
			return
		}
		t.Errorf("rebound request to %s was served", r.URL.Path)
	}), res, time.Second)
	if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/start"); !errors.Is(err, ErrAddress) {
		t.Fatalf("err %v, want ErrAddress", err)
	}
	if d := h.dialedAddrs(); len(d) != 1 || d[0] != publicIP+":443" {
		t.Fatalf("dialed %v, want only %s:443", d, publicIP)
	}
	if res.calls != 2 {
		t.Fatalf("resolver calls = %d, want 2", res.calls)
	}
}

func TestFetchSendsNoCookiesAcrossRedirects(t *testing.T) {
	var second http.Header
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Path: "/"})
			http.Redirect(w, r, "/icon", http.StatusFound)
			return
		}
		second = r.Header.Clone()
		_, _ = w.Write([]byte("ok"))
	}), publicResolver, time.Second)
	if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/start"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if second.Get("Cookie") != "" || second.Get("Authorization") != "" {
		t.Fatalf("redirected request carried Cookie %q / Authorization %q", second.Get("Cookie"), second.Get("Authorization"))
	}
	if second.Get("User-Agent") != UserAgent {
		t.Fatalf("redirected User-Agent = %q", second.Get("User-Agent"))
	}
}

func TestFetchBodyLimit(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		chunked bool
		wantErr bool
	}{
		{"exactly max", MaxBodyBytes, false, false},
		{"exactly max chunked", MaxBodyBytes, true, false},
		{"one over with length", MaxBodyBytes + 1, false, true},
		{"one over chunked", MaxBodyBytes + 1, true, true},
		{"far over chunked", 4 * MaxBodyBytes, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data := bytes.Repeat([]byte("a"), c.size)
				if c.chunked {
					_, _ = w.Write(data[:1])
					w.(http.Flusher).Flush()
					_, _ = w.Write(data[1:])
					return
				}
				w.Header().Set("Content-Length", strconv.Itoa(c.size))
				_, _ = w.Write(data)
			}), publicResolver, 5*time.Second)
			body, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/big")
			if c.wantErr {
				if !errors.Is(err, ErrBodyTooLarge) {
					t.Fatalf("err %v, want ErrBodyTooLarge", err)
				}
				if body != nil {
					t.Fatalf("got %d bytes with error", len(body))
				}
				return
			}
			if err != nil || len(body) != c.size {
				t.Fatalf("len %d, err %v", len(body), err)
			}
		})
	}
}

func TestFetchSlowBodyTimesOut(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), publicResolver, 200*time.Millisecond)
	start := time.Now()
	_, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/slow")
	if err == nil {
		t.Fatal("slow body: no error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow body: err %v, want a deadline error", err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("slow body took %v", el)
	}
}

func TestFetchSlowHeadersTimesOut(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), publicResolver, 200*time.Millisecond)
	_, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/slow")
	if err == nil {
		t.Fatal("slow headers: no error")
	}
	// Either the request context or the transport's header timeout may
	// fire first; both are timeouts, unlike a TLS or dial failure.
	var ne net.Error
	if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &ne) || !ne.Timeout()) {
		t.Fatalf("slow headers: err %v, want a deadline error", err)
	}
}

func TestFetchOnlyStatus200(t *testing.T) {
	for _, code := range []int{http.StatusNoContent, http.StatusPartialContent, http.StatusNotModified, http.StatusNotFound, http.StatusInternalServerError, http.StatusMovedPermanently} {
		h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code) // 301 without Location is not followed
		}), publicResolver, time.Second)
		if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/x"); !errors.Is(err, ErrStatus) {
			t.Errorf("status %d: err %v, want ErrStatus", code, err)
		}
	}
}

func TestFetchUntrustedCertificateFails(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), publicResolver, time.Second)
	h.client = newClient(Config{Resolver: publicResolver}, options{
		dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", h.srv.Listener.Addr().String())
		},
		rootCAs: x509.NewCertPool(),
		timeout: time.Second,
	})
	if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/x"); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestFetchIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}), publicResolver, time.Second)
	if _, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/x"); err != nil {
		t.Fatalf("Fetch with proxy env: %v", err)
	}
}

func TestNewUsesProductionDefaults(t *testing.T) {
	c := New(Config{})
	if c.hc.Timeout != TotalTimeout {
		t.Errorf("timeout = %v, want %v", c.hc.Timeout, TotalTimeout)
	}
	if c.hc.Jar != nil {
		t.Error("cookie jar set")
	}
	tr, ok := c.hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.hc.Transport)
	}
	if tr.Proxy != nil {
		t.Error("proxy function set")
	}
	if tr.DialContext == nil || tr.DialTLSContext != nil {
		t.Error("dial hooks not exactly the pinning dialer")
	}
}

// TestNewRefusesInternalAnswer drives the production client from New: a
// resolver answering 127.0.0.1 must end in ErrAddress, never a connect.
func TestNewRefusesInternalAnswer(t *testing.T) {
	var calls int
	res := funcResolver{fn: func(string) ([]netip.Addr, error) {
		calls++
		return addrs("127.0.0.1"), nil
	}}
	_, err := New(Config{Resolver: res}).Fetch(context.Background(), "https://avatars.githubusercontent.com/x")
	if !errors.Is(err, ErrAddress) {
		t.Fatalf("Fetch error = %v, want ErrAddress", err)
	}
	if calls == 0 {
		t.Fatal("New did not route the connect through the configured resolver")
	}
}

func TestDefaultAllowlistIsACopy(t *testing.T) {
	a := DefaultAllowlist()
	if len(a) == 0 {
		t.Fatal("empty default allowlist")
	}
	a[0] = "evil.example"
	_ = append(a, "evil2.example")
	if _, err := ValidateURL("https://evil.example/x", nil); !errors.Is(err, ErrURL) {
		t.Fatalf("mutating the returned allowlist widened the policy: %v", err)
	}
	if DefaultAllowlist()[0] == "evil.example" {
		t.Fatal("DefaultAllowlist returned shared storage")
	}
}

// eofAfterDeadline simulates the transport race behind the flaky slow-body
// test: the response body ends with a clean io.EOF only after the request
// context has expired, as when the stream is torn down at the deadline.
type eofAfterDeadline struct{}

func (eofAfterDeadline) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		ContentLength: -1,
		Body:          &ctxEOFBody{ctx: r.Context(), data: []byte("partial")},
		Request:       r,
	}, nil
}

type ctxEOFBody struct {
	ctx  context.Context
	data []byte
}

func (b *ctxEOFBody) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	<-b.ctx.Done()
	return 0, io.EOF
}

func (b *ctxEOFBody) Close() error { return nil }

func TestFetchCleanEOFAfterDeadline(t *testing.T) {
	h := newHarness(t, http.NotFoundHandler(), publicResolver, 200*time.Millisecond)
	h.client.hc.Transport = eofAfterDeadline{}
	body, err := h.client.Fetch(context.Background(), "https://avatars.githubusercontent.com/slow")
	if err == nil {
		t.Fatalf("truncated body returned as success: %q", body)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want a deadline error", err)
	}
	if body != nil {
		t.Fatalf("got %d bytes with error", len(body))
	}
}
