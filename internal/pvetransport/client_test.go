// SPDX-License-Identifier: AGPL-3.0-or-later

package pvetransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// serverCert creates a server certificate (with private key) signed by the
// CA for use with httptest TLS servers.
func (ca *testCA) serverCert(t *testing.T, spec leafSpec) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate(spec), ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func newTLSServer(t *testing.T, cert tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newTestClient(t *testing.T, opts Options) *http.Client {
	t.Helper()
	client, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func okHandler(hits *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*hits++
		fmt.Fprintln(w, "ok")
	}
}

// deadEndpoint returns an https URL whose port is not listening.
func deadEndpoint(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "https://" + addr
}

func TestCAPinRoundTrip(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var hits int
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&hits))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	resp, err := client.Get(srv.URL + "/api/json/version")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok\n" {
		t.Fatalf("body = %q", body)
	}
	if hits != 1 {
		t.Fatalf("server hits = %d, want 1", hits)
	}
}

func TestLeafPinRoundTrip(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	cert := ca.serverCert(t, leafSpec{ips: []net.IP{loopback}})
	leaf := parseCert(t, cert.Certificate[0])
	srv := newTLSServer(t, cert, okHandler(new(int)))
	client := newTestClient(t, Options{
		Trust:     Trust{LeafFingerprint: Fingerprint(leaf)},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestWrongPinFails(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	other := newTestCA(t, "other-ca")
	cert := ca.serverCert(t, leafSpec{ips: []net.IP{loopback}})
	srv := newTLSServer(t, cert, okHandler(new(int)))
	endpoint := mustParseURL(t, srv.URL)

	// Wrong CA: the served leaf chains to a different root.
	client := newTestClient(t, Options{Trust: Trust{CA: other.cert}, Endpoints: []*url.URL{endpoint}})
	if _, err := client.Get(srv.URL + "/x"); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("wrong CA: err = %v, want ErrTrustMismatch", err)
	}

	// Wrong leaf fingerprint: same CA, different pin.
	client = newTestClient(t, Options{Trust: Trust{LeafFingerprint: [32]byte{1}}, Endpoints: []*url.URL{endpoint}})
	if _, err := client.Get(srv.URL + "/x"); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("wrong leaf pin: err = %v, want ErrTrustMismatch", err)
	}
}

func TestExpiredCertFails(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	now := time.Now()
	cert := ca.serverCert(t, leafSpec{
		ips:       []net.IP{loopback},
		notBefore: now.Add(-2 * time.Hour),
		notAfter:  now.Add(-time.Hour),
	})
	srv := newTLSServer(t, cert, okHandler(new(int)))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	if _, err := client.Get(srv.URL + "/x"); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("expired cert: err = %v, want ErrTrustMismatch", err)
	}
}

func TestWrongSANFails(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	// The leaf has only a DNS SAN; the endpoint is an IP.
	cert := ca.serverCert(t, leafSpec{dnsNames: []string{"other.example.com"}})
	srv := newTLSServer(t, cert, okHandler(new(int)))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	if _, err := client.Get(srv.URL + "/x"); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("wrong SAN: err = %v, want ErrTrustMismatch", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	resp, err := client.Get(srv.URL + "/x")
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("redirect: err = %v, want ErrRedirect", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
}

func TestRedirectRefusedByBothConstructors(t *testing.T) {
	for _, constructor := range []string{"NewClient", "NewRoundTripper"} {
		for _, status := range []int{300, 301, 302, 303, 304, 305, 307, 308} {
			t.Run(fmt.Sprintf("%s/%d", constructor, status), func(t *testing.T) {
				ca := newTestCA(t, "pve-root-ca")
				var hits atomic.Int32
				srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if hits.Add(1) > 1 {
						w.WriteHeader(http.StatusOK)
						return
					}
					w.Header().Set("Location", "/elsewhere")
					w.WriteHeader(status)
				}))
				var fallbackHits atomic.Int32
				fallback := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fallbackHits.Add(1)
				}))
				opts := Options{Trust: Trust{CA: ca.cert}, Endpoints: []*url.URL{mustParseURL(t, srv.URL), mustParseURL(t, fallback.URL)}}
				req, err := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
				if err != nil {
					t.Fatal(err)
				}
				var resp *http.Response
				if constructor == "NewClient" {
					client := newTestClient(t, opts)
					t.Cleanup(client.CloseIdleConnections)
					resp, err = client.Do(req)
				} else {
					var rt http.RoundTripper
					rt, err = NewRoundTripper(opts)
					if err != nil {
						t.Fatal(err)
					}
					resp, err = rt.RoundTrip(req)
				}
				if resp != nil {
					resp.Body.Close()
				}
				if !errors.Is(err, ErrRedirect) {
					t.Fatalf("redirect: err = %v, want ErrRedirect", err)
				}
				if hits.Load() != 1 || fallbackHits.Load() != 0 {
					t.Fatalf("redirect followed or failed over: hits = %d, fallback hits = %d", hits.Load(), fallbackHits.Load())
				}
			})
		}
	}
}

func TestMalformedCertificateChainStopsFailover(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, malformed := range []string{"leaf", "intermediate"} {
			for _, pin := range []string{"CA", "leaf"} {
				t.Run(fmt.Sprintf("TLS%x/%s/%s", version, malformed, pin), func(t *testing.T) {
					ca := newTestCA(t, "pve-root-ca")
					cert := ca.serverCert(t, leafSpec{ips: []net.IP{loopback}})
					cert.Leaf = parseCert(t, cert.Certificate[0])
					goodCert := cert
					cert.Certificate = append([][]byte(nil), cert.Certificate...)
					trust := Trust{CA: ca.cert}
					if pin == "leaf" {
						trust = Trust{LeafFingerprint: Fingerprint(cert.Leaf)}
					}
					if malformed == "leaf" {
						cert.Certificate[0] = []byte{0x30, 0x00}
					} else {
						cert.Certificate = append(cert.Certificate, []byte{0x30, 0x00})
					}
					var badHits, goodHits atomic.Int32
					bad := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						badHits.Add(1)
					}))
					bad.TLS = &tls.Config{
						Certificates: []tls.Certificate{goodCert}, MinVersion: version, MaxVersion: version,
						// httptest parses its initial leaf; serve the malformed
						// chain only during the actual client handshake.
						GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
							return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version}, nil
						},
					}
					bad.StartTLS()
					t.Cleanup(bad.Close)
					good := newTLSServer(t, goodCert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						goodHits.Add(1)
					}))
					client := newTestClient(t, Options{Trust: trust, Endpoints: []*url.URL{mustParseURL(t, bad.URL), mustParseURL(t, good.URL)}})
					resp, err := client.Get(bad.URL + "/x")
					if resp != nil {
						resp.Body.Close()
					}
					if !errors.Is(err, ErrTrustMismatch) {
						t.Fatalf("malformed chain: err = %v, want ErrTrustMismatch", err)
					}
					if badHits.Load() != 0 || goodHits.Load() != 0 {
						t.Fatalf("request sent after malformed chain: bad hits = %d, good hits = %d", badHits.Load(), goodHits.Load())
					}
				})
			}
		}
	}
}

func TestFlushedHeadersAllowDelayedResponseBody(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	release := make(chan struct{})
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "delayed content")
	}))
	// Release the handler even if obtaining the response fails.
	t.Cleanup(func() { close(release) })
	client := newTestClient(t, Options{Trust: Trust{CA: ca.cert}, Endpoints: []*url.URL{mustParseURL(t, srv.URL)}})
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The body is sent only after RoundTrip has returned the headers.
	release <- struct{}{}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read delayed body: %v", err)
	}
	if string(body) != "delayed content" {
		t.Fatalf("body = %q, want delayed content", body)
	}
}

func TestStalledTLSHandshakeClosesConnectionAfterRequestTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		accepted <- conn
		_, err = io.Copy(io.Discard, conn)
		closed <- err
	}()
	ca := newTestCA(t, "pve-root-ca")
	endpoint := "https://" + listener.Addr().String()
	client := newTestClient(t, Options{
		Trust: Trust{CA: ca.cert}, Endpoints: []*url.URL{mustParseURL(t, endpoint)}, Timeout: 200 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("client did not connect")
	}
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("request: err = %v, want DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not time out")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("peer read: %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS connection remained open after request timeout")
	}
}

func TestFailoverOrder(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var hits int
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&hits))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, deadEndpoint(t)), mustParseURL(t, srv.URL)},
		Timeout:   5 * time.Second,
	})
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatalf("server hits = %d, want 1", hits)
	}
}

func TestTrustMismatchStopsFailover(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	other := newTestCA(t, "other-ca")
	// First endpoint serves a certificate from a different CA.
	wrongSrv := newTLSServer(t, other.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(new(int)))
	var goodHits int
	goodSrv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&goodHits))
	client := newTestClient(t, Options{
		Trust: Trust{CA: ca.cert},
		Endpoints: []*url.URL{
			mustParseURL(t, wrongSrv.URL),
			mustParseURL(t, goodSrv.URL),
		},
	})
	_, err := client.Get(goodSrv.URL + "/x")
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("err = %v, want ErrTrustMismatch", err)
	}
	if goodHits != 0 {
		t.Fatalf("failover happened after trust mismatch: %d hits on good endpoint", goodHits)
	}
}

func TestEnvironmentProxyIgnored(t *testing.T) {
	var proxyHits int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)

	ca := newTestCA(t, "pve-root-ca")
	var hits int
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&hits))
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
	})
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatalf("direct server hits = %d, want 1", hits)
	}
	if proxyHits != 0 {
		t.Fatalf("proxy hits = %d, want 0", proxyHits)
	}
}

func TestAuthAttachedOnlyAfterTrust(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	other := newTestCA(t, "other-ca")
	var authCalls int
	var seenAuth string
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		fmt.Fprintln(w, "ok")
	}))
	auth := func(ctx context.Context) (string, error) {
		authCalls++
		return "PVEAPIToken=admin@pam!tok", nil
	}
	client := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, srv.URL)},
		Auth:      auth,
	})
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if authCalls != 1 {
		t.Fatalf("auth calls = %d, want 1", authCalls)
	}
	if seenAuth != "PVEAPIToken=admin@pam!tok" {
		t.Fatalf("Authorization header = %q", seenAuth)
	}

	// Trust mismatch: the request, including the Authorization header,
	// must never be written to the endpoint. The server handler must
	// never see the request.
	var wrongHits int
	wrongSrv := newTLSServer(t, other.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&wrongHits))
	client2 := newTestClient(t, Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, wrongSrv.URL)},
		Auth:      auth,
	})
	if _, err := client2.Get(wrongSrv.URL + "/x"); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("err = %v, want ErrTrustMismatch", err)
	}
	if wrongHits != 0 {
		t.Fatalf("request written before trust was verified: %d hits on untrusted endpoint", wrongHits)
	}
}

func TestResponseSizeLimit(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	body := make([]byte, 1024+1)
	for i := range body {
		body[i] = byte(i)
	}
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))

	client := newTestClient(t, Options{
		Trust:            Trust{CA: ca.cert},
		Endpoints:        []*url.URL{mustParseURL(t, srv.URL)},
		MaxResponseBytes: 1024,
	})
	resp, err := client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("read: err = %v, want ErrResponseTooLarge", err)
	}

	// A body exactly at the limit passes.
	client = newTestClient(t, Options{
		Trust:            Trust{CA: ca.cert},
		Endpoints:        []*url.URL{mustParseURL(t, srv.URL)},
		MaxResponseBytes: 1025,
	})
	resp, err = client.Get(srv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read at exact limit: %v", err)
	}
	if len(got) != 1025 {
		t.Fatalf("len = %d, want 1025", len(got))
	}
}

func TestRequestSizeLimit(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	var hits int
	srv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&hits))
	client := newTestClient(t, Options{
		Trust:           Trust{CA: ca.cert},
		Endpoints:       []*url.URL{mustParseURL(t, srv.URL)},
		MaxRequestBytes: 16,
	})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/x", bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(req); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("Do: err = %v, want ErrRequestTooLarge", err)
	}
	if hits != 0 {
		t.Fatalf("server hits = %d, want 0 (oversized request must not be sent)", hits)
	}
}

func TestTimeoutFailover(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	slowSrv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		fmt.Fprintln(w, "slow")
	}))
	var hits int
	fastSrv := newTLSServer(t, ca.serverCert(t, leafSpec{ips: []net.IP{loopback}}), okHandler(&hits))
	client := newTestClient(t, Options{
		Trust: Trust{CA: ca.cert},
		Endpoints: []*url.URL{
			mustParseURL(t, slowSrv.URL),
			mustParseURL(t, fastSrv.URL),
		},
		Timeout: 300 * time.Millisecond,
	})
	resp, err := client.Get(fastSrv.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatalf("fast server hits = %d, want 1", hits)
	}
}

func TestNewClientValidation(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	if _, err := NewClient(Options{Trust: Trust{CA: ca.cert}}); !errors.Is(err, ErrNoEndpoints) {
		t.Fatalf("no endpoints: err = %v, want ErrNoEndpoints", err)
	}
	if _, err := NewClient(Options{
		Trust:     Trust{CA: ca.cert},
		Endpoints: []*url.URL{mustParseURL(t, "http://127.0.0.1:8006")},
	}); err == nil {
		t.Fatal("http endpoint accepted")
	}
	if _, err := NewClient(Options{
		Trust:     Trust{},
		Endpoints: []*url.URL{mustParseURL(t, "https://127.0.0.1:8006")},
	}); err == nil {
		t.Fatal("empty trust accepted")
	}
}

func TestParseEndpoint(t *testing.T) {
	u, err := ParseEndpoint("https://pve.example.com:8006")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if u.Host != "pve.example.com:8006" {
		t.Fatalf("host = %q", u.Host)
	}
	for _, bad := range []string{"http://pve.example.com", "https://", "pve.example.com", "ftp://x"} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) accepted", bad)
		}
	}
}
