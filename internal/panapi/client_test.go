// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
)

// testKey is a synthetic API key. Every test asserts that it never shows
// up in an error or a log line.
const testKey = "LUFRPT1-synthetic-test-key-0123456789abcdefABCDEF="

const okBody = `<?xml version="1.0"?><response status="success"><result><system><hostname>fw</hostname></system></result></response>`

// allowLoopback is the test address policy: the loopback test server is the
// only address a test client may dial.
func allowLoopback(a netip.Addr) error {
	if a.Unmap().IsLoopback() {
		return nil
	}
	return CheckManagementAddr(a)
}

// recorded is what the test server saw of one request.
type recorded struct {
	method, path, rawQuery, contentType, panKey, auth, body string
}

// testServer is a loopback TLS server counting the requests it receives.
type testServer struct {
	*httptest.Server
	hits atomic.Int32
	last atomic.Pointer[recorded]
}

func newTestServer(t *testing.T, cert *tls.Certificate, h http.HandlerFunc) *testServer {
	t.Helper()
	ts := &testServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		ts.last.Store(&recorded{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			contentType: r.Header.Get("Content-Type"), panKey: r.Header.Get("X-PAN-KEY"),
			auth: r.Header.Get("Authorization"), body: string(b),
		})
		h(w, r)
	}))
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	ts.Server = srv
	return ts
}

func (ts *testServer) endpoint(t *testing.T) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ap
}

func (ts *testServer) leafPin() pvetransport.Trust {
	return pvetransport.Trust{LeafFingerprint: pvetransport.Fingerprint(ts.Certificate())}
}

func replyXML(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, body)
	}
}

func newTestClient(t *testing.T, opts Options) *Client {
	t.Helper()
	if opts.Key == nil {
		opts.Key = func(context.Context) (string, error) { return testKey, nil }
	}
	c, err := newClient(opts, allowLoopback)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// assertNoKey fails if the test key appears in s.
func assertNoKey(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(s, testKey) || strings.Contains(s, testKey[:16]) {
		t.Fatalf("%s contains the API key", what)
	}
}

func TestSystemInfoSendsKeyInHeaderOnly(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	resp, err := c.Do(context.Background(), SystemInfoRequest())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != okBody {
		t.Fatalf("body = %q", resp.Body)
	}
	got := ts.last.Load()
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/api/" || got.rawQuery != "" {
		t.Errorf("URL = %s?%s, want /api/ without query", got.path, got.rawQuery)
	}
	if got.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("content type = %q", got.contentType)
	}
	if got.panKey != testKey {
		t.Errorf("X-PAN-KEY header not set to the key")
	}
	if got.auth != "" {
		t.Errorf("Authorization header set")
	}
	assertNoKey(t, "request body", got.body)
	assertNoKey(t, "request query", got.rawQuery)
	form, err := url.ParseQuery(got.body)
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("type") != "op" || form.Get("cmd") != cmdSystemInfo || form.Has("key") {
		t.Errorf("form = %v", form)
	}
}

func TestEntryRequestPostsFixedXPath(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	req, err := RunningEntryRequest(SubtreeSecurityRules, "allow dns")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(ts.last.Load().body)
	want := xpathVsys + "/rulebase/security/rules/entry[@name='allow dns']"
	if form.Get("type") != "config" || form.Get("action") != "show" || form.Get("xpath") != want {
		t.Fatalf("form = %v", form)
	}
}

func TestLeafPinMismatchSendsNothing(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	var wrong [32]byte
	wrong[0] = 1
	var buf bytes.Buffer
	c := newTestClient(t, Options{
		Endpoint: ts.endpoint(t),
		Trust:    pvetransport.Trust{LeafFingerprint: wrong},
		Logger:   slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	_, err := c.Do(context.Background(), SystemInfoRequest())
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("err = %v, want ErrTrustMismatch", err)
	}
	if n := ts.hits.Load(); n != 0 {
		t.Fatalf("server received %d requests before trust", n)
	}
	assertNoKey(t, "error", err.Error())
	assertNoKey(t, "log", buf.String())
	if !strings.Contains(buf.String(), "error=trust_mismatch") {
		t.Fatalf("log lacks error class: %s", buf.String())
	}
}

// testCA is an in-memory CA for CA-pin tests.
type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: priv}
}

func (ca *testCA) leaf(t *testing.T, dns []string, ips []net.IP) *tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dns,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func TestCAPin(t *testing.T) {
	ca := newTestCA(t)
	ts := newTestServer(t, ca.leaf(t, nil, []net.IP{net.IPv4(127, 0, 0, 1)}), replyXML(okBody))

	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: pvetransport.Trust{CA: ca.cert}})
	if _, err := c.Do(context.Background(), SystemInfoRequest()); err != nil {
		t.Fatalf("pinned CA: %v", err)
	}

	other := newTestCA(t)
	c2 := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: pvetransport.Trust{CA: other.cert}})
	before := ts.hits.Load()
	_, err := c2.Do(context.Background(), SystemInfoRequest())
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("other CA: err = %v, want ErrTrustMismatch", err)
	}
	if ts.hits.Load() != before {
		t.Fatal("request reached the server under a foreign CA")
	}
}

func TestSANIsChecked(t *testing.T) {
	ca := newTestCA(t)
	ts := newTestServer(t, ca.leaf(t, []string{"fw.lab.internal"}, nil), replyXML(okBody))
	trust := pvetransport.Trust{CA: ca.cert}

	ok := newTestClient(t, Options{Endpoint: ts.endpoint(t), ServerName: "fw.lab.internal", Trust: trust})
	if _, err := ok.Do(context.Background(), SystemInfoRequest()); err != nil {
		t.Fatalf("matching DNS SAN: %v", err)
	}
	for _, name := range []string{"", "other.lab.internal"} {
		c := newTestClient(t, Options{Endpoint: ts.endpoint(t), ServerName: name, Trust: trust})
		if _, err := c.Do(context.Background(), SystemInfoRequest()); !errors.Is(err, ErrTrustMismatch) {
			t.Fatalf("server name %q: err = %v, want ErrTrustMismatch", name, err)
		}
	}
	if n := ts.hits.Load(); n != 1 {
		t.Fatalf("server hits = %d, want 1", n)
	}
}

func TestExpiredCertificateRefused(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	c := newTestClient(t, Options{
		Endpoint: ts.endpoint(t),
		Trust:    ts.leafPin(),
		Now:      func() time.Time { return ts.Certificate().NotAfter.Add(time.Hour) },
	})
	if _, err := c.Do(context.Background(), SystemInfoRequest()); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("err = %v, want ErrTrustMismatch", err)
	}
	if ts.hits.Load() != 0 {
		t.Fatal("request sent with an expired certificate")
	}
}

func TestRedirectRefused(t *testing.T) {
	target := newTestServer(t, nil, replyXML(okBody))
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusNotModified} {
		ts := newTestServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/api/", code)
		})
		c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
		_, err := c.Do(context.Background(), SystemInfoRequest())
		if !errors.Is(err, ErrRedirect) {
			t.Fatalf("HTTP %d: err = %v, want ErrRedirect", code, err)
		}
		assertNoKey(t, "error", err.Error())
	}
	if target.hits.Load() != 0 {
		t.Fatal("redirect was followed")
	}
}

func TestEnvironmentProxyIgnored(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits.Add(1) }))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	ts := newTestServer(t, nil, replyXML(okBody))
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	if _, err := c.Do(context.Background(), SystemInfoRequest()); err != nil {
		t.Fatal(err)
	}
	if proxyHits.Load() != 0 || ts.hits.Load() != 1 {
		t.Fatalf("proxy hits %d, server hits %d", proxyHits.Load(), ts.hits.Load())
	}
}

// sizedBody returns a valid success response of exactly n bytes, padded
// with a comment.
func sizedBody(t *testing.T, n int64) string {
	t.Helper()
	const head, tail = `<response status="success"><result><!--`, `--></result></response>`
	pad := n - int64(len(head)+len(tail))
	if pad < 0 {
		t.Fatal("size too small")
	}
	return head + strings.Repeat("x", int(pad)) + tail
}

func TestResponseCaps(t *testing.T) {
	cfg, err := RunningConfigRequest(SubtreeVsys)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		desc string
		req  Request
		size int64
		ok   bool
	}{
		{"other at limit", SystemInfoRequest(), MaxOtherResponseBytes, true},
		{"other over limit", SystemInfoRequest(), MaxOtherResponseBytes + 1, false},
		{"config at limit", cfg, MaxConfigResponseBytes, true},
		{"config over limit", cfg, MaxConfigResponseBytes + 1, false},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			ts := newTestServer(t, nil, replyXML(sizedBody(t, tc.size)))
			c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
			resp, err := c.Do(context.Background(), tc.req)
			if tc.ok {
				if err != nil || int64(len(resp.Body)) != tc.size {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("err = %v, want ErrResponseTooLarge", err)
			}
		})
	}
}

func nested(depth int) string {
	// The <response> root is level 1.
	inner := strings.Repeat("<a>", depth-1) + strings.Repeat("</a>", depth-1)
	return `<response status="success">` + inner + `</response>`
}

func TestCheckResponseXMLLimits(t *testing.T) {
	elems := func(n int) string {
		return `<response status="success">` + strings.Repeat("<e/>", n-1) + `</response>`
	}
	for _, tc := range []struct {
		desc string
		body string
		want error
	}{
		{"depth at limit", nested(MaxXMLDepth), nil},
		{"depth over limit", nested(MaxXMLDepth + 1), ErrXMLLimit},
		{"elements at limit", elems(MaxXMLElements), nil},
		{"elements over limit", elems(MaxXMLElements + 1), ErrXMLLimit},
		{"text at limit", `<response status="success"><t>` + strings.Repeat("x", MaxXMLTextBytes) + `</t></response>`, nil},
		{"text over limit", `<response status="success"><t>` + strings.Repeat("x", MaxXMLTextBytes+1) + `</t></response>`, ErrXMLLimit},
		{"split text over limit", `<response status="success"><t>` + strings.Repeat("x", MaxXMLTextBytes) + `<![CDATA[y]]></t></response>`, ErrXMLLimit},
		{"attribute at limit", `<response status="success"><t a="` + strings.Repeat("x", MaxXMLTextBytes) + `"/></response>`, nil},
		{"attribute over limit", `<response status="success"><t a="` + strings.Repeat("x", MaxXMLTextBytes+1) + `"/></response>`, ErrXMLLimit},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := checkResponse([]byte(tc.body))
			if tc.want == nil && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestXMLLimitOverHTTP(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(nested(MaxXMLDepth+1)))
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	if _, err := c.Do(context.Background(), SystemInfoRequest()); !errors.Is(err, ErrXMLLimit) {
		t.Fatalf("err = %v, want ErrXMLLimit", err)
	}
}

// marker is device-supplied text that must never reach an error.
const marker = "DEVICE-SECRET-MARKER"

func TestMalformedResponsesRefused(t *testing.T) {
	for _, tc := range []struct{ desc, body string }{
		{"empty", ""},
		{"not xml", "hello " + marker},
		{"invalid utf-8", `<response status="success"><r>` + "\xff\xfe" + marker + `</r></response>`},
		{"doctype", `<!DOCTYPE response [<!ENTITY x "` + marker + `">]><response status="success">&x;</response>`},
		{"undefined entity", `<response status="success">&` + marker + `;</response>`},
		{"wrong root", `<` + marker + ` status="success"/>`},
		{"namespaced root", `<x:response xmlns:x="urn:x" status="success"/>`},
		{"missing status", `<response><msg>` + marker + `</msg></response>`},
		{"unknown status", `<response status="` + marker + `"/>`},
		{"second root", `<response status="success"/><response status="success"/>`},
		{"text after root", `<response status="success"/>` + marker},
		{"truncated", `<response status="success"><result><a>` + marker},
		{"mismatched tags", `<response status="success"><a></` + marker + `></response>`},
		{"latin-1 declaration", `<?xml version="1.0" encoding="ISO-8859-1"?><response status="success"/>`},
		{"late processing instruction", `<response status="success"><?` + marker + ` x?></response>`},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := checkResponse([]byte(tc.body))
			if !errors.Is(err, ErrMalformedResponse) {
				t.Fatalf("err = %v, want ErrMalformedResponse", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("error carries device text: %v", err)
			}
		})
	}
}

func TestAPIErrorKeepsNumericCodeOnly(t *testing.T) {
	for _, tc := range []struct{ code, want string }{
		{"403", "403"},
		{"17", "17"},
		{marker, ""},
		{"1234567", ""},
		{"", ""},
	} {
		body := `<response status="error" code="` + tc.code + `"><msg><line>` + marker + ` ` + testKey + `</line></msg></response>`
		ts := newTestServer(t, nil, replyXML(body))
		c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
		_, err := c.Do(context.Background(), SystemInfoRequest())
		var apiErr *APIError
		if !errors.As(err, &apiErr) || !errors.Is(err, ErrAPIStatus) {
			t.Fatalf("code %q: err = %v, want *APIError", tc.code, err)
		}
		if apiErr.Code != tc.want {
			t.Fatalf("code %q: Code = %q, want %q", tc.code, apiErr.Code, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("error carries the device message: %v", err)
		}
		assertNoKey(t, "error", err.Error())
	}
}

func TestHTTPErrorStatusBodyDiscarded(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrUnauthorized},
		{http.StatusInternalServerError, ErrHTTPStatus},
		{http.StatusNoContent, ErrHTTPStatus},
	} {
		ts := newTestServer(t, nil, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, `<response status="error"><msg>`+marker+`</msg></response>`)
		})
		c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
		_, err := c.Do(context.Background(), SystemInfoRequest())
		if !errors.Is(err, tc.want) {
			t.Fatalf("HTTP %d: err = %v, want %v", tc.status, err, tc.want)
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("error carries the body: %v", err)
		}
	}
}

func TestInvalidKeyNeverSent(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	for _, key := range []string{
		"",
		testKey + "\r\nX-Injected: 1",
		testKey + " ",
		testKey + "\x00",
		testKey + "ä",
		strings.Repeat("k", MaxKeyLength+1),
	} {
		c := newTestClient(t, Options{
			Endpoint: ts.endpoint(t),
			Trust:    ts.leafPin(),
			Key:      func(context.Context) (string, error) { return key, nil },
		})
		_, err := c.Do(context.Background(), SystemInfoRequest())
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("err = %v, want ErrInvalidKey", err)
		}
		assertNoKey(t, "error", err.Error())
		if key != "" && strings.Contains(err.Error(), key[:8]) {
			t.Fatal("error contains part of the key")
		}
	}
	if ts.hits.Load() != 0 {
		t.Fatal("invalid key was sent")
	}
}

func TestKeySourceFailureSendsNothing(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	locked := errors.New("vault locked")
	c := newTestClient(t, Options{
		Endpoint: ts.endpoint(t),
		Trust:    ts.leafPin(),
		Key:      func(context.Context) (string, error) { return "", locked },
	})
	_, err := c.Do(context.Background(), SystemInfoRequest())
	if !errors.Is(err, ErrKeyUnavailable) || !errors.Is(err, locked) {
		t.Fatalf("err = %v", err)
	}
	if ts.hits.Load() != 0 {
		t.Fatal("request sent without a key")
	}
}

// TestKeyNeverInErrorsOrLogs drives every outcome through one logger and
// asserts that neither errors nor log output contain the key.
func TestKeyNeverInErrorsOrLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handlers := []http.HandlerFunc{
		replyXML(okBody),
		replyXML(`<response status="error" code="22"><msg>` + testKey + `</msg></response>`),
		replyXML(nested(MaxXMLDepth + 1)),
		replyXML("not xml " + testKey),
		replyXML(sizedBody(t, MaxOtherResponseBytes+1)),
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, testKey)
		},
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://127.0.0.2/api/?key="+testKey, http.StatusFound)
		},
		func(w http.ResponseWriter, _ *http.Request) {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		},
	}
	for i, h := range handlers {
		ts := newTestServer(t, nil, h)
		c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin(), Logger: logger})
		_, err := c.Do(context.Background(), SystemInfoRequest())
		if i > 0 && err == nil {
			t.Fatalf("handler %d: no error", i)
		}
		if err != nil {
			assertNoKey(t, "error", err.Error())
		}
	}
	if buf.Len() == 0 {
		t.Fatal("no log output")
	}
	assertNoKey(t, "log", buf.String())
	if strings.Contains(buf.String(), "xpath") || strings.Contains(buf.String(), "<show>") {
		t.Fatal("log contains request details")
	}
}

func TestAddressCheckedAtEveryDial(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	if _, err := c.Do(context.Background(), SystemInfoRequest()); err != nil {
		t.Fatal(err)
	}
	c.Close() // drop the idle connection so the next request dials
	c.checkAddr = CheckManagementAddr
	_, err := c.Do(context.Background(), SystemInfoRequest())
	if !errors.Is(err, ErrAddressRefused) {
		t.Fatalf("err = %v, want ErrAddressRefused", err)
	}
	if ts.hits.Load() != 1 {
		t.Fatal("request sent to a refused address")
	}
}

func TestNewRefusesLoopbackEndpoint(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	_, err := New(Options{
		Endpoint: ts.endpoint(t),
		Trust:    ts.leafPin(),
		Key:      func(context.Context) (string, error) { return testKey, nil },
	})
	if !errors.Is(err, ErrAddressRefused) {
		t.Fatalf("err = %v, want ErrAddressRefused", err)
	}
}

func TestCheckManagementAddr(t *testing.T) {
	for _, tc := range []struct {
		addr string
		ok   bool
	}{
		{"10.0.0.1", true},
		{"172.16.5.4", true},
		{"192.168.1.1", true},
		{"fd00::1", true},
		{"::ffff:192.168.1.1", true},
		{"8.8.8.8", false},
		{"100.64.0.1", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"169.254.1.1", false},
		{"fe80::1", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"255.255.255.255", false},
		{"2001:db8::1", false},
		{"::ffff:8.8.8.8", false},
		{"::ffff:127.0.0.1", false},
	} {
		err := CheckManagementAddr(netip.MustParseAddr(tc.addr))
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.addr, err)
		}
		if !tc.ok && !errors.Is(err, ErrAddressRefused) {
			t.Errorf("%s: err = %v, want ErrAddressRefused", tc.addr, err)
		}
	}
	if err := CheckManagementAddr(netip.Addr{}); !errors.Is(err, ErrAddressRefused) {
		t.Errorf("zero addr: %v", err)
	}
}

func TestOneRequestInFlight(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	ts := newTestServer(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, okBody)
	})
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	first := make(chan error, 1)
	go func() {
		_, err := c.Do(context.Background(), SystemInfoRequest())
		first <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := c.Do(ctx, SystemInfoRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second request: err = %v, want DeadlineExceeded", err)
	}
	if ts.hits.Load() != 1 {
		t.Fatalf("server saw %d concurrent requests", ts.hits.Load())
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first request: %v", err)
	}
}

func TestRequestTimeout(t *testing.T) {
	ts := newTestServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	c.requestTimeout = 100 * time.Millisecond
	_, err := c.Do(context.Background(), SystemInfoRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

func TestZeroRequestRefused(t *testing.T) {
	ts := newTestServer(t, nil, replyXML(okBody))
	c := newTestClient(t, Options{Endpoint: ts.endpoint(t), Trust: ts.leafPin()})
	for _, r := range []Request{{}, {typ: "config", action: "set", xpath: "/config", maxBytes: 1}, {typ: "commit", cmd: "<commit/>", maxBytes: 1}} {
		if _, err := c.Do(context.Background(), r); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	}
	if ts.hits.Load() != 0 {
		t.Fatal("invalid request sent")
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	key := func(context.Context) (string, error) { return testKey, nil }
	pin := pvetransport.Trust{LeafFingerprint: [32]byte{1}}
	ep := netip.MustParseAddrPort("10.0.0.1:443")
	for _, tc := range []struct {
		desc string
		opts Options
	}{
		{"no trust", Options{Endpoint: ep, Key: key}},
		{"both pins", Options{Endpoint: ep, Key: key, Trust: pvetransport.Trust{LeafFingerprint: [32]byte{1}, CA: &x509.Certificate{}}}},
		{"zero endpoint", Options{Trust: pin, Key: key}},
		{"port zero", Options{Endpoint: netip.MustParseAddrPort("10.0.0.1:0"), Trust: pin, Key: key}},
		{"zone", Options{Endpoint: netip.MustParseAddrPort("[fd00::1%eth0]:443"), Trust: pin, Key: key}},
		{"no key source", Options{Endpoint: ep, Trust: pin}},
		{"ip server name", Options{Endpoint: ep, Trust: pin, Key: key, ServerName: "10.0.0.1"}},
		{"empty label", Options{Endpoint: ep, Trust: pin, Key: key, ServerName: "fw..lab"}},
		{"bad char", Options{Endpoint: ep, Trust: pin, Key: key, ServerName: "fw_1.lab"}},
		{"leading hyphen", Options{Endpoint: ep, Trust: pin, Key: key, ServerName: "-fw.lab"}},
		{"too long", Options{Endpoint: ep, Trust: pin, Key: key, ServerName: strings.Repeat("a.", 127) + "a"}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if _, err := New(tc.opts); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("err = %v, want ErrInvalidOptions", err)
			}
		})
	}
	if _, err := New(Options{Endpoint: ep, Trust: pin, Key: key, ServerName: "fw.lab.internal"}); err != nil {
		t.Fatalf("valid options: %v", err)
	}
}
