// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRefusesNonHTTPSOrDecoratedBaseURL(t *testing.T) {
	tok := writeToken(t, testToken, 0o600)
	for _, u := range []string{"", "http://127.0.0.1:1", "https://", "https://u:p@127.0.0.1", "https://127.0.0.1/api", "https://127.0.0.1?x=1",
		"ftp://127.0.0.1", "https://127.0.0.1#f"} {
		if _, err := New(Config{BaseURL: u, TokenFile: tok}); err == nil {
			t.Fatalf("%q accepted", u)
		}
	}
}

func TestNewRefusesAGroupReadableTokenFile(t *testing.T) {
	_, err := New(Config{BaseURL: "https://127.0.0.1:1", TokenFile: writeToken(t, testToken, 0o640)})
	if !errors.Is(err, ErrTokenFilePermissions) {
		t.Fatalf("%v", err)
	}
}

func TestNewRefusesAnUnusableCAFile(t *testing.T) {
	tok := writeToken(t, testToken, 0o600)
	empty := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(t.TempDir(), "big.pem")
	if err := os.WriteFile(big, make([]byte, MaxCAFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ca := range []string{empty, big, filepath.Join(t.TempDir(), "missing")} {
		if _, err := New(Config{BaseURL: "https://127.0.0.1:1", TokenFile: tok, CAFile: ca}); err == nil {
			t.Fatalf("%s accepted", ca)
		}
	}
}

func TestTLSConfigNeverSkipsVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	for _, ca := range []string{"", writeCA(t, srv)} {
		cfg, err := tlsConfig(ca)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.InsecureSkipVerify || cfg.MinVersion < 0x0303 {
			t.Fatalf("ca %q: insecure TLS config", ca)
		}
		if (ca == "") != (cfg.RootCAs == nil) {
			t.Fatalf("ca %q: pool not as configured", ca)
		}
	}
}

func TestSystemPoolRefusesAnUnpinnedTestServer(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	cfg.CAFile = ""
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Export(context.Background(), func(Page) error { return nil })
	if !errors.Is(err, ErrCertificate) {
		t.Fatalf("got %v", err)
	}
	if e.count(inventoryPath) != 0 {
		t.Fatal("request reached the handler without a verified certificate")
	}
	if len(e.sleeps) != 0 {
		t.Fatalf("certificate failure retried: %v", e.sleeps)
	}
}

// otherCA writes a freshly generated CA certificate (httptest servers all
// share one certificate, so another server's would not differ).
func otherCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "other.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPinnedCARefusesAServerItDidNotSign(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	cfg.CAFile = otherCA(t)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Export(context.Background(), func(Page) error { return nil }); !errors.Is(err, ErrCertificate) {
		t.Fatalf("server with an unpinned certificate: %v", err)
	}
	if e.count(inventoryPath) != 0 {
		t.Fatal("request reached the handler")
	}
}

func TestTokenIsSentAsBearerAndNeverQuoted(t *testing.T) {
	var auth atomic.Value
	cfg := fakeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		if r.URL.Query().Encode() != "" {
			t.Errorf("query %q", r.URL.RawQuery)
		}
		// A server that echoes the token must not get it into the error.
		fixed(http.StatusUnauthorized, `{"error":"bad token `+testToken+`\u0007"}`)(w, r)
	}))
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Export(context.Background(), func(Page) error { return nil })
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("%v", err)
	}
	if auth.Load() != "Bearer "+testToken {
		t.Fatal("token not sent as bearer")
	}
	if strings.Contains(err.Error(), testToken) || !strings.Contains(err.Error(), redacted) || strings.ContainsRune(err.Error(), 7) {
		t.Fatalf("error not cleaned: %q", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer other.Close()
	cfg := fakeServer(t, http.RedirectHandler(other.URL+inventoryPath, http.StatusFound))
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Export(context.Background(), func(Page) error { return nil }); !errors.Is(err, ErrProtocol) {
		t.Fatalf("%v", err)
	}
	if reached.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestRetryAfterFromTheServerIsHonoured(t *testing.T) {
	var n atomic.Int32
	var slept []time.Duration
	cfg := fakeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			fixed(http.StatusTooManyRequests, `{"error":"rate limit reached"}`, "Retry-After", "7")(w, r)
			return
		}
		fixed(http.StatusServiceUnavailable, `{"error":"inventory unavailable"}`)(w, r)
	}))
	cfg.MaxAttempts = 3
	cfg.Sleep = func(ctx context.Context, d time.Duration) error { slept = append(slept, d); return ctx.Err() }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Export(context.Background(), func(Page) error { return nil })
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if n.Load() != 3 || len(slept) != 2 || slept[0] != 7*time.Second || slept[1] != firstBackoff {
		t.Fatalf("attempts %d, sleeps %v", n.Load(), slept)
	}
}

func TestRetryAfterIsCapped(t *testing.T) {
	if d := retryAfter("999999"); d != maxRetryAfter {
		t.Fatalf("%v", d)
	}
	for _, v := range []string{"", "-1", "soon", "Wed, 21 Oct 2015 07:28:00 GMT"} {
		if retryAfter(v) != 0 {
			t.Fatalf("%q", v)
		}
	}
}

func TestClientWindowWaitsInsteadOfTrippingTheServerLimit(t *testing.T) {
	clk := &clock{t: t0}
	var slept []time.Duration
	c := &Client{now: clk.Now, sleep: func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		clk.Add(d)
		return nil
	}}
	w := &rateWindow{span: WriteWindow, max: MaxWriteRequests}
	for i := 0; i < MaxWriteRequests; i++ {
		if err := c.waitWindow(context.Background(), w); err != nil {
			t.Fatal(err)
		}
	}
	if len(slept) != 0 {
		t.Fatalf("waited within the limit: %v", slept)
	}
	if err := c.waitWindow(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	if len(slept) != 1 || slept[0] < WriteWindow || slept[0] > WriteWindow+time.Second {
		t.Fatalf("sleeps %v", slept)
	}
	// A cancelled context ends the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.sleep = sleepCtx
	full := &rateWindow{span: ExportWindow, max: 1, times: []time.Time{clk.Now()}}
	if err := c.waitWindow(ctx, full); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestErrorMessageIsBoundedAndPrintable(t *testing.T) {
	c := &Client{token: Token{value: testToken}}
	long := `{"error":"` + strings.Repeat("ä", 1000) + `"}`
	if m := c.errorMessage([]byte(long)); len(m) > maxErrorMessage {
		t.Fatalf("%d bytes", len(m))
	}
	if m := c.errorMessage([]byte("<html>")); m != "(no message)" {
		t.Fatalf("%q", m)
	}
	if m := c.errorMessage([]byte(`{"error":"a\u001b[31mb\nc"}`)); strings.ContainsAny(m, "\x1b\n") {
		t.Fatalf("%q", m)
	}
}
