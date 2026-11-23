// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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
	"testing"
	"time"
)

// agentConfigAnswer is a valid agent-config answer (every field known).
const agentConfigAnswer = `{"enabled":true,"llm_base_url":"","llm_model":"","allow_plain_http":false,` +
	`"data_class":"lab","language":"de","operator_instructions":"","prompt_version":"v1","version":7}`

// newTLSAPIServer starts a TLS server that answers agent-config with its own
// certificate, unlike httptest's built-in one, which every test server shares.
func newTLSAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "nos-ops-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentConfigPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(agentConfigAnswer))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// serverCAFile writes the PEM of the certificate srv presents: the test
// server's certificate is its own root, so this file pins it.
func serverCAFile(t *testing.T, srv *httptest.Server, name string) string {
	t.Helper()
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return writeTempFile(t, name, block)
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func tokenFileFor(t *testing.T) string {
	t.Helper()
	return writeTempFile(t, "token", []byte(testAPIToken))
}

// TestPinnedCAReachesTLSServer: with the server's own CA pinned, the call
// verifies the certificate and succeeds.
func TestPinnedCAReachesTLSServer(t *testing.T) {
	srv := newTLSAPIServer(t)
	c, err := New(Config{BaseURL: srv.URL, TokenFile: tokenFileFor(t), CAFile: serverCAFile(t, srv, "ca.pem")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cfg, err := c.AgentConfig(context.Background())
	if err != nil {
		t.Fatalf("AgentConfig over pinned TLS: %v", err)
	}
	if cfg.Version != 7 || cfg.DataClass != "lab" {
		t.Errorf("config = %+v, want version 7 and class lab", cfg)
	}
}

// TestForeignPinnedCAIsRefused: a pinned CA that did not sign the server's
// certificate makes the call fail as unavailable. The error names neither the
// URL nor the token.
func TestForeignPinnedCAIsRefused(t *testing.T) {
	srv := newTLSAPIServer(t)
	other := newTLSAPIServer(t)
	c, err := New(Config{BaseURL: srv.URL, TokenFile: tokenFileFor(t), CAFile: serverCAFile(t, other, "foreign.pem")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.AgentConfig(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("AgentConfig with a foreign CA: %v, want ErrUnavailable", err)
	}
	for _, secret := range []string{srv.URL, testAPIToken, strings.TrimPrefix(srv.URL, "https://")} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q carries %q", err, secret)
		}
	}
}

// TestWithoutCAFileSystemRootsRefuseTestServer: with no CA file the system
// pool applies, and it does not hold the test server's certificate.
func TestWithoutCAFileSystemRootsRefuseTestServer(t *testing.T) {
	srv := newTLSAPIServer(t)
	c, err := New(Config{BaseURL: srv.URL, TokenFile: tokenFileFor(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.AgentConfig(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("AgentConfig with system roots: %v, want ErrUnavailable", err)
	}
}

// TestUnusableCAFilesRefusedAtNew: a CA file that holds no certificate, or is
// empty, or is over MaxCAFileBytes, stops New. Verification is never turned
// off as a fallback.
func TestUnusableCAFilesRefusedAtNew(t *testing.T) {
	srv := newTLSAPIServer(t)
	keyOnly := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")})
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{"empty file", []byte{}, nil},
		{"text without a certificate", []byte("no pem here\n"), nil},
		{"pem block that is not a certificate", keyOnly, nil},
		{"over MaxCAFileBytes", make([]byte, MaxCAFileBytes+1), ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempFile(t, "ca.pem", tc.data)
			_, err := New(Config{BaseURL: srv.URL, TokenFile: tokenFileFor(t), CAFile: path})
			if err == nil {
				t.Fatal("New accepted the CA file")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("New: %v, want %v", err, tc.wantErr)
			}
		})
	}
}
