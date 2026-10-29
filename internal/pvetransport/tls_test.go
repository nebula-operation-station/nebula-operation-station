// SPDX-License-Identifier: AGPL-3.0-or-later

package pvetransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCA is an in-memory certificate authority for trust tests.
type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
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

// leafSpec describes a leaf certificate to create.
type leafSpec struct {
	dnsNames  []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

// leafTemplate builds the x509 template for a server leaf certificate.
func leafTemplate(spec leafSpec) *x509.Certificate {
	if spec.notBefore.IsZero() {
		spec.notBefore = time.Now().Add(-time.Hour)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = time.Now().Add(time.Hour)
	}
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
		DNSNames:     spec.dnsNames,
		IPAddresses:  spec.ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// leaf creates a server leaf certificate signed by the CA and returns its
// DER encoding.
func (ca *testCA) leaf(t *testing.T, spec leafSpec) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate(spec), ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func parseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

var loopback = net.ParseIP("127.0.0.1")

func TestVerifyCAPin(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	other := newTestCA(t, "other-ca")
	now := time.Now()

	tests := []struct {
		name      string
		trust     Trust
		rawCerts  [][]byte
		host      string
		wantErr   bool
		wantTrust bool // error must wrap ErrTrustMismatch
	}{
		{
			name:     "leaf signed by pinned CA with IP SAN",
			trust:    Trust{CA: ca.cert},
			rawCerts: [][]byte{ca.leaf(t, leafSpec{ips: []net.IP{loopback}})},
			host:     "127.0.0.1",
		},
		{
			name:     "leaf signed by pinned CA with DNS SAN",
			trust:    Trust{CA: ca.cert},
			rawCerts: [][]byte{ca.leaf(t, leafSpec{dnsNames: []string{"pve.example.com"}})},
			host:     "pve.example.com",
		},
		{
			name:     "wildcard DNS SAN matches one label",
			trust:    Trust{CA: ca.cert},
			rawCerts: [][]byte{ca.leaf(t, leafSpec{dnsNames: []string{"*.example.com"}})},
			host:     "pve.example.com",
		},
		{
			name:      "leaf signed by different CA",
			trust:     Trust{CA: ca.cert},
			rawCerts:  [][]byte{other.leaf(t, leafSpec{ips: []net.IP{loopback}})},
			host:      "127.0.0.1",
			wantErr:   true,
			wantTrust: true,
		},
		{
			name:      "wildcard does not cross labels",
			trust:     Trust{CA: ca.cert},
			rawCerts:  [][]byte{ca.leaf(t, leafSpec{dnsNames: []string{"*.example.com"}})},
			host:      "a.b.example.com",
			wantErr:   true,
			wantTrust: true,
		},
		{
			name:      "DNS SAN does not match IP host",
			trust:     Trust{CA: ca.cert},
			rawCerts:  [][]byte{ca.leaf(t, leafSpec{dnsNames: []string{"pve.example.com"}})},
			host:      "127.0.0.1",
			wantErr:   true,
			wantTrust: true,
		},
		{
			name:      "IP SAN does not match DNS host",
			trust:     Trust{CA: ca.cert},
			rawCerts:  [][]byte{ca.leaf(t, leafSpec{ips: []net.IP{loopback}})},
			host:      "pve.example.com",
			wantErr:   true,
			wantTrust: true,
		},
		{
			name:      "expired leaf",
			trust:     Trust{CA: ca.cert},
			rawCerts:  [][]byte{ca.leaf(t, leafSpec{ips: []net.IP{loopback}, notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)})},
			host:      "127.0.0.1",
			wantErr:   true,
			wantTrust: true,
		},
		{
			name:     "no certificate",
			trust:    Trust{CA: ca.cert},
			rawCerts: nil,
			host:     "127.0.0.1",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.trust.Verify(tt.rawCerts, tt.host, now)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantTrust && !errors.Is(err, ErrTrustMismatch) {
					t.Fatalf("error %v does not wrap ErrTrustMismatch", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyLeafPin(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	now := time.Now()
	leafDER := ca.leaf(t, leafSpec{ips: []net.IP{loopback}})
	leaf := parseCert(t, leafDER)
	pin := Trust{LeafFingerprint: Fingerprint(leaf)}

	if err := pin.Verify([][]byte{leafDER}, "127.0.0.1", now); err != nil {
		t.Fatalf("pinned leaf rejected: %v", err)
	}

	// A different leaf from the same CA must be rejected: the pin is on
	// the leaf itself, not on the CA.
	otherDER := ca.leaf(t, leafSpec{ips: []net.IP{loopback}})
	err := pin.Verify([][]byte{otherDER}, "127.0.0.1", now)
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("expected ErrTrustMismatch for different leaf, got %v", err)
	}

	// Pinned leaf with wrong SAN host.
	err = pin.Verify([][]byte{leafDER}, "pve.example.com", now)
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("expected ErrTrustMismatch for wrong SAN, got %v", err)
	}

	// Pinned leaf that is expired.
	expiredDER := ca.leaf(t, leafSpec{ips: []net.IP{loopback}, notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)})
	expired := Trust{LeafFingerprint: Fingerprint(parseCert(t, expiredDER))}
	err = expired.Verify([][]byte{expiredDER}, "127.0.0.1", now)
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("expected ErrTrustMismatch for expired pinned leaf, got %v", err)
	}
}

func TestVerifyRejectsChainNotEndingAtPinnedCA(t *testing.T) {
	// A CA-signed intermediate that is itself a CA: a leaf under it must
	// still verify, and the chain must end at the pinned root.
	ca := newTestCA(t, "pve-root-ca")
	now := time.Now()

	interPub, interPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, ca.cert, interPub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		IPAddresses:  []net.IP{loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, inter, leafPub, interPriv)
	if err != nil {
		t.Fatal(err)
	}

	// With the intermediate presented, the chain ends at the pinned CA.
	if err := (Trust{CA: ca.cert}).Verify([][]byte{leafDER, interDER}, "127.0.0.1", now); err != nil {
		t.Fatalf("intermediate chain rejected: %v", err)
	}

	// Without the intermediate the chain cannot be built.
	err = (Trust{CA: ca.cert}).Verify([][]byte{leafDER}, "127.0.0.1", now)
	if !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("expected ErrTrustMismatch for incomplete chain, got %v", err)
	}
}

func TestTrustValidate(t *testing.T) {
	ca := newTestCA(t, "pve-root-ca")
	if err := (Trust{}).Validate(); err == nil {
		t.Fatal("expected error for empty trust")
	}
	if err := (Trust{CA: ca.cert}).Validate(); err != nil {
		t.Fatalf("CA pin rejected: %v", err)
	}
	if err := (Trust{LeafFingerprint: [32]byte{1}}).Validate(); err != nil {
		t.Fatalf("leaf pin rejected: %v", err)
	}
	if err := (Trust{CA: ca.cert, LeafFingerprint: [32]byte{1}}).Validate(); err == nil {
		t.Fatal("expected error for double pin")
	}
}

func TestMatchDNS(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"pve.example.com", "pve.example.com", true},
		{"pve.example.com", "other.example.com", false},
		{"*.example.com", "pve.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "b.example.com.", false},
		{"pve.*.com", "pve.example.com", false},
	}
	for _, tt := range tests {
		if got := matchDNS(tt.pattern, tt.name); got != tt.want {
			t.Errorf("matchDNS(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}
