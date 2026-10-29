// SPDX-License-Identifier: AGPL-3.0-or-later

package pvetransport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrTrustMismatch is the hard, terminal trust failure for a remote: the
// certificate served by an endpoint does not match the pinned trust (pin
// mismatch, invalid chain, SAN mismatch or expired certificate). Per ADR
// 0006 a trust mismatch blocks the whole remote and stops failover; the
// transport never tries the next endpoint after it.
var ErrTrustMismatch = errors.New("pvetransport: certificate does not match pinned trust")

// Trust is the pinned trust of one remote. Exactly one of CA or
// LeafFingerprint must be set:
//
//   - CA pins the cluster CA certificate (pve-root-ca). Every served leaf
//     must chain to exactly that root. CA-preserving leaf renewals need no
//     re-pin.
//   - LeafFingerprint pins the served leaf certificate itself (standalone
//     hosts). Validity and SAN are still checked.
//
// There is no fallback to the system root store and no acceptance of any
// other certificate.
type Trust struct {
	// CA is the pinned cluster CA certificate.
	CA *x509.Certificate
	// LeafFingerprint is the SHA-256 fingerprint of the served leaf
	// certificate's DER encoding.
	LeafFingerprint [32]byte
}

// Validate reports whether exactly one pin is set.
func (t Trust) Validate() error {
	if (t.CA == nil) == (t.LeafFingerprint == [32]byte{}) {
		return errors.New("pvetransport: trust needs exactly one of CA or LeafFingerprint")
	}
	return nil
}

// Fingerprint returns the SHA-256 fingerprint of a certificate's DER
// encoding.
func Fingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// Verify checks the raw certificate chain served by a TLS server against
// the pinned trust for the endpoint host. It verifies the leaf's validity
// period, the pin, the chain (for a CA pin, exclusively against the pinned
// root) and the DNS/IP SAN of the endpoint. Every failure wraps
// ErrTrustMismatch so callers can treat all of them as terminal.
func (t Trust) Verify(rawCerts [][]byte, host string, now time.Time) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: server sent no certificate", ErrTrustMismatch)
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: parse leaf certificate: %v", ErrTrustMismatch, err)
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("%w: leaf certificate not yet valid (notBefore %s)", ErrTrustMismatch, leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: leaf certificate expired (notAfter %s)", ErrTrustMismatch, leaf.NotAfter.Format(time.RFC3339))
	}
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("%w: leaf certificate lacks serverAuth EKU", ErrTrustMismatch)
	}
	if t.LeafFingerprint != [32]byte{} {
		if Fingerprint(leaf) != t.LeafFingerprint {
			return fmt.Errorf("%w: leaf fingerprint mismatch", ErrTrustMismatch)
		}
		return checkSAN(leaf, host)
	}
	roots := x509.NewCertPool()
	roots.AddCert(t.CA)
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("%w: parse intermediate certificate: %v", ErrTrustMismatch, err)
		}
		intermediates.AddCert(cert)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("%w: chain verification: %v", ErrTrustMismatch, err)
	}
	pinned := Fingerprint(t.CA)
	for _, chain := range chains {
		if Fingerprint(chain[len(chain)-1]) != pinned {
			return fmt.Errorf("%w: chain does not end at the pinned CA", ErrTrustMismatch)
		}
	}
	return checkSAN(leaf, host)
}

// TLSConfig returns a *tls.Config that pins trust for host. It sets
// InsecureSkipVerify because verification is done exclusively in
// VerifyPeerCertificate against the pinned trust; the system root store is
// never consulted. now supplies the clock for expiry checks.
func (t Trust) TLSConfig(host string, now func() time.Time) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // verification is done exclusively below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return t.Verify(rawCerts, host, now())
		},
	}
}

// checkSAN reports whether host matches one of the leaf's SANs. IP
// endpoints match IP SANs, everything else DNS SANs (single-label
// wildcards allowed).
func checkSAN(leaf *x509.Certificate, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		for _, candidate := range leaf.IPAddresses {
			if candidate.Equal(ip) {
				return nil
			}
		}
		return fmt.Errorf("%w: no IP SAN for %s", ErrTrustMismatch, host)
	}
	for _, dns := range leaf.DNSNames {
		if matchDNS(dns, host) {
			return nil
		}
	}
	return fmt.Errorf("%w: no DNS SAN for %s", ErrTrustMismatch, host)
}

// hasExtKeyUsage reports whether the certificate carries extKeyUsage. An
// empty ExtKeyUsage list means all usages are allowed.
func hasExtKeyUsage(leaf *x509.Certificate, usage x509.ExtKeyUsage) bool {
	if len(leaf.ExtKeyUsage) == 0 {
		return true
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == usage {
			return true
		}
	}
	return false
}

// matchDNS reports whether pattern matches name. Exact matches and
// single-label leading wildcards ("*.example.com" matches "a.example.com"
// but not "a.b.example.com") are accepted.
func matchDNS(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	label := name[:len(name)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}
