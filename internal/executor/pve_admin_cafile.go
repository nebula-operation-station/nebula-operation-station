// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executor — admin-supplied cluster CA for PVE remotes (ADR 0006).
//
// A default PVE cluster node serves only its leaf (pve-ssl.pem), issued by
// the cluster CA ("PVE Cluster Manager CA", /etc/pve/pve-root-ca.pem). The
// probe then sees no CA, so the admin imports the CA from a trusted local
// file copied out of band. The file never establishes trust on its own:
// the admin still types its fingerprint back, and every endpoint's leaf
// must chain to it. A CA presented by a server is only compared with it.

package executor

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// MaxPveCAFileBytes bounds the admin-supplied cluster CA file (PEM).
const MaxPveCAFileBytes = 64 << 10

// Sentinel errors of the admin-supplied cluster CA.
var (
	// ErrPveClusterNoCA means a cluster endpoint presented no self-signed
	// CA and no CA file was supplied.
	ErrPveClusterNoCA = errors.New("executor: cluster endpoint presents no CA; pass --ca-file with /etc/pve/pve-root-ca.pem")
	// ErrPveSuppliedCA means the supplied CA file is not exactly one
	// currently valid, self-signed CA certificate, or was supplied for a
	// standalone remote.
	ErrPveSuppliedCA = errors.New("executor: supplied cluster CA file is invalid")
	// ErrPveLeafNotChained means an endpoint's leaf does not verify against
	// the supplied CA as the only root.
	ErrPveLeafNotChained = errors.New("executor: cluster endpoint leaf does not chain to the supplied CA")
	// ErrPveCAFileMismatch means an endpoint presented a CA that differs
	// from the supplied one. It is always joined with ErrPvePinMismatch.
	ErrPveCAFileMismatch = errors.New("executor: endpoint presents a CA that differs from the supplied CA file")
)

// ParsePveSuppliedCA parses an admin-supplied cluster CA file: at most
// MaxPveCAFileBytes of PEM holding exactly one CERTIFICATE block (only
// whitespace around it, no PEM headers), which must be a self-signed CA
// certificate valid at now. Every failure wraps ErrPveSuppliedCA.
func ParsePveSuppliedCA(raw []byte, now time.Time) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty", ErrPveSuppliedCA)
	}
	if len(raw) > MaxPveCAFileBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrPveSuppliedCA, MaxPveCAFileBytes)
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, fmt.Errorf("%w: not a PEM certificate", ErrPveSuppliedCA)
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("%w: not a PEM certificate", ErrPveSuppliedCA)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: want exactly one certificate and nothing else", ErrPveSuppliedCA)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %v", ErrPveSuppliedCA, err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, fmt.Errorf("%w: not a CA certificate", ErrPveSuppliedCA)
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignatureFrom(cert) != nil {
		return nil, fmt.Errorf("%w: not self-signed", ErrPveSuppliedCA)
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: not valid now (valid %s to %s)", ErrPveSuppliedCA, cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return cert, nil
}

// TrustIdentityWithCA is TrustIdentity with an optional admin-supplied
// cluster CA (nil: unchanged behaviour). With a supplied CA, a cluster's
// trust identity is that CA: an endpoint that presents a CA must present
// exactly it, and every endpoint's leaf must verify against it as the only
// root at now. A supplied CA is refused for a standalone remote.
func (r PveProbeResult) TrustIdentityWithCA(kind pvecontract.Kind, supplied *x509.Certificate, now time.Time) (string, pvetransport.Trust, error) {
	if supplied == nil {
		return r.TrustIdentity(kind)
	}
	if kind != pvecontract.KindCluster {
		return "", pvetransport.Trust{}, fmt.Errorf("%w: a CA file is only accepted for a cluster", ErrPveSuppliedCA)
	}
	if len(r.Endpoints) == 0 {
		return "", pvetransport.Trust{}, errors.New("executor: no endpoints probed")
	}
	want := pvetransport.Fingerprint(supplied)
	roots := x509.NewCertPool()
	roots.AddCert(supplied)
	for _, ep := range r.Endpoints {
		if ep.CA != nil && pvetransport.Fingerprint(ep.CA) != want {
			return "", pvetransport.Trust{}, fmt.Errorf("%w: %w: %s:%d", ErrPvePinMismatch, ErrPveCAFileMismatch, ep.Host, ep.Port)
		}
		if ep.Leaf == nil {
			return "", pvetransport.Trust{}, fmt.Errorf("%w: %s:%d presented no leaf certificate", ErrPveLeafNotChained, ep.Host, ep.Port)
		}
		chains, err := ep.Leaf.Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return "", pvetransport.Trust{}, fmt.Errorf("%w: %s:%d: %v", ErrPveLeafNotChained, ep.Host, ep.Port, err)
		}
		for _, chain := range chains {
			if pvetransport.Fingerprint(chain[len(chain)-1]) != want {
				return "", pvetransport.Trust{}, fmt.Errorf("%w: %s:%d: chain does not end at the supplied CA", ErrPveLeafNotChained, ep.Host, ep.Port)
			}
		}
	}
	return hex.EncodeToString(want[:]), pvetransport.Trust{CA: supplied}, nil
}

// pveCAFileError reports whether err is one of the CA-file conditions the
// RPC layer reports with their own actionable message.
func pveCAFileError(err error) bool {
	return errors.Is(err, ErrPveClusterNoCA) || errors.Is(err, ErrPveSuppliedCA) ||
		errors.Is(err, ErrPveLeafNotChained) || errors.Is(err, ErrPveCAFileMismatch)
}

// pveCAVaultID is the vault id of the supplied cluster CA of remoteID
// pinned to pin. It is keyed by the pin so that storing the CA of a new
// pin never overwrites the one the current pin still needs.
func pveCAVaultID(remoteID, pin string) string {
	if len(pin) > 16 {
		pin = pin[:16]
	}
	return PveVaultID(remoteID, "ca-"+pin)
}

// suppliedCA parses a supplied CA file with the admin clock; nil when
// none was supplied.
func (a *PveAdmin) suppliedCA(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return ParsePveSuppliedCA(raw, a.now())
}

func (a *PveAdmin) now() time.Time {
	if a.Now == nil {
		return time.Now()
	}
	return a.Now()
}

// StoredClusterCA returns the admin-supplied CA stored for rm's current
// pin, or nil if the remote has none (a standalone remote, or a cluster
// whose endpoints present their CA). A stored certificate whose SHA-256
// does not equal the pin is refused; it never becomes trust.
func (a *PveAdmin) StoredClusterCA(rm executordb.PveRemote) (*x509.Certificate, error) {
	if rm.Kind != pvecontract.KindCluster {
		return nil, nil
	}
	if a.Vault == nil {
		return nil, errors.New("executor: pve stored CA: Vault is required")
	}
	der, err := a.Vault.Open(pveCAVaultID(rm.RemoteID, rm.TrustPin))
	if errors.Is(err, vault.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("executor: pve stored CA of %s: %w", rm.RemoteID, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("executor: pve stored CA of %s: %w", rm.RemoteID, ErrPveSuppliedCA)
	}
	fp := pvetransport.Fingerprint(cert)
	if hex.EncodeToString(fp[:]) != rm.TrustPin {
		return nil, fmt.Errorf("executor: pve stored CA of %s: %w", rm.RemoteID, ErrPvePinMismatch)
	}
	return cert, nil
}

// storeClusterCA stores ca as the supplied CA of cluster remoteID pinned to
// pin and reads it back exactly as every later connection loads it
// (StoredClusterCA), so a CA that is stored is also usable. It returns the
// compensation that removes this version again; on a failed read-back the
// version is already removed and the error is returned.
func (a *PveAdmin) storeClusterCA(remoteID, pin string, ca *x509.Certificate, by string) (func(), error) {
	id := pveCAVaultID(remoteID, pin)
	version, err := a.Vault.Put(id, ca.Raw, by)
	if err != nil {
		return nil, fmt.Errorf("store cluster CA: %w", err)
	}
	compensate := func() { a.compensateVault(id, version) }
	got, err := a.StoredClusterCA(executordb.PveRemote{RemoteID: remoteID, Kind: pvecontract.KindCluster, TrustPin: pin})
	if err == nil && (got == nil || !bytes.Equal(got.Raw, ca.Raw)) {
		err = fmt.Errorf("executor: pve stored CA of %s: read back differs", remoteID)
	}
	if err != nil {
		compensate()
		return nil, fmt.Errorf("load stored cluster CA: %w", err)
	}
	return compensate, nil
}

// deleteStoredCAs removes every stored CA of remoteID except the one for
// keepPin ("" removes all).
func (a *PveAdmin) deleteStoredCAs(remoteID, keepPin string) error {
	infos, err := a.Vault.List()
	if err != nil {
		return fmt.Errorf("executor: pve stored CA of %s: %w", remoteID, err)
	}
	prefix := PveVaultID(remoteID, "ca-")
	keep := ""
	if keepPin != "" {
		keep = pveCAVaultID(remoteID, keepPin)
	}
	for _, info := range infos {
		if len(info.ID) < len(prefix) || info.ID[:len(prefix)] != prefix || info.ID == keep {
			continue
		}
		if err := a.Vault.Delete(info.ID); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return fmt.Errorf("executor: pve stored CA of %s: %w", remoteID, err)
		}
	}
	return nil
}
