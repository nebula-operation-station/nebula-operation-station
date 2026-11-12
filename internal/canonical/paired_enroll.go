// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/gowebpki/jcs"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Paired enrollment permit binding (ADR 0013 D4, spec 05 v25-05-01,
// spec 17). The executor builds it after its own constant-time code match;
// the approval (HIGH, user verification) signs its digest, and the commit
// is checked against every bound field.

// PairedEnrollVersion is embedded in every paired enrollment binding so
// that a change of the form can never produce a colliding digest.
const PairedEnrollVersion = 1

// PairedEnrollKind separates the paired enrollment binding from every
// other canonical document (execution requests and later permit kinds).
const PairedEnrollKind = "nebula.paired_enroll"

// MaxPairedEnrollLifetime bounds the expiry of a paired enrollment permit:
// the lifetime of other enrollment permits (re-pin and bulk enrollment).
const MaxPairedEnrollLifetime = 15 * time.Minute

// sshUserRe is the SSH user syntax accepted for enrollment (the same rule
// as bulk enrollment and the enrollment script).
var sshUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidSSHUser reports whether s is a well-formed SSH user for enrollment.
func ValidSSHUser(s string) bool { return sshUserRe.MatchString(s) }

// PairedEnroll is the canonical paired enrollment binding. Field names are
// part of the canonical form and must never change without bumping
// PairedEnrollVersion.
type PairedEnroll struct {
	Version int    `json:"paired_enroll_version"`
	Kind    string `json:"kind"`
	// OfferIDHash is the lowercase hex SHA-256 of the offer ID (the
	// executor never stores the ID itself).
	OfferIDHash string `json:"offer_id_hash"`
	HostID      string `json:"host_id"`
	// Endpoint is the probed endpoint in canonical host:port form.
	Endpoint string `json:"endpoint"`
	// EndpointToAdd: the endpoint is not yet an inventory endpoint of the
	// host and is appended to its list after a successful commit.
	EndpointToAdd bool   `json:"endpoint_to_add"`
	SSHUser       string `json:"ssh_user"`
	CredentialRef string `json:"credential_ref"`
	// HostKeyFingerprint is the full OpenSSH SHA256 fingerprint of the
	// presented ed25519 host key that matched the code.
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	// CodeMatched is the executor's finding; a binding with false is
	// refused, so a permit can only exist for a matched code.
	CodeMatched bool `json:"code_matched"`
	// PairingCode is the matched code in its canonical display form
	// XXXXX-XXXXX-XXXXX-XXXXX-XXXXC.
	PairingCode string `json:"pairing_code"`
	ExpiryUnix  int64  `json:"expiry_unix"`
}

// pairedEnrollFields lists the canonical member names in a fixed order,
// with an accessor that renders each for comparison. PairedEnrollDiff
// reports the first differing one.
var pairedEnrollFields = []struct {
	name string
	get  func(PairedEnroll) string
}{
	{"paired_enroll_version", func(b PairedEnroll) string { return fmt.Sprint(b.Version) }},
	{"kind", func(b PairedEnroll) string { return b.Kind }},
	{"offer_id_hash", func(b PairedEnroll) string { return b.OfferIDHash }},
	{"host_id", func(b PairedEnroll) string { return b.HostID }},
	{"endpoint", func(b PairedEnroll) string { return b.Endpoint }},
	{"endpoint_to_add", func(b PairedEnroll) string { return fmt.Sprint(b.EndpointToAdd) }},
	{"ssh_user", func(b PairedEnroll) string { return b.SSHUser }},
	{"credential_ref", func(b PairedEnroll) string { return b.CredentialRef }},
	{"host_key_fingerprint", func(b PairedEnroll) string { return b.HostKeyFingerprint }},
	{"code_matched", func(b PairedEnroll) string { return fmt.Sprint(b.CodeMatched) }},
	{"pairing_code", func(b PairedEnroll) string { return b.PairingCode }},
	{"expiry_unix", func(b PairedEnroll) string { return fmt.Sprint(b.ExpiryUnix) }},
}

// PairedEnrollDiff returns the canonical name of the first field in which
// a and b differ after filling version and kind, or "" if they are equal.
// It names the field only, never a value, so it may go into errors.
func PairedEnrollDiff(a, b PairedEnroll) string {
	a, b = fillPaired(a), fillPaired(b)
	for _, f := range pairedEnrollFields {
		if f.get(a) != f.get(b) {
			return f.name
		}
	}
	return ""
}

func fillPaired(b PairedEnroll) PairedEnroll {
	if b.Version == 0 {
		b.Version = PairedEnrollVersion
	}
	if b.Kind == "" {
		b.Kind = PairedEnrollKind
	}
	return b
}

// validatePaired checks the shape of every field (not the time) and
// returns the binding with version and kind filled. Every field must
// already be in canonical form: a second spelling of the same value is
// refused, so one meaning has exactly one digest.
func validatePaired(b PairedEnroll) (PairedEnroll, []string) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	if b.Version != 0 && b.Version != PairedEnrollVersion {
		add("unsupported paired_enroll_version %d", b.Version)
	}
	if b.Kind != "" && b.Kind != PairedEnrollKind {
		add("kind must be %s", PairedEnrollKind)
	}
	n := fillPaired(b)
	if !hex64.MatchString(n.OfferIDHash) {
		add("offer_id_hash must be 64 lowercase hex characters")
	}
	if !hostIDRe.MatchString(n.HostID) {
		add("host_id is malformed")
	}
	if ep, err := sshtransport.ParseEndpoint(n.Endpoint); err != nil || ep.String() != n.Endpoint {
		add("endpoint must be a valid endpoint in canonical host:port form")
	}
	if !sshUserRe.MatchString(n.SSHUser) {
		add("ssh_user is malformed")
	}
	if !credRefRe.MatchString(n.CredentialRef) {
		add("credential_ref is malformed")
	}
	if !fingerprintRe.MatchString(n.HostKeyFingerprint) {
		add("host_key_fingerprint must be a full OpenSSH SHA256 fingerprint")
	}
	if !n.CodeMatched {
		add("code_matched must be true: a paired permit exists only for a matched code")
	}
	if c, err := pairing.Parse(n.PairingCode); err != nil || c.String() != n.PairingCode {
		add("pairing_code must be a well-formed code in canonical form")
	}
	return n, p
}

// NormalizePairedEnroll validates b against now and returns it with
// version and kind filled. The expiry must lie in the future and at most
// MaxPairedEnrollLifetime ahead.
func NormalizePairedEnroll(b PairedEnroll, now time.Time) (PairedEnroll, error) {
	n, p := validatePaired(b)
	expiry := time.Unix(n.ExpiryUnix, 0)
	switch {
	case !expiry.After(now):
		p = append(p, "expiry is not in the future")
	case expiry.Sub(now) > MaxPairedEnrollLifetime:
		p = append(p, fmt.Sprintf("expiry exceeds the paired enrollment permit lifetime of %s", MaxPairedEnrollLifetime))
	}
	if len(p) > 0 {
		return PairedEnroll{}, &ValidationError{Problems: p}
	}
	return n, nil
}

// EncodePairedEnroll returns the RFC 8785 canonical JSON of a normalized
// binding.
func EncodePairedEnroll(n PairedEnroll) ([]byte, error) {
	raw, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("marshal paired enrollment: %w", err)
	}
	return jcs.Transform(raw)
}

// CanonicalizePairedEnroll normalizes b against now and returns the
// normalized binding, its canonical bytes and their SHA-256 digest.
func CanonicalizePairedEnroll(b PairedEnroll, now time.Time) (PairedEnroll, []byte, Digest, error) {
	n, err := NormalizePairedEnroll(b, now)
	if err != nil {
		return PairedEnroll{}, nil, Digest{}, err
	}
	c, err := EncodePairedEnroll(n)
	if err != nil {
		return PairedEnroll{}, nil, Digest{}, err
	}
	return n, c, sha256.Sum256(c), nil
}

// PairedEnrollDigest validates the shape of b, without the time checks,
// and returns its digest. The commit uses it to compare a presented
// binding with the approved one, also after the expiry has passed.
func PairedEnrollDigest(b PairedEnroll) (Digest, error) {
	n, p := validatePaired(b)
	if len(p) > 0 {
		return Digest{}, &ValidationError{Problems: p}
	}
	c, err := EncodePairedEnroll(n)
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(c), nil
}
