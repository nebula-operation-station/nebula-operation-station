// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// NetBird offer permit and NetBird peer delete permit bindings (ADR 0013
// D1 step 2 and D6, EN-07). Both are HIGH with user verification; the
// approval signs the digest of the binding, and the executor checks the
// binding it acts on against every bound field.

// Versions and kinds of the NetBird bindings. The kind separates them from
// each other and from every other canonical document.
const (
	NetBirdOfferVersion      = 1
	NetBirdOfferKind         = "nebula.netbird_offer"
	NetBirdPeerDeleteVersion = 1
	NetBirdPeerDeleteKind    = "nebula.netbird_peer_delete"
)

// NetBird binding limits.
const (
	// MaxNetBirdOfferLifetime bounds the expiry of a NetBird offer permit:
	// the offer lifetime (D2), since the permit must be approved while the
	// offer is still awaiting approval.
	MaxNetBirdOfferLifetime = 15 * time.Minute
	// MaxNetBirdSetupKeyLifetime bounds the bound setup-key expiry,
	// measured from the proposal (the key itself is created later, so its
	// own lifetime is shorter still).
	MaxNetBirdSetupKeyLifetime = time.Hour
	// MaxNetBirdPeerDeleteLifetime bounds the expiry of a NetBird peer
	// delete permit.
	MaxNetBirdPeerDeleteLifetime = 15 * time.Minute
	// MaxNetBirdGroupLen is the longest managed group name.
	MaxNetBirdGroupLen = 64
	// MaxNetBirdPeerIDLen is the longest NetBird peer ID.
	MaxNetBirdPeerIDLen = 64
	// MaxNetBirdPeerNameLen is the longest peer name in bytes.
	MaxNetBirdPeerNameLen = 255
	// maxNetBirdIPLen bounds the NetBird IP literal before parsing.
	maxNetBirdIPLen = 45
)

// Peer attribution methods (ADR 0013 D6, Q8).
const (
	// AttributionSetupKey: the NetBird API named this offer's setup key as
	// the one the peer registered with.
	AttributionSetupKey = "setup_key"
	// AttributionTimeWindow: the weaker fallback, the only new peer in the
	// managed group within the offer's time window.
	AttributionTimeWindow = "time_window"
)

var (
	// netbirdGroupRe is deliberately narrower than what NetBird accepts:
	// no spaces, separators or non-ASCII, so the name shown for approval
	// is unambiguous.
	netbirdGroupRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	netbirdPeerIDRe = regexp.MustCompile(`^[0-9a-z]+$`)
)

// ValidNetBirdGroup reports whether s is an acceptable managed group name.
func ValidNetBirdGroup(s string) bool {
	return len(s) <= MaxNetBirdGroupLen && netbirdGroupRe.MatchString(s)
}

// ValidNetBirdPeerID reports whether s is a well-formed NetBird peer ID:
// 1..MaxNetBirdPeerIDLen characters 0-9a-z.
func ValidNetBirdPeerID(s string) bool {
	return len(s) <= MaxNetBirdPeerIDLen && netbirdPeerIDRe.MatchString(s)
}

// ValidNetBirdPeerName reports whether s is an acceptable peer name: 1 to
// MaxNetBirdPeerNameLen bytes of valid UTF-8 with printable characters
// only (this also refuses control, bidi and zero-width characters). It
// comes from the NetBird API and is untrusted.
func ValidNetBirdPeerName(s string) bool {
	if s == "" || len(s) > MaxNetBirdPeerNameLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ValidNetBirdIP reports whether s is an IP address literal in canonical
// form: no zone, no IPv4-mapped IPv6 form, not unspecified.
func ValidNetBirdIP(s string) bool {
	if s == "" || len(s) > maxNetBirdIPLen {
		return false
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() {
		return false
	}
	return a.String() == s
}

// NetBirdOffer is the canonical NetBird offer permit binding. Its approval
// is what lets the executor create the offer's one-off setup key. Field
// names are part of the canonical form and must never change without
// bumping NetBirdOfferVersion.
type NetBirdOffer struct {
	Version int    `json:"netbird_offer_version"`
	Kind    string `json:"kind"`
	// OfferIDHash is the lowercase hex SHA-256 of the offer ID.
	OfferIDHash   string `json:"offer_id_hash"`
	HostID        string `json:"host_id"`
	SSHUser       string `json:"ssh_user"`
	CredentialRef string `json:"credential_ref"`
	// ManagedGroup is the only auto-group of the setup key.
	ManagedGroup string `json:"managed_group"`
	// Ephemeral: peers joining with the key are ephemeral.
	Ephemeral bool `json:"ephemeral"`
	// SetupKeyExpiryUnix is the latest expiry the setup key may get.
	SetupKeyExpiryUnix int64 `json:"setup_key_expiry_unix"`
	// ExpiryUnix is the permit's own expiry (the offer expiry).
	ExpiryUnix int64 `json:"expiry_unix"`
}

var netbirdOfferFields = []struct {
	name string
	get  func(NetBirdOffer) string
}{
	{"netbird_offer_version", func(b NetBirdOffer) string { return fmt.Sprint(b.Version) }},
	{"kind", func(b NetBirdOffer) string { return b.Kind }},
	{"offer_id_hash", func(b NetBirdOffer) string { return b.OfferIDHash }},
	{"host_id", func(b NetBirdOffer) string { return b.HostID }},
	{"ssh_user", func(b NetBirdOffer) string { return b.SSHUser }},
	{"credential_ref", func(b NetBirdOffer) string { return b.CredentialRef }},
	{"managed_group", func(b NetBirdOffer) string { return b.ManagedGroup }},
	{"ephemeral", func(b NetBirdOffer) string { return fmt.Sprint(b.Ephemeral) }},
	{"setup_key_expiry_unix", func(b NetBirdOffer) string { return fmt.Sprint(b.SetupKeyExpiryUnix) }},
	{"expiry_unix", func(b NetBirdOffer) string { return fmt.Sprint(b.ExpiryUnix) }},
}

// NetBirdOfferDiff returns the canonical name of the first field in which
// a and b differ after filling version and kind, or "" if they are equal.
// It names the field only, never a value.
func NetBirdOfferDiff(a, b NetBirdOffer) string {
	a, b = fillNetBirdOffer(a), fillNetBirdOffer(b)
	for _, f := range netbirdOfferFields {
		if f.get(a) != f.get(b) {
			return f.name
		}
	}
	return ""
}

func fillNetBirdOffer(b NetBirdOffer) NetBirdOffer {
	if b.Version == 0 {
		b.Version = NetBirdOfferVersion
	}
	if b.Kind == "" {
		b.Kind = NetBirdOfferKind
	}
	return b
}

// validateNetBirdOffer checks the shape of every field and the relation of
// the two expiries, but not the time; every field must already be in
// canonical form.
func validateNetBirdOffer(b NetBirdOffer) (NetBirdOffer, []string) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	if b.Version != 0 && b.Version != NetBirdOfferVersion {
		add("unsupported netbird_offer_version %d", b.Version)
	}
	if b.Kind != "" && b.Kind != NetBirdOfferKind {
		add("kind must be %s", NetBirdOfferKind)
	}
	n := fillNetBirdOffer(b)
	if !hex64.MatchString(n.OfferIDHash) {
		add("offer_id_hash must be 64 lowercase hex characters")
	}
	if !hostIDRe.MatchString(n.HostID) {
		add("host_id is malformed")
	}
	if !sshUserRe.MatchString(n.SSHUser) {
		add("ssh_user is malformed")
	}
	if !credRefRe.MatchString(n.CredentialRef) {
		add("credential_ref is malformed")
	}
	if !ValidNetBirdGroup(n.ManagedGroup) {
		add("managed_group must be 1..%d characters A-Za-z0-9._- starting with a letter or digit", MaxNetBirdGroupLen)
	}
	if n.SetupKeyExpiryUnix < n.ExpiryUnix {
		add("setup_key_expiry_unix must not lie before the permit expiry")
	}
	return n, p
}

// NormalizeNetBirdOffer validates b against now and returns it with
// version and kind filled. The permit expiry must lie in the future and at
// most MaxNetBirdOfferLifetime ahead; the setup-key expiry at most
// MaxNetBirdSetupKeyLifetime ahead.
func NormalizeNetBirdOffer(b NetBirdOffer, now time.Time) (NetBirdOffer, error) {
	n, p := validateNetBirdOffer(b)
	expiry := time.Unix(n.ExpiryUnix, 0)
	switch {
	case !expiry.After(now):
		p = append(p, "expiry is not in the future")
	case expiry.Sub(now) > MaxNetBirdOfferLifetime:
		p = append(p, fmt.Sprintf("expiry exceeds the NetBird offer permit lifetime of %s", MaxNetBirdOfferLifetime))
	}
	if time.Unix(n.SetupKeyExpiryUnix, 0).Sub(now) > MaxNetBirdSetupKeyLifetime {
		p = append(p, fmt.Sprintf("setup_key_expiry_unix exceeds the setup-key lifetime of %s", MaxNetBirdSetupKeyLifetime))
	}
	if len(p) > 0 {
		return NetBirdOffer{}, &ValidationError{Problems: p}
	}
	return n, nil
}

// EncodeNetBirdOffer returns the RFC 8785 canonical JSON of a normalized
// binding.
func EncodeNetBirdOffer(n NetBirdOffer) ([]byte, error) {
	raw, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("marshal netbird offer: %w", err)
	}
	return jcs.Transform(raw)
}

// CanonicalizeNetBirdOffer normalizes b against now and returns the
// normalized binding, its canonical bytes and their SHA-256 digest.
func CanonicalizeNetBirdOffer(b NetBirdOffer, now time.Time) (NetBirdOffer, []byte, Digest, error) {
	n, err := NormalizeNetBirdOffer(b, now)
	if err != nil {
		return NetBirdOffer{}, nil, Digest{}, err
	}
	c, err := EncodeNetBirdOffer(n)
	if err != nil {
		return NetBirdOffer{}, nil, Digest{}, err
	}
	return n, c, sha256.Sum256(c), nil
}

// NetBirdOfferDigest validates the shape of b, without the time checks,
// and returns its digest, for comparing a presented binding with the
// approved one.
func NetBirdOfferDigest(b NetBirdOffer) (Digest, error) {
	n, p := validateNetBirdOffer(b)
	if len(p) > 0 {
		return Digest{}, &ValidationError{Problems: p}
	}
	c, err := EncodeNetBirdOffer(n)
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(c), nil
}

// NetBirdPeerDelete is the canonical NetBird peer delete permit binding:
// the delete of a peer attributed to an offer (orphan or rogue peer).
// Field names are part of the canonical form and must never change
// without bumping NetBirdPeerDeleteVersion.
type NetBirdPeerDelete struct {
	Version int    `json:"netbird_peer_delete_version"`
	Kind    string `json:"kind"`
	PeerID  string `json:"peer_id"`
	// PeerName comes from the NetBird API; display it as text only.
	PeerName string `json:"peer_name"`
	// NetBirdIP is the peer's NetBird address in canonical form.
	NetBirdIP string `json:"netbird_ip"`
	// OfferIDHash is the offer the peer is attributed to.
	OfferIDHash string `json:"offer_id_hash"`
	// AttributionMethod is AttributionSetupKey or AttributionTimeWindow.
	AttributionMethod string `json:"attribution_method"`
	ExpiryUnix        int64  `json:"expiry_unix"`
}

var netbirdPeerDeleteFields = []struct {
	name string
	get  func(NetBirdPeerDelete) string
}{
	{"netbird_peer_delete_version", func(b NetBirdPeerDelete) string { return fmt.Sprint(b.Version) }},
	{"kind", func(b NetBirdPeerDelete) string { return b.Kind }},
	{"peer_id", func(b NetBirdPeerDelete) string { return b.PeerID }},
	{"peer_name", func(b NetBirdPeerDelete) string { return b.PeerName }},
	{"netbird_ip", func(b NetBirdPeerDelete) string { return b.NetBirdIP }},
	{"offer_id_hash", func(b NetBirdPeerDelete) string { return b.OfferIDHash }},
	{"attribution_method", func(b NetBirdPeerDelete) string { return b.AttributionMethod }},
	{"expiry_unix", func(b NetBirdPeerDelete) string { return fmt.Sprint(b.ExpiryUnix) }},
}

// NetBirdPeerDeleteDiff returns the canonical name of the first field in
// which a and b differ after filling version and kind, or "" if they are
// equal. It names the field only, never a value.
func NetBirdPeerDeleteDiff(a, b NetBirdPeerDelete) string {
	a, b = fillNetBirdPeerDelete(a), fillNetBirdPeerDelete(b)
	for _, f := range netbirdPeerDeleteFields {
		if f.get(a) != f.get(b) {
			return f.name
		}
	}
	return ""
}

func fillNetBirdPeerDelete(b NetBirdPeerDelete) NetBirdPeerDelete {
	if b.Version == 0 {
		b.Version = NetBirdPeerDeleteVersion
	}
	if b.Kind == "" {
		b.Kind = NetBirdPeerDeleteKind
	}
	return b
}

func validateNetBirdPeerDelete(b NetBirdPeerDelete) (NetBirdPeerDelete, []string) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }
	if b.Version != 0 && b.Version != NetBirdPeerDeleteVersion {
		add("unsupported netbird_peer_delete_version %d", b.Version)
	}
	if b.Kind != "" && b.Kind != NetBirdPeerDeleteKind {
		add("kind must be %s", NetBirdPeerDeleteKind)
	}
	n := fillNetBirdPeerDelete(b)
	if !ValidNetBirdPeerID(n.PeerID) {
		add("peer_id must be 1..%d characters 0-9a-z", MaxNetBirdPeerIDLen)
	}
	if !ValidNetBirdPeerName(n.PeerName) {
		add("peer_name must be 1..%d bytes of printable UTF-8", MaxNetBirdPeerNameLen)
	}
	if !ValidNetBirdIP(n.NetBirdIP) {
		add("netbird_ip must be an IP address in canonical form without zone")
	}
	if !hex64.MatchString(n.OfferIDHash) {
		add("offer_id_hash must be 64 lowercase hex characters")
	}
	if n.AttributionMethod != AttributionSetupKey && n.AttributionMethod != AttributionTimeWindow {
		add("attribution_method must be %s or %s", AttributionSetupKey, AttributionTimeWindow)
	}
	return n, p
}

// NormalizeNetBirdPeerDelete validates b against now and returns it with
// version and kind filled. The expiry must lie in the future and at most
// MaxNetBirdPeerDeleteLifetime ahead.
func NormalizeNetBirdPeerDelete(b NetBirdPeerDelete, now time.Time) (NetBirdPeerDelete, error) {
	n, p := validateNetBirdPeerDelete(b)
	expiry := time.Unix(n.ExpiryUnix, 0)
	switch {
	case !expiry.After(now):
		p = append(p, "expiry is not in the future")
	case expiry.Sub(now) > MaxNetBirdPeerDeleteLifetime:
		p = append(p, fmt.Sprintf("expiry exceeds the NetBird peer delete permit lifetime of %s", MaxNetBirdPeerDeleteLifetime))
	}
	if len(p) > 0 {
		return NetBirdPeerDelete{}, &ValidationError{Problems: p}
	}
	return n, nil
}

// EncodeNetBirdPeerDelete returns the RFC 8785 canonical JSON of a
// normalized binding.
func EncodeNetBirdPeerDelete(n NetBirdPeerDelete) ([]byte, error) {
	raw, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("marshal netbird peer delete: %w", err)
	}
	return jcs.Transform(raw)
}

// CanonicalizeNetBirdPeerDelete normalizes b against now and returns the
// normalized binding, its canonical bytes and their SHA-256 digest.
func CanonicalizeNetBirdPeerDelete(b NetBirdPeerDelete, now time.Time) (NetBirdPeerDelete, []byte, Digest, error) {
	n, err := NormalizeNetBirdPeerDelete(b, now)
	if err != nil {
		return NetBirdPeerDelete{}, nil, Digest{}, err
	}
	c, err := EncodeNetBirdPeerDelete(n)
	if err != nil {
		return NetBirdPeerDelete{}, nil, Digest{}, err
	}
	return n, c, sha256.Sum256(c), nil
}

// NetBirdPeerDeleteDigest validates the shape of b, without the time
// checks, and returns its digest.
func NetBirdPeerDeleteDigest(b NetBirdPeerDelete) (Digest, error) {
	n, p := validateNetBirdPeerDelete(b)
	if len(p) > 0 {
		return Digest{}, &ValidationError{Problems: p}
	}
	c, err := EncodeNetBirdPeerDelete(n)
	if err != nil {
		return Digest{}, err
	}
	return sha256.Sum256(c), nil
}
