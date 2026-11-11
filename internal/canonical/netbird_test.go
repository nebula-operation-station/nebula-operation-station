// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

var netbirdNow = time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

func validNetBirdOffer() NetBirdOffer {
	return NetBirdOffer{
		OfferIDHash:        strings.Repeat("ab", 32),
		HostID:             "vps01",
		SSHUser:            "nebula",
		CredentialRef:      "nebula-default",
		ManagedGroup:       "nos-managed",
		Ephemeral:          false,
		SetupKeyExpiryUnix: netbirdNow.Add(55 * time.Minute).Unix(),
		ExpiryUnix:         netbirdNow.Add(10 * time.Minute).Unix(),
	}
}

func validNetBirdPeerDelete() NetBirdPeerDelete {
	return NetBirdPeerDelete{
		PeerID:            "chacbco6lnnbn6cg5s90",
		PeerName:          "vps01",
		NetBirdIP:         "100.64.12.7",
		OfferIDHash:       strings.Repeat("ab", 32),
		AttributionMethod: AttributionTimeWindow,
		ExpiryUnix:        netbirdNow.Add(10 * time.Minute).Unix(),
	}
}

func TestNetBirdOfferCanonicalFormIsStable(t *testing.T) {
	n, b, d, err := CanonicalizeNetBirdOffer(validNetBirdOffer(), netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"credential_ref":"nebula-default","ephemeral":false,"expiry_unix":` +
		strconv.FormatInt(netbirdNow.Add(10*time.Minute).Unix(), 10) +
		`,"host_id":"vps01","kind":"nebula.netbird_offer","managed_group":"nos-managed",` +
		`"netbird_offer_version":1,"offer_id_hash":"` + strings.Repeat("ab", 32) + `",` +
		`"setup_key_expiry_unix":` + strconv.FormatInt(netbirdNow.Add(55*time.Minute).Unix(), 10) +
		`,"ssh_user":"nebula"}`
	if string(b) != want {
		t.Fatalf("canonical bytes\n got %s\nwant %s", b, want)
	}
	if n.Version != NetBirdOfferVersion || n.Kind != NetBirdOfferKind {
		t.Fatalf("version/kind not filled: %+v", n)
	}
	_, b2, d2, err := CanonicalizeNetBirdOffer(n, netbirdNow)
	if err != nil || string(b2) != string(b) || d2 != d {
		t.Fatalf("re-canonicalizing the normalized form changed it: %v", err)
	}
}

func netbirdOfferFieldMutations() map[string]func(*NetBirdOffer) {
	return map[string]func(*NetBirdOffer){
		"offer_id_hash":         func(b *NetBirdOffer) { b.OfferIDHash = strings.Repeat("cd", 32) },
		"host_id":               func(b *NetBirdOffer) { b.HostID = "vps02" },
		"ssh_user":              func(b *NetBirdOffer) { b.SSHUser = "root" },
		"credential_ref":        func(b *NetBirdOffer) { b.CredentialRef = "other-cred" },
		"managed_group":         func(b *NetBirdOffer) { b.ManagedGroup = "All" },
		"ephemeral":             func(b *NetBirdOffer) { b.Ephemeral = true },
		"setup_key_expiry_unix": func(b *NetBirdOffer) { b.SetupKeyExpiryUnix-- },
		"expiry_unix":           func(b *NetBirdOffer) { b.ExpiryUnix-- },
	}
}

// TestNetBirdOfferEveryFieldChangesDigest: each bound field, changed to
// another valid value, yields another digest and is named by the diff.
func TestNetBirdOfferEveryFieldChangesDigest(t *testing.T) {
	_, _, base, err := CanonicalizeNetBirdOffer(validNetBirdOffer(), netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	muts := netbirdOfferFieldMutations()
	// Every canonical member except version and kind has a mutation.
	if len(muts) != len(netbirdOfferFields)-2 {
		t.Fatalf("%d mutations for %d fields", len(muts), len(netbirdOfferFields)-2)
	}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			b := validNetBirdOffer()
			mut(&b)
			_, _, d, err := CanonicalizeNetBirdOffer(b, netbirdNow)
			if err != nil {
				t.Fatalf("mutation must stay valid: %v", err)
			}
			if d == base {
				t.Fatal("digest did not change")
			}
			if f := NetBirdOfferDiff(validNetBirdOffer(), b); f != name {
				t.Fatalf("NetBirdOfferDiff = %q, want %q", f, name)
			}
		})
	}
}

func TestNetBirdOfferRejects(t *testing.T) {
	cases := map[string]func(*NetBirdOffer){
		"offer hash short":        func(b *NetBirdOffer) { b.OfferIDHash = strings.Repeat("a", 63) },
		"offer hash upper":        func(b *NetBirdOffer) { b.OfferIDHash = strings.Repeat("AB", 32) },
		"host id empty":           func(b *NetBirdOffer) { b.HostID = "" },
		"host id newline":         func(b *NetBirdOffer) { b.HostID = "vps01\n" },
		"ssh user empty":          func(b *NetBirdOffer) { b.SSHUser = "" },
		"ssh user shell":          func(b *NetBirdOffer) { b.SSHUser = "a;b" },
		"credential malformed":    func(b *NetBirdOffer) { b.CredentialRef = "../x" },
		"group empty":             func(b *NetBirdOffer) { b.ManagedGroup = "" },
		"group with space":        func(b *NetBirdOffer) { b.ManagedGroup = "nos managed" },
		"group with comma":        func(b *NetBirdOffer) { b.ManagedGroup = "nos-managed,All" },
		"group control char":      func(b *NetBirdOffer) { b.ManagedGroup = "nos\x1b[2Jmanaged" },
		"group bidi":              func(b *NetBirdOffer) { b.ManagedGroup = "nos" + string(rune(0x202e)) + "managed" },
		"group too long":          func(b *NetBirdOffer) { b.ManagedGroup = strings.Repeat("a", MaxNetBirdGroupLen+1) },
		"expiry past":             func(b *NetBirdOffer) { b.ExpiryUnix = netbirdNow.Unix() },
		"expiry too far":          func(b *NetBirdOffer) { b.ExpiryUnix = netbirdNow.Add(MaxNetBirdOfferLifetime + time.Second).Unix() },
		"setup key before permit": func(b *NetBirdOffer) { b.SetupKeyExpiryUnix = b.ExpiryUnix - 1 },
		"setup key too long": func(b *NetBirdOffer) {
			b.SetupKeyExpiryUnix = netbirdNow.Add(MaxNetBirdSetupKeyLifetime + time.Second).Unix()
		},
		"setup key zero":            func(b *NetBirdOffer) { b.SetupKeyExpiryUnix = 0 },
		"version unknown":           func(b *NetBirdOffer) { b.Version = 2 },
		"kind of paired permit":     func(b *NetBirdOffer) { b.Kind = PairedEnrollKind },
		"kind of peer delete":       func(b *NetBirdOffer) { b.Kind = NetBirdPeerDeleteKind },
		"credential trailing space": func(b *NetBirdOffer) { b.CredentialRef += " " },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := validNetBirdOffer()
			mut(&b)
			_, _, _, err := CanonicalizeNetBirdOffer(b, netbirdNow)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want *ValidationError, got %v", err)
			}
		})
	}
}

func TestNetBirdOfferLimitsAccepted(t *testing.T) {
	b := validNetBirdOffer()
	b.ExpiryUnix = netbirdNow.Add(MaxNetBirdOfferLifetime).Unix()
	b.SetupKeyExpiryUnix = netbirdNow.Add(MaxNetBirdSetupKeyLifetime).Unix()
	b.ManagedGroup = strings.Repeat("a", MaxNetBirdGroupLen)
	if _, _, _, err := CanonicalizeNetBirdOffer(b, netbirdNow); err != nil {
		t.Fatal(err)
	}
	b = validNetBirdOffer()
	b.SetupKeyExpiryUnix = b.ExpiryUnix
	if _, _, _, err := CanonicalizeNetBirdOffer(b, netbirdNow); err != nil {
		t.Fatalf("setup key expiring with the permit: %v", err)
	}
}

func TestNetBirdOfferDigestIgnoresTime(t *testing.T) {
	b := validNetBirdOffer()
	_, _, d1, err := CanonicalizeNetBirdOffer(b, netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := NetBirdOfferDigest(b)
	if err != nil || d2 != d1 {
		t.Fatalf("NetBirdOfferDigest = %v, %v", d2, err)
	}
	b.ManagedGroup = "a b"
	if _, err := NetBirdOfferDigest(b); err == nil {
		t.Fatal("NetBirdOfferDigest accepted a malformed group")
	}
	b = validNetBirdOffer()
	b.SetupKeyExpiryUnix = b.ExpiryUnix - 1
	if _, err := NetBirdOfferDigest(b); err == nil {
		t.Fatal("NetBirdOfferDigest accepted a setup key expiring before the permit")
	}
}

func TestNetBirdPeerDeleteCanonicalFormIsStable(t *testing.T) {
	n, b, d, err := CanonicalizeNetBirdPeerDelete(validNetBirdPeerDelete(), netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"attribution_method":"time_window","expiry_unix":` +
		strconv.FormatInt(netbirdNow.Add(10*time.Minute).Unix(), 10) +
		`,"kind":"nebula.netbird_peer_delete","netbird_ip":"100.64.12.7",` +
		`"netbird_peer_delete_version":1,"offer_id_hash":"` + strings.Repeat("ab", 32) + `",` +
		`"peer_id":"chacbco6lnnbn6cg5s90","peer_name":"vps01"}`
	if string(b) != want {
		t.Fatalf("canonical bytes\n got %s\nwant %s", b, want)
	}
	if n.Version != NetBirdPeerDeleteVersion || n.Kind != NetBirdPeerDeleteKind {
		t.Fatalf("version/kind not filled: %+v", n)
	}
	_, b2, d2, err := CanonicalizeNetBirdPeerDelete(n, netbirdNow)
	if err != nil || string(b2) != string(b) || d2 != d {
		t.Fatalf("re-canonicalizing the normalized form changed it: %v", err)
	}
}

func netbirdPeerDeleteFieldMutations() map[string]func(*NetBirdPeerDelete) {
	return map[string]func(*NetBirdPeerDelete){
		"peer_id":            func(b *NetBirdPeerDelete) { b.PeerID = "chacbco6lnnbn6cg5s91" },
		"peer_name":          func(b *NetBirdPeerDelete) { b.PeerName = "vps02" },
		"netbird_ip":         func(b *NetBirdPeerDelete) { b.NetBirdIP = "100.64.12.8" },
		"offer_id_hash":      func(b *NetBirdPeerDelete) { b.OfferIDHash = strings.Repeat("cd", 32) },
		"attribution_method": func(b *NetBirdPeerDelete) { b.AttributionMethod = AttributionSetupKey },
		"expiry_unix":        func(b *NetBirdPeerDelete) { b.ExpiryUnix-- },
	}
}

func TestNetBirdPeerDeleteEveryFieldChangesDigest(t *testing.T) {
	_, _, base, err := CanonicalizeNetBirdPeerDelete(validNetBirdPeerDelete(), netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	muts := netbirdPeerDeleteFieldMutations()
	if len(muts) != len(netbirdPeerDeleteFields)-2 {
		t.Fatalf("%d mutations for %d fields", len(muts), len(netbirdPeerDeleteFields)-2)
	}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			b := validNetBirdPeerDelete()
			mut(&b)
			_, _, d, err := CanonicalizeNetBirdPeerDelete(b, netbirdNow)
			if err != nil {
				t.Fatalf("mutation must stay valid: %v", err)
			}
			if d == base {
				t.Fatal("digest did not change")
			}
			if f := NetBirdPeerDeleteDiff(validNetBirdPeerDelete(), b); f != name {
				t.Fatalf("NetBirdPeerDeleteDiff = %q, want %q", f, name)
			}
		})
	}
}

func TestNetBirdPeerDeleteRejects(t *testing.T) {
	cases := map[string]func(*NetBirdPeerDelete){
		"peer id empty":         func(b *NetBirdPeerDelete) { b.PeerID = "" },
		"peer id upper":         func(b *NetBirdPeerDelete) { b.PeerID = "CHACBCO6" },
		"peer id slash":         func(b *NetBirdPeerDelete) { b.PeerID = "abc/../x" },
		"peer id too long":      func(b *NetBirdPeerDelete) { b.PeerID = strings.Repeat("a", MaxNetBirdPeerIDLen+1) },
		"peer name empty":       func(b *NetBirdPeerDelete) { b.PeerName = "" },
		"peer name too long":    func(b *NetBirdPeerDelete) { b.PeerName = strings.Repeat("a", MaxNetBirdPeerNameLen+1) },
		"peer name newline":     func(b *NetBirdPeerDelete) { b.PeerName = "vps01\nApproval: none" },
		"peer name escape":      func(b *NetBirdPeerDelete) { b.PeerName = "vps\x1b[2J01" },
		"peer name bidi":        func(b *NetBirdPeerDelete) { b.PeerName = "vps" + string(rune(0x202e)) + "10" },
		"peer name invalid utf": func(b *NetBirdPeerDelete) { b.PeerName = "vps\xff" },
		"peer name zero width":  func(b *NetBirdPeerDelete) { b.PeerName = "vps" + string(rune(0x200b)) + "01" },
		"ip empty":              func(b *NetBirdPeerDelete) { b.NetBirdIP = "" },
		"ip not an ip":          func(b *NetBirdPeerDelete) { b.NetBirdIP = "vps01" },
		"ip with port":          func(b *NetBirdPeerDelete) { b.NetBirdIP = "100.64.12.7:22" },
		"ip with zone":          func(b *NetBirdPeerDelete) { b.NetBirdIP = "fe80::1%wt0" },
		"ip mapped":             func(b *NetBirdPeerDelete) { b.NetBirdIP = "::ffff:100.64.12.7" },
		"ip not canonical v6":   func(b *NetBirdPeerDelete) { b.NetBirdIP = "fd00:0::1" },
		"ip unspecified":        func(b *NetBirdPeerDelete) { b.NetBirdIP = "0.0.0.0" },
		"offer hash short":      func(b *NetBirdPeerDelete) { b.OfferIDHash = "ab" },
		"attribution empty":     func(b *NetBirdPeerDelete) { b.AttributionMethod = "" },
		"attribution unknown":   func(b *NetBirdPeerDelete) { b.AttributionMethod = "guess" },
		"expiry past":           func(b *NetBirdPeerDelete) { b.ExpiryUnix = netbirdNow.Unix() },
		"expiry too far": func(b *NetBirdPeerDelete) {
			b.ExpiryUnix = netbirdNow.Add(MaxNetBirdPeerDeleteLifetime + time.Second).Unix()
		},
		"version unknown":      func(b *NetBirdPeerDelete) { b.Version = 2 },
		"kind of offer permit": func(b *NetBirdPeerDelete) { b.Kind = NetBirdOfferKind },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := validNetBirdPeerDelete()
			mut(&b)
			_, _, _, err := CanonicalizeNetBirdPeerDelete(b, netbirdNow)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want *ValidationError, got %v", err)
			}
		})
	}
}

func TestNetBirdPeerDeleteAcceptsIPv6AndUnicodeName(t *testing.T) {
	b := validNetBirdPeerDelete()
	b.NetBirdIP = "fd00::1"
	b.PeerName = "büro-pc"
	b.PeerID = strings.Repeat("z", MaxNetBirdPeerIDLen)
	b.ExpiryUnix = netbirdNow.Add(MaxNetBirdPeerDeleteLifetime).Unix()
	if _, _, _, err := CanonicalizeNetBirdPeerDelete(b, netbirdNow); err != nil {
		t.Fatal(err)
	}
}

func TestNetBirdPeerDeleteDigestIgnoresTime(t *testing.T) {
	b := validNetBirdPeerDelete()
	_, _, d1, err := CanonicalizeNetBirdPeerDelete(b, netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := NetBirdPeerDeleteDigest(b)
	if err != nil || d2 != d1 {
		t.Fatalf("NetBirdPeerDeleteDigest = %v, %v", d2, err)
	}
	b.AttributionMethod = "guess"
	if _, err := NetBirdPeerDeleteDigest(b); err == nil {
		t.Fatal("NetBirdPeerDeleteDigest accepted an unknown attribution")
	}
}

// TestNetBirdKindsNeverShareADigest: the three enrollment bindings carry
// distinct kinds, so no binding of one kind hashes like another kind.
func TestNetBirdKindsNeverShareADigest(t *testing.T) {
	_, ob, _, err := CanonicalizeNetBirdOffer(validNetBirdOffer(), netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	_, pb, _, err := CanonicalizeNetBirdPeerDelete(validNetBirdPeerDelete(), netbirdNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ob), `"kind":"nebula.netbird_offer"`) ||
		!strings.Contains(string(pb), `"kind":"nebula.netbird_peer_delete"`) {
		t.Fatalf("kind missing:\n%s\n%s", ob, pb)
	}
	if NetBirdOfferKind == PairedEnrollKind || NetBirdPeerDeleteKind == PairedEnrollKind || NetBirdOfferKind == NetBirdPeerDeleteKind {
		t.Fatal("kinds collide")
	}
}

func TestNetBirdDiffEqual(t *testing.T) {
	if f := NetBirdOfferDiff(validNetBirdOffer(), validNetBirdOffer()); f != "" {
		t.Fatalf("equal offers differ in %q", f)
	}
	if f := NetBirdPeerDeleteDiff(validNetBirdPeerDelete(), validNetBirdPeerDelete()); f != "" {
		t.Fatalf("equal peer deletes differ in %q", f)
	}
}
