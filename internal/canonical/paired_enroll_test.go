// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
)

var pairedNow = time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

// validPaired returns a binding that canonicalizes at pairedNow. The pairing
// code is a well-formed code (check character included).
func validPaired() PairedEnroll {
	return PairedEnroll{
		OfferIDHash:        strings.Repeat("ab", 32),
		HostID:             "web01",
		Endpoint:           "192.0.2.10:22",
		EndpointToAdd:      true,
		SSHUser:            "nebula",
		CredentialRef:      "nebula-default",
		HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		CodeMatched:        true,
		PairingCode:        "00000-00000-00000-00000-0000" + "0",
		ExpiryUnix:         pairedNow.Add(10 * time.Minute).Unix(),
	}
}

func TestPairedEnrollCanonicalFormIsStable(t *testing.T) {
	n, b, d, err := CanonicalizePairedEnroll(validPaired(), pairedNow)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"code_matched":true,"credential_ref":"nebula-default","endpoint":"192.0.2.10:22","endpoint_to_add":true,` +
		`"expiry_unix":` + strconv.FormatInt(pairedNow.Add(10*time.Minute).Unix(), 10) + `,"host_id":"web01","host_key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",` +
		`"kind":"nebula.paired_enroll","offer_id_hash":"` + strings.Repeat("ab", 32) + `",` +
		`"paired_enroll_version":1,"pairing_code":"00000-00000-00000-00000-00000","ssh_user":"nebula"}`
	if string(b) != want {
		t.Fatalf("canonical bytes\n got %s\nwant %s", b, want)
	}
	if n.Version != PairedEnrollVersion || n.Kind != PairedEnrollKind {
		t.Fatalf("version/kind not filled: %+v", n)
	}
	_, b2, d2, err := CanonicalizePairedEnroll(n, pairedNow)
	if err != nil || string(b2) != string(b) || d2 != d {
		t.Fatalf("re-canonicalizing the normalized form changed it: %v", err)
	}
}

// TestPairedEnrollEveryFieldChangesDigest: each bound field, changed to
// another valid value, yields another digest.
func TestPairedEnrollEveryFieldChangesDigest(t *testing.T) {
	_, _, base, err := CanonicalizePairedEnroll(validPaired(), pairedNow)
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range pairedFieldMutations() {
		t.Run(name, func(t *testing.T) {
			b := validPaired()
			mut(&b)
			_, _, d, err := CanonicalizePairedEnroll(b, pairedNow)
			if err != nil {
				t.Fatalf("mutation must stay valid: %v", err)
			}
			if d == base {
				t.Fatal("digest did not change")
			}
			if f := PairedEnrollDiff(validPaired(), b); f != name {
				t.Fatalf("PairedEnrollDiff = %q, want %q", f, name)
			}
		})
	}
}

// pairedFieldMutations maps each bound field (by its canonical name) to a
// change to another valid value. code_matched has no valid alternative
// (false is refused), it is covered by TestPairedEnrollRejects.
func pairedFieldMutations() map[string]func(*PairedEnroll) {
	return map[string]func(*PairedEnroll){
		"offer_id_hash":        func(b *PairedEnroll) { b.OfferIDHash = strings.Repeat("cd", 32) },
		"host_id":              func(b *PairedEnroll) { b.HostID = "web02" },
		"endpoint":             func(b *PairedEnroll) { b.Endpoint = "192.0.2.11:22" },
		"endpoint_to_add":      func(b *PairedEnroll) { b.EndpointToAdd = false },
		"ssh_user":             func(b *PairedEnroll) { b.SSHUser = "root" },
		"credential_ref":       func(b *PairedEnroll) { b.CredentialRef = "other-cred" },
		"host_key_fingerprint": func(b *PairedEnroll) { b.HostKeyFingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
		"pairing_code":         func(b *PairedEnroll) { b.PairingCode = otherPairingCode() },
		"expiry_unix":          func(b *PairedEnroll) { b.ExpiryUnix-- },
	}
}

// otherPairingCode returns a well-formed canonical code other than the one
// in validPaired: data "1000…0" with the matching check character.
func otherPairingCode() string {
	for _, ch := range "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U" {
		c, err := pairing.Parse("10000-00000-00000-00000-0000" + string(ch))
		if err == nil {
			return c.String()
		}
	}
	panic("no check character found")
}

func TestPairedEnrollRejects(t *testing.T) {
	cases := map[string]func(*PairedEnroll){
		"offer hash short":          func(b *PairedEnroll) { b.OfferIDHash = strings.Repeat("a", 63) },
		"offer hash upper":          func(b *PairedEnroll) { b.OfferIDHash = strings.Repeat("AB", 32) },
		"host id empty":             func(b *PairedEnroll) { b.HostID = "" },
		"host id upper":             func(b *PairedEnroll) { b.HostID = "Web01" },
		"endpoint empty":            func(b *PairedEnroll) { b.Endpoint = "" },
		"endpoint without port":     func(b *PairedEnroll) { b.Endpoint = "192.0.2.10" },
		"endpoint upper case":       func(b *PairedEnroll) { b.Endpoint = "Host.example.org:22" },
		"endpoint leading zero":     func(b *PairedEnroll) { b.Endpoint = "192.0.2.10:022" },
		"endpoint bad host":         func(b *PairedEnroll) { b.Endpoint = "a b:22" },
		"endpoint newline":          func(b *PairedEnroll) { b.Endpoint = "host\n:22" },
		"ssh user empty":            func(b *PairedEnroll) { b.SSHUser = "" },
		"ssh user shell":            func(b *PairedEnroll) { b.SSHUser = "a;b" },
		"ssh user too long":         func(b *PairedEnroll) { b.SSHUser = strings.Repeat("a", 33) },
		"credential empty":          func(b *PairedEnroll) { b.CredentialRef = "" },
		"credential malformed":      func(b *PairedEnroll) { b.CredentialRef = "../x" },
		"fingerprint truncated":     func(b *PairedEnroll) { b.HostKeyFingerprint = "SHA256:AAAAAAAA" },
		"fingerprint md5":           func(b *PairedEnroll) { b.HostKeyFingerprint = "MD5:aa:bb" },
		"code not matched":          func(b *PairedEnroll) { b.CodeMatched = false },
		"code empty":                func(b *PairedEnroll) { b.PairingCode = "" },
		"code wrong check":          func(b *PairedEnroll) { b.PairingCode = "00000-00000-00000-00000-00001" },
		"code not canonical":        func(b *PairedEnroll) { b.PairingCode = "0000000000000000000000000" },
		"code lower case":           func(b *PairedEnroll) { b.PairingCode = strings.ToLower(otherPairingCode()) },
		"code with spaces":          func(b *PairedEnroll) { b.PairingCode = strings.ReplaceAll(b.PairingCode, "-", " ") },
		"expiry past":               func(b *PairedEnroll) { b.ExpiryUnix = pairedNow.Unix() },
		"expiry too far":            func(b *PairedEnroll) { b.ExpiryUnix = pairedNow.Add(MaxPairedEnrollLifetime + time.Second).Unix() },
		"version unknown":           func(b *PairedEnroll) { b.Version = 2 },
		"kind of another permit":    func(b *PairedEnroll) { b.Kind = "nebula.netbird_offer" },
		"offer hash with space":     func(b *PairedEnroll) { b.OfferIDHash = " " + strings.Repeat("a", 63) },
		"fingerprint trailing data": func(b *PairedEnroll) { b.HostKeyFingerprint += "\n" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := validPaired()
			mut(&b)
			_, _, _, err := CanonicalizePairedEnroll(b, pairedNow)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want *ValidationError, got %v", err)
			}
		})
	}
}

func TestPairedEnrollMaxLifetimeAccepted(t *testing.T) {
	b := validPaired()
	b.ExpiryUnix = pairedNow.Add(MaxPairedEnrollLifetime).Unix()
	if _, _, _, err := CanonicalizePairedEnroll(b, pairedNow); err != nil {
		t.Fatal(err)
	}
}

// TestPairedEnrollEncodingNamesItsKind: the kind member separates the
// paired binding from every other canonical document.
func TestPairedEnrollEncodingNamesItsKind(t *testing.T) {
	_, b, _, err := CanonicalizePairedEnroll(validPaired(), pairedNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"kind":"nebula.paired_enroll"`) {
		t.Fatalf("kind missing: %s", b)
	}
}

func TestPairedEnrollDigestIgnoresTime(t *testing.T) {
	b := validPaired()
	_, _, d1, err := CanonicalizePairedEnroll(b, pairedNow)
	if err != nil {
		t.Fatal(err)
	}
	// After expiry the binding no longer canonicalizes for a proposal, but
	// its digest is still computable for the commit-time comparison.
	d2, err := PairedEnrollDigest(b)
	if err != nil || d2 != d1 {
		t.Fatalf("PairedEnrollDigest = %v, %v", d2, err)
	}
	b.CodeMatched = false
	if _, err := PairedEnrollDigest(b); err == nil {
		t.Fatal("PairedEnrollDigest accepted an unmatched code")
	}
}

func TestPairedEnrollDiffEqual(t *testing.T) {
	if f := PairedEnrollDiff(validPaired(), validPaired()); f != "" {
		t.Fatalf("equal bindings differ in %q", f)
	}
	b := validPaired()
	b.CodeMatched = false
	if f := PairedEnrollDiff(validPaired(), b); f != "code_matched" {
		t.Fatalf("got %q", f)
	}
}
