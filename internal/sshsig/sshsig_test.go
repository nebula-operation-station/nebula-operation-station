// SPDX-License-Identifier: AGPL-3.0-or-later

package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Signatures made by OpenSSH's ssh-keygen -Y sign (testdata, from a
// throwaway key whose private half was deleted).
func TestOpenSSHSignatures(t *testing.T) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(load(t, "signer.pub"))
	if err != nil {
		t.Fatal(err)
	}
	msg := load(t, "message.json")
	for _, f := range []string{"message-512.sig", "message-256.sig"} {
		if err := Verify(pub, "nebula-module", msg, load(t, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if err := Verify(pub, "nebula-module", msg, load(t, "message-othernamespace.sig")); !errors.Is(err, ErrNamespace) {
		t.Fatal(err)
	}
	if err := Verify(pub, "nebula-module", append(msg, ' '), load(t, "message-512.sig")); !errors.Is(err, ErrSignature) {
		t.Fatal(err)
	}
	k, ns, err := Parse(load(t, "message-512.sig"))
	if err != nil || ns != "nebula-module" || Fingerprint(k) != Fingerprint(pub) {
		t.Fatal(ns, err)
	}
	// Another key does not verify, even with the same signature.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	op, _ := ssh.NewPublicKey(other)
	if err := Verify(op, "nebula-module", msg, load(t, "message-512.sig")); !errors.Is(err, ErrSignature) {
		t.Fatal(err)
	}
}

func TestMalformed(t *testing.T) {
	pub, _, _, _, _ := ssh.ParseAuthorizedKey(load(t, "signer.pub"))
	sig := string(load(t, "message-512.sig"))
	for name, s := range map[string]string{
		"empty":    "",
		"no armor": strings.TrimPrefix(sig, "-----BEGIN SSH SIGNATURE-----"),
		"bad b64":  strings.Replace(sig, "U1NI", "!!!!", 1),
		"huge":     strings.Repeat("A", 5000),
		"cut":      sig[:len(sig)/2] + "\n-----END SSH SIGNATURE-----\n",
	} {
		if err := Verify(pub, "nebula-module", load(t, "message.json"), []byte(s)); err == nil {
			t.Errorf("%s verified", name)
		}
	}
	if err := Verify(pub, "", load(t, "message.json"), []byte(sig)); err == nil {
		t.Fatal("empty namespace")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = Parse(b)
	})
}

// sign builds an SSHSIG signature with the given reserved field.
func sign(t *testing.T, signer ssh.Signer, ns, reserved string, msg []byte) []byte {
	t.Helper()
	h := sha512.Sum512(msg)
	var m [6]byte
	copy(m[:], magic)
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{m, ns, reserved, "sha512", h[:]})
	sig, err := signer.Sign(rand.Reader, signed)
	if err != nil {
		t.Fatal(err)
	}
	raw := ssh.Marshal(blob{Magic: m, Version: 1, PublicKey: signer.PublicKey().Marshal(), Namespace: ns, Reserved: reserved, HashAlg: "sha512",
		Signature: ssh.Marshal(sig)})
	return []byte(begin + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n" + end + "\n")
}

// PROTOCOL.sshsig: the reserved field must be empty, even when signed.
func TestReservedMustBeEmpty(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"x":1}`)
	if err := Verify(signer.PublicKey(), "nebula-module", msg, sign(t, signer, "nebula-module", "", msg)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(signer.PublicKey(), "nebula-module", msg, sign(t, signer, "nebula-module", "attacker-chosen", msg)); err == nil {
		t.Fatal("non-empty reserved field accepted")
	}
}

func TestReleaseSigningDocumentsOpenSSHUserPresenceLimitation(t *testing.T) {
	data, err := os.ReadFile("../../docs/admin/release-signing.md")
	if err != nil {
		t.Fatal(err)
	}
	_, procedure, ok := strings.Cut(string(data), "## Sign offline and verify\n")
	if !ok {
		t.Fatal("missing offline verification procedure")
	}
	procedure, _, _ = strings.Cut(procedure, "\n## Enroll, rotate and recover")
	procedure = strings.Join(strings.Fields(procedure), " ")
	for _, required := range []string{
		"`ssh-keygen -Y verify` does not enforce user presence",
		"`flags=0`",
		"allowed-signers file has no `no-touch-required` option",
		"Before publication of any release or rotation",
		"cryptographically authenticate the FIDO flags/counter",
		"require `(flags & 0x01) != 0`",
		"If that check is unavailable, do not publish",
	} {
		if !strings.Contains(procedure, required) {
			t.Errorf("offline verification procedure must document %q", required)
		}
	}
	for _, misleading := range []string{
		"Use OpenSSH with security-key support and its default touch requirement",
		"never use a `no-touch-required` allowed-signers option",
	} {
		if strings.Contains(procedure, misleading) {
			t.Errorf("offline verification procedure retains misleading guidance %q", misleading)
		}
	}
}
