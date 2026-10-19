// SPDX-License-Identifier: AGPL-3.0-or-later

package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
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
