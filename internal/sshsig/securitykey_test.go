// SPDX-License-Identifier: AGPL-3.0-or-later
package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// releaseRoot1 is the real primary release root (spec 10, release signing).
const releaseRoot1 = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIH6DVvY6q6jDyLGQeYjKhNufFKi2jzFHzFO04+ng5mkoAAAABHNzaDo= nebula-release-root-1"

// testSK is a software stand-in for a FIDO security key, test-only: it
// produces signatures in OpenSSH's sk-ssh-ed25519 encoding (PROTOCOL.u2f).
type testSK struct {
	priv ed25519.PrivateKey
	app  string
	pub  ssh.PublicKey
}

func newTestSK(t *testing.T, app string) *testSK {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, app})
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return &testSK{priv: priv, app: app, pub: k}
}

type skOpts struct {
	ns       string
	hashAlg  string
	flags    byte
	counter  uint32
	envKey   ssh.PublicKey // envelope key; defaults to the signer's key
	tamperFn func(sig *ssh.Signature)
}

func (k *testSK) sign(t *testing.T, msg []byte, o skOpts) []byte {
	t.Helper()
	if o.ns == "" {
		o.ns = "nebula-release"
	}
	if o.hashAlg == "" {
		o.hashAlg = "sha512"
	}
	var h []byte
	if o.hashAlg == "sha256" {
		s := sha256.Sum256(msg)
		h = s[:]
	} else {
		s := sha512.Sum512(msg)
		h = s[:]
	}
	var m [6]byte
	copy(m[:], magic)
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{m, o.ns, "", o.hashAlg, h})
	appDigest := sha256.Sum256([]byte(k.app))
	dataDigest := sha256.Sum256(signed)
	fido := ssh.Marshal(struct {
		App     []byte `ssh:"rest"`
		Flags   byte
		Counter uint32
		Data    []byte `ssh:"rest"`
	}{appDigest[:], o.flags, o.counter, dataDigest[:]})
	sig := ssh.Signature{
		Format: ssh.KeyAlgoSKED25519,
		Blob:   ed25519.Sign(k.priv, fido),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{o.flags, o.counter}),
	}
	if o.tamperFn != nil {
		o.tamperFn(&sig)
	}
	env := k.pub
	if o.envKey != nil {
		env = o.envKey
	}
	raw := ssh.Marshal(blob{Magic: m, Version: 1, PublicKey: env.Marshal(), Namespace: o.ns, HashAlg: o.hashAlg,
		Signature: ssh.Marshal(sig)})
	return []byte(begin + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n" + end + "\n")
}

func TestVerifySecurityKeyAcceptsTouchedSignature(t *testing.T) {
	k := newTestSK(t, "ssh:")
	msg := []byte(`{"format":"nebula-release-v1"}`)
	for _, tc := range []struct {
		name    string
		o       skOpts
		counter uint32
	}{
		{"sha512 up", skOpts{flags: 0x01, counter: 7}, 7},
		{"sha256 up", skOpts{hashAlg: "sha256", flags: 0x01}, 0},
		{"up and uv", skOpts{flags: 0x05, counter: 1}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifySecurityKey(k.pub, "nebula-release", "ssh:", msg, k.sign(t, msg, tc.o))
			if err != nil {
				t.Fatal(err)
			}
			if got.Flags != tc.o.flags || got.Counter != tc.counter {
				t.Fatalf("metadata = %+v", got)
			}
		})
	}
}

func TestVerifySecurityKeyRejects(t *testing.T) {
	k := newTestSK(t, "ssh:")
	other := newTestSK(t, "ssh:")
	msg := []byte(`{"format":"nebula-release-v1"}`)
	good := skOpts{flags: 0x01}

	plainPub, plainPriv, _ := ed25519.GenerateKey(rand.Reader)
	plainSigner, _ := ssh.NewSignerFromKey(plainPriv)
	plainKey, _ := ssh.NewPublicKey(plainPub)

	for _, tc := range []struct {
		name    string
		key     ssh.PublicKey
		app     string
		ns      string
		msg     []byte
		armored []byte
		want    error
	}{
		{"no user presence", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{flags: 0x00}), ErrUserPresence},
		{"uv without up", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{flags: 0x04}), ErrUserPresence},
		{"wrong namespace", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{ns: "nebula-module", flags: 1}), ErrNamespace},
		{"tampered message", k.pub, "ssh:", "nebula-release", []byte(`{"format":"x"}`), k.sign(t, msg, good), ErrSignature},
		{"other key in envelope", k.pub, "ssh:", "nebula-release", msg, other.sign(t, msg, good), ErrSignature},
		{"envelope names trusted key, other key signed", k.pub, "ssh:", "nebula-release", msg, other.sign(t, msg, skOpts{flags: 1, envKey: k.pub}), ErrSignature},
		{"flags changed after signing", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{flags: 0x01, tamperFn: func(s *ssh.Signature) {
			s.Rest = ssh.Marshal(struct {
				Flags   byte
				Counter uint32
			}{0x05, 0})
		}}), ErrSignature},
		{"counter changed after signing", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{flags: 0x01, counter: 1, tamperFn: func(s *ssh.Signature) {
			s.Rest = ssh.Marshal(struct {
				Flags   byte
				Counter uint32
			}{0x01, 2})
		}}), ErrSignature},
		{"trailing data after counter", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{flags: 0x01, tamperFn: func(s *ssh.Signature) {
			s.Rest = append(s.Rest, 0)
		}}), ErrSignature},
		{"fido wrapper stripped", k.pub, "ssh:", "nebula-release", msg, k.sign(t, msg, skOpts{flags: 0x01, tamperFn: func(s *ssh.Signature) {
			s.Format = ssh.KeyAlgoED25519
			s.Rest = nil
		}}), ErrSignature},
		{"wrong application", newTestSK(t, "ssh:other").pub, "ssh:", "nebula-release", msg, nil, ErrApplication},
		{"empty application policy", k.pub, "", "nebula-release", msg, k.sign(t, msg, good), ErrApplication},
		{"plain ed25519 key", plainKey, "ssh:", "nebula-release", msg, sign(t, plainSigner, "nebula-release", "", msg), ErrKeyType},
		{"garbage", k.pub, "ssh:", "nebula-release", msg, []byte("not a signature"), ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifySecurityKey(tc.key, tc.ns, tc.app, tc.msg, tc.armored)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifySecurityKeyRejectsCertificate(t *testing.T) {
	k := newTestSK(t, "ssh:")
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	cert := &ssh.Certificate{Key: k.pub, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	msg := []byte("m")
	if _, err := VerifySecurityKey(cert, "nebula-release", "ssh:", msg, k.sign(t, msg, skOpts{flags: 1})); !errors.Is(err, ErrKeyType) {
		t.Fatalf("certificate accepted: %v", err)
	}
}

// The plain-Ed25519 module verifier never accepts a security key.
func TestVerifyRejectsSecurityKey(t *testing.T) {
	k := newTestSK(t, "ssh:")
	msg := []byte("m")
	if err := Verify(k.pub, "nebula-release", msg, k.sign(t, msg, skOpts{flags: 1})); !errors.Is(err, ErrKeyType) {
		t.Fatalf("Verify with sk key: %v", err)
	}
}

// The real release root parses through golang.org/x/crypto/ssh as an
// sk-ssh-ed25519 key bound to "ssh:" with the documented fingerprint.
func TestReleaseRoot1ParsesAsSecurityKey(t *testing.T) {
	k, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(releaseRoot1))
	if err != nil {
		t.Fatal(err)
	}
	if k.Type() != ssh.KeyAlgoSKED25519 || comment != "nebula-release-root-1" {
		t.Fatalf("type %s comment %q", k.Type(), comment)
	}
	if got := Fingerprint(k); got != "SHA256:DMcoE6ngofND0L6+vT1OIPrvzDFSRmBNDPrR3hpy1MY" {
		t.Fatalf("fingerprint %s", got)
	}
	other := newTestSK(t, "ssh:")
	msg := []byte("m")
	if _, err := VerifySecurityKey(k, "nebula-release", "ssh:", msg, other.sign(t, msg, skOpts{flags: 1})); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign signature against root-1: %v", err)
	}
}
