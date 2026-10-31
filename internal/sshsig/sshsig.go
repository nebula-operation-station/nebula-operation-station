// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sshsig verifies SSH signatures (OpenSSH PROTOCOL.sshsig, made by
// `ssh-keygen -Y sign`), the format spec 10 uses for signed modules and
// releases, so that authors sign with tools they already have. Verify
// accepts plain Ed25519 keys (third-party modules); VerifySecurityKey
// accepts FIDO sk-ssh-ed25519@openssh.com keys (release roots) and
// requires user presence. Both take SHA-256 or SHA-512 message hashes
// under one namespace.
package sshsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Errors.
var (
	ErrFormat    = errors.New("sshsig: not an SSH signature")
	ErrKeyType   = errors.New("sshsig: only Ed25519 signing keys are accepted")
	ErrNamespace = errors.New("sshsig: signature is for another namespace")
	ErrSignature = errors.New("sshsig: signature does not verify")
	// ErrUserPresence reports a security-key signature made without the
	// user-presence (touch) flag.
	ErrUserPresence = errors.New("sshsig: security-key signature lacks user presence")
	// ErrApplication reports a security key bound to another FIDO
	// application.
	ErrApplication = errors.New("sshsig: security key is bound to another application")
)

// skFlagUserPresence is the FIDO user-presence flag (PROTOCOL.u2f).
const skFlagUserPresence = 0x01

const (
	magic      = "SSHSIG"
	begin      = "-----BEGIN SSH SIGNATURE-----"
	end        = "-----END SSH SIGNATURE-----"
	maxArmored = 4096
)

type blob struct {
	Magic     [6]byte
	Version   uint32
	PublicKey []byte
	Namespace string
	Reserved  string
	HashAlg   string
	Signature []byte
}

// Parse decodes an armored signature without verifying it and returns the
// signing key and the namespace.
func Parse(armored []byte) (ssh.PublicKey, string, error) {
	b, err := parse(armored)
	if err != nil {
		return nil, "", err
	}
	k, err := ssh.ParsePublicKey(b.PublicKey)
	if err != nil {
		return nil, "", ErrFormat
	}
	return k, b.Namespace, nil
}

func parse(armored []byte) (*blob, error) {
	if len(armored) > maxArmored {
		return nil, ErrFormat
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(armored), "\r\n", "\n"))
	if !strings.HasPrefix(s, begin) || !strings.HasSuffix(s, end) {
		return nil, ErrFormat
	}
	body := strings.Join(strings.Fields(s[len(begin):len(s)-len(end)]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, ErrFormat
	}
	var b blob
	if err := ssh.Unmarshal(raw, &b); err != nil || string(b.Magic[:]) != magic || b.Version != 1 {
		return nil, ErrFormat
	}
	return &b, nil
}

// Verify checks that armored is a valid signature over message by key in
// namespace. key must be an Ed25519 key.
func Verify(key ssh.PublicKey, namespace string, message, armored []byte) error {
	if key.Type() != ssh.KeyAlgoED25519 {
		return ErrKeyType
	}
	_, err := verify(key, namespace, message, armored, nil)
	return err
}

// SecurityKeySignature is the authenticated FIDO metadata of a verified
// security-key signature. The counter is informational only: zero,
// repeated and out-of-order counters are accepted.
type SecurityKeySignature struct {
	// Flags is the authenticator flags byte; user presence is set.
	Flags byte
	// Counter is the authenticator's signature counter.
	Counter uint32
}

// VerifySecurityKey checks that armored is a valid signature over message
// by the security key key in namespace. key must be a plain (non-
// certificate) sk-ssh-ed25519@openssh.com key bound to application, the
// signature envelope must carry exactly key's public-key blob, and the
// signature must have the user-presence flag set. The whole FIDO
// signature, including application, flags and counter, is verified by
// golang.org/x/crypto/ssh; the FIDO wrapper is never stripped.
func VerifySecurityKey(key ssh.PublicKey, namespace, application string, message, armored []byte) (SecurityKeySignature, error) {
	if key.Type() != ssh.KeyAlgoSKED25519 {
		return SecurityKeySignature{}, ErrKeyType
	}
	var wire struct {
		Type        string
		PubKey      []byte
		Application string
	}
	if err := ssh.Unmarshal(key.Marshal(), &wire); err != nil {
		return SecurityKeySignature{}, ErrKeyType
	}
	if application == "" || wire.Application != application {
		return SecurityKeySignature{}, ErrApplication
	}
	var fido struct {
		Flags   byte
		Counter uint32
	}
	// The flags are checked explicitly (spec 10) before the signature;
	// key.Verify then authenticates them as part of the FIDO blob.
	checkFlags := func(sig *ssh.Signature) error {
		if err := ssh.Unmarshal(sig.Rest, &fido); err != nil {
			return ErrSignature
		}
		if fido.Flags&skFlagUserPresence == 0 {
			return ErrUserPresence
		}
		return nil
	}
	if _, err := verify(key, namespace, message, armored, checkFlags); err != nil {
		return SecurityKeySignature{}, err
	}
	return SecurityKeySignature{Flags: fido.Flags, Counter: fido.Counter}, nil
}

// verify checks the envelope against key and namespace and verifies the
// inner signature, whose format must equal the key type. check, if set,
// inspects the parsed signature before it is verified.
func verify(key ssh.PublicKey, namespace string, message, armored []byte, check func(*ssh.Signature) error) (*ssh.Signature, error) {
	b, err := parse(armored)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b.PublicKey, key.Marshal()) {
		return nil, ErrSignature
	}
	if b.Namespace != namespace || namespace == "" {
		return nil, ErrNamespace
	}
	// PROTOCOL.sshsig: "Reserved for future use. Must be zero length."
	if b.Reserved != "" {
		return nil, fmt.Errorf("sshsig: the reserved field must be empty")
	}
	var h []byte
	switch b.HashAlg {
	case "sha256":
		s := sha256.Sum256(message)
		h = s[:]
	case "sha512":
		s := sha512.Sum512(message)
		h = s[:]
	default:
		return nil, fmt.Errorf("sshsig: hash %q not supported", b.HashAlg)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(b.Signature, &sig); err != nil || sig.Format != key.Type() {
		return nil, ErrSignature
	}
	if check != nil {
		if err := check(&sig); err != nil {
			return nil, err
		}
	}
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{b.Magic, b.Namespace, b.Reserved, b.HashAlg, h})
	if err := key.Verify(signed, &sig); err != nil {
		return nil, ErrSignature
	}
	return &sig, nil
}

// Fingerprint is the key's OpenSSH SHA256 fingerprint.
func Fingerprint(key ssh.PublicKey) string { return ssh.FingerprintSHA256(key) }
