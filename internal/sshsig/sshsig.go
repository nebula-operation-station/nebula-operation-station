// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sshsig verifies SSH signatures (OpenSSH PROTOCOL.sshsig, made by
// `ssh-keygen -Y sign`), the format spec 10 uses for signed modules, so
// that authors sign with tools they already have. Only Ed25519 keys are
// accepted, with SHA-256 or SHA-512 message hashes, under one namespace.
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
)

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
	b, err := parse(armored)
	if err != nil {
		return err
	}
	if !bytes.Equal(b.PublicKey, key.Marshal()) {
		return ErrSignature
	}
	if b.Namespace != namespace || namespace == "" {
		return ErrNamespace
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
		return fmt.Errorf("sshsig: hash %q not supported", b.HashAlg)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(b.Signature, &sig); err != nil || sig.Format != ssh.KeyAlgoED25519 {
		return ErrSignature
	}
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{b.Magic, b.Namespace, b.Reserved, b.HashAlg, h})
	if err := key.Verify(signed, &sig); err != nil {
		return ErrSignature
	}
	return nil
}

// Fingerprint is the key's OpenSSH SHA256 fingerprint.
func Fingerprint(key ssh.PublicKey) string { return ssh.FingerprintSHA256(key) }
