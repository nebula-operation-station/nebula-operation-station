// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pairing implements the one-step enrollment pairing code of
// ADR 0013 D3: a 120-bit value derived from SHA-256 over a domain string,
// the 32-byte offer salt and the host's ed25519 SSH host key blob, encoded
// as 24 Crockford base32 characters plus one mod-37 check character and
// shown as XXXXX-XXXXX-XXXXX-XXXXX-XXXXC.
//
// The code is a composition of SHA-256 and an encoding; no cryptography is
// implemented here. Codes are compared in constant time with Equal.
package pairing

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// domain is the domain-separation prefix of the digest; it is followed
	// by one 0x00 byte.
	domain = "nos-enroll-pair-v1"

	// SaltSize is the required length of the offer salt in bytes.
	SaltSize = 32

	// dataChars is the number of Crockford data characters (120 bits).
	dataChars = 24
	// halfChars is the number of characters per 60-bit half.
	halfChars = 12
	// codeChars is the number of characters without separators.
	codeChars = dataChars + 1
	// formattedLen is the length of String(): 25 characters, 4 hyphens.
	formattedLen = codeChars + codeChars/5 - 1

	// MaxInputLen bounds the raw input to Parse in bytes, separators
	// included, before any normalisation.
	MaxInputLen = 64

	// dataAlphabet is the Crockford base32 alphabet (value = index).
	dataAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// checkAlphabet is the 37-symbol Crockford check alphabet.
	checkAlphabet = dataAlphabet + "*~$=U"

	// twoPow60Mod37 is 2^60 mod 37, used to compute v mod 37 from the
	// two 60-bit halves: v = hi·2^60 + lo.
	twoPow60Mod37 = 10

	// ed25519KeySize is the length of a raw ed25519 public key.
	ed25519KeySize = 32
	// ed25519Algo is the SSH algorithm name of an ed25519 host key.
	ed25519Algo = "ssh-ed25519"
)

var (
	// ErrSaltSize reports a salt that is not exactly SaltSize bytes.
	ErrSaltSize = errors.New("pairing: salt must be 32 bytes")
	// ErrNotEd25519 reports a host key blob that is not exactly the SSH
	// wire format of an ed25519 public key.
	ErrNotEd25519 = errors.New("pairing: host key is not an ssh-ed25519 key blob")
	// ErrMalformed reports operator input that is not a well-formed
	// pairing code (a typing error, not a mismatch). Every error from
	// Parse is a *MalformedError that matches ErrMalformed.
	ErrMalformed = errors.New("pairing: malformed code")
)

// MalformedKind says why a code was rejected by Parse.
type MalformedKind int

const (
	// KindLength: the input is too long, or not 25 characters after
	// removing separators.
	KindLength MalformedKind = iota + 1
	// KindAlphabet: a character outside the allowed alphabet for its
	// position (including check-only symbols in a data position).
	KindAlphabet
	// KindCheck: the check character does not match the data characters.
	KindCheck
)

// String returns a short name for the kind.
func (k MalformedKind) String() string {
	switch k {
	case KindLength:
		return "length"
	case KindAlphabet:
		return "alphabet"
	case KindCheck:
		return "check"
	default:
		return "unknown"
	}
}

// MalformedError is the error type for a mistyped code. It never contains
// the input itself.
type MalformedError struct {
	// Kind is the reason for rejection.
	Kind MalformedKind
	// Position is the 1-based character position (separators not
	// counted) for KindAlphabet, otherwise 0.
	Position int
}

// Error implements error.
func (e *MalformedError) Error() string {
	switch e.Kind {
	case KindLength:
		return fmt.Sprintf("%v: want %d characters", ErrMalformed, codeChars)
	case KindAlphabet:
		return fmt.Sprintf("%v: invalid character at position %d", ErrMalformed, e.Position)
	case KindCheck:
		return fmt.Sprintf("%v: check character does not match", ErrMalformed)
	default:
		return ErrMalformed.Error()
	}
}

// Is makes errors.Is(err, ErrMalformed) true.
func (e *MalformedError) Is(target error) bool { return target == ErrMalformed }

// Code is a pairing code in canonical form. The zero value is not a valid
// code and never compares equal to anything.
type Code struct {
	c [codeChars]byte
}

// String returns the code as XXXXX-XXXXX-XXXXX-XXXXX-XXXXC, or "" for the
// zero value.
func (c Code) String() string {
	if c.c[0] == 0 {
		return ""
	}
	out := make([]byte, 0, formattedLen)
	for i, ch := range c.c {
		if i > 0 && i%5 == 0 {
			out = append(out, '-')
		}
		out = append(out, ch)
	}
	return string(out)
}

// Equal reports whether a and b are the same valid code. The comparison
// of the characters takes constant time.
func Equal(a, b Code) bool {
	valid := subtle.ConstantTimeByteEq(a.c[0], 0) == 0 && subtle.ConstantTimeByteEq(b.c[0], 0) == 0
	eq := subtle.ConstantTimeCompare(a.c[:], b.c[:]) == 1
	return valid && eq
}

// Compute derives the pairing code for an offer salt and an ed25519 host
// key in SSH wire format (the bytes the SHA-256 fingerprint covers).
func Compute(salt, hostKeyBlob []byte) (Code, error) {
	if len(salt) != SaltSize {
		return Code{}, fmt.Errorf("compute pairing code: %w", ErrSaltSize)
	}
	if !isEd25519Blob(hostKeyBlob) {
		return Code{}, fmt.Errorf("compute pairing code: %w", ErrNotEd25519)
	}
	d := digest(salt, hostKeyBlob)
	hi := binary.BigEndian.Uint64(d[0:8]) >> 4           // bits 1–60
	lo := binary.BigEndian.Uint64(d[7:15]) & (1<<60 - 1) // bits 61–120
	return encode(hi, lo), nil
}

// digest returns SHA-256(domain || 0x00 || salt || blob).
func digest(salt, blob []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(salt)
	h.Write(blob)
	var d [sha256.Size]byte
	h.Sum(d[:0])
	return d
}

// isEd25519Blob reports whether b is exactly string("ssh-ed25519") ||
// string(32-byte key) in SSH wire format, with no trailing bytes.
func isEd25519Blob(b []byte) bool {
	const want = 4 + len(ed25519Algo) + 4 + ed25519KeySize
	if len(b) != want {
		return false
	}
	if binary.BigEndian.Uint32(b[0:4]) != uint32(len(ed25519Algo)) {
		return false
	}
	if !bytes.Equal(b[4:4+len(ed25519Algo)], []byte(ed25519Algo)) {
		return false
	}
	off := 4 + len(ed25519Algo)
	return binary.BigEndian.Uint32(b[off:off+4]) == ed25519KeySize
}

// checkValue returns v mod 37 for v = hi·2^60 + lo, hi and lo < 2^60.
func checkValue(hi, lo uint64) int {
	return int(((hi%37)*twoPow60Mod37 + lo%37) % 37)
}

// encode builds the canonical code from the two 60-bit halves.
func encode(hi, lo uint64) Code {
	var c Code
	for i := 0; i < halfChars; i++ {
		shift := uint(5 * (halfChars - 1 - i))
		c.c[i] = dataAlphabet[(hi>>shift)&31]
		c.c[halfChars+i] = dataAlphabet[(lo>>shift)&31]
	}
	c.c[dataChars] = checkAlphabet[checkValue(hi, lo)]
	return c
}

// foldUpper upper-cases ASCII letters and applies Crockford folding
// (O→0, I and L→1).
func foldUpper(ch byte) byte {
	if ch >= 'a' && ch <= 'z' {
		ch -= 'a' - 'A'
	}
	switch ch {
	case 'O':
		return '0'
	case 'I', 'L':
		return '1'
	}
	return ch
}

// symbolValue returns the index of ch in alphabet, or -1.
func symbolValue(alphabet string, ch byte) int {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == ch {
			return i
		}
	}
	return -1
}

// Parse normalises and validates operator input: case-insensitive,
// Crockford folding, hyphens and spaces anywhere ignored; then exactly 24
// data characters and a matching check character. Every error is a
// *MalformedError matching ErrMalformed.
func Parse(s string) (Code, error) {
	if len(s) > MaxInputLen {
		return Code{}, &MalformedError{Kind: KindLength}
	}
	var buf [codeChars]byte
	n := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '-' || ch == ' ' {
			continue
		}
		ch = foldUpper(ch)
		if symbolValue(checkAlphabet, ch) < 0 {
			return Code{}, &MalformedError{Kind: KindAlphabet, Position: n + 1}
		}
		if n == codeChars {
			return Code{}, &MalformedError{Kind: KindLength}
		}
		buf[n] = ch
		n++
	}
	if n != codeChars {
		return Code{}, &MalformedError{Kind: KindLength}
	}
	var hi, lo uint64
	for i := 0; i < dataChars; i++ {
		v := symbolValue(dataAlphabet, buf[i])
		if v < 0 {
			return Code{}, &MalformedError{Kind: KindAlphabet, Position: i + 1}
		}
		if i < halfChars {
			hi = hi<<5 | uint64(v)
		} else {
			lo = lo<<5 | uint64(v)
		}
	}
	cv := symbolValue(checkAlphabet, buf[dataChars])
	if cv < 0 {
		return Code{}, &MalformedError{Kind: KindAlphabet, Position: codeChars}
	}
	if cv != checkValue(hi, lo) {
		return Code{}, &MalformedError{Kind: KindCheck}
	}
	return Code{c: buf}, nil
}
