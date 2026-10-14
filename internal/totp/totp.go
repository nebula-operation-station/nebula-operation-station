// SPDX-License-Identifier: AGPL-3.0-or-later

// Package totp implements RFC 6238 time-based one-time passwords
// (HMAC-SHA1, 6 digits, 30-second steps) for account recovery (spec 05).
// TOTP is never a login for privileged work: it only opens a reading web
// session from which a new WebAuthn credential must be registered.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; authenticator apps expect SHA-1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// Parameters every common authenticator app supports.
const (
	SecretSize = 20 // 160 bits, RFC 4226 recommendation
	Digits     = 6
	Step       = 30 * time.Second
	// Skew is how many steps before and after the current one are accepted
	// (clock drift between server and phone).
	Skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret.
func NewSecret() ([]byte, error) {
	s := make([]byte, SecretSize)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("totp: random secret: %w", err)
	}
	return s, nil
}

// EncodeSecret is the base32 form authenticator apps accept.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// URI is the otpauth:// URI for QR codes and manual entry.
func URI(secret []byte, issuer, account string) string {
	v := url.Values{}
	v.Set("secret", EncodeSecret(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(Digits))
	v.Set("period", fmt.Sprint(int(Step/time.Second)))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// StepAt is the RFC 6238 time step counter for t.
func StepAt(t time.Time) int64 { return t.Unix() / int64(Step/time.Second) }

// codeAt computes the code for a step, as a zero-padded string.
func codeAt(secret []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Code returns the current code for t.
func Code(secret []byte, t time.Time) string { return codeAt(secret, StepAt(t), Digits) }

// ErrInvalid is returned for a wrong, malformed or reused code.
var ErrInvalid = errors.New("totp: code not accepted")

// Verify checks code against the steps around t and returns the matching
// step. A step at or below lastUsed is refused, so a code works once.
func Verify(secret []byte, code string, t time.Time, lastUsed int64) (int64, error) {
	if len(code) != Digits {
		return 0, ErrInvalid
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, ErrInvalid
		}
	}
	now := StepAt(t)
	match := int64(-1)
	// Compare every candidate so the time does not depend on which matched.
	for s := now - Skew; s <= now+Skew; s++ {
		if subtle.ConstantTimeCompare([]byte(codeAt(secret, s, Digits)), []byte(code)) == 1 && s > lastUsed {
			match = s
		}
	}
	if match < 0 {
		return 0, ErrInvalid
	}
	return match, nil
}
