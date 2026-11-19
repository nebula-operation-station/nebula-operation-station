// SPDX-License-Identifier: AGPL-3.0-or-later

package secretguard

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// MaxQuestionBytes bounds a question in bytes (ADR 0014 D5: question ≤ 2 KiB).
const MaxQuestionBytes = 2 << 10

// nosTokenPrefix and nosTokenBodyLen describe the API token format issued by
// cmd/nebula-server/apitoken.go: "nos_" and 32 random bytes in unpadded
// base64url, which is 43 characters.
const (
	nosTokenPrefix  = "nos_"
	nosTokenBodyLen = 43
)

var (
	// ErrTooLong: the question is longer than MaxQuestionBytes.
	ErrTooLong = errors.New("question is longer than 2 KiB")
	// ErrInvalidText: the question is not valid UTF-8.
	ErrInvalidText = errors.New("question is not valid UTF-8 text")
	// ErrLooksLikeSecret: the question contains a secret pattern. Use
	// errors.Is; ClassOf names the class.
	ErrLooksLikeSecret = errors.New("this looks like a secret; remove it")
)

// Class is the kind of secret found in a question.
type Class int

// The classes of secret the guard refuses.
const (
	// ClassPrivateKeyBlock: a "-----BEGIN" line of a private key block.
	ClassPrivateKeyBlock Class = iota + 1
	// ClassAgeSecretKey: an age secret key ("AGE-SECRET-KEY-").
	ClassAgeSecretKey
	// ClassNOSToken: an API token of NOS's own format.
	ClassNOSToken
	// ClassOTPAuthURI: an otpauth URI, which carries a TOTP secret.
	ClassOTPAuthURI
)

// String names the class. It never contains a finding.
func (c Class) String() string {
	switch c {
	case ClassPrivateKeyBlock:
		return "private key block"
	case ClassAgeSecretKey:
		return "age secret key"
	case ClassNOSToken:
		return "NOS API token"
	case ClassOTPAuthURI:
		return "otpauth URI"
	default:
		return "unknown class"
	}
}

// SecretError is returned by Check for a question with a secret. It holds
// the class only, never the finding or its position.
type SecretError struct {
	class Class
}

// Error returns the fixed text of ErrLooksLikeSecret.
func (*SecretError) Error() string { return ErrLooksLikeSecret.Error() }

// Unwrap makes errors.Is(err, ErrLooksLikeSecret) hold.
func (*SecretError) Unwrap() error { return ErrLooksLikeSecret }

// ClassOf returns the class of the secret that Check found in err, and
// false when err is not a secret rejection.
func ClassOf(err error) (Class, bool) {
	var se *SecretError
	if errors.As(err, &se) {
		return se.class, true
	}
	return 0, false
}

// fixedPatterns are matched case-insensitively (ASCII letters only).
var fixedPatterns = []struct {
	lower string
	class Class
}{
	{"-----begin", ClassPrivateKeyBlock},
	{"age-secret-key-", ClassAgeSecretKey},
	{"otpauth://", ClassOTPAuthURI},
}

// Check returns nil when question may be sent to the LLM. Otherwise it
// returns ErrTooLong, ErrInvalidText, or a *SecretError that matches
// ErrLooksLikeSecret. The checks run in that order, and the error text
// never contains the question or the finding.
func Check(question string) error {
	if len(question) > MaxQuestionBytes {
		return ErrTooLong
	}
	if !utf8.ValidString(question) {
		return ErrInvalidText
	}
	for _, p := range fixedPatterns {
		if containsFold(question, p.lower) {
			return &SecretError{class: p.class}
		}
	}
	if containsNOSToken(question) {
		return &SecretError{class: ClassNOSToken}
	}
	return nil
}

// containsFold reports whether s contains lower, comparing ASCII letters
// case-insensitively. lower must be lowercase ASCII.
func containsFold(s, lower string) bool {
	n := len(lower)
	for i := 0; i+n <= len(s); i++ {
		if equalFoldASCII(s[i:i+n], lower) {
			return true
		}
	}
	return false
}

// equalFoldASCII compares a and lower (lowercase ASCII) ignoring ASCII case.
func equalFoldASCII(a, lower string) bool {
	for j := 0; j < len(lower); j++ {
		c := a[j]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[j] {
			return false
		}
	}
	return true
}

// containsNOSToken reports whether s holds the NOS token prefix followed by
// at least nosTokenBodyLen characters of the URL-safe base64 alphabet.
func containsNOSToken(s string) bool {
	rest := s
	for {
		i := strings.Index(rest, nosTokenPrefix)
		if i < 0 {
			return false
		}
		if base64URLRun(rest[i+len(nosTokenPrefix):]) >= nosTokenBodyLen {
			return true
		}
		rest = rest[i+1:]
	}
}

// base64URLRun counts the leading bytes of s in the URL-safe base64
// alphabet. It stops counting at nosTokenBodyLen.
func base64URLRun(s string) int {
	n := 0
	for n < len(s) && n < nosTokenBodyLen {
		c := s[n]
		isB64 := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_'
		if !isB64 {
			break
		}
		n++
	}
	return n
}
