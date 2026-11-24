// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// replacementRune is what encoding/json writes for an invalid UTF-8 byte
// and for a lone surrogate escape. The decoder cannot tell those apart from
// a literal U+FFFD, so every U+FFFD is refused.
const replacementRune = '�'

// checkFreeText validates a free-text field: printable UTF-8 of at most max
// bytes, newlines allowed, no URL.
func checkFreeText(field, s string, max int) error {
	return checkText(field, s, max, true)
}

// checkToken validates a single-line identifier (ref, digest, action, host):
// ASCII letters, digits and ._:/@+- only, at most MaxIDBytes, no URL.
// Citations have their own rule, checkCitation.
func checkToken(field, s string) error {
	if s == "" {
		return fmt.Errorf("%s: %w", field, ErrMissing)
	}
	if len(s) > MaxIDBytes {
		return fmt.Errorf("%s: %d bytes, max %d: %w", field, len(s), MaxIDBytes, ErrLimit)
	}
	for i := 0; i < len(s); i++ {
		if !tokenByte(s[i]) {
			return fmt.Errorf("%s: byte %#x at %d: %w", field, s[i], i, ErrInvalidField)
		}
	}
	return checkNoURL(field, s)
}

// checkCitation validates a citation: a handbook chunk ID as the embedded
// index writes it, Slug#Anchor, optionally with a "#pN" part suffix. It is
// checkToken with one addition: '#' is allowed between parts but not at
// either end and not twice in a row ("a##b"). No other identifier may
// contain '#'.
func checkCitation(field, s string) error {
	if s == "" {
		return fmt.Errorf("%s: %w", field, ErrMissing)
	}
	if len(s) > MaxIDBytes {
		return fmt.Errorf("%s: %d bytes, max %d: %w", field, len(s), MaxIDBytes, ErrLimit)
	}
	if s[0] == '#' || s[len(s)-1] == '#' {
		return fmt.Errorf("%s: '#' at an end of the chunk ID: %w", field, ErrInvalidField)
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '#' {
			if i > 0 && s[i-1] == '#' {
				return fmt.Errorf("%s: consecutive '#' at %d: %w", field, i, ErrInvalidField)
			}
			continue
		}
		if !tokenByte(s[i]) {
			return fmt.Errorf("%s: byte %#x at %d: %w", field, s[i], i, ErrInvalidField)
		}
	}
	return checkNoURL(field, s)
}

func tokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("._:/@+-", c) >= 0
}

// checkText validates text. Newlines are allowed only when multiline is set.
func checkText(field, s string, max int, multiline bool) error {
	if len(s) > max {
		return fmt.Errorf("%s: %d bytes, max %d: %w", field, len(s), max, ErrLimit)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s: not valid UTF-8: %w", field, ErrInvalidText)
	}
	for _, r := range s {
		if r == '\n' && multiline {
			continue
		}
		if r == replacementRune {
			return fmt.Errorf("%s: U+FFFD is refused: %w", field, ErrInvalidText)
		}
		// unicode.IsGraphic admits letters, marks, numbers, punctuation,
		// symbols and spaces (Zs). It refuses controls (Cc), format
		// characters (Cf: zero-width and bidi controls, BOM), private use
		// (Co) and line or paragraph separators.
		if !unicode.IsGraphic(r) {
			return fmt.Errorf("%s: rune %U is not printable: %w", field, r, ErrInvalidText)
		}
	}
	return checkNoURL(field, s)
}

// checkNoURL refuses "://" and "www." in any case.
func checkNoURL(field, s string) error {
	l := strings.ToLower(s)
	if strings.Contains(l, "://") || strings.Contains(l, "www.") {
		return fmt.Errorf("%s: %w", field, ErrURL)
	}
	return nil
}
