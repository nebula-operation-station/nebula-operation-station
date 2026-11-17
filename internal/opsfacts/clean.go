// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Strict shapes of untrusted identifiers. A value that does not match is
// rejected, never repaired.
var (
	vulnIDRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	packageRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9.+~:_-]{1,64}$`)
	enumRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
)

// printable reports whether r is a letter, mark, number, punctuation or
// symbol. Control, format (bidi controls, zero-width characters), private
// use, surrogate, unassigned and separator code points are not printable.
func printable(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// cleanText makes an untrusted text value safe to show as plain text. Bytes
// that are not valid UTF-8 are dropped. Whitespace and every non-printable
// rune become one separating space; runs of separators collapse; leading and
// trailing separators go; the result is cut to max bytes at a rune boundary.
// Instruction-like wording is kept: it is data, and the agent is told so.
func cleanText(s string, max int) string {
	if limit := max * textScanFactor; len(s) > limit {
		s = s[:runeCut(s, limit)]
	}
	var b strings.Builder
	pending := false // a separator follows the last written rune
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			continue // invalid byte: dropped, not a separator
		}
		if unicode.IsSpace(r) || !printable(r) {
			pending = b.Len() > 0
			continue
		}
		if pending {
			b.WriteByte(' ')
			pending = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > max {
		out = strings.TrimRight(out[:runeCut(out, max)], " ")
	}
	return out
}

// runeCut returns the largest index <= n that starts a rune of s, or len(s)
// when n is past the end.
func runeCut(s string, n int) int {
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}
