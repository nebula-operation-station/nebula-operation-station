// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// osRe is the charset of an OS family or release: letters, digits, dot,
// underscore, space and hyphen, at most MaxOSBytes bytes.
var osRe = regexp.MustCompile("^[A-Za-z0-9._ -]{1," + strconv.Itoa(MaxOSBytes) + "}$")

// textScanFactor bounds the input that cleanText reads: at most this many
// times the output limit. Work is therefore proportional to the output
// size, not to the stored size of an untrusted value.
const textScanFactor = 8

// printable reports whether r is a letter, mark, number, punctuation or
// symbol. Control, format, private-use, surrogate, unassigned and
// noncharacter code points are not printable.
func printable(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// cleanText makes an untrusted text value safe to show as plain text.
// Invalid UTF-8 bytes are dropped; whitespace and every non-printable rune
// become one separating space; runs of separators collapse; leading and
// trailing separators go; the value is cut to max bytes at a rune
// boundary. Every change sets Altered. Instruction-like wording is not
// removed; it stays data.
func cleanText(s string, max int) Text {
	var t Text
	if limit := max * textScanFactor; len(s) > limit {
		s = s[:runeCut(s, limit)]
		t.Altered = true
	}
	var b strings.Builder
	pending := false // a separator follows the last written rune
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			t.Altered = true // invalid byte, dropped
		case unicode.IsSpace(r) || !printable(r):
			if r != ' ' || pending || b.Len() == 0 {
				t.Altered = true
			}
			if b.Len() > 0 {
				pending = true
			}
		default:
			if pending {
				b.WriteByte(' ')
				pending = false
			}
			b.WriteRune(r)
		}
	}
	if pending {
		t.Altered = true // trailing separator
	}
	out := b.String()
	if len(out) > max {
		out = strings.TrimRight(out[:runeCut(out, max)], " ")
		t.Altered = true
	}
	t.Value = out
	return t
}

// runeCut returns the largest index ≤ n that starts a rune of s, or
// len(s) when n is past the end.
func runeCut(s string, n int) int {
	if n >= len(s) {
		return len(s)
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return n
}

// cleanOS accepts an OS family or release only from osRe; anything else
// is dropped and marked.
func cleanOS(s string) Text {
	if s == "" {
		return Text{}
	}
	if osRe.MatchString(s) {
		return Text{Value: s}
	}
	return Text{Altered: true}
}
