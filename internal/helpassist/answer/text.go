// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"strings"
	"unicode"
)

// ReplacementChar is written for every character that CleanText forbids
// (ADR 0014 D4). It is also written for an invalid UTF-8 byte.
const ReplacementChar = "�"

// CleanText applies the rendering rule of ADR 0014 D4 to a text field: every
// control character (Cc), format character (Cf: bidi overrides, zero-width
// and invisible characters), line separator (Zl) and paragraph separator (Zp)
// becomes U+FFFD. Line breaks are replaced too, because D4 names no
// exception; see the package comment. Invalid UTF-8 bytes also become U+FFFD.
// The output is valid UTF-8, and CleanText is idempotent.
//
// CleanText does not touch Command: the command is checked, not rewritten,
// so the copied text is the text the model wrote.
func CleanText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if forbidden(r) {
			b.WriteString(ReplacementChar)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// forbidden reports whether a rune must not be rendered in a text field.
// range over a string yields utf8.RuneError for an invalid byte, and that
// rune is not forbidden, so it is written as U+FFFD.
func forbidden(r rune) bool {
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp)
}
