// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrMultiLine is returned by CheckASCII when the text contains a line
// break. A command shown by the help assistant is exactly one line
// (ADR 0014, V1).
var ErrMultiLine = errors.New("command spans more than one line")

// NonASCIIError reports the first character of a text that is outside
// printable ASCII (0x20–0x7E). Rune is the code point (U+FFFD for an invalid
// UTF-8 byte) and Offset the byte offset of that character in the text.
type NonASCIIError struct {
	Offset int
	Rune   rune
}

// Error implements error. The message names the code point, as the red flag
// "contains the non-ASCII character U+XXXX" requires.
func (e *NonASCIIError) Error() string {
	return fmt.Sprintf("contains the non-ASCII character U+%04X at byte %d", e.Rune, e.Offset)
}

// CheckASCII implements check V1 of ADR 0014: the text consists only of
// printable ASCII (0x20–0x7E) and is one line. The text is scanned in order.
// The first character that is a line break yields ErrMultiLine; the first
// other character outside 0x20–0x7E yields a *NonASCIIError. Look-alikes
// (Cyrillic letters, dashes, fullwidth and no-break spaces), bidi overrides,
// zero-width characters and control characters are all rejected this way.
func CheckASCII(s string) error {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == '\n' || r == '\r' {
			return ErrMultiLine
		}
		if r < 0x20 || r > 0x7e {
			return &NonASCIIError{Offset: i, Rune: r}
		}
		i += size
	}
	return nil
}
