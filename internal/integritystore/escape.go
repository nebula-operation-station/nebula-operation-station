// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// EscapePath returns the display form of a raw path. Printable characters
// (valid UTF-8 that unicode.IsPrint accepts) are kept; a backslash becomes
// \\; every other byte, including invalid UTF-8 and control or invisible
// characters such as bidi overrides, becomes \xNN. The raw bytes are the
// stored key; this form is only for showing them.
func EscapePath(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, raw[i])
			i++
		case r == '\\':
			b.WriteString(`\\`)
			i += size
		case unicode.IsPrint(r):
			b.Write(raw[i : i+size])
			i += size
		default:
			for _, c := range raw[i : i+size] {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
			i += size
		}
	}
	return b.String()
}

// recordOK reports whether a record text is storable: at most
// MaxRecordBytes, valid UTF-8, no NUL.
func recordOK(s string) bool {
	return len(s) <= MaxRecordBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// actorOK reports whether an admin name is storable and safe to show as
// text: non-empty, at most MaxActorBytes, valid UTF-8, and only printable
// characters, so no control, invisible or bidi formatting characters.
func actorOK(actor string) bool {
	if actor == "" || len(actor) > MaxActorBytes || !utf8.ValidString(actor) {
		return false
	}
	for _, r := range actor {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
