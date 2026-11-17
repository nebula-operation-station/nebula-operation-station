// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// EscapePath returns the display form of a raw path (ADR 0015 D6 "Display").
// Valid printable UTF-8 stays as is. Everything else becomes \xNN per byte:
// invalid UTF-8, the backslash itself (so the output is unambiguous), control
// characters, non-ASCII spaces, and format characters of class Cf such as
// bidi controls and zero-width characters. The output is therefore always
// free of terminal and bidi controls. It must stay byte-identical to
// fimscan.EscapePath, which the fuzz test checks. The raw bytes are the stored
// key; this form is only for showing them.
func EscapePath(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for len(raw) > 0 {
		r, n := utf8.DecodeRune(raw)
		if r == utf8.RuneError && n <= 1 || r == '\\' || !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			for _, c := range raw[:max(n, 1)] {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
			raw = raw[max(n, 1):]
			continue
		}
		b.Write(raw[:n])
		raw = raw[n:]
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
