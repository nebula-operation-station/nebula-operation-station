// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"testing"
)

// The non-ASCII characters below are written as byte escapes so that the
// source file stays ASCII and each character is visible to a reviewer.
const (
	// r is U+FFFD, the replacement character.
	r = "\xef\xbf\xbd"
	// rlo is U+202E, a right-to-left override.
	rlo = "\xe2\x80\xae"
	// lri and pdi are U+2066 and U+2069, bidi isolates.
	lri = "\xe2\x81\xa6"
	pdi = "\xe2\x81\xa9"
	// zwsp and zwj are U+200B and U+200D, zero-width characters.
	zwsp = "\xe2\x80\x8b"
	zwj  = "\xe2\x80\x8d"
	// bom is U+FEFF, the byte order mark.
	bom = "\xef\xbb\xbf"
	// lsep and psep are U+2028 and U+2029.
	lsep = "\xe2\x80\xa8"
	psep = "\xe2\x80\xa9"
	// shy is U+00AD, a soft hyphen (format character).
	shy = "\xc2\xad"
	// c1nel is U+0085, a C1 control character.
	c1nel = "\xc2\x85"
)

// TestCleanTextReplacesForbiddenRunes covers ADR 0014 D4 rendering: control
// characters, bidi overrides and zero-width characters become U+FFFD.
func TestCleanTextReplacesForbiddenRunes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is unchanged", "Pin the host, then restart.", "Pin the host, then restart."},
		{"German umlauts are kept", "Schl\xc3\xbcssel pr\xc3\xbcfen, Gr\xc3\xb6\xc3\x9fe 5 \xe2\x82\xac", "Schl\xc3\xbcssel pr\xc3\xbcfen, Gr\xc3\xb6\xc3\x9fe 5 \xe2\x82\xac"},
		{"escape character of an ANSI sequence", "\x1b[31mred\x1b[0m", r + "[31mred" + r + "[0m"},
		{"NUL and bell", "a\x00b\x07c", "a" + r + "b" + r + "c"},
		{"line feed and tab are control characters", "a\nb\tc", "a" + r + "b" + r + "c"},
		{"carriage return", "a\rb", "a" + r + "b"},
		{"DEL and C1 control", "a\x7fb" + c1nel + "c", "a" + r + "b" + r + "c"},
		{"right-to-left override", "rm " + rlo + "exe.txt", "rm " + r + "exe.txt"},
		{"left-to-right isolate", "a" + lri + "b" + pdi + "c", "a" + r + "b" + r + "c"},
		{"zero-width space", "ni" + zwsp + "ce", "ni" + r + "ce"},
		{"zero-width joiner", "a" + zwj + "b", "a" + r + "b"},
		{"byte order mark in the middle", "a" + bom + "b", "a" + r + "b"},
		{"line separator", "a" + lsep + "b", "a" + r + "b"},
		{"paragraph separator", "a" + psep + "b", "a" + r + "b"},
		{"soft hyphen", "soft" + shy + "hyphen", "soft" + r + "hyphen"},
		{"invalid UTF-8 byte", "a\xffb", "a" + r + "b"},
		{"existing replacement character is kept", "a" + r + "b", "a" + r + "b"},
		{"empty string", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := CleanText(tc.in); got != tc.want {
				t.Fatalf("CleanText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCleanTextIsIdempotent checks that a second pass changes nothing.
func TestCleanTextIsIdempotent(t *testing.T) {
	for _, in := range []string{"a\x1b[0mb", "x" + rlo + "y" + zwsp + "z\n", "\xff\xfe", "plain"} {
		once := CleanText(in)
		if twice := CleanText(once); twice != once {
			t.Fatalf("CleanText not idempotent for %q: %q then %q", in, once, twice)
		}
	}
}
