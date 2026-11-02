// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"testing"
	"unicode/utf8"
)

func TestLeaseShortRuneBoundary(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "0a1b2c3d"},
		{"abc", "abc"},
		{"", ""},
		{"abcdefgh", "abcdefgh"},
		// multibyte rune at the cut
		{"abcdefgäöü", "abcdefgä"},
		// truncated rune
		{"abcdefg\xc3", "abcdefg�"},
		// invalid run collapses
		{"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7", "�"},
	} {
		got := leaseShort(tc.in)
		if !utf8.ValidString(got) {
			t.Errorf("leaseShort(%q) = %q is not valid UTF-8", tc.in, got)
		}
		if got != tc.want {
			t.Errorf("leaseShort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
