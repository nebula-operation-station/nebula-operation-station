// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"testing"
)

// r returns the character with the given code point. The test sources stay
// ASCII; the look-alikes are built from their code points on purpose.
func r(cp rune) string { return string(cp) }

func TestCheckASCIIAcceptsPrintableASCII(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"nebula status",
		"sudo rm -rf /var/lib/nebula",
		" ~ ", // 0x20 and 0x7E are the bounds
		"curl --cacert 'x' 'https://a/b?c=d&e=f'",
	}
	for _, s := range cases {
		if err := CheckASCII(s); err != nil {
			t.Errorf("CheckASCII(%q) = %v, want nil", s, err)
		}
	}
}

func TestCheckASCIIRejectsLookAlikesWithCodePoint(t *testing.T) {
	t.Parallel()
	// Examples from ADR 0014 V1 (Cyrillic е in nebula, en dash, fullwidth
	// and no-break space), plus bidi, zero-width and control characters.
	cases := []struct {
		name   string
		in     string
		offset int
		rune   rune
	}{
		{"cyrillic e in nebula", "n" + r(0x0435) + "bula status", 1, 0x0435},
		{"en dash before flag", "nebula netdev list " + r(0x2013) + "from x", 19, 0x2013},
		{"fullwidth n", r(0xff4e) + "ebula", 0, 0xff4e},
		{"no-break space", "nebula" + r(0x00a0) + "status", 6, 0x00a0},
		{"right-to-left override", "echo " + r(0x202e) + "abc", 5, 0x202e},
		{"zero-width space", "nebula" + r(0x200b) + " status", 6, 0x200b},
		{"zero-width joiner", "rm" + r(0x200d) + " -rf x", 2, 0x200d},
		{"tab", "a\tb", 1, 0x09},
		{"DEL", "a\x7fb", 1, 0x7f},
		{"NUL", "a\x00b", 1, 0x00},
		{"invalid UTF-8 byte", "a\xffb", 1, 0xfffd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := CheckASCII(tc.in)
			var na *NonASCIIError
			if !errors.As(err, &na) {
				t.Fatalf("CheckASCII(%q) = %v, want *NonASCIIError", tc.in, err)
			}
			if na.Rune != tc.rune || na.Offset != tc.offset {
				t.Errorf("got U+%04X at %d, want U+%04X at %d", na.Rune, na.Offset, tc.rune, tc.offset)
			}
		})
	}
}

func TestCheckASCIIReportsFirstOffendingCharacter(t *testing.T) {
	t.Parallel()
	err := CheckASCII(r(0x2013) + "a" + r(0x0435))
	var na *NonASCIIError
	if !errors.As(err, &na) || na.Rune != 0x2013 || na.Offset != 0 {
		t.Fatalf("got %v, want first offender U+2013 at byte 0", err)
	}
}

func TestCheckASCIIRejectsMoreThanOneLine(t *testing.T) {
	t.Parallel()
	cases := []string{
		"nebula status\nsudo rm -rf /x",
		"nebula status\r\n",
		"\n",
		"a\rb",
	}
	for _, s := range cases {
		if err := CheckASCII(s); !errors.Is(err, ErrMultiLine) {
			t.Errorf("CheckASCII(%q) = %v, want ErrMultiLine", s, err)
		}
	}
}
