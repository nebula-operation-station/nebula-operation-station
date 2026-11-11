// SPDX-License-Identifier: AGPL-3.0-or-later

package pairing

import (
	"errors"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"",
		"00000-00000-00000-00000-00000",
		"0123456789ABCDEFGHJKMNPQ0",
		"o1il-",
		"UUUUU-UUUUU-UUUUU-UUUUU-UUUUU",
		"*~$=U",
		"\xff\xfe",
		strings.Repeat(" ", 200),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		c, err := Parse(in)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Parse(%q): error %v is not ErrMalformed", in, err)
			}
			var me *MalformedError
			if !errors.As(err, &me) {
				t.Fatalf("Parse(%q): error %v is not *MalformedError", in, err)
			}
			if c != (Code{}) {
				t.Fatalf("Parse(%q): non-zero code on error", in)
			}
			return
		}
		if len(in) > MaxInputLen {
			t.Fatalf("Parse accepted %d bytes, limit %d", len(in), MaxInputLen)
		}
		s := c.String()
		if len(s) != 29 {
			t.Fatalf("Parse(%q).String() = %q, want 29 chars", in, s)
		}
		data := strings.ReplaceAll(s, "-", "")
		for i := 0; i < dataChars; i++ {
			if strings.IndexByte(dataAlphabet, data[i]) < 0 {
				t.Fatalf("non-canonical data char in %q", s)
			}
		}
		again, err := Parse(s)
		if err != nil || !Equal(again, c) {
			t.Fatalf("round trip of %q failed: %v", s, err)
		}
		lower, err := Parse(strings.ToLower(s))
		if err != nil || !Equal(lower, c) {
			t.Fatalf("lower-case round trip of %q failed: %v", s, err)
		}
		// Changing one data character must break the check.
		b := []byte(data)
		b[0] = dataAlphabet[(strings.IndexByte(dataAlphabet, b[0])+1)%32]
		if _, err := Parse(string(b)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("single-character change of %q accepted", s)
		}
	})
}
