// SPDX-License-Identifier: AGPL-3.0-or-later

package integritystore

import (
	"bytes"
	"fmt"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// unescapePath is the inverse of EscapePath, used only in tests. In the
// display form a raw backslash never appears unescaped, so every backslash
// starts a \xNN escape and the raw bytes can be recovered exactly.
func unescapePath(t testing.TB, s string) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out = append(out, s[i])
			i++
			continue
		}
		if i+4 > len(s) || s[i+1] != 'x' {
			t.Fatalf("display %q: malformed escape at byte %d", s, i)
		}
		var v byte
		if _, err := fmt.Sscanf(s[i+2:i+4], "%02x", &v); err != nil {
			t.Fatalf("display %q: bad hex at byte %d: %v", s, i, err)
		}
		out = append(out, v)
		i += 4
	}
	return out
}

func TestEscapePathDisplayForms(t *testing.T) {
	bom := string(rune(0xFEFF)) // byte order mark, a format character (Cf)
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"ascii", []byte("/etc/hosts"), "/etc/hosts"},
		{"backslash", []byte(`/etc/a\b`), `/etc/a\x5cb`},
		{"lone backslash", []byte(`\`), `\x5c`},
		{"newline", []byte("/etc/a\nb"), `/etc/a\x0ab`},
		{"tab and DEL", []byte("/a\tb\x7f"), `/a\x09b\x7f`},
		{"invalid byte", []byte{'/', 0xff}, `/\xff`},
		{"truncated multibyte", []byte{'/', 0xc3}, `/\xc3`},
		{"surrogate encoding", []byte{'/', 0xed, 0xa0, 0x80}, `/\xed\xa0\x80`},
		{"printable utf8", []byte("/etc/ä"), "/etc/ä"},
		{"bidi override RLO", []byte{'/', 'e', 't', 'c', '/', 0xe2, 0x80, 0xae, 'x'}, `/etc/\xe2\x80\xaex`},
		{"bidi isolate LRI", []byte{'/', 0xe2, 0x81, 0xa6, 'x'}, `/\xe2\x81\xa6x`},
		{"zero width space", []byte("/a​b"), `/a\xe2\x80\x8bb`},
		{"zero width joiner", []byte("/a‍b"), `/a\xe2\x80\x8db`},
		{"byte order mark", []byte(bom + "/etc"), `\xef\xbb\xbf/etc`},
		{"no-break space", []byte("/a b"), `/a\xc2\xa0b`},
		{"ideographic space", []byte("/a　b"), `/a\xe3\x80\x80b`},
		{"C1 control", []byte("/a\u0085b"), `/a\xc2\x85b`},
		{"mixed", []byte("/srv/ä\\\x1b[31m‮\xff"), `/srv/ä\x5c\x1b[31m\xe2\x80\xae\xff`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EscapePath(tc.raw)
			if got != tc.want {
				t.Errorf("EscapePath(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if fg := fimscan.EscapePath(tc.raw); got != fg {
				t.Errorf("EscapePath(%q) = %q, fimscan gives %q", tc.raw, got, fg)
			}
		})
	}
}

func FuzzEscapePathMatchesFimscan(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(""),
		[]byte("/etc/hosts"),
		[]byte(`\`),
		[]byte(`\x5c`),
		[]byte("\x00\x1b[2J"),
		[]byte("\xe2\x80\xae/etc"),
		[]byte("\xe2\x80\x8b"),
		[]byte("\xc3"),
		[]byte("\xff\xfe"),
		[]byte("ä　ß"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got := EscapePath(raw)
		if want := fimscan.EscapePath(raw); got != want {
			t.Fatalf("EscapePath(%q) = %q, fimscan gives %q", raw, got, want)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("EscapePath(%q) = %q: not valid UTF-8", raw, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) {
				t.Fatalf("EscapePath(%q) = %q: contains non-printable or format rune %U", raw, got, r)
			}
		}
		if back := unescapePath(t, got); !bytes.Equal(back, raw) {
			t.Fatalf("EscapePath(%q) = %q: unescapes to %q", raw, got, back)
		}
	})
}
