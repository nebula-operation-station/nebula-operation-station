// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"reflect"
	"strings"
	"testing"
)

// fuzzMaxBody bounds the block the fuzz target feeds to Shapes. The scan is
// linear in the block size (each line is read a fixed number of times, and
// the tokenizer is called once per line), so the bound keeps every run short;
// it is not a limit of the production code, which refuses blocks above
// MaxBlockBytes on its own.
const fuzzMaxBody = 8 << 10

// FuzzShapes checks the properties of the shape builder (ADR 0014 D4,
// "Shapes") on arbitrary input: no panic, the same input gives the same
// result, no shape holds a line break, no shape holds a control character, and
// no shape holds a word of a compound construct keyword (so no shape begins
// with one of for, while, until, if, case or select, or contains done, fi or
// esac as a word either).
func FuzzShapes(f *testing.F) {
	seeds := []struct{ info, body string }{
		{"", ""},
		{"sh", "nebula status"},
		{"bash", "curl -fsS \\\n  https://192.0.2.1/x"},
		{"console", "# note\n\n  nebula pve list # list"},
		{"json", "for x; do"},
		{"", "for f in a; do\n  if x; then\n    y\n  fi\ndone"},
		{"", "cat <<-EOF\n\tEOF\n"},
		{"", "cat <<'EOF\nx"},
		{"", "echo \"abc"},
		{"", "echo a \\"},
		{"", "echo\tx\r"},
	}
	for _, s := range seeds {
		f.Add(s.info, s.body)
	}
	f.Fuzz(func(t *testing.T, info, body string) {
		if len(body) > fuzzMaxBody {
			return
		}
		set := Shapes(info, body)
		if again := Shapes(info, body); !reflect.DeepEqual(set, again) {
			t.Fatalf("Shapes(%q, %q) is not deterministic: %+v and %+v", info, body, set, again)
		}
		lines := strings.Count(body, "\n") + 1
		for _, s := range set.Shapes {
			if strings.ContainsAny(s.Text, "\n\r") {
				t.Fatalf("Shapes(%q, %q) shape %q holds a line break", info, body, s.Text)
			}
			for i := 0; i < len(s.Text); i++ {
				if c := s.Text[i]; c < 0x20 || c == 0x7f {
					t.Fatalf("Shapes(%q, %q) shape %q holds control byte %#x", info, body, s.Text, c)
				}
			}
			if s.Line < 1 || s.Line > lines {
				t.Fatalf("Shapes(%q, %q) shape %q has line %d, block has %d lines", info, body, s.Text, s.Line, lines)
			}
			for _, w := range words(s.Text) {
				if openers[w] || closers[w] {
					t.Fatalf("Shapes(%q, %q) shape %q holds compound keyword %q", info, body, s.Text, w)
				}
			}
		}
		for _, e := range set.Excluded {
			if e.Line < 1 || e.Line > lines || e.Reason == "" {
				t.Fatalf("Shapes(%q, %q) exclusion %+v is out of range or has no reason", info, body, e)
			}
		}
	})
}
