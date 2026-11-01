// SPDX-License-Identifier: AGPL-3.0-or-later

package textdiff

import (
	"strings"
	"testing"
)

// apply rebuilds both sides from a diff.
func apply(d []Line) (string, string) {
	var a, b []string
	for _, l := range d {
		if l.Op != Insert {
			a = append(a, l.Text)
		}
		if l.Op != Delete {
			b = append(b, l.Text)
		}
	}
	return strings.Join(a, "\n"), strings.Join(b, "\n")
}

func edits(d []Line) int {
	n := 0
	for _, l := range d {
		if l.Op != Equal {
			n++
		}
	}
	return n
}

func TestDiffIsCorrectAndMinimal(t *testing.T) {
	for _, tc := range []struct {
		old, new string
		edits    int
	}{
		{"", "", 0},
		{"a\nb\nc\n", "a\nb\nc\n", 0},
		{"a\nb\nc\n", "a\nx\nc\n", 2},
		{"a\nb\nc\n", "a\nc\n", 1},
		{"", "a\nb\n", 2},
		{"a\nb\n", "", 2},
		{"a\nb\nc\nd\n", "b\nc\nd\ne\n", 2},
		{"x\na\nb\ny\n", "z\na\nb\nw\n", 4},
	} {
		d := Diff(tc.old, tc.new)
		a, b := apply(d)
		if a != strings.TrimSuffix(tc.old, "\n") || b != strings.TrimSuffix(tc.new, "\n") {
			t.Fatalf("%q -> %q: diff does not rebuild the inputs: %v", tc.old, tc.new, d)
		}
		if edits(d) != tc.edits {
			t.Fatalf("%q -> %q: %d edits, want %d", tc.old, tc.new, edits(d), tc.edits)
		}
		if Changed(d) != (tc.edits > 0) {
			t.Fatal("Changed disagrees")
		}
	}
}

// A change beyond MaxEdits falls back to a full replacement quickly and
// stays correct.
func TestDiffBoundedFallback(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 3*MaxEdits; i++ {
		a.WriteString("a" + strings.Repeat("x", i%7) + "\n")
		b.WriteString("b" + strings.Repeat("y", i%5) + "\n")
	}
	d := Diff(a.String(), b.String())
	ga, gb := apply(d)
	if ga != strings.TrimSuffix(a.String(), "\n") || gb != strings.TrimSuffix(b.String(), "\n") {
		t.Fatal("fallback diff does not rebuild the inputs")
	}
}

func FuzzDiff(f *testing.F) {
	f.Add("a\nb\n", "b\nc\n")
	f.Fuzz(func(t *testing.T, old, new string) {
		d := Diff(old, new)
		a, b := apply(d)
		if a != strings.Join(Lines(old), "\n") || b != strings.Join(Lines(new), "\n") {
			t.Fatalf("diff does not rebuild inputs")
		}
	})
}
