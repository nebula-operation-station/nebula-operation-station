// SPDX-License-Identifier: AGPL-3.0-or-later

package textdiff

import (
	"fmt"
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

// pairTexts builds two texts with pairs substituted line pairs, each
// preceded by one unchanged line, so the minimal script has 2*pairs edits.
// extraOld and extraNew add one line to one side, which adds one edit.
func pairTexts(pairs int, extraOld, extraNew bool) (string, string) {
	var a, b []string
	for i := 0; i < pairs; i++ {
		same := fmt.Sprintf("same %d", i)
		a = append(a, same, fmt.Sprintf("old %d", i))
		b = append(b, same, fmt.Sprintf("new %d", i))
	}
	if extraOld {
		a = append(a, "gone")
	}
	if extraNew {
		b = append(b, "added")
	}
	return strings.Join(a, "\n") + "\n", strings.Join(b, "\n") + "\n"
}

// ops renders the operation sequence, one byte per line: '=', '-' or '+'.
func ops(d []Line) string {
	var sb strings.Builder
	for _, l := range d {
		sb.WriteByte(byte(l.Op))
	}
	return sb.String()
}

// checkRebuild fails unless the diff rebuilds both inputs exactly.
func checkRebuild(t *testing.T, oldText, newText string, d []Line) {
	t.Helper()
	a, b := apply(d)
	if a != strings.Join(Lines(oldText), "\n") || b != strings.Join(Lines(newText), "\n") {
		t.Fatalf("diff does not rebuild the inputs: %v", d)
	}
}

// Exactly MaxEdits edits is still searched in full: the result keeps the
// unchanged lines between the substitutions, so it is not a replacement.
func TestDiffAtMaxEditsIsMinimalScript(t *testing.T) {
	oldText, newText := pairTexts(MaxEdits/2, false, false)
	d := Diff(oldText, newText)
	checkRebuild(t, oldText, newText, d)
	if got := edits(d); got != MaxEdits {
		t.Fatalf("%d edits, want %d", got, MaxEdits)
	}
	if kept := len(d) - edits(d); kept != MaxEdits/2 {
		t.Fatalf("%d unchanged lines, want %d: result is a full replacement", kept, MaxEdits/2)
	}
}

// One edit beyond MaxEdits falls back to a full replacement of the middle;
// only the common prefix is kept.
func TestDiffOneOverMaxEditsIsFullReplacement(t *testing.T) {
	oldText, newText := pairTexts(MaxEdits/2, false, true)
	d := Diff(oldText, newText)
	checkRebuild(t, oldText, newText, d)
	a, b := len(Lines(oldText)), len(Lines(newText))
	want := "=" + strings.Repeat("-", a-1) + strings.Repeat("+", b-1)
	if got := ops(d); got != want {
		t.Fatalf("ops %q, want full replacement %q", got, want)
	}
}

// One edit below MaxEdits is still minimal.
func TestDiffOneUnderMaxEditsIsMinimalScript(t *testing.T) {
	oldText, newText := pairTexts((MaxEdits-1)/2, true, false)
	d := Diff(oldText, newText)
	checkRebuild(t, oldText, newText, d)
	if got := edits(d); got != MaxEdits-1 {
		t.Fatalf("%d edits, want %d", got, MaxEdits-1)
	}
	if kept := len(d) - edits(d); kept != (MaxEdits-1)/2 {
		t.Fatalf("%d unchanged lines, want %d: result is a full replacement", kept, (MaxEdits-1)/2)
	}
}

// Edge cases on both sides of the boundary: pure insertions, pure deletions
// and unchanged lines around the change.
func TestDiffBoundaryEdgeCases(t *testing.T) {
	numbered := func(n int, tag string) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "%s %d\n", tag, i)
		}
		return sb.String()
	}
	for _, tc := range []struct {
		name, old, new string
		want           string
	}{
		{"insertions at MaxEdits", "", numbered(MaxEdits, "x"), strings.Repeat("+", MaxEdits)},
		{"insertions one over", "", numbered(MaxEdits+1, "x"), strings.Repeat("+", MaxEdits+1)},
		{"deletions at MaxEdits", numbered(MaxEdits, "x"), "", strings.Repeat("-", MaxEdits)},
		{"deletions one over", numbered(MaxEdits+1, "x"), "", strings.Repeat("-", MaxEdits+1)},
		{"insertions at MaxEdits after kept head", "h\n", "h\n" + numbered(MaxEdits, "x"), "=" + strings.Repeat("+", MaxEdits)},
		{"deletions at MaxEdits before kept tail", numbered(MaxEdits, "x") + "t\n", "t\n", strings.Repeat("-", MaxEdits) + "="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Diff(tc.old, tc.new)
			checkRebuild(t, tc.old, tc.new, d)
			if got := ops(d); got != tc.want {
				t.Fatalf("ops %q, want %q", got, tc.want)
			}
		})
	}
}

// Missing final newline does not change the edit count at the boundary.
func TestDiffBoundaryWithoutFinalNewline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pairs int
		extra bool
		want  int
	}{
		{"at MaxEdits", MaxEdits / 2, false, MaxEdits},
		{"one over MaxEdits", MaxEdits / 2, true, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldText, newText := pairTexts(tc.pairs, false, tc.extra)
			oldText = strings.TrimSuffix(oldText, "\n")
			newText = strings.TrimSuffix(newText, "\n")
			d := Diff(oldText, newText)
			checkRebuild(t, oldText, newText, d)
			if tc.want >= 0 && edits(d) != tc.want {
				t.Fatalf("%d edits, want %d", edits(d), tc.want)
			}
			if tc.want < 0 && edits(d) <= MaxEdits {
				t.Fatalf("%d edits, want more than %d", edits(d), MaxEdits)
			}
		})
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
