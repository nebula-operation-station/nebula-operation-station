// SPDX-License-Identifier: AGPL-3.0-or-later

// Package textdiff computes bounded line diffs for review screens. The
// result is always a correct edit script from old to new; it is minimal
// while the number of edits stays within MaxEdits and otherwise falls back
// to deleting all old lines and inserting all new ones, so hostile input
// cannot make the computation quadratic.
package textdiff

import "strings"

// MaxEdits bounds the Myers search (time O((N+M)·MaxEdits), memory about
// MaxEdits² words); larger changes are shown as a full replacement.
const MaxEdits = 1000

// Op is a diff operation.
type Op byte

// Operations.
const (
	Equal  Op = '='
	Delete Op = '-'
	Insert Op = '+'
)

// Line is one line of a diff.
type Line struct {
	// Op says whether the line is kept, removed or added.
	Op Op
	// Text is the line without its newline.
	Text string
}

// Lines splits text into lines; a final newline does not start a line.
func Lines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// Diff returns an edit script turning old into new.
func Diff(old, new string) []Line {
	a, b := Lines(old), Lines(new)
	// Common prefix and suffix are cheap and keep the search small.
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	out := make([]Line, 0, len(a)+len(b))
	for _, l := range a[:pre] {
		out = append(out, Line{Equal, l})
	}
	mid, ok := myers(a[pre:len(a)-suf], b[pre:len(b)-suf])
	if !ok {
		mid = mid[:0]
		for _, l := range a[pre : len(a)-suf] {
			mid = append(mid, Line{Delete, l})
		}
		for _, l := range b[pre : len(b)-suf] {
			mid = append(mid, Line{Insert, l})
		}
	}
	out = append(out, mid...)
	for _, l := range a[len(a)-suf:] {
		out = append(out, Line{Equal, l})
	}
	return out
}

// Changed reports whether a diff has any insertion or deletion.
func Changed(d []Line) bool {
	for _, l := range d {
		if l.Op != Equal {
			return true
		}
	}
	return false
}

// myers is the O((N+M)D) greedy diff with D bounded by MaxEdits.
func myers(a, b []string) ([]Line, bool) {
	n, m := len(a), len(b)
	max := n + m
	if max == 0 {
		return nil, true
	}
	if max > MaxEdits {
		max = MaxEdits
	}
	off := max + 1
	v := make([]int, 2*max+3)
	var trace [][]int
	for d := 0; d <= max; d++ {
		// Only diagonals -d-1..d+1 are read when backtracking step d.
		snap := make([]int, 2*d+3)
		copy(snap, v[off-d-1:off+d+2])
		trace = append(trace, snap)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(a, b, trace, d), true
			}
		}
	}
	return nil, false
}

func backtrack(a, b []string, trace [][]int, d int) []Line {
	x, y := len(a), len(b)
	var rev []Line
	for ; d > 0; d-- {
		snap := trace[d]
		at := func(k int) int { return snap[k+d+1] }
		k := x - y
		var pk int
		if k == -d || (k != d && at(k-1) < at(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := at(pk)
		py := px - pk
		for x > px && y > py {
			x--
			y--
			rev = append(rev, Line{Equal, a[x]})
		}
		if x == px {
			y--
			rev = append(rev, Line{Insert, b[y]})
		} else {
			x--
			rev = append(rev, Line{Delete, a[x]})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, Line{Equal, a[x]})
	}
	out := make([]Line, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}
