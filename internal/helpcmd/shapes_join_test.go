// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"strings"
	"testing"
)

// TestShapesAmbiguousJoinKeepsConstructBodiesExcluded checks that a logical line
// excluded with reasonAmbiguousJoin is still fed to the construct and heredoc
// tracker. The opener it holds opens a construct or a heredoc, so the body lines
// after it are excluded, and only the command after the closer is a shape.
func TestShapesAmbiguousJoinKeepsConstructBodiesExcluded(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"heredoc opener in a comment",
			"cat <<EOF # note \\\nnebula status\nEOF\nnebula pve list"},
		{"heredoc opener after a quote that the join splits",
			"cat <<EOF \"a \\\nb\"\nnebula status\nEOF\nnebula pve list"},
		{"for opener in a comment",
			"for x in a; do # c \\\necho hi\nnebula status\ndone\nnebula pve list"},
		{"if opener in a comment",
			"if true; then # c \\\necho hi\nnebula status\nfi\nnebula pve list"},
		// The shell does not join across a backslash that ends a comment, so
		// the next physical line is a command of its own.
		{"heredoc opener on the line after a backslash in a comment",
			"echo # c \\\ncat <<EOF\nnebula status\nEOF\nnebula pve list"},
		{"for opener on the line after a backslash in a comment",
			"echo # c \\\nfor x in a; do\necho hi\nnebula status\ndone\nnebula pve list"},
		{"if opener on the line after a backslash in a comment",
			"echo # c \\\nif true; then\necho hi\nnebula status\nfi\nnebula pve list"},
		// A doubled backslash is a literal backslash, so the line break ends
		// the command and the next physical line is read on its own.
		{"heredoc opener on the line after a doubled backslash",
			"echo foo \\\\\ncat <<EOF\nnebula status\nEOF\nnebula pve list"},
		{"for opener on the line after a doubled backslash",
			"echo foo \\\\\nfor x in a; do\necho hi\nnebula status\ndone\nnebula pve list"},
		{"while opener on the line after a doubled backslash",
			"echo foo \\\\\nwhile false; do\necho hi\nnebula status\ndone\nnebula pve list"},
		{"heredoc opener on the line after a comment backslash, then a real join",
			"echo # c \\\ncat <<EOF \\\n\"x\"\nnebula status\nEOF\nnebula pve list"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if len(set.Shapes) != 1 || set.Shapes[0].Text != "nebula pve list" {
				t.Fatalf("shapes %+v, want only nebula pve list", set.Shapes)
			}
			for _, e := range set.Excluded {
				if e.Reason == "" {
					t.Fatalf("exclusion %+v has no reason", e)
				}
			}
		})
	}
}

// TestShapesOverlongLineFailsClosedForQuotes checks that a logical line longer
// than MaxCommandBytes does not hide an unbalanced quote: the quote may run into
// the following lines, so the block is broken from that line on and no later
// line is a shape.
func TestShapesOverlongLineFailsClosedForQuotes(t *testing.T) {
	body := "echo \"" + strings.Repeat("a ", MaxCommandBytes) + "\nnebula status\nnebula pve list"
	set := Shapes("", body)
	if len(set.Shapes) != 0 {
		t.Fatalf("shapes %+v after an over-long line with an open quote, want none", set.Shapes)
	}
	if got := excludedLines(set); !equalInts(got, []int{1, 2, 3}) {
		t.Fatalf("excluded lines %v, want [1 2 3]", got)
	}
}

// TestShapesSegmentWithUnbalancedQuoteBreaksBlock checks that a command segment
// read after a line break the shell ends is checked for quoting like any line:
// an open quote there breaks the rest of the block, so no later line is a shape.
func TestShapesSegmentWithUnbalancedQuoteBreaksBlock(t *testing.T) {
	body := "echo # c \\\necho \"x\nnebula status\nnebula pve list"
	set := Shapes("", body)
	if len(set.Shapes) != 0 {
		t.Fatalf("shapes %+v after an unbalanced quote in a segment, want none", set.Shapes)
	}
	// Lines 1 and 2 are one joined logical line, which starts at line 1.
	if got := excludedLines(set); !equalInts(got, []int{1, 3, 4}) {
		t.Fatalf("excluded lines %v, want [1 3 4]", got)
	}
}
