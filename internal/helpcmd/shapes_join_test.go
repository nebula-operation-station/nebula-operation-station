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
