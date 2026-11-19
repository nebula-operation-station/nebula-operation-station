// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"strings"
	"testing"
)

// normalizeSpaces reduces runs of spaces to one, which is the only separator
// Tokenize uses, so two texts with the same normalized form have the same
// tokens. The table compares shape texts this way: the joining rule of ADR
// 0014 D4 says the backslash and the newline become one space, and the number
// of spaces in a shape does not matter to V3.
func normalizeSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// shapeLines returns the line numbers of the excluded lines, in order.
func excludedLines(set ShapeSet) []int {
	var out []int
	for _, e := range set.Excluded {
		out = append(out, e.Line)
	}
	return out
}

// TestShapesRuleOneInfoString checks which info strings count as shell blocks
// (ADR 0014 D4, rule 1): empty, sh, bash, shell and console, compared by the
// first word of the info string. Other info strings give no shapes and no
// exclusions.
func TestShapesRuleOneInfoString(t *testing.T) {
	const body = "nebula status"
	tests := []struct {
		name   string
		info   string
		counts bool
	}{
		{"untagged", "", true},
		{"sh", "sh", true},
		{"bash", "bash", true},
		{"shell", "shell", true},
		{"console", "console", true},
		{"bash with a second word", "bash title=x", true},
		{"json", "json", false},
		{"yaml", "yaml", false},
		{"json with a shell word after it", "json sh", false},
		{"upper-case SH is another tag", "SH", false},
		{"text", "text", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes(tt.info, body)
			if tt.counts {
				if len(set.Shapes) != 1 || set.Shapes[0].Text != "nebula status" {
					t.Fatalf("Shapes(%q) = %+v, want one shape %q", tt.info, set, body)
				}
				return
			}
			if len(set.Shapes) != 0 || len(set.Excluded) != 0 {
				t.Fatalf("Shapes(%q) = %+v, want nothing", tt.info, set)
			}
		})
	}
}

// TestShapesRuleTwoLines checks the line rules of ADR 0014 D4, rule 2: common
// fence indentation, continuation lines, blank lines, comment lines and
// trailing comments.
func TestShapesRuleTwoLines(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		shapes []Shape
	}{
		{
			name:   "common indentation is removed",
			body:   "  nebula status\n  nebula pve list",
			shapes: []Shape{{1, "nebula status"}, {2, "nebula pve list"}},
		},
		{
			name:   "indentation beyond the common part is kept out of the text",
			body:   "    a\n      b",
			shapes: []Shape{{1, "a"}, {2, "b"}},
		},
		{
			name:   "backslash continuation joins two lines into one",
			body:   "curl -fsS \\\n  https://192.0.2.1/x",
			shapes: []Shape{{1, "curl -fsS https://192.0.2.1/x"}},
		},
		{
			name:   "continuation of three lines has the line number of the first",
			body:   "nebula a \\\n  b \\\n  c\nnebula d",
			shapes: []Shape{{1, "nebula a b c"}, {4, "nebula d"}},
		},
		{
			name:   "blank lines and comment lines are dropped",
			body:   "# note\n\n   \nnebula status\n# end",
			shapes: []Shape{{4, "nebula status"}},
		},
		{
			name:   "trailing comment is removed",
			body:   "nebula status # show the status",
			shapes: []Shape{{1, "nebula status"}},
		},
		{
			name:   "hash inside double quotes stays",
			body:   `echo "a # b"`,
			shapes: []Shape{{1, `echo "a # b"`}},
		},
		{
			name:   "hash inside single quotes stays",
			body:   `echo 'a # b'`,
			shapes: []Shape{{1, `echo 'a # b'`}},
		},
		{
			name:   "hash inside a word stays",
			body:   "echo a#b",
			shapes: []Shape{{1, "echo a#b"}},
		},
		{
			name:   "escaped hash stays",
			body:   `echo \# x`,
			shapes: []Shape{{1, `echo \# x`}},
		},
		{
			name:   "hash after a quoted part of the same word is not a comment start",
			body:   "echo 'x'# y",
			shapes: []Shape{{1, "echo 'x'# y"}},
		},
		{
			name:   "hash after a quoted word is a comment start when it begins a word",
			body:   "echo 'x' # y",
			shapes: []Shape{{1, "echo 'x'"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if len(set.Excluded) != 0 {
				t.Fatalf("Shapes(%q) excluded %+v, want no exclusions", tt.body, set.Excluded)
			}
			if len(set.Shapes) != len(tt.shapes) {
				t.Fatalf("Shapes(%q) = %+v, want %+v", tt.body, set.Shapes, tt.shapes)
			}
			for i, want := range tt.shapes {
				got := set.Shapes[i]
				if got.Line != want.Line || normalizeSpaces(got.Text) != normalizeSpaces(want.Text) {
					t.Fatalf("Shapes(%q) shape %d = %+v, want %+v", tt.body, i, got, want)
				}
			}
		})
	}
}

// TestShapesRuleTwoExclusions checks the lines that rule 2 cannot turn into a
// shape. They are excluded with a reason, so nothing is dropped silently.
func TestShapesRuleTwoExclusions(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []int
	}{
		{"comment with an apostrophe after a command", "echo hi # don't", []int{1}},
		{"unbalanced double quote", `echo "abc`, []int{1}},
		{"tab inside a line", "echo\tx", []int{1}},
		{"carriage return", "nebula status\r", []int{1}},
		{"continuation at the end of the block", "echo a \\", []int{1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if len(set.Shapes) != 0 {
				t.Fatalf("Shapes(%q) = %+v, want no shape for the excluded line", tt.body, set.Shapes)
			}
			if got := excludedLines(set); !equalInts(got, tt.want) {
				t.Fatalf("Shapes(%q) excluded lines %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

// TestShapesRuleThreeBackupLoop checks the container backup loop of
// docs/handbook/backup-restore.md (ADR 0014 D4, rule 3): every line of the
// loop is excluded, and the shape list is empty.
func TestShapesRuleThreeBackupLoop(t *testing.T) {
	body := "for f in /var/lib/nebula/*; do\n" +
		"  tar -C /var/lib/nebula -czf \"/backup/$(date +%F).tgz\" \"$f\"\n" +
		"  age -r age1example -o \"$f.age\" \"$f.tgz\"\n" +
		"done"
	set := Shapes("", body)
	if len(set.Shapes) != 0 {
		t.Fatalf("backup loop gave shapes %+v, want none", set.Shapes)
	}
	if got, want := excludedLines(set), []int{1, 2, 3, 4}; !equalInts(got, want) {
		t.Fatalf("backup loop excluded lines %v, want %v", got, want)
	}
	if set.Excluded[0].Reason != "compound construct (for)" {
		t.Fatalf("backup loop reason = %q, want %q", set.Excluded[0].Reason, "compound construct (for)")
	}
}

// TestShapesRuleThreeConstructs checks compound constructs: nesting is counted,
// a construct without its closing word excludes everything up to the end of
// the block, and a line that holds a keyword in the middle is excluded too.
func TestShapesRuleThreeConstructs(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		shapes []Shape
		excl   []int
	}{
		{
			name: "if nested in for, the line after the loop is a shape",
			body: "for h in a b; do\n" +
				"  if [ -f \"$h\" ]; then\n" +
				"    echo \"$h\"\n" +
				"  fi\n" +
				"done\n" +
				"echo after",
			shapes: []Shape{{6, "echo after"}},
			excl:   []int{1, 2, 3, 4, 5},
		},
		{
			name:   "one-line loop",
			body:   "for x in a b; do echo $x; done\nnebula status",
			shapes: []Shape{{2, "nebula status"}},
			excl:   []int{1},
		},
		{
			name:   "for without done excludes to the end of the block",
			body:   "for x in a; do\necho $x",
			shapes: nil,
			excl:   []int{1, 2},
		},
		{
			name:   "if without fi excludes to the end of the block",
			body:   "if true; then\n  echo\nnebula status",
			shapes: nil,
			excl:   []int{1, 2, 3},
		},
		{
			name:   "case and esac",
			body:   "case $x in\n  a) nebula status;;\nesac\nnebula status",
			shapes: []Shape{{4, "nebula status"}},
			excl:   []int{1, 2, 3},
		},
		{
			name:   "keyword in the middle of a line is a compound construct",
			body:   "echo x; for f in a; do b; done\nnebula status",
			shapes: []Shape{{2, "nebula status"}},
			excl:   []int{1},
		},
		{
			name:   "keyword as a quoted word is not a keyword",
			body:   `echo "for"`,
			shapes: []Shape{{1, `echo "for"`}},
			excl:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if got, want := excludedLines(set), tt.excl; !equalInts(got, want) {
				t.Fatalf("excluded lines %v, want %v (set %+v)", got, want, set)
			}
			if len(set.Shapes) != len(tt.shapes) {
				t.Fatalf("shapes %+v, want %+v", set.Shapes, tt.shapes)
			}
			for i, want := range tt.shapes {
				if got := set.Shapes[i]; got.Line != want.Line || normalizeSpaces(got.Text) != normalizeSpaces(want.Text) {
					t.Fatalf("shape %d = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// TestShapesRuleThreeHeredocs checks heredocs: the line with `<<` and its body
// up to the delimiter are excluded; a heredoc whose delimiter is missing, or
// whose delimiter cannot be read, excludes to the end of the block.
func TestShapesRuleThreeHeredocs(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		shapes []Shape
		excl   []int
	}{
		{
			name:   "dash heredoc with a tab-indented delimiter",
			body:   "cat <<-EOF > /tmp/x\n\thello\n\tEOF\necho ok",
			shapes: []Shape{{4, "echo ok"}},
			excl:   []int{1, 2, 3},
		},
		{
			name:   "double-quoted delimiter",
			body:   "cat <<\"END\"\n$x\nEND\nnebula status",
			shapes: []Shape{{4, "nebula status"}},
			excl:   []int{1, 2, 3},
		},
		{
			name:   "single-quoted delimiter",
			body:   "cat <<'EOF'\n$(rm -rf /)\nEOF\nnebula status",
			shapes: []Shape{{4, "nebula status"}},
			excl:   []int{1, 2, 3},
		},
		{
			name:   "keyword in a heredoc body is not a construct",
			body:   "cat <<EOF\ndone\nEOF\necho ok",
			shapes: []Shape{{4, "echo ok"}},
			excl:   []int{1, 2, 3},
		},
		{
			name:   "unclosed heredoc excludes to the end",
			body:   "cat <<EOF\nline\necho",
			shapes: nil,
			excl:   []int{1, 2, 3},
		},
		{
			name:   "plain heredoc does not end at an indented delimiter",
			body:   "cat <<EOF\n\tEOF\necho",
			shapes: nil,
			excl:   []int{1, 2, 3},
		},
		{
			name:   "delimiter that cannot be read excludes to the end",
			body:   "cat <<'EOF\nx\nEOF\necho",
			shapes: nil,
			excl:   []int{1, 2, 3, 4},
		},
		{
			name:   "here-string has no body",
			body:   `grep x <<< "y"` + "\nnebula status",
			shapes: []Shape{{2, "nebula status"}},
			excl:   []int{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if got, want := excludedLines(set), tt.excl; !equalInts(got, want) {
				t.Fatalf("excluded lines %v, want %v (set %+v)", got, want, set)
			}
			if len(set.Shapes) != len(tt.shapes) {
				t.Fatalf("shapes %+v, want %+v", set.Shapes, tt.shapes)
			}
			for i, want := range tt.shapes {
				if got := set.Shapes[i]; got.Line != want.Line || normalizeSpaces(got.Text) != normalizeSpaces(want.Text) {
					t.Fatalf("shape %d = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// TestShapesRestorePipe checks a restore line of docs/handbook/backup-restore.md
// shape: a pipe is not a compound construct, so the line is one shape.
func TestShapesRestorePipe(t *testing.T) {
	body := "cat /backup/x.tgz | docker run -i --rm debian:12-slim tar -C /v -xpz"
	set := Shapes("bash", body)
	if len(set.Excluded) != 0 || len(set.Shapes) != 1 {
		t.Fatalf("restore pipe = %+v, want one shape and no exclusion", set)
	}
	if set.Shapes[0].Text != body {
		t.Fatalf("restore pipe text = %q, want %q", set.Shapes[0].Text, body)
	}
}

// TestShapesLineNumbersAreBlockLines checks that Line counts the lines of the
// block body, including dropped and continued lines, so a later caller can
// point at the source.
func TestShapesLineNumbersAreBlockLines(t *testing.T) {
	body := "# a\n\nnebula a \\\n  b\n\nnebula c"
	set := Shapes("sh", body)
	if len(set.Shapes) != 2 {
		t.Fatalf("shapes = %+v, want two", set.Shapes)
	}
	if set.Shapes[0].Line != 3 || set.Shapes[1].Line != 6 {
		t.Fatalf("line numbers = %d and %d, want 3 and 6", set.Shapes[0].Line, set.Shapes[1].Line)
	}
}

// TestShapesConsoleBlock checks a console block: its lines are shapes like the
// lines of any other shell block.
func TestShapesConsoleBlock(t *testing.T) {
	set := Shapes("console", "nebula status\nnebula pve list")
	if len(set.Shapes) != 2 || len(set.Excluded) != 0 {
		t.Fatalf("console block = %+v, want two shapes", set)
	}
}

// TestShapesJSONBlockIsEmpty checks rule 1 for a block tagged json: no shape
// and no exclusion, even when the body looks like a command.
func TestShapesJSONBlockIsEmpty(t *testing.T) {
	set := Shapes("json", "{\"cmd\": \"nebula status\"}\nfor x; do")
	if len(set.Shapes) != 0 || len(set.Excluded) != 0 {
		t.Fatalf("json block = %+v, want empty", set)
	}
}

// TestShapesBlockTooLong checks the size limit: a block longer than
// MaxBlockBytes gives no shape and one exclusion, so nothing is read past the
// limit.
func TestShapesBlockTooLong(t *testing.T) {
	body := strings.Repeat("a", MaxBlockBytes+1)
	set := Shapes("", body)
	if len(set.Shapes) != 0 {
		t.Fatalf("long block gave shapes %+v", set.Shapes)
	}
	if got := excludedLines(set); !equalInts(got, []int{1}) || set.Excluded[0].Reason != "block too long" {
		t.Fatalf("long block excluded = %+v, want one exclusion for line 1", set.Excluded)
	}
}

// TestShapesLineTooLong checks that a logical line longer than MaxCommandBytes
// is excluded, because Tokenize refuses it and no command can match it.
func TestShapesLineTooLong(t *testing.T) {
	body := "nebula " + strings.Repeat("a ", MaxCommandBytes)
	set := Shapes("", body)
	if len(set.Shapes) != 0 || !equalInts(excludedLines(set), []int{1}) {
		t.Fatalf("long line = %+v, want one exclusion", set)
	}
}

// TestShapesSelfMatch checks that every shape without a placeholder matches
// itself under MatchShape (ADR 0014 D4, V3): the builder never returns text
// the tokenizer refuses.
func TestShapesSelfMatch(t *testing.T) {
	bodies := []string{
		"nebula status\nnebula pve list",
		"curl -fsS \\\n  https://192.0.2.1/x",
		"cat /backup/x.tgz | docker run -i --rm debian:12-slim tar -C /v -xpz",
		"echo a#b # comment\necho 'x # y'",
		"nebula pve add <host> --endpoint <host>:8006",
	}
	for _, body := range bodies {
		for _, s := range Shapes("", body).Shapes {
			if HasPlaceholder(s.Text) {
				continue
			}
			if _, err := MatchShape(s.Text, s.Text); err != nil {
				t.Fatalf("MatchShape(%q, itself) = %v, want a match", s.Text, err)
			}
		}
	}
}

// TestShapesExclusionReasons checks the reason strings of the exclusions that
// the scan reports (ADR 0014 D4, rule 3), so that a later caller can show why
// a line is never copyable.
func TestShapesExclusionReasons(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		reason string
	}{
		{"loop", "for x; do\ny\ndone", "compound construct (for)"},
		{"unclosed loop", "while true; do", "unclosed compound construct (while)"},
		{"heredoc", "cat <<EOF\nx\nEOF", "heredoc"},
		{"heredoc body", "cat <<EOF\nx\nEOF", "heredoc body"},
		{"unclosed heredoc", "cat <<EOF\nx", "unclosed heredoc"},
		{"keyword in line", "echo x; if y; then z; fi", "compound keyword in line"},
		{"unbalanced quote", `echo "abc`, "unbalanced quote"},
		{"control character", "echo\tx", "control character"},
		{"continuation", "echo a \\", "continuation at end of block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			for _, e := range set.Excluded {
				if e.Reason == tt.reason {
					return
				}
			}
			t.Fatalf("Shapes(%q) = %+v, want a reason %q", tt.body, set, tt.reason)
		})
	}
}

// equalInts reports whether a and b hold the same numbers in the same order.
func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
