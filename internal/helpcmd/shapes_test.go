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
		{"bash with a second word is not bash", "bash title=x", false},
		{"json", "json", false},
		{"yaml", "yaml", false},
		{"json with a shell word after it", "json sh", false},
		{"sh with a second word is not sh", "sh title=x", false},
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

// TestShapesKeywordsOnlyInCommandPosition checks that a compound keyword is a
// keyword only where a command starts (ADR 0014 D4, rule 3). A closer used as
// an argument, a quoted keyword and a keyword inside a word are plain words:
// those lines are shapes. A keyword after a pipe or a group opens a construct.
func TestShapesKeywordsOnlyInCommandPosition(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		shapes []Shape
		excl   []int
	}{
		{"echo done is a shape", "echo done", []Shape{{1, "echo done"}}, nil},
		{"grep done log is a shape", "grep done log", []Shape{{1, "grep done log"}}, nil},
		{"quoted for in echo is a shape", "echo 'a for b'", []Shape{{1, "echo 'a for b'"}}, nil},
		{"keyword inside a word is a shape", "echo forx fi_ esacs", []Shape{{1, "echo forx fi_ esacs"}}, nil},
		{"pipe into while opens a construct", "ls | while read l; do\n  rm \"$l\"\ndone\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"group opens a for loop", "{ for f in a; do\n  rm x\ndone; }\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"command substitution with a loop", "x=$(\nfor f in a; do\n  rm \"$f\"\ndone\n)\nnebula status",
			[]Shape{{6, "nebula status"}}, []int{1, 2, 3, 4, 5}},
		{"if after and-list opens a construct", "true && if x; then\n  rm y\nfi\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"for) outside a case opens a construct", "for) rm -rf /\nnebula status",
			nil, []int{1, 2}},
		{"if) outside a case opens a construct", "if) x\nnebula status",
			nil, []int{1, 2}},
		{"for) inside a case is a pattern", "case $x in\n  for) rm -r y;;\n  *) rm z;;\nesac\nnebula status",
			[]Shape{{5, "nebula status"}}, []int{1, 2, 3, 4}},
		{"if) inside a case is a pattern", "case $x in\n  if) rm -r y;;\nesac\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"multi-line brace group", "{\n  rm x\n}\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"function body", "f() {\n  rm x\n}\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"multi-line subshell", "(\n  rm x\n)\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"multi-line command substitution", "x=$(\n  rm x\n)\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"single-line brace group is a shape", "{ nebula status; }", []Shape{{1, "{ nebula status; }"}}, nil},
		{"single-line command substitution is a shape", "x=$(date +%F)", []Shape{{1, "x=$(date +%F)"}}, nil},
		{"unclosed brace group excludes the rest", "{\n  nebula status",
			nil, []int{1, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if got := excludedLines(set); !equalInts(got, tt.excl) {
				t.Fatalf("excluded lines %v, want %v (set %+v)", got, tt.excl, set)
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

// TestShapesCloserInsideLoopBody checks the leak of a closing word used as a
// plain word in a loop body: the body lines after it stay excluded.
func TestShapesCloserInsideLoopBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"echo done", "for f in a; do\n  echo done\n  rm \"$f\"\ndone\nnebula status"},
		{"quoted fi", "for f in a; do\n  echo ' fi '\n  rm \"$f\"\ndone\nnebula status"},
		{"grep done in an if", "for f in a; do\n  if grep done \"$f\"; then\n    echo esac\n  fi\n  rm \"$f\"\ndone\nnebula status"},
		{"case pattern done", "case $x in\n  done) rm -r y;;\n  *) rm z;;\nesac\nnebula status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if len(set.Shapes) != 1 || set.Shapes[0].Text != "nebula status" {
				t.Fatalf("shapes %+v, want only nebula status", set.Shapes)
			}
			lines := strings.Count(tt.body, "\n") + 1
			if got := excludedLines(set); len(got) != lines-1 {
				t.Fatalf("excluded lines %v, want every line but the last", got)
			}
		})
	}
}

// TestShapesHeredocs checks heredocs: several "<<" on one line take their
// bodies in order, a quoted delimiter with trailing text is read per POSIX
// quote removal, and a here-string excludes its line without a body.
func TestShapesHeredocs(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		shapes []Shape
		excl   []int
	}{
		{"two heredocs on one line", "cat <<A <<B\na\nA\nb\nB\nnebula status",
			[]Shape{{6, "nebula status"}}, []int{1, 2, 3, 4, 5}},
		{"second heredoc starts after the first one ends", "cat <<A <<B\na\nB\nA\nnebula status",
			nil, []int{1, 2, 3, 4, 5}},
		{"quoted delimiter with trailing text", "cat <<\"E\"OF\nx\nEOF\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"single-quoted delimiter with trailing text", "cat <<'E'OF\nx\nEOF\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"heredoc inside a loop, delimiter line closes the heredoc only",
			"for f in a; do\n  cat <<EOF\ndone\nEOF\n  rm \"$f\"\ndone\nnebula status",
			[]Shape{{7, "nebula status"}}, []int{1, 2, 3, 4, 5, 6}},
		{"here-string in a loop", "for f in a; do\n  grep x <<< \"$f\"\ndone\nnebula status",
			[]Shape{{4, "nebula status"}}, []int{1, 2, 3}},
		{"empty delimiter excludes to the end", "cat <<\"\"\n\nnebula status",
			nil, []int{1, 2, 3}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if got := excludedLines(set); !equalInts(got, tt.excl) {
				t.Fatalf("excluded lines %v, want %v (set %+v)", got, tt.excl, set)
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

// TestShapesAmbiguousJoinIsExcluded checks rule 2 read literally: a line ending
// in a backslash is joined with the next line. When the shell would not read
// that join as a plain continuation (the backslash is in a comment, in quotes or
// after another backslash), the joined logical line is excluded with
// reasonAmbiguousJoin. It is never a shape and the next command is not dropped.
func TestShapesAmbiguousJoinIsExcluded(t *testing.T) {
	tests := []struct {
		name string
		body string
		excl []Excluded
	}{
		{"comment line ending in a backslash", "# note \\\nnebula status",
			[]Excluded{{1, "# note  nebula status", reasonAmbiguousJoin}}},
		{"trailing comment ending in a backslash", "echo a # c \\\nb",
			[]Excluded{{1, "echo a # c  b", reasonAmbiguousJoin}}},
		{"escaped backslash at the end is not a continuation", "echo a \\\\\nb",
			[]Excluded{{1, "echo a \\ b", reasonAmbiguousJoin}}},
		{"backslash inside single quotes", "echo 'a \\\nb'",
			[]Excluded{{1, "echo 'a  b'", reasonAmbiguousJoin}}},
		{"backslash inside double quotes", "echo \"a \\\nb\"",
			[]Excluded{{1, "echo \"a  b\"", reasonAmbiguousJoin}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := Shapes("", tt.body)
			if len(set.Shapes) != 0 {
				t.Fatalf("shapes %+v, want none", set.Shapes)
			}
			if len(set.Excluded) != len(tt.excl) {
				t.Fatalf("excluded %+v, want %+v", set.Excluded, tt.excl)
			}
			for i, want := range tt.excl {
				if got := set.Excluded[i]; got != want {
					t.Fatalf("excluded %d = %+v, want %+v", i, got, want)
				}
			}
		})
	}
}

// TestShapesPlainContinuationJoins checks that a backslash at the end of an
// unquoted command joins it with the next line into one shape.
func TestShapesPlainContinuationJoins(t *testing.T) {
	set := Shapes("", "echo a \\\n  b \\\n  c\nnebula status")
	if len(set.Excluded) != 0 {
		t.Fatalf("excluded %+v, want none", set.Excluded)
	}
	if len(set.Shapes) != 2 || set.Shapes[0].Line != 1 || normalizeSpaces(set.Shapes[0].Text) != "echo a b c" {
		t.Fatalf("shapes %+v, want the joined echo at line 1 and nebula status", set.Shapes)
	}
}

// TestShapesTrailingCommentDoesNotBreakQuotes checks that the quote check looks
// at the text before the trailing comment: "echo hi # don't" is a shape, and an
// apostrophe in a comment does not mark the later lines of the block broken.
func TestShapesTrailingCommentDoesNotBreakQuotes(t *testing.T) {
	set := Shapes("", "echo hi # don't\nnebula status\nnebula pve list")
	if len(set.Excluded) != 0 {
		t.Fatalf("excluded %+v, want none", set.Excluded)
	}
	want := []Shape{{1, "echo hi"}, {2, "nebula status"}, {3, "nebula pve list"}}
	if len(set.Shapes) != len(want) {
		t.Fatalf("shapes %+v, want %+v", set.Shapes, want)
	}
	for i := range want {
		if set.Shapes[i] != want[i] {
			t.Fatalf("shape %d = %+v, want %+v", i, set.Shapes[i], want[i])
		}
	}
}

// TestShapesUnbalancedQuoteEndsReadableBlock checks that after a line with an
// unbalanced quote the quoting state is unknown, so every later line is
// excluded with the reason of the quote.
func TestShapesUnbalancedQuoteEndsReadableBlock(t *testing.T) {
	set := Shapes("", "echo \"a\nnebula status\nnebula pve list")
	if len(set.Shapes) != 0 {
		t.Fatalf("shapes %+v, want none after an unbalanced quote", set.Shapes)
	}
	if got := excludedLines(set); !equalInts(got, []int{1, 2, 3}) {
		t.Fatalf("excluded lines %v, want [1 2 3]", got)
	}
	for _, e := range set.Excluded {
		if e.Reason != reasonUnbalancedQuote {
			t.Fatalf("exclusion %+v, want reason %q", e, reasonUnbalancedQuote)
		}
	}
}

// TestShapesConstructBodiesNeverShape is the oracle of the construct rules: it
// builds blocks from a known opener, a known body and a known closer. The body
// lines are never shapes, whatever words they hold, and the line after the
// closer is the only shape. The expected result follows from how the block is
// built, not from the scanner.
func TestShapesConstructBodiesNeverShape(t *testing.T) {
	type construct struct{ open, close string }
	constructs := []construct{
		{"for x in a; do", "done"},
		{"ls | while read l; do", "done"},
		{"{ for x in a; do", "done; }"},
		{"x=$(for x in a; do", "done)"},
		{"x=$(", ")"},
		{"{", "}"},
		{"f() {", "}"},
		{"(", ")"},
		{"if true; then", "fi"},
		{"case $x in", "esac"},
	}
	bodies := [][]string{
		{"echo done"},
		{"echo ' fi '", "rm \"$f\""},
		{"grep done log", "echo esac"},
		{"cat <<EOF", "done", "EOF"},
		{"for y in b; do", "echo y", "done"},
		{"echo \"done\" # fi"},
	}
	for _, c := range constructs {
		for bi, body := range bodies {
			lines := append([]string{c.open}, body...)
			lines = append(lines, c.close, "nebula status")
			block := strings.Join(lines, "\n")
			t.Run(c.open+" body "+string(rune('a'+bi)), func(t *testing.T) {
				set := Shapes("", block)
				last := len(lines)
				if len(set.Shapes) != 1 || set.Shapes[0].Line != last || set.Shapes[0].Text != "nebula status" {
					t.Fatalf("block %q shapes %+v, want only nebula status at line %d", block, set.Shapes, last)
				}
				var want []int
				for k := 1; k < last; k++ {
					want = append(want, k)
				}
				if got := excludedLines(set); !equalInts(got, want) {
					t.Fatalf("block %q excluded lines %v, want %v", block, got, want)
				}
			})
		}
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
