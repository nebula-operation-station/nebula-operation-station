// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"strings"
)

// MaxBlockBytes is the largest code block the shape builder reads (ADR 0014
// D4, "Shapes"). A longer block gives no shapes; it is reported as one
// exclusion, so the scan never reads past this size.
const MaxBlockBytes = 64 << 10

// Reasons of the exclusions that Shapes reports. They are the text a caller
// may show for a line that is never copyable.
const (
	reasonHeredoc         = "heredoc"
	reasonHeredocBody     = "heredoc body"
	reasonHeredocOpen     = "unclosed heredoc"
	reasonHeredocNoDelim  = "heredoc delimiter not parsed"
	reasonKeywordInLine   = "compound keyword in line"
	reasonUnbalancedQuote = "unbalanced quote"
	reasonLineTooLong     = "line too long"
	reasonControl         = "control character"
	reasonContinuation    = "continuation at end of block"
	reasonBlockTooLong    = "block too long"
)

// openers are the words that start a compound construct (ADR 0014 D4, rule 3).
var openers = map[string]bool{
	"for": true, "while": true, "until": true, "if": true, "case": true, "select": true,
}

// closers are the words that end one. done closes for, while, until and
// select; fi closes if; esac closes case.
var closers = map[string]bool{"done": true, "fi": true, "esac": true}

// Shape is one logical command line of a shell code block, a doc example for
// the V3 matching (ADR 0014 D4, "Shapes").
type Shape struct {
	// Line is the 1-based number, in the block body, of the first physical
	// line of the logical line.
	Line int
	// Text is the logical line: the common fence indentation removed, the
	// continuations joined, a trailing comment removed, and the surrounding
	// spaces trimmed. It holds no line break and no control character.
	Text string
}

// Excluded is a line of a code block that gives no shape. Compound constructs
// and heredocs are never copyable, so the caller shows them as "not
// copyable" and needs the reason.
type Excluded struct {
	// Line is the 1-based number, in the block body, of the first physical
	// line of the excluded logical line.
	Line int
	// Text is the logical line as the builder read it.
	Text string
	// Reason says why the line is not a shape.
	Reason string
}

// ShapeSet is the result of Shapes: the shapes of a block in source order and
// the excluded lines in source order.
type ShapeSet struct {
	// Shapes are the command lines of the block that the V3 matching may use.
	Shapes []Shape
	// Excluded are the lines that give no shape, each with its reason.
	Excluded []Excluded
}

// logicalLine is one logical line before the rules of ADR 0014 D4 are applied.
type logicalLine struct {
	line int    // 1-based first physical line
	raw  string // continuations joined, common indentation removed; keeps comments
	text string // raw without a trailing comment, trimmed; "" when raw is only a comment
	prob string // reason the line cannot be a shape, "" when it can
}

// Shapes builds the shapes of one fenced code block (ADR 0014 D4). info is the
// info string of the fence and body the code between the fences, lines joined
// with "\n". Only a block whose info string starts with the word "", sh, bash,
// shell or console gives shapes; any other block gives an empty ShapeSet.
//
// The rules, in order: remove the common indentation; join a line ending in a
// backslash with the next line, the backslash and the line break becoming one
// space; drop blank lines and lines starting with "#"; remove a trailing
// comment, that is a "#" starting a word outside quotes (Tokenize decides
// quoting). A line that starts with a compound construct keyword (for, while,
// until, if, case, select), or any line that holds one of these or done, fi,
// esac as a word, belongs to a construct that runs to its closing word, with
// the nesting counted; a line with a heredoc ("<<") and its body up to the
// delimiter is excluded too. A construct or heredoc that is not closed excludes
// everything to the end of the block (fail closed).
//
// A line the rules do not settle is excluded, not guessed: an unbalanced quote,
// a tab or other control character inside the line, a line longer than
// MaxCommandBytes, and a continuation at the end of the block.
func Shapes(info, body string) ShapeSet {
	var set ShapeSet
	if !isShellBlock(info) {
		return set
	}
	if len(body) > MaxBlockBytes {
		set.Excluded = append(set.Excluded, Excluded{Line: 1, Text: "", Reason: reasonBlockTooLong})
		return set
	}
	lines := joinContinuations(strings.Split(body, "\n"), &set)
	lines = dropBlankAndComment(lines)
	scan(lines, &set)
	return set
}

// isShellBlock reports whether the first word of the info string is one of the
// tags of ADR 0014 D4, rule 1: an empty info string, sh, bash, shell or console.
func isShellBlock(info string) bool {
	fields := strings.Fields(info)
	if len(fields) == 0 {
		return true
	}
	switch fields[0] {
	case "sh", "bash", "shell", "console":
		return true
	}
	return false
}

// commonIndent returns the longest leading whitespace shared by all non-blank
// lines of the block.
func commonIndent(phys []string) string {
	common, seen := "", false
	for _, p := range phys {
		if strings.TrimSpace(p) == "" {
			continue
		}
		ind := p[:len(p)-len(strings.TrimLeft(p, " \t"))]
		if !seen {
			common, seen = ind, true
			continue
		}
		n := 0
		for n < len(common) && n < len(ind) && common[n] == ind[n] {
			n++
		}
		common = common[:n]
	}
	return common
}

// joinContinuations removes the common indentation and joins every line that
// ends in a backslash with the next line. The backslash and the line break
// become one space. A continuation that runs to the end of the block is
// excluded, since the command is then not known.
func joinContinuations(phys []string, set *ShapeSet) []logicalLine {
	common := commonIndent(phys)
	var out []logicalLine
	var acc strings.Builder
	start := 0
	open := false
	for n, p := range phys {
		p = strings.TrimPrefix(p, common)
		if !open {
			start = n + 1
			acc.Reset()
		} else {
			acc.WriteByte(' ')
		}
		if strings.HasSuffix(p, `\`) {
			acc.WriteString(p[:len(p)-1])
			open = true
			continue
		}
		open = false
		acc.WriteString(p)
		out = append(out, logicalLine{line: start, raw: acc.String()})
	}
	if open {
		set.Excluded = append(set.Excluded, Excluded{Line: start, Text: acc.String(), Reason: reasonContinuation})
	}
	return out
}

// dropBlankAndComment removes the blank lines and the lines that start with
// "#" (after spaces and tabs), removes a trailing comment from the others, and
// records what keeps a line from being a shape.
func dropBlankAndComment(in []logicalLine) []logicalLine {
	out := in[:0]
	for _, l := range in {
		t := strings.TrimLeft(l.raw, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		text, err := stripComment(t)
		switch {
		case err != nil && isTooLong(err):
			l.prob = reasonLineTooLong
		case err != nil:
			l.prob = reasonUnbalancedQuote
		}
		l.text = strings.TrimRight(text, " ")
		if l.prob == "" && containsControl(l.text) {
			l.prob = reasonControl
		}
		out = append(out, l)
	}
	return out
}

// stripComment removes a trailing comment from s. The comment starts at the
// first token that begins with "#": Tokenize splits s, and a token starting
// with "#" is a word outside quotes. Tokens are literal substrings of s that
// are separated only by spaces, so the byte offset of each token is found by
// skipping the spaces before it. An error of Tokenize is returned unchanged
// and s is returned as it is.
func stripComment(s string) (string, error) {
	tokens, err := Tokenize(s)
	if err != nil {
		return s, err
	}
	pos := 0
	for _, tok := range tokens {
		for pos < len(s) && s[pos] == ' ' {
			pos++
		}
		if strings.HasPrefix(tok, "#") {
			return s[:pos], nil
		}
		pos += len(tok)
	}
	return s, nil
}

// containsControl reports whether s holds a byte below 0x20 or the byte 0x7f.
// A tab is one, so a tab inside a line excludes the line.
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// isTooLong reports whether err is the length refusal of Tokenize.
func isTooLong(err error) bool {
	return errors.Is(err, ErrTooLong)
}

// words splits a logical line into the words that matter for the compound
// constructs: the separators are spaces, tabs and the shell operators ; & | ( ).
// Quotes are not removed, so a quoted keyword is not a keyword word.
func words(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', ';', '&', '|', '(', ')':
			return true
		}
		return false
	})
}

// keywordDelta returns the number of openers minus the number of closers among
// the words of a line.
func keywordDelta(ws []string) int {
	d := 0
	for _, w := range ws {
		switch {
		case openers[w]:
			d++
		case closers[w]:
			d--
		}
	}
	return d
}

// hasKeyword reports whether a word of the line is an opener or a closer.
func hasKeyword(ws []string) bool {
	for _, w := range ws {
		if openers[w] || closers[w] {
			return true
		}
	}
	return false
}

// heredocOp describes the "<<" of a line.
type heredocOp struct {
	present bool   // the line contains "<<"
	body    bool   // a heredoc with a body (not a here-string "<<<")
	ok      bool   // the delimiter could be read
	delim   string // the delimiter word, quotes removed
	dash    bool   // "<<-": leading tabs of body and delimiter are ignored
}

// parseHeredoc reads the first "<<" of s. A "<<<" is a here-string and has no
// body. For a heredoc it reads the delimiter word: a word in single or double
// quotes, a word after a backslash, or a plain word ending at a space or a
// shell operator.
func parseHeredoc(s string) heredocOp {
	i := strings.Index(s, "<<")
	if i < 0 {
		return heredocOp{}
	}
	op := heredocOp{present: true}
	if i+2 < len(s) && s[i+2] == '<' {
		return op
	}
	op.body = true
	p := i + 2
	if p < len(s) && s[p] == '-' {
		op.dash = true
		p++
	}
	for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
		p++
	}
	if p >= len(s) {
		return op
	}
	switch s[p] {
	case '\'', '"':
		end := strings.IndexByte(s[p+1:], s[p])
		if end < 0 {
			return op
		}
		op.delim = s[p+1 : p+1+end]
	default:
		if s[p] == '\\' {
			p++
		}
		j := p
		for j < len(s) && !strings.ContainsRune(" \t;&|()<>", rune(s[j])) {
			j++
		}
		op.delim = s[p:j]
	}
	op.ok = op.delim != ""
	return op
}

// endsHeredoc reports whether a line ends a heredoc body: it equals the
// delimiter exactly, and with "<<-" it may have leading tabs.
func endsHeredoc(raw string, op heredocOp) bool {
	if op.dash {
		raw = strings.TrimLeft(raw, "\t")
	}
	return raw == op.delim
}

// findHeredocEnd returns the index of the line that ends the heredoc whose
// body starts at from, or -1 when no line ends it.
func findHeredocEnd(lines []logicalLine, from int, op heredocOp) int {
	for m := from; m < len(lines); m++ {
		if endsHeredoc(lines[m].raw, op) {
			return m
		}
	}
	return -1
}

// constructEnd returns the index of the line that closes the compound construct
// whose first line is start, and true. It counts openers and closers over the
// lines and skips the bodies of heredocs. When the construct is not closed, it
// returns the last line of the block and false.
func constructEnd(lines []logicalLine, start int) (int, bool) {
	depth := 0
	for k := start; k < len(lines); k++ {
		depth += keywordDelta(words(lines[k].text))
		if op := parseHeredoc(lines[k].text); op.body {
			if !op.ok {
				return len(lines) - 1, false
			}
			m := findHeredocEnd(lines, k+1, op)
			if m < 0 {
				return len(lines) - 1, false
			}
			k = m
		}
		if depth <= 0 {
			return k, true
		}
	}
	return len(lines) - 1, false
}

// scan walks the logical lines in order and sorts each into a shape or an
// exclusion. The order of the checks matters: a construct consumes its own
// heredocs, and a heredoc consumes its body, so no body line is read as a
// command.
func scan(lines []logicalLine, set *ShapeSet) {
	exclude := func(l logicalLine, reason string) {
		set.Excluded = append(set.Excluded, Excluded{Line: l.line, Text: l.text, Reason: reason})
	}
	last := len(lines) - 1
	for i := 0; i <= last; {
		l := lines[i]
		ws := words(l.text)
		op := parseHeredoc(l.text)
		switch {
		case len(ws) > 0 && openers[ws[0]]:
			end, closed := constructEnd(lines, i)
			reason := "compound construct (" + ws[0] + ")"
			if !closed {
				reason = "unclosed compound construct (" + ws[0] + ")"
			}
			for k := i; k <= end; k++ {
				exclude(lines[k], reason)
			}
			i = end + 1
		case hasKeyword(ws):
			exclude(l, reasonKeywordInLine)
			i++
		case op.present:
			exclude(l, reasonHeredoc)
			if !op.body {
				i++
				continue
			}
			if !op.ok {
				for k := i + 1; k <= last; k++ {
					exclude(lines[k], reasonHeredocNoDelim)
				}
				return
			}
			m := findHeredocEnd(lines, i+1, op)
			if m < 0 {
				for k := i + 1; k <= last; k++ {
					exclude(lines[k], reasonHeredocOpen)
				}
				return
			}
			for k := i + 1; k <= m; k++ {
				exclude(lines[k], reasonHeredocBody)
			}
			i = m + 1
		case l.prob != "":
			exclude(l, l.prob)
			i++
		default:
			set.Shapes = append(set.Shapes, Shape{Line: l.line, Text: l.text})
			i++
		}
	}
}
