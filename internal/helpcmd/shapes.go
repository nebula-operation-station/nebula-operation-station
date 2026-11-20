// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"fmt"
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
	reasonAmbiguousJoin   = "continuation inside a comment, quotes or after a backslash"
)

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
	line   int    // 1-based first physical line
	raw    string // continuations joined, common indentation removed; keeps comments
	joined bool   // the logical line holds more than one physical line
	prob   string // reason that excludes the whole logical line (a continuation at the end of the block, or an ambiguous join)
	// segs holds the command segments of an ambiguous join that the shell ends
	// at a line break (a backslash in a comment or after another backslash).
	// raw is kept joined for the exclusion; the tracker reads each segment as a
	// command of its own. nil when there is no such break.
	segs []string
}

// Shapes builds the shapes of one fenced code block (ADR 0014 D4). info is the
// info string of the fence and body the code between the fences, lines joined
// with "\n". Only a block whose info string is exactly empty, "sh", "bash",
// "shell" or "console" gives shapes; any other block gives an empty ShapeSet.
//
// The rules, in order: remove the common indentation; join every line ending in
// a backslash with the next line, the backslash and the line break becoming one
// space. A join that the shell would not read the same way (the backslash is
// inside a comment, inside quotes, or after another backslash) makes the joined
// logical line an exclusion with reasonAmbiguousJoin, so it is never a shape and
// the next command is never dropped; drop blank lines and lines starting with
// "#" outside a construct or heredoc body; remove a trailing comment, that is a
// "#" starting a word outside quotes (the lexer decides quoting). The quote
// check looks at the text before the trailing comment only. A backslash that
// ends a comment, or that follows another backslash outside quotes, joins
// nothing: the shell ends the command at that line break, so the physical line
// is excluded alone with reasonAmbiguousJoin and the next line is read on its own.
//
// A compound keyword (for, while, until, if, case, select) counts only in
// command position: the first word of a line, or a word after one of ; ;; &
// && | || ( ` or after do, then, else, elif, {, ! or time. A quoted word or a
// keyword that is an argument ("echo done", "grep done log") is a plain word.
// Such a keyword opens a construct that runs to its closing word (done for
// for, while, until and select; fi for if; esac for case), nesting counted; a
// opener that is directly followed by ")" is a case pattern only while a case
// is open; otherwise it opens a construct (fail closed). Every line of the
// construct is excluded, with the lines that open and close it on the same
// line counted as one line.
//
// Beyond the keyword list, a "{" in command position opens a brace group (closed
// by "}" in command position), a "(" in command position or right after "$"
// opens a subshell or command substitution (closed by ")" of the same level),
// and such a bracket that stays open at the end of a line makes that line the
// start of a construct, whose lines are all excluded. A bracket opened and
// closed on one line, as in "x=$(date +%F)", leaves the line a shape.
//
// A heredoc ("<<" or "<<-") excludes its line; its body is excluded up to the
// delimiter, which is read per POSIX quote removal ("<<\"E\"OF" has the
// delimiter EOF). Several heredocs on one line take their bodies in order, and
// a "<<<" here-string excludes its line but has no body. A construct or heredoc
// that is not closed excludes everything to the end of the block (fail closed).
//
// A line the rules do not settle is excluded, not guessed: an unbalanced quote
// (every later line of the block is then excluded too, since the quoting state
// is unknown), a delimiter that cannot be read, a tab or other control character
// inside the line, and a continuation at the end of the block. A line longer
// than MaxCommandBytes is excluded and, like an unbalanced quote, ends the
// readable part of the block: its quoting and heredocs are unknown past it.
func Shapes(info, body string) ShapeSet {
	var set ShapeSet
	if !isShellBlock(info) {
		return set
	}
	if len(body) > MaxBlockBytes {
		set.Excluded = append(set.Excluded, Excluded{Line: 1, Text: "", Reason: reasonBlockTooLong})
		return set
	}
	s := scanner{lines: joinContinuations(strings.Split(body, "\n"))}
	s.run()
	set.Shapes = s.shapes
	set.Excluded = s.excl
	return set
}

// isShellBlock reports whether the info string is one of the tags of ADR 0014
// D4, rule 1: exactly empty, sh, bash, shell or console. A second word, as in
// "bash title=x", is not one of them.
func isShellBlock(info string) bool {
	switch strings.TrimSpace(info) {
	case "", "sh", "bash", "shell", "console":
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

// joinContinuations removes the common indentation and joins every physical
// line that continues into the next one (see continues) with that line. The
// backslash and the line break become one space. A continuation that runs to
// the end of the block becomes a line with the reason reasonContinuation, since
// the command is then not known.
func joinContinuations(phys []string) []logicalLine {
	common := commonIndent(phys)
	var out []logicalLine
	var acc, seg strings.Builder // the joined text, and the command segment being read
	var segs []string            // the command segments closed by a line break the shell ends
	start := 0
	open := false
	multi := false
	ambiguous := false
	for n, p := range phys {
		p = strings.TrimPrefix(p, common)
		if !open {
			start = n + 1
			acc.Reset()
			seg.Reset()
			segs = nil
			multi = false
			ambiguous = false
		} else {
			acc.WriteByte(' ')
			seg.WriteByte(' ')
			multi = true
		}
		joins, clean, ends := continuation(p)
		if joins {
			acc.WriteString(p[:len(p)-1])
			open = true
			ambiguous = ambiguous || !clean
			if ends {
				// The shell ends the command at this line break, so the next
				// physical line is a command of its own. The text stays joined
				// for the exclusion; the segments are analyzed apart.
				seg.WriteString(p)
				segs = append(segs, seg.String())
				seg.Reset()
			} else {
				seg.WriteString(p[:len(p)-1])
			}
			continue
		}
		open = false
		acc.WriteString(p)
		seg.WriteString(p)
		l := logicalLine{line: start, raw: acc.String(), joined: multi}
		if ambiguous {
			l.prob = reasonAmbiguousJoin
		}
		if len(segs) > 0 {
			l.segs = append(segs, seg.String())
		}
		out = append(out, l)
	}
	if open {
		out = append(out, logicalLine{line: start, raw: acc.String(), joined: multi, prob: reasonContinuation})
	}
	return out
}

// continuation reports whether the physical line p ends in a backslash, which
// joins it with the next line (ADR 0014 D4, rule 2, read literally). clean is
// true when the shell reads the join the same way: the backslash is not inside a
// comment, not inside quotes and not masked by another backslash. Otherwise the
// joined logical line is excluded (see reasonAmbiguousJoin). ends is true when
// the shell ends the command at the line break instead: the backslash is in a
// comment or masked by another backslash outside quotes. Such a line is not
// joined with the next one; the next physical line is a command of its own.
func continuation(p string) (joins, clean, ends bool) {
	if !strings.HasSuffix(p, "\\") {
		return false, false, false
	}
	var quote byte
	for i := 0; i < len(p); i++ {
		if i == len(p)-1 {
			return true, quote == 0, false
		}
		c := p[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || isBlankOrOperator(p[i-1])):
			// A comment outside quotes: the backslash is part of the comment.
			return true, false, true
		}
	}
	// The loop ended on a masked final backslash: a doubled backslash, which
	// is a literal backslash, ends the command outside quotes. Inside quotes
	// the line break is part of the quoted text.
	return true, false, quote == 0
}

// segmentInfo lexes and checks the command segments of an ambiguous join on
// their own. The shell starts a new command after each line break it ends, so
// a comment or an opener in one segment does not hide the text of the next. The
// quoting of each segment is checked as a single line; joinedLen, the length of
// the whole joined line, is checked against MaxCommandBytes like a single line.
// On an error the returned info is empty.
func segmentInfo(segs []string, joinedLen int) (lineInfo, error) {
	if joinedLen > MaxCommandBytes {
		return lineInfo{}, fmt.Errorf("segments: %w: %d bytes, limit %d", ErrTooLong, joinedLen, MaxCommandBytes)
	}
	var info lineInfo
	for _, sg := range segs {
		sg = strings.TrimLeft(sg, " \t")
		lx := lexLine(sg)
		if _, err := Tokenize(sg[:lx.cut]); err != nil {
			return lineInfo{}, err
		}
		si := analyze(lx.toks)
		info.events = append(info.events, si.events...)
		info.docs = append(info.docs, si.docs...)
	}
	return info, nil
}

// isBlankOrOperator reports whether c ends a word: a space, a tab or one of the
// shell operator bytes.
func isBlankOrOperator(c byte) bool {
	return c == ' ' || c == '\t' || strings.IndexByte(";&|()<>`", c) >= 0
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

// tokKind classifies a token of a shell line.
type tokKind uint8

const (
	tokWord    tokKind = iota // a word, quotes and backslashes kept in text
	tokSep                    // a command separator: ; ;; & && | || ( ) or a backquote
	tokRedir                  // a redirection operator, its target is the next word
	tokHeredoc                // << or <<-, its delimiter is the next word
	tokHereStr                // <<<, a here-string, no body
)

// token is one token of a shell line.
type token struct {
	kind   tokKind
	text   string // the word as written, or the operator
	value  string // a word with quotes and backslashes removed
	quoted bool   // the word holds a quote or a backslash
}

// lexed is a shell line split into tokens. cut is the byte offset where a
// trailing comment starts, or len of the line when there is none.
type lexed struct {
	toks []token
	cut  int
}

// operatorAt returns the operator at the start of s and its kind, or "" when s
// does not start with an operator.
func operatorAt(s string) (string, tokKind) {
	switch {
	case strings.HasPrefix(s, "<<<"):
		return "<<<", tokHereStr
	case strings.HasPrefix(s, "<<-"):
		return "<<-", tokHeredoc
	case strings.HasPrefix(s, "<<"):
		return "<<", tokHeredoc
	case strings.HasPrefix(s, "&&"):
		return "&&", tokSep
	case strings.HasPrefix(s, "||"):
		return "||", tokSep
	case strings.HasPrefix(s, ";;"):
		return ";;", tokSep
	case strings.HasPrefix(s, ">>"), strings.HasPrefix(s, ">&"), strings.HasPrefix(s, ">|"),
		strings.HasPrefix(s, "<&"), strings.HasPrefix(s, "<>"):
		return s[:2], tokRedir
	}
	switch s[0] {
	case ';', '&', '|', '(', ')', '`':
		return s[:1], tokSep
	case '<', '>':
		return s[:1], tokRedir
	}
	return "", 0
}

// lexLine splits s into tokens. Spaces and tabs separate tokens, a "#" that
// starts a token is a comment that ends the line, and quotes and backslashes
// keep the characters they mask inside one word. It does not report errors:
// the caller has checked the quoting with Tokenize. An unclosed quote takes
// the rest of the line.
func lexLine(s string) lexed {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if c == '#' {
			return lexed{toks: toks, cut: i}
		}
		if op, kind := operatorAt(s[i:]); op != "" {
			toks = append(toks, token{kind: kind, text: op})
			i += len(op)
			continue
		}
		w, n := lexWord(s[i:])
		toks = append(toks, w)
		i += n
	}
	return lexed{toks: toks, cut: len(s)}
}

// lexWord reads the word at the start of s, which begins with a character that
// is neither a blank nor an operator, and returns it with its length in bytes.
// Quote removal follows POSIX: single quotes keep everything, double quotes
// keep everything except a backslash before one of "\$` and the quotes of the
// word, and a backslash outside quotes masks the next byte.
func lexWord(s string) (token, int) {
	var val strings.Builder
	quoted := false
	i := 0
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' {
			break
		}
		if op, _ := operatorAt(s[i:]); op != "" {
			break
		}
		switch c {
		case '\'':
			quoted = true
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				val.WriteString(s[i+1:])
				i = len(s)
				continue
			}
			val.WriteString(s[i+1 : i+1+end])
			i += end + 2
		case '"':
			quoted = true
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					val.WriteByte(s[i+1])
					i += 2
					continue
				}
				val.WriteByte(s[i])
				i++
			}
			i++
		case '\\':
			quoted = true
			if i+1 < len(s) {
				val.WriteByte(s[i+1])
			}
			i += 2
		default:
			val.WriteByte(c)
			i++
		}
	}
	if i > len(s) {
		i = len(s)
	}
	return token{kind: tokWord, text: s[:i], value: val.String(), quoted: quoted}, i
}

// kwEvent is a compound keyword in command position of a line.
type kwEvent struct {
	word    string // for, select, case, while, until, if, done, fi, esac, "{", "}", "(" or ")"
	open    bool   // the word opens a construct
	pattern bool   // an opener directly followed by ")": a case pattern while a case is open
}

// heredocOp describes a "<<", "<<-" or "<<<" of a line.
type heredocOp struct {
	body  bool   // a heredoc with a body (false for a here-string)
	ok    bool   // the delimiter could be read
	delim string // the delimiter word, quotes removed
	dash  bool   // "<<-": leading tabs of the body and the delimiter are ignored
}

// lineInfo is what the tokens of one line say about compound constructs and
// heredocs.
type lineInfo struct {
	events []kwEvent
	docs   []heredocOp
}

// closers maps each closing word to the opening words it closes.
var closers = map[string][]string{
	"done": {"for", "while", "until", "select"},
	"fi":   {"if"},
	"esac": {"case"},
	"}":    {"{"},
	")":    {"("},
}

// analyze finds the compound keywords in command position and the heredoc
// operators of a line. The start of a line is a command position, as are the
// words after a separator and after the reserved words that take a command. A
// redirection does not change the command position, and its target word is
// not a keyword.
func analyze(toks []token) lineInfo {
	var info lineInfo
	cmd := true
	for k := 0; k < len(toks); k++ {
		t := toks[k]
		switch t.kind {
		case tokSep:
			switch {
			case t.text == "(" && (cmd || dollarBefore(toks, k)):
				info.events = append(info.events, kwEvent{word: "(", open: true})
			case t.text == ")":
				info.events = append(info.events, kwEvent{word: ")"})
			}
			cmd = true
			continue
		case tokRedir, tokHereStr:
			if k+1 < len(toks) && toks[k+1].kind == tokWord {
				k++
			}
			if t.kind == tokHereStr {
				info.docs = append(info.docs, heredocOp{})
			}
			continue
		case tokHeredoc:
			op := heredocOp{body: true, dash: t.text == "<<-"}
			if k+1 < len(toks) && toks[k+1].kind == tokWord {
				k++
				op.delim = toks[k].value
				op.ok = op.delim != ""
			}
			info.docs = append(info.docs, op)
			continue
		}
		if !cmd || t.quoted {
			cmd = false
			continue
		}
		// A keyword directly followed by ")" is marked as a pattern. The scan
		// reads it as a case pattern only while a case is open.
		paren := k+1 < len(toks) && toks[k+1].kind == tokSep && toks[k+1].text == ")"
		switch t.text {
		case "for", "select", "case":
			info.events = append(info.events, kwEvent{word: t.text, open: true, pattern: paren})
			cmd = false
		case "while", "until", "if":
			info.events = append(info.events, kwEvent{word: t.text, open: true, pattern: paren})
			cmd = true
		case "{":
			info.events = append(info.events, kwEvent{word: "{", open: true})
			cmd = true
		case "}":
			info.events = append(info.events, kwEvent{word: "}"})
			cmd = false
		case "do", "then", "else", "elif", "!", "time":
			cmd = true
		case "done", "fi", "esac":
			info.events = append(info.events, kwEvent{word: t.text})
			cmd = false
		default:
			cmd = false
		}
	}
	return info
}

// dollarBefore reports whether the token before toks[k] is a word that ends in
// "$", so that the "(" at toks[k] is the start of a command substitution or an
// arithmetic expansion, "$(" or "$((".
func dollarBefore(toks []token, k int) bool {
	return k > 0 && toks[k-1].kind == tokWord && strings.HasSuffix(toks[k-1].text, "$")
}

// hasKeyword reports whether events hold a compound keyword (for, while, until,
// select, if, case, done, fi or esac). The brackets "(", ")", "{" and "}" are
// not keywords: a line that opens and closes them is a shape.
func hasKeyword(events []kwEvent) bool {
	for _, ev := range events {
		switch ev.word {
		case "(", ")", "{", "}":
		default:
			return true
		}
	}
	return false
}

// netOpen reports whether the events, applied to a copy of stack, leave a
// construct open at the end of the line.
func netOpen(stack []string, events []kwEvent) bool {
	st := append([]string(nil), stack...)
	for _, ev := range events {
		st = step(st, ev)
	}
	return len(st) > 0
}

// endsHeredoc reports whether the logical line l ends the heredoc of op: it
// equals the delimiter exactly, and with "<<-" it may have leading tabs. A
// line that was joined from several physical lines never ends a heredoc, so a
// backslash in a body fails closed.
func endsHeredoc(l logicalLine, op heredocOp) bool {
	if l.joined {
		return false
	}
	raw := l.raw
	if op.dash {
		raw = strings.TrimLeft(raw, "\t")
	}
	return raw == op.delim
}

// pendingDoc is a heredoc whose body has not ended yet.
type pendingDoc struct {
	op   heredocOp
	body []int // indices into scanner.excl of the body lines read so far
}

// scanner walks the logical lines in order and sorts each into a shape or an
// exclusion. It keeps the open compound constructs and the pending heredocs,
// so a line inside either is never read as a command.
type scanner struct {
	lines  []logicalLine
	excl   []Excluded
	shapes []Shape

	stack      []string // open compound constructs, innermost last
	inGroup    bool     // a construct is open or a line of one has been seen
	groupStart int      // index of the first line of the group
	groupFirst string   // the first opener of the group, "" when none
	groupIdx   []int    // indices into excl of the group's lines; reasons set when it ends

	pend   []pendingDoc
	broken string // reason for every remaining line; "" while the block is readable
}

// run sorts every line of the block.
func (s *scanner) run() {
	for i, l := range s.lines {
		s.line(i, l)
	}
	if s.inGroup {
		s.endGroup(len(s.lines)-1, true)
	}
	for _, p := range s.pend {
		for _, k := range p.body {
			s.excl[k].Reason = reasonHeredocOpen
		}
	}
}

// exclude records an excluded line and returns its index in excl.
func (s *scanner) exclude(l logicalLine, text, reason string) int {
	s.excl = append(s.excl, Excluded{Line: l.line, Text: text, Reason: reason})
	return len(s.excl) - 1
}

// line sorts one logical line.
func (s *scanner) line(i int, l logicalLine) {
	if s.broken != "" {
		s.exclude(l, strings.TrimRight(l.raw, " "), s.broken)
		return
	}
	if len(s.pend) > 0 {
		p := &s.pend[0]
		p.body = append(p.body, s.exclude(l, strings.TrimRight(l.raw, " "), reasonHeredocBody))
		if endsHeredoc(l, p.op) {
			s.pend = s.pend[1:]
		}
		return
	}
	t := strings.TrimLeft(l.raw, " \t")
	if !s.inGroup && l.prob == "" && (t == "" || strings.HasPrefix(t, "#")) {
		return
	}
	// A logical line joined by an ambiguous continuation is excluded from the
	// shapes, but it is still lexed and analyzed: an opener or heredoc it holds
	// must register, or the body lines after it would read as commands. A
	// continuation at the end of the block is not analyzed; nothing follows it.
	analyzable := l.prob == "" || l.prob == reasonAmbiguousJoin
	lx := lexed{cut: len(t)}
	if analyzable && l.segs == nil {
		lx = lexLine(t)
	}
	// Quote balance is checked on every analyzable line. A line longer than
	// MaxCommandBytes makes Tokenize return ErrTooLong before it scans any
	// quote, so its quoting is unknown: the block is broken from that line on
	// (see below), which is what keeps an open quote from running into the
	// following lines.
	var unbalanced, tooLong bool
	var quoteProb string
	var info lineInfo
	if analyzable {
		var err error
		if l.segs != nil {
			info, err = segmentInfo(l.segs, len(t))
		} else {
			_, err = Tokenize(t[:lx.cut])
		}
		if err != nil {
			if isTooLong(err) {
				tooLong = true
				quoteProb = reasonLineTooLong
			} else {
				unbalanced = true
				quoteProb = reasonUnbalancedQuote
			}
		}
	}
	prob := quoteProb
	if l.prob != "" {
		prob = l.prob
	}
	// A logical line with a prob keeps every joined part, comment included,
	// because the comment may hide the text the reader needs to see.
	text := strings.TrimRight(t[:lx.cut], " ")
	if l.prob != "" {
		text = strings.TrimRight(t, " ")
	}
	if prob == "" && containsControl(text) {
		prob = reasonControl
	}
	if analyzable && l.segs == nil && !unbalanced && !tooLong {
		info = analyze(lx.toks)
	}
	if s.inGroup || hasKeyword(info.events) || netOpen(nil, info.events) {
		s.constructLine(i, l, text, info)
	} else {
		s.plainLine(l, text, prob, info.docs)
	}
	switch {
	case unbalanced:
		s.broken = reasonUnbalancedQuote
	case tooLong:
		// The quoting of an over-long line is unknown past its end, so the
		// rest of the block is excluded, as after an unbalanced quote.
		s.broken = reasonLineTooLong
	}
}

// plainLine sorts a line that is outside every construct. A heredoc it opens
// is registered even when the line is excluded for another reason, so its body
// is excluded too.
func (s *scanner) plainLine(l logicalLine, text, prob string, docs []heredocOp) {
	switch {
	case len(docs) > 0:
		reason := reasonHeredoc
		if prob == reasonAmbiguousJoin {
			reason = prob
		}
		s.exclude(l, text, reason)
		s.addDocs(docs)
	case prob != "":
		s.exclude(l, text, prob)
	default:
		s.shapes = append(s.shapes, Shape{Line: l.line, Text: text})
	}
}

// constructLine adds a line of a compound construct to the open group. The
// group's reason is set when the group ends.
func (s *scanner) constructLine(i int, l logicalLine, text string, info lineInfo) {
	if !s.inGroup {
		s.inGroup = true
		s.groupStart = i
		s.groupFirst = ""
	}
	s.groupIdx = append(s.groupIdx, s.exclude(l, text, ""))
	for _, ev := range info.events {
		s.apply(ev)
	}
	s.addDocs(info.docs)
	if len(s.stack) == 0 {
		s.endGroup(i, false)
	}
}

// apply updates the open constructs for one event and records the first opener
// of the group.
func (s *scanner) apply(ev kwEvent) {
	before := len(s.stack)
	s.stack = step(s.stack, ev)
	if ev.open && len(s.stack) > before && s.groupFirst == "" {
		s.groupFirst = ev.word
	}
}

// step returns the open constructs after one event; stack lists them innermost
// last. An opener with the pattern mark is a case pattern while a case is open,
// so it opens nothing. A closer closes the innermost construct only when it
// matches it. A closer that does not match changes nothing, so the construct
// stays open and everything up to its real closer is excluded (fail closed).
func step(stack []string, ev kwEvent) []string {
	if ev.open {
		if ev.pattern && inCase(stack) {
			return stack
		}
		return append(stack, ev.word)
	}
	n := len(stack)
	if n == 0 {
		return stack
	}
	for _, opener := range closers[ev.word] {
		if stack[n-1] == opener {
			return stack[:n-1]
		}
	}
	return stack
}

// inCase reports whether a case construct is open in stack.
func inCase(stack []string) bool {
	for _, w := range stack {
		if w == "case" {
			return true
		}
	}
	return false
}

// constructName is the name of a construct in the exclusion reasons.
func constructName(word string) string {
	switch word {
	case "(":
		return "subshell"
	case "{":
		return "brace group"
	}
	return word
}

// endGroup closes the open group at line i and sets the reason of its lines.
// A group that was not closed says so.
func (s *scanner) endGroup(i int, unclosed bool) {
	reason := reasonKeywordInLine
	switch {
	case unclosed:
		reason = "unclosed compound construct (" + constructName(s.groupFirst) + ")"
	case s.groupFirst != "" && s.groupStart != i:
		reason = "compound construct (" + constructName(s.groupFirst) + ")"
	}
	for _, k := range s.groupIdx {
		s.excl[k].Reason = reason
	}
	s.groupIdx = nil
	s.inGroup = false
	s.groupFirst = ""
	s.stack = nil
}

// addDocs registers the heredocs of a line. A delimiter that cannot be read
// leaves the rest of the block unreadable.
func (s *scanner) addDocs(docs []heredocOp) {
	for _, op := range docs {
		if !op.body {
			continue
		}
		if !op.ok {
			s.broken = reasonHeredocNoDelim
			return
		}
		s.pend = append(s.pend, pendingDoc{op: op})
	}
}
