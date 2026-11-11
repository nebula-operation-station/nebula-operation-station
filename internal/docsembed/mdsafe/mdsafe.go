// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mdsafe renders a strict Markdown subset to escaped HTML.
//
// Supported: ATX headings (# … ######, each with a slug id), paragraphs,
// bullet and ordered lists (nested by indentation), fenced code blocks,
// pipe tables, inline code, **bold**, *emphasis*, links and backslash
// escapes. Everything else, including raw HTML, HTML comments, images,
// autolinks and entities, is emitted as escaped text.
//
// The output only ever contains the tags h1–h6, p, ul, ol, li, pre,
// code, strong, em, table, thead, tbody, tr, th, td, div (class
// "table-wrap") and a. Attributes are limited to a slug id on headings,
// the fixed class on div, and href (plus a fixed rel) on a. Every text
// byte goes through html.EscapeString.
//
// Links are rendered only when the destination is
//   - an https URL with a host and without user info,
//   - a fragment of the same page ("#slug"), or
//   - a relative path that Options.Relative maps to a local absolute
//     path ("/help/hosts#slug"); the mapped value is checked again.
//
// Any other destination (javascript:, data:, http:, //host, mailto:,
// paths the resolver does not know) renders only the link text.
package mdsafe

import (
	"errors"
	"html"
	"html/template"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits. Inputs beyond MaxSourceBytes are rejected; the others bound
// how far the parser looks, so no input makes it quadratic or deep.
const (
	// MaxSourceBytes is the largest Markdown source Render accepts.
	MaxSourceBytes = 1 << 20
	// MaxNesting bounds list nesting and inline nesting (bold in a
	// link in bold …). Deeper constructs render as text.
	MaxNesting = 8
	// maxInlineScan bounds the search for a closing delimiter (code
	// span, emphasis, link text).
	maxInlineScan = 1024
	// maxLinkDestBytes bounds a link destination.
	maxLinkDestBytes = 2048
	// maxTableColumns bounds the columns of a table.
	maxTableColumns = 32
	// tabWidth is the number of spaces a tab expands to.
	tabWidth = 4
)

var (
	// ErrTooLarge is returned for a source over MaxSourceBytes.
	ErrTooLarge = errors.New("mdsafe: source too large")
	// ErrInvalidUTF8 is returned for a source that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("mdsafe: source is not valid UTF-8")
)

// Options configures Render.
type Options struct {
	// Relative maps a relative link (path without fragment, fragment
	// without "#") to a local absolute href such as "/help/hosts#x".
	// ok false, or a nil Relative, renders the link text only. The
	// result must match a strict local-path form or no link is made.
	Relative func(path, fragment string) (href string, ok bool)
}

// Heading is one heading of a rendered document.
type Heading struct {
	// Level is 1 to 6.
	Level int
	// Text is the heading as plain text (markup removed, not escaped).
	Text string
	// ID is the element id (Slug of the text, made unique).
	ID string
}

// Result is a rendered document.
type Result struct {
	// HTML is the escaped HTML fragment.
	HTML template.HTML
	// Title is the plain text of the first level-1 heading, or "".
	Title string
	// Headings lists every heading in document order.
	Headings []Heading
}

var (
	// relativeDestRE is the only accepted relative destination form.
	relativeDestRE = regexp.MustCompile(`^[A-Za-z0-9._/-]*(#[\pL\pN_-]*)?$`)
	// localHrefRE is the only accepted form of a Relative result.
	localHrefRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]*(#[\pL\pN_-]+)?$`)
	// fragmentRE is the accepted fragment ("#…") of a same-page link.
	fragmentRE = regexp.MustCompile(`^[\pL\pN_-]+$`)
	// tableSepRE matches a table's header separator row.
	tableSepRE = regexp.MustCompile(`^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$`)
	// plainLinkRE strips link syntax for plain text: [text](dest).
	plainLinkRE = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
)

// Render converts src to escaped HTML.
func Render(src []byte, o Options) (Result, error) {
	if len(src) > MaxSourceBytes {
		return Result{}, ErrTooLarge
	}
	if !utf8.Valid(src) {
		return Result{}, ErrInvalidUTF8
	}
	s := strings.NewReplacer("\r\n", "\n", "\r", "\n", "\x00", "�", "\t", strings.Repeat(" ", tabWidth)).Replace(string(src))
	r := &renderer{o: o, ids: map[string]int{}}
	r.blocks(&r.out, strings.Split(s, "\n"), 0, false)
	return Result{
		// The builder only ever received escaped text and the fixed
		// tags written by this package.
		HTML:     template.HTML(r.out.String()),
		Title:    r.title,
		Headings: r.headings,
	}, nil
}

// Slug turns a heading's Markdown text into an element id the way
// GitHub does: markup removed, lower case, only letters, digits, "-"
// and "_" kept, spaces become "-".
func Slug(text string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(plainText(text)) {
		switch {
		case unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_':
			b.WriteRune(c)
		case c == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

// plainText removes inline markup from heading text.
func plainText(s string) string {
	s = plainLinkRE.ReplaceAllString(s, "$1")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && isASCIIPunct(s[i+1]):
			b.WriteByte(s[i+1])
			i++
		case c == '`' || c == '*':
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

type renderer struct {
	o        Options
	out      strings.Builder
	ids      map[string]int
	title    string
	headings []Heading
}

func esc(b *strings.Builder, s string) { b.WriteString(html.EscapeString(s)) }

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

// fenceOf returns the fence run ("```" or "~~~…") a line opens with.
func fenceOf(t string) string {
	for _, c := range []byte{'`', '~'} {
		n := 0
		for n < len(t) && t[n] == c {
			n++
		}
		if n >= 3 {
			return t[:n]
		}
	}
	return ""
}

// headingOf parses an ATX heading line (indent already removed).
func headingOf(t string) (int, string, bool) {
	n := 0
	for n < len(t) && t[n] == '#' {
		n++
	}
	if n == 0 || n > 6 || (n < len(t) && t[n] != ' ') {
		return 0, "", false
	}
	text := strings.TrimSpace(t[n:])
	// Optional closing sequence: "## Title ##".
	if trimmed := strings.TrimRight(text, "#"); trimmed != text && (trimmed == "" || strings.HasSuffix(trimmed, " ")) {
		text = strings.TrimSpace(trimmed)
	}
	return n, text, true
}

// marker is a parsed list item marker.
type marker struct {
	indent     int
	ordered    bool
	contentCol int
	rest       string
}

// listMarker parses a list item line.
func listMarker(line string) (marker, bool) {
	ind := indentOf(line)
	if ind >= 4 {
		return marker{}, false
	}
	t := line[ind:]
	n, ordered := 0, false
	switch {
	case t != "" && (t[0] == '-' || t[0] == '*' || t[0] == '+'):
		n = 1
	default:
		for n < len(t) && n < 9 && t[n] >= '0' && t[n] <= '9' {
			n++
		}
		if n == 0 || n >= len(t) || (t[n] != '.' && t[n] != ')') {
			return marker{}, false
		}
		n++
		ordered = true
	}
	if n < len(t) && t[n] != ' ' {
		return marker{}, false
	}
	rest := t[n:]
	sp := indentOf(rest)
	if sp == 0 && rest != "" {
		return marker{}, false
	}
	if sp > 4 || strings.TrimSpace(rest) == "" {
		sp = 1
	}
	if sp > len(rest) {
		sp = len(rest)
	}
	return marker{indent: ind, ordered: ordered, contentCol: ind + n + sp, rest: rest[sp:]}, true
}

// isTableStart reports whether lines[i] starts a pipe table.
func isTableStart(lines []string, i int) bool {
	return strings.HasPrefix(strings.TrimSpace(lines[i]), "|") && i+1 < len(lines) &&
		strings.Contains(lines[i+1], "-") && tableSepRE.MatchString(lines[i+1])
}

// blocks renders block-level Markdown. tight drops the <p> around
// paragraphs (tight list items).
func (r *renderer) blocks(b *strings.Builder, lines []string, depth int, tight bool) {
	var para []string
	flush := func() {
		if len(para) == 0 {
			return
		}
		if !tight {
			b.WriteString("<p>")
		}
		r.inline(b, strings.Join(para, "\n"), 0, false)
		if !tight {
			b.WriteString("</p>")
		}
		b.WriteByte('\n')
		para = nil
	}
	for i := 0; i < len(lines); {
		line := lines[i]
		if isBlank(line) {
			flush()
			i++
			continue
		}
		ind := indentOf(line)
		t := line[ind:]
		if ind < 4 {
			if fence := fenceOf(t); fence != "" {
				flush()
				i = r.codeBlock(b, lines, i, ind, fence)
				continue
			}
			if level, text, ok := headingOf(t); ok {
				flush()
				r.heading(b, level, text)
				i++
				continue
			}
			if isTableStart(lines, i) {
				flush()
				i = r.table(b, lines, i)
				continue
			}
			if _, ok := listMarker(line); ok && depth < MaxNesting {
				flush()
				i = r.list(b, lines, i, depth)
				continue
			}
		}
		para = append(para, strings.TrimSpace(line))
		i++
	}
	flush()
}

// codeBlock renders a fenced code block starting at lines[i].
func (r *renderer) codeBlock(b *strings.Builder, lines []string, i, ind int, fence string) int {
	b.WriteString("<pre><code>")
	i++
	for ; i < len(lines); i++ {
		line := lines[i]
		t := strings.TrimLeft(line, " ")
		if indentOf(line) < 4 && strings.HasPrefix(t, fence) && strings.Trim(t, fence[:1]+" ") == "" {
			i++
			break
		}
		strip := min(ind, indentOf(line))
		esc(b, line[strip:])
		b.WriteByte('\n')
	}
	b.WriteString("</code></pre>\n")
	return i
}

// heading renders one heading with a unique slug id.
func (r *renderer) heading(b *strings.Builder, level int, text string) {
	id := Slug(text)
	if id == "" {
		id = "section"
	}
	if n, seen := r.ids[id]; seen {
		r.ids[id] = n + 1
		id = id + "-" + itoa(n+1)
	}
	r.ids[id] = 0
	plain := plainText(text)
	r.headings = append(r.headings, Heading{Level: level, Text: plain, ID: id})
	if level == 1 && r.title == "" {
		r.title = plain
	}
	tag := "h" + itoa(level)
	b.WriteString("<" + tag + ` id="`)
	esc(b, id)
	b.WriteString(`">`)
	r.inline(b, text, 0, false)
	b.WriteString("</" + tag + ">\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

// table renders a pipe table starting at lines[i] (header row).
func (r *renderer) table(b *strings.Builder, lines []string, i int) int {
	head := splitRow(lines[i])
	cols := min(len(head), maxTableColumns)
	b.WriteString(`<div class="table-wrap"><table><thead><tr>`)
	for _, c := range head[:cols] {
		b.WriteString("<th>")
		r.inline(b, c, 0, false)
		b.WriteString("</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for i += 2; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|"); i++ {
		cells := splitRow(lines[i])
		b.WriteString("<tr>")
		for c := 0; c < cols; c++ {
			b.WriteString("<td>")
			if c < len(cells) {
				r.inline(b, cells[c], 0, false)
			}
			b.WriteString("</td>")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table></div>\n")
	return i
}

// splitRow splits a table row at "|" outside code spans; "\|" is a
// literal pipe.
func splitRow(line string) []string {
	s := strings.TrimSpace(line)
	s = strings.TrimPrefix(s, "|")
	if strings.HasSuffix(s, "|") && !strings.HasSuffix(s, `\|`) {
		s = s[:len(s)-1]
	}
	var cells []string
	var cur strings.Builder
	inCode := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s) && s[i+1] == '|':
			cur.WriteString(`\|`)
			i++
		case c == '`':
			inCode = !inCode
			cur.WriteByte(c)
		case c == '|' && !inCode:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

// list renders a list starting at lines[i].
func (r *renderer) list(b *strings.Builder, lines []string, i, depth int) int {
	first, _ := listMarker(lines[i])
	tag := "ul"
	if first.ordered {
		tag = "ol"
	}
	b.WriteString("<" + tag + ">\n")
	for i < len(lines) {
		m, ok := listMarker(lines[i])
		if !ok || m.ordered != first.ordered || m.indent >= first.contentCol {
			break
		}
		item := []string{m.rest}
		i++
		for i < len(lines) {
			l := lines[i]
			if isBlank(l) {
				j := i
				for j < len(lines) && isBlank(lines[j]) {
					j++
				}
				if j < len(lines) && indentOf(lines[j]) >= m.contentCol {
					for ; i < j; i++ {
						item = append(item, "")
					}
					continue
				}
				break
			}
			if indentOf(l) >= m.contentCol {
				item = append(item, l[m.contentCol:])
				i++
				continue
			}
			t := strings.TrimSpace(l)
			_, isMarker := listMarker(l)
			_, _, isHeading := headingOf(t)
			if isMarker || isHeading || fenceOf(t) != "" || strings.HasPrefix(t, "|") || isBlank(item[len(item)-1]) {
				break
			}
			// Lazy continuation of the item's paragraph.
			item = append(item, t)
			i++
		}
		tight := true
		for _, l := range item {
			if isBlank(l) {
				tight = false
			}
		}
		var sub strings.Builder
		r.blocks(&sub, item, depth+1, tight)
		b.WriteString("<li>")
		b.WriteString(strings.TrimRight(sub.String(), "\n"))
		b.WriteString("</li>\n")
		// Blank lines between items keep the list going.
		j := i
		for j < len(lines) && isBlank(lines[j]) {
			j++
		}
		if j > i && j < len(lines) {
			if n, ok := listMarker(lines[j]); ok && n.ordered == first.ordered && n.indent < first.contentCol {
				i = j
			}
		}
	}
	b.WriteString("</" + tag + ">\n")
	return i
}

func isASCIIPunct(c byte) bool {
	return c < 0x80 && unicode.IsPunct(rune(c)) || c == '`' || c == '|' || c == '<' || c == '>' || c == '$' || c == '^' || c == '+' || c == '=' || c == '~'
}

// findRun returns the index of the next run of exactly n copies of c in
// s at or after from, within maxInlineScan bytes, or -1.
func findRun(s string, from int, c byte, n int) int {
	limit := min(len(s), from+maxInlineScan)
	for j := from; j < limit; {
		if s[j] != c {
			j++
			continue
		}
		k := j
		for k < len(s) && s[k] == c {
			k++
		}
		if k-j == n {
			return j
		}
		j = k
	}
	return -1
}

// inline renders inline Markdown. inLink suppresses nested links.
func (r *renderer) inline(b *strings.Builder, s string, depth int, inLink bool) {
	var text strings.Builder
	flush := func() {
		esc(b, text.String())
		text.Reset()
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) && isASCIIPunct(s[i+1]):
			text.WriteByte(s[i+1])
			i += 2
		case c == '`':
			n := 0
			for i+n < len(s) && s[i+n] == '`' {
				n++
			}
			end := findRun(s, i+n, '`', n)
			if end < 0 {
				text.WriteString(s[i : i+n])
				i += n
				continue
			}
			code := strings.ReplaceAll(s[i+n:end], "\n", " ")
			if len(code) >= 2 && code[0] == ' ' && code[len(code)-1] == ' ' && strings.Trim(code, " ") != "" {
				code = code[1 : len(code)-1]
			}
			flush()
			b.WriteString("<code>")
			esc(b, code)
			b.WriteString("</code>")
			i = end + n
		case c == '*' && depth < MaxNesting:
			n := 1
			if i+1 < len(s) && s[i+1] == '*' {
				n = 2
			}
			open := i + n
			end := findRun(s, open, '*', n)
			if end <= open || s[open] == ' ' || s[end-1] == ' ' {
				text.WriteString(s[i:open])
				i = open
				continue
			}
			tag := "em"
			if n == 2 {
				tag = "strong"
			}
			flush()
			b.WriteString("<" + tag + ">")
			r.inline(b, s[open:end], depth+1, inLink)
			b.WriteString("</" + tag + ">")
			i = end + n
		case c == '[' && !inLink && depth < MaxNesting:
			label, dest, end, ok := parseLink(s, i)
			if !ok {
				text.WriteByte(c)
				i++
				continue
			}
			flush()
			if href, external, ok := r.resolve(dest); ok {
				b.WriteString(`<a href="`)
				esc(b, href)
				if external {
					b.WriteString(`" rel="noopener noreferrer">`)
				} else {
					b.WriteString(`">`)
				}
				r.inline(b, label, depth+1, true)
				b.WriteString("</a>")
			} else {
				r.inline(b, label, depth+1, true)
			}
			i = end
		default:
			text.WriteByte(c)
			i++
		}
	}
	flush()
}

// parseLink parses "[label](dest)" at s[i]; end is the index after ")".
func parseLink(s string, i int) (label, dest string, end int, ok bool) {
	level := 0
	j := i
	limit := min(len(s), i+maxInlineScan)
	for ; j < limit; j++ {
		switch s[j] {
		case '\\':
			j++
		case '[':
			level++
		case ']':
			level--
		}
		if level == 0 {
			break
		}
	}
	if j >= limit || level != 0 || j+1 >= len(s) || s[j+1] != '(' {
		return "", "", 0, false
	}
	label = s[i+1 : j]
	parens := 0
	limit = min(len(s), j+2+maxLinkDestBytes)
	for k := j + 2; k < limit; k++ {
		switch s[k] {
		case '(':
			parens++
		case ')':
			if parens == 0 {
				dest = strings.TrimSpace(s[j+2 : k])
				// A title ("dest "title"") is dropped.
				if f := strings.Fields(dest); len(f) > 0 {
					dest = f[0]
				}
				return label, dest, k + 1, true
			}
			parens--
		case '\n':
			return "", "", 0, false
		}
	}
	return "", "", 0, false
}

// resolve checks a link destination and returns the href to emit.
func (r *renderer) resolve(dest string) (href string, external, ok bool) {
	if dest == "" || len(dest) > maxLinkDestBytes {
		return "", false, false
	}
	for i := 0; i < len(dest); i++ {
		if c := dest[i]; c <= ' ' || c == 0x7f || strings.IndexByte("\"'<>\\`", c) >= 0 {
			return "", false, false
		}
	}
	if strings.HasPrefix(dest, "https://") {
		u, err := url.Parse(dest)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
			return "", false, false
		}
		return u.String(), true, true
	}
	if !relativeDestRE.MatchString(dest) || strings.HasPrefix(dest, "/") || strings.Contains(dest, "//") {
		return "", false, false
	}
	p, frag, _ := strings.Cut(dest, "#")
	if p == "" {
		if !fragmentRE.MatchString(frag) {
			return "", false, false
		}
		return "#" + frag, false, true
	}
	if r.o.Relative == nil {
		return "", false, false
	}
	h, ok := r.o.Relative(p, frag)
	if !ok || !localHrefRE.MatchString(h) || strings.Contains(h, "//") {
		return "", false, false
	}
	return h, false, true
}
