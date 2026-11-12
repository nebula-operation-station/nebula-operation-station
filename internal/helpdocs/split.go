// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// maxFenceIndent is the most leading spaces a fence or heading may have
// (CommonMark: four or more is an indented code block).
const maxFenceIndent = 3

// fence is one fenced code block, by 0-based line index.
type fence struct {
	open   int    // the opening fence line
	last   int    // the last line that belongs to the block
	closed bool   // false when the file ends before the closing fence
	info   string // text after the opening fence run, trimmed
	marker byte   // '`' or '~'
	run    int    // length of the opening fence run
}

// heading is an ATX heading outside code, by 0-based line index.
type heading struct {
	line  int
	level int
	text  string // heading text as the renderer parses it, before inline markup
}

// splitter holds one source's lines and cuts it into chunks.
type splitter struct {
	src      Source
	lines    []string
	fences   []fence
	fenceIdx []int // per line: index into fences, or -1
	prefix   []int // prefix[i] is the byte count of lines[:i] incl. newlines
	heads    []heading
	hd       []mdsafe.Heading // the renderer's headings, same order as heads
}

func newSplitter(s Source, lines []string, fences []fence, heads []heading, hd []mdsafe.Heading) *splitter {
	sp := &splitter{src: s, lines: lines, fences: fences, heads: heads, hd: hd}
	sp.fenceIdx = make([]int, len(lines))
	for i := range sp.fenceIdx {
		sp.fenceIdx[i] = -1
	}
	for k, f := range fences {
		for i := f.open; i <= f.last; i++ {
			sp.fenceIdx[i] = k
		}
	}
	sp.prefix = make([]int, len(lines)+1)
	for i, l := range lines {
		sp.prefix[i+1] = sp.prefix[i] + len(l) + 1
	}
	return sp
}

// size returns the byte count of lines [a, b).
func (sp *splitter) size(a, b int) int { return sp.prefix[b] - sp.prefix[a] }

func (sp *splitter) blank(i int) bool { return strings.TrimSpace(sp.lines[i]) == "" }

// openFenceAt returns the fence whose opening line is i, or nil.
func (sp *splitter) openFenceAt(i int) *fence {
	if k := sp.fenceIdx[i]; k >= 0 && sp.fences[k].open == i {
		return &sp.fences[k]
	}
	return nil
}

// scanFences finds every fenced code block. An unclosed fence runs to
// the end of the file, as in the renderer.
func scanFences(lines []string) []fence {
	var out []fence
	for i := 0; i < len(lines); i++ {
		marker, run, info, ok := fenceOpen(lines[i])
		if !ok {
			continue
		}
		f := fence{open: i, last: len(lines) - 1, marker: marker, run: run, info: info}
		for j := i + 1; j < len(lines); j++ {
			if fenceClose(lines[j], marker, run) {
				f.last = j
				f.closed = true
				break
			}
		}
		out = append(out, f)
		i = f.last
	}
	return out
}

// fenceOpen parses an opening fence line: three or more "`" or "~".
// It mirrors mdsafe.fenceOf, which accepts a backtick in the info string.
func fenceOpen(line string) (marker byte, run int, info string, ok bool) {
	ind := indentOf(line)
	if ind > maxFenceIndent {
		return 0, 0, "", false
	}
	t := line[ind:]
	if t == "" || (t[0] != '`' && t[0] != '~') {
		return 0, 0, "", false
	}
	marker = t[0]
	for run < len(t) && t[run] == marker {
		run++
	}
	if run < 3 {
		return 0, 0, "", false
	}
	return marker, run, strings.TrimSpace(t[run:]), true
}

// fenceClose reports whether line closes a fence opened with marker and
// run. It mirrors the renderer's codeBlock: the line starts with the
// opening run and holds nothing but marker characters and spaces.
func fenceClose(line string, marker byte, run int) bool {
	ind := indentOf(line)
	if ind > maxFenceIndent {
		return false
	}
	t := line[ind:]
	return strings.HasPrefix(t, strings.Repeat(string(marker), run)) &&
		strings.Trim(t, string(marker)+" ") == ""
}

// findHeadings lists the ATX headings that are not inside a fence.
func findHeadings(lines []string, fences []fence) []heading {
	inFence := make([]bool, len(lines))
	for _, f := range fences {
		for i := f.open; i <= f.last; i++ {
			inFence[i] = true
		}
	}
	var out []heading
	for i, l := range lines {
		if inFence[i] {
			continue
		}
		if lvl, text := parseHeading(l); lvl > 0 {
			out = append(out, heading{line: i, level: lvl, text: text})
		}
	}
	return out
}

// parseHeading returns the ATX level and text of a heading line, or
// level 0. It mirrors mdsafe.headingOf: an optional closing run of "#"
// is dropped.
func parseHeading(line string) (int, string) {
	ind := indentOf(line)
	if ind > maxFenceIndent {
		return 0, ""
	}
	t := line[ind:]
	n := 0
	for n < len(t) && t[n] == '#' {
		n++
	}
	if n == 0 || n > 6 || (n < len(t) && t[n] != ' ' && t[n] != '\t') {
		return 0, ""
	}
	text := strings.TrimSpace(t[n:])
	if trimmed := strings.TrimRight(text, "#"); trimmed != text && (trimmed == "" || strings.HasSuffix(trimmed, " ")) {
		text = strings.TrimSpace(trimmed)
	}
	return n, text
}

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// run cuts the source into chunks. The preamble before the first H2 is
// one section anchored at the H1; each H2 is a section; a section above
// MaxChunkBytes is cut at its H3 headings, and a piece still above it
// is cut into paragraph parts.
func (sp *splitter) run() ([]Chunk, error) {
	h1 := -1
	var h2 []int
	for k, h := range sp.heads {
		switch h.level {
		case 1:
			if h1 < 0 {
				h1 = k
			}
		case 2:
			h2 = append(h2, k)
		}
	}
	var out []Chunk
	first := len(sp.lines)
	if len(h2) > 0 {
		first = sp.heads[h2[0]].line
	}
	// The preamble before the first H2 is anchored at the H1, so text
	// above that H1 (or any text when there is no H1 before the first
	// H2) has no anchor to be cited by.
	if h1 >= 0 && sp.heads[h1].line < first {
		if sp.hasText(0, sp.heads[h1].line) {
			return nil, fmt.Errorf("text before the first H1: %w", ErrNoAnchor)
		}
		out = append(out, sp.emit(0, first, sp.hd[h1].ID, sp.path(-1, h1))...)
	} else if sp.hasText(0, first) {
		return nil, fmt.Errorf("text before the first H1: %w", ErrNoAnchor)
	}
	for n, k := range h2 {
		start := sp.heads[k].line
		end := len(sp.lines)
		if n+1 < len(h2) {
			end = sp.heads[h2[n+1]].line
		}
		out = append(out, sp.section(h1, k, start, end)...)
	}
	return out, nil
}

// section chunks one H2 section [start, end), headed by heads[k].
func (sp *splitter) section(h1, k, start, end int) []Chunk {
	anchor := sp.hd[k].ID
	if sp.size(start, end) <= MaxChunkBytes {
		return []Chunk{sp.chunk(start, end, anchor, sp.path(h1, k))}
	}
	var out []Chunk
	cur, curAnchor, curPath := start, anchor, sp.path(h1, k)
	for j := k + 1; j < len(sp.heads) && sp.heads[j].line < end; j++ {
		if sp.heads[j].level != 3 {
			continue
		}
		out = append(out, sp.emit(cur, sp.heads[j].line, curAnchor, curPath)...)
		cur, curAnchor, curPath = sp.heads[j].line, sp.hd[j].ID, sp.path(h1, k, j)
	}
	return append(out, sp.emit(cur, end, curAnchor, curPath)...)
}

// emit returns the chunks for the piece [start, end): one chunk when it
// fits, otherwise paragraph parts "anchor#pN" (or one chunk with the
// plain anchor when packing leaves a single part).
func (sp *splitter) emit(start, end int, anchor string, path []string) []Chunk {
	if sp.size(start, end) <= MaxChunkBytes {
		return []Chunk{sp.chunk(start, end, anchor, path)}
	}
	parts := packUnits(sp.units(start, end), sp.size)
	if len(parts) == 1 {
		return []Chunk{sp.chunk(parts[0][0], parts[0][1], anchor, path)}
	}
	out := make([]Chunk, 0, len(parts))
	for i, p := range parts {
		out = append(out, sp.chunk(p[0], p[1], fmt.Sprintf("%s#p%d", anchor, i+1), path))
	}
	return out
}

// units splits [start, end) into pieces that may be cut between: a
// fenced code block is one unit, a paragraph is one unit (split line by
// line when it is itself above MaxChunkBytes), and blank lines stick to
// the unit before them. Every line is in exactly one unit.
func (sp *splitter) units(start, end int) [][2]int {
	var out [][2]int
	for i := start; i < end; {
		if f := sp.openFenceAt(i); f != nil {
			out = append(out, [2]int{i, f.last + 1})
			i = f.last + 1
			continue
		}
		if sp.blank(i) {
			j := i
			for j < end && sp.blank(j) {
				j++
			}
			if len(out) > 0 && out[len(out)-1][1] == i {
				out[len(out)-1][1] = j
			} else {
				out = append(out, [2]int{i, j})
			}
			i = j
			continue
		}
		j := i
		for j < end && !sp.blank(j) && sp.openFenceAt(j) == nil {
			j++
		}
		if sp.size(i, j) > MaxChunkBytes {
			for k := i; k < j; k++ {
				out = append(out, [2]int{k, k + 1})
			}
		} else {
			out = append(out, [2]int{i, j})
		}
		i = j
	}
	return out
}

// packUnits groups contiguous units into parts of at most
// MaxChunkBytes. A unit that is alone above the limit is its own part.
func packUnits(units [][2]int, size func(a, b int) int) [][2]int {
	if len(units) == 0 {
		return nil
	}
	var parts [][2]int
	cs, ce := units[0][0], units[0][1]
	cur := size(cs, ce)
	for _, u := range units[1:] {
		us := size(u[0], u[1])
		if cur+us > MaxChunkBytes {
			parts = append(parts, [2]int{cs, ce})
			cs, cur = u[0], 0
		}
		ce = u[1]
		cur += us
	}
	return append(parts, [2]int{cs, ce})
}

// hasText reports whether lines [a, b) contain anything but blanks.
func (sp *splitter) hasText(a, b int) bool {
	for i := a; i < b; i++ {
		if !sp.blank(i) {
			return true
		}
	}
	return false
}

// path returns the heading path of the heads ks (indexes into heads),
// prefixed by the H1 text h1 when h1 is an earlier heading. Pass -1
// for h1 to leave the prefix out.
func (sp *splitter) path(h1 int, ks ...int) []string {
	var p []string
	if h1 >= 0 && h1 < ks[0] {
		p = append(p, sp.hd[h1].Text)
	}
	for _, k := range ks {
		p = append(p, sp.hd[k].Text)
	}
	return p
}

// chunk builds the chunk for lines [start, end) with the given anchor.
// The fences are sorted by opening line, so the chunk's own fences are
// found by binary search rather than by scanning every fence.
func (sp *splitter) chunk(start, end int, anchor string, path []string) Chunk {
	c := Chunk{
		ID:        sp.src.Slug + "#" + anchor,
		Slug:      sp.src.Slug,
		File:      sp.src.File,
		Anchor:    anchor,
		Path:      slices.Clone(path),
		StartLine: start + 1,
		EndLine:   end,
		Text:      strings.Join(sp.lines[start:end], "\n"),
	}
	first := sort.Search(len(sp.fences), func(k int) bool { return sp.fences[k].open >= start })
	for k := first; k < len(sp.fences) && sp.fences[k].open < end; k++ {
		c.Code = append(c.Code, sp.codeBlock(sp.fences[k]))
	}
	return c
}

// codeBlock returns the code block for a fence.
func (sp *splitter) codeBlock(f fence) CodeBlock {
	bodyEnd := f.last
	if !f.closed {
		bodyEnd = len(sp.lines)
	}
	cb := CodeBlock{
		Info:      f.info,
		StartLine: f.open + 1,
		EndLine:   f.last + 1,
		Body:      strings.Join(sp.lines[f.open+1:bodyEnd], "\n"),
	}
	if fields := strings.Fields(f.info); len(fields) > 0 {
		cb.Lang = fields[0]
	}
	return cb
}
