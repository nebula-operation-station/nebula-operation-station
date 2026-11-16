// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"fmt"
	"html"
	"strings"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// Markers that delimit one code block in the renderer's output. The
// renderer escapes all text, so these tags occur only as block markup.
const (
	preOpen  = "<pre><code>"
	preClose = "</code></pre>"
)

// checkOutline verifies that this package and the renderer agree on the
// document's block structure: the same headings in the same order, with
// the same level and text, and the same code blocks in the same order
// with the same bodies. Any disagreement returns ErrOutlineMismatch, so
// the index never picks an anchor or a code block boundary that differs
// from the /help page. Every H1 to H3 heading used as an anchor must
// also have a non-empty slug.
//
// Code bodies are compared without whitespace: the renderer strips
// indentation and expands tabs, and neither changes which lines are
// code. Heading text is compared through mdsafe.Slug, the function that
// derives the anchor.
func checkOutline(lines []string, fences []fence, heads []heading, r mdsafe.Result) error {
	if len(heads) != len(r.Headings) {
		return fmt.Errorf("%d headings, renderer found %d: %w", len(heads), len(r.Headings), ErrOutlineMismatch)
	}
	for i, h := range heads {
		rh := r.Headings[i]
		if h.level != rh.Level {
			return fmt.Errorf("heading %d at line %d: level %d, renderer %d: %w", i, h.line+1, h.level, rh.Level, ErrOutlineMismatch)
		}
		if mdsafe.Slug(h.text) != mdsafe.Slug(rh.Text) {
			return fmt.Errorf("heading %d at line %d: text %q, renderer %q: %w", i, h.line+1, h.text, rh.Text, ErrOutlineMismatch)
		}
		if h.level <= 3 && mdsafe.Slug(rh.Text) == "" {
			return fmt.Errorf("heading %q at line %d: %w", rh.Text, h.line+1, ErrNoAnchor)
		}
	}
	bodies, ok := renderedCodeBodies(string(r.HTML))
	if !ok {
		return fmt.Errorf("renderer output has an unterminated code block: %w", ErrOutlineMismatch)
	}
	if len(bodies) != len(fences) {
		return fmt.Errorf("%d code blocks, renderer found %d: %w", len(fences), len(bodies), ErrOutlineMismatch)
	}
	for k, f := range fences {
		if squeeze(fenceBody(lines, f)) != bodies[k] {
			return fmt.Errorf("code block at line %d: body differs from renderer: %w", f.open+1, ErrOutlineMismatch)
		}
	}
	return nil
}

// renderedCodeBodies returns the squeezed body of every code block in
// the renderer's HTML, in document order. ok is false when a block is
// not closed.
func renderedCodeBodies(out string) (bodies []string, ok bool) {
	for {
		i := strings.Index(out, preOpen)
		if i < 0 {
			return bodies, true
		}
		out = out[i+len(preOpen):]
		j := strings.Index(out, preClose)
		if j < 0 {
			return nil, false
		}
		bodies = append(bodies, squeeze(html.UnescapeString(out[:j])))
		out = out[j+len(preClose):]
	}
}

// fenceBody returns the lines between a fence's delimiters, joined. An
// unclosed fence runs to the end of the file.
func fenceBody(lines []string, f fence) string {
	end := f.last
	if !f.closed {
		end = len(lines)
	}
	return strings.Join(lines[f.open+1:end], "\n")
}

// squeeze drops all whitespace and maps NUL to U+FFFD, the one
// character the renderer rewrites, so that two bodies compare equal
// when they hold the same non-blank text.
func squeeze(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == 0:
			return unicode.ReplacementChar
		case unicode.IsSpace(r):
			return -1
		}
		return r
	}, s)
}
