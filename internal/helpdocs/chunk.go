// SPDX-License-Identifier: AGPL-3.0-or-later

// Package helpdocs builds a deterministic chunk index over the embedded
// operator documentation for the in-app help assistant (ADR 0014 D2).
//
// It is a plain library: no LLM, no network, no file access at run
// time. The index is built in memory from the Markdown sources. Each
// chunk is keyed by the same heading anchor the rendered /help page
// uses (internal/docsembed/mdsafe), so a citation can link to it.
// The same input always yields the same index, byte for byte.
package helpdocs

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// MaxChunkBytes is the size limit of one chunk's text. An H2 section
// above it is split at its H3 headings; a piece still above it is split
// at paragraph boundaries into parts "anchor#p1", "anchor#p2", …. A
// fenced code block is never split, so a chunk may exceed the limit by
// one code block or by one overlong prose line.
const MaxChunkBytes = 6 << 10

// Sentinel errors. Callers branch on them with errors.Is.
var (
	// ErrSourceTooLarge is returned for a source over mdsafe.MaxSourceBytes.
	ErrSourceTooLarge = errors.New("helpdocs: source too large")
	// ErrInvalidUTF8 is returned for a source that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("helpdocs: source is not valid UTF-8")
	// ErrInvalidSlug is returned for a source slug that is not a page slug.
	ErrInvalidSlug = errors.New("helpdocs: invalid source slug")
	// ErrDuplicateSource is returned when two sources share a slug.
	ErrDuplicateSource = errors.New("helpdocs: duplicate source slug")
	// ErrNoAnchor is returned when a section that needs an anchor has
	// no derivable one (for example "## !!!"), or text lies before any
	// H1 and so has no anchor to be cited by.
	ErrNoAnchor = errors.New("helpdocs: section has no anchor")
	// ErrDuplicateAnchor is returned when two chunks share an ID.
	ErrDuplicateAnchor = errors.New("helpdocs: duplicate chunk anchor")
	// ErrOutlineMismatch is returned when this package and the renderer
	// disagree about which lines are headings. The index refuses to
	// build rather than pick anchors that do not match the /help page.
	ErrOutlineMismatch = errors.New("helpdocs: heading outline differs from the renderer")
)

// Source is one Markdown document to index.
type Source struct {
	// Slug is the page slug ("faq"); it becomes the ID prefix.
	Slug string
	// File is the file name, for error messages and citations.
	File string
	// Data is the Markdown source.
	Data []byte
}

// CodeBlock is one fenced code block inside a chunk.
type CodeBlock struct {
	// Info is the info string after the opening fence, trimmed.
	Info string
	// Lang is the first word of Info, or "" when there is none.
	Lang string
	// StartLine is the 1-based line of the opening fence in the source.
	StartLine int
	// EndLine is the 1-based line of the closing fence, or the last
	// line of the source when the fence is never closed.
	EndLine int
	// Body is the code between the fences, lines joined with "\n".
	Body string
}

// Chunk is one citable piece of a document.
type Chunk struct {
	// ID is Slug + "#" + Anchor and is unique in the index.
	ID string
	// Slug is the page slug of the source.
	Slug string
	// File is the source file name.
	File string
	// Anchor is the heading anchor as the /help page renders it, or
	// that anchor plus "#pN" for a numbered part of a long section.
	Anchor string
	// Path is the heading path (H1, H2, and H3 where the chunk comes
	// from an H3 piece), so the chunk stands alone.
	Path []string
	// StartLine and EndLine are the 1-based first and last lines of
	// the chunk in the source.
	StartLine int
	EndLine   int
	// Text is the chunk's Markdown source.
	Text string
	// Code holds the fenced code blocks that start inside the chunk.
	// A code block is never split between two chunks.
	Code []CodeBlock
}

// Index is the chunk index over a set of sources, in source order and
// then in document order.
type Index struct {
	Chunks []Chunk
}

// Lookup returns the chunk with the given ID.
func (ix *Index) Lookup(id string) (Chunk, bool) {
	for _, c := range ix.Chunks {
		if c.ID == id {
			return c, true
		}
	}
	return Chunk{}, false
}

// FromDocsembed indexes the embedded operator handbook (docs/handbook,
// FAQ included) as embedded by internal/docsembed.
//
// The admin guide (docs/admin/guide.md) is not part of the embedding
// yet; it has to be added to internal/docsembed before it can be indexed.
func FromDocsembed() (*Index, error) {
	pages, err := docsembed.Pages()
	if err != nil {
		return nil, fmt.Errorf("helpdocs: load handbook: %w", err)
	}
	srcs := make([]Source, 0, len(pages))
	for _, p := range pages {
		srcs = append(srcs, Source{Slug: p.Slug, File: p.File, Data: p.Source})
	}
	return Build(srcs)
}

// Build indexes the sources. The result does not depend on the order
// of sources: they are sorted by slug first. Build fails on a source
// that cannot be split with a valid anchor for every chunk.
func Build(sources []Source) (*Index, error) {
	srcs := slices.Clone(sources)
	slices.SortFunc(srcs, func(a, b Source) int { return strings.Compare(a.Slug, b.Slug) })
	ix := &Index{}
	for i, s := range srcs {
		if i > 0 && srcs[i-1].Slug == s.Slug {
			return nil, fmt.Errorf("source %s: %w", s.File, ErrDuplicateSource)
		}
		chunks, err := splitSource(s)
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.File, err)
		}
		ix.Chunks = append(ix.Chunks, chunks...)
	}
	if err := checkUnique(ix.Chunks); err != nil {
		return nil, err
	}
	return ix, nil
}

// checkUnique rejects a chunk without an anchor or a shared ID.
func checkUnique(chunks []Chunk) error {
	seen := make(map[string]struct{}, len(chunks))
	for _, c := range chunks {
		if c.Anchor == "" {
			return fmt.Errorf("chunk %q: %w", c.ID, ErrNoAnchor)
		}
		if _, dup := seen[c.ID]; dup {
			return fmt.Errorf("chunk %q: %w", c.ID, ErrDuplicateAnchor)
		}
		seen[c.ID] = struct{}{}
	}
	return nil
}

// splitSource validates one source and returns its chunks in order.
func splitSource(s Source) ([]Chunk, error) {
	if !docsembed.ValidSlug(s.Slug) {
		return nil, fmt.Errorf("slug %q: %w", s.Slug, ErrInvalidSlug)
	}
	if len(s.Data) > mdsafe.MaxSourceBytes {
		return nil, ErrSourceTooLarge
	}
	if !utf8.Valid(s.Data) {
		return nil, ErrInvalidUTF8
	}
	rendered, err := mdsafe.Render(s.Data, mdsafe.Options{})
	if err != nil {
		return nil, fmt.Errorf("render outline: %w", err)
	}
	// A final newline ends the last line; it does not start an empty one.
	text := strings.TrimSuffix(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(string(s.Data)), "\n")
	lines := strings.Split(text, "\n")
	fences := scanFences(lines)
	heads := findHeadings(lines, fences)
	if err := checkOutline(heads, rendered.Headings); err != nil {
		return nil, fmt.Errorf("source %s: %w", s.File, err)
	}
	sp := newSplitter(s, lines, fences, heads, rendered.Headings)
	return sp.run()
}

// checkOutline verifies that the headings this package found are the
// headings the renderer found, in the same order and with the same
// levels. Every H1 to H3 heading used as an anchor must also have a
// non-empty slug.
func checkOutline(heads []heading, rendered []mdsafe.Heading) error {
	if len(heads) != len(rendered) {
		return fmt.Errorf("%d headings, renderer found %d: %w", len(heads), len(rendered), ErrOutlineMismatch)
	}
	for i, h := range heads {
		if h.level != rendered[i].Level {
			return fmt.Errorf("heading %d at line %d: level %d, renderer %d: %w", i, h.line+1, h.level, rendered[i].Level, ErrOutlineMismatch)
		}
		if h.level <= 3 && mdsafe.Slug(rendered[i].Text) == "" {
			return fmt.Errorf("heading %q at line %d: %w", rendered[i].Text, h.line+1, ErrNoAnchor)
		}
	}
	return nil
}
