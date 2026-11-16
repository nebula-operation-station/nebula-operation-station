// SPDX-License-Identifier: AGPL-3.0-or-later

// Package helpsearch ranks help-documentation chunks for a question
// (ADR 0014 D2, AS-04). It is a deterministic lexical retriever over
// the helpdocs index: BM25F over two fields (heading path and body),
// German and English normalisation, and a small reviewed synonym table
// for German questions against the English corpus. Standard library
// only; no model, no network, no file access.
package helpsearch

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
)

// Limits (ADR 0014 D2).
const (
	// TopK is the most chunks a search returns.
	TopK = 6
	// MaxContextDocBytes caps the summed Text bytes of the returned
	// chunks. The result is a prefix of the ranking: the search stops
	// at the first chunk that would cross the cap.
	MaxContextDocBytes = 24 << 10
	// MaxQueryBytes is the longest accepted question.
	MaxQueryBytes = 512
	// MaxQueryTokens is the most tokens (before stop-word removal) an
	// accepted question may have.
	MaxQueryTokens = 32
)

// BM25F parameters (Robertson/Zaragoza "simple BM25F"): per term, the
// occurrences in each field are weighted and length-normalised per
// field, summed, and only then saturated once with k1.
//
// They were chosen on the golden query set in golden_test.go (the two
// AS-04 questions plus twelve handbook questions in German and
// English) as the centre of the region where all of them pass, not at
// its edge: every golden query also passes with any single parameter
// moved to its neighbour values (TestGoldenStableAroundParameters).
// The sweep that found the region: k1 3–5, titleWeight 5–8, titleB
// 0.3–0.75, pathWeight 0.5–2 and bodyB 0.6–0.8 all pass.
const (
	// k1 is the saturation of the weighted term frequency. It is
	// higher than the BM25 textbook 1.2 because the field weights
	// inflate the pseudo frequency: one title hit alone is already
	// 6. With k1 = 1.2 that single hit reaches 83 % of the term's
	// maximum, so the body and the parent headings could hardly add
	// evidence; with k1 = 4 it reaches 60 %, and a section that is
	// about the term in its title, its parent heading and its body
	// still ranks above one that only names it in the title.
	k1 = 4.0
	// titleWeight multiplies an occurrence in the chunk's own heading.
	// The heading names what the section is about; a body mention may
	// be a side remark, a cross reference or a "see also".
	titleWeight = 6.0
	// pathWeight multiplies an occurrence in the parent headings (H1,
	// and H2 for an H3 piece). They give context ("7. Adding and
	// enrolling hosts" above "7.1 The enrollment script") but are
	// shared by all their sections, so they count like the body.
	pathWeight = 1.0
	// bodyWeight multiplies an occurrence in the body.
	bodyWeight = 1.0
	// titleB is the length normalisation of the title: a short title
	// is more about each of its words than a long one, but titles are
	// all short, so only half of the length effect applies.
	titleB = 0.5
	// pathB is the length normalisation of the parent headings. Their
	// length says how deep a section sits (an admin guide H3 carries a
	// long H1 and an H2), not how focused it is, so it barely counts.
	pathB = 0.3
	// bodyB is the length normalisation of the body, the usual BM25
	// 0.75: a long body mentioning a word once is less about it than a
	// short one. The heading path is not part of the body length.
	bodyB = 0.75
)

// Sentinel errors. Callers branch on them with errors.Is.
var (
	// ErrEmptyQuery is returned for a question without a usable term.
	ErrEmptyQuery = errors.New("helpsearch: empty query")
	// ErrQueryTooLarge is returned for a question over MaxQueryBytes
	// or MaxQueryTokens.
	ErrQueryTooLarge = errors.New("helpsearch: query too large")
	// ErrInvalidQuery is returned for a question that is not UTF-8.
	ErrInvalidQuery = errors.New("helpsearch: query is not valid UTF-8")
)

// field indexes.
const (
	// fieldTitle is the chunk's own heading (last element of Path).
	fieldTitle = iota
	// fieldPath is the parent headings (H1, and H2 for an H3 piece).
	fieldPath
	// fieldBody is the chunk text without its own heading line.
	fieldBody
	numFields
)

// params are the scoring parameters of an Index.
type params struct {
	k1     float64
	weight [numFields]float64
	b      [numFields]float64
}

// defaultParams are the documented constants above.
var defaultParams = params{
	k1:     k1,
	weight: [numFields]float64{titleWeight, pathWeight, bodyWeight},
	b:      [numFields]float64{titleB, pathB, bodyB},
}

// doc is one indexed chunk.
type doc struct {
	chunk helpdocs.Chunk
	tf    [numFields]map[string]int
	len   [numFields]int
}

// Index is a search index over a helpdocs index. It is read-only after
// New and safe for concurrent use.
type Index struct {
	docs   []doc
	df     map[string]int
	avgLen [numFields]float64
	p      params
}

// Hit is one ranked chunk.
type Hit struct {
	Chunk helpdocs.Chunk
	Score float64
}

// New indexes the chunks of ix. A nil index gives an empty Index.
func New(ix *helpdocs.Index) *Index {
	return newWithParams(ix, defaultParams)
}

// newWithParams is New with explicit scoring parameters (tests).
func newWithParams(ix *helpdocs.Index, p params) *Index {
	s := &Index{df: map[string]int{}, p: p}
	if ix == nil {
		return s
	}
	var total [numFields]int
	for _, c := range ix.Chunks {
		d := doc{chunk: c}
		seen := map[string]struct{}{}
		for f, ts := range fields(c) {
			d.tf[f] = make(map[string]int, len(ts))
			for _, t := range ts {
				d.tf[f][t]++
				seen[t] = struct{}{}
			}
			d.len[f] = len(ts)
			total[f] += len(ts)
		}
		for t := range seen {
			s.df[t]++
		}
		s.docs = append(s.docs, d)
	}
	for f := range numFields {
		if len(s.docs) > 0 {
			s.avgLen[f] = float64(total[f]) / float64(len(s.docs))
		}
	}
	return s
}

// fields returns the title, parent-path and body terms of a chunk.
// The chunk's own heading line opens its Text (except for a later
// paragraph part) and is also the last element of Path; it is counted
// in the title only, so the heading path does not lengthen the body.
func fields(c helpdocs.Chunk) [numFields][]string {
	var f [numFields][]string
	if n := len(c.Path); n > 0 {
		f[fieldTitle] = terms(c.Path[n-1])
		f[fieldPath] = terms(strings.Join(c.Path[:n-1], "\n"))
	}
	text := c.Text
	if first, rest, _ := strings.Cut(text, "\n"); atxHeading(first) {
		text = rest
	}
	f[fieldBody] = terms(text)
	return f
}

// atxHeading reports whether line is a Markdown ATX heading: up to
// three spaces, one to six '#', then a space, a tab or the line end.
// A line such as "#hashtag" or "#!/bin/sh" is not a heading.
func atxHeading(line string) bool {
	s := strings.TrimLeft(line, " ")
	if len(line)-len(s) > 3 {
		return false
	}
	n := len(s) - len(strings.TrimLeft(s, "#"))
	if n < 1 || n > 6 {
		return false
	}
	return n == len(s) || s[n] == ' ' || s[n] == '\t'
}

// Search ranks the chunks for question q. It returns at most TopK hits
// whose Text adds up to at most MaxContextDocBytes, best first; equal
// scores are ordered by chunk ID. Chunks matching no query term are
// not returned.
func (s *Index) Search(q string) ([]Hit, error) {
	qt, err := queryTerms(q)
	if err != nil {
		return nil, err
	}
	n := float64(len(s.docs))
	hits := make([]Hit, 0, len(s.docs))
	for i := range s.docs {
		d := &s.docs[i]
		score := 0.0
		for _, t := range qt {
			df := s.df[t]
			if df == 0 {
				continue
			}
			w := 0.0
			for f := range numFields {
				tf := d.tf[f][t]
				if tf == 0 {
					continue
				}
				norm := 1 - s.p.b[f]
				if s.avgLen[f] > 0 {
					norm += s.p.b[f] * float64(d.len[f]) / s.avgLen[f]
				}
				w += s.p.weight[f] * float64(tf) / norm
			}
			if w == 0 {
				continue
			}
			idf := math.Log(1 + (n-float64(df)+0.5)/(float64(df)+0.5))
			score += idf * w / (s.p.k1 + w)
		}
		if score > 0 {
			hits = append(hits, Hit{Chunk: d.chunk, Score: score})
		}
	}
	slices.SortStableFunc(hits, func(a, b Hit) int {
		if a.Score != b.Score {
			if a.Score > b.Score {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Chunk.ID, b.Chunk.ID)
	})
	return limit(hits), nil
}

// limit applies TopK and MaxContextDocBytes.
func limit(hits []Hit) []Hit {
	out := make([]Hit, 0, TopK)
	size := 0
	for _, h := range hits {
		if len(out) == TopK || size+len(h.Chunk.Text) > MaxContextDocBytes {
			break
		}
		size += len(h.Chunk.Text)
		out = append(out, h)
	}
	return out
}

// queryTerms validates q and returns its distinct terms, with synonyms
// and the parts of joined tokens added, in sorted order (so the float
// sum never depends on map order). Each distinct term counts once.
func queryTerms(q string) ([]string, error) {
	if len(q) > MaxQueryBytes {
		return nil, fmt.Errorf("query of %d bytes, limit %d: %w", len(q), MaxQueryBytes, ErrQueryTooLarge)
	}
	if !utf8.ValidString(q) {
		return nil, ErrInvalidQuery
	}
	raw := rawTokens(q)
	if len(raw) > MaxQueryTokens {
		return nil, fmt.Errorf("query of %d tokens, limit %d: %w", len(raw), MaxQueryTokens, ErrQueryTooLarge)
	}
	set := map[string]struct{}{}
	for _, t := range raw {
		for _, extra := range expand(t) {
			for _, e := range terms(extra) {
				set[e] = struct{}{}
			}
		}
		for _, e := range tokenTerms(t) {
			set[e] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil, ErrEmptyQuery
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	slices.Sort(out)
	return out, nil
}

// synonymIndex maps a From word to its row's To terms.
var synonymIndex = func() map[string][]string {
	m := map[string][]string{}
	for _, row := range synonyms {
		for _, f := range row.From {
			m[f] = append(m[f], row.To...)
		}
	}
	return m
}()

// expand returns the synonym terms for one raw question token, looked
// up as written and folded.
func expand(t string) []string {
	out := synonymIndex[t]
	if ft := fold(t); ft != t {
		out = append(slices.Clone(out), synonymIndex[ft]...)
	}
	return out
}
