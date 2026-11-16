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
	"net/netip"
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
// 0.3–0.75, pathWeight 0.5–2 and bodyB 0.6–0.8 all pass. This is no
// held-out evaluation: the set is small and was seen while tuning. The
// six set-up questions (setupGolden) were added afterwards as a drift
// check and pass in the same neighbourhood, synWeight 0.35–0.7
// included.
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
	// synWeight scales one synonym group (all targets added for one
	// question token, scored as a single pseudo term). Below 1 so a
	// word the user wrote counts more than vocabulary added for it: an
	// English question is not pulled off topic by its own expansions,
	// and in a mixed question the matching own word dominates. A German
	// question whose words only match through synonyms is scaled
	// uniformly, so its ranking does not change.
	synWeight = 0.5
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
	k1        float64
	weight    [numFields]float64
	b         [numFields]float64
	synWeight float64
}

// defaultParams are the documented constants above.
var defaultParams = params{
	k1:        k1,
	weight:    [numFields]float64{titleWeight, pathWeight, bodyWeight},
	b:         [numFields]float64{titleB, pathB, bodyB},
	synWeight: synWeight,
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
	qr, err := parseQuery(q)
	if err != nil {
		return nil, err
	}
	gw := make([]float64, len(qr.groups))
	for i, g := range qr.groups {
		gw[i] = s.groupWeight(g)
	}
	hits := make([]Hit, 0, len(s.docs))
	for i := range s.docs {
		d := &s.docs[i]
		score := 0.0
		for _, t := range qr.terms {
			score += s.altScore(d, alt{whole: t})
		}
		for gi, g := range qr.groups {
			best := 0.0
			for _, a := range g.alts {
				best = max(best, s.altScore(d, a))
			}
			score += gw[gi] * best
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

// groupWeight is the weight of a synonym group: synWeight when a
// question word it was added for occurs in the corpus, so the user's
// own word dominates its expansion; 1 when none does (a German word
// against the English docs, an address literal), because then the
// group is the only form in which that word can match: it is a
// translation, not an addition.
func (s *Index) groupWeight(g group) float64 {
	for _, t := range g.own {
		if s.df[t] > 0 {
			return s.p.synWeight
		}
	}
	return 1
}

// altScore is the BM25F score of d for one term or synonym target:
// per field the occurrences are weighted and length-normalised, summed,
// and saturated once with k1. A synonym group scores as the best of
// its targets (a disjunction maximum), so a row adds at most as much
// as one term, however many targets it lists.
func (s *Index) altScore(d *doc, a alt) float64 {
	df := s.altDF(a)
	if df == 0 {
		return 0
	}
	w := 0.0
	for f := range numFields {
		tf := a.tf(d.tf[f])
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
		return 0
	}
	n := float64(len(s.docs))
	idf := math.Log(1 + (n-float64(df)+0.5)/(float64(df)+0.5))
	return idf * w / (s.p.k1 + w)
}

// alt is one alternative of a query concept. A joined synonym target
// ("enroll-script") keeps its parts: it matches the whole token, or
// all its parts together in the same field ("The enrollment script"),
// but never one part alone, so "enroll-script" does not turn every
// mention of "script" into evidence.
type alt struct {
	whole string
	parts []string
}

// tf is the frequency of a in one field: the whole token's count, or
// for a joined target, if higher, the count of its rarest part when
// every part occurs. The maximum (not the sum) avoids counting an
// occurrence of the whole token twice, as the corpus side also indexes
// its parts.
func (a alt) tf(field map[string]int) int {
	n := field[a.whole]
	if len(a.parts) < 2 {
		return n
	}
	m := field[a.parts[0]]
	for _, p := range a.parts[1:] {
		m = min(m, field[p])
	}
	return max(n, m)
}

// altDF is the document frequency of a: that of the whole token, or
// for a joined target, if higher, that of its rarest part (an upper
// bound of the documents holding all parts, so the IDF errs low).
func (s *Index) altDF(a alt) int {
	n := s.df[a.whole]
	if len(a.parts) < 2 {
		return n
	}
	m := s.df[a.parts[0]]
	for _, p := range a.parts[1:] {
		m = min(m, s.df[p])
	}
	return max(n, m)
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

// query is a parsed question.
type query struct {
	// terms are the question's own terms (each token and the parts of
	// a joined token), distinct and sorted. Each scores at full weight.
	terms []string
	// groups are the synonym expansions, one per distinct set of
	// targets, sorted by their targets. See group.
	groups []group
}

// group is the synonym expansion of one question token: the targets of
// its rows (and, for an address literal, addressTerms), minus terms the
// question already has. A group scores as its best target (a
// disjunction maximum), times groupWeight, so one row adds at most as
// much as one term however many targets it lists.
type group struct {
	// alts are the targets, sorted by whole token.
	alts []alt
	// own are the terms of the question token(s) the group was added
	// for, sorted; they decide groupWeight.
	own []string
}

// parseQuery validates q and splits it into own terms and synonym
// groups. Everything is sorted, so the float sum never depends on map
// order.
func parseQuery(q string) (query, error) {
	if len(q) > MaxQueryBytes {
		return query{}, fmt.Errorf("query of %d bytes, limit %d: %w", len(q), MaxQueryBytes, ErrQueryTooLarge)
	}
	if !utf8.ValidString(q) {
		return query{}, ErrInvalidQuery
	}
	raw := rawTokens(q)
	if len(raw) > MaxQueryTokens {
		return query{}, fmt.Errorf("query of %d tokens, limit %d: %w", len(raw), MaxQueryTokens, ErrQueryTooLarge)
	}
	own := map[string]struct{}{}
	for _, t := range raw {
		for _, e := range tokenTerms(t) {
			own[e] = struct{}{}
		}
	}
	var qr query
	byKey := map[string]int{}
	for _, t := range raw {
		byWhole := map[string]alt{}
		for _, to := range expand(t) {
			// A target is one alternative: its hyphen parts are not
			// separate terms (see alt).
			whole, parts := splitToken(to)
			if _, dup := own[whole]; whole == "" || dup {
				continue
			}
			byWhole[whole] = alt{whole: whole, parts: parts}
		}
		if len(byWhole) == 0 {
			continue
		}
		names := make([]string, 0, len(byWhole))
		for w := range byWhole {
			names = append(names, w)
		}
		slices.Sort(names)
		key := strings.Join(names, " ")
		if i, dup := byKey[key]; dup {
			g := &qr.groups[i]
			g.own = slices.Compact(slices.Sorted(slices.Values(append(g.own, tokenTerms(t)...))))
			continue
		}
		byKey[key] = len(qr.groups)
		g := group{alts: make([]alt, len(names))}
		for i, w := range names {
			g.alts[i] = byWhole[w]
		}
		g.own = slices.Compact(slices.Sorted(slices.Values(tokenTerms(t))))
		qr.groups = append(qr.groups, g)
	}
	qr.terms = sortedKeys(own)
	if len(qr.terms) == 0 && len(qr.groups) == 0 {
		return query{}, ErrEmptyQuery
	}
	slices.SortFunc(qr.groups, func(a, b group) int {
		return slices.CompareFunc(a.alts, b.alts, func(x, y alt) int { return strings.Compare(x.whole, y.whole) })
	})
	return qr, nil
}

// all returns every term of the query, own and synonym targets (whole
// tokens), distinct and sorted.
func (qr query) all() []string {
	set := map[string]struct{}{}
	for _, t := range qr.terms {
		set[t] = struct{}{}
	}
	for _, g := range qr.groups {
		for _, a := range g.alts {
			set[a.whole] = struct{}{}
		}
	}
	return sortedKeys(set)
}

// groupNames returns the target names of each synonym group (tests).
func (qr query) groupNames() [][]string {
	out := make([][]string, len(qr.groups))
	for i, g := range qr.groups {
		for _, a := range g.alts {
			out[i] = append(out[i], a.whole)
		}
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
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

// addressTerms are the words the docs use for an IP address. A question
// naming a concrete address ("192.168.22.1") rarely meets the same
// literal in the docs, which speak of "IP"/"IPs" and "address"
// instead.
var addressTerms = []string{"ip", "address"}

// expand returns the synonym terms for one raw question token, looked
// up as written and folded; an IPv4 address literal adds addressTerms
// (an IPv6 literal never reaches here whole: the tokenizer splits at
// ':').
func expand(t string) []string {
	out := synonymIndex[t]
	if ft := fold(t); ft != t {
		out = append(slices.Clone(out), synonymIndex[ft]...)
	}
	if _, err := netip.ParseAddr(t); err == nil {
		out = append(slices.Clone(out), addressTerms...)
	}
	return out
}
