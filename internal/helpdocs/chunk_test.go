// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// para returns a prose paragraph of exactly n bytes (including the
// trailing blank line), starting with tag so tests can find it.
func para(tag string, n int) string {
	body := tag + strings.Repeat("x", n-len(tag)-2) + "\n\n"
	return body
}

func build(t *testing.T, slug, src string) *Index {
	t.Helper()
	ix, err := Build([]Source{{Slug: slug, File: slug + ".md", Data: []byte(src)}})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return ix
}

func chunkIDs(ix *Index) []string {
	out := make([]string, 0, len(ix.Chunks))
	for _, c := range ix.Chunks {
		out = append(out, c.ID)
	}
	return out
}

func mustLookup(t *testing.T, ix *Index, id string) Chunk {
	t.Helper()
	c, ok := ix.Lookup(id)
	if !ok {
		t.Fatalf("no chunk %q; have %v", id, chunkIDs(ix))
	}
	return c
}

// checkInvariants asserts what every index must hold: unique IDs,
// IDs built from slug and anchor, anchors non-empty, line ranges
// ordered, and every code block inside the line range of its chunk.
func checkInvariants(t *testing.T, ix *Index) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range ix.Chunks {
		if c.Anchor == "" {
			t.Errorf("chunk %q has empty anchor", c.ID)
		}
		if c.ID != c.Slug+"#"+c.Anchor {
			t.Errorf("chunk ID %q != slug#anchor (%q, %q)", c.ID, c.Slug, c.Anchor)
		}
		if seen[c.ID] {
			t.Errorf("duplicate chunk ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.StartLine < 1 || c.EndLine < c.StartLine {
			t.Errorf("chunk %q: bad line range %d-%d", c.ID, c.StartLine, c.EndLine)
		}
		for _, cb := range c.Code {
			if cb.StartLine < c.StartLine || cb.EndLine > c.EndLine || cb.EndLine < cb.StartLine {
				t.Errorf("chunk %q: code block %d-%d outside chunk %d-%d", c.ID, cb.StartLine, cb.EndLine, c.StartLine, c.EndLine)
			}
		}
	}
}

func TestChunkPerH2KeysByRenderedAnchor(t *testing.T) {
	src := "# Hosts\n\nIntro.\n\n## Add a host\n\nUse the form.\n\n## Remove a host\n\nDelete it.\n"
	ix := build(t, "hosts", src)
	want := []string{"hosts#hosts", "hosts#add-a-host", "hosts#remove-a-host"}
	if got := chunkIDs(ix); !slices.Equal(got, want) {
		t.Fatalf("chunk IDs = %v, want %v", got, want)
	}
	c := mustLookup(t, ix, "hosts#add-a-host")
	if !slices.Equal(c.Path, []string{"Hosts", "Add a host"}) {
		t.Errorf("path = %v, want [Hosts Add a host]", c.Path)
	}
	if !strings.Contains(c.Text, "Use the form.") || strings.Contains(c.Text, "Delete it.") {
		t.Errorf("chunk text does not hold exactly its section: %q", c.Text)
	}
	checkInvariants(t, ix)
}

func TestDuplicateH2TitlesGetTheRenderedAnchors(t *testing.T) {
	src := "# T\n\n## Hosts\n\na\n\n## Hosts\n\nb\n"
	ix := build(t, "t", src)
	r, err := mdsafe.Render([]byte(src), mdsafe.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var rendered []string
	for _, h := range r.Headings {
		if h.Level == 2 {
			rendered = append(rendered, h.ID)
		}
	}
	want := []string{"hosts", "hosts-1"}
	if !slices.Equal(rendered, want) {
		t.Fatalf("renderer ids = %v, want %v", rendered, want)
	}
	for _, id := range want {
		mustLookup(t, ix, "t#"+id)
	}
	checkInvariants(t, ix)
}

func TestHeadingWithoutAnchorFailsBuild(t *testing.T) {
	for _, src := range []string{
		"# T\n\n## !!!\n\ntext\n",
		"# T\n\n### ***\n\ntext\n",
		"# \n\nintro\n",
		"intro without any heading\n",
	} {
		_, err := Build([]Source{{Slug: "p", File: "p.md", Data: []byte(src)}})
		if !errors.Is(err, ErrNoAnchor) {
			t.Errorf("source %q: err = %v, want ErrNoAnchor", src, err)
		}
	}
}

func TestDuplicateChunkIDFailsCheck(t *testing.T) {
	chunks := []Chunk{
		{ID: "p#a", Anchor: "a"},
		{ID: "p#a", Anchor: "a"},
	}
	if err := checkUnique(chunks); !errors.Is(err, ErrDuplicateAnchor) {
		t.Fatalf("err = %v, want ErrDuplicateAnchor", err)
	}
	if err := checkUnique([]Chunk{{ID: "", Anchor: ""}}); !errors.Is(err, ErrNoAnchor) {
		t.Fatalf("empty anchor: err = %v, want ErrNoAnchor", err)
	}
}

func TestDuplicateSourceSlugIsRejected(t *testing.T) {
	_, err := Build([]Source{
		{Slug: "a", File: "a.md", Data: []byte("# A\n")},
		{Slug: "a", File: "a2.md", Data: []byte("# A\n")},
	})
	if !errors.Is(err, ErrDuplicateSource) {
		t.Fatalf("err = %v, want ErrDuplicateSource", err)
	}
}

func TestInvalidSlugAndSourceLimitsAreRejected(t *testing.T) {
	cases := []struct {
		name string
		src  Source
		want error
	}{
		{"slug with hash", Source{Slug: "a#b", Data: []byte("# A\n")}, ErrInvalidSlug},
		{"too large", Source{Slug: "a", Data: make([]byte, mdsafe.MaxSourceBytes+1)}, ErrSourceTooLarge},
		{"invalid utf-8", Source{Slug: "a", Data: []byte("# A\n\xff\n")}, ErrInvalidUTF8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Build([]Source{tc.src})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHeadingInsideFenceIsNoSection(t *testing.T) {
	src := "## Real\n\n```\n## Fake\n```\n"
	ix := build(t, "p", src)
	if got, want := chunkIDs(ix), []string{"p#real"}; !slices.Equal(got, want) {
		t.Fatalf("chunk IDs = %v, want %v", got, want)
	}
	c := mustLookup(t, ix, "p#real")
	if len(c.Code) != 1 || c.Code[0].Body != "## Fake" {
		t.Fatalf("code block not kept inside the section: %+v", c.Code)
	}
}

func TestSmallSectionIsNotSplitAtH3(t *testing.T) {
	src := "## S\n\n### a\n\nx\n\n### b\n\ny\n"
	ix := build(t, "p", src)
	if got, want := chunkIDs(ix), []string{"p#s"}; !slices.Equal(got, want) {
		t.Fatalf("chunk IDs = %v, want %v", got, want)
	}
}

func TestOversizedH2SplitsAtH3(t *testing.T) {
	src := "## Big\n\n" + para("intro", 300) +
		"### One\n\n" + para("one", 4000) +
		"### Two\n\n" + para("two", 4000)
	ix := build(t, "p", src)
	want := []string{"p#big", "p#one", "p#two"}
	if got := chunkIDs(ix); !slices.Equal(got, want) {
		t.Fatalf("chunk IDs = %v, want %v", got, want)
	}
	for _, c := range ix.Chunks {
		if len(c.Text) > MaxChunkBytes {
			t.Errorf("chunk %q is %d bytes, above MaxChunkBytes", c.ID, len(c.Text))
		}
	}
	if got := mustLookup(t, ix, "p#two").Path; !slices.Equal(got, []string{"Big", "Two"}) {
		t.Errorf("path of H3 chunk = %v, want [Big Two]", got)
	}
	checkInvariants(t, ix)
}

func TestOversizedParagraphSplitsIntoNumberedParts(t *testing.T) {
	var b strings.Builder
	b.WriteString("## Long\n\n")
	const n = 12
	for i := 1; i <= n; i++ {
		b.WriteString(para(fmt.Sprintf("P%02d:", i), 1000))
	}
	ix := build(t, "p", b.String())
	var parts []Chunk
	for _, c := range ix.Chunks {
		parts = append(parts, c)
	}
	if len(parts) < 2 {
		t.Fatalf("expected numbered parts, got %v", chunkIDs(ix))
	}
	var all strings.Builder
	for i, c := range parts {
		if want := fmt.Sprintf("p#long#p%d", i+1); c.ID != want {
			t.Errorf("part %d ID = %q, want %q", i+1, c.ID, want)
		}
		if len(c.Text) > MaxChunkBytes {
			t.Errorf("part %q is %d bytes, above MaxChunkBytes", c.ID, len(c.Text))
		}
		all.WriteString(c.Text)
	}
	for i := 1; i <= n; i++ {
		tag := fmt.Sprintf("P%02d:", i)
		if strings.Count(all.String(), tag) != 1 {
			t.Errorf("paragraph %s lost or duplicated across parts", tag)
		}
	}
	checkInvariants(t, ix)
}

// codeText is a fenced block of about n bytes, one line per 60 bytes.
func codeText(tag string, n int) string {
	var b strings.Builder
	b.WriteString("```sh\n")
	for line := 0; b.Len() < n; line++ {
		fmt.Fprintf(&b, "%s-%04d %s\n", tag, line, strings.Repeat("y", 50))
	}
	b.WriteString("```\n\n")
	return b.String()
}

// TestCodeBlockNeverCutAcrossSplitPoints sweeps the position of a
// code block against the chunk limit so that the block lands on every
// kind of boundary a split could produce.
func TestCodeBlockNeverCutAcrossSplitPoints(t *testing.T) {
	for prose := 4000; prose <= 9000; prose += 97 {
		src := "## Sweep\n\n" + para("before", prose) + codeText("CODE", 1500) + para("after", 3000)
		ix := build(t, "p", src)
		checkInvariants(t, ix)
		found := 0
		for _, c := range ix.Chunks {
			for _, cb := range c.Code {
				found++
				if cb.Lang != "sh" || !strings.HasPrefix(cb.Body, "CODE-0000 ") {
					t.Fatalf("prose=%d: code block cut or changed: %+v", prose, cb)
				}
				if strings.Count(c.Text, "```") != 2 {
					t.Fatalf("prose=%d: chunk %q holds half a code fence", prose, c.ID)
				}
			}
		}
		if found != 1 {
			t.Fatalf("prose=%d: found %d code blocks, want 1 whole block", prose, found)
		}
	}
}

func TestOversizedCodeBlockIsKeptWhole(t *testing.T) {
	src := "## Huge\n\n" + codeText("H", 8000)
	ix := build(t, "p", src)
	found := 0
	for _, c := range ix.Chunks {
		for _, cb := range c.Code {
			found++
			if !strings.HasPrefix(cb.Body, "H-0000 ") || !strings.HasSuffix(strings.TrimRight(cb.Body, "\n"), strings.Repeat("y", 50)) {
				t.Fatalf("code body cut: %q", cb.Body[:40])
			}
		}
	}
	if found != 1 {
		t.Fatalf("found %d code blocks, want 1", found)
	}
	checkInvariants(t, ix)
}

func TestCodeBlockInfoAndLineNumbers(t *testing.T) {
	src := "## Run\n\n```sh\nnebula host list\n```\n\n~~~ bash title\necho hi\n~~~\n\n```\nplain\n```\n"
	ix := build(t, "p", src)
	c := mustLookup(t, ix, "p#run")
	want := []CodeBlock{
		{Info: "sh", Lang: "sh", StartLine: 3, EndLine: 5, Body: "nebula host list"},
		{Info: "bash title", Lang: "bash", StartLine: 7, EndLine: 9, Body: "echo hi"},
		{Info: "", Lang: "", StartLine: 11, EndLine: 13, Body: "plain"},
	}
	if len(c.Code) != len(want) {
		t.Fatalf("code blocks = %+v, want %+v", c.Code, want)
	}
	for i := range want {
		if c.Code[i] != want[i] {
			t.Errorf("code block %d = %+v, want %+v", i, c.Code[i], want[i])
		}
	}
	checkInvariants(t, ix)
}

func TestUnclosedFenceRunsToEndOfFile(t *testing.T) {
	src := "## Open\n\n```sh\nnebula x\n"
	ix := build(t, "p", src)
	c := mustLookup(t, ix, "p#open")
	if len(c.Code) != 1 || c.Code[0].Body != "nebula x" || c.Code[0].EndLine != 4 {
		t.Fatalf("unclosed fence = %+v", c.Code)
	}
	checkInvariants(t, ix)
}

func TestIndexIsByteIdenticalForSameInput(t *testing.T) {
	a := build(t, "p", "# T\n\n## A\n\nx\n\n## B\n\ny\n")
	b := build(t, "p", "# T\n\n## A\n\nx\n\n## B\n\ny\n")
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ja) != string(jb) {
		t.Fatalf("index differs for the same input:\n%s\n%s", ja, jb)
	}
}

func TestIndexDoesNotDependOnSourceOrder(t *testing.T) {
	srcs := []Source{
		{Slug: "b", File: "b.md", Data: []byte("# B\n\n## Two\n\nx\n")},
		{Slug: "a", File: "a.md", Data: []byte("# A\n\n## One\n\ny\n")},
	}
	rev := []Source{srcs[1], srcs[0]}
	ix1, err := Build(srcs)
	if err != nil {
		t.Fatal(err)
	}
	ix2, err := Build(rev)
	if err != nil {
		t.Fatal(err)
	}
	j1, _ := json.Marshal(ix1)
	j2, _ := json.Marshal(ix2)
	if string(j1) != string(j2) {
		t.Fatalf("source order changes the index")
	}
}

func TestFromDocsembedCoversHandbookAndMatchesRenderedAnchors(t *testing.T) {
	ix, err := FromDocsembed()
	if err != nil {
		t.Fatalf("FromDocsembed: %v", err)
	}
	checkInvariants(t, ix)
	pages, err := docsembed.Pages()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		r, err := mdsafe.Render(p.Source, mdsafe.Options{})
		if err != nil {
			t.Fatalf("render %s: %v", p.File, err)
		}
		rendered := map[string]bool{}
		for _, h := range r.Headings {
			rendered[h.ID] = true
		}
		n := 0
		for _, c := range ix.Chunks {
			if c.Slug != p.Slug {
				continue
			}
			n++
			if len(c.Text) > MaxChunkBytes && len(c.Code) == 0 {
				t.Errorf("%s: chunk %q is %d bytes without a code block to excuse it", p.File, c.ID, len(c.Text))
			}
			base, _, _ := strings.Cut(c.Anchor, "#")
			if !rendered[base] {
				t.Errorf("%s: chunk anchor %q is not an anchor of the rendered page", p.File, c.Anchor)
			}
		}
		if n == 0 {
			t.Errorf("%s: no chunks", p.File)
		}
	}
}
