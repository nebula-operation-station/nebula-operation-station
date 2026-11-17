// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"errors"
	"fmt"
	"html/template"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// TestOutlineCheckRejectsRendererThatDisagrees feeds checkOutline a
// renderer result that matches our headings by count and level but
// not by text, by code block count, or by code block body. Each must
// fail with ErrOutlineMismatch.
func TestOutlineCheckRejectsRendererThatDisagrees(t *testing.T) {
	lines := []string{"# T", "", "## S", "```", "x", "```"}
	fences := scanFences(lines)
	heads := findHeadings(lines, fences)
	const page = "<h1 id=\"t\">T</h1>\n<h2 id=\"s\">S</h2>\n<pre><code>x\n</code></pre>\n"
	good := mdsafe.Result{
		HTML: template.HTML(page),
		Headings: []mdsafe.Heading{
			{Level: 1, Text: "T", ID: "t"},
			{Level: 2, Text: "S", ID: "s"},
		},
	}
	if err := checkOutline(lines, fences, heads, good); err != nil {
		t.Fatalf("agreeing renderer rejected: %v", err)
	}
	cases := map[string]mdsafe.Result{
		"same level, other text": {
			HTML:     template.HTML(page),
			Headings: []mdsafe.Heading{{Level: 1, Text: "T", ID: "t"}, {Level: 2, Text: "Other", ID: "other"}},
		},
		"code block missing": {
			HTML:     template.HTML("<h1 id=\"t\">T</h1>\n<h2 id=\"s\">S</h2>\n"),
			Headings: good.Headings,
		},
		"code block body differs": {
			HTML:     template.HTML("<h1 id=\"t\">T</h1>\n<h2 id=\"s\">S</h2>\n<pre><code>y\n</code></pre>\n"),
			Headings: good.Headings,
		},
		"extra code block": {
			HTML:     template.HTML(page + "<pre><code></code></pre>\n"),
			Headings: good.Headings,
		},
		"unterminated code block": {
			HTML:     template.HTML("<h1 id=\"t\">T</h1>\n<pre><code>x\n"),
			Headings: good.Headings,
		},
	}
	for name, r := range cases {
		if err := checkOutline(lines, fences, heads, r); !errors.Is(err, ErrOutlineMismatch) {
			t.Errorf("%s: err = %v, want ErrOutlineMismatch", name, err)
		}
	}
}

// TestCancellingDivergenceCannotMisplaceAnchors is the case that
// slipped past a count-and-level check: the renderer and the splitter
// disagreed about one fence and about one heading inside it, and the
// two disagreements cancelled out. The fence info string holds a
// backtick, which the renderer accepts. The heading inside the fence
// is code and must not become a chunk, and the next H2 keeps its
// anchor.
func TestCancellingDivergenceCannotMisplaceAnchors(t *testing.T) {
	src := "# T\n\n```a`b\n## Hidden\n```\n\n## Real\n\ntext\n"
	ix := build(t, "p", src)
	if got, want := chunkIDs(ix), []string{"p#t", "p#real"}; !slices.Equal(got, want) {
		t.Fatalf("chunk IDs = %v, want %v", got, want)
	}
	c := mustLookup(t, ix, "p#t")
	if len(c.Code) != 1 || c.Code[0].Info != "a`b" || c.Code[0].Body != "## Hidden" {
		t.Fatalf("code block = %+v", c.Code)
	}
	if real := mustLookup(t, ix, "p#real"); real.StartLine != 7 {
		t.Errorf("## Real starts at line %d, want 7", real.StartLine)
	}
	checkInvariants(t, ix)
}

// TestRendererOnlyStructureFailsBuild covers fences and headings that
// the renderer recognises inside list items. The index does not model
// list items, so it must refuse the source instead of guessing.
func TestRendererOnlyStructureFailsBuild(t *testing.T) {
	for name, src := range map[string]string{
		"fence in list item":   "# T\n\n- ```\n  code\n  ```\n\n## After\n\ntext\n",
		"heading in list item": "# T\n\n- ## Inside\n\n## After\n\ntext\n",
	} {
		_, err := Build([]Source{{Slug: "p", File: "p.md", Data: []byte(src)}})
		if !errors.Is(err, ErrOutlineMismatch) {
			t.Errorf("%s: err = %v, want ErrOutlineMismatch", name, err)
		}
	}
}

// TestFenceCloseMatchesRenderer checks that a closing line with a
// space between marks closes the fence, as the renderer does.
func TestFenceCloseMatchesRenderer(t *testing.T) {
	src := "## S\n\n```\nx\n``` ```\n\n## T\n\ntext\n"
	ix := build(t, "p", src)
	c := mustLookup(t, ix, "p#s")
	if len(c.Code) != 1 || c.Code[0].Body != "x" || c.Code[0].EndLine != 5 {
		t.Fatalf("code block = %+v", c.Code)
	}
	mustLookup(t, ix, "p#t")
	checkInvariants(t, ix)
}

// TestTextBeforeFirstH1FailsBuild: text above the H1 has no heading to
// be cited by, so the source is refused, with or without an H2.
func TestTextBeforeFirstH1FailsBuild(t *testing.T) {
	for _, src := range []string{
		"intro\n\n# T\n\n## S\n\nx\n",
		"intro\n\n# T\n",
		"intro\n\n## S\n\nx\n\n# T\n",
	} {
		_, err := Build([]Source{{Slug: "p", File: "p.md", Data: []byte(src)}})
		if !errors.Is(err, ErrNoAnchor) {
			t.Errorf("source %q: err = %v, want ErrNoAnchor", src, err)
		}
	}
}

// TestTextAfterH1IsAnchoredToH1 is the accepted counterpart: prose
// under the H1 and before the first H2 is chunked under the H1 anchor.
func TestTextAfterH1IsAnchoredToH1(t *testing.T) {
	ix := build(t, "p", "\n# T\n\nintro\n\n## S\n\nx\n")
	c := mustLookup(t, ix, "p#t")
	if !strings.Contains(c.Text, "intro") || strings.Contains(c.Text, "## S") {
		t.Fatalf("H1 chunk text = %q", c.Text)
	}
	checkInvariants(t, ix)
}

// TestManySectionsWithFencesIndexesEachOnce builds about 240 KB of
// tiny H2 sections, each with an empty fence. Each chunk must hold its
// own fence only. A scan of every fence per chunk would take quadratic
// time here.
func TestManySectionsWithFencesIndexesEachOnce(t *testing.T) {
	const n = 20000
	var b strings.Builder
	b.WriteString("# T\n")
	for i := range n {
		fmt.Fprintf(&b, "\n## S%d\n```\n```\n", i)
	}
	ix := build(t, "p", b.String())
	if len(ix.Chunks) != n+1 {
		t.Fatalf("chunks = %d, want %d", len(ix.Chunks), n+1)
	}
	for _, c := range ix.Chunks[1:] {
		if len(c.Code) != 1 {
			t.Fatalf("chunk %q has %d code blocks, want 1", c.ID, len(c.Code))
		}
	}
	checkInvariants(t, ix)
}
