// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
)

// handbookSources returns the handbook pages as index sources, the
// corpus of FromDocsembed before the admin guide was added.
func handbookSources(t *testing.T) []Source {
	t.Helper()
	pages, err := docsembed.Pages()
	if err != nil {
		t.Fatalf("docsembed.Pages: %v", err)
	}
	srcs := make([]Source, 0, len(pages))
	for _, p := range pages {
		srcs = append(srcs, Source{Slug: p.Slug, File: p.File, Data: p.Source})
	}
	return srcs
}

// TestFromDocsembedIndexesAdminGuideAsThirdSource checks that the admin
// guide is part of the production index, under its own slug, and that
// every one of its chunks keeps the ID rule of the handbook chunks.
func TestFromDocsembedIndexesAdminGuideAsThirdSource(t *testing.T) {
	ix, err := FromDocsembed()
	if err != nil {
		t.Fatalf("FromDocsembed: %v", err)
	}
	checkInvariants(t, ix)
	n := 0
	for _, c := range ix.Chunks {
		if c.Slug != docsembed.AdminGuideSlug {
			continue
		}
		n++
		if c.File != "guide.md" {
			t.Errorf("admin guide chunk %q has file %q, want guide.md", c.ID, c.File)
		}
	}
	if n == 0 {
		t.Fatalf("FromDocsembed has no admin guide chunks")
	}
}

// TestHandbookChunksUnchangedByAdminGuide compares the handbook part of
// the production index with an index built from the handbook alone:
// same chunk IDs, anchors, line ranges and text, in the same order.
// Adding the admin guide must not move or rename any handbook chunk.
func TestHandbookChunksUnchangedByAdminGuide(t *testing.T) {
	full, err := FromDocsembed()
	if err != nil {
		t.Fatalf("FromDocsembed: %v", err)
	}
	only, err := Build(handbookSources(t))
	if err != nil {
		t.Fatalf("Build handbook: %v", err)
	}
	var got []Chunk
	for _, c := range full.Chunks {
		if c.Slug != docsembed.AdminGuideSlug {
			got = append(got, c)
		}
	}
	if len(got) != len(only.Chunks) {
		t.Fatalf("handbook chunks: got %d, want %d", len(got), len(only.Chunks))
	}
	for i := range got {
		if got[i].ID != only.Chunks[i].ID ||
			got[i].Anchor != only.Chunks[i].Anchor ||
			got[i].StartLine != only.Chunks[i].StartLine ||
			got[i].EndLine != only.Chunks[i].EndLine ||
			got[i].Text != only.Chunks[i].Text {
			t.Errorf("handbook chunk %d changed: got %q, want %q", i, got[i].ID, only.Chunks[i].ID)
		}
	}
}

// TestAdminGuideAnchorsMatchRenderedPage checks that every admin guide
// chunk is keyed by an anchor the rendered page really has, and that
// the guide's heading anchors are unique, with the same rule the
// handbook uses.
func TestAdminGuideAnchorsMatchRenderedPage(t *testing.T) {
	g := docsembed.AdminGuide()
	r, err := mdsafe.Render(g.Source, mdsafe.Options{})
	if err != nil {
		t.Fatalf("render admin guide: %v", err)
	}
	rendered := map[string]bool{}
	for _, h := range r.Headings {
		if rendered[h.ID] {
			t.Errorf("admin guide: rendered anchor %q is not unique", h.ID)
		}
		rendered[h.ID] = true
	}
	ix, err := FromDocsembed()
	if err != nil {
		t.Fatalf("FromDocsembed: %v", err)
	}
	n := 0
	for _, c := range ix.Chunks {
		if c.Slug != g.Slug {
			continue
		}
		n++
		base, _, _ := strings.Cut(c.Anchor, "#")
		if !rendered[base] {
			t.Errorf("admin guide chunk anchor %q is not an anchor of the rendered page", c.Anchor)
		}
	}
	if n == 0 {
		t.Errorf("admin guide: no chunks")
	}
}

// TestAdminGuideSectionAnchorIsCitable pins one anchor that the AS-04
// golden query cites ("7.1 The enrollment script"), so a renamed
// heading shows up here before it breaks citations.
func TestAdminGuideSectionAnchorIsCitable(t *testing.T) {
	ix, err := FromDocsembed()
	if err != nil {
		t.Fatalf("FromDocsembed: %v", err)
	}
	const want = "admin-guide#71-the-enrollment-script"
	if _, ok := ix.Lookup(want); !ok {
		t.Errorf("chunk %q missing from the production index", want)
	}
}
