// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// citationPageBody renders the ops page for one fix note that cites ids.
func citationPageBody(t *testing.T, ids ...string) string {
	t.Helper()
	store := &fakeOpsStore{notes: []opsnotes.Note{fixNote(1, time.Unix(0, 0), snapshotOpenSSL, opsnotes.Body{
		Summary:   "Paket aktualisieren",
		Citations: ids,
	})}}
	h := assistantServer(t, assistantOps(store, newCatalog()), assistantUser{"root"})
	return doAssistant(t, h, http.MethodGet, "/assistant/ops", nil).Body.String()
}

// handbookPath is the in-app path of the handbook page with the given slug.
func handbookPath(slug string) string {
	if slug == docsembed.IndexSlug {
		return "/help"
	}
	return "/help/" + slug
}

// handbookSlugs are the slugs of the handbook pages the UI serves. The index
// holds more sources (admin-guide has no /help page), so a chunk of another
// slug has no page to link to.
func handbookSlugs(t *testing.T) map[string]bool {
	t.Helper()
	docs, err := docsembed.Pages()
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool, len(docs))
	for _, d := range docs {
		out[d.Slug] = true
	}
	return out
}

// TestAssistantCitationLinksToTheChunkHeading renders a note that cites real
// chunk IDs of served handbook pages, "slug#anchor" and "slug#anchor#pN", and
// expects each to link to the heading of its own page.
func TestAssistantCitationLinksToTheChunkHeading(t *testing.T) {
	ix, err := helpdocs.FromDocsembed()
	if err != nil {
		t.Fatal(err)
	}
	served := handbookSlugs(t)
	var plain *helpdocs.Chunk
	for i := range ix.Chunks {
		c := &ix.Chunks[i]
		if served[c.Slug] && strings.Count(c.ID, "#") == 1 {
			plain = c
			break
		}
	}
	if plain == nil {
		t.Fatal("the served pages have no chunk ID of the form slug#anchor")
	}
	// The index names a paragraph part "slug#anchor#pN" only for long sections
	// (none of the served pages has one), so the part form is built from a
	// served chunk: the UI must parse it like the server does.
	part := *plain
	part.ID = plain.ID + "#p1"
	for _, c := range []*helpdocs.Chunk{plain, &part} {
		body := citationPageBody(t, c.ID)
		want := `<a href="` + handbookPath(c.Slug) + "#" + c.Anchor + `">` + c.ID + `</a>`
		if !strings.Contains(body, want) {
			t.Errorf("citation %q: page lacks %s", c.ID, want)
		}
	}
}

// TestAssistantCitationNeedsItsOwnPageAndHeading checks the cases that must
// stay plain text: a heading anchor that belongs to another page (its slug
// is not that page's slug), an anchor the page does not have, and a suffix
// that is not a part number.
func TestAssistantCitationNeedsItsOwnPageAndHeading(t *testing.T) {
	ix, err := helpdocs.FromDocsembed()
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]map[string]bool{}
	for _, c := range ix.Chunks {
		if anchors[c.Slug] == nil {
			anchors[c.Slug] = map[string]bool{}
		}
		anchors[c.Slug][c.Anchor] = true
	}
	var wrongPage string
	var anchor string
	for _, c := range ix.Chunks {
		for slug := range anchors {
			if slug != c.Slug && !anchors[slug][c.Anchor] {
				wrongPage, anchor = slug, c.Anchor
				break
			}
		}
		if wrongPage != "" {
			break
		}
	}
	if wrongPage == "" {
		t.Fatal("no page slug to pair with a heading of another page")
	}
	served := handbookSlugs(t)
	var unserved string
	for _, c := range ix.Chunks {
		if !served[c.Slug] {
			unserved = c.ID
			break
		}
	}
	if unserved == "" {
		t.Fatal("the index has no chunk of a page the UI does not serve")
	}
	ids := []string{
		wrongPage + "#" + anchor,
		wrongPage + "#gibt-es-nicht",
		wrongPage + "#" + anchor + "#x1",
		unserved,
	}
	body := citationPageBody(t, ids...)
	for _, id := range ids {
		if want := "<span>" + id + "</span>"; !strings.Contains(body, want) {
			t.Errorf("citation %q should be plain text, page lacks %s", id, want)
		}
	}
}
