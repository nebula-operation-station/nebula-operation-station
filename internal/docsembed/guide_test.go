// SPDX-License-Identifier: AGPL-3.0-or-later

package docsembed_test

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
)

// TestEmbeddedAdminGuideMatchesDocs keeps the embedded admin guide
// identical to docs/admin/guide.md: same bytes. Run "go generate
// ./internal/docsembed" when it fails. Editing the guide (for example
// in ag26) requires that command too.
func TestEmbeddedAdminGuideMatchesDocs(t *testing.T) {
	want, err := os.ReadFile("../../docs/admin/guide.md")
	if err != nil {
		t.Fatalf("read docs/admin/guide.md: %v", err)
	}
	g := docsembed.AdminGuide()
	if !bytes.Equal(g.Source, want) {
		t.Errorf("embedded admin guide differs from docs/admin/guide.md: run go generate ./internal/docsembed")
	}
	if g.File != "guide.md" {
		t.Errorf("admin guide file = %q, want guide.md", g.File)
	}
	if g.Slug != docsembed.AdminGuideSlug || !docsembed.ValidSlug(g.Slug) {
		t.Errorf("admin guide slug = %q, want a valid page slug equal to AdminGuideSlug", g.Slug)
	}
}

// TestAdminGuideIsNotAHandbookPage keeps /help unchanged: the admin
// guide is handed out by AdminGuide only. Pages and Page serve the
// handbook and must not list or serve it.
func TestAdminGuideIsNotAHandbookPage(t *testing.T) {
	pages, err := docsembed.Pages()
	if err != nil {
		t.Fatalf("Pages: %v", err)
	}
	for _, p := range pages {
		if p.Slug == docsembed.AdminGuideSlug || p.File == "guide.md" {
			t.Errorf("Pages lists the admin guide as %q (%s)", p.Slug, p.File)
		}
	}
	if _, err := docsembed.Page(docsembed.AdminGuideSlug); !errors.Is(err, docsembed.ErrNotFound) {
		t.Errorf("Page(%q) error = %v, want ErrNotFound", docsembed.AdminGuideSlug, err)
	}
}
