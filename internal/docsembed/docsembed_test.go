// SPDX-License-Identifier: AGPL-3.0-or-later

package docsembed_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
)

// TestEmbeddedHandbookMatchesDocs keeps the embedded copy identical to
// docs/handbook: same files, same bytes. Run "go generate
// ./internal/docsembed" when it fails.
func TestEmbeddedHandbookMatchesDocs(t *testing.T) {
	files, err := filepath.Glob("../../docs/handbook/*.md")
	if err != nil || len(files) == 0 {
		t.Fatalf("list docs/handbook: %v (%d files)", err, len(files))
	}
	docs, err := docsembed.Pages()
	if err != nil {
		t.Fatalf("Pages: %v", err)
	}
	embedded := map[string][]byte{}
	for _, d := range docs {
		embedded[d.File] = d.Source
	}
	for _, f := range files {
		want, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		got, ok := embedded[filepath.Base(f)]
		if !ok {
			t.Errorf("%s is not embedded: run go generate ./internal/docsembed", filepath.Base(f))
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("embedded %s differs from docs/handbook: run go generate ./internal/docsembed", filepath.Base(f))
		}
		delete(embedded, filepath.Base(f))
	}
	for f := range embedded {
		t.Errorf("embedded %s no longer exists in docs/handbook: run go generate ./internal/docsembed", f)
	}
}

func TestPagesHaveIndexAndFAQ(t *testing.T) {
	for _, slug := range []string{docsembed.IndexSlug, "faq", "getting-started"} {
		d, err := docsembed.Page(slug)
		if err != nil {
			t.Fatalf("Page(%q): %v", slug, err)
		}
		if len(d.Source) == 0 {
			t.Errorf("Page(%q) is empty", slug)
		}
	}
}

func TestPageRejectsUnsafeSlugs(t *testing.T) {
	for _, slug := range []string{
		"", "../faq", "faq.md", "FAQ", "faq/", "/faq", "fa q", "faq\x00",
		"-faq", "faq-", "a--b", "%2e%2e", "de/readme", strings.Repeat("a", docsembed.MaxSlugBytes+1),
		"missing-page",
	} {
		if _, err := docsembed.Page(slug); !errors.Is(err, docsembed.ErrNotFound) {
			t.Errorf("Page(%q) err = %v, want ErrNotFound", slug, err)
		}
	}
}
