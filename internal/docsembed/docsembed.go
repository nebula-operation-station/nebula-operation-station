// SPDX-License-Identifier: AGPL-3.0-or-later

// Package docsembed embeds the operator handbook (docs/handbook/*.md)
// into the binary at build time.
//
// //go:embed cannot reach files outside the package directory, so the
// handbook is copied into handbook/ by "go generate ./internal/docsembed"
// (gen.go, a plain file copy). docs/handbook stays the source of truth;
// TestEmbeddedHandbookMatchesDocs fails whenever the copy differs, so a
// stale copy cannot pass make check. Translations in subdirectories
// (docs/handbook/de/) are not embedded yet.
//
// The package only hands out the Markdown source; rendering it is the
// job of internal/docsembed/mdsafe.
package docsembed

//go:generate go run gen.go

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

//go:embed handbook/*.md
var handbookFS embed.FS

// IndexSlug is the slug of the handbook's overview page (README.md).
const IndexSlug = "readme"

// MaxSlugBytes bounds a page slug; longer names are rejected unparsed.
const MaxSlugBytes = 64

// ErrNotFound is returned by Page for a slug that names no handbook page.
var ErrNotFound = errors.New("docsembed: no such handbook page")

// slugRE is the only accepted page slug form: lower-case letters,
// digits and inner hyphens. It keeps request paths out of fs lookups.
var slugRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// Doc is one embedded handbook page.
type Doc struct {
	// Slug is the file name without ".md", lower-cased ("faq",
	// "getting-started"; README.md is IndexSlug).
	Slug string
	// File is the file name in docs/handbook ("faq.md").
	File string
	// Source is the Markdown text.
	Source []byte
}

// ValidSlug reports whether s has the form of a page slug.
func ValidSlug(s string) bool {
	return len(s) <= MaxSlugBytes && slugRE.MatchString(s)
}

// Pages returns every handbook page, sorted by slug.
func Pages() ([]Doc, error) {
	names, err := fs.Glob(handbookFS, "handbook/*.md")
	if err != nil {
		return nil, fmt.Errorf("list handbook: %w", err)
	}
	docs := make([]Doc, 0, len(names))
	for _, name := range names {
		file := path.Base(name)
		slug := strings.ToLower(strings.TrimSuffix(file, ".md"))
		if !ValidSlug(slug) {
			return nil, fmt.Errorf("handbook file %q: name is not a valid page slug", file)
		}
		b, err := handbookFS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read handbook %s: %w", file, err)
		}
		docs = append(docs, Doc{Slug: slug, File: file, Source: b})
	}
	slices.SortFunc(docs, func(a, b Doc) int { return strings.Compare(a.Slug, b.Slug) })
	return docs, nil
}

// Page returns the page with the given slug, or ErrNotFound.
func Page(slug string) (Doc, error) {
	if !ValidSlug(slug) {
		return Doc{}, ErrNotFound
	}
	docs, err := Pages()
	if err != nil {
		return Doc{}, err
	}
	for _, d := range docs {
		if d.Slug == slug {
			return d, nil
		}
	}
	return Doc{}, ErrNotFound
}
