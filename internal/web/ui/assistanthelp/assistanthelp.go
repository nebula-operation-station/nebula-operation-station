// SPDX-License-Identifier: AGPL-3.0-or-later

// Package assistanthelp is the Help backend of the Assistant panel (ADR 0016
// D11). It builds the Help tab from a handbook it is given and from plain
// request values. It holds no notes store, no Ops configuration and no
// handler: its only inputs are the Book interface and url.Values. The
// boundary test in this directory checks that its import graph never
// reaches the notes or findings stores or the UI package.
package assistanthelp

import (
	"errors"
	"net/url"
	"unicode/utf8"
)

// MaxQueryBytes bounds the search text of the Help tab; the same limit as
// the /help search.
const MaxQueryBytes = 100

// ErrNoBook is returned by Build when no handbook is given.
var ErrNoBook = errors.New("assistanthelp: no handbook")

// Result is one search match of the handbook.
type Result struct {
	// Section is the heading text; Page the page title.
	Section string
	Page    string
	URL     string
}

// Chapter is one entry of the handbook table of contents.
type Chapter struct {
	Title string
	URL   string
}

// Book is the handbook the Help tab reads. The UI supplies it from the
// rendered handbook; it never carries notes or request state.
type Book interface {
	// Chapters returns the table of contents in reading order.
	Chapters() []Chapter
	// Search returns the matching sections and whether more matched than
	// were returned.
	Search(query string) (results []Result, truncated bool)
}

// View is what the Help tab shows.
type View struct {
	// Query is the search text as typed; empty when the search was refused.
	Query string
	// Searched is true when a search was submitted.
	Searched bool
	// Invalid is true when the search text is too long or not UTF-8.
	Invalid bool
	// Results are the matching sections.
	Results []Result
	// Truncated is true when more matches exist than are shown.
	Truncated bool
	// Chapters is the handbook's table of contents.
	Chapters []Chapter
}

// Build builds the Help view. The search runs only when withSearch is true
// and the query has a "q" value; a search text that is too long or not
// valid UTF-8 is refused without reaching the book. A nil book is ErrNoBook.
func Build(book Book, query url.Values, withSearch bool) (*View, error) {
	if book == nil {
		return nil, ErrNoBook
	}
	v := &View{}
	if withSearch {
		if q, ok := query["q"]; ok && len(q) > 0 {
			v.Searched = true
			v.Query = q[0]
			if len(v.Query) > MaxQueryBytes || !utf8.ValidString(v.Query) {
				v.Invalid = true
				v.Query = ""
			} else {
				v.Results, v.Truncated = book.Search(v.Query)
			}
		}
	}
	v.Chapters = book.Chapters()
	return v, nil
}
