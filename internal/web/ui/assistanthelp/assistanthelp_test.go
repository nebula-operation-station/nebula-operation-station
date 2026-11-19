// SPDX-License-Identifier: AGPL-3.0-or-later

package assistanthelp

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// fakeBook is a handbook with one chapter and one matching section. It
// records the searches it was asked for, so a test can see whether the
// search ran.
type fakeBook struct {
	searches []string
}

func (b *fakeBook) Chapters() []Chapter {
	return []Chapter{{Title: "Overview", URL: "/help"}, {Title: "Updates", URL: "/help/updates"}}
}

func (b *fakeBook) Search(q string) ([]Result, bool) {
	b.searches = append(b.searches, q)
	return []Result{{Section: "Rolling updates", Page: "Updates", URL: "/help/updates#rolling"}}, false
}

// Build lists the chapters for every request and searches only when a
// search was submitted, so a plain panel open reads no search at all.
func TestBuildSearchesOnlyWhenSearchIsRequested(t *testing.T) {
	tests := []struct {
		name       string
		query      url.Values
		withSearch bool
		wantSearch bool
	}{
		{name: "panel open without search", query: url.Values{}, withSearch: false, wantSearch: false},
		{name: "panel open with q but search off", query: url.Values{"q": {"update"}}, withSearch: false, wantSearch: false},
		{name: "help search submitted", query: url.Values{"q": {"update"}}, withSearch: true, wantSearch: true},
		{name: "help page without q", query: url.Values{}, withSearch: true, wantSearch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			book := &fakeBook{}
			v, err := Build(book, tt.query, tt.withSearch)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got := len(book.searches) > 0; got != tt.wantSearch {
				t.Errorf("search ran = %v, want %v", got, tt.wantSearch)
			}
			if len(v.Chapters) != 2 {
				t.Errorf("chapters = %d, want 2 on every request", len(v.Chapters))
			}
		})
	}
}

// A search text that is too long or not valid UTF-8 is refused: the view
// is marked invalid, the text is not echoed back and nothing is searched.
func TestBuildRefusesLongOrInvalidSearchText(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{name: "too long", query: strings.Repeat("a", MaxQueryBytes+1)},
		{name: "not utf-8", query: "\xff\xfe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			book := &fakeBook{}
			v, err := Build(book, url.Values{"q": {tt.query}}, true)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if !v.Searched || !v.Invalid {
				t.Errorf("Searched=%v Invalid=%v, want both true", v.Searched, v.Invalid)
			}
			if v.Query != "" {
				t.Errorf("Query = %q, want empty for a refused search", v.Query)
			}
			if len(book.searches) != 0 {
				t.Errorf("refused search reached the handbook: %v", book.searches)
			}
		})
	}
}

// A valid search returns the matches of the book, shown back as text.
func TestBuildReturnsMatchesOfValidSearch(t *testing.T) {
	v, err := Build(&fakeBook{}, url.Values{"q": {"rolling"}}, true)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !v.Searched || v.Invalid || v.Query != "rolling" {
		t.Fatalf("view = %+v, want a valid search for rolling", v)
	}
	if len(v.Results) != 1 || v.Results[0].Section != "Rolling updates" {
		t.Errorf("results = %+v, want the rolling section", v.Results)
	}
}

// A missing handbook is an error, not a panic.
func TestBuildNilBookIsAnError(t *testing.T) {
	_, err := Build(nil, url.Values{}, false)
	if !errors.Is(err, ErrNoBook) {
		t.Fatalf("Build(nil) error = %v, want ErrNoBook", err)
	}
}
