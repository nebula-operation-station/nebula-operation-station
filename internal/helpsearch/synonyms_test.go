// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

import (
	"slices"
	"strings"
	"testing"
)

func TestSynonymRowsAreReviewed(t *testing.T) {
	seen := map[string]int{}
	for i, row := range synonyms {
		if strings.TrimSpace(row.Why) == "" {
			t.Errorf("row %d %v: no review note (Why)", i, row.From)
		}
		if len(row.From) == 0 || len(row.To) == 0 {
			t.Errorf("row %d: empty From or To", i)
		}
		for _, f := range row.From {
			// A From word must be written as the normaliser produces
			// it, or it can never match.
			if got := rawTokens(f); len(got) != 1 || got[0] != f {
				t.Errorf("row %d: From %q is not in normalised form (got %q)", i, f, got)
			}
			if prev, dup := seen[f]; dup {
				t.Errorf("row %d: From %q already in row %d", i, f, prev)
			}
			seen[f] = i
		}
		for _, to := range row.To {
			if len(terms(to)) == 0 {
				t.Errorf("row %d: To %q yields no term", i, to)
			}
		}
	}
}

func queryTermNames(t *testing.T, q string) []string {
	t.Helper()
	qt, err := queryTerms(q)
	if err != nil {
		t.Fatalf("queryTerms(%q): %v", q, err)
	}
	return qt
}

func TestGermanQuestionExpandsToCorpusTerms(t *testing.T) {
	got := queryTermNames(t, "Verbindung einrichten")
	for _, want := range []string{"enroll", "enroll-script", "login", "ssh", "einrichten", "verbindung"} {
		if !slices.Contains(got, want) {
			t.Errorf("queryTerms = %q, missing %q", got, want)
		}
	}
}

func TestSynonymsMatchFoldedForms(t *testing.T) {
	// "enrolling" folds to "enroll", which has a row.
	if got := queryTermNames(t, "enrolling"); !slices.Contains(got, "enroll-script") {
		t.Fatalf("queryTerms(enrolling) = %q, want enroll-script", got)
	}
}

func TestQueryTermsAreDistinctAndSorted(t *testing.T) {
	got := queryTermNames(t, "script enroll-script Script")
	want := []string{"enroll", "enroll-script", "script"}
	if !slices.Equal(got, want) {
		t.Fatalf("queryTerms = %q, want %q", got, want)
	}
}
