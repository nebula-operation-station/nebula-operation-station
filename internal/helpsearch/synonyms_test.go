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
	qr, err := parseQuery(q)
	if err != nil {
		t.Fatalf("parseQuery(%q): %v", q, err)
	}
	return qr.all()
}

func TestGermanQuestionExpandsToCorpusTerms(t *testing.T) {
	got := queryTermNames(t, "Verbindung einrichten")
	for _, want := range []string{"setup", "set", "configur", "login", "ssh", "einrichten", "verbindung"} {
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

// TestEinrichtenIsNotEnrollmentOnly is the regression test for the row
// that mapped the general German verb "einrichten" to enrollment
// vocabulary only. The ranking side is TestSetupQuestionsDoNotDriftToEnrollment.
func TestEinrichtenIsNotEnrollmentOnly(t *testing.T) {
	qr, err := parseQuery("einrichten")
	if err != nil {
		t.Fatal(err)
	}
	groups := qr.groupNames()
	if len(groups) != 1 {
		t.Fatalf("groups = %q, want one group", groups)
	}
	for _, want := range []string{"setup", "set", "configur"} {
		if !slices.Contains(groups[0], want) {
			t.Errorf("einrichten group %q lacks general set-up term %q", groups[0], want)
		}
	}
	for _, bad := range []string{"enroll-script", "script"} {
		if slices.Contains(groups[0], bad) {
			t.Errorf("einrichten group %q contains %q", groups[0], bad)
		}
	}
}

// TestSynonymTargetsFormOneGroupWithoutParts is the regression test for
// synonym targets (and their hyphen parts) becoming independent full
// terms: one question token gives one group, a joined target is not
// split, and targets the user already wrote stay own terms.
func TestSynonymTargetsFormOneGroupWithoutParts(t *testing.T) {
	qr, err := parseQuery("enroll Verbindung")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"enroll", "verbindung"}; !slices.Equal(qr.terms, want) {
		t.Errorf("terms = %q, want %q", qr.terms, want)
	}
	// "enroll" → {enroll-script} (no "script" part); "verbindung" →
	// {connect, login, ssh}.
	want := [][]string{{"connect", "login", "ssh"}, {"enroll-script"}}
	if got := qr.groupNames(); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("groups = %q, want %q", got, want)
	}
	if got := queryTermNames(t, "enroll"); slices.Contains(got, "script") {
		t.Errorf("queryTerms(enroll) = %q, contains the part %q", got, "script")
	}
}

// TestSynonymGroupIsDownWeighted checks the scoring side: a section
// matching every target of a synonym row does not outrank one matching
// the word the user wrote, and a group adds less than an own term.
func TestSynonymGroupIsDownWeighted(t *testing.T) {
	s := index(
		chunk("keep", "Keep copies", "keep a backup off the machine"),
		chunk("remote", "Remote access", "connect with the ssh login of the nebula user"),
		chunk("x1", "Pinning", "pin the host key"),
		chunk("x2", "Patching", "patch the packages"),
		chunk("x3", "Rollouts", "roll out in stages"),
	)
	hits, err := s.Search("backup verbindung")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) < 2 || hits[0].Chunk.ID != "t#keep" {
		t.Fatalf("Search(backup verbindung) = %v, want t#keep first", ids(hits))
	}
	// One own term against the group of all three targets: the group
	// scores below the term although it matches three words.
	if hits[1].Score >= hits[0].Score {
		t.Fatalf("group score %v >= own term score %v", hits[1].Score, hits[0].Score)
	}
}

// TestJoinedSynonymTargetNeedsAllItsParts: the target "enroll-script"
// (from "onboard") matches a section titled "The enrollment script",
// but a section that only mentions "script" gets nothing from it.
func TestJoinedSynonymTargetNeedsAllItsParts(t *testing.T) {
	s := index(
		chunk("enroll", "The enrollment script", "run it on the host"),
		chunk("script", "Shell script", "a script for backups"),
		chunk("x1", "Pinning", "pin the host key"),
	)
	hits, err := s.Search("onboard")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(hits); !slices.Equal(got, []string{"t#enroll"}) {
		t.Fatalf("Search(onboard) = %v, want only t#enroll", got)
	}
}

// TestTranslationGroupKeepsFullWeight: a group added for a word the
// corpus never contains (a German word) is its only way to match and
// keeps full weight; a group added for a word the corpus has is
// down-weighted.
func TestTranslationGroupKeepsFullWeight(t *testing.T) {
	s := index(
		chunk("keep", "Keep copies", "keep a backup off the machine and connect"),
		chunk("x1", "Pinning", "pin the host key"),
	)
	for _, c := range []struct {
		q    string
		want float64
	}{
		{"verbindung", 1},
		{"connect", synWeight},
		{"192.168.0.1", 1},
	} {
		qr, err := parseQuery(c.q)
		if err != nil {
			t.Fatal(err)
		}
		if len(qr.groups) != 1 {
			t.Fatalf("parseQuery(%q) groups = %q, want one", c.q, qr.groupNames())
		}
		if got := s.groupWeight(qr.groups[0]); got != c.want {
			t.Errorf("groupWeight(%q) = %v, want %v", c.q, got, c.want)
		}
	}
}

func TestAddressLiteralExpandsToAddressWords(t *testing.T) {
	// IPv6 literals are split at ':' by the tokenizer and not covered.
	for _, q := range []string{"192.168.22.1", "10.0.0.5"} {
		got := queryTermNames(t, q)
		for _, want := range addressTerms {
			if !slices.Contains(got, fold(want)) {
				t.Errorf("queryTerms(%q) = %q, missing %q", q, got, want)
			}
		}
	}
	if got := queryTermNames(t, "1.2.3"); slices.Contains(got, "address") {
		t.Errorf("queryTerms(1.2.3) = %q: a version is not an address", got)
	}
}

func TestQueryTermsAreDistinctAndSorted(t *testing.T) {
	got := queryTermNames(t, "script enroll-script Script")
	want := []string{"enroll", "enroll-script", "script"}
	if !slices.Equal(got, want) {
		t.Fatalf("queryTerms = %q, want %q", got, want)
	}
}
