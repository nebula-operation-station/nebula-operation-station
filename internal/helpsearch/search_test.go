// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
)

func chunk(id, title, body string) helpdocs.Chunk {
	return helpdocs.Chunk{
		ID:     "t#" + id,
		Slug:   "t",
		Anchor: id,
		Path:   []string{"Test", title},
		Text:   "## " + title + "\n\n" + body,
	}
}

func index(chunks ...helpdocs.Chunk) *Index {
	return New(&helpdocs.Index{Chunks: chunks})
}

func TestSearchRejectsBadQueries(t *testing.T) {
	s := index(chunk("a", "Backup", "back up the database"))
	tests := []struct {
		name string
		q    string
		want error
	}{
		{"empty", "", ErrEmptyQuery},
		{"blank", "  \t\n ", ErrEmptyQuery},
		{"punctuation", "?!? ... --", ErrEmptyQuery},
		{"stop words only", "the and ich will", ErrEmptyQuery},
		{"too many bytes", strings.Repeat("a", MaxQueryBytes+1), ErrQueryTooLarge},
		{"too many tokens", strings.Repeat("x ", MaxQueryTokens+1), ErrQueryTooLarge},
		{"invalid utf-8", "backup \xff", ErrInvalidQuery},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hits, err := s.Search(tt.q)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Search error = %v, want %v", err, tt.want)
			}
			if hits != nil {
				t.Fatalf("Search hits = %v, want nil", hits)
			}
		})
	}
}

func TestSearchAcceptsQueriesAtTheLimits(t *testing.T) {
	s := index(chunk("a", "Backup", "back up the database"))
	atBytes := "backup" + strings.Repeat(" ", MaxQueryBytes-len("backup"))
	if _, err := s.Search(atBytes); err != nil {
		t.Errorf("Search of %d bytes: %v", len(atBytes), err)
	}
	atTokens := "backup" + strings.Repeat(" x", MaxQueryTokens-1)
	if _, err := s.Search(atTokens); err != nil {
		t.Errorf("Search of %d tokens: %v", MaxQueryTokens, err)
	}
}

func TestSearchReturnsNoHitForUnknownTerms(t *testing.T) {
	s := index(chunk("a", "Backup", "back up the database"))
	hits, err := s.Search("kubernetes")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("hits = %v, want none", ids(hits))
	}
}

func TestNilIndexSearchesNothing(t *testing.T) {
	hits, err := New(nil).Search("backup")
	if err != nil || len(hits) != 0 {
		t.Fatalf("Search on nil index = %v, %v", hits, err)
	}
}

func TestSearchReturnsAtMostTopK(t *testing.T) {
	var cs []helpdocs.Chunk
	for i := range 10 {
		cs = append(cs, chunk(fmt.Sprintf("c%02d", i), "Backup", "backup"))
	}
	hits, err := index(cs...).Search("backup")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != TopK {
		t.Fatalf("len(hits) = %d, want %d", len(hits), TopK)
	}
}

func TestSearchStopsAtContextByteCap(t *testing.T) {
	filler := strings.Repeat("x ", 5<<10/2) // 5 KiB
	var cs []helpdocs.Chunk
	for i := range 6 {
		cs = append(cs, chunk(fmt.Sprintf("c%d", i), "Backup", "backup "+filler))
	}
	hits, err := index(cs...).Search("backup")
	if err != nil {
		t.Fatal(err)
	}
	size := 0
	for _, h := range hits {
		size += len(h.Chunk.Text)
	}
	if size > MaxContextDocBytes {
		t.Fatalf("hits hold %d bytes, cap %d", size, MaxContextDocBytes)
	}
	if len(hits) != 4 {
		t.Fatalf("len(hits) = %d, want 4 chunks of about 5 KiB under a 24 KiB cap", len(hits))
	}
}

func TestSearchResultIsPrefixOfRankingUnderByteCap(t *testing.T) {
	// The best chunk alone is over the cap: nothing is returned rather
	// than skipping it and citing worse chunks in its place.
	big := chunk("big", "Backup backup", "backup "+strings.Repeat("y ", MaxContextDocBytes))
	small := chunk("small", "Other", "backup")
	hits, err := index(big, small).Search("backup")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("hits = %v, want none", ids(hits))
	}
}

func TestEqualScoresAreOrderedByChunkID(t *testing.T) {
	var cs []helpdocs.Chunk
	for _, id := range []string{"d", "b", "e", "a", "c"} {
		cs = append(cs, chunk(id, "Restore", "restore the backup"))
	}
	want := []string{"t#a", "t#b", "t#c", "t#d", "t#e"}
	for range 20 {
		hits, err := index(cs...).Search("restore backup")
		if err != nil {
			t.Fatal(err)
		}
		if got := ids(hits); !slices.Equal(got, want) {
			t.Fatalf("ids = %v, want %v", got, want)
		}
		slices.Reverse(cs)
	}
}

func TestSearchIsDeterministicOnTheCorpus(t *testing.T) {
	ix := corpus(t)
	for _, g := range allGolden() {
		first, err := New(ix).Search(g.q)
		if err != nil {
			t.Fatal(err)
		}
		for range 10 {
			again, err := New(ix).Search(g.q)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(ids(again), ids(first)) {
				t.Fatalf("Search(%q) changed: %v then %v", g.q, ids(first), ids(again))
			}
			for i := range again {
				if again[i].Score != first[i].Score {
					t.Fatalf("Search(%q) score %d changed: %v then %v", g.q, i, first[i].Score, again[i].Score)
				}
			}
		}
	}
}

func TestFlagsMatchOnlyAsWholeTokens(t *testing.T) {
	// "--from" must not match "from" in prose (a stop word anyway) or
	// "--from-file"; every hit carries the exact flag.
	s := New(corpus(t))
	for _, q := range []string{"--from", "--criticality", "--user"} {
		hits, err := s.Search(q)
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if len(hits) == 0 {
			t.Fatalf("Search(%q): no hits", q)
		}
		for _, h := range hits {
			if !slices.Contains(rawTokens(h.Chunk.Text), q) {
				t.Errorf("Search(%q): hit %s does not contain the flag", q, h.Chunk.ID)
			}
		}
	}
}

func TestCommandTokenRanksSectionsWithTheCommandFirst(t *testing.T) {
	// The parts of "enroll-script" also match prose ("enrollment
	// script"), but the whole token is rarer, so the sections showing
	// the command lead the ranking.
	s := New(corpus(t))
	for _, q := range []string{"enroll-script", "nos-read"} {
		hits, err := s.Search(q)
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if len(hits) < 3 {
			t.Fatalf("Search(%q): %d hits", q, len(hits))
		}
		for _, h := range hits[:3] {
			if !slices.Contains(rawTokens(h.Chunk.Text), q) {
				t.Errorf("Search(%q): top-3 hit %s does not contain the command", q, h.Chunk.ID)
			}
		}
	}
}

func TestWholeCommandTokenOutranksItsParts(t *testing.T) {
	cmd := chunk("cmd", "Hosts", "run nebula host enroll-script on the machine")
	parts := chunk("parts", "Hosts", "run the script to enroll the machine")
	hits, err := index(parts, cmd).Search("enroll-script")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(hits); len(got) != 2 || got[0] != "t#cmd" {
		t.Fatalf("ids = %v, want t#cmd first", got)
	}
}

func TestTitleHitOutranksSameBodyHit(t *testing.T) {
	inTitle := chunk("title", "Restore", "steps for the database files")
	inBody := chunk("body", "Database", "steps for restore files")
	hits, err := index(inBody, inTitle).Search("restore")
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(hits); len(got) != 2 || got[0] != "t#title" {
		t.Fatalf("ids = %v, want t#title first", got)
	}
}

func TestHeadingLineIsNotCountedInBody(t *testing.T) {
	c := chunk("a", "Restore a backup", "steps")
	f := fields(c)
	if slices.Contains(f[fieldBody], "restor") {
		t.Fatalf("body terms %q contain the heading", f[fieldBody])
	}
	if !slices.Contains(f[fieldTitle], "restor") || !slices.Contains(f[fieldPath], "test") {
		t.Fatalf("fields = %q", f)
	}
	// A paragraph part (#p2) has no heading line; its text is all body.
	c.Text = "restore steps"
	if f := fields(c); !slices.Contains(f[fieldBody], "restor") {
		t.Fatalf("body terms %q lost the first line of a part", f[fieldBody])
	}
}
