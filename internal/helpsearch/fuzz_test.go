// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

import (
	"errors"
	"testing"
	"unicode/utf8"
)

func FuzzSearch(f *testing.F) {
	for _, q := range []string{
		"enroll 192.168.22.1",
		"ich will auf IP 192.168.22.1 die Connection einrichten",
		"--from", "enroll-script", "", "\xff", "ÄÖÜß---...", "a-b_c.d",
	} {
		f.Add(q)
	}
	s := New(corpus(f))
	f.Fuzz(func(t *testing.T, q string) {
		hits, err := s.Search(q)
		if err != nil {
			if !errors.Is(err, ErrEmptyQuery) && !errors.Is(err, ErrQueryTooLarge) && !errors.Is(err, ErrInvalidQuery) {
				t.Fatalf("Search(%q): unexpected error %v", q, err)
			}
			return
		}
		if len(hits) > TopK {
			t.Fatalf("Search(%q): %d hits", q, len(hits))
		}
		size := 0
		for i, h := range hits {
			size += len(h.Chunk.Text)
			if h.Score <= 0 {
				t.Fatalf("Search(%q): hit %d score %v", q, i, h.Score)
			}
			if i > 0 && (h.Score > hits[i-1].Score || h.Score == hits[i-1].Score && h.Chunk.ID < hits[i-1].Chunk.ID) {
				t.Fatalf("Search(%q): hits out of order at %d", q, i)
			}
		}
		if size > MaxContextDocBytes {
			t.Fatalf("Search(%q): %d bytes", q, size)
		}
	})
}

func FuzzTerms(f *testing.F) {
	for _, s := range []string{"enroll-script --from 192.168.0.10", "Schlüssel", "\xff\xfe", "----", "a_b-c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, term := range terms(s) {
			if term == "" || len(term) > maxTokenBytes {
				t.Fatalf("terms(%q): bad term %q", s, term)
			}
			if utf8.ValidString(s) && !utf8.ValidString(term) {
				t.Fatalf("terms(%q): invalid UTF-8 term %q", s, term)
			}
		}
	})
}
