// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// journalResult builds a systemd-status-v1 result whose journal block is the
// base64 of the given raw bytes, as the host script produces it.
func journalResult(t *testing.T, raw string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"format":  "systemd-status-v1",
		"phase":   "done",
		"verb":    "",
		"exit":    0,
		"show":    "",
		"journal": base64.StdEncoding.EncodeToString([]byte(raw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestServiceJournalKeepsValidLinesAroundInvalidUTF8 is the mixed journal: one
// line that is not valid UTF-8 is dropped, and the valid lines around it stay.
func TestServiceJournalKeepsValidLinesAroundInvalidUTF8(t *testing.T) {
	for name, tc := range map[string]struct {
		raw     string
		want    []string
		dropped int
	}{
		"invalid line in the middle": {
			raw:     "line one\nbad \xff byte\nline three\n",
			want:    []string{"line one", "line three"},
			dropped: 1,
		},
		"truncated multibyte sequence": {
			raw:     "ok\nbad \xc3(\nok again\n",
			want:    []string{"ok", "ok again"},
			dropped: 1,
		},
		"invalid first and last line": {
			raw:     "\xfe first\nmiddle\nlast \xc0\xaf\n",
			want:    []string{"middle"},
			dropped: 2,
		},
		"all lines invalid": {
			raw:     "\xff\n\xfe\n",
			want:    nil,
			dropped: 2,
		},
		"all lines valid": {
			raw:     "a\nü\n日本\n",
			want:    []string{"a", "ü", "日本"},
			dropped: 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			st, err := ParseServiceStatus(journalResult(t, tc.raw))
			if err != nil {
				t.Fatalf("ParseServiceStatus: %v", err)
			}
			if strings.Join(st.Journal, "|") != strings.Join(tc.want, "|") || len(st.Journal) != len(tc.want) {
				t.Errorf("journal = %q, want %q", st.Journal, tc.want)
			}
			if st.JournalDropped != tc.dropped {
				t.Errorf("JournalDropped = %d, want %d", st.JournalDropped, tc.dropped)
			}
			for _, l := range st.Journal {
				if !utf8.ValidString(l) {
					t.Errorf("kept line is not UTF-8: %q", l)
				}
			}
		})
	}
}

// TestServiceJournalLongLineIsCutOnRuneBoundary: a line over the length limit
// is cut, but never in the middle of a multibyte character.
func TestServiceJournalLongLineIsCutOnRuneBoundary(t *testing.T) {
	// 999 ASCII bytes then "ü" (2 bytes): the 1000-byte cut would split it.
	line := strings.Repeat("a", 999) + "ü" + "tail"
	st, err := ParseServiceStatus(journalResult(t, line+"\n"))
	if err != nil {
		t.Fatalf("ParseServiceStatus: %v", err)
	}
	if len(st.Journal) != 1 {
		t.Fatalf("journal lines = %d, want 1", len(st.Journal))
	}
	got := st.Journal[0]
	if !utf8.ValidString(got) || strings.Contains(got, "�") {
		t.Fatalf("cut line is not clean UTF-8: %q", got)
	}
	if got != strings.Repeat("a", 999) {
		t.Errorf("cut line = %d bytes, want the 999 ASCII bytes", len(got))
	}
}
