// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

import (
	"slices"
	"strings"
	"testing"
)

func TestRawTokensKeepCommandsFlagsAndAddressesWhole(t *testing.T) {
	got := rawTokens("Run `nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh`.")
	want := []string{"run", "nebula", "host", "enroll-script", "--from", "192.168.0.10", "100.64.0.10", "enroll.sh"}
	if !slices.Equal(got, want) {
		t.Fatalf("rawTokens = %q, want %q", got, want)
	}
}

func TestRawTokensTrimSentencePunctuation(t *testing.T) {
	tests := []struct{ in, want string }{
		{"host.", "host"},
		{"host-", "host"},
		{".hidden", "hidden"},
		{"--no-sudo", "--no-sudo"},
		{"Schlüssel", "schluessel"},
		{"Größe", "groesse"},
		{"ÄNDERN", "aendern"},
	}
	for _, tt := range tests {
		got := rawTokens(tt.in)
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("rawTokens(%q) = %q, want [%q]", tt.in, got, tt.want)
		}
	}
}

func TestRawTokensDropPunctuationOnlyAndOverlongTokens(t *testing.T) {
	long := strings.Repeat("a", maxTokenBytes+1)
	if got := rawTokens("-- ... --- " + long); len(got) != 0 {
		t.Fatalf("rawTokens = %q, want none", got)
	}
	ok := strings.Repeat("a", maxTokenBytes)
	if got := rawTokens(ok); len(got) != 1 {
		t.Fatalf("rawTokens of a %d-byte token = %q, want it kept", maxTokenBytes, got)
	}
}

func TestFoldJoinsRelatedForms(t *testing.T) {
	groups := [][]string{
		{"enroll", "enrolls", "enrolled", "enrolling", "enrollment", "enrollments"},
		{"pin", "pins", "pinned", "pinning"},
		{"key", "keys"},
		{"update", "updates", "updated", "updating"},
		{"change", "changed", "changes"},
		{"restore", "restored"},
		{"entry", "entries"},
		{"add", "adds", "added", "adding"},
		{"embed", "embeds", "embedded", "embedding"},
		{"run", "running"},
		{"exceed", "exceeds", "exceeded"},
		{"connect", "connects", "connection", "connections"},
		{"restrict", "restriction"},
		{"ip", "ips"},
		{"vm", "vms"},
	}
	for _, g := range groups {
		want := fold(g[0])
		for _, w := range g[1:] {
			if got := fold(w); got != want {
				t.Errorf("fold(%q) = %q, want %q like fold(%q)", w, got, want, g[0])
			}
		}
	}
}

func TestFoldLeavesNonWordsAlone(t *testing.T) {
	for _, w := range []string{"enroll-script", "--from", "192.168.22.1", "enroll.sh", "status", "access", "ssh", "einrichten", "v1s"} {
		if got := fold(w); got != w && !plainWord(w) {
			t.Errorf("fold(%q) = %q, want unchanged", w, got)
		}
	}
	for _, w := range []string{"status", "access", "analysis", "ssh"} {
		if got := fold(w); got != w {
			t.Errorf("fold(%q) = %q, want unchanged", w, got)
		}
	}
}

// TestFoldKeepsEndingsThatBelongToTheWord covers the over-stripping of
// "-ed"/"-ing": a stem shorter than four letters means the ending is
// part of the word, and "-eed" is never an inflection.
func TestFoldKeepsEndingsThatBelongToTheWord(t *testing.T) {
	for _, w := range []string{"embed", "speed", "need", "string", "thing", "bring", "nos", "has", "yes"} {
		if got := fold(w); got != w {
			t.Errorf("fold(%q) = %q, want unchanged", w, got)
		}
	}
	// Unrelated words must not merge.
	for _, pair := range [][2]string{{"string", "str"}, {"speed", "spend"}, {"embed", "emblem"}} {
		if fold(pair[0]) == fold(pair[1]) {
			t.Errorf("fold(%q) == fold(%q) = %q", pair[0], pair[1], fold(pair[0]))
		}
	}
}

func TestTermsDropStopWordsInBothLanguages(t *testing.T) {
	got := terms("ich will auf the host die Verbindung und the key")
	want := []string{"host", "verbindung", "key"}
	if !slices.Equal(got, want) {
		t.Fatalf("terms = %q, want %q", got, want)
	}
}

func TestTokenTermsAddPartsAfterWholeToken(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"enroll-script", []string{"enroll-script", "enroll", "script"}},
		{"--no-sudo", []string{"--no-sudo", "sudo"}},
		{"--from", []string{"--from"}},
		{"nos_read", []string{"nos_read", "nos", "read"}},
		{"192.168.22.1", []string{"192.168.22.1"}},
		{"the", nil},
	}
	for _, tt := range tests {
		if got := tokenTerms(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("tokenTerms(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
