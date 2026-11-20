// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
)

// nodeIDPrefixes are the prefixes the adapters of this package pass to
// nodeID, each with the kind the Builder binds to it. Every node ID a
// source reports starts with one of them.
var nodeIDPrefixes = []struct {
	prefix string
	kind   attackpath.NodeKind
}{
	{"host:", attackpath.NodeHost},
	{"ctr:", attackpath.NodeContainer},
	{"pve:", attackpath.NodePVENode},
	{"guest:", attackpath.NodeGuest},
	{"unk:", attackpath.NodeUnmanaged},
}

// builderAccepts reports whether the attackpath Builder takes a node with
// this ID, kind and label. It is the reference the adapters must mirror.
func builderAccepts(id string, kind attackpath.NodeKind, label string) error {
	return attackpath.NewBuilder().AddNode(attackpath.Node{ID: id, Kind: kind, Label: label})
}

// FuzzNodeID checks the adapter rule against the Builder itself: whatever
// nodeID accepts, the Builder accepts as a node of the prefix's kind, and a
// rejection yields "".
func FuzzNodeID(f *testing.F) {
	for _, s := range [][3]string{
		{"web-01", "", ""},
		{"", "", ""},
		{"a", "b", "c"},
		{"a b", "", ""},
		{"ü", "", ""},
		{"x\x00y", "", ""},
		{"a/b", "c", ""},
		{"", "a", ""},
		{strings.Repeat("a", attackpath.MaxIDBytes), "", ""},
		{strings.Repeat("a", attackpath.MaxIDBytes-len("host:")), "", ""},
		{strings.Repeat("a", attackpath.MaxIDBytes-len("host:")+1), "", ""},
		{"1", "2", "3"},
		{"vm:1", "@x", "-y_z.w"},
		{"\x7f", "", ""},
	} {
		f.Add(uint8(0), uint8(0), s[0], s[1], s[2])
		f.Add(uint8(3), uint8(2), s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, pi, n uint8, a, b, c string) {
		pf := nodeIDPrefixes[int(pi)%len(nodeIDPrefixes)]
		parts := []string{a, b, c}[:1+int(n)%3]

		id, ok := nodeID(pf.prefix, parts...)
		if !ok {
			if id != "" {
				t.Fatalf("nodeID(%q, %q) rejected but returned %q", pf.prefix, parts, id)
			}
			return
		}
		if !strings.HasPrefix(id, pf.prefix) || len(id) <= len(pf.prefix) {
			t.Fatalf("nodeID(%q, %q) = %q: not prefix plus at least one character", pf.prefix, parts, id)
		}
		if len(id) > attackpath.MaxIDBytes {
			t.Fatalf("nodeID(%q, %q) = %d bytes, above MaxIDBytes", pf.prefix, parts, len(id))
		}
		for _, p := range parts {
			if p == "" {
				t.Fatalf("nodeID(%q, %q) accepted an empty part", pf.prefix, parts)
			}
		}
		if err := builderAccepts(id, pf.kind, "x"); err != nil {
			t.Fatalf("nodeID(%q, %q) accepted %q, but the Builder rejects it as %v", pf.prefix, parts, id, err)
		}
	})
}

// FuzzLabel checks the label rule against the Builder: label returns s or
// "", and it returns s exactly when the Builder accepts s as a label.
func FuzzLabel(f *testing.F) {
	for _, s := range []string{
		"",
		"plain name",
		"tab\there",
		"line\nbreak",
		"carriage\rreturn",
		"nul\x00byte",
		"rtl‮override",
		"isolate⁦x",
		"arabic؜mark",
		"lrm‎mark",
		strings.Repeat("ü", attackpath.MaxLabelBytes/2),
		strings.Repeat("ü", attackpath.MaxLabelBytes/2+1),
		strings.Repeat("x", attackpath.MaxLabelBytes+1),
		"cut\xe2\x80",
		"invalid\xff",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := label(s)
		if got != "" && got != s {
			t.Fatalf("label(%q) = %q: neither the input nor empty", s, got)
		}
		builderErr := builderAccepts("host:x", attackpath.NodeHost, s)
		switch {
		case builderErr == nil && got != s:
			t.Fatalf("label(%q) dropped a label the Builder accepts", s)
		case builderErr != nil && !errors.Is(builderErr, attackpath.ErrInvalidNode):
			t.Fatalf("Builder rejected label %q with %v, not ErrInvalidNode", s, builderErr)
		case builderErr != nil && got != "":
			t.Fatalf("label(%q) = %q, but the Builder rejects it: %v", s, got, builderErr)
		}
		if got == "" {
			return
		}
		if len(got) > attackpath.MaxLabelBytes || !utf8.ValidString(got) {
			t.Fatalf("label %q: too long or not UTF-8", got)
		}
		for _, r := range got {
			if r != '\t' && unicode.IsControl(r) {
				t.Fatalf("label %q contains control character %U", got, r)
			}
			if isBidiChar(r) {
				t.Fatalf("label %q contains bidi character %U", got, r)
			}
		}
	})
}

// isBidiChar reports the bidi controls label rejects (ADR 0011 D10).
func isBidiChar(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

// TestNodeIDBoundariesMatchBuilder runs the length and character boundaries
// of nodeID without the fuzzer, so they run in make test.
func TestNodeIDBoundariesMatchBuilder(t *testing.T) {
	maxTail := strings.Repeat("a", attackpath.MaxIDBytes-len("host:"))
	tests := []struct {
		name  string
		parts []string
		ok    bool
	}{
		{"plain", []string{"web-01"}, true},
		{"empty part", []string{""}, false},
		{"empty second part", []string{"a", ""}, false},
		{"joined parts", []string{"a", "b"}, true},
		{"space", []string{"a b"}, false},
		{"non-ascii", []string{"ü"}, false},
		{"control", []string{"a\x7f"}, false},
		{"allowed punctuation", []string{"._:/@-"}, true},
		{"exactly max", []string{maxTail}, true},
		{"one over max", []string{maxTail + "a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := nodeID("host:", tt.parts...)
			if ok != tt.ok {
				t.Fatalf("nodeID(%q) ok = %v, want %v", tt.parts, ok, tt.ok)
			}
			if !ok {
				if id != "" {
					t.Fatalf("rejected nodeID returned %q", id)
				}
				return
			}
			if err := builderAccepts(id, attackpath.NodeHost, "x"); err != nil {
				t.Fatalf("Builder rejects accepted ID %q: %v", id, err)
			}
		})
	}
}

// TestLabelBoundariesMatchBuilder runs the label boundaries without the
// fuzzer, so they run in make test.
func TestLabelBoundariesMatchBuilder(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		keeps bool
	}{
		{"empty", "", true},
		{"tab kept", "a\tb", true},
		{"newline dropped", "a\nb", false},
		{"nul dropped", "a\x00b", false},
		{"rtl override dropped", "a‮b", false},
		{"isolate dropped", "a⁦b", false},
		{"arabic letter mark dropped", "a؜b", false},
		{"lrm dropped", "a‎b", false},
		{"truncated utf-8 dropped", "a\xe2\x80", false},
		{"exactly max kept", strings.Repeat("x", attackpath.MaxLabelBytes), true},
		{"one over max dropped", strings.Repeat("x", attackpath.MaxLabelBytes+1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := label(tt.in)
			if (got == tt.in) != tt.keeps {
				t.Fatalf("label(%q) = %q, keeps = %v, want %v", tt.in, got, got == tt.in, tt.keeps)
			}
			err := builderAccepts("host:x", attackpath.NodeHost, tt.in)
			if (err == nil) != tt.keeps {
				t.Fatalf("Builder accepts label %q = %v, want %v", tt.in, err == nil, tt.keeps)
			}
		})
	}
}
