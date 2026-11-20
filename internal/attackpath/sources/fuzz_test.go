// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"errors"
	"slices"
	"strings"
	"testing"

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

// FuzzNodeID checks the adapter rule against the Builder itself, in both
// directions. Whatever nodeID accepts, the Builder accepts as a node of the
// prefix's kind. Whatever nodeID rejects with non-empty parts, the Builder
// rejects too: the candidate is prefix plus the parts joined with "/", the
// form nodeID documents. An empty part is an adapter rule of its own (a
// dangling "/" is a malformed record, which the Builder would accept), so
// that case is left to TestNodeIDBoundariesMatchBuilder.
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
			if slices.Contains(parts, "") {
				return
			}
			candidate := pf.prefix + strings.Join(parts, "/")
			if err := builderAccepts(candidate, pf.kind, "x"); err == nil {
				t.Fatalf("nodeID(%q, %q) rejected, but the Builder accepts %q as %v", pf.prefix, parts, candidate, pf.kind)
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

// FuzzLabel checks the label rule against the Builder: label returns s
// exactly when the Builder accepts s as a label, and "" otherwise.
func FuzzLabel(f *testing.F) {
	for _, s := range []string{
		"",
		"plain name",
		"tab\there",
		"line\nbreak",
		"carriage\rreturn",
		"nul\x00byte",
		"rtl" + string(rune(0x202e)) + "override",
		"isolate" + string(rune(0x2066)) + "x",
		"arabic" + string(rune(0x061c)) + "mark",
		"lrm" + string(rune(0x200e)) + "mark",
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
		builderErr := builderAccepts("host:x", attackpath.NodeHost, s)
		if builderErr != nil && !errors.Is(builderErr, attackpath.ErrInvalidNode) {
			t.Fatalf("Builder rejected label %q with %v, not ErrInvalidNode", s, builderErr)
		}
		if (builderErr == nil) != (got == s) {
			t.Fatalf("label(%q) = %q, but the Builder accepts it as a label: %v", s, got, builderErr == nil)
		}
	})
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
		{"rtl override dropped", "a" + string(rune(0x202e)) + "b", false},
		{"isolate dropped", "a" + string(rune(0x2066)) + "b", false},
		{"arabic letter mark dropped", "a" + string(rune(0x061c)) + "b", false},
		{"lrm dropped", "a" + string(rune(0x200e)) + "b", false},
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
