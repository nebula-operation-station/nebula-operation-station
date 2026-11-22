// SPDX-License-Identifier: AGPL-3.0-or-later

package jewels

import (
	"errors"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
)

// builderKinds returns the kinds from kinds that the attackpath Builder
// accepts id as. The Builder binds each ID to one kind by prefix, so the
// result has at most one element; the Builder itself decides, not a copy of
// its rule.
func builderKinds(id string, kinds []attackpath.NodeKind) []attackpath.NodeKind {
	var out []attackpath.NodeKind
	for _, k := range kinds {
		if builderAccepts(id, k) == nil {
			out = append(out, k)
		}
	}
	return out
}

// FuzzNodeKind checks the markable-ID rule against the Builder: NodeKind
// returns a kind exactly when the Builder accepts id as a node of a markable
// kind, and then the kind is that one.
func FuzzNodeKind(f *testing.F) {
	for _, s := range []string{
		"host:1", "pve:n1", "guest:100", "ctr:abc", "dev:sw1", "host:", "unk:x", "internet", "netbird",
		"host:a b", "host:\x00", "host:\xff", "host:é", "host:!", "host:a/b@c.d-e_f:g",
		"ctr:" + strings.Repeat("a", attackpath.MaxIDBytes-len("ctr:")),
		"ctr:" + strings.Repeat("a", attackpath.MaxIDBytes-len("ctr:")+1),
		"", "host:" + string(rune(0x202e)),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := NodeKind(s)
		if err != nil && (!errors.Is(err, ErrInvalidNode) || k != 0) {
			t.Fatalf("NodeKind(%q) = %v, %v: want ErrInvalidNode and kind 0", s, k, err)
		}
		want := builderKinds(s, markableKinds)
		switch {
		case len(want) > 1:
			t.Fatalf("the Builder accepts %q as %v: prefixes overlap", s, want)
		case err != nil && len(want) == 1:
			t.Fatalf("NodeKind(%q) rejects, but the Builder accepts it as %v", s, want[0])
		case err == nil && len(want) == 0:
			t.Fatalf("NodeKind(%q) = %v, but the Builder rejects it as every markable kind", s, k)
		case err == nil && k != want[0]:
			t.Fatalf("NodeKind(%q) = %v, but the Builder accepts it as %v", s, k, want[0])
		}
	})
}

// TestNodeKindRefusesIDsTheBuilderRejects pins the IDs that NodeKind used to
// accept while the Builder rejects them. Marking such an ID would store a
// crown jewel that makes attack-path prepareTargets fail the whole
// computation. Mark refusing them is tested in jewels_test.go
// (TestMarkRejectsBadInput).
func TestNodeKindRefusesIDsTheBuilderRejects(t *testing.T) {
	for _, id := range []string{"host:!", "host:é", "host:a+b", "host:a%20b", "ctr:x~y", "host:a\x7f"} {
		if k, err := NodeKind(id); !errors.Is(err, ErrInvalidNode) {
			t.Errorf("NodeKind(%q) = %v, %v: want ErrInvalidNode", id, k, err)
		}
		if err := validExposed(id); !errors.Is(err, ErrInvalidNode) {
			t.Errorf("validExposed(%q) = %v: want ErrInvalidNode", id, err)
		}
		if got := builderKinds(id, exposableKinds); len(got) != 0 {
			t.Errorf("the Builder accepts %q as %v; the test premise is wrong", id, got)
		}
	}
}

// TestNodeKindBoundaries runs the prefix, length and character boundaries of
// NodeKind and the Builder without the fuzzer, so they run in make test.
func TestNodeKindBoundaries(t *testing.T) {
	maxCtr := "ctr:" + strings.Repeat("a", attackpath.MaxIDBytes-len("ctr:"))
	tests := []struct {
		name string
		id   string
		want attackpath.NodeKind // 0: rejected
	}{
		{"host", "host:1", attackpath.NodeHost},
		{"container", "ctr:abc", attackpath.NodeContainer},
		{"device", "dev:sw1", attackpath.NodeNetworkDevice},
		{"prefix only", "host:", 0},
		{"entry", attackpath.InternetID, 0},
		{"unmanaged is not markable", "unk:x", 0},
		{"space", "host:a b", 0},
		{"nul", "host:\x00", 0},
		{"invalid utf-8", "host:\xff", 0},
		{"exactly max", maxCtr, attackpath.NodeContainer},
		{"one over max", maxCtr + "a", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := NodeKind(tt.id)
			if tt.want == 0 {
				if !errors.Is(err, ErrInvalidNode) {
					t.Fatalf("NodeKind(%q) = %v, %v: want ErrInvalidNode", tt.id, k, err)
				}
				return
			}
			if err != nil || k != tt.want {
				t.Fatalf("NodeKind(%q) = %v, %v: want %v", tt.id, k, err, tt.want)
			}
			if err := builderAccepts(tt.id, tt.want); err != nil {
				t.Fatalf("Builder rejects %q accepted by NodeKind: %v", tt.id, err)
			}
		})
	}
}

// FuzzCheckText checks the bounded admin text rule: optional text may be
// empty, required text may not, and every non-empty text is within the
// limit, valid UTF-8 and free of control characters.
func FuzzCheckText(f *testing.F) {
	for _, s := range []string{"", "admin", "a\tb", "a\nb", "a\x00b", "ü", "a\xff", "x"} {
		f.Add(s, 8, true)
		f.Add(s, 8, false)
	}
	f.Add(strings.Repeat("x", MaxReasonBytes), MaxReasonBytes, false)
	f.Add(strings.Repeat("x", MaxReasonBytes+1), MaxReasonBytes, true)
	f.Fuzz(func(t *testing.T, s string, max int, optional bool) {
		if max < 0 {
			max = -max
		}
		want := (s == "" && optional) || (s != "" && len(s) <= max && utf8.ValidString(s) && !hasControl(s))
		err := checkText(s, max, optional)
		if (err == nil) != want {
			t.Fatalf("checkText(%q, %d, %v) = %v, want accepted = %v", s, max, optional, err, want)
		}
		if err != nil && !errors.Is(err, ErrInvalidText) {
			t.Fatalf("checkText(%q): %v, want ErrInvalidText", s, err)
		}
	})
}

// hasControl reports whether s has a control character.
func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// FuzzValidExposed checks the exposure rule against the Builder: validExposed
// accepts an ID exactly when the Builder accepts it as a node of an exposable
// kind, whatever prefix the ID has.
func FuzzValidExposed(f *testing.F) {
	for _, s := range []string{
		"unk:1.2.3.4", "host:1", "dev:sw", "guest:1", "unk:", "internet", "netbird", "host:a b", "host:é",
		"foo:bar", "", "unk:\x7f",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := validExposed(s)
		if err != nil && !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("validExposed(%q): %v, want ErrInvalidNode", s, err)
		}
		want := builderKinds(s, exposableKinds)
		switch {
		case len(want) > 1:
			t.Fatalf("the Builder accepts %q as %v: prefixes overlap", s, want)
		case err == nil && len(want) == 0:
			t.Fatalf("validExposed(%q) accepts, but the Builder rejects it as every exposable kind", s)
		case err != nil && len(want) == 1:
			t.Fatalf("validExposed(%q) rejects, but the Builder accepts it as %v", s, want[0])
		}
	})
}

// TestValidExposedBoundaries runs the exposure rule without the fuzzer.
func TestValidExposedBoundaries(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"unk:1.2.3.4", true},
		{"host:1", true},
		{"unk:", false},
		{"internet", false},
		{"netbird", false},
		{"host:a b", false},
		{"", false},
		{"unk:\x7f", false},
		{"foo:bar", false},
	}
	for _, tt := range tests {
		if err := validExposed(tt.id); (err == nil) != tt.ok {
			t.Fatalf("validExposed(%q) = %v, want accepted = %v", tt.id, err, tt.ok)
		}
	}
}
