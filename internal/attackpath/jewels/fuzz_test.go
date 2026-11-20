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

// builderIDByte reports whether the attackpath Builder admits byte c in a
// node ID: printable ASCII [A-Za-z0-9._:/@-] (model.go validID).
func builderIDByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("._:/@-", c) >= 0
}

// builderAccepts reports the Builder's verdict on id as a node of kind.
func builderAccepts(id string, kind attackpath.NodeKind) error {
	return attackpath.NewBuilder().AddNode(attackpath.Node{ID: id, Kind: kind, Label: "x"})
}

// FuzzNodeKind checks the markable-ID rule against the Builder. NodeKind is
// the looser of the two: every ID the Builder accepts, NodeKind accepts with
// the same kind; and NodeKind accepts an ID the Builder rejects only when the
// ID has a byte outside the Builder's ASCII set. That last part records a
// known gap, see the comment at TestNodeKindKnownGapNonASCII.
func FuzzNodeKind(f *testing.F) {
	for _, s := range []string{
		"host:1", "pve:n1", "guest:100", "ctr:abc", "dev:sw1", "host:", "unk:x", "internet", "netbird",
		"host:a b", "host:\x00", "host:\xff", "host:é", "host:a/b@c.d-e_f:g",
		"ctr:" + strings.Repeat("a", attackpath.MaxIDBytes-len("ctr:")),
		"ctr:" + strings.Repeat("a", attackpath.MaxIDBytes-len("ctr:")+1),
		"", "host:" + string(rune(0x202e)),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := NodeKind(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidNode) || k != 0 {
				t.Fatalf("NodeKind(%q) = %v, %v: want ErrInvalidNode and kind 0", s, k, err)
			}
			for _, mk := range markableKinds {
				if builderAccepts(s, mk) == nil {
					t.Fatalf("NodeKind(%q) rejects, but the Builder accepts it as %v", s, mk)
				}
			}
			return
		}
		p := k.IDPrefix()
		if !strings.HasPrefix(s, p) || len(s) <= len(p) || len(s) > attackpath.MaxIDBytes {
			t.Fatalf("NodeKind(%q) = %v: prefix %q, length %d outside the rule", s, k, p, len(s))
		}
		if !utf8.ValidString(s) {
			t.Fatalf("NodeKind(%q) accepted invalid UTF-8", s)
		}
		for _, r := range s {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				t.Fatalf("NodeKind(%q) accepted control or space %U", s, r)
			}
		}
		for _, mk := range markableKinds {
			err := builderAccepts(s, mk)
			switch {
			case err == nil && mk != k:
				t.Fatalf("NodeKind(%q) = %v, but the Builder accepts it as %v", s, k, mk)
			case err != nil && mk == k && !errors.Is(err, attackpath.ErrInvalidNode):
				t.Fatalf("Builder rejects %q as %v with %v, not ErrInvalidNode", s, mk, err)
			case err != nil && mk == k && !hasNonBuilderByte(s):
				t.Fatalf("NodeKind(%q) accepts, the Builder rejects with %v, and all bytes are Builder bytes", s, err)
			}
		}
	})
}

// hasNonBuilderByte reports whether s has a byte the Builder's ID rule
// rejects.
func hasNonBuilderByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if !builderIDByte(s[i]) {
			return true
		}
	}
	return false
}

// TestNodeKindKnownGapNonASCII documents a known gap, not a passing rule.
// NodeKind("host:é") is accepted as a crown jewel target, but the Builder
// rejects the ID (ASCII only, ErrInvalidNode). The consequence is in the
// report of ticket ud08 (internal/attackpath/jewels, fuzz_test.go): the
// marked jewel reaches attackpath's prepareTargets, which refuses the whole
// computation with ErrInvalidTarget. Follow-up ticket: make NodeKind use the
// Builder's ID rule. When that lands, this test must change with it.
func TestNodeKindKnownGapNonASCII(t *testing.T) {
	// "host:!" is the smallest case: printable ASCII outside the Builder set.
	for _, id := range []string{"host:!", "host:é"} {
		if k, err := NodeKind(id); err != nil || k != attackpath.NodeHost {
			t.Fatalf("NodeKind(%q) = %v, %v: the documented gap no longer holds, update the report and this test", id, k, err)
		}
		if err := builderAccepts(id, attackpath.NodeHost); !errors.Is(err, attackpath.ErrInvalidNode) {
			t.Fatalf("Builder accepts %q (%v): the documented gap no longer holds", id, err)
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

// FuzzValidExposed checks the exposure rule against the Builder: an exposed
// ID the Builder accepts is accepted, and one it rejects is rejected unless
// the same known ASCII gap as NodeKind applies.
func FuzzValidExposed(f *testing.F) {
	for _, s := range []string{
		"unk:1.2.3.4", "host:1", "dev:sw", "guest:1", "unk:", "internet", "netbird", "host:a b", "host:é", "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := validExposed(s)
		if err != nil && !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("validExposed(%q): %v, want ErrInvalidNode", s, err)
		}
		for _, k := range exposableKinds {
			p := k.IDPrefix()
			if !strings.HasPrefix(s, p) || len(s) <= len(p) {
				continue
			}
			bErr := builderAccepts(s, k)
			switch {
			case bErr == nil && err != nil:
				t.Fatalf("validExposed(%q) rejects, the Builder accepts it as %v", s, k)
			case bErr != nil && err == nil && !hasNonBuilderByte(s):
				t.Fatalf("validExposed(%q) accepts, the Builder rejects it as %v with %v, and all bytes are Builder bytes", s, k, bErr)
			}
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
	}
	for _, tt := range tests {
		if err := validExposed(tt.id); (err == nil) != tt.ok {
			t.Fatalf("validExposed(%q) = %v, want accepted = %v", tt.id, err, tt.ok)
		}
	}
}
