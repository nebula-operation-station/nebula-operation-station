// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"errors"
	"strings"
	"testing"
)

// dpkgOrderCases are ordered pairs (a, b, sign of compare(a, b)). They come
// from Debian Policy §5.6.12 (the "~~ < ~~a < ~ < (empty) < a" example and
// the epoch, upstream and revision rules), from the dpkg test suite
// (lib/dpkg/t/t-version.c) and from real archive version lines.
var dpkgOrderCases = []struct {
	a, b string
	want int
}{
	// Equality and implicit parts.
	{"1.0", "1.0", 0},
	{"0:1.0", "1.0", 0},          // epoch 0 is the default
	{"1.0", "1.0-0", 0},          // absent revision compares like "0"
	{"1.001", "1.1", 0},          // numeric parts ignore leading zeros
	{"1.0-1", "0:1.0-01", 0},     // revision digits too
	{"0:0-0", "0", 0},            // minimal versions
	{"2.30-2", "2.30-2", 0},      // identical strings
	{"1:2.30-2", "01:2.30-2", 0}, // epoch is a number

	// Policy §5.6.12 tilde example: ~~ < ~~a < ~ < "" < a.
	{"1.0~~", "1.0~~a", -1},
	{"1.0~~a", "1.0~", -1},
	{"1.0~", "1.0", -1},
	{"1.0", "1.0a", -1},

	// Epochs dominate everything else.
	{"1:1.0", "2.0", 1},
	{"2:0", "1:9.9.9-99", 1},
	{"1:0.1", "0:99", 1},
	{"0:99", "1:0.1", -1},

	// Upstream ordering.
	{"1.0", "1.1", -1},
	{"1.2.3", "1.2.10", -1}, // numeric, not lexical
	{"1.10", "1.9", 1},
	{"1.0", "1.0.0", -1},
	{"1.0.0", "1.0.0.0", -1},
	{"1.0a", "1.0b", -1},
	{"1.0a", "1.0+", -1}, // letters sort before non-letters
	{"1.0+", "1.0.", -1}, // '+' (0x2b) before '.' (0x2e)
	{"1.0Z", "1.0a", -1}, // ASCII order among letters
	{"1.0~rc1", "1.0", -1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~beta", "1.0~rc", -1},
	{"1.0+dfsg", "1.0", 1},
	{"1.0+dfsg", "1.0.1", -1},
	{"99999999999999999999999999", "99999999999999999999999998", 1}, // no integer overflow
	{"1.00000000000000000000000001", "1.1", 0},

	// Revision ordering.
	{"1.0-1", "1.0", 1},
	{"1.0-1", "1.0-2", -1},
	{"1.0-10", "1.0-9", 1},
	{"1.0-1-1", "1.0-1", 1}, // last hyphen splits; upstream "1.0-1"

	// Debian stable and security updates: +debNNuM sorts after the base
	// revision and before the next one; ~debNNuM sorts before it.
	{"1.2-3", "1.2-3+deb12u1", -1},
	{"1.2-3+deb12u1", "1.2-3+deb12u2", -1},
	{"1.2-3+deb12u2", "1.2-4", -1},
	{"1.2-3+deb11u5", "1.2-3+deb12u1", -1},
	{"1.2-3~deb12u1", "1.2-3", -1},
	{"2.36-9+deb12u4", "2.36-9+deb12u10", -1},

	// Backports: ~bpoNN+M sorts before the version it was backported from.
	{"6.10.11-1~bpo12+1", "6.10.11-1", -1},
	{"6.10.11-1~bpo12+1", "6.10.6-1", 1},
	{"1.0-1~bpo12+1", "1.0-1~bpo12+2", -1},

	// Debian backports security fixes into old upstream versions: openssl
	// 3.0.15-1~deb12u1 is older than upstream 3.0.16 but newer than every
	// earlier bookworm upload (illustrative pair from ADR 0011 D4).
	{"3.0.15-1~deb12u1", "3.0.16-1", -1},
	{"3.0.14-1~deb12u2", "3.0.15-1~deb12u1", -1},
	{"3.0.11-1~deb12u2", "3.0.15-1~deb12u1", -1},
	{"3.0.15-1~deb12u1", "3.0.15-1", -1},

	// binNMU: the binary version 1.2-3+b1 sorts after its source 1.2-3.
	{"1.2-3+b1", "1.2-3", 1},
	{"1.2-3+b1", "1.2-3+b2", -1},
	{"1.2-3+b1", "1.2-4", -1},
	{"1.2-3+deb12u1+b1", "1.2-3+deb12u1", 1},

	// Ubuntu forms.
	{"1.2-3ubuntu0.1", "1.2-3ubuntu0.2", -1},
	{"1.2-3ubuntu0.1", "1.2-3", 1},
	{"1.2-3ubuntu0.1+esm1", "1.2-3ubuntu0.1", 1},
	{"6.8.0-45.45", "6.8.0-47.47", -1},
	{"6.8.0-45.45~22.04.1", "6.8.0-45.45", -1},
}

func TestCompareDpkgPolicyVectors(t *testing.T) {
	for _, tc := range dpkgOrderCases {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got, err := CompareDpkg(tc.a, tc.b)
			if err != nil {
				t.Fatalf("CompareDpkg(%q, %q): %v", tc.a, tc.b, err)
			}
			if got != tc.want {
				t.Fatalf("CompareDpkg(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			back, err := CompareDpkg(tc.b, tc.a)
			if err != nil {
				t.Fatalf("CompareDpkg(%q, %q): %v", tc.b, tc.a, err)
			}
			if back != -tc.want {
				t.Fatalf("CompareDpkg(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, back, -tc.want)
			}
		})
	}
}

func TestParseDpkgSplitsEpochUpstreamRevision(t *testing.T) {
	cases := []struct {
		in                  string
		epoch               uint32
		upstream, revision  string
		hasEpoch, hasRevNum bool
	}{
		{"1.0", 0, "1.0", "", false, false},
		{"1:1.0", 1, "1.0", "", true, false},
		{"1:1.0-1-2", 1, "1.0-1", "2", true, true},
		{"3.0.15-1~deb12u1", 0, "3.0.15", "1~deb12u1", false, true},
		{"2147483647:1", 2147483647, "1", "", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			v, err := ParseDpkg(tc.in)
			if err != nil {
				t.Fatalf("ParseDpkg(%q): %v", tc.in, err)
			}
			if v.Epoch != tc.epoch || v.Upstream != tc.upstream || v.Revision != tc.revision {
				t.Fatalf("ParseDpkg(%q) = %+v", tc.in, v)
			}
			if v.String() != tc.in {
				t.Fatalf("String() = %q, want %q", v.String(), tc.in)
			}
		})
	}
}

func TestParseDpkgRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":                   "",
		"only epoch":              "1:",
		"empty epoch":             ":1.0",
		"non-digit epoch":         "a:1.0",
		"negative epoch":          "-1:1.0",
		"epoch overflow":          "2147483648:1.0",
		"huge epoch":              "99999999999999999999:1.0",
		"upstream not digit":      "a1.0",
		"upstream starts tilde":   "~1.0",
		"empty upstream":          "1:-1",
		"empty revision":          "1.0-",
		"colon in upstream":       "1:1.0:2",
		"bad char upstream":       "1.0_1",
		"bad char revision":       "1.0-1_1",
		"colon in revision":       "1.0-1:2",
		"space":                   "1.0 1",
		"leading space":           " 1.0",
		"trailing newline":        "1.0\n",
		"nul":                     "1.0\x00",
		"non-ascii":               "1.0é",
		"invalid utf-8":           "1.0\xff",
		"slash":                   "1.0/1",
		"too long":                "1." + strings.Repeat("1", MaxVersionLen),
		"hyphen only":             "-",
		"revision bad first char": "1.0-:",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDpkg(in); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("ParseDpkg(%q) err = %v, want ErrInvalidVersion", in, err)
			}
			if _, err := CompareDpkg(in, "1.0"); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("CompareDpkg(%q, 1.0) err = %v, want ErrInvalidVersion", in, err)
			}
			if _, err := CompareDpkg("1.0", in); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("CompareDpkg(1.0, %q) err = %v, want ErrInvalidVersion", in, err)
			}
		})
	}
}

func TestParseDpkgErrorDoesNotEchoHugeInput(t *testing.T) {
	in := "x" + strings.Repeat("A", 10000)
	_, err := ParseDpkg(in)
	if err == nil {
		t.Fatal("want error")
	}
	if len(err.Error()) > 200 {
		t.Fatalf("error message is %d bytes; untrusted input must not be echoed in full", len(err.Error()))
	}
}

func TestParseDpkgAcceptsMaxLength(t *testing.T) {
	in := "1." + strings.Repeat("1", MaxVersionLen-2)
	if _, err := ParseDpkg(in); err != nil {
		t.Fatalf("version of exactly MaxVersionLen bytes rejected: %v", err)
	}
}
