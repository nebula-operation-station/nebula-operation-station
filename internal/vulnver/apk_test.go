// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"errors"
	"strings"
	"testing"
)

// apkOrderCases follow apk-tools' version ordering (Gentoo-style: numeric
// components, an optional letter, suffixes _alpha < _beta < _pre < _rc <
// release < _cvs < _svn < _git < _hg < _p, then -rN) and use real Alpine
// package versions.
var apkOrderCases = []struct {
	a, b string
	want int
}{
	{"1.0", "1.0", 0},
	{"1.0-r0", "1.0", 0}, // -r0 is the default revision
	{"1.0", "1.0-r1", -1},
	{"1.0-r1", "1.0-r2", -1},
	{"1.0-r9", "1.0-r10", -1},
	{"1.0", "1.1", -1},
	{"1.2.3", "1.2.10", -1},
	{"1.10", "1.9", 1},
	{"1.0", "1.0.0", -1},
	{"2", "10", -1},

	// Leading zeros in non-first components compare as fractions.
	{"1.01", "1.1", -1},
	{"1.01", "1.001", 1},
	{"1.010", "1.01", 0}, // trailing zeros are stripped in that mode
	{"1.1", "1.10", -1},
	{"01.0", "1.0", 0}, // first component is always numeric

	// Letters.
	{"1.0a", "1.0", 1},
	{"1.0a", "1.0b", -1},
	{"1.0z", "1.0.1", -1}, // more numeric components win first

	// Suffixes.
	{"1.0_alpha", "1.0_beta", -1},
	{"1.0_beta", "1.0_pre", -1},
	{"1.0_pre", "1.0_rc", -1},
	{"1.0_rc", "1.0", -1},
	{"1.0", "1.0_cvs", -1},
	{"1.0_cvs", "1.0_svn", -1},
	{"1.0_svn", "1.0_git", -1},
	{"1.0_git", "1.0_hg", -1},
	{"1.0_hg", "1.0_p", -1},
	{"1.0_rc1", "1.0_rc2", -1},
	{"1.0_rc", "1.0_rc0", 0},
	{"1.0_rc9", "1.0_rc10", -1},
	{"1.0_p1", "1.0_p2", -1},
	{"1.0_alpha1_p1", "1.0_alpha1", 1},
	{"1.0_alpha1_beta1", "1.0_alpha1", -1},
	{"1.0_rc1", "1.0.1_rc1", -1},
	{"1.0_rc1-r5", "1.0-r0", -1},
	{"1.0_git20240101", "1.0_git20240102", -1},
	{"1.0a_p1", "1.0b", -1},

	// Real Alpine lines.
	{"3.3.2-r0", "3.3.2-r1", -1},     // openssl 3.3.2 rebuild
	{"3.1.7-r0", "3.3.2-r0", -1},     // openssl across releases
	{"1.36.1-r29", "1.36.1-r30", -1}, // busybox
	{"8.9.1-r1", "8.11.0-r0", -1},    // curl
	{"2.12.10-r0", "2.12.9-r1", 1},   // apk-tools
	{"1.2.4_git20230717-r4", "1.2.5-r0", -1},
	{"6.4_p20231125-r0", "6.4_p20230506-r0", 1}, // ncurses
	{"6.4_p20231125-r0", "6.5_p20240601-r0", -1},
	{"99999999999999999999.0", "99999999999999999998.0", 1}, // no overflow
}

func TestCompareAPKVectors(t *testing.T) {
	for _, tc := range apkOrderCases {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got, err := CompareAPK(tc.a, tc.b)
			if err != nil {
				t.Fatalf("CompareAPK(%q, %q): %v", tc.a, tc.b, err)
			}
			if got != tc.want {
				t.Fatalf("CompareAPK(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			back, err := CompareAPK(tc.b, tc.a)
			if err != nil {
				t.Fatalf("CompareAPK(%q, %q): %v", tc.b, tc.a, err)
			}
			if back != -tc.want {
				t.Fatalf("CompareAPK(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, back, -tc.want)
			}
		})
	}
}

func TestParseAPKRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":                 "",
		"letter first":          "a1.0",
		"leading dot":           ".1",
		"trailing dot":          "1.",
		"double dot":            "1..0",
		"two letters":           "1.0ab",
		"unknown suffix":        "1.0_foo",
		"bare underscore":       "1.0_",
		"suffix before letter":  "1.0_rc1a",
		"revision without r":    "1.0-1",
		"revision empty":        "1.0-r",
		"revision letters":      "1.0-rx",
		"double revision":       "1.0-r1-r2",
		"trailing garbage":      "1.0-r1x",
		"commit hash":           "1.0~abc123", // not supported: unknown rather than guessed
		"space":                 "1.0 ",
		"uppercase letter":      "1.0A",
		"uppercase suffix":      "1.0_RC1",
		"dpkg style":            "1.0-1+deb12u1",
		"epoch":                 "1:1.0",
		"invalid utf-8":         "1.0\xff",
		"too long":              "1." + strings.Repeat("1", MaxVersionLen),
		"letter then digit dot": "1a.0",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAPK(in); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("ParseAPK(%q) err = %v, want ErrInvalidVersion", in, err)
			}
			if _, err := CompareAPK(in, "1.0"); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("CompareAPK(%q, 1.0) err = %v, want ErrInvalidVersion", in, err)
			}
			if _, err := CompareAPK("1.0", in); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("CompareAPK(1.0, %q) err = %v, want ErrInvalidVersion", in, err)
			}
		})
	}
}

func TestParseAPKRoundTrip(t *testing.T) {
	for _, in := range []string{"1.0", "1.2.3a_rc1_p2-r7", "6.4_p20231125-r0", "1.0-r0"} {
		v, err := ParseAPK(in)
		if err != nil {
			t.Fatalf("ParseAPK(%q): %v", in, err)
		}
		if v.String() != in {
			t.Fatalf("String() = %q, want %q", v.String(), in)
		}
	}
}

func TestCompareDispatchesByScheme(t *testing.T) {
	// "1.0-1" is a valid dpkg version but not a valid apk version.
	if _, err := Compare(SchemeDpkg, "1.0-1", "1.0"); err != nil {
		t.Fatalf("dpkg: %v", err)
	}
	if _, err := Compare(SchemeAPK, "1.0-1", "1.0"); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("apk err = %v, want ErrInvalidVersion", err)
	}
	if _, err := Compare(Scheme(0), "1", "1"); !errors.Is(err, ErrUnsupportedEcosystem) {
		t.Fatalf("zero scheme err = %v, want ErrUnsupportedEcosystem", err)
	}
	if err := Validate(Scheme(99), "1"); !errors.Is(err, ErrUnsupportedEcosystem) {
		t.Fatalf("Validate unknown scheme err = %v", err)
	}
}

func TestAffectedIsStrictlyLess(t *testing.T) {
	cases := []struct {
		s                Scheme
		installed, fixed string
		want             bool
	}{
		{SchemeDpkg, "1.2-3", "1.2-3+deb12u1", true},
		{SchemeDpkg, "1.2-3+deb12u1", "1.2-3+deb12u1", false},
		{SchemeDpkg, "1.2-3+deb12u2", "1.2-3+deb12u1", false},
		{SchemeDpkg, "3.0.15-1~deb12u1", "3.0.15-1~deb12u1", false},
		{SchemeDpkg, "3.0.14-1~deb12u2", "3.0.15-1~deb12u1", true},
		{SchemeAPK, "3.3.2-r0", "3.3.2-r1", true},
		{SchemeAPK, "3.3.2-r1", "3.3.2-r1", false},
	}
	for _, tc := range cases {
		got, err := Affected(tc.s, tc.installed, tc.fixed)
		if err != nil {
			t.Fatalf("Affected(%v, %q, %q): %v", tc.s, tc.installed, tc.fixed, err)
		}
		if got != tc.want {
			t.Fatalf("Affected(%v, %q, %q) = %v, want %v", tc.s, tc.installed, tc.fixed, got, tc.want)
		}
	}
	if _, err := Affected(SchemeDpkg, "", "1.0"); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("empty installed err = %v", err)
	}
}
