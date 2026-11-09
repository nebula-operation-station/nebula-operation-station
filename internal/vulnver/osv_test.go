// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"errors"
	"strings"
	"testing"
)

func TestSchemeForEcosystem(t *testing.T) {
	ok := map[string]Scheme{
		"debian:bookworm": SchemeDpkg,
		"debian:12":       SchemeDpkg,
		"ubuntu:24.04":    SchemeDpkg,
		"alpine:3.20":     SchemeAPK,
	}
	for eco, want := range ok {
		got, err := SchemeForEcosystem(eco)
		if err != nil || got != want {
			t.Fatalf("SchemeForEcosystem(%q) = %v, %v; want %v", eco, got, err, want)
		}
	}
	for _, eco := range []string{"", "debian", "debian:", "Debian:12", "npm", "Go", "PyPI", "proxmox",
		"vendor:cisco:ios", "alpine", ":3.20", "debian:bookworm\n", "debian:" + strings.Repeat("x", 100)} {
		if _, err := SchemeForEcosystem(eco); !errors.Is(err, ErrUnsupportedEcosystem) {
			t.Fatalf("SchemeForEcosystem(%q) err = %v, want ErrUnsupportedEcosystem", eco, err)
		}
	}
}

func ev(kind EventKind, v string) Event { return Event{Kind: kind, Version: v} }

func TestOSVRangeEvaluation(t *testing.T) {
	introduced0Fixed := []Range{{Type: RangeEcosystem, Events: []Event{
		ev(EventIntroduced, "0"), ev(EventFixed, "1.2-3+deb12u1"),
	}}}
	twoWindows := []Range{{Type: RangeEcosystem, Events: []Event{
		// Deliberately unsorted: evaluation sorts by version.
		ev(EventFixed, "2.0-2"), ev(EventIntroduced, "1.0-1"), ev(EventFixed, "1.0-5"), ev(EventIntroduced, "2.0-1"),
	}}}
	lastAffected := []Range{{Type: RangeEcosystem, Events: []Event{
		ev(EventIntroduced, "1.0-1"), ev(EventLastAffected, "1.0-4"),
	}}}
	limited := []Range{{Type: RangeEcosystem, Events: []Event{
		ev(EventIntroduced, "0"), ev(EventLimit, "3.0-1"),
	}}}
	openEnded := []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "1.5-1")}}}
	apkRange := []Range{{Type: RangeEcosystem, Events: []Event{
		ev(EventIntroduced, "0"), ev(EventFixed, "3.3.2-r1"),
	}}}
	sameVersion := []Range{{Type: RangeEcosystem, Events: []Event{
		ev(EventFixed, "1.0-1"), ev(EventIntroduced, "1.0-1"),
	}}}
	twoRanges := []Range{
		{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "1.0-1"), ev(EventFixed, "1.0-3")}},
		{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "2.0-1"), ev(EventFixed, "2.0-3")}},
	}

	cases := []struct {
		name    string
		scheme  Scheme
		version string
		ranges  []Range
		want    bool
	}{
		{"before fix", SchemeDpkg, "1.2-3", introduced0Fixed, true},
		{"at fix", SchemeDpkg, "1.2-3+deb12u1", introduced0Fixed, false},
		{"after fix", SchemeDpkg, "1.2-4", introduced0Fixed, false},
		{"epoch beats fix", SchemeDpkg, "1:0.1-1", introduced0Fixed, false},
		{"tilde before fix", SchemeDpkg, "1.2-3+deb12u1~1", introduced0Fixed, true},
		{"below first window", SchemeDpkg, "0.9-1", twoWindows, false},
		{"in first window", SchemeDpkg, "1.0-4", twoWindows, true},
		{"between windows", SchemeDpkg, "1.5-1", twoWindows, false},
		{"in second window", SchemeDpkg, "2.0-1", twoWindows, true},
		{"after second window", SchemeDpkg, "2.0-2", twoWindows, false},
		{"last_affected inclusive", SchemeDpkg, "1.0-4", lastAffected, true},
		{"after last_affected", SchemeDpkg, "1.0-4+deb12u1", lastAffected, false},
		{"before introduced", SchemeDpkg, "1.0-0", lastAffected, false},
		{"below limit", SchemeDpkg, "2.9-1", limited, true},
		{"at limit", SchemeDpkg, "3.0-1", limited, false},
		{"open ended", SchemeDpkg, "9.9-1", openEnded, true},
		{"open ended before", SchemeDpkg, "1.4-1", openEnded, false},
		{"apk before fix", SchemeAPK, "3.3.2-r0", apkRange, true},
		{"apk at fix", SchemeAPK, "3.3.2-r1", apkRange, false},
		{"introduced and fixed equal", SchemeDpkg, "1.0-1", sameVersion, false},
		{"second of two ranges", SchemeDpkg, "2.0-2", twoRanges, true},
		{"outside both ranges", SchemeDpkg, "1.5-1", twoRanges, false},
		{"no ranges", SchemeDpkg, "1.0-1", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OSVAffected(tc.scheme, tc.version, tc.ranges)
			if err != nil {
				t.Fatalf("OSVAffected: %v", err)
			}
			if got != tc.want {
				t.Fatalf("OSVAffected(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestOSVRangeRejectsMalformed(t *testing.T) {
	many := make([]Event, MaxRangeEvents+1)
	for i := range many {
		many[i] = ev(EventIntroduced, "1.0")
	}
	manyRanges := make([]Range, MaxRanges+1)
	for i := range manyRanges {
		manyRanges[i] = Range{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0")}}
	}
	cases := []struct {
		name    string
		scheme  Scheme
		version string
		ranges  []Range
		want    error
	}{
		{"semver range", SchemeDpkg, "1.0", []Range{{Type: "SEMVER", Events: []Event{ev(EventIntroduced, "0")}}}, ErrUnsupportedRange},
		{"git range", SchemeDpkg, "1.0", []Range{{Type: "GIT", Events: []Event{ev(EventIntroduced, "0")}}}, ErrUnsupportedRange},
		{"empty type", SchemeDpkg, "1.0", []Range{{Events: []Event{ev(EventIntroduced, "0")}}}, ErrUnsupportedRange},
		{"no events", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem}}, ErrInvalidRange},
		{"no introduced", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventFixed, "2.0")}}}, ErrInvalidRange},
		{"unknown event kind", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0"), ev(EventKind(99), "2.0")}}}, ErrInvalidRange},
		{"zero event kind", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0"), {Version: "2.0"}}}}, ErrInvalidRange},
		{"fixed and last_affected", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0"), ev(EventFixed, "2.0"), ev(EventLastAffected, "1.5")}}}, ErrInvalidRange},
		{"empty fixed version", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0"), ev(EventFixed, "")}}}, ErrInvalidVersion},
		{"invalid fixed version", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0"), ev(EventFixed, "x1")}}}, ErrInvalidVersion},
		{"invalid introduced", SchemeAPK, "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "1.0-1")}}}, ErrInvalidVersion},
		{"invalid installed", SchemeDpkg, "", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0")}}}, ErrInvalidVersion},
		{"invalid installed no ranges", SchemeDpkg, "~", nil, ErrInvalidVersion},
		{"too many events", SchemeDpkg, "1.0", []Range{{Type: RangeEcosystem, Events: many}}, ErrInvalidRange},
		{"too many ranges", SchemeDpkg, "1.0", manyRanges, ErrInvalidRange},
		{"unknown scheme", Scheme(7), "1.0", []Range{{Type: RangeEcosystem, Events: []Event{ev(EventIntroduced, "0")}}}, ErrUnsupportedEcosystem},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OSVAffected(tc.scheme, tc.version, tc.ranges)
			if !errors.Is(err, tc.want) {
				t.Fatalf("OSVAffected err = %v, want %v", err, tc.want)
			}
			if got {
				t.Fatal("an error must never come with affected = true")
			}
		})
	}
}
