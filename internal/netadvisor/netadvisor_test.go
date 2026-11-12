// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

func TestNewInputRejects(t *testing.T) {
	tooManyClasses := map[string]TrustClass{}
	for i := range MaxZoneClasses + 1 {
		tooManyClasses[fmt.Sprint("z", i)] = TrustGuest
	}
	atLimitClasses := map[string]TrustClass{}
	for i := range MaxZoneClasses {
		atLimitClasses[fmt.Sprint("z", i)] = TrustGuest
	}
	tooManyProfiles := ProfileSetting{Profiles: make([]string, MaxProfilesPerRule+1)}
	longName := strings.Repeat("n", nr.MaxNameBytes)
	tests := []struct {
		name    string
		snap    *nr.Snapshot
		classes map[string]TrustClass
		prof    nr.Field[map[string]ProfileSetting]
		ok      bool
	}{
		{name: "valid", snap: labSnapshot(), ok: true},
		{name: "no snapshot", snap: nil},
		{name: "invalid rule name", snap: labSnapshot(rule("bad\xff", allow, s("any"), s("any"), s("any"), s("any"), s("any")))},
		{name: "zone classes at limit", snap: labSnapshot(), classes: atLimitClasses, ok: true},
		{name: "zone classes over limit", snap: labSnapshot(), classes: tooManyClasses},
		{name: "profiles per rule at limit", snap: labSnapshot(), ok: true,
			prof: nr.Collected(map[string]ProfileSetting{"u": {Profiles: make([]string, MaxProfilesPerRule)}})},
		{name: "profiles per rule over limit", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": tooManyProfiles})},
		{name: "profile name at byte limit", snap: labSnapshot(), ok: true,
			prof: nr.Collected(map[string]ProfileSetting{"u": {Profiles: s(longName)}})},
		{name: "profile name over byte limit", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": {Profiles: s(longName + "x")}})},
		{name: "profile name invalid UTF-8", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": {Profiles: s("av\xff")}})},
		{name: "group at byte limit", snap: labSnapshot(), ok: true,
			prof: nr.Collected(map[string]ProfileSetting{"u": {Group: longName}})},
		{name: "group over byte limit", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": {Group: longName + "x"}})},
		{name: "group invalid UTF-8", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": {Group: "\xc3"}})},
		{name: "dropped marker over byte limit", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": {Dropped: s("<dropped:" + longName + ">")}})},
		{name: "dropped marker invalid UTF-8", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u": {Dropped: s("<dropped:\xff>")}})},
		{name: "rule UUID over byte limit", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{longName + "x": {Group: "g"}})},
		{name: "rule UUID invalid UTF-8", snap: labSnapshot(),
			prof: nr.Collected(map[string]ProfileSetting{"u\xff": {Group: "g"}})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewInput(tc.snap, tc.classes, tc.prof)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalidInput) {
				t.Errorf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestCleanText(t *testing.T) {
	if got := clean("a\x1b[31mb" + string(rune(0x202e)) + "c\xff"); got != "a�[31mb�c�" {
		t.Errorf("clean = %q", got)
	}
	long := clean(strings.Repeat("é", MaxTextBytes))
	if len(long) > MaxTextBytes || !utf8.ValidString(long) {
		t.Errorf("clean long: %d bytes, valid %v", len(long), utf8.ValidString(long))
	}
}

func TestChecksIDsAndStates(t *testing.T) {
	want := []string{CheckShadowedRule, CheckAnyAny, CheckAllowWithoutProfile}
	cs := Checks()
	if len(cs) != len(want) {
		t.Fatalf("checks = %d, want %d", len(cs), len(want))
	}
	for i, c := range cs {
		if c.ID() != want[i] {
			t.Errorf("check %d ID = %s, want %s", i, c.ID(), want[i])
		}
	}
	for _, st := range []State{StateOK, StateFinding} {
		if !st.Evaluated() {
			t.Errorf("%s not evaluated", st)
		}
	}
	for _, st := range []State{StateCannotDecide, StateDataNotCollected, ""} {
		if st.Evaluated() {
			t.Errorf("%q evaluated", st)
		}
	}
}

// TestUnevaluableSnapshotNeverOK runs every check on a snapshot collected
// before NS-04 (no Q11 fields, no default rules, no profile data) with
// rules that would fire on complete data: no check reports ok for them.
func TestUnevaluableSnapshotNeverOK(t *testing.T) {
	strip := func(r nr.SecurityRule) nr.SecurityRule {
		r.NegateSource, r.NegateDestination = nr.Field[bool]{}, nr.Field[bool]{}
		r.Type = nr.Field[nr.RuleType]{}
		r.SourceHIP, r.DestinationHIP = nr.Field[[]string]{}, nr.Field[[]string]{}
		return r
	}
	snap := labSnapshot(
		strip(rule("a", allow, s("guest"), s("lan"), s("any"), s("any"), s("svc-web"))),
		strip(rule("b", allow, s("guest"), s("lan"), s("any"), s("any"), s("svc-web"))),
	)
	snap.DefaultRules = nr.Field[nr.DefaultRules]{}
	in := newInput(t, snap, nr.Field[map[string]ProfileSetting]{})
	for _, c := range Checks() {
		for _, f := range c.Run(in).Findings {
			if f.State == StateOK {
				t.Errorf("%v: ok on an unevaluable snapshot", f)
			}
		}
	}
}
