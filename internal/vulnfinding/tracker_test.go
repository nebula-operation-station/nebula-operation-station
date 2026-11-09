// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import (
	"errors"
	"testing"
)

// TestDebianTrackerStateMapping is the ADR 0011 D4 table: every tracker
// state maps to exactly one fix state and note.
func TestDebianTrackerStateMapping(t *testing.T) {
	cases := []struct {
		state TrackerState
		fix   FixState
		note  string
		opens bool
	}{
		{TrackerNotAffected, FixNotAffected, "", false},
		{TrackerFixed, FixFixed, "", true},
		{TrackerUnfixed, FixNoFixYet, "", true},
		{TrackerPostponed, FixNoFixYet, "postponed", true},
		{TrackerNoDSA, FixNoFixYet, "no DSA (may come in a point release)", true},
		{TrackerIgnored, FixWontFix, "ignored by the Debian security team", true},
		{TrackerEndOfLife, FixWontFix, "release end of life", true},
	}
	if len(cases) != len(AllTrackerStates()) {
		t.Fatalf("table covers %d states, package knows %d", len(cases), len(AllTrackerStates()))
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			m, err := MapDebianTrackerState(tc.state)
			if err != nil {
				t.Fatalf("MapDebianTrackerState: %v", err)
			}
			if m.Fix != tc.fix || m.Note != tc.note || m.Fix.Opens() != tc.opens {
				t.Fatalf("got %+v (opens %v), want fix %s note %q opens %v", m, m.Fix.Opens(), tc.fix, tc.note, tc.opens)
			}
		})
	}
	for _, s := range []TrackerState{"", "not-affected", "<NOT-AFFECTED>", "<unimportant>", "<undetermined>", "resolved", "open"} {
		if _, err := MapDebianTrackerState(s); !errors.Is(err, ErrInvalidField) {
			t.Fatalf("state %q: err = %v, want ErrInvalidField", s, err)
		}
	}
}

// TestTrackerStateMustMatchFix checks that a Debian distro_tracker record
// carries a tracker state and that its fix is the one target of that state.
func TestTrackerStateMustMatchFix(t *testing.T) {
	for _, state := range AllTrackerStates() {
		m, err := MapDebianTrackerState(state)
		if err != nil {
			t.Fatalf("map %s: %v", state, err)
		}
		for _, fix := range []FixState{FixFixed, FixNoFixYet, FixWontFix, FixNotAffected} {
			t.Run(string(state)+"/"+string(fix), func(t *testing.T) {
				r := mustParse(t, validHostJSON).Record
				r.TrackerState = state
				r.Fix = Fix{State: fix}
				if fix == FixFixed {
					r.Fix.Version = "3.0.16-1~deb12u1"
				}
				f, err := Validate(r)
				if fix == m.Fix {
					if err != nil {
						t.Fatalf("matching fix rejected: %v", err)
					}
					if f.TrackerNote != m.Note {
						t.Fatalf("note = %q, want %q", f.TrackerNote, m.Note)
					}
				} else if !errors.Is(err, ErrInconsistent) {
					t.Fatalf("err = %v, want ErrInconsistent", err)
				}
			})
		}
	}
	r := mustParse(t, validHostJSON).Record
	r.TrackerState = ""
	if _, err := Validate(r); !errors.Is(err, ErrMissingField) {
		t.Fatalf("missing tracker state: err = %v, want ErrMissingField", err)
	}
	img := mustParse(t, validImageJSON).Record
	img.TrackerState = TrackerUnfixed
	if _, err := Validate(img); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("tracker state on non-Debian record: err = %v, want ErrInconsistent", err)
	}
	osv := mustParse(t, validHostJSON).Record
	osv.MatchBasis = MatchOSVRange
	if _, err := Validate(osv); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("tracker state on osv_range record: err = %v, want ErrInconsistent", err)
	}
	osv.TrackerState = ""
	if _, err := Validate(osv); err != nil {
		t.Fatalf("Debian osv_range record without tracker state rejected: %v", err)
	}
}
