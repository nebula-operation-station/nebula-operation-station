// SPDX-License-Identifier: AGPL-3.0-or-later

package leasewatch

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

var testBase = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func lease(id string, expires time.Time) Grant {
	return Grant{ID: id, Name: "name-" + id, Kind: KindReadLease, ExpiresAt: expires}
}

// thresholds returns the threshold of each expiring event, in order.
func thresholds(events []Event) []time.Duration {
	var out []time.Duration
	for _, e := range events {
		out = append(out, e.Threshold)
	}
	return out
}

func mustExpiring(t *testing.T, grants []Grant, st State, now time.Time) ([]Event, State) {
	t.Helper()
	events, next, err := Expiring(grants, st, now)
	if err != nil {
		t.Fatalf("Expiring at %s: unexpected error: %v", now, err)
	}
	return events, next
}

func TestExpiringRulesWithInjectedTime(t *testing.T) {
	tests := []struct {
		name string
		// steps are evaluated in order, carrying the state from one to the next.
		steps []struct {
			at   time.Duration // offset from testBase
			grnt []Grant       // grants at this step; expiry is relative to testBase
			want []time.Duration
		}
	}{
		{
			name: "seven day warning fires once at threshold",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{0, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, nil},
				{3 * 24 * time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, []time.Duration{ExpiryWarnLong}},
				{3*24*time.Hour + time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, nil},
			},
		},
		{
			name: "one day warning fires after seven day warning",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{5 * 24 * time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, []time.Duration{ExpiryWarnLong}},
				{9*24*time.Hour + 12*time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, []time.Duration{ExpiryWarnShort}},
				{9*24*time.Hour + 13*time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, nil},
			},
		},
		{
			name: "first seen inside one day window reports only the short threshold",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{9*24*time.Hour + 12*time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, []time.Duration{ExpiryWarnShort}},
				{9*24*time.Hour + 13*time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, nil},
			},
		},
		{
			name: "grant far from expiry reports nothing",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{0, []Grant{lease("g1", testBase.Add(30*24*time.Hour))}, nil},
				{20 * 24 * time.Hour, []Grant{lease("g1", testBase.Add(30*24*time.Hour))}, nil},
			},
		},
		{
			name: "expired grant reports nothing, also exactly at expiry",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{10 * 24 * time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, nil},
				{11 * 24 * time.Hour, []Grant{lease("g1", testBase.Add(10*24*time.Hour))}, nil},
			},
		},
		{
			name: "revoked grant reports nothing",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{5 * 24 * time.Hour, []Grant{{ID: "g1", Name: "n", Kind: KindReadLease, ExpiresAt: testBase.Add(10 * 24 * time.Hour), Revoked: true}}, nil},
				{9*24*time.Hour + 12*time.Hour, []Grant{{ID: "g1", Name: "n", Kind: KindReadLease, ExpiresAt: testBase.Add(10 * 24 * time.Hour), Revoked: true}}, nil},
			},
		},
		{
			name: "schedule grant follows the same rules",
			steps: []struct {
				at   time.Duration
				grnt []Grant
				want []time.Duration
			}{
				{5 * 24 * time.Hour, []Grant{{ID: "s1", Name: "sched", Kind: KindScheduleGrant, ExpiresAt: testBase.Add(7 * 24 * time.Hour)}}, []time.Duration{ExpiryWarnLong}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var st State
			for i, step := range tt.steps {
				var events []Event
				events, st = mustExpiring(t, step.grnt, st, testBase.Add(step.at))
				got := thresholds(events)
				if !equalDurations(got, step.want) {
					t.Fatalf("step %d: thresholds = %v, want %v", i, got, step.want)
				}
			}
		})
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExpiringEventFieldsAndOrder(t *testing.T) {
	exp := testBase.Add(6 * 24 * time.Hour)
	grants := []Grant{
		{ID: "b", Name: "Second", Kind: KindScheduleGrant, ExpiresAt: exp},
		{ID: "a", Name: "First", Kind: KindReadLease, ExpiresAt: exp},
	}
	events, _ := mustExpiring(t, grants, State{}, testBase)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].GrantID != "a" || events[1].GrantID != "b" {
		t.Fatalf("events not ordered by grant ID: %q, %q", events[0].GrantID, events[1].GrantID)
	}
	for _, e := range events {
		if e.Type != EventExpiring {
			t.Errorf("type = %q, want %q", e.Type, EventExpiring)
		}
		if !e.ExpiresAt.Equal(exp) || !e.At.Equal(testBase) {
			t.Errorf("event %s: ExpiresAt/At = %s/%s, want %s/%s", e.GrantID, e.ExpiresAt, e.At, exp, testBase)
		}
	}
	if events[0].GrantName != "First" || events[0].Kind != KindReadLease {
		t.Errorf("event fields for a: name %q kind %q", events[0].GrantName, events[0].Kind)
	}
}

func TestExpiringDoesNotMutateInputState(t *testing.T) {
	grants := []Grant{lease("g1", testBase.Add(5*24*time.Hour))}
	st := State{}
	_, next := mustExpiring(t, grants, st, testBase)
	if len(st.Expiry) != 0 {
		t.Fatalf("input state mutated: %v", st.Expiry)
	}
	events, _ := mustExpiring(t, grants, next, testBase)
	if len(events) != 0 {
		t.Fatalf("second call with returned state emitted %d events", len(events))
	}
}

func TestExpiringClockRewindDoesNotRepeat(t *testing.T) {
	exp := testBase.Add(10 * 24 * time.Hour)
	grants := []Grant{lease("g1", exp)}
	var st State
	var events []Event
	events, st = mustExpiring(t, grants, st, testBase.Add(9*24*time.Hour+12*time.Hour))
	if got := thresholds(events); !equalDurations(got, []time.Duration{ExpiryWarnShort}) {
		t.Fatalf("first short event missing: %v", got)
	}
	// Clock jumps back to a time where neither threshold applies, then forward again.
	events, st = mustExpiring(t, grants, st, testBase)
	if len(events) != 0 {
		t.Fatalf("rewind emitted %d events", len(events))
	}
	events, _ = mustExpiring(t, grants, st, testBase.Add(9*24*time.Hour+18*time.Hour))
	if len(events) != 0 {
		t.Fatalf("forward again after rewind emitted %d events", len(events))
	}
}

func TestExpiringRewindAfterSevenDayWarningDoesNotRepeatLong(t *testing.T) {
	grants := []Grant{lease("g1", testBase.Add(10*24*time.Hour))}
	events, st := mustExpiring(t, grants, State{}, testBase.Add(4*24*time.Hour))
	if len(events) != 1 {
		t.Fatalf("long warning: got %d events", len(events))
	}
	events, _ = mustExpiring(t, grants, st, testBase.Add(5*24*time.Hour))
	if len(events) != 0 {
		t.Fatalf("long warning repeated: %d events", len(events))
	}
}

func TestExpiringPrunesRemovedGrants(t *testing.T) {
	exp := testBase.Add(5 * 24 * time.Hour)
	_, st := mustExpiring(t, []Grant{lease("g1", exp)}, State{}, testBase)
	if _, ok := st.Expiry["g1"]; !ok {
		t.Fatal("expected a mark for g1")
	}
	// g1 is removed from the list: its marks are dropped.
	_, st = mustExpiring(t, []Grant{lease("g2", exp)}, st, testBase)
	if _, ok := st.Expiry["g1"]; ok {
		t.Fatal("marks of removed grant g1 kept")
	}
	if _, ok := st.Expiry["g2"]; !ok {
		t.Fatal("expected a mark for g2")
	}
}

func TestExpiringRejectsInvalidGrants(t *testing.T) {
	exp := testBase.Add(3 * 24 * time.Hour)
	long := make([]byte, MaxIDLen+1)
	for i := range long {
		long[i] = 'x'
	}
	tests := []struct {
		name   string
		grants []Grant
	}{
		{"empty id", []Grant{lease("", exp)}},
		{"overlong id", []Grant{lease(string(long), exp)}},
		{"duplicate id", []Grant{lease("g1", exp), lease("g1", exp)}},
		{"unknown kind", []Grant{{ID: "g1", Kind: "bogus", ExpiresAt: exp}}},
		{"zero expiry", []Grant{{ID: "g1", Kind: KindReadLease}}},
		{"too many grants", manyGrants(MaxTrackedGrants+1, exp)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Expiring(tt.grants, State{}, testBase)
			if !errors.Is(err, ErrInvalidGrant) && !errors.Is(err, ErrTooManyGrants) {
				t.Fatalf("err = %v, want ErrInvalidGrant or ErrTooManyGrants", err)
			}
		})
	}
}

func manyGrants(n int, exp time.Time) []Grant {
	out := make([]Grant, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, lease(strconv.Itoa(i), exp))
	}
	return out
}
