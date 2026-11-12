// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"strings"
	"testing"
	"time"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

var hitsNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func daysAgo(d int) time.Time { return hitsNow.Add(-time.Duration(d) * 24 * time.Hour) }

func hitInput(t *testing.T, st nr.InputState, rules []nr.SecurityRule, hits ...RuleHits) *Input {
	t.Helper()
	in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})
	in.Now = func() time.Time { return hitsNow }
	if err := in.SetObservations(Observations{Hits: HitCounts{State: st, ObservedAt: hitsNow, Rules: hits}}); err != nil {
		t.Fatalf("SetObservations: %v", err)
	}
	return in
}

func TestZeroHits(t *testing.T) {
	r := rule("r", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web"))
	disabled := r
	disabled.Disabled = nr.Collected(true)
	disabledNC := r
	disabledNC.Disabled = nr.Field[bool]{}
	created := func(d int) nr.Field[time.Time] { return nr.Collected(daysAgo(d)) }
	tests := []struct {
		name   string
		r      nr.SecurityRule
		hits   []RuleHits
		state  State
		reason string
	}{
		{name: "zero hits 40 days since reset fires", r: r,
			hits:  []RuleHits{{RuleName: "r", ResetAt: daysAgo(40), Created: created(100)}},
			state: StateFinding, reason: "no hits in 40 days"},
		{name: "exactly 30 days fires", r: r,
			hits:  []RuleHits{{RuleName: "r", ResetAt: daysAgo(30), Created: created(100)}},
			state: StateFinding, reason: "no hits in 30 days"},
		{name: "window from later creation", r: r,
			hits:  []RuleHits{{RuleName: "r", ResetAt: daysAgo(100), Created: created(10)}},
			state: StateCannotDecide, reason: "observed 10 days"},
		{name: "29 days cannot decide", r: r,
			hits:  []RuleHits{{RuleName: "r", ResetAt: daysAgo(29), Created: created(100)}},
			state: StateCannotDecide, reason: "need 30"},
		{name: "hits no longer fires", r: r,
			hits:  []RuleHits{{RuleName: "r", Hits: 5, FirstHit: daysAgo(3), LastHit: daysAgo(1), ResetAt: daysAgo(40), Created: created(100)}},
			state: StateOK, reason: "5 hits"},
		{name: "disabled rule ok", r: disabled, hits: nil, state: StateOK, reason: "disabled"},
		{name: "disabled not collected", r: disabledNC,
			hits:  []RuleHits{{RuleName: "r", ResetAt: daysAgo(40), Created: created(100)}},
			state: StateDataNotCollected, reason: "disabled"},
		{name: "rule missing from hit counts", r: r, hits: []RuleHits{{RuleName: "other"}},
			state: StateCannotDecide, reason: "not in the hit counts"},
		{name: "duplicate hit entry", r: r,
			hits:  []RuleHits{{RuleName: "r", Hits: 1}, {RuleName: "r", ResetAt: daysAgo(40), Created: created(100)}},
			state: StateCannotDecide, reason: "more than once"},
		{name: "no reset time", r: r, hits: []RuleHits{{RuleName: "r", Created: created(100)}},
			state: StateCannotDecide, reason: "reset time not reported"},
		{name: "creation not collected", r: r, hits: []RuleHits{{RuleName: "r", ResetAt: daysAgo(40)}},
			state: StateDataNotCollected, reason: "creation time"},
		{name: "zero hits with last hit is inconsistent", r: r,
			hits:  []RuleHits{{RuleName: "r", LastHit: daysAgo(2), ResetAt: daysAgo(40), Created: created(100)}},
			state: StateCannotDecide, reason: "inconsistent"},
		{name: "reset after observation", r: r,
			hits:  []RuleHits{{RuleName: "r", ResetAt: hitsNow.Add(time.Hour), Created: created(100)}},
			state: StateCannotDecide, reason: "after the observation"},
		{name: "hits with reset after observation", r: r,
			hits:  []RuleHits{{RuleName: "r", Hits: 3, ResetAt: hitsNow.Add(time.Hour), Created: created(100)}},
			state: StateCannotDecide, reason: "after the observation"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := HitsCheck{}.Run(hitInput(t, nr.InputFresh, []nr.SecurityRule{tc.r}, tc.hits...))
			if rep.State != StateOK {
				t.Fatalf("report state %s: %s", rep.State, rep.Reason)
			}
			f := byRule(t, rep, CheckZeroHits, 0)
			if f.State != tc.state || !strings.Contains(f.Reason, tc.reason) {
				t.Errorf("got %s %q, want %s containing %q", f.State, f.Reason, tc.state, tc.reason)
			}
			if f.State == StateFinding {
				if f.Hits == nil || f.Hits.ResetAt.IsZero() || f.Hits.Window < MinZeroHitsWindow {
					t.Errorf("finding without reset time or window evidence: %+v", f.Hits)
				}
				if !strings.Contains(f.Reason, "not a delete proposal") {
					t.Errorf("reason %q must say it is not a delete proposal", f.Reason)
				}
			}
		})
	}
}

// TestZeroHitsOnlyFromFreshData: stale, incomplete or missing hit counts,
// or a stale policy, never give ok (which would resolve a finding) and
// never a new finding.
func TestZeroHitsOnlyFromFreshData(t *testing.T) {
	rules := []nr.SecurityRule{
		rule("busy", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web")),
		rule("idle", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-http")),
	}
	hits := []RuleHits{
		{RuleName: "busy", Hits: 9, ResetAt: daysAgo(40), Created: nr.Collected(daysAgo(90))},
		{RuleName: "idle", ResetAt: daysAgo(40), Created: nr.Collected(daysAgo(90))},
	}
	tests := []struct {
		name  string
		st    nr.InputState
		stale nr.InputKind
		want  State
	}{
		{name: "hit counts stale", st: nr.InputStale, want: StateCannotDecide},
		{name: "hit counts incomplete", st: nr.InputIncomplete, want: StateCannotDecide},
		{name: "hit counts missing", st: nr.InputMissing, want: StateDataNotCollected},
		{name: "rules stale", st: nr.InputFresh, stale: nr.InputSecurityRules, want: StateCannotDecide},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := labSnapshot(rules...)
			if tc.stale != "" {
				snap.Inputs[tc.stale] = nr.Input{State: nr.InputStale}
			}
			in := newInput(t, snap, nr.Field[map[string]ProfileSetting]{})
			in.Now = func() time.Time { return hitsNow }
			if err := in.SetObservations(Observations{Hits: HitCounts{State: tc.st, ObservedAt: hitsNow, Rules: hits}}); err != nil {
				t.Fatal(err)
			}
			rep := HitsCheck{}.Run(in)
			if rep.State != tc.want {
				t.Errorf("report state %s, want %s", rep.State, tc.want)
			}
			for _, f := range rep.Findings {
				if f.State != tc.want {
					t.Errorf("rule %s: %s, want %s", f.RuleName, f.State, tc.want)
				}
			}
		})
	}
	// Without SetObservations the hit counts are missing.
	rep := HitsCheck{}.Run(newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{}))
	if rep.State != StateDataNotCollected {
		t.Errorf("no observations: %s", rep.State)
	}
	// Fresh counts without an observation time cannot be windowed.
	in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})
	if err := in.SetObservations(Observations{Hits: HitCounts{State: nr.InputFresh, Rules: hits}}); err != nil {
		t.Fatal(err)
	}
	if rep := (HitsCheck{}).Run(in); rep.State != StateCannotDecide {
		t.Errorf("no observation time: %s", rep.State)
	}
}

// TestZeroHitsFutureObservationCannotDecide: hit counts observed after
// the injected clock (a skewed or forged ObservedAt) would stretch the
// observed window; they give cannot_decide for every rule, never a
// finding and never ok.
func TestZeroHitsFutureObservationCannotDecide(t *testing.T) {
	rules := []nr.SecurityRule{
		rule("busy", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web")),
		rule("idle", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-http")),
	}
	hits := []RuleHits{
		{RuleName: "busy", Hits: 9, ResetAt: daysAgo(1), Created: nr.Collected(daysAgo(2))},
		{RuleName: "idle", ResetAt: daysAgo(1), Created: nr.Collected(daysAgo(2))},
	}
	for _, tc := range []struct {
		name     string
		observed time.Time
		want     State
	}{
		{"observed 400 days ahead", hitsNow.Add(400 * 24 * time.Hour), StateCannotDecide},
		{"observed one second ahead", hitsNow.Add(time.Second), StateCannotDecide},
		{"observed now", hitsNow, StateOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})
			in.Now = func() time.Time { return hitsNow }
			if err := in.SetObservations(Observations{Hits: HitCounts{State: nr.InputFresh, ObservedAt: tc.observed, Rules: hits}}); err != nil {
				t.Fatal(err)
			}
			rep := HitsCheck{}.Run(in)
			if rep.State != tc.want {
				t.Fatalf("report %s %q, want %s", rep.State, rep.Reason, tc.want)
			}
			if tc.want != StateCannotDecide {
				return
			}
			if !strings.Contains(rep.Reason, "after the current time") {
				t.Errorf("reason %q", rep.Reason)
			}
			for _, f := range rep.Findings {
				if f.State != StateCannotDecide {
					t.Errorf("rule %s: %s, want cannot_decide", f.RuleName, f.State)
				}
			}
		})
	}
	// Without an injected clock the observation time cannot be checked.
	in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})
	if err := in.SetObservations(Observations{Hits: HitCounts{State: nr.InputFresh, ObservedAt: hitsNow, Rules: hits}}); err != nil {
		t.Fatal(err)
	}
	rep := HitsCheck{}.Run(in)
	if rep.State != StateCannotDecide || !strings.Contains(rep.Reason, "no clock") {
		t.Errorf("nil clock: %s %q, want cannot_decide", rep.State, rep.Reason)
	}
	for _, f := range rep.Findings {
		if f.State != StateCannotDecide {
			t.Errorf("nil clock: rule %s: %s", f.RuleName, f.State)
		}
	}
}

func TestZeroHitsDuplicateRuleName(t *testing.T) {
	a := rule("r", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web"))
	b := a
	b.UUID = "uuid-other"
	rep := HitsCheck{}.Run(hitInput(t, nr.InputFresh, []nr.SecurityRule{a, b},
		RuleHits{RuleName: "r", Hits: 4, ResetAt: daysAgo(40), Created: nr.Collected(daysAgo(90))}))
	for i := range 2 {
		if f := byRule(t, rep, CheckZeroHits, i); f.State != StateCannotDecide {
			t.Errorf("rule %d: %s, want cannot_decide for an ambiguous name", i, f.State)
		}
	}
}

func TestSetObservationsRejects(t *testing.T) {
	in := newInput(t, labSnapshot(), nr.Field[map[string]ProfileSetting]{})
	long := strings.Repeat("n", nr.MaxNameBytes+1)
	tests := []struct {
		name string
		o    Observations
	}{
		{"unknown state", Observations{Hits: HitCounts{State: 99}}},
		{"hit name invalid UTF-8", Observations{Hits: HitCounts{Rules: []RuleHits{{RuleName: "r\xff"}}}}},
		{"hit name empty", Observations{Hits: HitCounts{Rules: []RuleHits{{}}}}},
		{"hit name too long", Observations{Hits: HitCounts{Rules: []RuleHits{{RuleName: long}}}}},
		{"too many hit entries", Observations{Hits: HitCounts{Rules: make([]RuleHits, MaxHitEntries+1)}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := in.SetObservations(tc.o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
