// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// anySnapshot is the lab with an extra snapshot zone literally named
// "any".
func anySnapshot(rules ...nr.SecurityRule) *nr.Snapshot {
	snap := labSnapshot(rules...)
	snap.Zones = append(snap.Zones, nr.Zone{Name: "any"})
	return snap
}

// TestShadowAnyInZoneListCannotDecide: a zone list holding "any" next to
// other zones is ambiguous (netreach reads it as every zone, resolveZones
// refuses it). The shadow check agrees with resolveZones: such a rule is
// cannot_decide itself, and as an earlier rule it is never ignored, so a
// later rule it may match is not ok.
func TestShadowAnyInZoneListCannotDecide(t *testing.T) {
	mixed := func(name string, action nr.Action) nr.SecurityRule {
		return rule(name, action, s("any", "lan"), s("any"), s("any"), s("any"), s("any"))
	}
	tests := []struct {
		name  string
		rules []nr.SecurityRule
		i     int
	}{
		{"rule itself", []nr.SecurityRule{mixed("r", allow)}, 0},
		{"rule itself to list", []nr.SecurityRule{rule("r", allow, s("lan"), s("lan", "any"), s("any"), s("any"), s("any"))}, 0},
		{"later rule from wan", []nr.SecurityRule{mixed("broad", allow), rule("later", deny, s("wan"), s("dmz"), s("any"), s("any"), s("any"))}, 1},
		{"later rule from lan", []nr.SecurityRule{mixed("broad", allow), rule("later", deny, s("lan"), s("dmz"), s("any"), s("any"), s("any"))}, 1},
	}
	for _, snapName := range []string{"lab", "lab with zone any"} {
		for _, tc := range tests {
			t.Run(snapName+"/"+tc.name, func(t *testing.T) {
				snap := labSnapshot(tc.rules...)
				if snapName != "lab" {
					snap = anySnapshot(tc.rules...)
				}
				// Without a zone named "any" netreach already refuses the
				// list ("zone any not in snapshot"); with one, the shadow
				// check must refuse it itself.
				reason := "any"
				if snapName != "lab" {
					reason = "has any next to other zones"
				}
				r := ShadowCheck{}.Run(newInput(t, snap, nr.Field[map[string]ProfileSetting]{}))
				for _, id := range []string{CheckShadowedRule, CheckOverlap} {
					f := byRule(t, r, id, tc.i)
					if f.State != StateCannotDecide || !strings.Contains(f.Reason, reason) {
						t.Errorf("%s = %s %q, want cannot_decide ... %s", id, f.State, f.Reason, reason)
					}
				}
			})
		}
	}
	// An earlier mixed list whose other zone list is disjoint from the
	// later rule cannot match it and does not block a decision.
	early := rule("early", allow, s("any", "lan"), s("mgmt"), s("any"), s("any"), s("any"))
	later := rule("later", deny, s("wan"), s("dmz"), s("any"), s("any"), s("any"))
	r := ShadowCheck{}.Run(newInput(t, anySnapshot(early, later), nr.Field[map[string]ProfileSetting]{}))
	for _, id := range []string{CheckShadowedRule, CheckOverlap} {
		if f := byRule(t, r, id, 1); f.State != StateOK {
			t.Errorf("disjoint to zone: %s = %v, want ok", id, f)
		}
	}
	// "any" alone still means every snapshot zone, the zone named "any"
	// included, as in resolveZones.
	r = ShadowCheck{}.Run(newInput(t, anySnapshot(
		rule("broad", allow, s("any"), s("any"), s("any"), s("any"), s("any")),
		rule("later", deny, s("any"), s("lan"), s("any"), s("any"), s("any")),
	), nr.Field[map[string]ProfileSetting]{}))
	if f := byRule(t, r, CheckShadowedRule, 1); f.State != StateFinding {
		t.Errorf("any alone: %v, want finding", f)
	}
}

// TestShadowPrepChecksBudget: the prep loop stops building match spaces
// once the shared budget is gone; every rule is then cannot_decide.
func TestShadowPrepChecksBudget(t *testing.T) {
	rules := partialOverlaps(30, list("any"))
	in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})
	// A budget that the prep of the first few rules already uses up.
	r := ShadowCheck{workPerSnapshot: 5}.Run(in)
	for i := range rules {
		wantLimit(t, r, i)
	}
}

// TestShadowPrepStopsEarly checks the prep loop directly: with a tiny
// shared budget it leaves the match spaces of later rules unbuilt.
func TestShadowPrepStopsEarly(t *testing.T) {
	rules := partialOverlaps(30, list("any"))
	in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})
	sh, ok := newShadowState(in, 5)
	if ok {
		t.Fatal("prep with budget 5 reported ok")
	}
	if b := sh.boxes[len(rules)-1]; b.src != nil || b.from != nil {
		t.Errorf("last rule box built after budget exhausted: %+v", b)
	}
}
