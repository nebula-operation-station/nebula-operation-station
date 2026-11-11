// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"slices"
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

func TestProfileCheck(t *testing.T) {
	guestToLAN := func() nr.SecurityRule {
		return rule("r", allow, s("guest"), s("lan"), s("any"), s("lan-net"), s("svc-web"))
	}
	with := func(f func(*nr.SecurityRule)) nr.SecurityRule {
		r := guestToLAN()
		f(&r)
		return r
	}
	collected := func(m map[string]ProfileSetting) nr.Field[map[string]ProfileSetting] { return nr.Collected(m) }
	none := collected(map[string]ProfileSetting{"uuid-r": {}})
	tests := []struct {
		name     string
		r        nr.SecurityRule
		profiles nr.Field[map[string]ProfileSetting]
		classes  map[string]TrustClass
		state    State
		reason   string
		zones    []string
	}{
		{name: "guest rule without profile", r: guestToLAN(), profiles: none, state: StateFinding, zones: s("guest")},
		{
			name: "toward untrusted zone without profile", profiles: none, state: StateFinding, zones: s("wan"),
			r: with(func(r *nr.SecurityRule) { r.From, r.To = list("lan"), list("wan") }),
		},
		{
			name: "zone any includes untrusted zones", profiles: none, state: StateFinding, zones: s("guest", "wan"),
			r: with(func(r *nr.SecurityRule) { r.From = list("any") }),
		},
		{
			name: "zone without class counts as untrusted", profiles: none, state: StateFinding, zones: s("dmz"),
			r:       with(func(r *nr.SecurityRule) { r.From = list("dmz") }),
			classes: map[string]TrustClass{"lan": TrustInternal},
		},
		{
			name: "profile group set", r: guestToLAN(), state: StateOK,
			profiles: collected(map[string]ProfileSetting{"uuid-r": {Group: "strict"}}),
		},
		{
			name: "profiles set", r: guestToLAN(), state: StateOK,
			profiles: collected(map[string]ProfileSetting{"uuid-r": {Profiles: s("av", "vuln")}}),
		},
		{
			name: "internal only rule", profiles: none, state: StateOK, reason: "no untrusted",
			r: with(func(r *nr.SecurityRule) { r.From = list("dmz") }),
		},
		{name: "deny rule", profiles: none, state: StateOK, r: with(func(r *nr.SecurityRule) { r.Action = deny })},
		{name: "disabled rule", profiles: none, state: StateOK, r: with(func(r *nr.SecurityRule) { r.Disabled = nr.Collected(true) })},
		// Fail-safe.
		{
			name: "no NS-04 data", r: guestToLAN(), profiles: nr.Field[map[string]ProfileSetting]{},
			state: StateDataNotCollected, reason: "NS-04",
		},
		{
			name: "no NS-04 data for an internal rule", profiles: nr.Field[map[string]ProfileSetting]{},
			r:     with(func(r *nr.SecurityRule) { r.From = list("dmz") }),
			state: StateDataNotCollected, reason: "NS-04",
		},
		{
			name: "entry of the rule missing", r: guestToLAN(),
			profiles: collected(map[string]ProfileSetting{"uuid-other": {}}),
			state:    StateDataNotCollected, reason: "profile-setting of the rule",
		},
		{
			name: "dropped marker on the setting", r: guestToLAN(),
			profiles: collected(map[string]ProfileSetting{"uuid-r": {Dropped: s("<dropped:profiles>")}}),
			state:    StateCannotDecide, reason: "<dropped:profiles>",
		},
		{
			name: "dropped marker as profile name", r: guestToLAN(),
			profiles: collected(map[string]ProfileSetting{"uuid-r": {Profiles: s("<dropped:av>")}}),
			state:    StateCannotDecide, reason: "<dropped:av>",
		},
		{
			name: "rule without UUID", profiles: none, state: StateCannotDecide, reason: "no UUID",
			r: with(func(r *nr.SecurityRule) { r.UUID = "" }),
		},
		{
			name: "zones not collected", profiles: none, state: StateDataNotCollected, reason: "to not collected",
			r: with(func(r *nr.SecurityRule) { r.To = nr.Field[[]string]{} }),
		},
		{
			name: "zone with marker", profiles: none, state: StateCannotDecide, reason: "<dropped:zone>",
			r: with(func(r *nr.SecurityRule) { r.To = list("<dropped:zone>") }),
		},
		{
			name: "disabled not collected", profiles: none, state: StateDataNotCollected, reason: "disabled",
			r: with(func(r *nr.SecurityRule) { r.Disabled = nr.Field[bool]{} }),
		},
		{
			name: "unknown action", profiles: none, state: StateCannotDecide, reason: "unknown action",
			r: with(func(r *nr.SecurityRule) { r.Action = "maybe" }),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			classes := tc.classes
			if classes == nil {
				classes = labClasses
			}
			in, err := NewInput(labSnapshot(tc.r), classes, tc.profiles)
			if err != nil {
				t.Fatal(err)
			}
			rep := ProfileCheck{}.Run(in)
			f := byRule(t, rep, CheckAllowWithoutProfile, 0)
			if f.State != tc.state {
				t.Fatalf("state = %s (%q), want %s", f.State, f.Reason, tc.state)
			}
			if !strings.Contains(f.Reason, tc.reason) {
				t.Errorf("reason = %q, want %q", f.Reason, tc.reason)
			}
			if tc.zones != nil && !slices.Equal(f.Zones, tc.zones) {
				t.Errorf("zones = %v, want %v", f.Zones, tc.zones)
			}
			if (f.State == StateFinding) != (f.Severity == SeverityMedium) {
				t.Errorf("severity %q on state %s", f.Severity, f.State)
			}
			if !tc.profiles.Collected && rep.State != StateDataNotCollected {
				t.Errorf("report state = %s, want data_not_collected", rep.State)
			}
		})
	}
}
