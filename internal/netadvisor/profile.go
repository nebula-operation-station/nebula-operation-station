// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// ProfileCheck is the check allow-without-profile (ADR 0012 D4): an
// enabled allow rule toward or from a zone of trust class untrusted or
// guest (or without a class, Q9) with no security profile and no profile
// group.
//
// It needs the NS-04 profile-setting data (ADR 0012 Q11). Without it every
// rule is StateDataNotCollected, never StateOK, and so is a relevant rule
// whose entry is missing; a <dropped:…> marker gives StateCannotDecide. A
// rule with a rule-level marker (SecurityRule.Dropped or
// OutsideAllowlist) is never StateOK.
type ProfileCheck struct{}

// ID returns CheckAllowWithoutProfile.
func (ProfileCheck) ID() string { return CheckAllowWithoutProfile }

var profileInputs = []netreach.InputKind{netreach.InputZones, netreach.InputSecurityRules}

// Run runs the check over every rule, in rule order.
func (ProfileCheck) Run(in *Input) Report {
	if st, why := precondition(in, profileInputs...); st != StateOK {
		return failedReport(CheckAllowWithoutProfile, in, st, why)
	}
	if !in.Profiles.Collected {
		return failedReport(CheckAllowWithoutProfile, in, StateDataNotCollected, "data not collected: profile-setting (NS-04)")
	}
	// The profile-setting is keyed by rule UUID: a UUID that several rules
	// carry cannot tell whose setting it is.
	uuids := make(map[string]int, len(in.Snapshot.SecurityRules))
	for i := range in.Snapshot.SecurityRules {
		uuids[in.Snapshot.SecurityRules[i].UUID]++
	}
	r := Report{CheckID: CheckAllowWithoutProfile, CheckVersion: CheckVersion, State: StateOK}
	for i := range in.Snapshot.SecurityRules {
		r.Findings = append(r.Findings, profileRule(in, i, uuids))
	}
	return r
}

// profileRule checks rule i; uuids counts the rules per UUID.
func profileRule(in *Input, i int, uuids map[string]int) Finding {
	r := &in.Snapshot.SecurityRules[i]
	f := newFinding(CheckAllowWithoutProfile, i, r)
	marker := ""
	set := func(st State, why string) Finding {
		if st == StateOK && marker != "" {
			// A rule-level marker: the dropped or unlisted field may
			// be the one that decides, so ok is never certain.
			st, why = StateCannotDecide, "cannot decide: "+marker
		}
		f.State, f.Reason = st, clean(why)
		return f
	}
	switch {
	case !r.Disabled.Collected:
		return set(StateDataNotCollected, "data not collected: disabled not collected")
	case r.Disabled.Value:
		return set(StateOK, "rule disabled")
	}
	marker = ruleMarker(r)
	switch r.Action {
	case netreach.ActionAllow:
	case netreach.ActionDeny, netreach.ActionDrop, netreach.ActionResetClient, netreach.ActionResetServer, netreach.ActionResetBoth:
		return set(StateOK, "not an allow rule")
	default:
		return set(StateCannotDecide, "cannot decide: unknown action")
	}
	var zones []string
	for _, zl := range []zoneList{in.resolveZones("from", r.From), in.resolveZones("to", r.To)} {
		if zl.why != "" {
			if zl.nc {
				return set(StateDataNotCollected, "data not collected: "+zl.why)
			}
			return set(StateCannotDecide, "cannot decide: "+zl.why)
		}
		for _, z := range zl.zones {
			if untrustedLike(in.zoneClass(z)) {
				zones = append(zones, z)
			}
		}
	}
	if len(zones) == 0 {
		return set(StateOK, "no untrusted or guest zone")
	}
	f.Zones = cleanAll(sortedUnique(zones))
	if r.UUID == "" {
		return set(StateCannotDecide, "cannot decide: rule has no UUID")
	}
	if uuids[r.UUID] > 1 {
		return set(StateCannotDecide, "cannot decide: rule UUID is not unique in the snapshot")
	}
	p, ok := in.Profiles.Value[r.UUID]
	if !ok {
		return set(StateDataNotCollected, "data not collected: profile-setting of the rule")
	}
	if len(p.Dropped) > 0 {
		return set(StateCannotDecide, "cannot decide: profile-setting has "+p.Dropped[0])
	}
	for _, n := range append([]string{p.Group}, p.Profiles...) {
		if hasMarker(n) {
			return set(StateCannotDecide, "cannot decide: profile-setting has "+n)
		}
	}
	if len(p.Profiles) > 0 || p.Group != "" {
		return set(StateOK, "security profile set")
	}
	f.Severity = SeverityMedium
	return set(StateFinding, "allow rule with untrusted or guest zone has no security profile: "+strings.Join(f.Zones, ", "))
}
