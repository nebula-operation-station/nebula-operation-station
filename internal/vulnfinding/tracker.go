// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import "fmt"

// TrackerState is a Debian Security Tracker state of a source package in
// one release, as the tracker JSON spells it.
type TrackerState string

// Debian tracker states (ADR 0011 D4).
const (
	TrackerFixed       TrackerState = "fixed"
	TrackerUnfixed     TrackerState = "unfixed"
	TrackerNotAffected TrackerState = "<not-affected>"
	TrackerPostponed   TrackerState = "<postponed>"
	TrackerNoDSA       TrackerState = "<no-dsa>"
	TrackerIgnored     TrackerState = "<ignored>"
	TrackerEndOfLife   TrackerState = "<end-of-life>"
)

// TrackerMapping is the single target of a tracker state.
type TrackerMapping struct {
	// Fix is the fix state the record must carry.
	Fix FixState
	// Note is NOS's tracker note shown with the finding; empty if none.
	Note string
}

// trackerTable is the D4 table, one target per state. States the tracker
// knows but the ADR does not list (for example <unimportant>,
// <undetermined>) are rejected rather than guessed.
var trackerTable = map[TrackerState]TrackerMapping{
	TrackerNotAffected: {Fix: FixNotAffected},
	TrackerFixed:       {Fix: FixFixed},
	TrackerUnfixed:     {Fix: FixNoFixYet},
	TrackerPostponed:   {Fix: FixNoFixYet, Note: "postponed"},
	TrackerNoDSA:       {Fix: FixNoFixYet, Note: "no DSA (may come in a point release)"},
	TrackerIgnored:     {Fix: FixWontFix, Note: "ignored by the Debian security team"},
	TrackerEndOfLife:   {Fix: FixWontFix, Note: "release end of life"},
}

// AllTrackerStates returns every tracker state the D4 table maps.
func AllTrackerStates() []TrackerState {
	return []TrackerState{
		TrackerNotAffected, TrackerFixed, TrackerUnfixed, TrackerPostponed,
		TrackerNoDSA, TrackerIgnored, TrackerEndOfLife,
	}
}

// MapDebianTrackerState returns the one target of a Debian tracker state.
// For TrackerFixed the finding exists only while the installed source
// version is below the fixed version; that comparison is not done here.
func MapDebianTrackerState(s TrackerState) (TrackerMapping, error) {
	m, ok := trackerTable[s]
	if !ok {
		return TrackerMapping{}, fmt.Errorf("tracker_state: %w", ErrInvalidField)
	}
	return m, nil
}
