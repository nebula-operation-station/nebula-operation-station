// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// MinZeroHitsWindow is the minimum observed window of zero-hits (ADR 0012
// D4, the same rule as ADR 0010 ND-20): a rule fires only after at least
// 30 days without hits since the later of creation and counter reset.
const MinZeroHitsWindow = 30 * 24 * time.Hour

// HitEvidence is the evidence of a zero-hits result: the counter as the
// device reported it, the start of the observed window (the later of
// creation and reset) and the window length up to ObservedAt.
type HitEvidence struct {
	Hits       uint64
	FirstHit   time.Time
	LastHit    time.Time
	ResetAt    time.Time
	Created    time.Time
	Since      time.Time
	ObservedAt time.Time
	Window     time.Duration
}

// HitsCheck is the check zero-hits (ADR 0012 D4): an enabled rule with
// zero hits since the later of rule creation and counter reset, with at
// least MinZeroHitsWindow observed. It is never a delete proposal.
//
// Only fresh, complete hit counts decide: stale, incomplete or missing
// hit counts, or a stale security-rule input, give StateCannotDecide (or
// StateDataNotCollected) for every rule, so neither a new finding nor
// "no longer fires" comes from old data. Hit counts observed after the
// injected clock Input.Now (a skewed or forged ObservedAt that would
// stretch the observed window), or a nil clock, give StateCannotDecide
// for every rule as well. Per rule, a missing or ambiguous
// counter, a missing reset or creation time, inconsistent values or a
// window shorter than MinZeroHitsWindow give "cannot decide" too; only a
// counter with hits gives StateOK.
type HitsCheck struct{}

// ID returns CheckZeroHits.
func (HitsCheck) ID() string { return CheckZeroHits }

// Run runs the check over every rule, in rule order.
func (HitsCheck) Run(in *Input) Report {
	if st, why := precondition(in, netreach.InputSecurityRules); st != StateOK {
		return failedReport(CheckZeroHits, in, st, why)
	}
	h := &in.obs.Hits
	if st, why := observationState("hit counts", h.State); st != StateOK {
		return failedReport(CheckZeroHits, in, st, why)
	}
	if h.ObservedAt.IsZero() {
		return failedReport(CheckZeroHits, in, StateCannotDecide, "hit counts without observation time")
	}
	if in.Now == nil {
		return failedReport(CheckZeroHits, in, StateCannotDecide, "no clock: observation time of the hit counts cannot be checked")
	}
	if now := in.Now(); h.ObservedAt.After(now) {
		return failedReport(CheckZeroHits, in, StateCannotDecide, fmt.Sprintf("hit counts observed at %s, after the current time %s",
			h.ObservedAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)))
	}
	byName := make(map[string][]int, len(h.Rules))
	for i := range h.Rules {
		byName[h.Rules[i].RuleName] = append(byName[h.Rules[i].RuleName], i)
	}
	ruleNames := make(map[string]int, len(in.Snapshot.SecurityRules))
	for i := range in.Snapshot.SecurityRules {
		ruleNames[in.Snapshot.SecurityRules[i].Name]++
	}
	r := Report{CheckID: CheckZeroHits, CheckVersion: CheckVersion, State: StateOK}
	for i := range in.Snapshot.SecurityRules {
		sr := &in.Snapshot.SecurityRules[i]
		r.Findings = append(r.Findings, zeroHitsRule(i, sr, h.ObservedAt, ruleNames[sr.Name], h.Rules, byName[sr.Name]))
	}
	return r
}

func zeroHitsRule(i int, sr *netreach.SecurityRule, observed time.Time, sameName int, all []RuleHits, entries []int) Finding {
	f := newFinding(CheckZeroHits, i, sr)
	set := func(st State, why string) Finding {
		f.State, f.Reason = st, clean(why)
		return f
	}
	switch {
	case !sr.Disabled.Collected:
		return set(StateDataNotCollected, "data not collected: disabled not collected")
	case sr.Disabled.Value:
		return set(StateOK, "rule disabled")
	case sameName > 1:
		return set(StateCannotDecide, "cannot decide: rule name appears more than once in the policy")
	case len(entries) == 0:
		return set(StateCannotDecide, "cannot decide: rule not in the hit counts")
	case len(entries) > 1:
		return set(StateCannotDecide, "cannot decide: rule appears more than once in the hit counts")
	}
	h := all[entries[0]]
	ev := &HitEvidence{Hits: h.Hits, FirstHit: h.FirstHit, LastHit: h.LastHit, ResetAt: h.ResetAt, ObservedAt: observed}
	if h.Created.Collected {
		ev.Created = h.Created.Value
	}
	f.Hits = ev
	if !h.ResetAt.IsZero() && h.ResetAt.After(observed) {
		return set(StateCannotDecide, "cannot decide: counter reset time after the observation")
	}
	if h.Hits > 0 {
		return set(StateOK, fmt.Sprintf("%d hits since the counter reset", h.Hits))
	}
	switch {
	case !h.FirstHit.IsZero() || !h.LastHit.IsZero():
		return set(StateCannotDecide, "cannot decide: inconsistent counter (zero hits with a hit time)")
	case h.ResetAt.IsZero():
		return set(StateCannotDecide, "cannot decide: counter reset time not reported, observed window unknown")
	case !h.Created.Collected || h.Created.Value.IsZero():
		return set(StateDataNotCollected, "data not collected: rule creation time")
	case h.Created.Value.After(observed):
		return set(StateCannotDecide, "cannot decide: rule creation time after the observation")
	}
	ev.Since = h.ResetAt
	if h.Created.Value.After(ev.Since) {
		ev.Since = h.Created.Value
	}
	ev.Window = observed.Sub(ev.Since)
	days := int(ev.Window / (24 * time.Hour))
	if ev.Window < MinZeroHitsWindow {
		return set(StateCannotDecide, fmt.Sprintf("cannot decide: zero hits but observed %d days only, need %d", days, int(MinZeroHitsWindow/(24*time.Hour))))
	}
	f.Severity = SeverityInfo
	return set(StateFinding, fmt.Sprintf("no hits in %d days since %s (counter reset at %s); review the rule, this is not a delete proposal",
		days, ev.Since.UTC().Format(time.RFC3339), h.ResetAt.UTC().Format(time.RFC3339)))
}
