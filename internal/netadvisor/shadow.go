// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// ShadowCheck is the check shadowed-rule with its lower hint overlap
// (ADR 0012 D4). For every enabled rule it reports two findings, one per
// check ID:
//
//   - shadowed-rule fires when earlier enabled rules whose conditions
//     (application, source user, URL category, schedule) certainly include
//     the rule's own together cover its whole match space (zones, source
//     and destination addresses with negation, service). Order among the
//     earlier rules does not matter: whichever matches first, the rule is
//     never reached.
//   - overlap fires when the rule is not shadowed but an earlier evaluable
//     rule matches part of its match space.
//
// Fail-safe (ADR 0012 D2): the rule itself unevaluable, an earlier rule
// that is unevaluable and may match the rule's traffic, a covering set
// that needs a rule whose conditions cannot be compared, or a work limit
// give StateCannotDecide for both IDs, never StateOK.
type ShadowCheck struct{}

// ID returns CheckShadowedRule.
func (ShadowCheck) ID() string { return CheckShadowedRule }

// shadowInputs are the inputs the shadow check reads.
var shadowInputs = []netreach.InputKind{netreach.InputZones, netreach.InputSecurityRules, netreach.InputObjects}

// Run runs the check over every rule. The report carries the
// shadowed-rule findings followed by the overlap findings, both in rule
// order.
func (c ShadowCheck) Run(in *Input) Report {
	if st, why := precondition(in, shadowInputs...); st != StateOK {
		r := failedReport(CheckShadowedRule, in, st, why)
		o := failedReport(CheckOverlap, in, st, why)
		r.Findings = append(r.Findings, o.Findings...)
		return r
	}
	views := in.Index.SecurityRules()
	raws := in.Snapshot.SecurityRules
	var allZones []string
	for _, z := range in.Snapshot.Zones {
		allZones = append(allZones, z.Name)
	}
	allZones = sortedUnique(allZones)

	shared := MaxShadowWorkPerSnapshot
	shadowed := make([]Finding, len(views))
	overlap := make([]Finding, len(views))
	for i := range views {
		w := &work{max: MaxShadowWorkPerRule, shared: &shared}
		s, o := shadowRule(views, raws, allZones, i, w)
		shadowed[i], overlap[i] = s, o
	}
	return Report{
		CheckID:      CheckShadowedRule,
		CheckVersion: CheckVersion,
		State:        StateOK,
		Findings:     append(shadowed, overlap...),
	}
}

// candidate is an earlier rule that may take part in covering a rule.
type candidate struct {
	index int
	b     box
}

func shadowRule(views []netreach.RuleView, raws []netreach.SecurityRule, allZones []string, i int, w *work) (Finding, Finding) {
	sf := newFinding(CheckShadowedRule, i, &raws[i])
	of := newFinding(CheckOverlap, i, &raws[i])
	both := func(st State, why string) (Finding, Finding) {
		sf.State, sf.Reason = st, clean(why)
		of.State, of.Reason = st, clean(why)
		return sf, of
	}
	v := views[i]
	switch {
	case v.Disabled:
		return both(StateOK, "rule disabled")
	case !v.Evaluable():
		return both(StateCannotDecide, "cannot decide: "+v.Reason())
	}
	target := ruleBox(v, allZones, w)
	appDefault := v.Service.ApplicationDefault
	if appDefault {
		// The real ports are the default ports of the rule's
		// applications, a subset of every port: covering the whole
		// service dimension is enough, never needed.
		target.svc = fullService()
	}

	var definite, possible []candidate
	var definiteHit, overlapping, uneval, incomparable []string
	for j := range i {
		cv := views[j]
		if cv.Disabled {
			continue
		}
		if !cv.Evaluable() {
			if zonesExclude(&raws[j], target) {
				continue
			}
			uneval = append(uneval, cv.Reason())
			continue
		}
		cb := ruleBox(cv, allZones, w)
		sure := conditionsCover(&raws[j], &raws[i])
		if cv.Service.ApplicationDefault {
			cb.svc = fullService()
			// The default ports of the earlier rule's applications are
			// known to include the rule's own only when both use
			// application-default and the applications are included.
			sure = sure && appDefault
		}
		in := target.intersect(&cb, w)
		if w.exhausted() {
			return both(StateCannotDecide, "cannot decide: "+netreach.ErrLimitReached.Error())
		}
		if in.empty() {
			continue
		}
		name := clean(cv.Name)
		overlapping = append(overlapping, name)
		if sure {
			definite = append(definite, candidate{j, cb})
			definiteHit = append(definiteHit, name)
		} else {
			possible = append(possible, candidate{j, cb})
			incomparable = append(incomparable, name)
		}
	}

	switch covers(target, boxes(definite), w) {
	case fullyCovered:
		sf.State, sf.Covering = StateFinding, definiteHit
		sf.Severity = shadowSeverity(&raws[i], raws, definite)
		if len(definiteHit) == 0 {
			sf.Reason = "rule matches no traffic (empty match space)"
		} else {
			sf.Reason = clean("rule never matches: earlier rules cover its zones, addresses, service and conditions: " + strings.Join(definiteHit, ", "))
		}
		of.State, of.Covering = StateOK, definiteHit
		of.Reason = "fully covered, reported as shadowed-rule"
		return sf, of
	case coverLimit:
		return both(StateCannotDecide, "cannot decide: "+netreach.ErrLimitReached.Error())
	}
	if len(uneval) > 0 {
		sf, of = both(StateCannotDecide, "cannot decide: earlier "+uneval[0])
		sf.Covering, of.Covering = overlapping, overlapping
		return sf, of
	}
	switch covers(target, append(boxes(definite), boxes(possible)...), w) {
	case fullyCovered:
		sf, of = both(StateCannotDecide, "cannot decide: covered only together with rules whose conditions cannot be compared: "+strings.Join(incomparable, ", "))
		sf.Covering, of.Covering = overlapping, overlapping
		return sf, of
	case coverLimit:
		return both(StateCannotDecide, "cannot decide: "+netreach.ErrLimitReached.Error())
	}
	sf.State, sf.Reason = StateOK, "not covered by earlier rules"
	if len(overlapping) == 0 {
		of.State, of.Reason = StateOK, "no earlier rule overlaps"
		return sf, of
	}
	of.State, of.Severity, of.Covering = StateFinding, SeverityInfo, overlapping
	of.Reason = clean("earlier rules match part of this rule's traffic: " + strings.Join(overlapping, ", "))
	return sf, of
}

func boxes(cs []candidate) []box {
	out := make([]box, len(cs))
	for i, c := range cs {
		out[i] = c.b
	}
	return out
}

// ruleBox returns the match space of an evaluable rule, without
// conditions. Service application-default is left empty here; the caller
// decides.
func ruleBox(v netreach.RuleView, allZones []string, w *work) box {
	zones := func(l []string) []string {
		if len(l) == 1 && l[0] == "any" {
			return allZones
		}
		return sortedUnique(l)
	}
	return box{
		from: zones(v.From),
		to:   zones(v.To),
		src:  addrSet(v.Source, v.NegateSource, w),
		dst:  addrSet(v.Destination, v.NegateDestination, w),
		svc:  serviceSet(v.Service, w),
	}
}

// zonesExclude reports whether an unevaluable rule certainly cannot match
// any traffic of target: its from or to zone list is collected, free of
// markers, not "any" and disjoint from the target's. Like netreach's
// path completeness, only the zones of an unevaluable rule are trusted.
func zonesExclude(r *netreach.SecurityRule, target box) bool {
	disjoint := func(f netreach.Field[[]string], zones []string) bool {
		if !f.Collected || len(f.Value) == 0 {
			return false
		}
		for _, z := range f.Value {
			if z == "any" || hasMarker(z) {
				return false
			}
			if _, ok := slices.BinarySearch(zones, z); ok {
				return false
			}
		}
		return true
	}
	return disjoint(r.From, target.from) || disjoint(r.To, target.to)
}

// conditionsCover reports whether the conditions of rule c (application,
// source user, URL category, schedule) certainly include those of rule t.
// A list includes another when it is "any" or holds every member of the
// other by name; a schedule includes another when it is empty or the
// same. Anything not collected or different is not certain.
func conditionsCover(c, t *netreach.SecurityRule) bool {
	return listCovers(c.Application, t.Application) &&
		listCovers(c.SourceUser, t.SourceUser) &&
		listCovers(c.Category, t.Category) &&
		scheduleCovers(c.Schedule, t.Schedule)
}

func listCovers(c, t netreach.Field[[]string]) bool {
	if !c.Collected || !t.Collected || len(c.Value) == 0 || len(t.Value) == 0 {
		return false
	}
	for _, m := range c.Value {
		if hasMarker(m) {
			return false
		}
	}
	if len(c.Value) == 1 && c.Value[0] == "any" {
		return true
	}
	for _, m := range t.Value {
		if m == "any" || hasMarker(m) || !slices.Contains(c.Value, m) {
			return false
		}
	}
	return true
}

func scheduleCovers(c, t netreach.Field[string]) bool {
	switch {
	case !c.Collected:
		return false
	case c.Value == "":
		return true
	}
	return t.Collected && t.Value == c.Value
}

// shadowSeverity is high when a blocking rule is shadowed by an earlier
// allow rule (the intended block never applies), otherwise medium.
func shadowSeverity(r *netreach.SecurityRule, raws []netreach.SecurityRule, covering []candidate) Severity {
	if r.Action == netreach.ActionAllow {
		return SeverityMedium
	}
	for _, c := range covering {
		if raws[c.index].Action == netreach.ActionAllow {
			return SeverityHigh
		}
	}
	return SeverityMedium
}

// String returns a one-line form of a finding for logs and tests.
func (f Finding) String() string {
	return fmt.Sprintf("%s %s rule %d %q: %s", f.CheckID, f.State, f.RuleIndex, f.RuleName, f.Reason)
}
