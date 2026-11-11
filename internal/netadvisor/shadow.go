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
//     rule may match part of its match space (its conditions need not
//     certainly include the rule's own).
//
// A rule with service application-default matches only the default ports
// of its applications, which the snapshot does not hold: it is shadowed
// when earlier rules cover it on every port, ok when some of its zones and
// addresses are matched by no earlier rule on any port, and otherwise
// StateCannotDecide.
//
// Fail-safe (ADR 0012 D2): the rule itself unevaluable, an earlier rule
// that is unevaluable and may match the rule's traffic, a covering set
// that needs a rule whose conditions cannot be compared, unknown
// application-default ports, or a work limit give StateCannotDecide for
// both IDs, never StateOK. All per-pair work (zone tests, condition
// comparison, set operations) is charged to the work limits before it is
// done.
type ShadowCheck struct {
	// workPerRule and workPerSnapshot override MaxShadowWorkPerRule and
	// MaxShadowWorkPerSnapshot when not zero (tests only).
	workPerRule, workPerSnapshot int
}

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
	perRule, perSnapshot := MaxShadowWorkPerRule, MaxShadowWorkPerSnapshot
	if c.workPerRule != 0 {
		perRule = c.workPerRule
	}
	if c.workPerSnapshot != 0 {
		perSnapshot = c.workPerSnapshot
	}
	var allZones []string
	for _, z := range in.Snapshot.Zones {
		allZones = append(allZones, z.Name)
	}
	sh := shadowState{
		views:    in.Index.SecurityRules(),
		raws:     in.Snapshot.SecurityRules,
		allZones: sortedUnique(allZones),
		shared:   perSnapshot,
	}
	// Match spaces and condition sets are built once per rule (linear in
	// the snapshot) and charged to the shared budget.
	prep := &work{max: perSnapshot, shared: &sh.shared}
	sh.boxes = make([]box, len(sh.views))
	sh.conds = make([]ruleConds, len(sh.views))
	for i, v := range sh.views {
		if v.Disabled || !v.Evaluable() {
			continue
		}
		sh.boxes[i] = ruleBox(v, sh.allZones, prep)
		sh.conds[i] = newRuleConds(&sh.raws[i], prep)
	}

	shadowed := make([]Finding, len(sh.views))
	overlap := make([]Finding, len(sh.views))
	for i := range sh.views {
		w := &work{max: perRule, shared: &sh.shared}
		s, o := sh.rule(i, w)
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

// shadowState is the per-run state of the shadow check: the rules, their
// match spaces and condition sets (zero for disabled and unevaluable
// rules) and the remaining shared budget.
type shadowState struct {
	views    []netreach.RuleView
	raws     []netreach.SecurityRule
	allZones []string
	boxes    []box
	conds    []ruleConds
	shared   int
}

func (sh *shadowState) rule(i int, w *work) (Finding, Finding) {
	raws := sh.raws
	sf := newFinding(CheckShadowedRule, i, &raws[i])
	of := newFinding(CheckOverlap, i, &raws[i])
	both := func(st State, why string) (Finding, Finding) {
		sf.State, sf.Reason = st, clean(why)
		of.State, of.Reason = st, clean(why)
		return sf, of
	}
	limit := func() (Finding, Finding) {
		return both(StateCannotDecide, "cannot decide: "+netreach.ErrLimitReached.Error())
	}
	v := sh.views[i]
	switch {
	case v.Disabled:
		return both(StateOK, "rule disabled")
	case !v.Evaluable():
		return both(StateCannotDecide, "cannot decide: "+v.Reason())
	case w.exhausted():
		return limit()
	}
	target := sh.boxes[i]
	appDefault := v.Service.ApplicationDefault
	if appDefault {
		// The real ports are the default ports of the rule's
		// applications, a subset of every port: covering the whole
		// service dimension is enough to shadow; covering only some
		// ports decides nothing (the projection test below).
		target.svc = fullService()
	}

	var definite, possible []candidate
	var definiteHit, overlapping, incomparable []string
	firstUneval := ""
	for j := range i {
		cv := sh.views[j]
		if cv.Disabled {
			continue
		}
		if !cv.Evaluable() {
			w.add(len(raws[j].From.Value) + len(raws[j].To.Value))
			if w.exhausted() {
				return limit()
			}
			if zonesExclude(&raws[j], target) {
				continue
			}
			if firstUneval == "" {
				firstUneval = cv.Reason()
			}
			continue
		}
		cb := sh.boxes[j]
		if cv.Service.ApplicationDefault {
			cb.svc = fullService()
		}
		in := target.intersect(&cb, w)
		if w.exhausted() {
			return limit()
		}
		if in.empty() {
			continue
		}
		sure := conditionsCover(&sh.conds[j], &sh.conds[i], w)
		if w.exhausted() {
			return limit()
		}
		if cv.Service.ApplicationDefault {
			// The default ports of the earlier rule's applications are
			// known to include the rule's own only when both use
			// application-default and the applications are included.
			sure = sure && appDefault
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
		return limit()
	}
	if firstUneval != "" {
		sf, of = both(StateCannotDecide, "cannot decide: earlier "+firstUneval)
		sf.Covering, of.Covering = overlapping, overlapping
		return sf, of
	}
	all := append(boxes(definite), boxes(possible)...)
	switch covers(target, all, w) {
	case fullyCovered:
		sf, of = both(StateCannotDecide, "cannot decide: covered only together with rules whose conditions cannot be compared: "+strings.Join(incomparable, ", "))
		sf.Covering, of.Covering = overlapping, overlapping
		return sf, of
	case coverLimit:
		return limit()
	}
	if appDefault {
		// Not covered on every port. When earlier rules still match
		// every zone and address pair of the rule on some port, whether
		// they cover the applications' default ports is unknown.
		for k := range all {
			all[k].svc = fullService()
		}
		switch covers(target, all, w) {
		case fullyCovered:
			sf, of = both(StateCannotDecide, "cannot decide: service application-default: default ports unknown, earlier rules cover only some ports: "+strings.Join(overlapping, ", "))
			sf.Covering, of.Covering = overlapping, overlapping
			return sf, of
		case coverLimit:
			return limit()
		}
	}
	sf.State, sf.Reason = StateOK, "not covered by earlier rules"
	if len(overlapping) == 0 {
		of.State, of.Reason = StateOK, "no earlier rule overlaps"
		return sf, of
	}
	of.State, of.Severity, of.Covering = StateFinding, SeverityInfo, overlapping
	// Earlier rules whose conditions cannot be compared are listed too:
	// they may, not certainly, match the shared traffic.
	of.Reason = clean("earlier rules may match part of this rule's traffic: " + strings.Join(overlapping, ", "))
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

// condList is one condition list of a rule (application, source user,
// URL category), prepared once per run for coverage tests.
type condList struct {
	// certain: collected, non-empty and free of markers.
	certain bool
	// any: exactly "any".
	any bool
	// hasAny: "any" is one of several members.
	hasAny bool
	// members holds the members by name when certain and not any.
	members map[string]struct{}
	// list is the member list in input order (for the included side).
	list []string
}

func newCondList(f netreach.Field[[]string], w *work) condList {
	w.add(len(f.Value))
	if !f.Collected || len(f.Value) == 0 {
		return condList{}
	}
	for _, m := range f.Value {
		if hasMarker(m) {
			return condList{}
		}
	}
	if len(f.Value) == 1 && f.Value[0] == "any" {
		return condList{certain: true, any: true}
	}
	l := condList{certain: true, members: make(map[string]struct{}, len(f.Value)), list: f.Value}
	for _, m := range f.Value {
		if m == "any" {
			l.hasAny = true
		}
		l.members[m] = struct{}{}
	}
	return l
}

// ruleConds are the conditions of a rule prepared for conditionsCover.
type ruleConds struct {
	app, user, category condList
	schedule            netreach.Field[string]
}

func newRuleConds(r *netreach.SecurityRule, w *work) ruleConds {
	return ruleConds{
		app:      newCondList(r.Application, w),
		user:     newCondList(r.SourceUser, w),
		category: newCondList(r.Category, w),
		schedule: r.Schedule,
	}
}

// conditionsCover reports whether the conditions of rule c (application,
// source user, URL category, schedule) certainly include those of rule t.
// A list includes another when it is "any" or holds every member of the
// other by name; a schedule includes another when it is empty or the
// same. Anything not collected or different is not certain. The member
// lookups are charged to w before they are done; when w is exhausted the
// answer is false and the caller must stop.
func conditionsCover(c, t *ruleConds, w *work) bool {
	w.add(len(t.app.list) + len(t.user.list) + len(t.category.list) + 1)
	if w.exhausted() {
		return false
	}
	return listCovers(&c.app, &t.app) &&
		listCovers(&c.user, &t.user) &&
		listCovers(&c.category, &t.category) &&
		scheduleCovers(c.schedule, t.schedule)
}

func listCovers(c, t *condList) bool {
	switch {
	case !c.certain || !t.certain:
		return false
	case c.any:
		return true
	case t.any || t.hasAny:
		return false
	}
	for _, m := range t.list {
		if _, ok := c.members[m]; !ok {
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
