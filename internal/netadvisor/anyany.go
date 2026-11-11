// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// Variants of the any-any check, reported in Finding.Fields.
const (
	// VariantAddressAny: source and destination address both "any" (not
	// negated).
	VariantAddressAny = "source-and-destination-any"
	// VariantZoneAny: source or destination zone "any".
	VariantZoneAny = "zone-any"
	// VariantServiceAny: service and application both "any".
	VariantServiceAny = "service-and-application-any"
	// VariantFromUntrusted: from an untrusted, guest or unknown zone into
	// a zone that is not untrusted-like (internal, management or iot)
	// with destination "any" or
	// service and application "any". A rule between untrusted-like zones
	// only is not this variant.
	VariantFromUntrusted = "broad-from-untrusted"
	// VariantToUntrusted: from a trusted zone into an untrusted, guest or
	// unknown zone with destination "any" and service and application
	// "any".
	VariantToUntrusted = "broad-to-untrusted"
)

// AnyAnyCheck is the check any-any (ADR 0012 D4) with its variants: an
// enabled allow rule with source and destination address "any", or source
// or destination zone "any", or service and application both "any", and
// too broad rules between untrusted or guest zones and the rest. A zone
// without a trust class counts as untrusted (Q9).
//
// The check reads the rule fields literally; it does not need the rule to
// be evaluable for reachability. A field it needs that was not collected
// gives StateDataNotCollected, a field with a <dropped:…> marker, a
// rule-level marker (SecurityRule.Dropped or OutsideAllowlist) or an
// unknown action StateCannotDecide, unless another variant already fires.
// A rule with a rule-level marker is never StateOK.
type AnyAnyCheck struct{}

// ID returns CheckAnyAny.
func (AnyAnyCheck) ID() string { return CheckAnyAny }

var anyAnyInputs = []netreach.InputKind{netreach.InputZones, netreach.InputSecurityRules}

// Run runs the check over every rule, in rule order.
func (AnyAnyCheck) Run(in *Input) Report {
	if st, why := precondition(in, anyAnyInputs...); st != StateOK {
		return failedReport(CheckAnyAny, in, st, why)
	}
	r := Report{CheckID: CheckAnyAny, CheckVersion: CheckVersion, State: StateOK}
	for i := range in.Snapshot.SecurityRules {
		r.Findings = append(r.Findings, anyAnyRule(in, i))
	}
	return r
}

// tri is a three-valued answer with the reason when unknown. nc marks an
// unknown that comes only from fields that were not collected.
type tri struct {
	v   int // triNo, triYes, triUnknown
	why string
	nc  bool
}

const (
	triNo = iota
	triYes
	triUnknown
)

var (
	yes = tri{v: triYes}
	no  = tri{v: triNo}
)

func unknown(why string, nc bool) tri { return tri{v: triUnknown, why: why, nc: nc} }

func and(a, b tri) tri {
	switch {
	case a.v == triNo || b.v == triNo:
		return no
	case a.v == triUnknown:
		return a
	}
	return b
}

func or(a, b tri) tri {
	switch {
	case a.v == triYes || b.v == triYes:
		return yes
	case a.v == triUnknown:
		return a
	}
	return b
}

// anyField answers whether a member list is exactly "any".
func anyField(name string, f netreach.Field[[]string]) tri {
	switch {
	case !f.Collected:
		return unknown(name+" not collected", true)
	case len(f.Value) == 0:
		return unknown(name+" empty", false)
	}
	for _, m := range f.Value {
		if hasMarker(m) {
			return unknown(name+" has "+m, false)
		}
	}
	if len(f.Value) == 1 && f.Value[0] == "any" {
		return yes
	}
	return no
}

// effectiveAny answers whether an address list matches every address:
// "any" and not negated (negated "any" matches nothing).
func effectiveAny(name string, f netreach.Field[[]string], negate netreach.Field[bool]) tri {
	a := anyField(name, f)
	if a.v != triYes {
		return a
	}
	switch {
	case !negate.Collected:
		return unknown("negate-"+name+" not collected", true)
	case negate.Value:
		return no
	}
	return yes
}

func anyAnyRule(in *Input, i int) Finding {
	r := &in.Snapshot.SecurityRules[i]
	f := newFinding(CheckAnyAny, i, r)
	set := func(st State, why string) Finding {
		f.State, f.Reason = st, clean(why)
		return f
	}
	switch {
	case !r.Disabled.Collected:
		return set(StateDataNotCollected, "data not collected: disabled not collected")
	case r.Disabled.Value:
		return set(StateOK, "rule disabled")
	}
	// A rule-level marker makes every answer short of a finding unknown:
	// the dropped or unlisted field may be the one that decides.
	marker := ruleMarker(r)
	switch r.Action {
	case netreach.ActionAllow:
	case netreach.ActionDeny, netreach.ActionDrop, netreach.ActionResetClient, netreach.ActionResetServer, netreach.ActionResetBoth:
		if marker != "" {
			return set(StateCannotDecide, "cannot decide: "+marker)
		}
		return set(StateOK, "not an allow rule")
	default:
		return set(StateCannotDecide, "cannot decide: unknown action")
	}

	srcAny := effectiveAny("source", r.Source, r.NegateSource)
	dstAny := effectiveAny("destination", r.Destination, r.NegateDestination)
	svcAny := and(anyField("service", r.Service), anyField("application", r.Application))
	fromUntrusted, toUntrusted, zones := untrustedCrossing(in, r)
	variants := []struct {
		name string
		t    tri
		sev  Severity
	}{
		{VariantAddressAny, and(srcAny, dstAny), SeverityHigh},
		{VariantZoneAny, or(anyField("from", r.From), anyField("to", r.To)), SeverityMedium},
		{VariantServiceAny, svcAny, SeverityMedium},
		{VariantFromUntrusted, and(fromUntrusted, or(dstAny, svcAny)), SeverityHigh},
		{VariantToUntrusted, and(toUntrusted, and(dstAny, svcAny)), SeverityLow},
	}
	var fired, open []string
	allNC := true
	if marker != "" {
		open, allNC = append(open, marker), false
	}
	for _, v := range variants {
		switch v.t.v {
		case triYes:
			fired = append(fired, v.name)
			if rankSeverity(v.sev) > rankSeverity(f.Severity) {
				f.Severity = v.sev
			}
		case triUnknown:
			open = append(open, v.name+" ("+v.t.why+")")
			allNC = allNC && v.t.nc
		}
	}
	switch {
	case len(fired) > 0:
		f.State, f.Fields, f.Zones = StateFinding, fired, cleanAll(zones)
		why := "allow rule too broad: " + strings.Join(fired, ", ")
		if len(open) > 0 {
			why += "; not decided: " + strings.Join(open, ", ")
		}
		f.Reason = clean(why)
		return f
	case len(open) > 0 && allNC:
		return set(StateDataNotCollected, "data not collected: "+strings.Join(open, ", "))
	case len(open) > 0:
		return set(StateCannotDecide, "cannot decide: "+strings.Join(open, ", "))
	}
	return set(StateOK, "no field any")
}

// untrustedCrossing answers whether the rule leads from an untrusted-like
// zone into a trusted one, and from a trusted zone into an untrusted-like
// one, and returns the untrusted-like zones involved. An intrazone rule
// crosses no zone boundary; a rule type that was not collected may.
func untrustedCrossing(in *Input, r *netreach.SecurityRule) (from, to tri, zones []string) {
	fz, tz := in.resolveZones("from", r.From), in.resolveZones("to", r.To)
	if fz.why != "" {
		return unknown(fz.why, fz.nc), unknown(fz.why, fz.nc), nil
	}
	if tz.why != "" {
		return unknown(tz.why, tz.nc), unknown(tz.why, tz.nc), nil
	}
	split := func(l []string) (untrusted, trusted bool, names []string) {
		for _, z := range l {
			if untrustedLike(in.zoneClass(z)) {
				untrusted = true
				names = append(names, z)
			} else {
				trusted = true
			}
		}
		return untrusted, trusted, names
	}
	fu, ft, fn := split(fz.zones)
	tu, tt, tn := split(tz.zones)
	from, to = no, no
	if fu && tt {
		from = yes
		zones = append(zones, fn...)
	}
	if ft && tu {
		to = yes
		zones = append(zones, tn...)
	}
	switch {
	case !r.Type.Collected:
		typ := unknown("rule-type not collected", true)
		from, to = and(from, typ), and(to, typ)
	case r.Type.Value == netreach.RuleTypeIntrazone:
		return no, no, nil
	case r.Type.Value != netreach.RuleTypeUniversal && r.Type.Value != netreach.RuleTypeInterzone:
		typ := unknown("rule-type unknown", false)
		from, to = and(from, typ), and(to, typ)
	}
	return from, to, sortedUnique(zones)
}

func rankSeverity(s Severity) int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	}
	return 0
}
