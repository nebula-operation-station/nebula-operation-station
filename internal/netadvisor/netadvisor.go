// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netadvisor holds the rule advisor checks na-v1 of ADR 0012 D4.
// It is a pure library on top of the reachability model nr-v1
// (internal/netreach): no I/O, no clock, no global state.
//
// Every check reports one of four states per rule. A check never turns
// something it cannot evaluate into "ok" (which would resolve an existing
// finding): an unevaluable rule (ADR 0012 D2 fail-safe), an object that
// cannot be evaluated, a stale or incomplete input or a work limit gives
// StateCannotDecide, and an element that was not collected (for example
// the NS-04 profile names) gives StateDataNotCollected.
//
// Every text in a Finding may contain device text (rule names, zone
// names); render it as text only.
package netadvisor

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// CheckVersion is the version of the advisor checks stored with every
// finding (ADR 0012 D4). Any change to check semantics creates a new
// version.
const CheckVersion = "na-v1"

// Check IDs of this package (ADR 0012 D4 "Checks (na-v1)").
const (
	CheckShadowedRule        = "shadowed-rule"
	CheckOverlap             = "overlap"
	CheckAnyAny              = "any-any"
	CheckAllowWithoutProfile = "allow-without-profile"
)

// State is the outcome of one check for one rule.
type State string

// States. Only StateOK and StateFinding are evaluated results; the other
// two never resolve an existing finding (ADR 0012 D4).
const (
	StateOK               State = "ok"
	StateFinding          State = "finding"
	StateCannotDecide     State = "cannot_decide"
	StateDataNotCollected State = "data_not_collected"
)

// Evaluated reports whether the state is an evaluated result (ok or
// finding) rather than "cannot decide" or "data not collected".
func (s State) Evaluated() bool { return s == StateOK || s == StateFinding }

// Severity is the severity of a finding. It is empty for every state other
// than StateFinding.
type Severity string

// Severities.
const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// TrustClass is the operator-set trust class of a zone (ADR 0012 D4).
type TrustClass string

// Trust classes. A zone without a class, or with a value outside this
// list, is TrustUnknown, which counts as untrusted (ADR 0012 Q9).
const (
	TrustUntrusted  TrustClass = "untrusted"
	TrustGuest      TrustClass = "guest"
	TrustIoT        TrustClass = "iot"
	TrustInternal   TrustClass = "internal"
	TrustManagement TrustClass = "management"
	TrustUnknown    TrustClass = "unknown"
)

// ProfileSetting is the profile-setting of one security rule as NS-04
// collects it (profile and group names only, ADR 0012 Q11). Dropped holds
// the <dropped:…> markers the redaction left on it.
type ProfileSetting struct {
	Profiles []string
	Group    string
	Dropped  []string
}

// Input is everything one advisor run reads: the reachability snapshot
// with its index, the zone trust classes and the NS-04 profile settings.
// Profiles is keyed by rule UUID; when Collected is false (no NS-04 data)
// the profile check reports StateDataNotCollected for every rule.
type Input struct {
	Snapshot    *netreach.Snapshot
	Index       *netreach.Index
	ZoneClasses map[string]TrustClass
	Profiles    netreach.Field[map[string]ProfileSetting]
}

// Limits of the advisor input.
const (
	// MaxZoneClasses bounds the zone trust class entries.
	MaxZoneClasses = netreach.MaxZones
	// MaxProfileEntries bounds the rule profile-setting entries.
	MaxProfileEntries = netreach.MaxSecurityRules
	// MaxProfilesPerRule bounds the profile names of one rule.
	MaxProfilesPerRule = 64
	// MaxTextBytes bounds every text a finding carries (reasons, names).
	MaxTextBytes = 2048
)

// ErrInvalidInput is wrapped by errors for an input the advisor cannot use
// at all (no snapshot, a snapshot the model refuses, a limit).
var ErrInvalidInput = errors.New("invalid advisor input")

// NewInput checks the snapshot, builds its index and returns the input of
// one advisor run. classes and profiles are copied by reference and must
// not change afterwards.
func NewInput(s *netreach.Snapshot, classes map[string]TrustClass, profiles netreach.Field[map[string]ProfileSetting]) (*Input, error) {
	if err := netreach.CheckLimits(s); err != nil {
		return nil, fmt.Errorf("new advisor input: %w: %w", ErrInvalidInput, err)
	}
	if len(classes) > MaxZoneClasses {
		return nil, fmt.Errorf("new advisor input: %w: %d zone classes, limit %d", ErrInvalidInput, len(classes), MaxZoneClasses)
	}
	if len(profiles.Value) > MaxProfileEntries {
		return nil, fmt.Errorf("new advisor input: %w: %d profile entries, limit %d", ErrInvalidInput, len(profiles.Value), MaxProfileEntries)
	}
	for uuid, p := range profiles.Value {
		if len(p.Profiles) > MaxProfilesPerRule || len(p.Dropped) > netreach.MaxMarkers {
			return nil, fmt.Errorf("new advisor input: %w: profile setting of rule %s over limit", ErrInvalidInput, clean(uuid))
		}
	}
	x, err := netreach.NewIndex(s)
	if err != nil {
		return nil, fmt.Errorf("new advisor input: %w: %w", ErrInvalidInput, err)
	}
	return &Input{Snapshot: s, Index: x, ZoneClasses: classes, Profiles: profiles}, nil
}

// Finding is the result of one check for one rule. RuleIndex is the
// position in rule order (-1 for a result that concerns no single rule).
// Reason says why, in one sentence. Covering lists the covering rules of
// shadowed-rule and overlap; Fields the fields that are "any" (any-any);
// Zones the zones that made the rule relevant (any-any,
// allow-without-profile).
type Finding struct {
	CheckID      string
	CheckVersion string
	RuleIndex    int
	RuleName     string
	RuleUUID     string
	State        State
	Severity     Severity
	Reason       string
	Covering     []string
	Fields       []string
	Zones        []string
}

// Report is the result of one check over one snapshot. State is StateOK
// when the check could run on every rule; otherwise it is the state of
// the precondition that failed (every rule then carries that state too),
// with Reason.
type Report struct {
	CheckID      string
	CheckVersion string
	State        State
	Reason       string
	Findings     []Finding
}

// Check is one advisor check. Run never fails: whatever it cannot
// evaluate is reported as StateCannotDecide or StateDataNotCollected.
type Check interface {
	ID() string
	Run(in *Input) Report
}

// Checks returns the checks of this package in a fixed order.
func Checks() []Check {
	return []Check{ShadowCheck{}, AnyAnyCheck{}, ProfileCheck{}}
}

// precondition returns the state and reason when the snapshot as a whole
// cannot be used for a check that needs the inputs needs: an input that
// is missing gives StateDataNotCollected; one that is stale or incomplete,
// or a vsys count other than one, gives StateCannotDecide.
func precondition(in *Input, needs ...netreach.InputKind) (State, string) {
	if in == nil || in.Snapshot == nil || in.Index == nil {
		return StateCannotDecide, "no snapshot"
	}
	for _, k := range needs {
		switch st := in.Snapshot.Inputs[k].State; st {
		case netreach.InputFresh:
		case netreach.InputMissing:
			return StateDataNotCollected, fmt.Sprintf("input %s not collected", k)
		default:
			return StateCannotDecide, fmt.Sprintf("input %s %s", k, st)
		}
	}
	switch in.Snapshot.Vsys {
	case 1:
	case 0:
		return StateCannotDecide, "vsys count not reported"
	default:
		return StateCannotDecide, "more than one vsys"
	}
	return StateOK, ""
}

// failedReport returns a report in which the precondition state applies to
// the check and to every rule of the snapshot.
func failedReport(id string, in *Input, st State, reason string) Report {
	r := Report{CheckID: id, CheckVersion: CheckVersion, State: st, Reason: clean(reason)}
	if in == nil || in.Snapshot == nil {
		return r
	}
	for i := range in.Snapshot.SecurityRules {
		f := newFinding(id, i, &in.Snapshot.SecurityRules[i])
		f.State, f.Reason = st, clean(reason)
		r.Findings = append(r.Findings, f)
	}
	return r
}

func newFinding(id string, i int, r *netreach.SecurityRule) Finding {
	return Finding{CheckID: id, CheckVersion: CheckVersion, RuleIndex: i, RuleName: clean(r.Name), RuleUUID: clean(r.UUID)}
}

// zoneClass returns the trust class of a zone; a zone without a valid
// class is TrustUnknown.
func (in *Input) zoneClass(zone string) TrustClass {
	switch c := in.ZoneClasses[zone]; c {
	case TrustUntrusted, TrustGuest, TrustIoT, TrustInternal, TrustManagement:
		return c
	}
	return TrustUnknown
}

// untrustedLike reports whether a class counts as untrusted or guest for
// the checks of this package (unknown counts as untrusted, Q9).
func untrustedLike(c TrustClass) bool {
	return c == TrustUntrusted || c == TrustGuest || c == TrustUnknown
}

// zoneList is a zone list of a rule resolved against the snapshot: the
// names (every snapshot zone for "any"), whether it was "any", and a
// reason when it cannot be used (not collected, empty, a marker).
type zoneList struct {
	zones []string
	any   bool
	why   string
	nc    bool // why is "not collected"
}

func (in *Input) resolveZones(field string, f netreach.Field[[]string]) zoneList {
	switch {
	case !f.Collected:
		return zoneList{why: field + " not collected", nc: true}
	case len(f.Value) == 0:
		return zoneList{why: field + " empty"}
	}
	if len(f.Value) == 1 && f.Value[0] == "any" {
		zl := zoneList{any: true}
		for _, z := range in.Snapshot.Zones {
			zl.zones = append(zl.zones, z.Name)
		}
		return zl
	}
	for _, z := range f.Value {
		if hasMarker(z) || z == "any" {
			return zoneList{why: field + " has " + z}
		}
	}
	return zoneList{zones: f.Value}
}

func hasMarker(s string) bool { return strings.HasPrefix(s, "<dropped:") }

// ruleMarker returns why a rule is unevaluable at rule level: a
// <dropped:…> marker the redaction left on it or a field outside the
// collected allowlist (ADR 0012 D2). It returns "" for neither.
func ruleMarker(r *netreach.SecurityRule) string {
	switch {
	case len(r.Dropped) > 0:
		return "rule has " + r.Dropped[0]
	case len(r.OutsideAllowlist) > 0:
		return "rule has a field outside the collected allowlist: " + r.OutsideAllowlist[0]
	}
	return ""
}

// clean makes device text safe to carry: invalid UTF-8 and control or
// format characters become U+FFFD, and the text is cut at MaxTextBytes.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = utf8.RuneError
		}
		if b.Len()+utf8.RuneLen(r) > MaxTextBytes {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func cleanAll(l []string) []string {
	out := make([]string, 0, len(l))
	for _, s := range l {
		out = append(out, clean(s))
	}
	return out
}

// sortedUnique returns the sorted distinct values of l.
func sortedUnique(l []string) []string {
	out := slices.Clone(l)
	slices.Sort(out)
	return slices.Compact(out)
}
