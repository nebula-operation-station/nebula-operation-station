// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"slices"
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

func TestAnyAnyCheck(t *testing.T) {
	// narrow is an allow rule with nothing "any".
	narrow := func() nr.SecurityRule {
		r := rule("r", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web"))
		r.Application = list("ssl")
		return r
	}
	with := func(f func(*nr.SecurityRule)) nr.SecurityRule {
		r := narrow()
		f(&r)
		return r
	}
	tests := []struct {
		name     string
		r        nr.SecurityRule
		classes  map[string]TrustClass // nil: labClasses
		state    State
		fields   []string
		severity Severity
		reason   string
		zones    []string
	}{
		{name: "narrow rule is ok", r: narrow(), state: StateOK, reason: "no field any"},
		{
			name:  "source and destination any",
			r:     with(func(r *nr.SecurityRule) { r.Source, r.Destination = list("any"), list("any") }),
			state: StateFinding, fields: s(VariantAddressAny), severity: SeverityHigh,
		},
		{
			name:  "only source any is not the address variant",
			r:     with(func(r *nr.SecurityRule) { r.Source = list("any") }),
			state: StateOK,
		},
		{
			name: "negated any source is not any",
			r: with(func(r *nr.SecurityRule) {
				r.Source, r.Destination, r.NegateSource = list("any"), list("any"), nr.Collected(true)
			}),
			state: StateOK,
		},
		{
			name:  "from zone any",
			r:     with(func(r *nr.SecurityRule) { r.From = list("any") }),
			state: StateFinding, fields: s(VariantZoneAny), severity: SeverityMedium,
		},
		{
			name:  "from zone any with destination any reaches lan from untrusted zones",
			r:     with(func(r *nr.SecurityRule) { r.From, r.Destination = list("any"), list("any") }),
			state: StateFinding, fields: s(VariantZoneAny, VariantFromUntrusted), severity: SeverityHigh,
			zones: s("guest", "wan"),
		},
		{
			name:  "to zone any between trusted zones",
			r:     with(func(r *nr.SecurityRule) { r.From = list("lan"); r.To = list("any") }),
			state: StateFinding, fields: s(VariantZoneAny), severity: SeverityMedium,
		},
		{
			name:  "service and application any",
			r:     with(func(r *nr.SecurityRule) { r.Service, r.Application = list("any"), list("any") }),
			state: StateFinding, fields: s(VariantServiceAny), severity: SeverityMedium,
		},
		// "any" next to other members matches everything, as in netreach.
		{
			name:  "any inside source and destination lists",
			r:     with(func(r *nr.SecurityRule) { r.Source, r.Destination = list("lan-net", "any"), list("any", "web-server") }),
			state: StateFinding, fields: s(VariantAddressAny), severity: SeverityHigh,
		},
		{
			name:  "any inside service and application lists",
			r:     with(func(r *nr.SecurityRule) { r.Service, r.Application = list("svc-web", "any"), list("ssl", "any") }),
			state: StateFinding, fields: s(VariantServiceAny), severity: SeverityMedium,
		},
		{
			name:  "any inside a zone list",
			r:     with(func(r *nr.SecurityRule) { r.From = list("lan", "any") }),
			state: StateFinding, fields: s(VariantZoneAny), severity: SeverityMedium,
		},
		{
			name: "negated source list with any is not any",
			r: with(func(r *nr.SecurityRule) {
				r.Source, r.Destination, r.NegateSource = list("lan-net", "any"), list("any"), nr.Collected(true)
			}),
			state: StateOK,
		},
		{
			name:  "service any with an application is ok",
			r:     with(func(r *nr.SecurityRule) { r.Service = list("any") }),
			state: StateOK,
		},
		{
			name:  "application-default is not service any",
			r:     with(func(r *nr.SecurityRule) { r.Service, r.Application = list("application-default"), list("any") }),
			state: StateOK,
		},
		{
			name:  "from guest to lan with destination any",
			r:     with(func(r *nr.SecurityRule) { r.From, r.Destination = list("guest"), list("any") }),
			state: StateFinding, fields: s(VariantFromUntrusted), severity: SeverityHigh, zones: s("guest"),
		},
		{
			name:  "from guest to lan narrow is ok",
			r:     with(func(r *nr.SecurityRule) { r.From = list("guest") }),
			state: StateOK,
		},
		{
			name:    "zone without class counts as untrusted",
			r:       with(func(r *nr.SecurityRule) { r.From, r.To, r.Destination = list("dmz"), list("lan"), list("any") }),
			classes: map[string]TrustClass{"lan": TrustInternal},
			state:   StateFinding, fields: s(VariantFromUntrusted), severity: SeverityHigh, zones: s("dmz"),
		},
		{
			name:    "invalid class counts as untrusted",
			r:       with(func(r *nr.SecurityRule) { r.From, r.To, r.Destination = list("dmz"), list("lan"), list("any") }),
			classes: map[string]TrustClass{"lan": TrustInternal, "dmz": "trusted-ish"},
			state:   StateFinding, fields: s(VariantFromUntrusted), severity: SeverityHigh, zones: s("dmz"),
		},
		{
			name: "from lan to wan with everything any",
			r: with(func(r *nr.SecurityRule) {
				r.To, r.Destination, r.Service, r.Application = list("wan"), list("any"), list("any"), list("any")
			}),
			state: StateFinding, fields: s(VariantServiceAny, VariantToUntrusted), severity: SeverityMedium, zones: s("wan"),
		},
		{
			name: "intrazone rule crosses no zone",
			r: with(func(r *nr.SecurityRule) {
				r.From, r.To, r.Destination, r.Type = list("guest"), list("guest"), list("any"), nr.Collected(nr.RuleTypeIntrazone)
			}),
			state: StateOK,
		},
		{name: "deny rule is ok", r: rule("r", deny, s("any"), s("any"), s("any"), s("any"), s("any")), state: StateOK, reason: "not an allow"},
		{name: "disabled rule is ok", r: with(func(r *nr.SecurityRule) { r.From, r.Disabled = list("any"), nr.Collected(true) }), state: StateOK, reason: "disabled"},
		// Fail-safe: never ok when a needed field is missing.
		{
			name:  "disabled not collected",
			r:     with(func(r *nr.SecurityRule) { r.Disabled = nr.Field[bool]{} }),
			state: StateDataNotCollected, reason: "disabled not collected",
		},
		{
			name:  "unknown action",
			r:     with(func(r *nr.SecurityRule) { r.Action = "" }),
			state: StateCannotDecide, reason: "unknown action",
		},
		{
			name: "source any without negation flag",
			r: with(func(r *nr.SecurityRule) {
				r.Source, r.Destination, r.NegateSource = list("any"), list("any"), nr.Field[bool]{}
			}),
			state: StateDataNotCollected, reason: "negate-source not collected",
		},
		{
			name:  "source with dropped marker",
			r:     with(func(r *nr.SecurityRule) { r.Source, r.Destination = list("<dropped:x>"), list("any") }),
			state: StateCannotDecide, reason: "source has <dropped:x>",
		},
		{
			name:  "from zone not collected",
			r:     with(func(r *nr.SecurityRule) { r.From = nr.Field[[]string]{} }),
			state: StateDataNotCollected, reason: "from not collected",
		},
		{
			name: "from guest with destination any but rule type not collected",
			r: with(func(r *nr.SecurityRule) {
				r.From, r.Destination, r.Type = list("guest"), list("any"), nr.Field[nr.RuleType]{}
			}),
			state: StateDataNotCollected, reason: "rule-type not collected",
		},
		{
			name: "a firing variant wins over an undecided one",
			r: with(func(r *nr.SecurityRule) {
				r.Service, r.Application, r.Source, r.Destination, r.NegateSource =
					list("any"), list("any"), list("any"), list("any"), nr.Field[bool]{}
			}),
			state: StateFinding, fields: s(VariantServiceAny), severity: SeverityMedium, reason: "not decided",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			classes := tc.classes
			if classes == nil {
				classes = labClasses
			}
			tc.r.Name = "r"
			in, err := NewInput(labSnapshot(tc.r), classes, nr.Field[map[string]ProfileSetting]{})
			if err != nil {
				t.Fatal(err)
			}
			rep := AnyAnyCheck{}.Run(in)
			if rep.State != StateOK || rep.CheckID != CheckAnyAny {
				t.Fatalf("report = %+v", rep)
			}
			f := byRule(t, rep, CheckAnyAny, 0)
			if f.State != tc.state {
				t.Fatalf("state = %s (%q), want %s", f.State, f.Reason, tc.state)
			}
			if tc.fields != nil && !slices.Equal(f.Fields, tc.fields) {
				t.Errorf("fields = %v, want %v", f.Fields, tc.fields)
			}
			if f.Severity != tc.severity {
				t.Errorf("severity = %q, want %q", f.Severity, tc.severity)
			}
			if !strings.Contains(f.Reason, tc.reason) {
				t.Errorf("reason = %q, want %q", f.Reason, tc.reason)
			}
			if tc.zones != nil && !slices.Equal(f.Zones, tc.zones) {
				t.Errorf("zones = %v, want %v", f.Zones, tc.zones)
			}
		})
	}
}

func TestAnyAnyPreconditions(t *testing.T) {
	snap := labSnapshot(rule("r", allow, s("any"), s("any"), s("any"), s("any"), s("any")))
	setInput(snap, nr.InputSecurityRules, nr.InputIncomplete)
	r := AnyAnyCheck{}.Run(newInput(t, snap, nr.Field[map[string]ProfileSetting]{}))
	if r.State != StateCannotDecide || byRule(t, r, CheckAnyAny, 0).State != StateCannotDecide {
		t.Errorf("incomplete rules: %+v, want cannot_decide", r)
	}
	snap = labSnapshot(rule("r", allow, s("any"), s("any"), s("any"), s("any"), s("any")))
	delete(snap.Inputs, nr.InputZones)
	r = AnyAnyCheck{}.Run(newInput(t, snap, nr.Field[map[string]ProfileSetting]{}))
	if r.State != StateDataNotCollected || byRule(t, r, CheckAnyAny, 0).State != StateDataNotCollected {
		t.Errorf("zones missing: %+v, want data_not_collected", r)
	}
}
