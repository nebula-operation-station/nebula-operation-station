// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"slices"
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

const (
	allow = nr.ActionAllow
	deny  = nr.ActionDeny
)

func TestShadowCheck(t *testing.T) {
	type want struct {
		shadow, overlap State
		covering        []string // of shadowed-rule
		reason          string   // substring of the shadowed-rule reason
		severity        Severity
	}
	base := func() nr.SecurityRule {
		return rule("target", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web"))
	}
	with := func(f func(*nr.SecurityRule)) nr.SecurityRule {
		r := base()
		f(&r)
		return r
	}
	tests := []struct {
		name  string
		rules []nr.SecurityRule // the last rule is the one checked
		want  want
	}{
		{
			name:  "exact duplicate shadows",
			rules: []nr.SecurityRule{with(func(r *nr.SecurityRule) { r.Name = "first" }), base()},
			want:  want{StateFinding, StateOK, s("first"), "never matches", SeverityMedium},
		},
		{
			name: "two halves of the source together shadow",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Source = "low", list("lan-low") }),
				with(func(r *nr.SecurityRule) { r.Name, r.Source = "high", list("lan-high") }),
				base(),
			},
			want: want{StateFinding, StateOK, s("low", "high"), "never matches", SeverityMedium},
		},
		{
			name: "two services together shadow",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Service = "https", list("svc-https") }),
				with(func(r *nr.SecurityRule) { r.Name, r.Service = "http", list("svc-http") }),
				base(),
			},
			want: want{StateFinding, StateOK, s("https", "http"), "never matches", SeverityMedium},
		},
		{
			name:  "zone any and address any shadow",
			rules: []nr.SecurityRule{rule("broad", allow, s("any"), s("any"), s("any"), s("any"), s("any")), base()},
			want:  want{StateFinding, StateOK, s("broad"), "never matches", SeverityMedium},
		},
		{
			name:  "blocking rule shadowed by allow is high",
			rules: []nr.SecurityRule{rule("broad", allow, s("any"), s("any"), s("any"), s("any"), s("any")), with(func(r *nr.SecurityRule) { r.Action = deny })},
			want:  want{StateFinding, StateOK, s("broad"), "never matches", SeverityHigh},
		},
		{
			name:  "blocking rule shadowed by deny is medium",
			rules: []nr.SecurityRule{rule("broad", deny, s("any"), s("any"), s("any"), s("any"), s("any")), with(func(r *nr.SecurityRule) { r.Action = deny })},
			want:  want{StateFinding, StateOK, s("broad"), "never matches", SeverityMedium},
		},
		{
			name: "negated source covers",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) {
					r.Name, r.Source, r.NegateSource = "not-dmz", list("dmz-net"), nr.Collected(true)
				}),
				base(),
			},
			want: want{StateFinding, StateOK, s("not-dmz"), "never matches", SeverityMedium},
		},
		{
			name: "negated source that excludes part is only overlap",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) {
					r.Name, r.Source, r.NegateSource = "not-lan-low", list("lan-low"), nr.Collected(true)
				}),
				base(),
			},
			want: want{StateOK, StateFinding, nil, "not covered", ""},
		},
		{
			name: "negated any matches nothing",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Source, r.NegateSource = list("any"), nr.Collected(true) }),
			},
			want: want{StateFinding, StateOK, nil, "no traffic", SeverityMedium},
		},
		{
			name:  "partial overlap",
			rules: []nr.SecurityRule{with(func(r *nr.SecurityRule) { r.Name, r.Source = "low", list("lan-low") }), base()},
			want:  want{StateOK, StateFinding, nil, "not covered", ""},
		},
		{
			name:  "partial overlap on service",
			rules: []nr.SecurityRule{with(func(r *nr.SecurityRule) { r.Name, r.Service = "https", list("svc-https") }), base()},
			want:  want{StateOK, StateFinding, nil, "not covered", ""},
		},
		{
			name:  "disjoint zones",
			rules: []nr.SecurityRule{with(func(r *nr.SecurityRule) { r.Name, r.From = "other", list("guest") }), base()},
			want:  want{StateOK, StateOK, nil, "not covered", ""},
		},
		{
			name:  "disabled earlier rule does not cover",
			rules: []nr.SecurityRule{with(func(r *nr.SecurityRule) { r.Name, r.Disabled = "off", nr.Collected(true) }), base()},
			want:  want{StateOK, StateOK, nil, "not covered", ""},
		},
		{
			name:  "disabled rule is ok",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.Disabled = nr.Collected(true) })},
			want:  want{StateOK, StateOK, nil, "disabled", ""},
		},
		{
			name: "covering rule with the same applications shadows",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Application = "apps", list("ssl", "web-browsing") }),
				with(func(r *nr.SecurityRule) { r.Application = list("ssl") }),
			},
			want: want{StateFinding, StateOK, s("apps"), "never matches", SeverityMedium},
		},
		{
			name: "covering rule with any application shadows a rule with applications",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name = "first" }),
				with(func(r *nr.SecurityRule) { r.Application = list("ssl") }),
			},
			want: want{StateFinding, StateOK, s("first"), "never matches", SeverityMedium},
		},
		{
			name: "both application-default with included applications shadows",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) {
					r.Name, r.Application, r.Service = "appdef", list("ssl", "dns"), list("application-default")
				}),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateFinding, StateOK, s("appdef"), "never matches", SeverityMedium},
		},
		{
			name: "application-default rule shadowed by service any",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Service = "any-svc", list("any") }),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateFinding, StateOK, s("any-svc"), "never matches", SeverityMedium},
		},
		// Cannot decide: conditions that cannot be compared.
		{
			name: "covering rule with other applications cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Application = "dns-only", list("dns") }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("dns-only"), "conditions cannot be compared", ""},
		},
		{
			name: "covering rule with a schedule cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Schedule = "office", nr.Collected("office-hours") }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("office"), "conditions cannot be compared", ""},
		},
		{
			name: "covering rule with uncollected schedule cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Schedule = "nosched", nr.Field[string]{} }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("nosched"), "conditions cannot be compared", ""},
		},
		{
			name: "covering application-default rule against explicit ports cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Service = "appdef", list("application-default") }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("appdef"), "conditions cannot be compared", ""},
		},
		// Cannot decide: the rule itself is unevaluable (ADR 0012 D2).
		{
			name:  "rule with an FQDN object cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.Destination = list("cloud") })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "unevaluable", ""},
		},
		{
			name:  "rule with a dropped object cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.Destination = list("dropped-obj") })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "<dropped:ip-netmask>", ""},
		},
		{
			name:  "rule with a dynamic group cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.Destination = list("dyn") })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "dynamic", ""},
		},
		{
			name:  "rule with a dropped marker on the rule cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.Dropped = []string{"<dropped:target>"} })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "<dropped:target>", ""},
		},
		{
			name:  "intrazone rule cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.Type = nr.Collected(nr.RuleTypeIntrazone) })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "rule-type", ""},
		},
		{
			name:  "rule with source-hip cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.SourceHIP = list("hip-profile") })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "source-hip", ""},
		},
		{
			name:  "rule without negation flags cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.NegateSource = nr.Field[bool]{} })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "negate-source", ""},
		},
		{
			name:  "rule with a field outside the allowlist cannot decide",
			rules: []nr.SecurityRule{base(), with(func(r *nr.SecurityRule) { r.OutsideAllowlist = []string{"source-imei"} })},
			want:  want{StateCannotDecide, StateCannotDecide, nil, "source-imei", ""},
		},
		// Cannot decide: an earlier (covering) rule is unevaluable.
		{
			name: "unevaluable covering rule intrazone cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Type = "intra", nr.Collected(nr.RuleTypeIntrazone) }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, nil, "rule intra unevaluable", ""},
		},
		{
			name: "unevaluable covering rule with FQDN object cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Destination = "fqdn", list("cloud") }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, nil, "rule fqdn unevaluable", ""},
		},
		{
			name: "covering rule without disabled flag cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Disabled = "nodis", nr.Field[bool]{} }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, nil, "rule nodis unevaluable: disabled", ""},
		},
		{
			name: "covering rule with dropped marker cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Dropped = "marked", []string{"<dropped:source>"} }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, nil, "rule marked unevaluable", ""},
		},
		{
			name: "unevaluable rule with uncollected zones cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.From = "nozones", nr.Field[[]string]{} }),
				base(),
			},
			want: want{StateCannotDecide, StateCannotDecide, nil, "rule nozones unevaluable", ""},
		},
		{
			name: "unevaluable rule in disjoint zones does not block",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) {
					r.Name, r.From, r.Type = "elsewhere", list("guest"), nr.Collected(nr.RuleTypeIntrazone)
				}),
				base(),
			},
			want: want{StateOK, StateOK, nil, "not covered", ""},
		},
		{
			name: "evaluable cover proves shadowing even after an unevaluable rule",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Type = "intra", nr.Collected(nr.RuleTypeIntrazone) }),
				with(func(r *nr.SecurityRule) { r.Name = "dup" }),
				base(),
			},
			want: want{StateFinding, StateOK, s("dup"), "never matches", SeverityMedium},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := newInput(t, labSnapshot(tc.rules...), nr.Field[map[string]ProfileSetting]{})
			r := ShadowCheck{}.Run(in)
			if r.State != StateOK || r.CheckID != CheckShadowedRule || r.CheckVersion != CheckVersion {
				t.Fatalf("report = %+v", r)
			}
			i := len(tc.rules) - 1
			sf, of := byRule(t, r, CheckShadowedRule, i), byRule(t, r, CheckOverlap, i)
			if sf.State != tc.want.shadow || of.State != tc.want.overlap {
				t.Fatalf("states = %s/%s (%q / %q), want %s/%s", sf.State, of.State, sf.Reason, of.Reason, tc.want.shadow, tc.want.overlap)
			}
			if tc.want.covering != nil && !slices.Equal(sf.Covering, tc.want.covering) {
				t.Errorf("covering = %v, want %v", sf.Covering, tc.want.covering)
			}
			if !strings.Contains(sf.Reason, tc.want.reason) {
				t.Errorf("reason = %q, want it to contain %q", sf.Reason, tc.want.reason)
			}
			if sf.Severity != tc.want.severity {
				t.Errorf("severity = %q, want %q", sf.Severity, tc.want.severity)
			}
			if of.State == StateFinding && of.Severity != SeverityInfo {
				t.Errorf("overlap severity = %q, want info", of.Severity)
			}
			for _, f := range []Finding{sf, of} {
				if f.State != StateFinding && f.Severity != "" {
					t.Errorf("%s: severity %q on state %s", f.CheckID, f.Severity, f.State)
				}
				if f.RuleUUID != "uuid-"+tc.rules[i].Name || f.CheckVersion != CheckVersion {
					t.Errorf("finding identity = %+v", f)
				}
			}
		})
	}
}

// TestShadowUnevaluableNeverOK proves the fail-safe rule over every
// unevaluable earlier rule: whatever its cause, a rule it may cover is
// never reported ok or as a plain overlap.
func TestShadowUnevaluableNeverOK(t *testing.T) {
	causes := map[string]func(*nr.SecurityRule){
		"rule-type not collected": func(r *nr.SecurityRule) { r.Type = nr.Field[nr.RuleType]{} },
		"interzone":               func(r *nr.SecurityRule) { r.Type = nr.Collected(nr.RuleTypeInterzone) },
		"destination-hip":         func(r *nr.SecurityRule) { r.DestinationHIP = list("hip") },
		"negate-destination":      func(r *nr.SecurityRule) { r.NegateDestination = nr.Field[bool]{} },
		"outside allowlist":       func(r *nr.SecurityRule) { r.OutsideAllowlist = []string{"x"} },
		"unknown action":          func(r *nr.SecurityRule) { r.Action = "" },
		"source not collected":    func(r *nr.SecurityRule) { r.Source = nr.Field[[]string]{} },
		"service dropped":         func(r *nr.SecurityRule) { r.Service = list("<dropped:svc>") },
	}
	for name, mut := range causes {
		t.Run(name, func(t *testing.T) {
			// The earlier rule is narrower than the target: evaluable,
			// it would be a partial overlap only.
			early := rule("early", deny, s("lan"), s("dmz"), s("lan-low"), s("web-server"), s("svc-https"))
			mut(&early)
			target := rule("target", allow, s("lan"), s("dmz"), s("lan-net"), s("dmz-net"), s("any"))
			r := ShadowCheck{}.Run(newInput(t, labSnapshot(early, target), nr.Field[map[string]ProfileSetting]{}))
			for _, id := range []string{CheckShadowedRule, CheckOverlap} {
				if f := byRule(t, r, id, 1); f.State != StateCannotDecide {
					t.Errorf("%s = %s (%q), want cannot_decide", id, f.State, f.Reason)
				}
				if f := byRule(t, r, id, 0); f.State != StateCannotDecide {
					t.Errorf("unevaluable rule itself: %s = %s, want cannot_decide", id, f.State)
				}
			}
		})
	}
}

// TestShadowSnapshotWithoutQ11 is the snapshot as collected before NS-04:
// no negation flags, rule type or HIP fields. Nothing is decidable.
func TestShadowSnapshotWithoutQ11(t *testing.T) {
	strip := func(r nr.SecurityRule) nr.SecurityRule {
		r.NegateSource, r.NegateDestination = nr.Field[bool]{}, nr.Field[bool]{}
		r.Type = nr.Field[nr.RuleType]{}
		r.SourceHIP, r.DestinationHIP = nr.Field[[]string]{}, nr.Field[[]string]{}
		return r
	}
	snap := labSnapshot(
		strip(rule("a", allow, s("any"), s("any"), s("any"), s("any"), s("any"))),
		strip(rule("b", allow, s("lan"), s("dmz"), s("lan-net"), s("any"), s("any"))),
	)
	snap.DefaultRules = nr.Field[nr.DefaultRules]{}
	r := ShadowCheck{}.Run(newInput(t, snap, nr.Field[map[string]ProfileSetting]{}))
	if len(r.Findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(r.Findings))
	}
	for _, f := range r.Findings {
		if f.State != StateCannotDecide {
			t.Errorf("%v, want cannot_decide", f)
		}
	}
}

func TestShadowPreconditions(t *testing.T) {
	tests := []struct {
		name   string
		mut    func(*nr.Snapshot)
		state  State
		reason string
	}{
		{"security rules stale", func(s *nr.Snapshot) { setInput(s, nr.InputSecurityRules, nr.InputStale) }, StateCannotDecide, "security_rules stale"},
		{"objects incomplete", func(s *nr.Snapshot) { setInput(s, nr.InputObjects, nr.InputIncomplete) }, StateCannotDecide, "objects incomplete"},
		{"zones missing", func(s *nr.Snapshot) { delete(s.Inputs, nr.InputZones) }, StateDataNotCollected, "zones not collected"},
		{"two vsys", func(s *nr.Snapshot) { s.Vsys = 2 }, StateCannotDecide, "more than one vsys"},
		{"vsys not reported", func(s *nr.Snapshot) { s.Vsys = 0 }, StateCannotDecide, "vsys"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := labSnapshot(
				rule("a", allow, s("any"), s("any"), s("any"), s("any"), s("any")),
				rule("b", allow, s("lan"), s("dmz"), s("lan-net"), s("any"), s("any")),
			)
			tc.mut(snap)
			r := ShadowCheck{}.Run(newInput(t, snap, nr.Field[map[string]ProfileSetting]{}))
			if r.State != tc.state || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("report = %s %q, want %s %q", r.State, r.Reason, tc.state, tc.reason)
			}
			if len(r.Findings) != 4 {
				t.Fatalf("findings = %d, want 4 (two per rule)", len(r.Findings))
			}
			for _, f := range r.Findings {
				if f.State != tc.state {
					t.Errorf("%v, want %s", f, tc.state)
				}
			}
		})
	}
	// An input the shadow check does not read does not matter.
	snap := labSnapshot(rule("a", allow, s("any"), s("any"), s("any"), s("any"), s("any")))
	setInput(snap, nr.InputRoutes, nr.InputStale)
	if r := (ShadowCheck{}).Run(newInput(t, snap, nr.Field[map[string]ProfileSetting]{})); r.State != StateOK {
		t.Errorf("routes stale: report %s %q, want ok", r.State, r.Reason)
	}
	if r := (ShadowCheck{}).Run(nil); r.State != StateCannotDecide {
		t.Errorf("nil input: %s, want cannot_decide", r.State)
	}
}

func setInput(s *nr.Snapshot, k nr.InputKind, st nr.InputState) {
	in := s.Inputs[k]
	in.State = st
	s.Inputs[k] = in
}

// TestShadowLimitCannotDecide exhausts the shared work budget: every rule
// after that is cannot_decide "limit reached", never ok.
func TestShadowLimitCannotDecide(t *testing.T) {
	target := box{
		from: s("a"), to: s("b"),
		src: addrUniverse, dst: addrUniverse, svc: fullService(),
	}
	cover := target
	shared := 0
	w := &work{max: MaxShadowWorkPerRule, shared: &shared}
	if got := covers(target, []box{cover}, w); got != coverLimit {
		t.Errorf("shared budget 0: covers = %v, want coverLimit", got)
	}
	w = &work{max: 0}
	if got := covers(target, []box{cover}, w); got != coverLimit {
		t.Errorf("rule budget 0: covers = %v, want coverLimit", got)
	}
	w = &work{max: MaxShadowWorkPerRule}
	if got := covers(target, []box{cover}, w); got != fullyCovered {
		t.Errorf("enough budget: covers = %v, want fullyCovered", got)
	}
}
