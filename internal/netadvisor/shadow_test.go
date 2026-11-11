// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"fmt"
	"runtime"
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
		// Application-default target: its real ports are unknown, so
		// earlier rules that cover only some ports decide nothing.
		{
			name: "application-default rule under tcp and udp all ports cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Service = "tcpudp", list("svc-tcp-all", "svc-udp-all") }),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("tcpudp"), "application-default", ""},
		},
		{
			name: "application-default rule under tcp 80 and 443 cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name = "web" }),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("web"), "application-default", ""},
		},
		{
			name: "application-default rule under two port rules cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Service = "https", list("svc-https") }),
				with(func(r *nr.SecurityRule) { r.Name, r.Service, r.Source = "http", list("svc-http"), list("lan-low") }),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("https", "http"), "application-default", ""},
		},
		{
			name: "application-default rule under a port rule on its whole address space cannot decide",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Source = "low", list("lan-low") }),
				with(func(r *nr.SecurityRule) {
					r.Name, r.Source, r.Service = "high-web", list("lan-high"), list("svc-https")
				}),
				with(func(r *nr.SecurityRule) {
					r.Source, r.Application, r.Service = list("lan-low"), list("ssl"), list("application-default")
				}),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("low"), "application-default", ""},
		},
		{
			name: "application-default rule partly covered on addresses is ok",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Source = "low", list("lan-low") }),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateOK, StateFinding, nil, "not covered", ""},
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
		{
			// The rule's explicit https ports are not default ports of
			// the earlier rule's applications: not a definite cover.
			name: "application-default rule does not shadow a rule mixing application-default and ports",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) { r.Name, r.Application, r.Service = "appdef", list("ssl"), list("application-default") }),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default", "svc-https") }),
			},
			want: want{StateCannotDecide, StateCannotDecide, s("appdef"), "cannot be compared", ""},
		},
		{
			name: "rule mixing application-default and ports shadows an application-default rule",
			rules: []nr.SecurityRule{
				with(func(r *nr.SecurityRule) {
					r.Name, r.Application, r.Service = "mixed", list("ssl"), list("application-default", "svc-https")
				}),
				with(func(r *nr.SecurityRule) { r.Application, r.Service = list("ssl"), list("application-default") }),
			},
			want: want{StateFinding, StateOK, s("mixed"), "never matches", SeverityMedium},
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

// partialOverlaps returns n earlier rules that each cover a part of the
// target (lan-low, https) followed by the target, which is not covered:
// with enough budget it is ok with an overlap hint.
func partialOverlaps(n int, apps nr.Field[[]string]) []nr.SecurityRule {
	var rules []nr.SecurityRule
	for k := range n {
		r := rule(fmt.Sprintf("part-%d", k), deny, s("lan"), s("dmz"), s("lan-low"), s("web-server"), s("svc-https"))
		r.Application = apps
		rules = append(rules, r)
	}
	target := rule("target", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web"))
	target.Application = apps
	return append(rules, target)
}

func wantLimit(t *testing.T, r Report, i int) {
	t.Helper()
	for _, id := range []string{CheckShadowedRule, CheckOverlap} {
		f := byRule(t, r, id, i)
		if f.State != StateCannotDecide || !strings.Contains(f.Reason, "limit reached") {
			t.Errorf("%s rule %d = %s %q, want cannot_decide limit reached", id, i, f.State, f.Reason)
		}
	}
}

// TestShadowRunLimitCannotDecide exhausts the per-rule and the shared
// budget inside ShadowCheck.Run: the rule is cannot_decide "limit
// reached", never ok, while the same policy with enough budget is ok.
func TestShadowRunLimitCannotDecide(t *testing.T) {
	rules := partialOverlaps(30, list("any"))
	last := len(rules) - 1
	in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})

	r := ShadowCheck{}.Run(in)
	if f := byRule(t, r, CheckShadowedRule, last); f.State != StateOK {
		t.Fatalf("default budget: %v, want ok", f)
	}
	if f := byRule(t, r, CheckOverlap, last); f.State != StateFinding {
		t.Fatalf("default budget: %v, want overlap finding", f)
	}

	wantLimit(t, ShadowCheck{workPerRule: 100}.Run(in), last)
	wantLimit(t, ShadowCheck{workPerSnapshot: 1000}.Run(in), last)
}

// TestShadowConditionWorkCharged: a hostile policy within the snapshot
// limits (large application lists on every rule) is stopped by the work
// budget before the condition comparison, so it ends with cannot_decide
// "limit reached". The same policy with application "any" fits the same
// budget and is ok, so the limit comes from the condition work.
func TestShadowConditionWorkCharged(t *testing.T) {
	const budget = 20000
	apps := make([]string, nr.MaxRuleMembers)
	for k := range apps {
		apps[k] = fmt.Sprintf("app-%d", k)
	}
	small := partialOverlaps(10, list("any"))
	in := newInput(t, labSnapshot(small...), nr.Field[map[string]ProfileSetting]{})
	if f := byRule(t, ShadowCheck{workPerRule: budget}.Run(in), CheckShadowedRule, 10); f.State != StateOK {
		t.Fatalf("application any: %v, want ok within budget %d", f, budget)
	}

	hostile := partialOverlaps(10, list(apps...))
	in = newInput(t, labSnapshot(hostile...), nr.Field[map[string]ProfileSetting]{})
	wantLimit(t, ShadowCheck{workPerRule: budget}.Run(in), 10)
	// With the default budget the same policy is decided.
	if f := byRule(t, ShadowCheck{}.Run(in), CheckShadowedRule, 10); f.State != StateOK {
		t.Errorf("default budget: %v, want ok", f)
	}
}

// TestShadowOverlapBookkeepingBounded: a hostile policy of many rules that
// all match everything, with long names, makes every pair of rules
// overlap. The covering names a finding carries stay bounded
// (MaxCoveringNames plus a count), the reasons stay within MaxTextBytes,
// and the bytes the whole run allocates grow linearly with the rules, not
// with the pairs.
func TestShadowOverlapBookkeepingBounded(t *testing.T) {
	const (
		n = 800
		// perRuleBytes is the stated allocation bound of one rule (its
		// match space, conditions, two findings with reasons and covering
		// names). Holding one name per overlapping pair would need about
		// n/2 * 200 bytes per rule (80 KiB here) on average, and joining
		// them into the reason as much again.
		perRuleBytes = 32 << 10
	)
	variants := map[string]struct {
		app   func(k int) nr.Field[[]string]
		state State
	}{
		// Identical rules: rule k is shadowed by all k earlier rules.
		"identical": {func(int) nr.Field[[]string] { return list("any") }, StateFinding},
		// Distinct applications: conditions cannot be compared, rule k
		// is covered only together with them.
		"distinct applications": {func(k int) nr.Field[[]string] { return list(fmt.Sprintf("app-%d", k)) }, StateCannotDecide},
	}
	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			rules := make([]nr.SecurityRule, n)
			for k := range rules {
				rules[k] = rule(fmt.Sprintf("%0200d", k), allow, s("any"), s("any"), s("any"), s("any"), s("any"))
				rules[k].UUID = fmt.Sprintf("uuid-%d", k)
				rules[k].Application = v.app(k)
			}
			in := newInput(t, labSnapshot(rules...), nr.Field[map[string]ProfileSetting]{})

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			r := ShadowCheck{}.Run(in)
			runtime.ReadMemStats(&after)

			if got := after.TotalAlloc - before.TotalAlloc; got > n*perRuleBytes {
				t.Errorf("run allocated %d bytes, bound %d (%d per rule)", got, n*perRuleBytes, perRuleBytes)
			}
			for _, f := range r.Findings {
				if len(f.Covering) > MaxCoveringNames || len(f.Reason) > MaxTextBytes {
					t.Fatalf("rule %d %s: %d covering names, reason %d bytes", f.RuleIndex, f.CheckID, len(f.Covering), len(f.Reason))
				}
				if f.RuleIndex > 0 && f.CoveringTotal != f.RuleIndex {
					t.Fatalf("rule %d %s: covering total %d, want %d", f.RuleIndex, f.CheckID, f.CoveringTotal, f.RuleIndex)
				}
				if f.CoveringTotal < len(f.Covering) {
					t.Fatalf("rule %d %s: covering total %d below %d names", f.RuleIndex, f.CheckID, f.CoveringTotal, len(f.Covering))
				}
			}
			last := byRule(t, r, CheckShadowedRule, n-1)
			if last.State != v.state {
				t.Fatalf("last rule = %v, want %s", last, v.state)
			}
			if len(last.Covering) != MaxCoveringNames || !strings.Contains(last.Reason, fmt.Sprintf("%d more", n-1-MaxCoveringNames)) {
				t.Errorf("last rule covering %d names, reason %q: want %d names and the rest counted", len(last.Covering), last.Reason, MaxCoveringNames)
			}
		})
	}
}
