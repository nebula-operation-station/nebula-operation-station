// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// TestRuleMarkersNeverOK covers rule-level unevaluability (ADR 0012 D2):
// a rule with a <dropped:…> marker or a field outside the collected
// allowlist is never reported ok by any-any or allow-without-profile.
func TestRuleMarkersNeverOK(t *testing.T) {
	marks := map[string]func(*nr.SecurityRule){
		"dropped marker":    func(r *nr.SecurityRule) { r.Dropped = []string{"<dropped:source-user>"} },
		"outside allowlist": func(r *nr.SecurityRule) { r.OutsideAllowlist = []string{"source-imei"} },
	}
	// Rules both checks would otherwise report ok.
	bases := map[string]func() nr.SecurityRule{
		"narrow internal allow": func() nr.SecurityRule {
			r := rule("r", allow, s("lan"), s("dmz"), s("lan-net"), s("web-server"), s("svc-web"))
			r.Application = list("ssl")
			return r
		},
		"deny rule": func() nr.SecurityRule {
			r := rule("r", deny, s("guest"), s("lan"), s("lan-net"), s("web-server"), s("svc-web"))
			r.Application = list("ssl")
			return r
		},
		"guest rule with profile": func() nr.SecurityRule {
			r := rule("r", allow, s("guest"), s("lan"), s("lan-net"), s("web-server"), s("svc-web"))
			r.Application = list("ssl")
			return r
		},
	}
	profiles := nr.Collected(map[string]ProfileSetting{"uuid-r": {Group: "strict"}})
	for bn, base := range bases {
		for mn, mark := range marks {
			t.Run(bn+"/"+mn, func(t *testing.T) {
				// Without the marker both checks are ok.
				in := newInput(t, labSnapshot(base()), profiles)
				for _, c := range []Check{AnyAnyCheck{}, ProfileCheck{}} {
					if f := c.Run(in).Findings[0]; f.State != StateOK {
						t.Fatalf("%s unmarked = %v, want ok", c.ID(), f)
					}
				}
				r := base()
				mark(&r)
				in = newInput(t, labSnapshot(r), profiles)
				for _, c := range []Check{AnyAnyCheck{}, ProfileCheck{}} {
					f := c.Run(in).Findings[0]
					if f.State != StateCannotDecide || !strings.HasPrefix(f.Reason, "cannot decide:") {
						t.Errorf("%s marked = %v, want cannot_decide", c.ID(), f)
					}
				}
			})
		}
	}
}

// TestRuleMarkersKeepFinding: a marker does not hide a finding a check
// can prove from the collected fields; it is named as not decided.
func TestRuleMarkersKeepFinding(t *testing.T) {
	r := rule("r", allow, s("lan"), s("dmz"), s("any"), s("any"), s("svc-web"))
	r.Dropped = []string{"<dropped:category>"}
	f := AnyAnyCheck{}.Run(newInput(t, labSnapshot(r), nr.Field[map[string]ProfileSetting]{})).Findings[0]
	if f.State != StateFinding || !strings.Contains(f.Reason, "<dropped:category>") {
		t.Errorf("any-any = %v, want finding naming the marker", f)
	}
	r = rule("r", allow, s("guest"), s("lan"), s("any"), s("lan-net"), s("svc-web"))
	r.OutsideAllowlist = []string{"source-imei"}
	f = ProfileCheck{}.Run(newInput(t, labSnapshot(r), nr.Collected(map[string]ProfileSetting{"uuid-r": {}}))).Findings[0]
	if f.State != StateFinding {
		t.Errorf("allow-without-profile = %v, want finding", f)
	}
}

// TestRuleMarkersDisabledRuleOK: a disabled rule is out of every check,
// as in netreach's classification.
func TestRuleMarkersDisabledRuleOK(t *testing.T) {
	r := rule("r", allow, s("any"), s("any"), s("any"), s("any"), s("any"))
	r.Disabled = nr.Collected(true)
	r.Dropped = []string{"<dropped:x>"}
	in := newInput(t, labSnapshot(r), nr.Collected(map[string]ProfileSetting{"uuid-r": {}}))
	for _, c := range []Check{AnyAnyCheck{}, ProfileCheck{}} {
		if f := c.Run(in).Findings[0]; f.State != StateOK {
			t.Errorf("%s = %v, want ok", c.ID(), f)
		}
	}
}
