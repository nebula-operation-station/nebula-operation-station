// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

func fuzzList(v string) nr.Field[[]string] {
	if v == "!" {
		return nr.Field[[]string]{}
	}
	return nr.Collected(strings.Split(v, ","))
}

// FuzzRuleInputs builds one security rule and its hit counter from fuzzed
// device text and runs every check with fresh or stale observations. No
// check may panic, every text must be valid UTF-8 within MaxTextBytes,
// only the four states may appear, a failed report carries no ok result,
// stale hit counts never give ok, and an enabled rule with a rule-level
// <dropped:…> marker is never ok for dns-bypass.
func FuzzRuleInputs(f *testing.F) {
	f.Add("r", "allow", "lan", "wan", "any", "any", "any", "any", uint8(0), uint64(0), int16(40), int16(90))
	f.Add("r", "allow", "any", "any", "any", "any", "svc-dns", "dns", uint8(0b10), uint64(5), int16(10), int16(5))
	f.Add("x\xff", "deny", "guest", "mgmt", "!", "<dropped:a>", "application-default", "ssl", uint8(0xff), uint64(0), int16(-3), int16(400))
	f.Fuzz(func(t *testing.T, name, action, from, to, src, dst, svc, app string, flags uint8, hits uint64, resetDays, createdDays int16) {
		r := rule(name, nr.Action(action), nil, nil, nil, nil, nil)
		r.From, r.To, r.Source, r.Destination = fuzzList(from), fuzzList(to), fuzzList(src), fuzzList(dst)
		r.Service, r.Application = fuzzList(svc), fuzzList(app)
		disabled := flags&1 != 0
		r.Disabled = nr.Collected(disabled)
		if flags&2 != 0 {
			r.Type = nr.Field[nr.RuleType]{}
		}
		if flags&4 != 0 {
			r.NegateDestination = nr.Collected(true)
		}
		dropped := flags&8 != 0
		if dropped {
			r.Dropped = s("<dropped:x>")
		}
		hitState := nr.InputFresh
		if flags&16 != 0 {
			hitState = nr.InputStale
		}
		in, err := NewInput(labSnapshot(r), labClasses, nr.Field[map[string]ProfileSetting]{})
		if err != nil {
			return
		}
		rh := RuleHits{RuleName: name, Hits: hits, ResetAt: hitsNow.Add(-time.Duration(resetDays) * 24 * time.Hour)}
		if flags&32 == 0 {
			rh.Created = nr.Collected(hitsNow.Add(-time.Duration(createdDays) * 24 * time.Hour))
		}
		obs := Observations{
			Hits:          HitCounts{State: hitState, ObservedAt: hitsNow, Rules: []RuleHits{rh}},
			Flows:         Flows{State: nr.InputFresh, Flows: []Flow{flow("10.0.1.5", "10.20.0.10", "tcp", 443), flow("10.0.1.5", "8.8.8.8", "udp", 53)}},
			FirewallAddrs: FirewallAddrs{State: nr.InputFresh, Addrs: labFirewallAddrs},
			MgmtTargets:   MgmtTargets{State: nr.InputFresh, Targets: []MgmtTarget{pveTarget()}},
		}
		if err := in.SetObservations(obs); err != nil {
			if utf8.ValidString(name) && name != "" && len(name) <= nr.MaxNameBytes {
				t.Fatalf("valid observations refused: %v", err)
			}
			return
		}
		for _, c := range Checks() {
			rep := c.Run(in)
			if rep.CheckID != c.ID() || rep.CheckVersion != CheckVersion || !validFuzzState(rep.State) || !validText(rep.Reason) {
				t.Fatalf("%s: bad report header %+v", c.ID(), rep)
			}
			for _, fd := range rep.Findings {
				if !validFuzzState(fd.State) || !validText(fd.Reason) || !validText(fd.RuleName) ||
					(fd.CheckID != c.ID() && (c.ID() != CheckShadowedRule || fd.CheckID != CheckOverlap)) {
					t.Fatalf("%s: bad finding %+v", c.ID(), fd)
				}
				if rep.State != StateOK && fd.State == StateOK {
					t.Fatalf("%s: ok result in a %s report", c.ID(), rep.State)
				}
				switch {
				case c.ID() == CheckZeroHits && hitState != nr.InputFresh && fd.State == StateOK:
					t.Fatalf("zero-hits ok from stale hit counts: %+v", fd)
				case c.ID() == CheckDNSBypass && fd.RuleIndex == 0 && dropped && !disabled && fd.State == StateOK:
					t.Fatalf("dns-bypass ok on a rule with a dropped marker: %+v", fd)
				case fd.State == StateFinding && fd.Severity == "":
					t.Fatalf("%s: finding without severity: %+v", c.ID(), fd)
				}
			}
		}
	})
}

func validFuzzState(s State) bool {
	switch s {
	case StateOK, StateFinding, StateCannotDecide, StateDataNotCollected:
		return true
	}
	return false
}

func validText(s string) bool { return utf8.ValidString(s) && len(s) <= MaxTextBytes }
