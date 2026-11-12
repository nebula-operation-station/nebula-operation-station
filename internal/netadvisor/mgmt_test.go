// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"context"
	"maps"
	"net/netip"
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// pveTarget is a PVE node in the mgmt zone. Its NetBird traffic enters
// the lab through a routing peer in the guest zone.
func pveTarget() MgmtTarget {
	return MgmtTarget{
		Name:  "pve1",
		Addrs: []netip.Addr{netip.MustParseAddr("192.168.99.10")},
		Ports: []MgmtPort{{"tcp", 8006}},
		NetBird: nr.NetBirdFacts{
			Peer:         nr.Collected(false),
			RoutingPeers: nr.Collected([]nr.RoutingPeer{{Name: "nb-router", Addr: netip.MustParseAddr("10.50.0.5")}}),
		},
	}
}

func mgmtInput(t *testing.T, snap *nr.Snapshot, classes map[string]TrustClass, targets ...MgmtTarget) *Input {
	t.Helper()
	in, err := NewInput(snap, classes, nr.Field[map[string]ProfileSetting]{})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.SetObservations(Observations{MgmtTargets: MgmtTargets{State: nr.InputFresh, Targets: targets}}); err != nil {
		t.Fatal(err)
	}
	return in
}

func onlyResult(t *testing.T, r Report) Finding {
	t.Helper()
	if r.State != StateOK {
		t.Fatalf("report %s: %s", r.State, r.Reason)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings %+v, want one", r.Findings)
	}
	return r.Findings[0]
}

func TestMgmtFromUntrusted(t *testing.T) {
	noType := rule("lan-dmz", allow, s("any"), s("any"), s("any"), s("any"), s("svc-web"))
	noType.Type = nr.Field[nr.RuleType]{}
	dropped := rule("odd", deny, s("guest"), s("mgmt"), s("any"), s("any"), s("any"))
	dropped.Dropped = s("<dropped:source-user>")
	peer := pveTarget()
	peer.NetBird.Peer = nr.Collected(true)
	unproven := pveTarget()
	unproven.NetBird = nr.NetBirdFacts{}
	tests := []struct {
		name     string
		rules    []nr.SecurityRule
		noDefRul bool
		target   MgmtTarget
		state    State
		sev      Severity
		reason   string
	}{
		{name: "default deny everywhere is ok", target: pveTarget(), state: StateOK, reason: "denied from every"},
		{name: "allow from guest fires", target: pveTarget(), state: StateFinding, sev: SeverityHigh, reason: "guest (allowed)",
			rules: []nr.SecurityRule{rule("g", allow, s("guest"), s("mgmt"), s("any"), s("any"), s("any"))}},
		{name: "allow from wan zone fires as internet too", target: pveTarget(), state: StateFinding, sev: SeverityHigh, reason: "internet (allowed)",
			rules: []nr.SecurityRule{rule("w", allow, s("wan"), s("mgmt"), s("any"), s("192.168.99.10"), s("any"))}},
		{name: "allow from internal lan is ok", target: pveTarget(), state: StateOK,
			rules: []nr.SecurityRule{rule("l", allow, s("lan"), s("mgmt"), s("any"), s("any"), s("any"))}},
		{name: "allow on another port is ok", target: pveTarget(), state: StateOK,
			rules: []nr.SecurityRule{rule("g", allow, s("guest"), s("mgmt"), s("any"), s("any"), s("svc-web"))}},
		{name: "conditional allow fires", target: pveTarget(), state: StateFinding, sev: SeverityHigh, reason: "conditional",
			rules: []nr.SecurityRule{func() nr.SecurityRule {
				r := rule("g", allow, s("guest"), s("mgmt"), s("any"), s("any"), s("any"))
				r.Schedule = nr.Collected("weekdays")
				return r
			}()}},
		{name: "netbird peer is not filtered", target: peer, state: StateFinding, sev: SeverityHigh, reason: "netbird (not_filtered)"},
		{name: "netbird not proven is unknown", target: unproven, state: StateFinding, sev: SeverityMedium, reason: "unknown (fail closed) from netbird"},
		{name: "unevaluable rule reached is unknown, never ok", target: pveTarget(), state: StateFinding, sev: SeverityMedium, reason: "unknown",
			rules: []nr.SecurityRule{noType}},
		{name: "dropped marker on a deny is unknown, never ok", target: pveTarget(), state: StateFinding, sev: SeverityMedium, reason: "unknown",
			rules: []nr.SecurityRule{dropped}},
		{name: "default rules not collected is unknown, never ok", target: pveTarget(), noDefRul: true, state: StateFinding, sev: SeverityMedium, reason: "unknown"},
		{name: "target without address", target: MgmtTarget{Name: "bmc", Ports: []MgmtPort{{"tcp", 443}}}, state: StateCannotDecide, reason: "no known address"},
		{name: "target without ports", target: MgmtTarget{Name: "bmc", Addrs: []netip.Addr{netip.MustParseAddr("192.168.99.20")}}, state: StateCannotDecide, reason: "no known address or management port"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := labSnapshot(tc.rules...)
			if tc.noDefRul {
				snap.DefaultRules = nr.Field[nr.DefaultRules]{}
			}
			f := onlyResult(t, MgmtCheck{}.Run(mgmtInput(t, snap, labClasses, tc.target)))
			if f.State != tc.state || f.Severity != tc.sev || !strings.Contains(f.Reason, tc.reason) {
				t.Errorf("got %s/%s %q, want %s/%s containing %q", f.State, f.Severity, f.Reason, tc.state, tc.sev, tc.reason)
			}
			if f.Mgmt == nil || f.Mgmt.Target != tc.target.Name {
				t.Errorf("evidence %+v", f.Mgmt)
			}
			if f.State == StateFinding {
				chain := false
				for _, sv := range f.Mgmt.Sources {
					chain = chain || (sv.Verdict != nr.VerdictDenied && sv.Chain != "")
				}
				if !chain {
					t.Errorf("finding without verdict chain: %+v", f.Mgmt.Sources)
				}
			}
		})
	}
}

// TestMgmtUnknownZoneClassCountsAsUntrusted: a zone without a trust class
// is a source (Q9); classed internal it is not.
func TestMgmtUnknownZoneClassCountsAsUntrusted(t *testing.T) {
	snap := func() *nr.Snapshot {
		return labSnapshot(rule("d", allow, s("dmz"), s("mgmt"), s("any"), s("any"), s("any")))
	}
	unclassed := maps.Clone(labClasses)
	delete(unclassed, "dmz")
	if f := onlyResult(t, MgmtCheck{}.Run(mgmtInput(t, snap(), unclassed, pveTarget()))); f.State != StateFinding || !strings.Contains(f.Reason, "dmz") {
		t.Errorf("unclassed dmz: %s %q", f.State, f.Reason)
	}
	iot := maps.Clone(labClasses)
	iot["dmz"] = TrustIoT
	if f := onlyResult(t, MgmtCheck{}.Run(mgmtInput(t, snap(), iot, pveTarget()))); f.State != StateFinding {
		t.Errorf("iot dmz: %s %q", f.State, f.Reason)
	}
	if f := onlyResult(t, MgmtCheck{}.Run(mgmtInput(t, snap(), labClasses, pveTarget()))); f.State != StateOK {
		t.Errorf("internal dmz: %s %q", f.State, f.Reason)
	}
}

// TestMgmtClosesOnlyOnCompleteSnapshot: a stale or incomplete snapshot
// input, a missing or stale target list, more than one vsys, the query
// limit or a canceled job never give ok.
func TestMgmtClosesOnlyOnCompleteSnapshot(t *testing.T) {
	for _, k := range nr.RequiredInputs {
		for _, st := range []nr.InputState{nr.InputStale, nr.InputIncomplete, nr.InputMissing} {
			snap := labSnapshot()
			snap.Inputs[k] = nr.Input{State: st}
			rep := MgmtCheck{}.Run(mgmtInput(t, snap, labClasses, pveTarget()))
			if rep.State == StateOK || len(rep.Findings) != 0 {
				t.Errorf("input %s %s: report %s with %d results", k, st, rep.State, len(rep.Findings))
			}
		}
	}
	snap := labSnapshot()
	snap.Vsys = 2
	if rep := (MgmtCheck{}).Run(mgmtInput(t, snap, labClasses, pveTarget())); rep.State != StateCannotDecide {
		t.Errorf("two vsys: %s", rep.State)
	}
	for st, want := range map[nr.InputState]State{nr.InputMissing: StateDataNotCollected, nr.InputStale: StateCannotDecide, nr.InputIncomplete: StateCannotDecide} {
		in := newInput(t, labSnapshot(), nr.Field[map[string]ProfileSetting]{})
		if err := in.SetObservations(Observations{MgmtTargets: MgmtTargets{State: st, Targets: []MgmtTarget{pveTarget()}}}); err != nil {
			t.Fatal(err)
		}
		if rep := (MgmtCheck{}).Run(in); rep.State != want || len(rep.Findings) != 0 {
			t.Errorf("targets %s: %s with %d results, want %s", st, rep.State, len(rep.Findings), want)
		}
	}

	big := make([]MgmtTarget, 0, MaxMgmtQueries/(MaxMgmtAddrsPerTarget*MaxMgmtPortsPerTarget)+1)
	for range cap(big) {
		tg := pveTarget()
		tg.Addrs = make([]netip.Addr, MaxMgmtAddrsPerTarget)
		tg.Ports = make([]MgmtPort, MaxMgmtPortsPerTarget)
		for i := range tg.Addrs {
			tg.Addrs[i] = netip.AddrFrom4([4]byte{192, 168, 99, byte(i + 10)})
		}
		for i := range tg.Ports {
			tg.Ports[i] = MgmtPort{"tcp", uint16(8000 + i)}
		}
		big = append(big, tg)
	}
	if rep := (MgmtCheck{}).Run(mgmtInput(t, labSnapshot(), labClasses, big...)); rep.State != StateCannotDecide || !strings.Contains(rep.Reason, "limit reached") {
		t.Errorf("query limit: %s %q", rep.State, rep.Reason)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := onlyResult(t, MgmtCheck{}.RunContext(ctx, mgmtInput(t, labSnapshot(), labClasses, pveTarget())))
	if f.State != StateFinding || !strings.Contains(f.Reason, "unknown") {
		t.Errorf("canceled job: %s %q, want unknown finding", f.State, f.Reason)
	}
}

func TestSetObservationsRejectsTargets(t *testing.T) {
	in := newInput(t, labSnapshot(), nr.Field[map[string]ProfileSetting]{})
	with := func(mod func(*MgmtTarget)) Observations {
		tg := pveTarget()
		mod(&tg)
		return Observations{MgmtTargets: MgmtTargets{Targets: []MgmtTarget{tg}}}
	}
	tests := map[string]Observations{
		"empty name":       with(func(t *MgmtTarget) { t.Name = "" }),
		"invalid name":     with(func(t *MgmtTarget) { t.Name = "\xff" }),
		"icmp port":        with(func(t *MgmtTarget) { t.Ports = []MgmtPort{{"icmp", 1}} }),
		"port 0":           with(func(t *MgmtTarget) { t.Ports = []MgmtPort{{"tcp", 0}} }),
		"invalid address":  with(func(t *MgmtTarget) { t.Addrs = []netip.Addr{{}} }),
		"too many addrs":   with(func(t *MgmtTarget) { t.Addrs = make([]netip.Addr, MaxMgmtAddrsPerTarget+1) }),
		"too many ports":   with(func(t *MgmtTarget) { t.Ports = make([]MgmtPort, MaxMgmtPortsPerTarget+1) }),
		"bad peer":         with(func(t *MgmtTarget) { t.NetBird.RoutingPeers = nr.Collected([]nr.RoutingPeer{{Name: "p"}}) }),
		"too many targets": {MgmtTargets: MgmtTargets{Targets: make([]MgmtTarget, MaxMgmtTargets+1)}},
	}
	for name, o := range tests {
		if err := in.SetObservations(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := in.SetObservations(with(func(*MgmtTarget) {})); err != nil {
		t.Errorf("valid target refused: %v", err)
	}
}
