// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	nr "github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

func contraInput(t *testing.T, snap *nr.Snapshot, st nr.InputState, flows ...Flow) *Input {
	t.Helper()
	in := newInput(t, snap, nr.Field[map[string]ProfileSetting]{})
	if err := in.SetObservations(Observations{Flows: Flows{State: st, Flows: flows}}); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestModelContradiction(t *testing.T) {
	webAllow := rule("web", allow, s("lan"), s("dmz"), s("any"), s("web-server"), s("svc-web"))
	noType := rule("odd", allow, s("any"), s("any"), s("any"), s("any"), s("svc-web"))
	noType.Type = nr.Field[nr.RuleType]{}
	denied := flow("10.0.1.5", "10.20.0.10", "tcp", 443)
	denied.Action = FlowDeny
	tests := []struct {
		name   string
		rules  []nr.SecurityRule
		flows  []Flow
		state  State // "" = no result
		reason string
	}{
		{name: "observed allowed, model denied fires", flows: []Flow{flow("10.0.1.5", "10.20.0.10", "tcp", 443)},
			state: StateFinding, reason: "model contradicted by observed traffic"},
		{name: "model allows", rules: []nr.SecurityRule{webAllow}, flows: []Flow{flow("10.0.1.5", "10.20.0.10", "tcp", 443)}},
		{name: "same segment is not filtered", flows: []Flow{flow("10.0.1.5", "10.0.1.6", "tcp", 22)}},
		{name: "denied flow is no contradiction", flows: []Flow{denied}},
		{name: "icmp is not modelled and cannot decide", flows: []Flow{flow("10.0.1.5", "10.20.0.10", "icmp", 0)},
			state: StateCannotDecide, reason: "not modelled"},
		{name: "other protocol cannot decide", flows: []Flow{flow("10.0.1.5", "10.20.0.10", "other", 0)},
			state: StateCannotDecide, reason: "not modelled"},
		{name: "tcp without port cannot decide", flows: []Flow{flow("10.0.1.5", "10.20.0.10", "tcp", 0)},
			state: StateCannotDecide, reason: "no port"},
		{name: "udp without port cannot decide even if the model allows udp", rules: []nr.SecurityRule{webAllow},
			flows: []Flow{flow("10.0.1.5", "10.20.0.10", "udp", 0)}, state: StateCannotDecide, reason: "no port"},
		{name: "unevaluable rule gives cannot decide", rules: []nr.SecurityRule{noType},
			flows: []Flow{flow("10.0.1.5", "10.20.0.10", "tcp", 443)}, state: StateCannotDecide, reason: "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := ContradictionCheck{}.Run(contraInput(t, labSnapshot(tc.rules...), nr.InputFresh, tc.flows...))
			if rep.State != StateOK {
				t.Fatalf("report %s: %s", rep.State, rep.Reason)
			}
			if tc.state == "" {
				if len(rep.Findings) != 0 {
					t.Fatalf("results %+v, want none", rep.Findings)
				}
				return
			}
			f := onlyResult(t, rep)
			if f.State != tc.state || !strings.Contains(f.Reason, tc.reason) {
				t.Errorf("got %s %q, want %s containing %q", f.State, f.Reason, tc.state, tc.reason)
			}
			unevaluable := f.Flow != nil && (f.Flow.Port == 0 || f.Flow.Protocol == "icmp" || f.Flow.Protocol == "other")
			if f.Flow == nil || f.Flow.Source != "10.0.1.5" || (f.Flow.Chain == "") != unevaluable {
				t.Errorf("evidence %+v", f.Flow)
			}
		})
	}
}

// TestModelContradictionUnevaluableFlowNeverResolves: an allowed flow the
// model cannot evaluate is listed as cannot decide (aggregated over
// IPv4-mapped sources), so it never reads as "no longer fires".
func TestModelContradictionUnevaluableFlowNeverResolves(t *testing.T) {
	denied := flow("10.0.1.5", "10.20.0.10", "udp", 0)
	denied.Action = FlowDeny
	rep := ContradictionCheck{}.Run(contraInput(t, labSnapshot(), nr.InputFresh,
		flow("10.0.1.5", "10.20.0.10", "udp", 0), flow("::ffff:10.0.1.5", "10.20.0.10", "udp", 0), denied))
	f := onlyResult(t, rep)
	if f.State != StateCannotDecide || f.Flow.Sessions != 6 {
		t.Errorf("got %s %q %+v", f.State, f.Reason, f.Flow)
	}
}

func TestModelContradictionAggregates(t *testing.T) {
	a := flow("10.0.1.5", "10.20.0.10", "tcp", 443)
	b := a
	b.Src = netip.MustParseAddr("::ffff:10.0.1.5")
	b.Origin = "fw-log"
	f := onlyResult(t, ContradictionCheck{}.Run(contraInput(t, labSnapshot(), nr.InputFresh, a, b)))
	if f.Flow.Sessions != 6 || len(f.Flow.Origins) != 2 {
		t.Errorf("aggregate %+v", f.Flow)
	}
}

func TestModelContradictionFailSafe(t *testing.T) {
	f := flow("10.0.1.5", "10.20.0.10", "tcp", 443)
	for _, tc := range []struct {
		name  string
		st    nr.InputState
		stale nr.InputKind
		want  State
	}{
		{"flows missing", nr.InputMissing, "", StateDataNotCollected},
		{"flows stale", nr.InputStale, "", StateCannotDecide},
		{"flows incomplete", nr.InputIncomplete, "", StateCannotDecide},
		{"default rules stale", nr.InputFresh, nr.InputDefaultRules, StateCannotDecide},
	} {
		snap := labSnapshot()
		if tc.stale != "" {
			snap.Inputs[tc.stale] = nr.Input{State: nr.InputStale}
		}
		rep := ContradictionCheck{}.Run(contraInput(t, snap, tc.st, f))
		if rep.State != tc.want || len(rep.Findings) != 0 {
			t.Errorf("%s: %s with %d results, want %s", tc.name, rep.State, len(rep.Findings), tc.want)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := onlyResult(t, ContradictionCheck{}.RunContext(ctx, contraInput(t, labSnapshot(), nr.InputFresh, f)))
	if got.State != StateCannotDecide {
		t.Errorf("canceled job: %s %q", got.State, got.Reason)
	}

	var many []Flow
	for i := range MaxContradictionQueries + 1 {
		many = append(many, flow("10.0.1.5", "10.20.0.10", "tcp", uint16(i+1)))
	}
	rep := ContradictionCheck{}.Run(contraInput(t, labSnapshot(), nr.InputFresh, many...))
	if rep.State != StateCannotDecide || !strings.Contains(rep.Reason, "limit reached") {
		t.Errorf("limit: %s %q", rep.State, rep.Reason)
	}
}
