// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// MaxContradictionQueries bounds the distinct flows (source, destination,
// protocol, port) one model-contradiction run evaluates. A run that would
// need more reports StateCannotDecide "limit reached".
const MaxContradictionQueries = 1 << 14

// ContradictionCheck is the check model-contradiction (ADR 0012 D3/D4):
// observed allowed traffic (traffic-map flows, log aggregates with action
// allow) where the model says denied. It reports one result per distinct
// flow with RuleIndex -1: a finding when the model says denied,
// StateCannotDecide when the model says unknown (it may be either). A
// flow the model also lets through is not listed; with Report.State
// StateOK a flow without a result no longer fires.
//
// It needs every snapshot input fresh and fresh flows; otherwise the
// report is "cannot decide" or "data not collected" and resolves nothing.
// Only tcp and udp flows with a port are evaluated against the model
// (nr-v1 models nothing else); every other allowed flow (icmp, other
// protocols, tcp or udp without a port) gets a StateCannotDecide result,
// so an unevaluable flow never reads as "no longer fires".
type ContradictionCheck struct{}

// ID returns CheckModelContradiction.
func (ContradictionCheck) ID() string { return CheckModelContradiction }

// Run runs the check with context.Background(); see RunContext.
func (c ContradictionCheck) Run(in *Input) Report {
	return c.RunContext(context.Background(), in)
}

type contraKey struct {
	src, dst netip.Addr
	proto    FlowProtocol
	port     uint16
}

type contraAgg struct {
	sessions uint64
	origins  map[string]bool
}

// RunContext runs the check, bounded by netreach.JobBudget. A query
// stopped by the budget is unknown and gives StateCannotDecide.
func (ContradictionCheck) RunContext(ctx context.Context, in *Input) Report {
	fail := func(st State, why string) Report {
		return Report{CheckID: CheckModelContradiction, CheckVersion: CheckVersion, State: st, Reason: clean(why)}
	}
	if st, why := precondition(in, netreach.RequiredInputs...); st != StateOK {
		return fail(st, why)
	}
	if st, why := observationState("flows", in.obs.Flows.State); st != StateOK {
		return fail(st, why)
	}
	aggs := map[contraKey]*contraAgg{}
	for _, fl := range in.obs.Flows.Flows {
		if fl.Action != FlowAllow {
			continue
		}
		k := contraKey{fl.Src.Unmap(), fl.Dst.Unmap(), fl.Protocol, fl.Port}
		a := aggs[k]
		if a == nil {
			if len(aggs) == MaxContradictionQueries {
				return fail(StateCannotDecide, fmt.Sprintf("%s: more than %d distinct flows", netreach.ErrLimitReached, MaxContradictionQueries))
			}
			a = &contraAgg{origins: map[string]bool{}}
			aggs[k] = a
		}
		a.sessions = satAdd(a.sessions, fl.Sessions)
		a.origins[fl.Origin] = true
	}
	keys := make([]contraKey, 0, len(aggs))
	for k := range aggs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b contraKey) int {
		return cmp.Or(a.src.Compare(b.src), a.dst.Compare(b.dst), cmp.Compare(a.proto, b.proto), cmp.Compare(a.port, b.port))
	})
	ctx, cancel := context.WithTimeout(ctx, netreach.JobBudget)
	defer cancel()
	r := Report{CheckID: CheckModelContradiction, CheckVersion: CheckVersion, State: StateOK}
	for _, k := range keys {
		flow := fmt.Sprintf("%s -> %s %s/%d", k.src, k.dst, k.proto, k.port)
		f := Finding{CheckID: CheckModelContradiction, CheckVersion: CheckVersion, RuleIndex: -1}
		a := aggs[k]
		if !k.proto.evaluable(k.port) {
			// nr-v1 models only tcp and udp with a port: the flow may
			// contradict the model or not, so it is never left out.
			why := "protocol " + string(k.proto) + " is not modelled"
			if k.proto == FlowTCP || k.proto == FlowUDP {
				why = "observation has no port"
			}
			f.State = StateCannotDecide
			f.Reason = clean("cannot decide: " + flow + ": " + why)
			f.Flow = &FlowEvidence{
				Source: k.src.String(), Destination: k.dst.String(), Protocol: string(k.proto), Port: k.port,
				Sessions: a.sessions, Origins: cleanAll(sortedUnique(mapKeys(a.origins))),
			}
			r.Findings = append(r.Findings, f)
			continue
		}
		res := in.Index.Evaluate(ctx, netreach.Query{Source: netreach.SourceAddress, SourceAddr: k.src, Destination: k.dst, Protocol: string(k.proto), Port: k.port})
		switch res.Verdict {
		case netreach.VerdictDenied:
			f.State, f.Severity = StateFinding, SeverityHigh
			f.Reason = clean("model contradicted by observed traffic: " + flow + " was observed allowed, the model says denied (" + res.Reason + ")")
		case netreach.VerdictAllowed, netreach.VerdictConditional, netreach.VerdictNotFiltered:
			continue
		default:
			f.State = StateCannotDecide
			f.Reason = clean("cannot decide: " + flow + ": model verdict unknown (" + res.Reason + ")")
		}
		f.Flow = &FlowEvidence{
			Source: k.src.String(), Destination: k.dst.String(), Protocol: string(k.proto), Port: k.port,
			Sessions: a.sessions, Origins: cleanAll(sortedUnique(mapKeys(a.origins))), Chain: clean(res.Text()),
		}
		r.Findings = append(r.Findings, f)
	}
	return r
}
