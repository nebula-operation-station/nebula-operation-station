// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"context"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// MaxMgmtQueries bounds the reachability queries of one
// mgmt-from-untrusted run (targets × addresses × ports × sources). A run
// that would need more reports StateCannotDecide "limit reached".
const MaxMgmtQueries = 1 << 16

// Source names of mgmt-from-untrusted next to zone names.
const (
	SourceNameInternet = "internet"
	SourceNameNetBird  = "netbird"
)

// MgmtEvidence is the evidence of one mgmt-from-untrusted result: the
// target, the address and port, and the verdict from every untrusted
// source (zone name, "internet" or "netbird") in source order.
type MgmtEvidence struct {
	Target   string
	Addr     string
	Protocol string
	Port     uint16
	Sources  []SourceVerdict
}

// SourceVerdict is the verdict of one source. Chain is the explanation
// chain as text for every verdict other than denied (device text; render
// as text only).
type SourceVerdict struct {
	Source  string
	Verdict netreach.Verdict
	Reason  string
	Chain   string
}

// MgmtCheck is the check mgmt-from-untrusted (ADR 0012 D4): a management
// target reachable on a management port from a zone of trust class
// untrusted, guest, iot or unknown (Q9), or from internet or netbird.
// Reachable means a verdict of allowed, conditional, not_filtered or
// unknown (fail closed): an unknown verdict, for example a path that
// reaches an unevaluable rule or the uncollected default rule (ADR 0012
// D2 fail-safe), is a finding, never StateOK.
//
// StateOK ("no longer fires") needs a complete snapshot: every required
// snapshot input fresh, exactly one vsys, fresh management targets and
// the verdict denied from every untrusted source for that address and
// port. Otherwise the report is StateCannotDecide or
// StateDataNotCollected and resolves nothing. One result per (target,
// address, port) with RuleIndex -1; a target without addresses or ports
// gives StateCannotDecide.
type MgmtCheck struct{}

// ID returns CheckMgmtFromUntrusted.
func (MgmtCheck) ID() string { return CheckMgmtFromUntrusted }

// Run runs the check with context.Background(); see RunContext.
func (c MgmtCheck) Run(in *Input) Report { return c.RunContext(context.Background(), in) }

// RunContext runs the check. The whole run is bounded by
// netreach.JobBudget; a query stopped by it is unknown and therefore a
// finding, never StateOK.
func (MgmtCheck) RunContext(ctx context.Context, in *Input) Report {
	fail := func(st State, why string) Report {
		return Report{CheckID: CheckMgmtFromUntrusted, CheckVersion: CheckVersion, State: st, Reason: clean(why)}
	}
	if st, why := precondition(in, netreach.RequiredInputs...); st != StateOK {
		return fail(st, why)
	}
	mt := &in.obs.MgmtTargets
	if st, why := observationState("management targets", mt.State); st != StateOK {
		return fail(st, why)
	}
	sources := mgmtSources(in)
	n := 0
	for _, t := range mt.Targets {
		n += len(t.Addrs) * len(t.Ports) * len(sources)
	}
	if n > MaxMgmtQueries {
		return fail(StateCannotDecide, fmt.Sprintf("%s: %d queries, limit %d", netreach.ErrLimitReached, n, MaxMgmtQueries))
	}
	ctx, cancel := context.WithTimeout(ctx, netreach.JobBudget)
	defer cancel()
	r := Report{CheckID: CheckMgmtFromUntrusted, CheckVersion: CheckVersion, State: StateOK}
	for _, t := range mt.Targets {
		if len(t.Addrs) == 0 || len(t.Ports) == 0 {
			f := Finding{CheckID: CheckMgmtFromUntrusted, CheckVersion: CheckVersion, RuleIndex: -1, State: StateCannotDecide,
				Reason: clean("cannot decide: target " + t.Name + " has no known address or management port"),
				Mgmt:   &MgmtEvidence{Target: clean(t.Name)}}
			r.Findings = append(r.Findings, f)
			continue
		}
		for _, a := range t.Addrs {
			for _, p := range t.Ports {
				r.Findings = append(r.Findings, mgmtResult(ctx, in, &t, a.String(), netreach.Query{Destination: a, Protocol: p.Protocol, Port: p.Port}, sources))
			}
		}
	}
	return r
}

// mgmtSource is one untrusted source of the check.
type mgmtSource struct {
	name string
	kind netreach.SourceKind
}

// mgmtSources returns the zones of trust class untrusted, guest, iot or
// unknown in snapshot order, then internet and netbird.
func mgmtSources(in *Input) []mgmtSource {
	var out []mgmtSource
	for _, z := range in.Snapshot.Zones {
		switch in.zoneClass(z.Name) {
		case TrustUntrusted, TrustGuest, TrustIoT, TrustUnknown:
			out = append(out, mgmtSource{z.Name, netreach.SourceZone})
		}
	}
	return append(out, mgmtSource{SourceNameInternet, netreach.SourceInternet}, mgmtSource{SourceNameNetBird, netreach.SourceNetBird})
}

func mgmtResult(ctx context.Context, in *Input, t *MgmtTarget, addr string, q netreach.Query, sources []mgmtSource) Finding {
	ev := &MgmtEvidence{Target: clean(t.Name), Addr: addr, Protocol: q.Protocol, Port: q.Port}
	f := Finding{CheckID: CheckMgmtFromUntrusted, CheckVersion: CheckVersion, RuleIndex: -1, Mgmt: ev}
	var reached, unknown []string
	for _, s := range sources {
		q.Source, q.SourceZone, q.NetBird = s.kind, "", netreach.NetBirdFacts{}
		switch s.kind {
		case netreach.SourceZone:
			q.SourceZone = s.name
		case netreach.SourceNetBird:
			q.NetBird = t.NetBird
		}
		res := in.Index.Evaluate(ctx, q)
		sv := SourceVerdict{Source: clean(s.name), Verdict: res.Verdict, Reason: clean(res.Reason)}
		switch res.Verdict {
		case netreach.VerdictDenied:
		case netreach.VerdictAllowed, netreach.VerdictConditional, netreach.VerdictNotFiltered:
			reached = append(reached, s.name+" ("+string(res.Verdict)+")")
			sv.Chain = clean(res.Text())
		default:
			sv.Verdict = netreach.VerdictUnknown
			unknown = append(unknown, s.name)
			sv.Chain = clean(res.Text())
		}
		ev.Sources = append(ev.Sources, sv)
	}
	where := fmt.Sprintf("management target %s %s %s/%d", t.Name, addr, q.Protocol, q.Port)
	switch {
	case len(reached) > 0:
		f.State, f.Severity = StateFinding, SeverityHigh
		why := where + " reachable from " + strings.Join(reached, ", ")
		if len(unknown) > 0 {
			why += "; unknown from " + strings.Join(unknown, ", ")
		}
		f.Reason = clean(why)
	case len(unknown) > 0:
		f.State, f.Severity = StateFinding, SeverityMedium
		f.Reason = clean(where + ": reachability unknown (fail closed) from " + strings.Join(unknown, ", "))
	default:
		f.State, f.Reason = StateOK, clean(where+" denied from every untrusted source")
	}
	return f
}
