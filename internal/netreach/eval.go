// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SourceKind is the kind of a query source (ADR 0012 D2).
type SourceKind string

// Source kinds. Zone, internet and NetBird sources have no single source
// address: a rule whose source field is not "any" then matches only part of
// the possible sources and is treated as a condition ("source address").
const (
	SourceAddress  SourceKind = "address"
	SourceSubnet   SourceKind = "subnet"
	SourceZone     SourceKind = "zone"
	SourceInternet SourceKind = "internet"
	SourceNetBird  SourceKind = "netbird"
)

// Reasons of the NetBird source (ADR 0012 D2 step 1).
const (
	ReasonOverlayBypass    = "overlay path bypasses the firewall"
	ReasonNetBirdNotProven = "NetBird path not proven"
)

// Query is one reachability query (ADR 0012 D2). Exactly the field that
// belongs to Source is read: SourceAddr for an address, SourcePrefix for a
// subnet, SourceZone for a zone, NetBird for the netbird entry class.
// Protocol is "tcp" or "udp"; Port is 1–65535.
type Query struct {
	Source       SourceKind
	SourceAddr   netip.Addr
	SourcePrefix netip.Prefix
	SourceZone   string
	NetBird      NetBirdFacts
	Destination  netip.Addr
	Protocol     string
	Port         uint16
}

// NetBirdFacts is what the host data (ADR 0009 net.facts) says about the
// NetBird paths to the destination. Peer is set when the destination has a
// NetBird interface itself. RoutingPeers are the places where overlay
// traffic to the destination enters the lab: the lab address of each
// routing peer whose routes cover the destination, or an overlay address
// the firewall routes when the firewall is the peer. Both must be
// collected; anything not collected gives unknown "NetBird path not
// proven".
type NetBirdFacts struct {
	Peer         Field[bool]
	RoutingPeers Field[[]RoutingPeer]
}

// RoutingPeer is one place where overlay traffic enters the lab.
type RoutingPeer struct {
	Name string
	Addr netip.Addr
}

// Evaluate answers one query against the snapshot (ADR 0012 D2 steps 1–5)
// and returns its verdict, reason and explanation chain. It never fails:
// whatever cannot be evaluated gives unknown with a reason. Every budget
// stop gives unknown with the reason "limit reached" (ADR 0012 limits):
// the work budget (MaxWorkPerQuery), the path limit (MaxPathsPerQuery),
// the chain limit (MaxChainSteps) and the wall-clock budget. Evaluate
// bounds ctx with JobBudget itself, so a caller that passes
// context.Background() still stops at the deadline; an earlier caller
// deadline or cancel stops it as well. The verdict step of the chain
// names the limit that was hit. Apart from ctx and the wall clock it is
// pure and deterministic: the same index and query give the same result.
func (x *Index) Evaluate(ctx context.Context, q Query) Result {
	return x.evaluate(ctx, q, defaultEvalLimits())
}

// JobBudget is the ADR 0012 wall-clock budget of one advisor job (default
// 30 s). Evaluate applies it to every query (context.WithTimeout on the
// caller's ctx); a job that runs several queries bounds its own context
// with it as well, so the whole job ends within the budget.
const JobBudget = 30 * time.Second

// Limits named in the verdict step of a query stopped with "limit
// reached". The reason is always ErrLimitReached; these say which limit.
const (
	limitWork     = "work budget per query"
	limitPaths    = "paths per query"
	limitChain    = "explanation chain steps"
	limitDeadline = "wall-clock budget: deadline exceeded"
	limitCanceled = "wall-clock budget: job canceled"
)

// MaxWorkPerQuery is the operation budget of one query. One unit is one
// address range or port span comparison, one zone list member compared,
// or one rule or NAT rule step. Every rule step is charged before its
// match runs, with an upper bound of the comparisons it can make
// (searchCost), so a query never does more than MaxWorkPerQuery units of
// matching work; a query that would exceed it ends with unknown "limit
// reached". At a few nanoseconds per comparison the budget is well under
// one second. A lab at the snapshot limits with small rule fields needs
// far less: 64 paths · 10000 rules · about 30 units is about 2e7. Without
// the budget a hostile snapshot (63 port forwards with 4096-range pre-NAT
// destinations, rules with 4096-range destinations) costs about 1e10.
// Placement is bounded separately: at most MaxPathsPerQuery+2 Place calls
// per query, each linear in the placement inputs.
const MaxWorkPerQuery = 1 << 26

// evalLimits are the per-query limits. They are a value so tests can check
// the limit logic at small sizes.
type evalLimits struct {
	paths  int           // MaxPathsPerQuery
	steps  int           // MaxChainSteps
	work   int           // MaxWorkPerQuery
	budget time.Duration // JobBudget
}

func defaultEvalLimits() evalLimits {
	return evalLimits{paths: MaxPathsPerQuery, steps: MaxChainSteps, work: MaxWorkPerQuery, budget: JobBudget}
}

// searchCost bounds the comparisons of matching nx packet ranges against
// a merged field of nm ranges: per packet range two binary searches of at
// most bits.Len(nm) probes and two comparisons each.
func searchCost(nx, nm int) int {
	return 2 * nx * (bits.Len(uint(nm)) + 2)
}

// outcome is the verdict of one path or of the whole query.
type outcome struct {
	verdict Verdict
	reason  string
}

func unknownOut(reason string) outcome { return outcome{VerdictUnknown, reason} }

// rank orders verdicts from most to least reachable (ADR 0012 D2 step 3).
func rank(v Verdict) int {
	switch v {
	case VerdictAllowed:
		return 0
	case VerdictConditional:
		return 1
	case VerdictNotFiltered:
		return 2
	case VerdictDenied:
		return 4
	}
	return 3
}

// mostReachable combines the outcomes of several paths: the most reachable
// one wins, so the result is denied only when every path is denied. No
// outcome at all is unknown.
func mostReachable(outs []outcome) outcome {
	if len(outs) == 0 {
		return unknownOut("no path evaluated")
	}
	best := outs[0]
	for _, o := range outs[1:] {
		if rank(o.verdict) < rank(best.verdict) {
			best = o
		}
	}
	return best
}

type evaluator struct {
	// ctx is the caller's context; job is ctx bounded with lim.budget
	// while result runs.
	ctx   context.Context
	job   context.Context
	x     *Index
	q     Query
	lim   evalLimits
	chain chain
	paths int
	work  int
	// stop is why the evaluation stopped early (always "limit reached");
	// it is then the reason of the verdict. limit names the limit.
	stop  string
	limit string
}

func (x *Index) newEvaluator(ctx context.Context, q Query, lim evalLimits) *evaluator {
	return &evaluator{ctx: ctx, x: x, q: q, lim: lim, chain: chain{max: lim.steps}}
}

func (x *Index) evaluate(ctx context.Context, q Query, lim evalLimits) Result {
	return x.newEvaluator(ctx, q, lim).result()
}

// result runs the evaluation within the wall-clock budget lim.budget and
// returns its result.
func (e *evaluator) result() Result {
	job, cancel := context.WithTimeout(e.ctx, e.lim.budget)
	defer cancel()
	e.job = job
	out := e.run()
	switch {
	case e.stop != "":
		out = unknownOut(e.stop)
	case e.chain.full:
		e.limit = limitChain
		out = unknownOut(ErrLimitReached.Error())
	}
	out.reason = sanitizeText(out.reason)
	detail := out.reason
	if e.limit != "" {
		detail += " (" + e.limit + ")"
	}
	e.chain.final(Step{Kind: StepVerdict, Outcome: string(out.verdict), Detail: detail})
	return Result{
		Verdict:      out.verdict,
		Reason:       out.reason,
		Chain:        e.chain.steps,
		ModelVersion: ModelVersion,
		SnapshotHash: SnapshotHash(e.x.snap),
	}
}

// step charges cost work units for the next step of the evaluation. It
// returns false when the evaluation must stop: the chain is full
// (MaxChainSteps), the wall-clock budget is spent (job deadline, caller
// deadline or cancel), or the step would exceed the work budget
// (MaxWorkPerQuery). e.stop then holds "limit reached" and e.limit the
// limit. Every loop over rules, NAT rules and paths calls it once per
// iteration before doing the iteration's work.
func (e *evaluator) step(cost int) bool {
	if e.stop != "" {
		return false
	}
	switch err := e.ctxErr(); {
	case e.chain.full:
		e.halt(limitChain)
	case errors.Is(err, context.DeadlineExceeded):
		e.halt(limitDeadline)
	case err != nil:
		e.halt(limitCanceled)
	case cost > e.lim.work-e.work:
		e.halt(limitWork)
	default:
		e.work += cost
		return true
	}
	return false
}

// ctxErr is the error of the job context. The caller's context is checked
// directly as well: the cancel of a caller context of a type the context
// package does not know reaches job only later, through a goroutine.
func (e *evaluator) ctxErr() error {
	if e.job != nil {
		if err := e.job.Err(); err != nil {
			return err
		}
	}
	return e.ctx.Err()
}

// halt stops the evaluation with "limit reached" at limit.
func (e *evaluator) halt(limit string) {
	e.stop, e.limit = ErrLimitReached.Error(), limit
}

// stopped is the outcome of a path that step stopped.
func (e *evaluator) stopped() outcome { return unknownOut(e.stop) }

// newPath charges one path; false means MaxPathsPerQuery was reached or
// step stopped the evaluation, so no further path is evaluated.
func (e *evaluator) newPath() bool {
	if e.paths >= e.lim.paths && e.stop == "" {
		e.halt(limitPaths)
	}
	if !e.step(1) {
		return false
	}
	e.paths++
	return true
}

func (e *evaluator) run() outcome {
	if !e.step(1) {
		return e.stopped()
	}
	if r := e.checkQuery(); r != "" {
		return unknownOut(r)
	}
	if r := e.checkInputs(); r != "" {
		return unknownOut(r)
	}
	dst := e.x.placer.Place(e.q.Destination)
	e.placementStep("destination", dst)
	switch e.q.Source {
	case SourceAddress:
		src := e.x.placer.Place(e.q.SourceAddr)
		e.placementStep("source", src)
		if !src.Addr.IsValid() || src.Unknown && src.Reason == ReasonInvalidAddress {
			return unknownOut("source: " + ReasonInvalidAddress)
		}
		return e.fromPlacement(src, []AddrRange{{From: src.Addr, To: src.Addr}}, dst)
	case SourceSubnet:
		src, set, r := e.placeSubnet(e.q.SourcePrefix)
		if r != "" {
			return unknownOut(r)
		}
		return e.fromPlacement(src, set, dst)
	case SourceZone:
		z := e.q.SourceZone
		e.chain.add(Step{Kind: StepPlacement, Name: "source zone", Outcome: OutcomePlaced, Detail: "zone " + z})
		if z == "" || !e.x.zones[z] {
			return unknownOut("source zone " + z + " not in snapshot")
		}
		return e.fromZone(z, universe, dst)
	case SourceInternet:
		z, r := e.internetZone(e.q.Destination)
		if r != "" {
			e.chain.add(Step{Kind: StepPlacement, Name: "internet", Outcome: OutcomeUnknown, Detail: r})
			return unknownOut(r)
		}
		e.chain.add(Step{Kind: StepPlacement, Name: "internet", Outcome: OutcomePlaced, Detail: "zone " + z + " (default route)"})
		return e.fromZone(z, universe, dst)
	case SourceNetBird:
		return e.netbird(dst)
	}
	return unknownOut("invalid query: unknown source kind")
}

func (e *evaluator) checkQuery() string {
	q := e.q
	switch {
	case q.Protocol != "tcp" && q.Protocol != "udp":
		return "invalid query: protocol must be tcp or udp"
	case q.Port == 0:
		return "invalid query: port 0"
	case !q.Destination.IsValid() || q.Destination.Zone() != "":
		return "invalid query: destination " + ReasonInvalidAddress
	}
	return ""
}

// checkInputs requires every input fresh and exactly one vsys; the step
// lists the dataset of every input.
func (e *evaluator) checkInputs() string {
	var parts, bad []string
	for _, k := range RequiredInputs {
		in := e.x.snap.Inputs[k]
		parts = append(parts, fmt.Sprintf("%s %s %s", k, in.DatasetID, in.State))
		if in.State != InputFresh {
			bad = append(bad, fmt.Sprintf("input %s %s", k, in.State))
		}
	}
	switch e.x.snap.Vsys {
	case 1:
	case 0:
		bad = append(bad, "vsys count not reported")
	default:
		bad = append(bad, "more than one vsys")
	}
	out := OutcomePlaced
	if len(bad) > 0 {
		out = OutcomeUnknown
	}
	e.chain.add(Step{Kind: StepInput, Name: "datasets", Outcome: out, Detail: strings.Join(parts, ", ")})
	if len(bad) > 0 {
		return strings.Join(bad, "; ")
	}
	return ""
}

func (e *evaluator) placementStep(side string, p Placement) {
	st := Step{Kind: StepPlacement, Name: side + " " + p.Addr.String()}
	var d []string
	if p.Segment != nil {
		s := "segment " + p.Segment.Prefix.String()
		if p.Segment.SubnetID != "" {
			s += " (IPAM " + p.Segment.SubnetID + ")"
		}
		d = append(d, s)
	}
	if p.Unknown {
		st.Outcome = OutcomeUnknown
		d = append(d, p.Reason)
	} else {
		st.Outcome = OutcomePlaced
		via := "interface " + p.Interface
		if p.Route != nil {
			via = "route " + p.Route.Prefix.String()
			if p.Interface != "" {
				via += " via " + p.Interface
			}
		}
		d = append(d, "zone "+p.Zone+" through "+via)
	}
	st.Detail = strings.Join(d, ", ")
	e.chain.add(st)
}

// placeSubnet places a subnet source: it must be one known segment, or
// part of one.
func (e *evaluator) placeSubnet(p netip.Prefix) (Placement, []AddrRange, string) {
	if !p.IsValid() || p.Masked() != p || p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return Placement{}, nil, "invalid query: source subnet invalid"
	}
	pl := e.x.placer.Place(p.Addr())
	e.placementStep("source subnet "+p.String()+":", pl)
	// An unsplit segment holds no other segment, so every part of it is
	// in the same zone.
	if pl.Segment == nil || pl.Segment.Prefix.Bits() > p.Bits() || !pl.Segment.Unsplit {
		return Placement{}, nil, "source subnet is not one known segment"
	}
	return pl, []AddrRange{prefixRange(p)}, ""
}

// internetZone is the zone of the default route of the destination's
// family: the WAN zone (ADR 0012 D2 step 1).
func (e *evaluator) internetZone(dst netip.Addr) (string, string) {
	p := e.x.placer
	if r, bad := p.notFresh[InputRoutes]; bad {
		return "", r
	}
	if r, bad := p.notFresh[InputInterfaces]; bad {
		return "", r
	}
	zone := ""
	for _, rt := range p.routes {
		if rt.Prefix.Bits() != 0 || rt.Prefix.Addr().Is4() != dst.Unmap().Is4() {
			continue
		}
		z, r := p.routeZone(rt)
		if r != "" {
			return "", r
		}
		if zone != "" && z != zone {
			return "", ReasonRouteAmbiguous
		}
		zone = z
	}
	if zone == "" {
		return "", "no default route for the internet source"
	}
	return zone, ""
}

// fromPlacement evaluates a source that was placed: same segment gives
// not_filtered (rules irrelevant); otherwise both zones must be proven.
func (e *evaluator) fromPlacement(src Placement, set []AddrRange, dst Placement) outcome {
	if c := CrossingTest(src, dst); c.NotFiltered {
		e.chain.add(Step{Kind: StepCrossing, Outcome: OutcomeNotFiltered, Detail: c.Reason + "; firewall rules irrelevant, host firewalls not modelled in " + ModelVersion})
		return outcome{VerdictNotFiltered, c.Reason}
	}
	e.chain.add(Step{Kind: StepCrossing, Outcome: "crosses or not proven", Detail: "not one L2 segment per the data"})
	if src.Unknown {
		return unknownOut(src.Reason)
	}
	return e.fromZone(src.Zone, set, dst)
}

// fromZone evaluates every path from a source zone and address set to the
// destination: the direct path with forward NAT and every pre-NAT
// destination of the reverse-NAT lookup.
func (e *evaluator) fromZone(srcZone string, src []AddrRange, dst Placement) outcome {
	if dst.Unknown {
		return unknownOut(dst.Reason)
	}
	for _, z := range []string{srcZone, dst.Zone} {
		if !e.x.zones[z] {
			return unknownOut("zone " + z + " not in snapshot")
		}
	}
	outs := e.forward(srcZone, src, dst)
	outs = append(outs, e.reverseNAT(srcZone, src, dst)...)
	return mostReachable(outs)
}

// netbird evaluates the netbird entry class (ADR 0012 D2 step 1): an
// overlay path that bypasses the firewall is not_filtered, a path not
// proven is unknown, a proven firewall-crossing path gets the rule verdict.
func (e *evaluator) netbird(dst Placement) outcome {
	f := e.q.NetBird
	step := func(name, out, detail string) {
		e.chain.add(Step{Kind: StepNetBird, Name: name, Outcome: out, Detail: detail})
	}
	switch {
	case !f.Peer.Collected:
		step("destination", OutcomeUnknown, "host data not collected")
		return unknownOut(ReasonNetBirdNotProven + ": host data not collected")
	case f.Peer.Value:
		step("destination", OutcomeNotFiltered, "destination is a NetBird peer")
		return outcome{VerdictNotFiltered, ReasonOverlayBypass}
	case !f.RoutingPeers.Collected:
		step("routing peers", OutcomeUnknown, "not collected")
		return unknownOut(ReasonNetBirdNotProven + ": routing peers unknown")
	case len(f.RoutingPeers.Value) == 0:
		step("routing peers", OutcomeUnknown, "none known")
		return unknownOut(ReasonNetBirdNotProven + ": no routing peer known")
	}
	var outs []outcome
	for _, rp := range f.RoutingPeers.Value {
		if !e.newPath() {
			return e.stopped()
		}
		name := "routing peer " + rp.Name
		pl := e.x.placer.Place(rp.Addr)
		e.placementStep(name, pl)
		if c := CrossingTest(pl, dst); c.NotFiltered {
			step(rp.Name, OutcomeNotFiltered, c.Reason)
			outs = append(outs, outcome{VerdictNotFiltered, ReasonOverlayBypass})
			continue
		}
		if pl.Unknown || dst.Unknown {
			r := pl.Reason
			if !pl.Unknown {
				r = "destination: " + dst.Reason
			}
			step(rp.Name, OutcomeUnknown, r)
			outs = append(outs, unknownOut(ReasonNetBirdNotProven+": "+name+": "+r))
			continue
		}
		step(rp.Name, "crosses the firewall", "enters through zone "+pl.Zone)
		// The source address of overlay traffic (masqueraded or not) is
		// not modelled: every source field other than "any" is a condition.
		outs = append(outs, e.fromZone(pl.Zone, universe, dst))
	}
	return mostReachable(outs)
}

// packet is the packet one path presents to the security rules: pre-NAT
// addresses and ports, post-NAT destination zone (PAN-OS semantics). conds
// are path conditions (a NAT rule that matches only part of the sources):
// an allow on this path is then conditional.
type packet struct {
	path    string
	srcZone string
	dstZone string
	src     []AddrRange
	dst     []AddrRange
	proto   string
	ports   []portSpan
	conds   []string
}

// condMatch is a conditional rule match recorded on the way to the final
// decision (ADR 0012 D2 step 4).
type condMatch struct {
	rule  string
	allow bool
}

func isAllow(a Action) bool { return a == ActionAllow }

// securityPath evaluates the security rules in order on one packet: first
// match wins, disabled rules are skipped and listed, conditional matches
// are recorded and evaluation continues to the next unconditional match or
// the default rule. An unevaluable rule that is reached ends the path with
// unknown, or conditional when a conditional allow was recorded before it
// (see undecided).
func (e *evaluator) securityPath(p packet) outcome {
	var conds []condMatch
	for i := range e.x.rules {
		if !e.step(e.ruleCost(i, &p)) {
			return e.stopped()
		}
		v := &e.x.rules[i]
		st := Step{Path: p.path, Kind: StepRule, Name: v.Name}
		if v.Disabled {
			st.Outcome = OutcomeSkippedDisabled
			e.chain.add(st)
			continue
		}
		if !v.Evaluable() {
			if f := zonesExclude(&e.x.snap.SecurityRules[i], p.srcZone, p.dstZone); f != "" {
				st.Outcome, st.Detail = OutcomeNoMatch, "because "+f+"; rule is unevaluable: "+v.Reason()
				e.chain.add(st)
				continue
			}
			st.Outcome, st.Detail = OutcomeUnevaluable, v.Reason()
			e.chain.add(st)
			return undecided(conds, v.Reason())
		}
		why, extra := ruleMatch(v, &e.x.ruleAddrs[i], &p)
		if why != "" {
			st.Outcome, st.Detail = OutcomeNoMatch, "because "+why
			e.chain.add(st)
			continue
		}
		cs := append(slices.Clip(v.Conditions), extra...)
		if len(cs) > 0 {
			st.Outcome = OutcomeConditional
			st.Detail = string(v.Action) + " if " + strings.Join(cs, ", ") + " decide"
			e.chain.add(st)
			conds = append(conds, condMatch{rule: v.Name, allow: isAllow(v.Action)})
			continue
		}
		st.Outcome, st.Detail = OutcomeMatch, string(v.Action)
		e.chain.add(st)
		return decide(conds, v.Name, v.Action, p.conds)
	}
	if !e.step(1) {
		return e.stopped()
	}
	d := e.x.DefaultRule(p.srcZone == p.dstZone)
	st := Step{Path: p.path, Kind: StepDefaultRule, Name: d.Name}
	if !d.Evaluable() {
		st.Outcome, st.Detail = OutcomeUnevaluable, d.Reason()
		e.chain.add(st)
		return undecided(conds, d.Reason())
	}
	st.Outcome, st.Detail = OutcomeMatch, string(d.Action)
	e.chain.add(st)
	return decide(conds, d.Name, d.Action, p.conds)
}

// ruleCost bounds the work of security rule i on packet p: the step, the
// zone lists (raw and classified) and the three field matches.
func (e *evaluator) ruleCost(i int, p *packet) int {
	v, a, r := &e.x.rules[i], &e.x.ruleAddrs[i], &e.x.snap.SecurityRules[i]
	c := 1 + len(v.From) + len(v.To) + len(r.From.Value) + len(r.To.Value)
	if v.Disabled || !v.Evaluable() {
		return c
	}
	return c + a.src.cost(p.src) + a.dst.cost(p.dst) + a.svc.cost(p.proto, p.ports)
}

// undecided is the outcome of a path whose final decision cannot be
// determined (an unevaluable rule or default rule is reached). ADR 0012
// D2 step 4: an allow among the recorded conditional matches makes it
// conditional (allowed whenever its conditions hold, whatever follows);
// otherwise it is unknown. It is never denied.
func undecided(conds []condMatch, reason string) outcome {
	var by []string
	for _, c := range conds {
		if c.allow {
			by = append(by, sanitizeText(c.rule))
		}
	}
	if len(by) == 0 {
		return unknownOut(reason)
	}
	return outcome{VerdictConditional, "conditional: allowed under conditions (rules " + strings.Join(by, ", ") + "); otherwise " + reason}
}

// decide combines the conditional matches and the final unconditional
// decision (ADR 0012 D2 step 4): any allow among them gives conditional,
// all deny gives denied, no condition gives the final action.
func decide(conds []condMatch, name string, a Action, pathConds []string) outcome {
	name = sanitizeText(name)
	anyAllow := isAllow(a)
	for _, c := range conds {
		anyAllow = anyAllow || c.allow
	}
	switch {
	case len(conds) == 0 && len(pathConds) == 0 && isAllow(a):
		return outcome{VerdictAllowed, "allowed by rule " + name}
	case anyAllow:
		var by []string
		for _, c := range conds {
			by = append(by, sanitizeText(c.rule))
		}
		by = append(by, name)
		return outcome{VerdictConditional, "conditional: allowed under conditions (rules " + strings.Join(by, ", ") + ")"}
	case len(conds) == 0:
		return outcome{VerdictDenied, "denied by rule " + name}
	}
	return outcome{VerdictDenied, "denied by rule " + name + "; every conditional match before it denies as well"}
}

// zonesExclude reports why an unevaluable rule cannot match the zones of
// the path, or "" when it may. Only collected zone lists without markers
// decide, and only on a rule that carries no rule-level marker and no
// field outside the allowlist (such a field could change what it matches).
func zonesExclude(r *SecurityRule, src, dst string) string {
	if len(r.Dropped) > 0 || len(r.OutsideAllowlist) > 0 {
		return ""
	}
	if !zoneMayMatch(r.From, src) {
		return "from zone"
	}
	if !zoneMayMatch(r.To, dst) {
		return "to zone"
	}
	return ""
}

// ruleMatch matches an evaluable rule, with its merged fields a,
// against a packet. It returns the field that does not match, or "" and
// the fields that match only in part (conditions).
func ruleMatch(v *RuleView, a *ruleAddrs, p *packet) (string, []string) {
	if !zoneIn(v.From, p.srcZone) {
		return "from zone", nil
	}
	if !zoneIn(v.To, p.dstZone) {
		return "to zone", nil
	}
	var extra []string
	switch a.src.match(v.NegateSource, p.src) {
	case matchNone:
		return "source address", nil
	case matchPartial:
		extra = append(extra, "source address")
	}
	switch a.dst.match(v.NegateDestination, p.dst) {
	case matchNone:
		return "destination address", nil
	case matchPartial:
		extra = append(extra, "destination address")
	}
	if !v.Service.ApplicationDefault {
		// application-default is a condition already (RuleView.Conditions).
		switch a.svc.match(p.proto, p.ports) {
		case matchNone:
			return "service", nil
		case matchPartial:
			extra = append(extra, "service port")
		}
	}
	return "", extra
}

func zoneIn(l []string, z string) bool {
	return slices.Contains(l, memberAny) || slices.Contains(l, z)
}

// match is the result of matching a rule field against a set of packet
// values: all of them, part of them or none.
type match int

const (
	matchNone match = iota
	matchPartial
	matchFull
)

// universe is every address of both families: the source set of a source
// without a single address.
var universe = []AddrRange{
	{From: netip.IPv4Unspecified(), To: netip.AddrFrom4([4]byte{255, 255, 255, 255})},
	{From: netip.IPv6Unspecified(), To: netip.AddrFrom16([16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})},
}

// matchAddr matches an address field, with negation, against the packet
// set x. Negation matches the complement of the field: it covers x when
// the field does not overlap x, and overlaps x when the field does not
// cover x.
func matchAddr(set AddrSet, neg bool, x []AddrRange) match {
	return mergeSet(set).match(neg, x)
}

// mergedAddrs is an address field ready for matching: any, or its ranges
// sorted and merged. The Index builds one per rule field (ruleAddrs,
// natAddrs), so a query never sorts a rule's ranges.
type mergedAddrs struct {
	any bool
	m   []AddrRange
}

// mergeSet merges the ranges of set. Ranges that are already sorted and
// merged are shared, not copied.
func mergeSet(set AddrSet) mergedAddrs {
	if set.Any {
		return mergedAddrs{any: true}
	}
	if isMerged(set.Ranges) {
		return mergedAddrs{m: set.Ranges}
	}
	return mergedAddrs{m: mergeAddr(set.Ranges)}
}

// cost bounds the comparisons of matching the field against x.
func (s mergedAddrs) cost(x []AddrRange) int {
	if s.any {
		return 1
	}
	return searchCost(len(x), len(s.m))
}

// match matches the field, with negation, against the packet set x; see
// matchAddr. The cost is O(len(x) · log len(m)), at most cost(x).
func (s mergedAddrs) match(neg bool, x []AddrRange) match {
	cov, ov := true, true
	if !s.any {
		cov, ov = coversAddr(s.m, x), overlapsAddr(s.m, x)
	}
	if neg {
		cov, ov = !ov, !cov
	}
	switch {
	case cov:
		return matchFull
	case ov:
		return matchPartial
	}
	return matchNone
}

// mergeAddr returns the ranges sorted and merged: no two overlap or touch.
func mergeAddr(rs []AddrRange) []AddrRange {
	m := slices.Clone(rs)
	slices.SortFunc(m, func(a, b AddrRange) int { return a.From.Compare(b.From) })
	out := m[:0]
	for _, r := range m {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if last.From.BitLen() == r.From.BitLen() &&
				(r.From.Compare(last.To) <= 0 || last.To.Next() == r.From) {
				if r.To.Compare(last.To) > 0 {
					last.To = r.To
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// isMerged reports whether rs is sorted and merged as mergeAddr returns it.
func isMerged(rs []AddrRange) bool {
	for i := 1; i < len(rs); i++ {
		last, r := rs[i-1], rs[i]
		if r.From.Compare(last.From) < 0 || last.From.BitLen() == r.From.BitLen() &&
			(r.From.Compare(last.To) <= 0 || last.To.Next() == r.From) {
			return false
		}
	}
	return true
}

// firstEndingAtOrAfter returns the index of the first merged range whose
// end is not before a.
func firstEndingAtOrAfter(m []AddrRange, a netip.Addr) int {
	return sort.Search(len(m), func(i int) bool { return m[i].To.Compare(a) >= 0 })
}

func coversAddr(m, x []AddrRange) bool {
	for _, r := range x {
		i := firstEndingAtOrAfter(m, r.From)
		if i == len(m) || m[i].From.Compare(r.From) > 0 || m[i].To.Compare(r.To) < 0 {
			return false
		}
	}
	return true
}

func overlapsAddr(m, x []AddrRange) bool {
	for _, r := range x {
		i := firstEndingAtOrAfter(m, r.From)
		if i < len(m) && m[i].From.Compare(r.To) <= 0 {
			return true
		}
	}
	return false
}

// portSpan is an inclusive port range of the query protocol.
type portSpan struct{ from, to int }

// mergedService is a service field ready for matching: any, or its port
// spans per protocol, sorted and merged. The Index builds one per rule
// (ruleAddrs.svc, natAddrs.svc), so a query never sorts or copies a rule's
// ports.
type mergedService struct {
	any   bool
	ports map[string][]portSpan
}

// mergeService groups the ports of s by protocol and merges each group.
func mergeService(s ServiceSet) mergedService {
	if s.Any {
		return mergedService{any: true}
	}
	by := map[string][]portSpan{}
	for _, p := range s.Ports {
		by[p.Protocol] = append(by[p.Protocol], portSpan{int(p.From), int(p.To)})
	}
	for k, m := range by {
		by[k] = mergePorts(m)
	}
	return mergedService{ports: by}
}

// cost bounds the comparisons of matching the field against x.
func (s mergedService) cost(proto string, x []portSpan) int {
	if s.any {
		return 1
	}
	return searchCost(len(x), len(s.ports[proto]))
}

// match matches the field against the packet ports x of protocol proto.
// A field with application-default is handled by the caller. The cost is
// O(len(x) · log m), at most cost(proto, x), and it does not allocate.
func (s mergedService) match(proto string, x []portSpan) match {
	if s.any {
		return matchFull
	}
	m := s.ports[proto]
	cov, ov := true, false
	for _, r := range x {
		i := sort.Search(len(m), func(i int) bool { return m[i].to >= r.from })
		if i == len(m) || m[i].from > r.from || m[i].to < r.to {
			cov = false
		}
		if i < len(m) && m[i].from <= r.to {
			ov = true
		}
	}
	switch {
	case cov && len(x) > 0:
		return matchFull
	case ov:
		return matchPartial
	}
	return matchNone
}

func mergePorts(m []portSpan) []portSpan {
	slices.SortFunc(m, func(a, b portSpan) int { return a.from - b.from })
	out := m[:0]
	for _, r := range m {
		if n := len(out); n > 0 && r.from <= out[n-1].to+1 {
			out[n-1].to = max(out[n-1].to, r.to)
			continue
		}
		out = append(out, r)
	}
	return out
}

func portsText(ps []portSpan) string {
	var parts []string
	for _, p := range ps {
		if p.from == p.to {
			parts = append(parts, strconv.Itoa(p.from))
		} else {
			parts = append(parts, strconv.Itoa(p.from)+"-"+strconv.Itoa(p.to))
		}
	}
	return strings.Join(parts, ",")
}
