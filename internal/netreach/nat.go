// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"net/netip"
	"slices"
	"strings"
)

// NAT evaluation (ADR 0012 D2 step 3). Security rules match the pre-NAT
// destination address and port and the post-NAT destination zone (PAN-OS
// semantics, to be verified in NS-03).
//
// forward evaluates the NAT rules in NAT rule order on the queried packet:
// first match wins; a rule that matches only part of the possible sources
// (a source without a single address) branches: the translated path is
// evaluated, and the remaining sources continue to the next NAT rule. An
// unevaluable NAT rule that is reached ends the NAT step with unknown.
//
// reverseNAT looks up every destination NAT rule whose translated address
// and port cover the queried destination and port and evaluates the query
// once more on the rule's pre-NAT packet. While any NAT rule is
// unevaluable, the lookup cannot exclude a port forward to the destination,
// so it contributes unknown. The lookup does not check whether an earlier
// NAT rule would take the pre-NAT packet first; a forward that is shadowed
// that way only makes the result more reachable, never less (fail closed).

// forward evaluates destination NAT and the security rules on the packet
// as queried. It returns one outcome per evaluated path.
func (e *evaluator) forward(srcZone string, src []AddrRange, dst Placement) []outcome {
	const path = "direct"
	d := dst.Addr
	port := portSpan{int(e.q.Port), int(e.q.Port)}
	base := packet{
		srcZone: srcZone, dstZone: dst.Zone,
		src: src, dst: []AddrRange{{From: d, To: d}},
		proto: e.q.Protocol, ports: []portSpan{port},
	}
	if !e.newPath() {
		return []outcome{unknownOut(ErrLimitReached.Error())}
	}
	var outs []outcome
	var conds []string
	for i := range e.x.nat {
		v := &e.x.nat[i]
		st := Step{Path: path, Kind: StepNAT, Name: v.Name}
		if v.Disabled {
			st.Outcome = OutcomeSkippedDisabled
			e.chain.add(st)
			continue
		}
		if !v.Evaluable() {
			st.Outcome, st.Detail = OutcomeUnevaluable, v.Reason()
			e.chain.add(st)
			return append(outs, unknownOut(v.Reason()))
		}
		m, why := natMatch(v, &base)
		if m == matchNone {
			st.Outcome, st.Detail = OutcomeNoMatch, "because "+why
			e.chain.add(st)
			continue
		}
		cond := "source address (NAT rule " + v.Name + ")"
		if v.Translation == nil {
			if m == matchFull {
				st.Outcome, st.Detail = OutcomeMatch, "no destination translation"
				e.chain.add(st)
				break
			}
			st.Outcome, st.Detail = OutcomeConditional, "no destination translation for part of the sources"
			e.chain.add(st)
			conds = append(conds, cond)
			continue
		}
		p := base
		p.path = "via NAT rule " + v.Name
		p.conds = slices.Clone(conds)
		if m == matchPartial {
			p.conds = append(p.conds, cond)
			st.Outcome = OutcomeConditional
		} else {
			st.Outcome = OutcomeMatch
		}
		st.Detail = "destination translated to " + v.Translation.Address
		e.chain.add(st)
		outs = append(outs, e.translated(v, p))
		if m == matchFull {
			return outs
		}
		conds = append(conds, cond)
	}
	p := base
	p.path = path
	p.conds = conds
	return append(outs, e.securityPath(p))
}

// translated evaluates the security rules for a translated packet: the
// post-NAT zone is the zone of the translated address.
func (e *evaluator) translated(v *NATRuleView, p packet) outcome {
	if !e.newPath() {
		return unknownOut(ErrLimitReached.Error())
	}
	zone, r := e.translatedZone(v)
	if r != "" {
		e.chain.add(Step{Path: p.path, Kind: StepNAT, Name: v.Name, Outcome: OutcomeUnknown, Detail: "post-NAT zone: " + r})
		return unknownOut("NAT rule " + sanitizeText(v.Name) + ": post-NAT zone: " + r)
	}
	if !e.x.zones[zone] {
		return unknownOut("zone " + zone + " not in snapshot")
	}
	p.dstZone = zone
	return e.securityPath(p)
}

// translatedZone places the translated address of a NAT rule. Every range
// must be a single address, or lie in one placed segment that is Unsplit
// (as placeSubnet requires: a split segment may hold a nested segment of
// another zone); all ranges must give the same zone. Anything else leaves
// the post-NAT zone unknown.
func (e *evaluator) translatedZone(v *NATRuleView) (string, string) {
	zone := ""
	for _, r := range v.TranslatedAddress.Ranges {
		pl := e.x.placer.Place(r.From)
		if pl.Unknown {
			return "", pl.Reason
		}
		if r.From != r.To {
			if pl.Segment == nil || !pl.Segment.Prefix.Contains(r.To) {
				return "", "translated address spans more than one segment"
			}
			if !pl.Segment.Unsplit {
				return "", "translated address lies in a split segment"
			}
		}
		if zone != "" && pl.Zone != zone {
			return "", "translated address spans more than one zone"
		}
		zone = pl.Zone
	}
	if zone == "" {
		return "", "translated address not placed"
	}
	return zone, ""
}

// natMatch matches an evaluable NAT rule against the pre-NAT packet: from
// zone, to zone (the zone of the pre-NAT destination), source, destination
// and service. It returns matchPartial when the rule matches only part of
// the possible sources.
func natMatch(v *NATRuleView, p *packet) (match, string) {
	if !zoneIn(v.From, p.srcZone) {
		return matchNone, "from zone"
	}
	if v.To != memberAny && v.To != p.dstZone {
		return matchNone, "to zone"
	}
	if matchAddr(v.Destination, false, p.dst) != matchFull {
		// The queried destination is a single address.
		return matchNone, "destination address"
	}
	if matchService(v.Service, p.proto, p.ports) != matchFull {
		return matchNone, "service"
	}
	switch matchAddr(v.Source, false, p.src) {
	case matchNone:
		return matchNone, "source address"
	case matchPartial:
		return matchPartial, ""
	}
	return matchFull, ""
}

// reverseNAT evaluates the query on the pre-NAT packet of every
// destination NAT rule that forwards to the queried address and port.
func (e *evaluator) reverseNAT(srcZone string, src []AddrRange, dst Placement) []outcome {
	d := dst.Addr
	var outs []outcome
	for i := range e.x.nat {
		v := &e.x.nat[i]
		st := Step{Kind: StepReverseNAT, Name: v.Name}
		if v.Disabled {
			continue
		}
		if !v.Evaluable() {
			st.Outcome = OutcomeUnevaluable
			st.Detail = "cannot exclude a port forward to " + d.String() + ": " + v.Reason()
			e.chain.add(st)
			outs = append(outs, unknownOut(v.Reason()+" (reverse-NAT lookup)"))
			continue
		}
		if v.Translation == nil || !containsAddr(v.TranslatedAddress, d) {
			continue
		}
		ports, why := e.preNATPorts(v)
		if why == "" && !zoneIn(v.From, srcZone) {
			why = "from zone"
		}
		m := matchFull
		if why == "" {
			if m = matchAddr(v.Source, false, src); m == matchNone {
				why = "source address"
			}
		}
		if why != "" {
			st.Outcome, st.Detail = OutcomeNoMatch, "forwards to "+d.String()+" but no match because "+why
			e.chain.add(st)
			continue
		}
		if !e.newPath() {
			return append(outs, unknownOut(ErrLimitReached.Error()))
		}
		r := &e.x.snap.NATRules[i]
		st.Outcome = OutcomeTried
		st.Detail = "pre-NAT destination " + strings.Join(r.Destination.Value, ",") +
			" zone " + v.To + " port " + e.q.Protocol + "/" + portsText(ports)
		e.chain.add(st)
		dstSet := universe
		if !v.Destination.Any {
			dstSet = v.Destination.Ranges
		}
		p := packet{
			path:    "reverse NAT rule " + v.Name,
			srcZone: srcZone, dstZone: dst.Zone,
			src: src, dst: dstSet,
			proto: e.q.Protocol, ports: ports,
		}
		if m == matchPartial {
			p.conds = []string{"source address (NAT rule " + v.Name + ")"}
		}
		outs = append(outs, e.securityPath(p))
	}
	return outs
}

// preNATPorts returns the pre-NAT destination ports of a NAT rule whose
// translation leads to the queried port, or why it does not.
func (e *evaluator) preNATPorts(v *NATRuleView) ([]portSpan, string) {
	q := portSpan{int(e.q.Port), int(e.q.Port)}
	if v.Translation.Port == 0 {
		if matchService(v.Service, e.q.Protocol, []portSpan{q}) != matchFull {
			return nil, "service"
		}
		return []portSpan{q}, ""
	}
	if int(v.Translation.Port) != q.from {
		return nil, "translated port"
	}
	if v.Service.Any {
		return []portSpan{{1, 65535}}, ""
	}
	var ps []portSpan
	for _, p := range v.Service.Ports {
		if p.Protocol == e.q.Protocol {
			ps = append(ps, portSpan{int(p.From), int(p.To)})
		}
	}
	if len(ps) == 0 {
		return nil, "service protocol"
	}
	return mergePorts(ps), ""
}

// containsAddr reports whether the set contains the address.
func containsAddr(s AddrSet, a netip.Addr) bool {
	return matchAddr(s, false, []AddrRange{{From: a, To: a}}) == matchFull
}
