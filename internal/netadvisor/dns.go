// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// MaxListedEndpoints bounds the endpoints a flow finding lists; the rest
// is only counted (FlowEvidence.EndpointsTotal).
const MaxListedEndpoints = 8

// dnsPorts are the DNS ports of ADR 0012 D4 dns-bypass: 53/udp, 53/tcp
// and 853/tcp (DNS over TLS).
var dnsPorts = []MgmtPort{{"udp", 53}, {"tcp", 53}, {"tcp", 853}}

func isDNSPort(proto string, port uint16) bool {
	return slices.Contains(dnsPorts, MgmtPort{Protocol: proto, Port: port})
}

// FlowEvidence is the evidence of a flow-based result. For an aggregate
// (dns-bypass) Source is empty and Endpoints lists at most
// MaxListedEndpoints internal endpoints in address order, EndpointsTotal
// counts all of them. Chain is the model's explanation chain as text
// (model-contradiction). Addresses are log- or flow-derived evidence
// (ADR 0012 D5: never exported).
type FlowEvidence struct {
	Source         string
	Destination    string
	Protocol       string
	Port           uint16
	Endpoints      []string
	EndpointsTotal int
	Sessions       uint64
	Origins        []string
	Chain          string
}

// DNSCheck is the check dns-bypass (ADR 0012 D4). It has two parts:
//
//   - Flow part: observed DNS (53/udp, 53/tcp, 853/tcp) from internal
//     endpoints to a destination other than the designated resolver,
//     which is the firewall only (its interface addresses, Q9). An
//     internal resolver that is not the firewall fires too. One result
//     per (destination, protocol, port) with RuleIndex -1: a finding when
//     at least one source is proven internal, StateCannotDecide when no
//     source could be placed. Flows the firewall denied, and loopback
//     destinations, are not a bypass. With Report.State StateOK a
//     destination without a result no longer fires.
//   - Rule part: per rule, an allow rule that permits DNS from an
//     internal zone to an external zone (a zone of a default route)
//     without restricting the destination.
//
// The check needs fresh placement and rule inputs, fresh flows and the
// fresh firewall addresses; otherwise every result is "cannot decide" or
// "data not collected" and nothing resolves. An unevaluable rule (ADR
// 0012 D2 fail-safe) is never StateOK.
type DNSCheck struct{}

// ID returns CheckDNSBypass.
func (DNSCheck) ID() string { return CheckDNSBypass }

var dnsInputs = []netreach.InputKind{
	netreach.InputZones, netreach.InputInterfaces, netreach.InputSecurityRules,
	netreach.InputObjects, netreach.InputRoutes, netreach.InputIPAM,
}

// Run runs both parts: the rule results in rule order, then the flow
// results in (destination, protocol, port) order.
func (DNSCheck) Run(in *Input) Report {
	if st, why := precondition(in, dnsInputs...); st != StateOK {
		return failedReport(CheckDNSBypass, in, st, why)
	}
	if st, why := observationState("flows", in.obs.Flows.State); st != StateOK {
		return failedReport(CheckDNSBypass, in, st, why)
	}
	if st, why := observationState("firewall addresses", in.obs.FirewallAddrs.State); st != StateOK {
		return failedReport(CheckDNSBypass, in, st, why)
	}
	ext, extWhy := externalZones(in.Snapshot)
	r := Report{CheckID: CheckDNSBypass, CheckVersion: CheckVersion, State: StateOK}
	views := in.Index.SecurityRules()
	for i := range in.Snapshot.SecurityRules {
		r.Findings = append(r.Findings, dnsRule(in, i, &views[i], ext, extWhy))
	}
	r.Findings = append(r.Findings, dnsFlows(in, ext)...)
	return r
}

// externalZones returns the zones of the default routes (the WAN side).
// A default route whose zone is not proven gives a reason instead.
func externalZones(s *netreach.Snapshot) (map[string]bool, string) {
	ifZone := make(map[string]string, len(s.Interfaces))
	for _, i := range s.Interfaces {
		ifZone[i.Name] = i.Zone
	}
	ext := map[string]bool{}
	for _, rt := range s.Routes {
		if rt.Prefix.Bits() != 0 {
			continue
		}
		z := rt.Zone
		if z == "" {
			z = ifZone[rt.Interface]
		}
		if z == "" {
			return nil, "zone of a default route unknown"
		}
		ext[z] = true
	}
	if len(ext) == 0 {
		return nil, "no default route: external zone unknown"
	}
	return ext, ""
}

func dnsRule(in *Input, i int, v *netreach.RuleView, ext map[string]bool, extWhy string) Finding {
	sr := &in.Snapshot.SecurityRules[i]
	f := newFinding(CheckDNSBypass, i, sr)
	set := func(st State, why string) Finding {
		f.State, f.Reason = st, clean(why)
		return f
	}
	switch {
	case !sr.Disabled.Collected:
		return set(StateDataNotCollected, "data not collected: disabled not collected")
	case v.Disabled:
		return set(StateOK, "rule disabled")
	case !v.Evaluable():
		if onlyNotCollected(v.Unevaluable) {
			return set(StateDataNotCollected, "data not collected: "+v.Reason())
		}
		return set(StateCannotDecide, "cannot decide: "+v.Reason())
	case v.Action != netreach.ActionAllow:
		return set(StateOK, "not an allow rule")
	case extWhy != "":
		return set(StateCannotDecide, "cannot decide: "+extWhy)
	}
	var fromInt, toExt []string
	for _, z := range expandZones(in.Snapshot, v.From) {
		if !ext[z] {
			fromInt = append(fromInt, z)
		}
	}
	for _, z := range expandZones(in.Snapshot, v.To) {
		if ext[z] {
			toExt = append(toExt, z)
		}
	}
	if len(fromInt) == 0 || len(toExt) == 0 {
		return set(StateOK, "not from an internal to an external zone")
	}
	unrestricted := ""
	switch {
	case v.Destination.Any && v.NegateDestination:
		return set(StateOK, "destination restricted (negated any matches nothing)")
	case v.Destination.Any:
		unrestricted = "without restricting the destination"
	case v.NegateDestination:
		unrestricted = "with a negated destination (everything except the listed addresses)"
	case !smallRanges(v.Destination.Ranges):
		unrestricted = fmt.Sprintf("with a destination too broad to count as restricted (a range of more than %d addresses)", MaxRestrictedDNSDestination)
	default:
		return set(StateOK, "destination restricted")
	}
	switch dns, unknown := permitsDNS(v, sr.Application.Value); dns {
	case dnsNo:
		return set(StateOK, "does not permit DNS")
	case dnsUnknown:
		names := "(empty list)"
		if len(unknown) > 0 {
			names = strings.Join(unknown[:min(len(unknown), MaxCoveringNames)], ", ")
			if len(unknown) > MaxCoveringNames {
				names += fmt.Sprintf(" and %d more", len(unknown)-MaxCoveringNames)
			}
		}
		return set(StateCannotDecide, "cannot decide: application(s) "+names+
			" not resolvable (application group, filter or unknown App-ID); whether the rule permits DNS is unknown")
	}
	why := fmt.Sprintf("allow rule permits DNS from internal zone(s) %s to external zone(s) %s %s; the designated resolver is the firewall",
		strings.Join(fromInt, ", "), strings.Join(toExt, ", "), unrestricted)
	if len(v.Conditions) > 0 {
		why += " (conditional: " + strings.Join(v.Conditions, ", ") + ")"
	}
	f.Severity, f.Zones = SeverityMedium, cleanAll(sortedUnique(append(fromInt, toExt...)))
	return set(StateFinding, why)
}

// onlyNotCollected reports whether every cause is a field that was not
// collected (the Q11 elements before NS-04): "data not collected".
func onlyNotCollected(cs []netreach.Cause) bool {
	for _, c := range cs {
		if c.Detail != "not collected" {
			return false
		}
	}
	return len(cs) > 0
}

// expandZones returns the zones of a classified zone list; "any" is every
// snapshot zone.
func expandZones(s *netreach.Snapshot, l []string) []string {
	if len(l) == 1 && l[0] == "any" {
		out := make([]string, 0, len(s.Zones))
		for _, z := range s.Zones {
			out = append(out, z.Name)
		}
		return out
	}
	return l
}

// MaxRestrictedDNSDestination is the largest number of addresses one
// destination range of a rule may hold and still count as "destination
// restricted" in the dns-bypass rule part (one IPv4 /24). A broader range,
// such as 0.0.0.0/0 or a large public block, does not restrict where DNS
// goes.
const MaxRestrictedDNSDestination = 256

// smallRanges reports whether every range holds at most
// MaxRestrictedDNSDestination addresses. An empty list is not small: it
// restricts nothing the check can show.
func smallRanges(rs []netreach.AddrRange) bool {
	for _, r := range rs {
		if !rangeAtMost(r, MaxRestrictedDNSDestination) {
			return false
		}
	}
	return len(rs) > 0
}

// rangeAtMost reports whether the inclusive range r holds at most n
// addresses (n >= 1). A range of mixed or invalid families, or with To
// before From, is not small.
func rangeAtMost(r netreach.AddrRange, n uint64) bool {
	from, to := r.From.Unmap(), r.To.Unmap()
	if !from.IsValid() || !to.IsValid() || from.Is4() != to.Is4() || to.Less(from) {
		return false
	}
	f, t := from.As16(), to.As16()
	fHi, fLo := binary.BigEndian.Uint64(f[:8]), binary.BigEndian.Uint64(f[8:])
	tHi, tLo := binary.BigEndian.Uint64(t[:8]), binary.BigEndian.Uint64(t[8:])
	if tHi != fHi {
		return false // more than 2^64 addresses apart
	}
	return tLo-fLo < n
}

// dnsVerdict is what permitsDNS can say about a rule.
type dnsVerdict int

const (
	dnsNo dnsVerdict = iota
	dnsYes
	dnsUnknown
)

// nonDNSAppIDs are predefined PAN-OS App-IDs that never carry DNS. PAN-OS
// identifies DNS as dns, dns-base, dns-over-tls, ... ; a rule limited to
// these applications does not pass DNS. The list is closed on purpose:
// every other application name may be an application group or filter
// (the snapshot has no application definitions) and is not resolvable.
var nonDNSAppIDs = map[string]bool{
	"ssl": true, "web-browsing": true, "ssh": true, "ping": true, "icmp": true,
	"ipv6-icmp": true, "traceroute": true, "ntp": true, "ntp-base": true,
	"snmp": true, "smtp": true, "imap": true, "pop3": true, "ftp": true,
	"ms-rdp": true, "quic": true, "ike": true, "ipsec-esp": true,
	"openvpn": true, "wireguard": true, "syslog": true, "ldap": true,
	"kerberos": true,
}

// permitsDNS reports whether an evaluable rule's service and application
// let DNS through. Service: "any", application-default or a port range
// holding a DNS port; any other service gives dnsNo whatever the
// applications are. Applications: "any" or a name starting with "dns"
// (dns, dns-base, dns-over-tls, ...) gives dnsYes; a list made only of
// nonDNSAppIDs gives dnsNo. Any other name (an application group, filter,
// custom or unknown App-ID) cannot be resolved here and gives dnsUnknown
// with those names, never dnsNo.
func permitsDNS(v *netreach.RuleView, apps []string) (dnsVerdict, []string) {
	svcOK := v.Service.Any || v.Service.ApplicationDefault
	for _, p := range v.Service.Ports {
		for _, d := range dnsPorts {
			if p.Protocol == d.Protocol && p.From <= d.Port && d.Port <= p.To {
				svcOK = true
			}
		}
	}
	if !svcOK {
		return dnsNo, nil
	}
	var unknown []string
	for _, a := range apps {
		switch {
		case a == "any" || strings.HasPrefix(strings.ToLower(a), "dns"):
			return dnsYes, nil
		case !nonDNSAppIDs[a]:
			unknown = append(unknown, a)
		}
	}
	if len(unknown) > 0 || len(apps) == 0 {
		return dnsUnknown, cleanAll(sortedUnique(unknown))
	}
	return dnsNo, nil
}

type flowKey struct {
	dst   netip.Addr
	proto string
	port  uint16
}

type dnsAgg struct {
	internal  map[netip.Addr]bool
	undecided map[netip.Addr]bool
	sessions  uint64
	origins   map[string]bool
}

func dnsFlows(in *Input, ext map[string]bool) []Finding {
	fw := make(map[netip.Addr]bool, len(in.obs.FirewallAddrs.Addrs))
	for _, a := range in.obs.FirewallAddrs.Addrs {
		fw[a.Unmap()] = true
	}
	placer := in.Index.Placer()
	aggs := map[flowKey]*dnsAgg{}
	placed := map[netip.Addr]int{} // 1 internal, 2 external, 3 undecided
	for _, fl := range in.obs.Flows.Flows {
		dst := fl.Dst.Unmap()
		if !isDNSPort(fl.Protocol, fl.Port) || fl.Action == FlowDeny || fw[dst] || dst.IsLoopback() {
			continue
		}
		src := fl.Src.Unmap()
		where, ok := placed[src]
		if !ok {
			where = sourceSide(placer, ext, src)
			placed[src] = where
		}
		if where == sideExternal {
			continue
		}
		k := flowKey{dst, fl.Protocol, fl.Port}
		a := aggs[k]
		if a == nil {
			a = &dnsAgg{internal: map[netip.Addr]bool{}, undecided: map[netip.Addr]bool{}, origins: map[string]bool{}}
			aggs[k] = a
		}
		if where == sideInternal {
			a.internal[src] = true
		} else {
			a.undecided[src] = true
		}
		a.sessions = satAdd(a.sessions, fl.Sessions)
		a.origins[fl.Origin] = true
	}
	keys := make([]flowKey, 0, len(aggs))
	for k := range aggs {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b flowKey) int {
		return cmp.Or(a.dst.Compare(b.dst), cmp.Compare(a.proto, b.proto), cmp.Compare(a.port, b.port))
	})
	out := make([]Finding, 0, len(keys))
	for _, k := range keys {
		a := aggs[k]
		f := Finding{CheckID: CheckDNSBypass, CheckVersion: CheckVersion, RuleIndex: -1}
		ev := &FlowEvidence{Destination: k.dst.String(), Protocol: clean(k.proto), Port: k.port, Sessions: a.sessions, Origins: cleanAll(sortedUnique(mapKeys(a.origins)))}
		f.Flow = ev
		where := "external destination"
		if netreach.IsSpecialAddress(k.dst) {
			where = "internal resolver"
		}
		if len(a.internal) > 0 {
			ev.Endpoints, ev.EndpointsTotal = listAddrs(a.internal)
			f.State, f.Severity = StateFinding, SeverityMedium
			f.Reason = clean(fmt.Sprintf("DNS %s/%d from %d internal endpoint(s) to %s %s, not the firewall (the designated resolver)",
				k.proto, k.port, ev.EndpointsTotal, where, k.dst))
		} else {
			ev.Endpoints, ev.EndpointsTotal = listAddrs(a.undecided)
			f.State = StateCannotDecide
			f.Reason = clean(fmt.Sprintf("cannot decide: DNS %s/%d to %s from %d source(s) that could not be placed",
				k.proto, k.port, k.dst, ev.EndpointsTotal))
		}
		out = append(out, f)
	}
	return out
}

// Sides of a flow source.
const (
	sideInternal = 1 + iota
	sideExternal
	sideUndecided
)

// sourceSide places a flow source: inside a known lab segment, in a
// proven zone that is not external, or in a private or special range is
// internal; a proven external zone is external; anything else is
// undecided.
func sourceSide(p *netreach.Placer, ext map[string]bool, src netip.Addr) int {
	pl := p.Place(src)
	switch {
	case pl.Segment != nil:
		return sideInternal
	case !pl.Unknown && pl.Zone != "" && ext != nil:
		if ext[pl.Zone] {
			return sideExternal
		}
		return sideInternal
	case netreach.IsSpecialAddress(src):
		return sideInternal
	}
	return sideUndecided
}

func listAddrs(m map[netip.Addr]bool) ([]string, int) {
	l := make([]netip.Addr, 0, len(m))
	for a := range m {
		l = append(l, a)
	}
	slices.SortFunc(l, netip.Addr.Compare)
	out := make([]string, 0, min(len(l), MaxListedEndpoints))
	for _, a := range l[:min(len(l), MaxListedEndpoints)] {
		out = append(out, a.String())
	}
	return out, len(l)
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func satAdd(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}
