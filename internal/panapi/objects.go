// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// MaxGroupResolveDepth bounds group nesting during resolution: a group
// whose members are all plain objects has depth 1 (ADR 0010 D3).
const MaxGroupResolveDepth = netdevcontract.MaxGroupNestingDepth

// maxTagObjects bounds tag objects; ADR 0010 D3 names no tag limit, so
// the object limit applies.
const maxTagObjects = netdevcontract.MaxAddressObjects

// maxFQDNBytes bounds an FQDN address value (DNS name limit).
const maxFQDNBytes = 253

// Sentinel errors of group resolution. A caller doing risk derivation
// (ADR 0010 D5) treats every one of them as "cannot evaluate", which counts
// as overlapping.
var (
	// ErrGroupNotFound is returned when the named group does not exist.
	ErrGroupNotFound = errors.New("panapi: group not found")
	// ErrGroupCycle is returned when group membership contains a cycle.
	ErrGroupCycle = errors.New("panapi: group membership has a cycle")
	// ErrGroupDepth is returned when nesting exceeds MaxGroupResolveDepth.
	ErrGroupDepth = errors.New("panapi: group nesting too deep")
	// ErrDynamicGroup is returned when resolution reaches a dynamic
	// address group; its tag filter is kept but never evaluated here.
	ErrDynamicGroup = errors.New("panapi: dynamic group cannot be resolved")
	// ErrGroupIncomplete is returned when resolution depends on a list that
	// was cut at its parse limit.
	ErrGroupIncomplete = errors.New("panapi: group data incomplete")
	// ErrUnresolvedMember is returned for a member that is neither an
	// object nor a group of this vsys (for example a shared or predefined
	// object).
	ErrUnresolvedMember = errors.New("panapi: group member unresolved")
	// ErrGroupUnresolvable is returned when resolution reaches a group with
	// neither static members nor a dynamic filter (InvalidAddressGroups,
	// InvalidServiceGroups): its content cannot be evaluated. It never
	// means "matches nothing".
	ErrGroupUnresolvable = errors.New("panapi: group cannot be evaluated")
)

// Objects is the parsed object configuration of the supported vsys. All
// names are validated (ValidateName), unique within their namespace
// (addresses and address groups share one, as do services and service
// groups), and every value is checked against its type.
//
// Incomplete is set when any list (objects, groups, members, tags) exceeded
// its netdevcontract limit; the lists then hold the entries up to the limit
// and must not be treated as complete or as deletions. Incomplete is also
// set when a group is invalid (InvalidAddressGroups, InvalidServiceGroups).
type Objects struct {
	Addresses     []netdevcontract.AddressObject
	AddressGroups []netdevcontract.Group
	Services      []netdevcontract.ServiceObject
	ServiceGroups []netdevcontract.Group
	// Tags are the names of the tag objects.
	Tags       []string
	Incomplete bool
	// InvalidAddressGroups and InvalidServiceGroups name the groups that
	// have neither static members nor a dynamic filter. They stay in
	// AddressGroups and ServiceGroups, but resolving them (directly or as
	// a nested member) fails with ErrGroupUnresolvable: an empty group is
	// "cannot evaluate", never "matches nothing".
	InvalidAddressGroups []string
	InvalidServiceGroups []string

	// truncatedAddr and truncatedSvc hold the address and service groups
	// whose member list was cut (two namespaces, two sets).
	truncatedAddr map[string]bool
	truncatedSvc  map[string]bool
}

// Policy returns the objects as a netdevcontract.FirewallPolicy fragment
// (rules, zones and interfaces are filled by their own parsers).
func (o Objects) Policy() netdevcontract.FirewallPolicy {
	return netdevcontract.FirewallPolicy{
		Addresses:     o.Addresses,
		AddressGroups: o.AddressGroups,
		Services:      o.Services,
		ServiceGroups: o.ServiceGroups,
	}
}

// ParseObjects parses the address, address-group, service, service-group
// and tag objects of a configuration response: a read of the whole vsys1
// or of one of these subtrees. It performs no I/O. The response is limit-
// checked and decoded by decodeConfig; every element outside the allowlist
// is dropped. Dynamic address groups keep their filter text unresolved.
func ParseObjects(data []byte) (Objects, error) {
	sec, err := decodeConfig(data)
	if err != nil {
		return Objects{}, fmt.Errorf("parse objects: %w", err)
	}
	p := objectParser{o: Objects{truncatedAddr: map[string]bool{}, truncatedSvc: map[string]bool{}}}
	if err := p.parse(sec); err != nil {
		return Objects{}, fmt.Errorf("parse objects: %w", err)
	}
	return p.o, nil
}

// objectParser accumulates Objects while enforcing the name namespaces.
type objectParser struct {
	o        Objects
	addrNS   map[string]struct{}
	svcNS    map[string]struct{}
	tagNames map[string]struct{}
}

// entries returns the entries of an optional container, cut to limit.
func entries[T any](p *objectParser, l *xmlList[T], what string, limit int) []T {
	if l == nil {
		return nil
	}
	es := l.Entries
	if netdevcontract.CheckCount(what, len(es), limit) != nil {
		es, p.o.Incomplete = es[:limit], true
	}
	return es
}

// claim registers name in a namespace or reports it as malformed or
// duplicated. The name itself is never put into the error.
func claim(ns map[string]struct{}, name, what string, i int) error {
	if ValidateName(name) != nil {
		return fmt.Errorf("%w: %s %d: invalid name", ErrInvalidConfig, what, i)
	}
	if _, dup := ns[name]; dup {
		return fmt.Errorf("%w: %s %d: name duplicated", ErrInvalidConfig, what, i)
	}
	ns[name] = struct{}{}
	return nil
}

func (p *objectParser) parse(sec xmlSection) error {
	p.addrNS = map[string]struct{}{}
	p.svcNS = map[string]struct{}{}
	p.tagNames = map[string]struct{}{}

	for i, e := range entries(p, sec.Tag, "tags", maxTagObjects) {
		if err := claim(p.tagNames, e.Name, "tag", i); err != nil {
			return err
		}
		p.o.Tags = append(p.o.Tags, e.Name)
	}
	for i, e := range entries(p, sec.Address, "addresses", netdevcontract.MaxAddressObjects) {
		a, err := p.address(e)
		if err != nil {
			return fmt.Errorf("address %d: %w", i, err)
		}
		if err := claim(p.addrNS, a.Name, "address", i); err != nil {
			return err
		}
		p.o.Addresses = append(p.o.Addresses, a)
	}
	for i, e := range entries(p, sec.AddressGroup, "address groups", netdevcontract.MaxAddressGroups) {
		g, err := p.addressGroup(e)
		if err != nil {
			return fmt.Errorf("address group %d: %w", i, err)
		}
		if err := claim(p.addrNS, g.Name, "address group", i); err != nil {
			return err
		}
		if emptyGroup(g) {
			p.o.Incomplete = true
			p.o.InvalidAddressGroups = append(p.o.InvalidAddressGroups, g.Name)
		}
		p.o.AddressGroups = append(p.o.AddressGroups, g)
	}
	for i, e := range entries(p, sec.Service, "services", netdevcontract.MaxServiceObjects) {
		s, err := p.service(e)
		if err != nil {
			return fmt.Errorf("service %d: %w", i, err)
		}
		if err := claim(p.svcNS, s.Name, "service", i); err != nil {
			return err
		}
		p.o.Services = append(p.o.Services, s)
	}
	for i, e := range entries(p, sec.ServiceGroup, "service groups", netdevcontract.MaxServiceGroups) {
		g, err := p.serviceGroup(e)
		if err != nil {
			return fmt.Errorf("service group %d: %w", i, err)
		}
		if err := claim(p.svcNS, g.Name, "service group", i); err != nil {
			return err
		}
		if emptyGroup(g) {
			p.o.Incomplete = true
			p.o.InvalidServiceGroups = append(p.o.InvalidServiceGroups, g.Name)
		}
		p.o.ServiceGroups = append(p.o.ServiceGroups, g)
	}
	return nil
}

// emptyGroup reports whether g has neither static members nor a dynamic
// filter. Such a group cannot be evaluated (ErrGroupUnresolvable).
func emptyGroup(g netdevcontract.Group) bool {
	return len(g.Static) == 0 && g.DynamicFilter == ""
}

// commonFields validates description and tags of an object or group.
func (p *objectParser) commonFields(desc []string, tags []xmlMembers) (string, []string, error) {
	d, err := atMostOne(desc, "description")
	if err != nil {
		return "", nil, err
	}
	if !validText(d, netdevcontract.MaxDescriptionBytes) {
		return "", nil, fmt.Errorf("%w: description is not printable text of at most %d bytes", ErrInvalidConfig, netdevcontract.MaxDescriptionBytes)
	}
	ts, truncated, err := nameList(tags, netdevcontract.MaxTagsPerObject, "tag")
	if err != nil {
		return "", nil, err
	}
	p.o.Incomplete = p.o.Incomplete || truncated
	return d, ts, nil
}

func (p *objectParser) address(e xmlAddress) (netdevcontract.AddressObject, error) {
	a := netdevcontract.AddressObject{Name: e.Name}
	var raw []string
	for _, c := range []struct {
		t  netdevcontract.AddressType
		vs []string
	}{
		{netdevcontract.AddressNetmask, e.IPNetmask},
		{netdevcontract.AddressRange, e.IPRange},
		{netdevcontract.AddressWildcard, e.IPWildcard},
		{netdevcontract.AddressFQDN, e.FQDN},
	} {
		if len(c.vs) == 0 {
			continue
		}
		if raw != nil {
			return a, fmt.Errorf("%w: more than one address value", ErrInvalidConfig)
		}
		a.Type, raw = c.t, c.vs
	}
	if len(raw) != 1 {
		return a, fmt.Errorf("%w: exactly one address value required", ErrInvalidConfig)
	}
	v, ok := addressValue(a.Type, raw[0])
	if !ok {
		return a, fmt.Errorf("%w: %s value is malformed", ErrInvalidConfig, a.Type)
	}
	a.Value = v
	var err error
	a.Description, a.Tags, err = p.commonFields(e.Description, e.Tag)
	return a, err
}

// addressValue validates v as a value of type t and returns its canonical
// form (IP literals as netip prints them, so the value passes the
// netdevcontract checks).
func addressValue(t netdevcontract.AddressType, v string) (string, bool) {
	if v == "" || len(v) > netdevcontract.MaxLabelBytes {
		return "", false
	}
	switch t {
	case netdevcontract.AddressNetmask:
		if !strings.Contains(v, "/") {
			a, ok := ipLiteral(v)
			return a.String(), ok
		}
		pfx, err := netip.ParsePrefix(v)
		if err != nil {
			return "", false
		}
		return pfx.String(), true
	case netdevcontract.AddressRange:
		lo, hi, ok := strings.Cut(v, "-")
		a, ok1 := ipLiteral(lo)
		b, ok2 := ipLiteral(hi)
		if !ok || !ok1 || !ok2 || a.Is4() != b.Is4() || a.Compare(b) > 0 {
			return "", false
		}
		return a.String() + "-" + b.String(), true
	case netdevcontract.AddressWildcard:
		addr, mask, ok := strings.Cut(v, "/")
		a, ok1 := ipLiteral(addr)
		m, ok2 := ipLiteral(mask)
		if !ok || !ok1 || !ok2 || a.Is4() != m.Is4() {
			return "", false
		}
		return a.String() + "/" + m.String(), true
	case netdevcontract.AddressFQDN:
		if !validFQDN(v) {
			return "", false
		}
		return v, true
	}
	return "", false
}

// ipLiteral parses an IP address without a zone.
func ipLiteral(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}

// validFQDN accepts ASCII DNS names of LDH labels (case-insensitive) up to
// maxFQDNBytes. Non-ASCII is refused before lowercasing so that lookalike
// runes cannot fold into ASCII letters.
func validFQDN(s string) bool {
	if s == "" || len(s) > maxFQDNBytes {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func (p *objectParser) addressGroup(e xmlAddressGroup) (netdevcontract.Group, error) {
	g := netdevcontract.Group{Name: e.Name}
	members, truncated, err := nameList(e.Static, netdevcontract.MaxGroupMembers, "member")
	if err != nil {
		return g, err
	}
	g.Static = members
	switch len(e.Dynamic) {
	case 0:
	case 1:
		if len(e.Static) > 0 {
			return g, fmt.Errorf("%w: static members and dynamic filter are exclusive", ErrInvalidConfig)
		}
		f, err := atMostOne(e.Dynamic[0].Filter, "filter")
		if err != nil {
			return g, err
		}
		if f == "" || !validText(f, netdevcontract.MaxFilterBytes) {
			return g, fmt.Errorf("%w: dynamic filter is not printable text of 1 to %d bytes", ErrInvalidConfig, netdevcontract.MaxFilterBytes)
		}
		g.DynamicFilter = f
	default:
		return g, fmt.Errorf("%w: dynamic repeated", ErrInvalidConfig)
	}
	g.Description, g.Tags, err = p.commonFields(e.Description, e.Tag)
	if err != nil {
		return g, err
	}
	p.markTruncated(p.o.truncatedAddr, g.Name, truncated)
	return g, nil
}

func (p *objectParser) serviceGroup(e xmlServiceGroup) (netdevcontract.Group, error) {
	g := netdevcontract.Group{Name: e.Name}
	members, truncated, err := nameList(e.Members, netdevcontract.MaxGroupMembers, "member")
	if err != nil {
		return g, err
	}
	g.Static = members
	_, g.Tags, err = p.commonFields(nil, e.Tag)
	if err != nil {
		return g, err
	}
	p.markTruncated(p.o.truncatedSvc, g.Name, truncated)
	return g, nil
}

// markTruncated records in set a group whose member list was cut.
func (p *objectParser) markTruncated(set map[string]bool, name string, truncated bool) {
	if truncated {
		p.o.Incomplete = true
		set[name] = true
	}
}

func (p *objectParser) service(e xmlService) (netdevcontract.ServiceObject, error) {
	s := netdevcontract.ServiceObject{Name: e.Name}
	if len(e.Protocol) != 1 {
		return s, fmt.Errorf("%w: exactly one protocol element required", ErrInvalidConfig)
	}
	var ports []xmlPorts
	for _, c := range []struct {
		name string
		ps   []xmlPorts
	}{{"tcp", e.Protocol[0].TCP}, {"udp", e.Protocol[0].UDP}, {"sctp", e.Protocol[0].SCTP}} {
		if len(c.ps) == 0 {
			continue
		}
		if ports != nil {
			return s, fmt.Errorf("%w: more than one protocol", ErrInvalidConfig)
		}
		s.Protocol, ports = c.name, c.ps
	}
	if len(ports) != 1 {
		return s, fmt.Errorf("%w: exactly one tcp, udp or sctp element required", ErrInvalidConfig)
	}
	port, err := atMostOne(ports[0].Port, "port")
	if err != nil {
		return s, err
	}
	if !validPortSpec(port) {
		return s, fmt.Errorf("%w: port is malformed", ErrInvalidConfig)
	}
	src, err := atMostOne(ports[0].SourcePort, "source-port")
	if err != nil {
		return s, err
	}
	if src != "" && !validPortSpec(src) {
		return s, fmt.Errorf("%w: source-port is malformed", ErrInvalidConfig)
	}
	s.Port, s.SourcePort = port, src
	s.Description, s.Tags, err = p.commonFields(e.Description, e.Tag)
	return s, err
}

// validPortSpec accepts a comma-separated list of ports (0-65535) and
// ascending port ranges "lo-hi" of at most netdevcontract.MaxLabelBytes.
func validPortSpec(s string) bool {
	if s == "" || len(s) > netdevcontract.MaxLabelBytes {
		return false
	}
	for part := range strings.SplitSeq(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, ok := portNumber(lo)
		if !ok {
			return false
		}
		if isRange {
			b, ok := portNumber(hi)
			if !ok || a > b {
				return false
			}
		}
	}
	return true
}

// portNumber parses 1 to 5 ASCII digits as a port of at most 65535.
func portNumber(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n <= 65535
}

// ResolveGroup expands the address group name into the address objects it
// contains, through nested static groups, in first-seen order without
// duplicates. It fails with ErrGroupNotFound, ErrGroupCycle,
// ErrGroupDepth (nesting deeper than MaxGroupResolveDepth),
// ErrDynamicGroup, ErrGroupIncomplete, ErrGroupUnresolvable or
// ErrUnresolvedMember; the error never contains the group name, which is
// device text. Each group is
// expanded at most once per call, so the work is linear in the total
// member count.
func (o Objects) ResolveGroup(name string) ([]netdevcontract.AddressObject, error) {
	leaves := make(map[string]int, len(o.Addresses))
	for i, a := range o.Addresses {
		leaves[a.Name] = i
	}
	names, err := o.resolve(name, leaves, o.AddressGroups, o.truncatedAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve address group: %w", err)
	}
	out := make([]netdevcontract.AddressObject, 0, len(names))
	for _, i := range names {
		out = append(out, o.Addresses[i])
	}
	return out, nil
}

// ResolveServiceGroup expands the service group name into its service
// objects, with the same rules and errors as ResolveGroup. Predefined
// services (for example service-http) are not part of the configuration
// and yield ErrUnresolvedMember.
func (o Objects) ResolveServiceGroup(name string) ([]netdevcontract.ServiceObject, error) {
	leaves := make(map[string]int, len(o.Services))
	for i, s := range o.Services {
		leaves[s.Name] = i
	}
	names, err := o.resolve(name, leaves, o.ServiceGroups, o.truncatedSvc)
	if err != nil {
		return nil, fmt.Errorf("resolve service group: %w", err)
	}
	out := make([]netdevcontract.ServiceObject, 0, len(names))
	for _, i := range names {
		out = append(out, o.Services[i])
	}
	return out, nil
}

// resolve returns the leaf indexes reachable from group root.
func (o Objects) resolve(root string, leaves map[string]int, groups []netdevcontract.Group, truncated map[string]bool) ([]int, error) {
	index := make(map[string]int, len(groups))
	for i, g := range groups {
		index[g.Name] = i
	}
	if _, ok := index[root]; !ok {
		return nil, ErrGroupNotFound
	}
	r := resolver{
		incomplete: o.Incomplete,
		truncated:  truncated,
		leaves:     leaves,
		groups:     groups,
		index:      index,
		height:     make(map[int]int),
		seen:       make(map[int]struct{}),
	}
	if _, err := r.visit(index[root], 1); err != nil {
		return nil, err
	}
	return r.out, nil
}

// resolver is the state of one resolution. height memoizes the nesting
// height of every finished group (visiting while on the current path), so
// a group shared by many parents is expanded once and the depth limit
// still sees its full height from every path.
type resolver struct {
	incomplete bool
	truncated  map[string]bool
	leaves     map[string]int
	groups     []netdevcontract.Group
	index      map[string]int
	height     map[int]int
	seen       map[int]struct{}
	out        []int
}

// heightVisiting marks a group on the current resolution path.
const heightVisiting = -1

func (r *resolver) visit(gi, level int) (int, error) {
	if level > MaxGroupResolveDepth {
		return 0, ErrGroupDepth
	}
	switch h, ok := r.height[gi]; {
	case ok && h == heightVisiting:
		return 0, ErrGroupCycle
	case ok:
		return h, nil
	}
	g := r.groups[gi]
	if emptyGroup(g) {
		return 0, ErrGroupUnresolvable
	}
	if g.DynamicFilter != "" {
		return 0, ErrDynamicGroup
	}
	if r.truncated[g.Name] {
		return 0, ErrGroupIncomplete
	}
	r.height[gi] = heightVisiting
	h := 1
	for _, m := range g.Static {
		if li, ok := r.leaves[m]; ok {
			if _, dup := r.seen[li]; !dup {
				r.seen[li] = struct{}{}
				r.out = append(r.out, li)
			}
			continue
		}
		sub, ok := r.index[m]
		if !ok {
			if r.incomplete {
				// the member may be one of the entries cut at a limit
				return 0, ErrGroupIncomplete
			}
			return 0, ErrUnresolvedMember
		}
		sh, err := r.visit(sub, level+1)
		if err != nil {
			return 0, err
		}
		h = max(h, sh+1)
		if h > MaxGroupResolveDepth {
			return 0, ErrGroupDepth
		}
	}
	r.height[gi] = h
	return h, nil
}
