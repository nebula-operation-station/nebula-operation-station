// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Rule-count limits of ADR 0010 D3. A rulebase over its limit is cut to the
// first rules in document order and marked incomplete.
const (
	// MaxSecurityRules bounds the security rules read from one response.
	MaxSecurityRules = netdevcontract.MaxSecurityRules
	// MaxNATRules bounds the NAT rules read from one response.
	MaxNATRules = netdevcontract.MaxNATRules
	// MaxRuleMembers bounds the members of one rule field (from, to,
	// source, destination, application, service, ...).
	MaxRuleMembers = netdevcontract.MaxRuleMembers
)

// RuleType is the PAN-OS security rule type.
type RuleType string

// Rule types. A rule without a rule-type element is universal.
const (
	RuleTypeUniversal RuleType = "universal"
	RuleTypeIntrazone RuleType = "intrazone"
	RuleTypeInterzone RuleType = "interzone"
)

// Rule is one PAN-OS security rule of the supported vsys.
//
// Index is the position in the rulebase (document order, from 0); it is
// the evaluation order of the firewall and is never re-sorted. Disabled
// rules are kept in place with Disabled set. Every member list holds the
// members exactly as configured, in device order: names are validated
// (ValidateName), source users are printable text. A source or destination
// member that is no valid name must be an IP, prefix or ascending range
// literal and is stored in canonical form; a member that is a valid name is
// stored as configured even when it looks like an address (for example
// "10.0.0.1" or a descending range). ResolveRule reads such a member as a
// literal only if it names no object and is a valid literal; otherwise it
// is reported as unresolved. A member that names no known object is kept
// here and reported by ResolveRule, never dropped.
//
// NegateSource and NegateDestination invert the address match: a reader
// that ignores them inverts the meaning of the rule.
type Rule struct {
	Index             int
	Name              string
	UUID              string
	Type              RuleType
	From              []string
	To                []string
	Source            []string
	Destination       []string
	NegateSource      bool
	NegateDestination bool
	SourceUser        []string
	Application       []string
	Service           []string
	Category          []string
	Action            netdevcontract.RuleAction
	Disabled          bool
	// LogStart and LogEnd carry the PAN-OS defaults when the element is
	// absent: no logging at session start, logging at session end
	// (*verify* against the installed release, ND-03).
	LogStart    bool
	LogEnd      bool
	Description string
	Tags        []string
}

// RuleSet is the parsed security rulebase of the supported vsys in rule
// order. Incomplete is set when the rule list, a member list or a tag list
// exceeded its limit (the lists then hold the first entries up to the
// limit), or when the response cannot be told apart from missing data
// (see decodeConfig). An incomplete set must not be treated as the whole
// policy, and a rule missing from it must not be read as deleted.
type RuleSet struct {
	Rules      []Rule
	Incomplete bool
}

// xmlSecurityRule is one <entry> of rulebase/security/rules: the element
// allowlist of ADR 0010 D4 for security rules. Every other element
// (profile settings, schedules, options, HIP, ...) is dropped with its
// subtree; single-valued elements are slices so that a repetition is
// detected.
type xmlSecurityRule struct {
	Name              string       `xml:"name,attr"`
	UUID              string       `xml:"uuid,attr"`
	RuleType          []string     `xml:"rule-type"`
	From              []xmlMembers `xml:"from"`
	To                []xmlMembers `xml:"to"`
	Source            []xmlMembers `xml:"source"`
	Destination       []xmlMembers `xml:"destination"`
	NegateSource      []string     `xml:"negate-source"`
	NegateDestination []string     `xml:"negate-destination"`
	SourceUser        []xmlMembers `xml:"source-user"`
	Application       []xmlMembers `xml:"application"`
	Service           []xmlMembers `xml:"service"`
	Category          []xmlMembers `xml:"category"`
	Action            []string     `xml:"action"`
	Disabled          []string     `xml:"disabled"`
	LogStart          []string     `xml:"log-start"`
	LogEnd            []string     `xml:"log-end"`
	Description       []string     `xml:"description"`
	Tag               []xmlMembers `xml:"tag"`
}

// ParseSecurityRules parses the security rulebase of a configuration
// response: a read of rulebase/security/rules of vsys1 (SubtreeSecurityRules)
// or of the whole vsys. It performs no I/O. The response passes the same
// limit checks and strict decoding as every ND-09 parser; only the
// allowlisted rule elements are read. Errors never contain device text.
func ParseSecurityRules(data []byte) (RuleSet, error) {
	entries, incomplete, err := decodeRules[xmlSecurityRule](data, "security")
	if err != nil {
		return RuleSet{}, fmt.Errorf("parse security rules: %w", err)
	}
	set := RuleSet{Incomplete: incomplete}
	if netdevcontract.CheckCount("security rules", len(entries), MaxSecurityRules) != nil {
		entries, set.Incomplete = entries[:MaxSecurityRules], true
	}
	names := make(map[string]struct{}, len(entries))
	set.Rules = make([]Rule, 0, len(entries))
	for i, e := range entries {
		r, truncated, err := parseSecurityRule(e)
		if err != nil {
			return RuleSet{}, fmt.Errorf("parse security rules: rule %d: %w", i, err)
		}
		if _, dup := names[r.Name]; dup {
			return RuleSet{}, fmt.Errorf("parse security rules: rule %d: %w: name duplicated", i, ErrInvalidConfig)
		}
		names[r.Name] = struct{}{}
		r.Index = i
		set.Incomplete = set.Incomplete || truncated
		set.Rules = append(set.Rules, r)
	}
	return set, nil
}

// parseSecurityRule validates one rule entry. truncated reports a member or
// tag list cut at its limit.
func parseSecurityRule(e xmlSecurityRule) (Rule, bool, error) {
	if ValidateName(e.Name) != nil {
		return Rule{}, false, fmt.Errorf("%w: invalid name", ErrInvalidConfig)
	}
	r := Rule{Name: e.Name}
	var err error
	if r.UUID, err = ruleUUID(e.UUID); err != nil {
		return Rule{}, false, err
	}
	t, err := atMostOne(e.RuleType, "rule-type")
	if err != nil {
		return Rule{}, false, err
	}
	switch RuleType(t) {
	case "":
		r.Type = RuleTypeUniversal
	case RuleTypeUniversal, RuleTypeIntrazone, RuleTypeInterzone:
		r.Type = RuleType(t)
	default:
		return Rule{}, false, fmt.Errorf("%w: rule-type is unknown", ErrInvalidConfig)
	}

	var truncated bool
	for _, f := range []struct {
		dst      *[]string
		src      []xmlMembers
		kind     memberKind
		what     string
		required bool
	}{
		{&r.From, e.From, memberName, "from", true},
		{&r.To, e.To, memberName, "to", true},
		{&r.Source, e.Source, memberAddress, "source", true},
		{&r.Destination, e.Destination, memberAddress, "destination", true},
		{&r.SourceUser, e.SourceUser, memberText, "source-user", false},
		{&r.Application, e.Application, memberName, "application", true},
		{&r.Service, e.Service, memberName, "service", true},
		{&r.Category, e.Category, memberName, "category", false},
	} {
		ms, cut, err := ruleMembers(f.src, f.kind, f.what)
		if err != nil {
			return Rule{}, false, err
		}
		if f.required && len(ms) == 0 {
			// PAN-OS stores "any" explicitly; an empty match field cannot
			// be evaluated and must not read as "matches nothing"
			return Rule{}, false, fmt.Errorf("%w: %s has no members", ErrInvalidConfig, f.what)
		}
		*f.dst, truncated = ms, truncated || cut
	}

	a, err := atMostOne(e.Action, "action")
	if err != nil {
		return Rule{}, false, err
	}
	switch act := netdevcontract.RuleAction(a); act {
	case netdevcontract.ActionAllow, netdevcontract.ActionDeny, netdevcontract.ActionDrop,
		netdevcontract.ActionResetClient, netdevcontract.ActionResetServer, netdevcontract.ActionResetBoth:
		r.Action = act
	default:
		return Rule{}, false, fmt.Errorf("%w: action is missing or unknown", ErrInvalidConfig)
	}

	for _, f := range []struct {
		dst  *bool
		src  []string
		what string
		def  bool
	}{
		{&r.Disabled, e.Disabled, "disabled", false},
		{&r.NegateSource, e.NegateSource, "negate-source", false},
		{&r.NegateDestination, e.NegateDestination, "negate-destination", false},
		{&r.LogStart, e.LogStart, "log-start", false},
		{&r.LogEnd, e.LogEnd, "log-end", true},
	} {
		if *f.dst, err = yesNo(f.src, f.what, f.def); err != nil {
			return Rule{}, false, err
		}
	}

	if r.Description, err = description(e.Description); err != nil {
		return Rule{}, false, err
	}
	tags, cut, err := nameList(e.Tag, netdevcontract.MaxTagsPerObject, "tag")
	if err != nil {
		return Rule{}, false, err
	}
	r.Tags = tags
	return r, truncated || cut, nil
}

// ruleUUID validates an optional uuid attribute and returns it in lower
// case (the netdevcontract form).
func ruleUUID(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if len(s) != 36 {
		return "", fmt.Errorf("%w: uuid is malformed", ErrInvalidConfig)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return "", fmt.Errorf("%w: uuid is malformed", ErrInvalidConfig)
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return "", fmt.Errorf("%w: uuid is malformed", ErrInvalidConfig)
		}
	}
	return strings.ToLower(s), nil
}

// yesNo parses an optional PAN-OS yes/no element; def applies when it is
// absent.
func yesNo(vs []string, what string, def bool) (bool, error) {
	v, err := atMostOne(vs, what)
	if err != nil {
		return false, err
	}
	switch {
	case len(vs) == 0:
		return def, nil
	case v == "yes":
		return true, nil
	case v == "no":
		return false, nil
	}
	return false, fmt.Errorf("%w: %s is not yes or no", ErrInvalidConfig, what)
}

// description validates an optional description element.
func description(vs []string) (string, error) {
	d, err := atMostOne(vs, "description")
	if err != nil {
		return "", err
	}
	if !validText(d, netdevcontract.MaxDescriptionBytes) {
		return "", fmt.Errorf("%w: description is not printable text of at most %d bytes", ErrInvalidConfig, netdevcontract.MaxDescriptionBytes)
	}
	return d, nil
}

// memberKind selects the validation of a rule member.
type memberKind int

const (
	// memberName is a PAN-OS name (zones, applications, services,
	// categories; "any" and "application-default" are names too).
	memberName memberKind = iota
	// memberAddress is a name or an IP, prefix or range literal.
	memberAddress
	// memberText is printable text (source users such as domain\user or a
	// distinguished name).
	memberText
)

// memberValue validates m as a member of kind and returns its stored form.
func memberValue(kind memberKind, m string) (string, bool) {
	switch kind {
	case memberName:
		return m, ValidateName(m) == nil
	case memberAddress:
		if ValidateName(m) == nil {
			return m, true
		}
		return addressLiteral(m)
	case memberText:
		return m, m != "" && validText(m, netdevcontract.MaxLabelBytes)
	}
	return "", false
}

// addressLiteral accepts an IP address, a prefix or an ascending range and
// returns its canonical form.
func addressLiteral(m string) (string, bool) {
	if strings.Contains(m, "-") {
		return addressValue(netdevcontract.AddressRange, m)
	}
	return addressValue(netdevcontract.AddressNetmask, m)
}

// ruleMembers validates one member list of a rule. Lists longer than
// MaxRuleMembers are cut and reported as truncated; a repeated container,
// an invalid or a duplicated member is refused. Errors name the field (a
// fixed string) and the member position, never the member.
func ruleMembers(ms []xmlMembers, kind memberKind, what string) (out []string, truncated bool, err error) {
	if len(ms) > 1 {
		return nil, false, errRepeated(what)
	}
	if len(ms) == 0 || len(ms[0].Members) == 0 {
		return nil, false, nil
	}
	in := ms[0].Members
	if netdevcontract.CheckCount(what, len(in), MaxRuleMembers) != nil {
		in, truncated = in[:MaxRuleMembers], true
	}
	seen := make(map[string]struct{}, len(in))
	out = make([]string, 0, len(in))
	for i, m := range in {
		v, ok := memberValue(kind, m)
		if !ok {
			return nil, false, fmt.Errorf("%w: %s member %d: invalid", ErrInvalidConfig, what, i)
		}
		if _, dup := seen[v]; dup {
			return nil, false, fmt.Errorf("%w: %s member %d: duplicated", ErrInvalidConfig, what, i)
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out, truncated, nil
}

// decodeRules is the decode step of the rulebase parsers. It applies the
// same checks as decodeConfig (limits before decoding, success status,
// strict decoder without entities or foreign charsets, no repeated
// containers, single supported vsys) and returns the <entry> elements of
// rulebase/<base>/rules in document order. Two response forms are
// accepted: a read of the rules subtree (<result><rules>) and a read of
// the whole vsys (<result><vsys><entry name="vsys1"><rulebase><base>
// <rules>). incomplete has the meaning of decodeConfig. Errors never
// contain response text.
func decodeRules[T any](data []byte, base string) (entries []T, incomplete bool, err error) {
	if err := netdevcontract.CheckXML(data, MaxParseResponseBytes); err != nil {
		if errors.Is(err, netdevcontract.ErrOverLimit) {
			return nil, false, fmt.Errorf("%w: %w", ErrXMLLimit, err)
		}
		return nil, false, fmt.Errorf("%w: XML check failed", ErrMalformedResponse)
	}
	if err := checkResponse(data); err != nil {
		return nil, false, err
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	// Entity and CharsetReader stay nil: only the predefined entities and
	// UTF-8 are accepted.
	rd := rulesDecoder[T]{d: dec, base: base}
	if err := rd.response(); err != nil {
		if errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrMalformedResponse) {
			// fixed element names only
			return nil, false, err
		}
		return nil, false, fmt.Errorf("%w: decode failed", ErrMalformedResponse)
	}
	switch rd.results {
	case 0:
		return nil, false, fmt.Errorf("%w: no result element", ErrMalformedResponse)
	case 1:
	default:
		// decodeResult refuses the second one already; kept as defence in depth
		return nil, false, errRepeated("result")
	}
	if !rd.vsys {
		if rd.direct == nil {
			return nil, rd.foreign > 0, nil
		}
		return rd.direct.Entries, false, nil
	}
	if rd.direct != nil {
		return nil, false, fmt.Errorf("%w: result mixes a vsys and subtree content", ErrInvalidConfig)
	}
	if rd.vsysEntries == 0 {
		return nil, true, nil
	}
	if rd.nested == nil {
		return nil, false, nil
	}
	return rd.nested.Entries, false, nil
}

// rulesDecoder walks a configuration response down to one rulebase. Every
// level refuses a repeated container and skips elements outside the path.
type rulesDecoder[T any] struct {
	d           *xml.Decoder
	base        string
	results     int
	vsys        bool
	vsysEntries int
	rulebase    bool
	baseSeen    bool
	direct      *xmlList[T]
	nested      *xmlList[T]
	foreign     int
}

// response reads the <response> root element.
func (rd *rulesDecoder[T]) response() error {
	for {
		tok, err := rd.d.Token()
		if err != nil {
			return err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "response" {
			return fmt.Errorf("%w: root is not response", ErrMalformedResponse)
		}
		status := ""
		for _, a := range se.Attr {
			if a.Name.Space == "" && a.Name.Local == "status" {
				status = a.Value
			}
		}
		if status != "success" {
			// checkResponse already enforced this; kept as defence in depth
			return fmt.Errorf("%w: status is not success", ErrMalformedResponse)
		}
		return decodeChildren(rd.d, rd.responseChild)
	}
}

func (rd *rulesDecoder[T]) responseChild(se xml.StartElement) error {
	if se.Name.Local != "result" {
		return rd.d.Skip()
	}
	rd.results++
	if rd.results > 1 {
		return errRepeated("result")
	}
	return decodeChildren(rd.d, rd.resultChild)
}

func (rd *rulesDecoder[T]) resultChild(se xml.StartElement) error {
	switch se.Name.Local {
	case "rules":
		return decodeOnce(rd.d, se, &rd.direct)
	case "vsys":
		if rd.vsys {
			return errRepeated("vsys")
		}
		rd.vsys = true
		return decodeChildren(rd.d, rd.vsysChild)
	}
	rd.foreign++
	return rd.d.Skip()
}

func (rd *rulesDecoder[T]) vsysChild(se xml.StartElement) error {
	if se.Name.Local != "entry" {
		return rd.d.Skip()
	}
	rd.vsysEntries++
	if rd.vsysEntries > 1 {
		return fmt.Errorf("%w: more than one vsys", ErrInvalidConfig)
	}
	name := ""
	for _, a := range se.Attr {
		if a.Name.Space == "" && a.Name.Local == "name" {
			name = a.Value
		}
	}
	if name != supportedVsys {
		return fmt.Errorf("%w: unsupported vsys", ErrInvalidConfig)
	}
	return decodeChildren(rd.d, rd.vsysEntryChild)
}

func (rd *rulesDecoder[T]) vsysEntryChild(se xml.StartElement) error {
	if se.Name.Local != "rulebase" {
		return rd.d.Skip()
	}
	if rd.rulebase {
		return errRepeated("rulebase")
	}
	rd.rulebase = true
	return decodeChildren(rd.d, rd.rulebaseChild)
}

func (rd *rulesDecoder[T]) rulebaseChild(se xml.StartElement) error {
	if se.Name.Local != rd.base {
		return rd.d.Skip()
	}
	if rd.baseSeen {
		return errRepeated(rd.base)
	}
	rd.baseSeen = true
	return decodeChildren(rd.d, rd.baseChild)
}

func (rd *rulesDecoder[T]) baseChild(se xml.StartElement) error {
	if se.Name.Local != "rules" {
		return rd.d.Skip()
	}
	return decodeOnce(rd.d, se, &rd.nested)
}

// RuleField names the rule field an unresolved member belongs to.
type RuleField string

// Rule fields ResolveRule expands.
const (
	FieldSource      RuleField = "source"
	FieldDestination RuleField = "destination"
	FieldService     RuleField = "service"
)

// UnresolvedMember is a rule member ResolveRule could not expand. Name is
// the member as configured (device text, to be rendered as text only).
// Reason is one of the resolution sentinels: ErrUnresolvedMember (no object
// or group of that name in the vsys, for example a shared, predefined or
// misspelt object), ErrGroupIncomplete (the object data was cut at a limit,
// so the member may exist), ErrGroupCycle, ErrGroupDepth, ErrDynamicGroup
// or ErrGroupUnresolvable. A caller doing risk derivation treats every
// unresolved member as "cannot evaluate" (ADR 0010 D5).
type UnresolvedMember struct {
	Field  RuleField
	Name   string
	Reason error
}

// ResolvedAddresses is the expanded address side of a rule. Any is set by
// the member "any"; Objects are the address objects reached directly or
// through static groups, in first-seen order without duplicates; Literals
// are IP, prefix and range members in rule order.
type ResolvedAddresses struct {
	Any      bool
	Objects  []netdevcontract.AddressObject
	Literals []string
}

// ResolvedServices is the expanded service side of a rule. Any and
// ApplicationDefault are set by the members of the same name; Objects are
// the service objects reached directly or through service groups.
type ResolvedServices struct {
	Any                bool
	ApplicationDefault bool
	Objects            []netdevcontract.ServiceObject
}

// ResolvedRule is the result of ResolveRule. Unresolved lists, in field
// and member order, every member that could not be expanded; the member is
// never dropped silently. Incomplete is set when the object data was
// incomplete, so even a fully resolved rule may lack objects.
type ResolvedRule struct {
	Source      ResolvedAddresses
	Destination ResolvedAddresses
	Service     ResolvedServices
	Unresolved  []UnresolvedMember
	Incomplete  bool
}

// ResolveRule expands the source, destination and service members of rule
// against objects: address and service objects by name, address and
// service groups with the semantics and errors of ResolveGroup and
// ResolveServiceGroup (cycle check, MaxGroupResolveDepth, dynamic, empty
// and truncated groups). A member that names no object or group but is a
// valid IP, prefix or ascending range literal is returned in Literals.
// Negation is not applied: the rule's NegateSource and NegateDestination
// still hold. Applications, zones, users and categories are not resolved.
// It performs no I/O and never fails; what cannot be expanded is listed in
// Unresolved. Resolving many rules against the same objects is cheaper
// through one RuleResolver.
func ResolveRule(rule Rule, objects Objects) ResolvedRule {
	return NewRuleResolver(objects).Resolve(rule)
}

// RuleResolver resolves rules against one Objects value. It indexes the
// objects and groups once, so a rule costs work linear in its members and
// the groups they reach, independent of the number of objects. A
// RuleResolver is read-only after construction and safe for concurrent
// use.
type RuleResolver struct {
	objects Objects
	addrs   groupIndex
	svcs    groupIndex
}

// groupIndex is the name index of one object kind (addresses or services)
// and its groups.
type groupIndex struct {
	leaves    map[string]int
	groups    []netdevcontract.Group
	index     map[string]int
	truncated map[string]bool
}

// resolveIndexHook, when set, is called once per index build. Tests use it
// to pin that the object index is not rebuilt per rule member.
var resolveIndexHook func()

// NewRuleResolver indexes objects for Resolve.
func NewRuleResolver(objects Objects) *RuleResolver {
	if resolveIndexHook != nil {
		resolveIndexHook()
	}
	rr := &RuleResolver{
		objects: objects,
		addrs:   newGroupIndex(len(objects.Addresses), objects.AddressGroups, objects.truncatedAddr),
		svcs:    newGroupIndex(len(objects.Services), objects.ServiceGroups, objects.truncatedSvc),
	}
	for i, a := range objects.Addresses {
		rr.addrs.leaves[a.Name] = i
	}
	for i, s := range objects.Services {
		rr.svcs.leaves[s.Name] = i
	}
	return rr
}

// newGroupIndex indexes groups by name; the leaves map is filled by the
// caller.
func newGroupIndex(leaves int, groups []netdevcontract.Group, truncated map[string]bool) groupIndex {
	gx := groupIndex{
		leaves:    make(map[string]int, leaves),
		groups:    groups,
		index:     make(map[string]int, len(groups)),
		truncated: truncated,
	}
	for i, g := range groups {
		gx.index[g.Name] = i
	}
	return gx
}

// expand returns the leaf indexes reachable from the group at gi with the
// resolver of ResolveGroup; only the per-resolution state is fresh.
func (gx *groupIndex) expand(gi int, incomplete bool) ([]int, error) {
	r := resolver{
		incomplete: incomplete,
		truncated:  gx.truncated,
		leaves:     gx.leaves,
		groups:     gx.groups,
		index:      gx.index,
		height:     make(map[int]int),
		seen:       make(map[int]struct{}),
	}
	if _, err := r.visit(gi, 1); err != nil {
		return nil, err
	}
	return r.out, nil
}

// Resolve expands rule as ResolveRule does.
func (rr *RuleResolver) Resolve(rule Rule) ResolvedRule {
	objects := rr.objects
	res := ResolvedRule{Incomplete: objects.Incomplete}
	unknown := func(field RuleField, m string) {
		reason := ErrUnresolvedMember
		if objects.Incomplete {
			// the member may be one of the entries cut at a limit
			reason = ErrGroupIncomplete
		}
		res.Unresolved = append(res.Unresolved, UnresolvedMember{Field: field, Name: m, Reason: reason})
	}

	resolveAddrs := func(field RuleField, members []string, out *ResolvedAddresses) {
		seen := map[int]struct{}{}
		add := func(i int) {
			if _, dup := seen[i]; !dup {
				seen[i] = struct{}{}
				out.Objects = append(out.Objects, objects.Addresses[i])
			}
		}
		for _, m := range members {
			if m == "any" {
				out.Any = true
				continue
			}
			if i, ok := rr.addrs.leaves[m]; ok {
				add(i)
				continue
			}
			if gi, ok := rr.addrs.index[m]; ok {
				is, err := rr.addrs.expand(gi, objects.Incomplete)
				if err != nil {
					res.Unresolved = append(res.Unresolved, UnresolvedMember{Field: field, Name: m,
						Reason: fmt.Errorf("resolve address group: %w", err)})
					continue
				}
				for _, i := range is {
					add(i)
				}
				continue
			}
			if lit, ok := addressLiteral(m); ok {
				out.Literals = append(out.Literals, lit)
				continue
			}
			unknown(field, m)
		}
	}
	resolveAddrs(FieldSource, rule.Source, &res.Source)
	resolveAddrs(FieldDestination, rule.Destination, &res.Destination)

	seen := map[int]struct{}{}
	add := func(i int) {
		if _, dup := seen[i]; !dup {
			seen[i] = struct{}{}
			res.Service.Objects = append(res.Service.Objects, objects.Services[i])
		}
	}
	for _, m := range rule.Service {
		switch m {
		case "any":
			res.Service.Any = true
			continue
		case "application-default":
			res.Service.ApplicationDefault = true
			continue
		}
		if i, ok := rr.svcs.leaves[m]; ok {
			add(i)
			continue
		}
		if gi, ok := rr.svcs.index[m]; ok {
			is, err := rr.svcs.expand(gi, objects.Incomplete)
			if err != nil {
				res.Unresolved = append(res.Unresolved, UnresolvedMember{Field: FieldService, Name: m,
					Reason: fmt.Errorf("resolve service group: %w", err)})
				continue
			}
			for _, i := range is {
				add(i)
			}
			continue
		}
		unknown(FieldService, m)
	}
	return res
}
