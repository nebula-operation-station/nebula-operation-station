// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

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
// so the member may exist), ErrGroupCycle, ErrGroupDepth, ErrDynamicGroup,
// ErrGroupUnresolvable or ErrResolveBudget (not expanded because a
// RuleResolver budget is exhausted; the result is then Incomplete). A
// caller doing risk derivation treats every unresolved member as "cannot
// evaluate" (ADR 0010 D5).
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
// incomplete, so even a fully resolved rule may lack objects, and when a
// member was not expanded because a RuleResolver budget is exhausted (a
// field may then hold part of that member's objects).
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

// Work and memory budgets of one RuleResolver (fail-safe caps in the sense
// of ADR 0010 D3). Both are charged before the work they pay for and are
// never refunded; once a budget is exhausted it stays exhausted for the
// lifetime of the RuleResolver, and every member that would need it is
// reported with ErrResolveBudget in a result marked Incomplete.
//
// A real PAN-OS configuration stays well below both: the walk of all
// groups is bounded by the group members of one 8 MiB response (under
// 500,000). The medium configuration of the tests (8,000 addresses, 1,500
// groups in three levels, 20 groups of 400 objects shared by a third of
// the others, 3,000 rules) needs about 2 million operations and result
// objects; 10,000 such rules need about 7 million, under half of
// MaxResolveResultLeaves. 1,000 rules whose three fields each reach a
// group of 2,500 objects need 7.5 million.
const (
	// MaxResolveLeafOps bounds the leaf operations of one RuleResolver: every
	// group member iterated by the memo walk or the failure-reason pass,
	// every group edge followed by the reason pass, and every member (object
	// or group reference) a rule field merge iterates, direct object members
	// included. It bounds the CPU time of any number of Resolve calls.
	MaxResolveLeafOps = 1 << 25
	// MaxResolveResultLeaves bounds the objects one RuleResolver places into
	// results: each distinct object of a rule field counts once per field and
	// rule. The memo table holds no leaf lists, so this is the bound of the
	// leaf memory a RuleResolver produces beyond its index of the objects:
	// at most 16,777,216 object values of 88 (address) or 104 (service)
	// bytes, about 1.4 to 1.7 GiB if a caller keeps every result; their
	// strings are shared with Objects. A caller that keeps one rule at a
	// time holds at most three fields of MaxAddressObjects or
	// MaxServiceObjects objects.
	MaxResolveResultLeaves = 1 << 24
)

// ErrResolveBudget is the reason of a rule member that was not expanded
// because the RuleResolver exhausted MaxResolveLeafOps or
// MaxResolveResultLeaves. The member may resolve; the rule is incomplete.
var ErrResolveBudget = errors.New("panapi: rule resolution budget exhausted")

// RuleResolver resolves rules against one Objects value.
//
// It keeps a memo table with one entry per group: whether the group
// expands, its nesting height, the error it fails with, and its Static list
// resolved to object positions and member-group references. An entry is
// filled lazily, the first time a rule member reaches the group, by an
// iterative depth-first walk that also fills the entries of every group
// below it; a filled entry, failure included, is never computed again.
// Each group is entered at most once and each member of its Static list is
// iterated at most once over the lifetime of the RuleResolver, so the walk
// costs O(G + M) time and memory for G groups with M members in total. The
// memo table never copies the leaves of a member group into its parent.
//
// For a group member that fails, the reason is computed once per group by
// a pass that follows the order of ResolveGroup and shares nothing with
// other groups except the heights of groups known to expand. It iterates
// the members of the failing groups it reaches and follows the
// member-group edges of the expanding ones: O(M) per failing group.
//
// Resolve merges a field's members into a fresh result: each direct member
// is looked up once, and the expansion of a group member is a depth-first
// walk of the memoized Static lists that enters every group at most once
// per field. A rule field therefore costs O(direct members + G + M) and
// usually much less: the members of the distinct groups it reaches. Shared
// member groups, however often they are referenced, are merged once per
// field.
//
// Without a budget, a rulebase of R fields could still cost R times
// (G + M). MaxResolveLeafOps and MaxResolveResultLeaves are the hard bound:
// over its lifetime a RuleResolver performs at most MaxResolveLeafOps
// member and leaf operations plus O(1) per direct rule member, and places at
// most MaxResolveResultLeaves objects into results. Its memory is the memo
// table (O(G + M)), the per-field sets of one Resolve call (O(objects + G))
// and the results it returned.
//
// A group fails a member exactly when ResolveGroup or ResolveServiceGroup
// fails it, with the same reason. A member not expanded because a budget is
// exhausted is reported with ErrResolveBudget instead.
//
// A RuleResolver is safe for concurrent use; the memo table is guarded by
// a mutex, its entries are immutable once filled and the budgets are
// atomic counters shared by all Resolve calls.
type RuleResolver struct {
	objects Objects

	mu    sync.Mutex
	addrs groupIndex
	svcs  groupIndex
	// groupChecks counts the groups entered by the walk (guarded by mu);
	// each group is entered at most once.
	groupChecks int
	// memberIters counts the Static-member iterations of the walk (guarded
	// by mu); it never exceeds the total number of group members.
	memberIters int
	// reasonPasses counts the failure-reason passes (guarded by mu), at
	// most one per failing group.
	reasonPasses int
	// groupVisits counts the memo lookups of all Resolve calls, one per
	// direct group member of a rule.
	groupVisits atomic.Int64
	// leafOps and resultLeaves are the charged MaxResolveLeafOps and
	// MaxResolveResultLeaves budgets; a charge over the limit is kept, so
	// an exhausted budget stays exhausted.
	leafOps      atomic.Int64
	resultLeaves atomic.Int64
}

// chargeOps charges n leaf operations; it reports false when the budget is
// exhausted, and the work must then not be done.
func (rr *RuleResolver) chargeOps(n int) bool {
	return rr.leafOps.Add(int64(n)) <= MaxResolveLeafOps
}

// chargeResult charges one result object.
func (rr *RuleResolver) chargeResult() bool {
	return rr.resultLeaves.Add(1) <= MaxResolveResultLeaves
}

// groupIndex is the name index of one object kind (addresses or services)
// and its groups, with the memo table of the group walk.
type groupIndex struct {
	leaves     map[string]int
	groups     []netdevcontract.Group
	index      map[string]int
	truncated  map[string]bool
	incomplete bool
	// The memo table is by group position and guarded by the RuleResolver
	// mutex. err[gi] and height[gi] are final once state[gi] is walkDone;
	// for a group that expands, codes[gi] is its Static list resolved to
	// object positions (>= 0) and member groups (^position), kids[gi] its
	// member groups in order, both immutable from then on and readable
	// without the mutex by whoever observed the group done under it.
	state  []uint8
	height []int
	err    []error
	codes  [][]int32
	kids   [][]int32
	// reason memoizes the ResolveGroup error of failing groups.
	reason map[int]error
}

// NewRuleResolver indexes objects for Resolve. Groups are walked lazily,
// on first use.
func NewRuleResolver(objects Objects) *RuleResolver {
	rr := &RuleResolver{
		objects: objects,
		addrs:   newGroupIndex(len(objects.Addresses), objects.AddressGroups, objects.truncatedAddr, objects.Incomplete),
		svcs:    newGroupIndex(len(objects.Services), objects.ServiceGroups, objects.truncatedSvc, objects.Incomplete),
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
func newGroupIndex(leaves int, groups []netdevcontract.Group, truncated map[string]bool, incomplete bool) groupIndex {
	gx := groupIndex{
		leaves:     make(map[string]int, leaves),
		groups:     groups,
		index:      make(map[string]int, len(groups)),
		truncated:  truncated,
		incomplete: incomplete,
		state:      make([]uint8, len(groups)),
		height:     make([]int, len(groups)),
		err:        make([]error, len(groups)),
		codes:      make([][]int32, len(groups)),
		kids:       make([][]int32, len(groups)),
		reason:     map[int]error{},
	}
	for i, g := range groups {
		gx.index[g.Name] = i
	}
	return gx
}

// Group walk states: white (not entered), grey (on the current path),
// black (memo entry final).
const (
	walkNew = iota
	walkVisiting
	walkDone
)

// walkFrame is one group on the path of the iterative walk.
type walkFrame struct {
	gi     int
	next   int
	height int
}

// expand returns the memoized error of group gi (nil when it expands),
// walking gi and every group below it that has no entry yet. The caller
// holds the RuleResolver mutex.
//
// The walk is depth-first with an explicit stack (the group graph may be a
// chain of thousands of groups); it enters every group at most once and
// iterates every group member at most once, so over all calls its work is
// O(groups + group members), each member charged to MaxResolveLeafOps
// before it is iterated. A group fails with the first defect in member
// order: ErrGroupUnresolvable (empty), ErrDynamicGroup, ErrGroupIncomplete
// (truncated, or an unknown member while the objects are incomplete),
// ErrUnresolvedMember, ErrGroupCycle (a member on the current path),
// ErrGroupDepth (height over MaxGroupResolveDepth) or the failure of a
// member group. Every group on the path reaches the defect, so marking the
// whole path failed is exact for whether a group fails; which reason
// ResolveGroup reports depends on where it starts and is computed by
// rootReason. Heights do not depend on where the walk started.
//
// When the budget is exhausted the walk stops, the groups on its path are
// reset to unwalked and ErrResolveBudget is returned; groups finished
// before stay memoized.
func (gx *groupIndex) expand(gi int, rr *RuleResolver) error {
	if gx.state[gi] == walkDone {
		return gx.err[gi]
	}
	var stack []walkFrame

	finish := func(g int, err error) {
		gx.err[g], gx.state[g] = err, walkDone
		if err != nil {
			gx.codes[g], gx.kids[g] = nil, nil
		}
	}
	// enter starts the walk of g; it returns the error g fails with on its
	// own (memoized) or ErrResolveBudget (not memoized, g not pushed).
	enter := func(g int) error {
		rr.groupChecks++
		grp := gx.groups[g]
		var err error
		switch {
		case emptyGroup(grp):
			err = ErrGroupUnresolvable
		case grp.DynamicFilter != "":
			err = ErrDynamicGroup
		case gx.truncated[grp.Name]:
			err = ErrGroupIncomplete
		}
		if err != nil {
			finish(g, err)
			return err
		}
		if !rr.chargeOps(len(grp.Static)) {
			return ErrResolveBudget
		}
		gx.state[g] = walkVisiting
		gx.codes[g] = make([]int32, 0, len(grp.Static))
		stack = append(stack, walkFrame{gi: g, height: 1})
		return nil
	}
	// fail ends every group on the path with err.
	fail := func(err error) {
		for _, f := range stack {
			finish(f.gi, err)
		}
		stack = stack[:0]
	}

	if err := enter(gi); err != nil {
		return err
	}
	for len(stack) > 0 {
		f := &stack[len(stack)-1]
		members := gx.groups[f.gi].Static
		if f.next == len(members) {
			// the group expands; its parent grows by its height
			h := f.height
			gx.height[f.gi] = h
			finish(f.gi, nil)
			stack = stack[:len(stack)-1]
			if len(stack) > 0 {
				p := &stack[len(stack)-1]
				if p.height = max(p.height, h+1); p.height > MaxGroupResolveDepth {
					fail(ErrGroupDepth)
				}
			}
			continue
		}
		g := f.gi
		m := members[f.next]
		f.next++
		rr.memberIters++
		if li, ok := gx.leaves[m]; ok {
			gx.codes[g] = append(gx.codes[g], int32(li))
			continue
		}
		sub, ok := gx.index[m]
		if !ok {
			if gx.incomplete {
				// the member may be one of the entries cut at a limit
				fail(ErrGroupIncomplete)
			} else {
				fail(ErrUnresolvedMember)
			}
			continue
		}
		switch gx.state[sub] {
		case walkVisiting:
			fail(ErrGroupCycle)
			continue
		case walkDone:
			if err := gx.err[sub]; err != nil {
				fail(err)
				continue
			}
			if f.height = max(f.height, gx.height[sub]+1); f.height > MaxGroupResolveDepth {
				fail(ErrGroupDepth)
				continue
			}
		}
		// the edge is recorded before sub is walked; if sub fails, so
		// does g and its codes are dropped
		gx.codes[g] = append(gx.codes[g], ^int32(sub))
		gx.kids[g] = append(gx.kids[g], int32(sub))
		if gx.state[sub] == walkNew {
			if err := enter(sub); errors.Is(err, ErrResolveBudget) {
				for _, fr := range stack {
					gx.state[fr.gi], gx.codes[fr.gi], gx.kids[fr.gi] = walkNew, nil, nil
				}
				return ErrResolveBudget
			} else if err != nil {
				fail(err)
			}
		}
	}
	return gx.err[gi]
}

// rootReason returns the error ResolveGroup returns for group gi, which
// the walk found failing. The result is memoized, except ErrResolveBudget.
// The caller holds the RuleResolver mutex.
func (gx *groupIndex) rootReason(gi int, rr *RuleResolver) error {
	if err, ok := gx.reason[gi]; ok {
		return err
	}
	rr.reasonPasses++
	p := reasonPass{gx: gx, rr: rr, height: map[int]int{}}
	_, err := p.visit(gi, 1)
	if errors.Is(err, ErrResolveBudget) {
		return err
	}
	if err == nil {
		// unreachable: the walk and ResolveGroup agree on failure
		err = gx.err[gi]
	}
	gx.reason[gi] = err
	return err
}

// reasonPass replays ResolveGroup from one root: levels count from the
// root, height memoizes the groups finished in this pass (heightVisiting
// while on the path). The only shortcut is a group the memo walk found
// expanding whose subtree fits below the current level: ResolveGroup
// cannot fail inside it and would finish every group of it, so the pass
// marks them finished through the kids lists without iterating members.
type reasonPass struct {
	gx     *groupIndex
	rr     *RuleResolver
	height map[int]int
}

// visit mirrors resolver.visit in objects.go check by check; every member
// iteration and followed edge is charged to MaxResolveLeafOps first.
func (p *reasonPass) visit(g, level int) (int, error) {
	if level > MaxGroupResolveDepth {
		return 0, ErrGroupDepth
	}
	switch h, ok := p.height[g]; {
	case ok && h == heightVisiting:
		return 0, ErrGroupCycle
	case ok:
		return h, nil
	}
	gx := p.gx
	if gx.state[g] == walkDone && gx.err[g] == nil && level+gx.height[g]-1 <= MaxGroupResolveDepth {
		if !p.finishSubtree(g) {
			return 0, ErrResolveBudget
		}
		return gx.height[g], nil
	}
	grp := gx.groups[g]
	if emptyGroup(grp) {
		return 0, ErrGroupUnresolvable
	}
	if grp.DynamicFilter != "" {
		return 0, ErrDynamicGroup
	}
	if gx.truncated[grp.Name] {
		return 0, ErrGroupIncomplete
	}
	if !p.rr.chargeOps(len(grp.Static)) {
		return 0, ErrResolveBudget
	}
	p.height[g] = heightVisiting
	h := 1
	for _, m := range grp.Static {
		if _, ok := gx.leaves[m]; ok {
			continue
		}
		sub, ok := gx.index[m]
		if !ok {
			if gx.incomplete {
				return 0, ErrGroupIncomplete
			}
			return 0, ErrUnresolvedMember
		}
		sh, err := p.visit(sub, level+1)
		if err != nil {
			return 0, err
		}
		h = max(h, sh+1)
		if h > MaxGroupResolveDepth {
			return 0, ErrGroupDepth
		}
	}
	p.height[g] = h
	return h, nil
}

// finishSubtree marks the expanding group g and every group below it
// finished with their memoized heights. A group finished already has its
// whole subtree finished; an expanding group reaches no group on the
// current path (that would be a cycle through it).
func (p *reasonPass) finishSubtree(g int) bool {
	gx := p.gx
	stack := []int{g}
	p.height[g] = gx.height[g]
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !p.rr.chargeOps(len(gx.kids[k])) {
			return false
		}
		for _, c := range gx.kids[k] {
			if _, done := p.height[int(c)]; !done {
				p.height[int(c)] = gx.height[c]
				stack = append(stack, int(c))
			}
		}
	}
	return true
}

// lookup returns nil when group gi of gx expands, its ResolveGroup error
// when it fails, or ErrResolveBudget.
func (rr *RuleResolver) lookup(gx *groupIndex, gi int) error {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	err := gx.expand(gi, rr)
	if err == nil || errors.Is(err, ErrResolveBudget) {
		return err
	}
	return gx.rootReason(gi, rr)
}

// leafUnion collects the leaves of one rule field in first-seen order
// without duplicates; groups holds the groups entered by the field merge.
// failed is set when a group merge stopped on a budget; every later group
// merge of the field then fails, since a group entered before the stop may
// be merged only in part.
type leafUnion struct {
	rr     *RuleResolver
	gx     *groupIndex
	seen   map[int]struct{}
	groups map[int]struct{}
	add    func(int)
	failed bool
}

func newLeafUnion(rr *RuleResolver, gx *groupIndex, add func(int)) *leafUnion {
	return &leafUnion{rr: rr, gx: gx, seen: map[int]struct{}{}, groups: map[int]struct{}{}, add: add}
}

// leaf adds one leaf; a new one is charged to MaxResolveResultLeaves. It
// reports false when the budget is exhausted.
func (u *leafUnion) leaf(li int) bool {
	if _, dup := u.seen[li]; dup {
		return true
	}
	if !u.rr.chargeResult() {
		return false
	}
	u.seen[li] = struct{}{}
	u.add(li)
	return true
}

// done reports whether group gi was merged into the field already.
func (u *leafUnion) done(gi int) bool {
	_, ok := u.groups[gi]
	return ok
}

// group merges expanding group gi: a depth-first walk of the memoized
// Static lists in member order (the first-seen order of ResolveGroup) that
// enters every group at most once per field. A group merged already
// contributed all its leaves, so skipping it keeps the order. Each group's
// list is charged to MaxResolveLeafOps before it is iterated; group
// reports false when a budget is exhausted, and the field then holds part
// of the group's leaves.
func (u *leafUnion) group(gi int) bool {
	type pos struct{ g, next int }
	var stack []pos
	enter := func(g int) bool {
		if !u.rr.chargeOps(len(u.gx.codes[g])) {
			return false
		}
		u.groups[g] = struct{}{}
		stack = append(stack, pos{g: g})
		return true
	}
	if u.failed {
		// a group entered before the stop may be merged only in part
		return false
	}
	if u.done(gi) {
		return true
	}
	if !enter(gi) {
		u.failed = true
		return false
	}
	for len(stack) > 0 {
		top := &stack[len(stack)-1]
		cs := u.gx.codes[top.g]
		if top.next == len(cs) {
			stack = stack[:len(stack)-1]
			continue
		}
		c := cs[top.next]
		top.next++
		if c >= 0 {
			if !u.leaf(int(c)) {
				u.failed = true
				return false
			}
			continue
		}
		if sub := int(^c); !u.done(sub) && !enter(sub) {
			u.failed = true
			return false
		}
	}
	return true
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

	// fail reports member m of field as not expanded with err; a budget
	// error makes the result incomplete
	fail := func(field RuleField, m, what string, err error) {
		if errors.Is(err, ErrResolveBudget) {
			res.Incomplete = true
		}
		res.Unresolved = append(res.Unresolved, UnresolvedMember{Field: field, Name: m,
			Reason: fmt.Errorf("%s: %w", what, err)})
	}
	// member resolves a direct object or group member into u; it reports
	// false when m names neither
	member := func(gx *groupIndex, u *leafUnion, field RuleField, m, kind string) bool {
		if i, ok := gx.leaves[m]; ok {
			if !rr.chargeOps(1) || !u.leaf(i) {
				fail(field, m, "resolve "+kind, ErrResolveBudget)
			}
			return true
		}
		gi, ok := gx.index[m]
		if !ok {
			return false
		}
		rr.groupVisits.Add(1)
		err := rr.lookup(gx, gi)
		if err == nil && !u.group(gi) {
			err = ErrResolveBudget
		}
		if err != nil {
			fail(field, m, "resolve "+kind+" group", err)
		}
		return true
	}

	resolveAddrs := func(field RuleField, members []string, out *ResolvedAddresses) {
		u := newLeafUnion(rr, &rr.addrs, func(i int) { out.Objects = append(out.Objects, objects.Addresses[i]) })
		for _, m := range members {
			if m == "any" {
				out.Any = true
				continue
			}
			if member(&rr.addrs, u, field, m, "address") {
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

	u := newLeafUnion(rr, &rr.svcs, func(i int) { res.Service.Objects = append(res.Service.Objects, objects.Services[i]) })
	for _, m := range rule.Service {
		switch m {
		case "any":
			res.Service.Any = true
			continue
		case "application-default":
			res.Service.ApplicationDefault = true
			continue
		}
		if member(&rr.svcs, u, FieldService, m, "service") {
			continue
		}
		unknown(FieldService, m)
	}
	return res
}
