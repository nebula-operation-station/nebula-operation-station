// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netreach is the reachability model nr-v1 of ADR 0012 D2: the
// snapshot types, placement of addresses in segments and zones, the
// fail-safe classification of unevaluable rules and the work limits. It is
// a pure library: no I/O, no clock, no global state.
//
// Every value in a Snapshot comes from a managed device or a server store
// and is untrusted. Every field that a dataset may lack carries an explicit
// "collected" marker (Field), and the zero value of every type is the
// fail-safe one: a field that was not collected is never read as "absent",
// "false" or "any", an input without a state is missing, and a default-rule
// step without data is not collected. Whatever cannot be evaluated leads to
// the verdict unknown with a reason, never to denied or allowed.
//
// Rule evaluation, NAT and the explanation chain follow in a later part
// (NS-05 part 2); this part holds only types, placement and limits.
package netreach

import (
	"net/netip"
)

// ModelVersion is the evaluation semantics version stored with every
// verdict (ADR 0012 D2). Any change to evaluation semantics creates a new
// version.
const ModelVersion = "nr-v1"

// Verdict is the result of one reachability query (ADR 0012 D2).
type Verdict string

// Verdicts. The zero value is not a verdict; code that has none returns
// VerdictUnknown.
const (
	VerdictAllowed     Verdict = "allowed"
	VerdictConditional Verdict = "conditional"
	VerdictDenied      Verdict = "denied"
	VerdictNotFiltered Verdict = "not_filtered"
	VerdictUnknown     Verdict = "unknown"
)

// Field is a value from a dataset together with the marker whether the
// dataset carried it. A field that was not collected (the zero value) must
// never be read as its zero Value: the ND-07 allowlist may simply not pass
// it (ADR 0012 Q11).
type Field[T any] struct {
	Collected bool
	Value     T
}

// Collected returns a Field holding v that was collected.
func Collected[T any](v T) Field[T] { return Field[T]{Collected: true, Value: v} }

// InputKind names one input dataset of a snapshot (ADR 0012 D2 "Inputs").
type InputKind string

// Inputs of a snapshot. Every one is required for a complete snapshot.
const (
	InputZones         InputKind = "zones"
	InputInterfaces    InputKind = "interfaces"
	InputSecurityRules InputKind = "security_rules"
	InputNATRules      InputKind = "nat_rules"
	InputObjects       InputKind = "objects"
	InputDefaultRules  InputKind = "default_rules"
	InputRoutes        InputKind = "routes"
	InputIPAM          InputKind = "ipam"
)

// RequiredInputs lists every input a complete snapshot needs, in a fixed
// order (determinism of reasons).
var RequiredInputs = []InputKind{
	InputZones, InputInterfaces, InputSecurityRules, InputNATRules,
	InputObjects, InputDefaultRules, InputRoutes, InputIPAM,
}

// InputState is the freshness of one input dataset as the server store
// reports it. The zero value is InputMissing.
type InputState int

// Input states. Stale means three missed intervals (ADR 0010); Incomplete
// means the dataset was cut at a limit (ADR 0010 D3).
const (
	InputMissing InputState = iota
	InputFresh
	InputStale
	InputIncomplete
)

// String returns the state name used in reasons.
func (s InputState) String() string {
	switch s {
	case InputFresh:
		return "fresh"
	case InputStale:
		return "stale"
	case InputIncomplete:
		return "incomplete"
	default:
		return "missing"
	}
}

// Input is the state of one dataset and the identifiers that enter the
// snapshot hash (dataset ID and redacted digest, never the raw digest).
type Input struct {
	State          InputState
	DatasetID      string
	RedactedDigest string
}

// Zone is one firewall zone.
type Zone struct {
	Name string
}

// Interface is one firewall interface or subinterface. Prefixes are the
// connected networks of its addresses (an address "10.0.1.1/24" gives
// 10.0.1.0/24). VLAN is the subinterface tag if the dataset carried it.
type Interface struct {
	Name     string
	Zone     string
	VLAN     Field[uint16]
	Prefixes []netip.Prefix
}

// Subnet is one IPAM network, an L2 segment of the lab. VLAN is set only
// when IPAM records it.
type Subnet struct {
	ID     string
	Prefix netip.Prefix
	VLAN   Field[uint16]
}

// Route is one route of the firewall: traffic to Prefix leaves through the
// interface Interface into Zone. A route with a zero-length prefix is a
// default route.
type Route struct {
	Prefix    netip.Prefix
	Interface string
	Zone      string
}

// AddressType is the kind of an address object.
type AddressType string

// Address object types. Only netmask and range are evaluable in nr-v1;
// wildcard, FQDN, EDL, region and unknown types are not (ADR 0012 D2).
const (
	AddressNetmask  AddressType = "ip-netmask"
	AddressRange    AddressType = "ip-range"
	AddressWildcard AddressType = "ip-wildcard"
	AddressFQDN     AddressType = "fqdn"
	AddressEDL      AddressType = "edl"
	AddressRegion   AddressType = "region"
)

// AddressObject is one address object. Value is the device text of the
// object value ("10.0.0.0/24", "10.0.0.1-10.0.0.9", a name, ...). Dropped
// holds the <dropped:…> markers the redaction left on the object.
type AddressObject struct {
	Name    string
	Type    AddressType
	Value   string
	Dropped []string
}

// Group is one address or service group. Static members are names (of
// objects or groups) or, for address groups, literals. A group with a
// dynamic filter cannot be evaluated: its members are unknown.
type Group struct {
	Name    string
	Static  []string
	Dynamic bool
	Dropped []string
}

// ServiceObject is one service object. Ports is the device text of the
// destination ports ("80", "80,443", "8000-8080"). SourcePorts is the
// source-port condition; it is evaluable only when collected and empty,
// because a query has no source port.
type ServiceObject struct {
	Name        string
	Protocol    string
	Ports       string
	SourcePorts Field[string]
	Dropped     []string
}

// Action is the action of a security rule.
type Action string

// Rule actions. Any other value, the empty one included, is unevaluable.
const (
	ActionAllow       Action = "allow"
	ActionDeny        Action = "deny"
	ActionDrop        Action = "drop"
	ActionResetClient Action = "reset-client"
	ActionResetServer Action = "reset-server"
	ActionResetBoth   Action = "reset-both"
)

// RuleType is the PAN-OS security rule type.
type RuleType string

// Rule types. nr-v1 evaluates universal rules only; intrazone and
// interzone rules are unevaluable (ADR 0012 D2, Required tests item 1).
const (
	RuleTypeUniversal RuleType = "universal"
	RuleTypeIntrazone RuleType = "intrazone"
	RuleTypeInterzone RuleType = "interzone"
)

// SecurityRule is one security rule in rule order. Every match field is a
// Field: a field that was not collected makes the rule unevaluable. The
// Q11 fields (NegateSource, NegateDestination, Type, SourceHIP,
// DestinationHIP) are not passed by the ND-07 allowlist today, so a rule
// from such a dataset is unevaluable until NS-04 (ADR 0012 D2 fail-safe).
//
// Schedule is a condition (the rule then matches only at certain times),
// not an unevaluable field; a schedule that was not collected is reported
// as a condition by Conditions. Dropped holds the <dropped:…> markers the
// redaction left on the rule; OutsideAllowlist names fields the device
// carried that the allowlist did not pass.
type SecurityRule struct {
	Name              string
	UUID              string
	Disabled          Field[bool]
	Action            Action
	From              Field[[]string]
	To                Field[[]string]
	Source            Field[[]string]
	Destination       Field[[]string]
	NegateSource      Field[bool]
	NegateDestination Field[bool]
	Type              Field[RuleType]
	SourceHIP         Field[[]string]
	DestinationHIP    Field[[]string]
	SourceUser        Field[[]string]
	Application       Field[[]string]
	Service           Field[[]string]
	Category          Field[[]string]
	Schedule          Field[string]
	Dropped           []string
	OutsideAllowlist  []string
}

// DestinationTranslation is the destination translation of a NAT rule.
// Address is an address member (name or literal). Port is the translated
// port, 0 when the port is not translated. Dynamic marks a
// dynamic-destination-translation, which nr-v1 cannot evaluate.
type DestinationTranslation struct {
	Address string
	Port    uint16
	Dynamic bool
}

// NATRule is one NAT rule in NAT rule order. To is the single destination
// zone of the pre-NAT packet. DestinationTranslation is nil when the rule
// has none; when the field was not collected the rule is unevaluable,
// because it may forward to any host. Source translation does not change
// where a packet goes and is not modelled.
type NATRule struct {
	Name                   string
	UUID                   string
	Disabled               Field[bool]
	From                   Field[[]string]
	To                     Field[string]
	Source                 Field[[]string]
	Destination            Field[[]string]
	Service                Field[string]
	DestinationTranslation Field[*DestinationTranslation]
	Dropped                []string
	OutsideAllowlist       []string
}

// DefaultRules are the collected default security rules
// (rulebase/default-security-rules, ADR 0012 Q11). Without them
// (Collected false in Snapshot.DefaultRules) the default-rule step is
// unevaluable. Dropped holds the <dropped:…> markers the redaction left;
// OutsideAllowlist names fields the device carried that the allowlist did
// not pass. Either makes both default rules unevaluable.
type DefaultRules struct {
	Intrazone        Action
	Interzone        Action
	Dropped          []string
	OutsideAllowlist []string
}

// Snapshot is the complete input of one model computation (ADR 0012 D2).
// Inputs holds the state of every dataset; an input absent from the map is
// missing. Vsys is the number of virtual systems the device reports; only
// exactly one is evaluable (zero means not reported).
type Snapshot struct {
	Inputs        map[InputKind]Input
	Vsys          int
	Zones         []Zone
	Interfaces    []Interface
	Subnets       []Subnet
	Routes        []Route
	Addresses     []AddressObject
	AddressGroups []Group
	Services      []ServiceObject
	ServiceGroups []Group
	SecurityRules []SecurityRule
	NATRules      []NATRule
	DefaultRules  Field[DefaultRules]
}
