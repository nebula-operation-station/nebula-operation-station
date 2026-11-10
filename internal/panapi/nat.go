// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// SourceTranslationType is the kind of source translation of a NAT rule.
type SourceTranslationType string

// Source translation types. SourceNone means the rule has no
// source-translation element. SourceUnknown means it has one whose content
// is outside the allowlist (a type NOS does not read): the translation is
// then unknown, never "none", and the rule set is marked incomplete.
const (
	SourceNone             SourceTranslationType = ""
	SourceDynamicIPAndPort SourceTranslationType = "dynamic-ip-and-port"
	SourceDynamicIP        SourceTranslationType = "dynamic-ip"
	SourceStaticIP         SourceTranslationType = "static-ip"
	SourceUnknown          SourceTranslationType = "unknown"
)

// SourceTranslation is the source translation of a NAT rule.
// TranslatedAddresses holds address members (names or IP, prefix or range
// literals) in device order; dynamic-ip-and-port uses either them or
// Interface with an optional InterfaceIP; static-ip has exactly one
// translated address and may be BiDirectional.
type SourceTranslation struct {
	Type                SourceTranslationType
	TranslatedAddresses []string
	Interface           string
	InterfaceIP         string
	BiDirectional       bool
}

// DestinationTranslation is the destination translation of a NAT rule.
// Enabled is false when the rule has none. Dynamic marks a
// dynamic-destination-translation (FQDN or group based). TranslatedAddress
// is an address member; TranslatedPort is a single port or empty.
type DestinationTranslation struct {
	Enabled           bool
	Dynamic           bool
	TranslatedAddress string
	TranslatedPort    string
}

// NATRule is one PAN-OS NAT rule of the supported vsys. Index is the
// position in the NAT rulebase (document order, from 0); disabled rules
// are kept in place with Disabled set. Members are validated as in Rule;
// unknown object names are kept as configured.
type NATRule struct {
	Index                  int
	Name                   string
	UUID                   string
	From                   []string
	To                     []string
	Source                 []string
	Destination            []string
	Service                string
	SourceTranslation      SourceTranslation
	DestinationTranslation DestinationTranslation
	Disabled               bool
	Description            string
	Tags                   []string
}

// NATRuleSet is the parsed NAT rulebase of the supported vsys in rule
// order. Incomplete has the meaning of RuleSet.Incomplete and is also set
// when a source translation of unknown type was seen.
type NATRuleSet struct {
	Rules      []NATRule
	Incomplete bool
}

// xmlNATRule is one <entry> of rulebase/nat/rules: the element allowlist
// of ADR 0010 D4 for NAT rules. Every other element (nat-type,
// to-interface, active-active binding, ...) is dropped with its subtree.
type xmlNATRule struct {
	Name                          string                 `xml:"name,attr"`
	UUID                          string                 `xml:"uuid,attr"`
	From                          []xmlMembers           `xml:"from"`
	To                            []xmlMembers           `xml:"to"`
	Source                        []xmlMembers           `xml:"source"`
	Destination                   []xmlMembers           `xml:"destination"`
	Service                       []string               `xml:"service"`
	SourceTranslation             []xmlSourceTranslation `xml:"source-translation"`
	DestinationTranslation        []xmlDestTranslation   `xml:"destination-translation"`
	DynamicDestinationTranslation []xmlDestTranslation   `xml:"dynamic-destination-translation"`
	Disabled                      []string               `xml:"disabled"`
	Description                   []string               `xml:"description"`
	Tag                           []xmlMembers           `xml:"tag"`
}

// xmlSourceTranslation holds the allowlisted source translation types.
type xmlSourceTranslation struct {
	DynamicIPAndPort []struct {
		TranslatedAddress []xmlMembers `xml:"translated-address"`
		InterfaceAddress  []struct {
			Interface []string `xml:"interface"`
			IP        []string `xml:"ip"`
		} `xml:"interface-address"`
	} `xml:"dynamic-ip-and-port"`
	DynamicIP []struct {
		TranslatedAddress []xmlMembers `xml:"translated-address"`
	} `xml:"dynamic-ip"`
	StaticIP []struct {
		TranslatedAddress []string `xml:"translated-address"`
		BiDirectional     []string `xml:"bi-directional"`
	} `xml:"static-ip"`
}

// xmlDestTranslation is a static or dynamic destination translation.
type xmlDestTranslation struct {
	TranslatedAddress []string `xml:"translated-address"`
	TranslatedPort    []string `xml:"translated-port"`
}

// ParseNATRules parses the NAT rulebase of a configuration response: a
// read of rulebase/nat/rules of vsys1 (SubtreeNATRules) or of the whole
// vsys. It performs no I/O and applies the same decoding, limits and
// validation rules as ParseSecurityRules. Errors never contain device
// text.
func ParseNATRules(data []byte) (NATRuleSet, error) {
	entries, incomplete, err := decodeRules[xmlNATRule](data, "nat")
	if err != nil {
		return NATRuleSet{}, fmt.Errorf("parse nat rules: %w", err)
	}
	set := NATRuleSet{Incomplete: incomplete}
	if netdevcontract.CheckCount("nat rules", len(entries), MaxNATRules) != nil {
		entries, set.Incomplete = entries[:MaxNATRules], true
	}
	names := make(map[string]struct{}, len(entries))
	set.Rules = make([]NATRule, 0, len(entries))
	for i, e := range entries {
		r, partial, err := parseNATRule(e)
		if err != nil {
			return NATRuleSet{}, fmt.Errorf("parse nat rules: rule %d: %w", i, err)
		}
		if _, dup := names[r.Name]; dup {
			return NATRuleSet{}, fmt.Errorf("parse nat rules: rule %d: %w: name duplicated", i, ErrInvalidConfig)
		}
		names[r.Name] = struct{}{}
		r.Index = i
		set.Incomplete = set.Incomplete || partial
		set.Rules = append(set.Rules, r)
	}
	return set, nil
}

// parseNATRule validates one NAT rule entry. partial reports a list cut at
// its limit or a source translation of unknown type.
func parseNATRule(e xmlNATRule) (NATRule, bool, error) {
	if ValidateName(e.Name) != nil {
		return NATRule{}, false, fmt.Errorf("%w: invalid name", ErrInvalidConfig)
	}
	r := NATRule{Name: e.Name}
	var err error
	if r.UUID, err = ruleUUID(e.UUID); err != nil {
		return NATRule{}, false, err
	}
	var partial bool
	for _, f := range []struct {
		dst  *[]string
		src  []xmlMembers
		kind memberKind
		what string
	}{
		{&r.From, e.From, memberName, "from"},
		{&r.To, e.To, memberName, "to"},
		{&r.Source, e.Source, memberAddress, "source"},
		{&r.Destination, e.Destination, memberAddress, "destination"},
	} {
		ms, cut, err := ruleMembers(f.src, f.kind, f.what)
		if err != nil {
			return NATRule{}, false, err
		}
		if len(ms) == 0 {
			return NATRule{}, false, fmt.Errorf("%w: %s has no members", ErrInvalidConfig, f.what)
		}
		*f.dst, partial = ms, partial || cut
	}
	svc, err := atMostOne(e.Service, "service")
	if err != nil {
		return NATRule{}, false, err
	}
	if ValidateName(svc) != nil {
		return NATRule{}, false, fmt.Errorf("%w: service is missing or invalid", ErrInvalidConfig)
	}
	r.Service = svc

	st, cut, err := sourceTranslation(e.SourceTranslation)
	if err != nil {
		return NATRule{}, false, err
	}
	r.SourceTranslation = st
	partial = partial || cut || st.Type == SourceUnknown

	if r.DestinationTranslation, err = destinationTranslation(e.DestinationTranslation, e.DynamicDestinationTranslation); err != nil {
		return NATRule{}, false, err
	}
	if r.Disabled, err = yesNo(e.Disabled, "disabled", false); err != nil {
		return NATRule{}, false, err
	}
	if r.Description, err = description(e.Description); err != nil {
		return NATRule{}, false, err
	}
	tags, cut, err := nameList(e.Tag, netdevcontract.MaxTagsPerObject, "tag")
	if err != nil {
		return NATRule{}, false, err
	}
	r.Tags = tags
	return r, partial || cut, nil
}

// singleAddress validates the single-valued address member of a
// translation; it is required.
func singleAddress(vs []string, what string) (string, error) {
	v, err := atMostOne(vs, what)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("%w: %s missing", ErrInvalidConfig, what)
	}
	a, ok := memberValue(memberAddress, v)
	if !ok {
		return "", fmt.Errorf("%w: %s invalid", ErrInvalidConfig, what)
	}
	return a, nil
}

// sourceTranslation validates the optional source-translation element.
// truncated reports a translated address list cut at MaxRuleMembers.
func sourceTranslation(xs []xmlSourceTranslation) (st SourceTranslation, truncated bool, err error) {
	switch len(xs) {
	case 0:
		return SourceTranslation{}, false, nil
	case 1:
	default:
		return SourceTranslation{}, false, errRepeated("source-translation")
	}
	x := xs[0]
	kinds := 0
	for _, n := range []int{len(x.DynamicIPAndPort), len(x.DynamicIP), len(x.StaticIP)} {
		if n > 1 {
			return SourceTranslation{}, false, fmt.Errorf("%w: source translation type repeated", ErrInvalidConfig)
		}
		kinds += n
	}
	switch {
	case kinds == 0:
		return SourceTranslation{Type: SourceUnknown}, false, nil
	case kinds > 1:
		return SourceTranslation{}, false, fmt.Errorf("%w: more than one source translation type", ErrInvalidConfig)
	}

	translated := func(ms []xmlMembers) ([]string, bool, error) {
		addrs, cut, err := ruleMembers(ms, memberAddress, "translated-address")
		if err == nil && len(addrs) == 0 {
			err = fmt.Errorf("%w: translated-address missing", ErrInvalidConfig)
		}
		return addrs, cut, err
	}
	switch {
	case len(x.DynamicIPAndPort) == 1:
		p := x.DynamicIPAndPort[0]
		st.Type = SourceDynamicIPAndPort
		switch {
		case len(p.TranslatedAddress) > 0 && len(p.InterfaceAddress) > 0:
			return SourceTranslation{}, false, fmt.Errorf("%w: translated-address and interface-address are exclusive", ErrInvalidConfig)
		case len(p.InterfaceAddress) > 1:
			return SourceTranslation{}, false, errRepeated("interface-address")
		case len(p.InterfaceAddress) == 1:
			ia := p.InterfaceAddress[0]
			itf, err := atMostOne(ia.Interface, "interface")
			if err != nil {
				return SourceTranslation{}, false, err
			}
			if !netdevcontract.ValidInterfaceName(itf) {
				return SourceTranslation{}, false, fmt.Errorf("%w: interface missing or invalid", ErrInvalidConfig)
			}
			st.Interface = itf
			if len(ia.IP) > 0 {
				if st.InterfaceIP, err = singleAddress(ia.IP, "ip"); err != nil {
					return SourceTranslation{}, false, err
				}
			}
		default:
			if st.TranslatedAddresses, truncated, err = translated(p.TranslatedAddress); err != nil {
				return SourceTranslation{}, false, err
			}
		}
	case len(x.DynamicIP) == 1:
		st.Type = SourceDynamicIP
		if st.TranslatedAddresses, truncated, err = translated(x.DynamicIP[0].TranslatedAddress); err != nil {
			return SourceTranslation{}, false, err
		}
	default:
		s := x.StaticIP[0]
		st.Type = SourceStaticIP
		a, err := singleAddress(s.TranslatedAddress, "translated-address")
		if err != nil {
			return SourceTranslation{}, false, err
		}
		st.TranslatedAddresses = []string{a}
		if st.BiDirectional, err = yesNo(s.BiDirectional, "bi-directional", false); err != nil {
			return SourceTranslation{}, false, err
		}
	}
	return st, truncated, nil
}

// destinationTranslation validates the optional static or dynamic
// destination translation; a rule has at most one of them.
func destinationTranslation(static, dynamic []xmlDestTranslation) (DestinationTranslation, error) {
	if len(static) > 1 || len(dynamic) > 1 {
		return DestinationTranslation{}, errRepeated("destination-translation")
	}
	if len(static)+len(dynamic) == 0 {
		return DestinationTranslation{}, nil
	}
	if len(static) == 1 && len(dynamic) == 1 {
		return DestinationTranslation{}, fmt.Errorf("%w: static and dynamic destination translation are exclusive", ErrInvalidConfig)
	}
	dt := DestinationTranslation{Enabled: true}
	x := static
	if len(dynamic) == 1 {
		dt.Dynamic, x = true, dynamic
	}
	var err error
	if dt.TranslatedAddress, err = singleAddress(x[0].TranslatedAddress, "translated-address"); err != nil {
		return DestinationTranslation{}, err
	}
	port, err := atMostOne(x[0].TranslatedPort, "translated-port")
	if err != nil {
		return DestinationTranslation{}, err
	}
	if port != "" {
		if _, ok := portNumber(port); !ok {
			return DestinationTranslation{}, fmt.Errorf("%w: translated-port is malformed", ErrInvalidConfig)
		}
	}
	dt.TranslatedPort = port
	return dt, nil
}
