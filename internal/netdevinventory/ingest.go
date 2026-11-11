// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

// Ingest mapping (ADR 0010 D4, plan ND-16 part 2): the collector spools
// one typed executor read per file, its payload the protojson encoding of
// the read's executorv1 message. DecodePayload strictly decodes such a
// payload and maps it onto the typed rows the store writes. Nothing here
// trusts the payload: unknown fields, unspecified enum values and integers
// outside their target type are refused, and the store validates the rows
// against netdevcontract again before it writes them.
//
// The ten reads map onto the seven stored reads. CBS reads map one to one.
// The PAN-OS zones, objects, security rule and NAT rule reads are four
// separately polled parts of one firewall_policy dataset; each is stored
// as a PolicyPartRows, which replaces only the rows of its own part: rows
// of the other parts are carried over unchanged and never marked absent
// by a part that did not read them. Ordering and completeness are tracked
// per part (policyparts.go).

import (
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// MaxIngestPayloadBytes bounds one read payload DecodePayload accepts: the
// largest ADR 0010 D3 transport cap of a read (the spool enforces the
// per-read cap before this).
const MaxIngestPayloadBytes = max(netdevcontract.MaxCBSCommandOutputBytes, netdevcontract.MaxPANOSResponseBytes)

// ErrInvalidPayload means a read payload does not decode into its typed
// message or does not map onto typed rows. Its messages never quote the
// payload.
var ErrInvalidPayload = errors.New("netdevinventory: invalid read payload")

// PolicyPart names the PAN-OS read that delivers one part of the firewall
// policy dataset.
type PolicyPart string

// Firewall policy parts.
const (
	PolicyZones         PolicyPart = "zones"
	PolicyObjects       PolicyPart = "objects"
	PolicySecurityRules PolicyPart = "security_rules"
	PolicyNATRules      PolicyPart = "nat_rules"
)

// PolicyPartRows is one part of a PAN-OS firewall policy read. Only the
// fields of Part may be set. Stored, it replaces the rows of its part and
// carries the rows of the other parts over unchanged.
type PolicyPartRows struct {
	Part   PolicyPart
	Policy netdevcontract.FirewallPolicy
}

// Read implements Rows.
func (PolicyPartRows) Read() Read { return ReadFirewallPolicy }

func (r PolicyPartRows) payload() any {
	return struct {
		Part   PolicyPart                    `json:"part"`
		Policy netdevcontract.FirewallPolicy `json:"policy"`
	}{r.Part, r.Policy}
}

func (r PolicyPartRows) tableRows() ([]rowSet, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return PolicyRows{Policy: r.Policy}.tableRows()
}

// check refuses an unknown part and fields of another part.
func (r PolicyPartRows) check() error {
	p := r.Policy
	objects := len(p.Addresses) + len(p.AddressGroups) + len(p.Services) + len(p.ServiceGroups)
	var other int
	switch r.Part {
	case PolicyZones:
		other = len(p.SecurityRules) + len(p.NATRules) + objects + len(p.Interfaces)
	case PolicyObjects:
		other = len(p.SecurityRules) + len(p.NATRules) + len(p.Zones) + len(p.Interfaces)
	case PolicySecurityRules:
		other = len(p.NATRules) + objects + len(p.Zones) + len(p.Interfaces)
	case PolicyNATRules:
		other = len(p.SecurityRules) + objects + len(p.Zones) + len(p.Interfaces)
	default:
		return fmt.Errorf("%w: unknown policy part", ErrRowsMismatch)
	}
	if other != 0 {
		return fmt.Errorf("%w: policy part %s carries rows of another part", ErrRowsMismatch, r.Part)
	}
	return nil
}

// carryScope returns the SQL predicate over t's columns that selects the
// carried rows a complete read of rows covers: those become absent, the
// others keep their absent flag. The predicates are constants.
func carryScope(rows Rows, t *table) string {
	r, ok := rows.(PolicyPartRows)
	if !ok {
		return "1"
	}
	switch {
	case r.Part == PolicySecurityRules && t == tblFWRules,
		r.Part == PolicyNATRules && t == tblNATRules:
		return "1"
	case r.Part == PolicyZones && t == tblObjects:
		return "kind = 'zone'"
	case r.Part == PolicyObjects && t == tblObjects:
		return "kind IN ('address', 'address_group', 'service', 'service_group')"
	}
	return "0"
}

// DecodePayload strictly decodes the protojson payload of one typed
// executor read (as the collector spools it) and maps it onto the rows the
// store writes for that read. Errors wrap ErrInvalidPayload.
func DecodePayload(read pb.NetDeviceRead, payload []byte) (Rows, error) {
	if len(payload) > MaxIngestPayloadBytes {
		return nil, fmt.Errorf("%w: %s: %d bytes exceed %d", ErrInvalidPayload, read, len(payload), MaxIngestPayloadBytes)
	}
	if !utf8.Valid(payload) {
		return nil, fmt.Errorf("%w: %s: not valid UTF-8", ErrInvalidPayload, read)
	}
	var msg proto.Message
	switch read {
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION:
		msg = &pb.NetDevCBSVersion{}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:
		msg = &pb.NetDevVLANs{}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES:
		msg = &pb.NetDevPorts{}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE:
		msg = &pb.NetDevMACTable{}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP:
		msg = &pb.NetDevLLDPNeighbors{}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES:
		msg = &pb.NetDevZones{}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS:
		msg = &pb.NetDevObjects{}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES:
		msg = &pb.NetDevSecurityRules{}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES:
		msg = &pb.NetDevNATRules{}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS:
		msg = &pb.NetDevRuleHitCounts{}
	default:
		return nil, fmt.Errorf("%w: read %d is not ingested", ErrUnknownRead, int32(read))
	}
	// The decoder's error text can quote the payload; it is not passed on.
	if err := (protojson.UnmarshalOptions{}).Unmarshal(payload, msg); err != nil {
		return nil, fmt.Errorf("%w: %s: payload does not decode", ErrInvalidPayload, read)
	}
	rows, err := mapPayload(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidPayload, read, err)
	}
	return rows, nil
}

func mapPayload(msg proto.Message) (Rows, error) {
	switch m := msg.(type) {
	case *pb.NetDevCBSVersion:
		return FactsRows{Facts: netdevcontract.Facts{Model: m.GetModel(), FirmwareVersion: m.GetFirmware(),
			Serial: m.GetSerial()}}, nil
	case *pb.NetDevVLANs:
		return mapVLANs(m)
	case *pb.NetDevPorts:
		return mapPorts(m)
	case *pb.NetDevMACTable:
		return mapMACs(m)
	case *pb.NetDevLLDPNeighbors:
		return mapLLDP(m)
	case *pb.NetDevZones:
		return mapZones(m)
	case *pb.NetDevObjects:
		return mapObjects(m)
	case *pb.NetDevSecurityRules:
		return mapSecurityRules(m)
	case *pb.NetDevNATRules:
		var p netdevcontract.FirewallPolicy
		for _, r := range m.GetRules() {
			p.NATRules = append(p.NATRules, netdevcontract.NATRule{Name: r.GetName(), UUID: r.GetUuid(),
				From: r.GetFromZones(), To: r.GetToZones(), Source: r.GetSource(), Destination: r.GetDestination(),
				Service: r.GetService(), SourceTranslation: r.GetSourceTranslation(),
				DestinationTranslation: r.GetDestinationTranslation(), Disabled: r.GetDisabled(),
				Description: r.GetDescription(), Tags: r.GetTags()})
		}
		return PolicyPartRows{Part: PolicyNATRules, Policy: p}, nil
	case *pb.NetDevRuleHitCounts:
		return mapHitCounts(m)
	}
	return nil, ErrRowsMismatch
}

// u16 narrows a VLAN number; netdevcontract checks the VLAN range later.
func u16(field string, i int, v uint32) (uint16, error) {
	if v > math.MaxUint16 {
		return 0, fmt.Errorf("entry %d: %s out of range", i, field)
	}
	return uint16(v), nil
}

func optVLAN(field string, i int, v *uint32) (*uint16, error) {
	if v == nil {
		return nil, nil
	}
	n, err := u16(field, i, *v)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func mapVLANs(m *pb.NetDevVLANs) (Rows, error) {
	out := make(VLANRows, 0, len(m.GetVlans()))
	for i, v := range m.GetVlans() {
		id, err := u16("id", i, v.GetId())
		if err != nil {
			return nil, err
		}
		out = append(out, netdevcontract.VLAN{ID: id, Name: v.GetName()})
	}
	return out, nil
}

var linkStates = map[pb.NetDevLinkState]netdevcontract.LinkState{
	pb.NetDevLinkState_NET_DEV_LINK_STATE_UP:      netdevcontract.LinkUp,
	pb.NetDevLinkState_NET_DEV_LINK_STATE_DOWN:    netdevcontract.LinkDown,
	pb.NetDevLinkState_NET_DEV_LINK_STATE_UNKNOWN: netdevcontract.LinkUnknown,
}

var portModes = map[pb.NetDevPortMode]netdevcontract.PortMode{
	pb.NetDevPortMode_NET_DEV_PORT_MODE_ACCESS:  netdevcontract.ModeAccess,
	pb.NetDevPortMode_NET_DEV_PORT_MODE_TRUNK:   netdevcontract.ModeTrunk,
	pb.NetDevPortMode_NET_DEV_PORT_MODE_GENERAL: netdevcontract.ModeGeneral,
	pb.NetDevPortMode_NET_DEV_PORT_MODE_UNKNOWN: netdevcontract.ModeUnknown,
}

func mapPorts(m *pb.NetDevPorts) (Rows, error) {
	out := make(PortRows, 0, len(m.GetPorts()))
	for i, p := range m.GetPorts() {
		admin, ok1 := linkStates[p.GetAdminState()]
		oper, ok2 := linkStates[p.GetOperState()]
		mode, ok3 := portModes[p.GetMode()]
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("entry %d: state or mode is unspecified", i)
		}
		access, err := optVLAN("access_vlan", i, p.AccessVlan)
		if err != nil {
			return nil, err
		}
		native, err := optVLAN("native_vlan", i, p.NativeVlan)
		if err != nil {
			return nil, err
		}
		var allowed []uint16
		for _, v := range p.GetAllowedVlans() {
			n, err := u16("allowed_vlans", i, v)
			if err != nil {
				return nil, err
			}
			allowed = append(allowed, n)
		}
		out = append(out, netdevcontract.Port{Name: p.GetName(), AdminState: admin, OperState: oper,
			SpeedMbps: p.SpeedMbps, Mode: mode, AccessVLAN: access, NativeVLAN: native,
			AllowedVLANs: allowed, Description: p.GetDescription()})
	}
	return out, nil
}

var macTypes = map[pb.NetDevMACType]netdevcontract.MACType{
	pb.NetDevMACType_NET_DEV_MAC_TYPE_DYNAMIC: netdevcontract.MACDynamic,
	pb.NetDevMACType_NET_DEV_MAC_TYPE_STATIC:  netdevcontract.MACStatic,
	pb.NetDevMACType_NET_DEV_MAC_TYPE_OTHER:   netdevcontract.MACOther,
}

func mapMACs(m *pb.NetDevMACTable) (Rows, error) {
	out := make(MACRows, 0, len(m.GetEntries()))
	for i, e := range m.GetEntries() {
		vlan, err := u16("vlan", i, e.GetVlan())
		if err != nil {
			return nil, err
		}
		typ, ok := macTypes[e.GetType()]
		if !ok {
			return nil, fmt.Errorf("entry %d: type is unspecified", i)
		}
		out = append(out, netdevcontract.MACEntry{VLAN: vlan, MAC: e.GetMac(), Port: e.GetPort(), Type: typ})
	}
	return out, nil
}

var lldpCaps = map[pb.NetDevLLDPCapability]netdevcontract.LLDPCapability{
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_OTHER:               netdevcontract.CapOther,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_REPEATER:            netdevcontract.CapRepeater,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_BRIDGE:              netdevcontract.CapBridge,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_WLAN_ACCESS_POINT:   netdevcontract.CapWLANAP,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_ROUTER:              netdevcontract.CapRouter,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_TELEPHONE:           netdevcontract.CapTelephone,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_DOCSIS_CABLE_DEVICE: netdevcontract.CapDOCSIS,
	pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_STATION_ONLY:        netdevcontract.CapStationOnly,
}

func mapLLDP(m *pb.NetDevLLDPNeighbors) (Rows, error) {
	out := make(LLDPRows, 0, len(m.GetNeighbors()))
	for i, n := range m.GetNeighbors() {
		var caps []netdevcontract.LLDPCapability
		for _, c := range n.GetCapabilities() {
			v, ok := lldpCaps[c]
			if !ok {
				return nil, fmt.Errorf("entry %d: capability is unspecified", i)
			}
			caps = append(caps, v)
		}
		out = append(out, netdevcontract.LLDPNeighbor{LocalPort: n.GetLocalPort(), ChassisID: n.GetChassisId(),
			PortID: n.GetPortId(), SystemName: n.GetSystemName(), ManagementAddress: n.GetManagementAddress(),
			Capabilities: caps})
	}
	return out, nil
}

// mapZones maps the zones read. A zone type must be one of the known
// types, like every other enum; it has no stored column and is not kept.
func mapZones(m *pb.NetDevZones) (Rows, error) {
	var p netdevcontract.FirewallPolicy
	for i, z := range m.GetZones() {
		if _, ok := pb.NetDevZoneType_name[int32(z.GetType())]; !ok ||
			z.GetType() == pb.NetDevZoneType_NET_DEV_ZONE_TYPE_UNSPECIFIED {
			return nil, fmt.Errorf("zone %d: type is unspecified", i)
		}
		p.Zones = append(p.Zones, netdevcontract.Zone{Name: z.GetName(), Interfaces: z.GetInterfaces()})
	}
	return PolicyPartRows{Part: PolicyZones, Policy: p}, nil
}

var addressTypes = map[pb.NetDevAddressType]netdevcontract.AddressType{
	pb.NetDevAddressType_NET_DEV_ADDRESS_TYPE_IP_NETMASK:  netdevcontract.AddressNetmask,
	pb.NetDevAddressType_NET_DEV_ADDRESS_TYPE_IP_RANGE:    netdevcontract.AddressRange,
	pb.NetDevAddressType_NET_DEV_ADDRESS_TYPE_IP_WILDCARD: netdevcontract.AddressWildcard,
	pb.NetDevAddressType_NET_DEV_ADDRESS_TYPE_FQDN:        netdevcontract.AddressFQDN,
}

func mapGroup(g *pb.NetDevGroup) netdevcontract.Group {
	return netdevcontract.Group{Name: g.GetName(), Static: g.GetStaticMembers(), DynamicFilter: g.GetDynamicFilter(),
		Description: g.GetDescription(), Tags: g.GetTags()}
}

// mapObjects maps the objects read. Its tag list and the names of groups
// the executor could not evaluate have no stored column and are not kept.
func mapObjects(m *pb.NetDevObjects) (Rows, error) {
	var p netdevcontract.FirewallPolicy
	for i, a := range m.GetAddresses() {
		typ, ok := addressTypes[a.GetType()]
		if !ok {
			return nil, fmt.Errorf("address %d: type is unspecified", i)
		}
		p.Addresses = append(p.Addresses, netdevcontract.AddressObject{Name: a.GetName(), Type: typ,
			Value: a.GetValue(), Description: a.GetDescription(), Tags: a.GetTags()})
	}
	for _, g := range m.GetAddressGroups() {
		p.AddressGroups = append(p.AddressGroups, mapGroup(g))
	}
	for _, s := range m.GetServices() {
		p.Services = append(p.Services, netdevcontract.ServiceObject{Name: s.GetName(), Protocol: s.GetProtocol(),
			Port: s.GetPort(), SourcePort: s.GetSourcePort(), Description: s.GetDescription(), Tags: s.GetTags()})
	}
	for _, g := range m.GetServiceGroups() {
		p.ServiceGroups = append(p.ServiceGroups, mapGroup(g))
	}
	return PolicyPartRows{Part: PolicyObjects, Policy: p}, nil
}

var ruleActions = map[pb.NetDevRuleAction]netdevcontract.RuleAction{
	pb.NetDevRuleAction_NET_DEV_RULE_ACTION_ALLOW:        netdevcontract.ActionAllow,
	pb.NetDevRuleAction_NET_DEV_RULE_ACTION_DENY:         netdevcontract.ActionDeny,
	pb.NetDevRuleAction_NET_DEV_RULE_ACTION_DROP:         netdevcontract.ActionDrop,
	pb.NetDevRuleAction_NET_DEV_RULE_ACTION_RESET_CLIENT: netdevcontract.ActionResetClient,
	pb.NetDevRuleAction_NET_DEV_RULE_ACTION_RESET_SERVER: netdevcontract.ActionResetServer,
	pb.NetDevRuleAction_NET_DEV_RULE_ACTION_RESET_BOTH:   netdevcontract.ActionResetBoth,
}

func mapSecurityRules(m *pb.NetDevSecurityRules) (Rows, error) {
	var p netdevcontract.FirewallPolicy
	for i, r := range m.GetRules() {
		action, ok := ruleActions[r.GetAction()]
		if !ok {
			return nil, fmt.Errorf("rule %d: action is unspecified", i)
		}
		p.SecurityRules = append(p.SecurityRules, netdevcontract.SecurityRule{Name: r.GetName(), UUID: r.GetUuid(),
			From: r.GetFromZones(), To: r.GetToZones(), Source: r.GetSource(), Destination: r.GetDestination(),
			SourceUser: r.GetSourceUser(), Application: r.GetApplication(), Service: r.GetService(),
			Category: r.GetCategory(), Action: action, Disabled: r.GetDisabled(), Description: r.GetDescription(),
			Tags: r.GetTags()})
	}
	return PolicyPartRows{Part: PolicySecurityRules, Policy: p}, nil
}

// Unix second bounds of the netdevcontract timestamp years.
var (
	minHitUnix = time.Date(netdevcontract.MinObservedYear, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	maxHitUnix = time.Date(netdevcontract.MaxObservedYear, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
)

func hitTime(i int, v *int64) (*time.Time, error) {
	if v == nil {
		return nil, nil
	}
	if *v < minHitUnix || *v > maxHitUnix {
		return nil, fmt.Errorf("entry %d: time out of range", i)
	}
	t := time.Unix(*v, 0).UTC()
	return &t, nil
}

func mapHitCounts(m *pb.NetDevRuleHitCounts) (Rows, error) {
	out := make(HitCountRows, 0, len(m.GetEntries()))
	for i, e := range m.GetEntries() {
		first, err := hitTime(i, e.FirstHitUnix)
		if err != nil {
			return nil, err
		}
		last, err := hitTime(i, e.LastHitUnix)
		if err != nil {
			return nil, err
		}
		reset, err := hitTime(i, e.ResetAtUnix)
		if err != nil {
			return nil, err
		}
		out = append(out, netdevcontract.HitCount{RuleName: e.GetRuleName(), Hits: e.GetHits(),
			FirstHit: first, LastHit: last, ResetAt: reset})
	}
	return out, nil
}
