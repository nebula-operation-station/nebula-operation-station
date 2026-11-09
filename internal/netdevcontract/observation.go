// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Availability is the state of one dataset in an observation.
type Availability string

// Dataset states. A dataset that is absent from an observation was not
// part of that read; it is never the same as "unavailable" or "empty".
const (
	// Available means the dataset was read completely. Its value may be
	// empty: a complete enumeration that found nothing.
	Available Availability = "available"
	// Incomplete means the dataset was read but a list exceeded its parse
	// limit: the value holds the entries up to the limit and Reason is
	// ReasonOverLimit. It is never treated as complete or as a deletion.
	Incomplete Availability = "incomplete"
	// Unavailable means the dataset could not be read; it carries a reason
	// and no value.
	Unavailable Availability = "unavailable"
)

// Reason is a fixed code explaining an unavailable or incomplete dataset.
// Free text from the device never appears in it.
type Reason string

// Reason codes.
const (
	ReasonUnreachable      Reason = "unreachable"
	ReasonTimeout          Reason = "timeout"
	ReasonAuthFailed       Reason = "auth_failed"
	ReasonPinMismatch      Reason = "pin_mismatch"
	ReasonDeviceBlocked    Reason = "device_blocked"
	ReasonVaultLocked      Reason = "vault_locked"
	ReasonLeaseMissing     Reason = "lease_missing"
	ReasonUnsupported      Reason = "unsupported"
	ReasonUnexpectedPrompt Reason = "unexpected_prompt"
	ReasonOutputCap        Reason = "output_cap"
	ReasonParseError       Reason = "parse_error"
	ReasonOverLimit        Reason = "over_limit"
	ReasonDeviceError      Reason = "device_error"
)

func validReason(r Reason) bool {
	switch r {
	case ReasonUnreachable, ReasonTimeout, ReasonAuthFailed, ReasonPinMismatch,
		ReasonDeviceBlocked, ReasonVaultLocked, ReasonLeaseMissing, ReasonUnsupported,
		ReasonUnexpectedPrompt, ReasonOutputCap, ReasonParseError, ReasonOverLimit,
		ReasonDeviceError:
		return true
	}
	return false
}

// Dataset distinguishes a read value (which may be empty), a value cut at
// a parse limit, and a value that could not be read.
type Dataset[T any] struct {
	State  Availability `json:"state"`
	Value  T            `json:"value"`
	Reason Reason       `json:"reason,omitempty"`
}

// AvailableDataset wraps a completely read value, which may be empty.
func AvailableDataset[T any](v T) *Dataset[T] {
	return &Dataset[T]{State: Available, Value: v}
}

// IncompleteDataset wraps a list that was cut at its parse limit.
func IncompleteDataset[T any](v T) *Dataset[T] {
	return &Dataset[T]{State: Incomplete, Value: v, Reason: ReasonOverLimit}
}

// UnavailableDataset records a dataset that could not be read.
func UnavailableDataset[T any](reason Reason) *Dataset[T] {
	return &Dataset[T]{State: Unavailable, Reason: reason}
}

// shape checks the state, reason and value presence of a dataset.
func (d Dataset[T]) shape() error {
	zero := reflect.ValueOf(&d.Value).Elem().IsZero()
	switch d.State {
	case Available:
		if d.Reason != "" {
			return errors.New("available dataset must not carry a reason")
		}
	case Incomplete:
		if d.Reason != ReasonOverLimit {
			return fmt.Errorf("incomplete dataset requires reason %q", ReasonOverLimit)
		}
	case Unavailable:
		if !validReason(d.Reason) {
			return errors.New("unavailable dataset requires a known reason")
		}
		if !zero {
			return errors.New("unavailable dataset must not carry a value")
		}
	default:
		return errors.New("dataset state is unknown")
	}
	return nil
}

// MarshalJSON renders an available or incomplete dataset with its value
// (an empty list as []) and an unavailable one with its reason only.
func (d Dataset[T]) MarshalJSON() ([]byte, error) {
	if err := d.shape(); err != nil {
		return nil, err
	}
	if d.State == Unavailable {
		return encodeJSON(struct {
			State  Availability `json:"state"`
			Reason Reason       `json:"reason"`
		}{d.State, d.Reason})
	}
	var value any = d.Value
	if rv := reflect.ValueOf(d.Value); rv.Kind() == reflect.Slice && rv.IsNil() {
		value = reflect.MakeSlice(rv.Type(), 0, 0).Interface()
	}
	return encodeJSON(struct {
		State  Availability `json:"state"`
		Value  any          `json:"value"`
		Reason Reason       `json:"reason,omitempty"`
	}{d.State, value, d.Reason})
}

// UnmarshalJSON decodes a dataset, rejecting unknown keys and values of
// the wrong shape. Duplicate keys and nulls were rejected by the document
// walk.
func (d *Dataset[T]) UnmarshalJSON(raw []byte) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return fmt.Errorf("dataset: %w", err)
	}
	for k := range keys {
		switch k {
		case "state", "value", "reason":
		default:
			return errors.New("dataset: unknown key")
		}
	}
	var out Dataset[T]
	if err := json.Unmarshal(keys["state"], &out.State); err != nil {
		return fmt.Errorf("dataset: state: %w", err)
	}
	if r, ok := keys["reason"]; ok {
		if err := json.Unmarshal(r, &out.Reason); err != nil {
			return fmt.Errorf("dataset: reason: %w", err)
		}
	}
	rawValue, hasValue := keys["value"]
	switch out.State {
	case Available, Incomplete:
		if !hasValue {
			return errors.New("dataset: value is required")
		}
	case Unavailable:
		if hasValue {
			return errors.New("dataset: unavailable dataset must not carry a value")
		}
	}
	if hasValue {
		dec := json.NewDecoder(bytes.NewReader(rawValue))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out.Value); err != nil {
			return fmt.Errorf("dataset: value: %w", err)
		}
	}
	if err := out.shape(); err != nil {
		return fmt.Errorf("dataset: %w", err)
	}
	*d = out
	return nil
}

// Facts are the device facts (ADR 0010 D4): model, serial, firmware or
// PAN-OS version, uptime and management addresses. Every string is device
// text and rendered as text only.
type Facts struct {
	Model               string   `json:"model"`
	FirmwareVersion     string   `json:"firmware_version"`
	Serial              string   `json:"serial,omitempty"`
	Hostname            string   `json:"hostname,omitempty"`
	UptimeSeconds       *uint64  `json:"uptime_seconds,omitempty"`
	ManagementAddresses []string `json:"management_addresses,omitempty"`
}

// ConfigSnapshot is one redacted configuration as returned by the
// executor: the redacted text as lines (joined with "\n"), the keyed
// raw_digest (HMAC-SHA-256 under the per-device digest key) and the
// redacted_digest (SHA-256 of the joined redacted text). The raw
// configuration and any unkeyed digest of it never appear here.
type ConfigSnapshot struct {
	Lines          []string `json:"lines"`
	RawDigest      string   `json:"raw_digest"`
	RedactedDigest string   `json:"redacted_digest"`
}

// RedactedText returns the redacted configuration text the redacted
// digest is computed over.
func (c ConfigSnapshot) RedactedText() string { return strings.Join(c.Lines, "\n") }

// RedactedDigestOf returns the lowercase hex SHA-256 of the joined lines.
func RedactedDigestOf(lines []string) string {
	h := sha256.New()
	for i, l := range lines {
		if i > 0 {
			h.Write([]byte{'\n'})
		}
		h.Write([]byte(l))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LinkState is the administrative or operational state of a port.
type LinkState string

// Link states.
const (
	LinkUp      LinkState = "up"
	LinkDown    LinkState = "down"
	LinkUnknown LinkState = "unknown"
)

// PortMode is the switchport mode of a CBS port.
type PortMode string

// Port modes.
const (
	ModeAccess  PortMode = "access"
	ModeTrunk   PortMode = "trunk"
	ModeGeneral PortMode = "general"
	ModeUnknown PortMode = "unknown"
)

// Port is one switch port (CBS).
type Port struct {
	Name         string    `json:"name"`
	AdminState   LinkState `json:"admin_state"`
	OperState    LinkState `json:"oper_state"`
	SpeedMbps    *uint64   `json:"speed_mbps,omitempty"`
	Mode         PortMode  `json:"mode"`
	AccessVLAN   *uint16   `json:"access_vlan,omitempty"`
	NativeVLAN   *uint16   `json:"native_vlan,omitempty"`
	AllowedVLANs []uint16  `json:"allowed_vlans,omitempty"`
	Description  string    `json:"description,omitempty"`
}

// VLAN is one switch VLAN.
type VLAN struct {
	ID   uint16 `json:"id"`
	Name string `json:"name,omitempty"`
}

// MACType is the type of a MAC table entry.
type MACType string

// MAC entry types.
const (
	MACDynamic MACType = "dynamic"
	MACStatic  MACType = "static"
	MACOther   MACType = "other"
)

// MACEntry is one MAC address table entry. Port is empty for entries not
// bound to a front port (for example the switch's own address).
type MACEntry struct {
	VLAN uint16  `json:"vlan"`
	MAC  string  `json:"mac"`
	Port string  `json:"port,omitempty"`
	Type MACType `json:"type"`
}

// LLDPCapability is one LLDP system capability.
type LLDPCapability string

// LLDP capabilities (IEEE 802.1AB).
const (
	CapOther       LLDPCapability = "other"
	CapRepeater    LLDPCapability = "repeater"
	CapBridge      LLDPCapability = "bridge"
	CapWLANAP      LLDPCapability = "wlan-access-point"
	CapRouter      LLDPCapability = "router"
	CapTelephone   LLDPCapability = "telephone"
	CapDOCSIS      LLDPCapability = "docsis-cable-device"
	CapStationOnly LLDPCapability = "station-only"
)

// LLDPNeighbor is one LLDP neighbor seen on a local port. Everything but
// LocalPort was sent by an arbitrary device on the wire and is doubly
// untrusted: a hint with its source, never an identity.
type LLDPNeighbor struct {
	LocalPort         string           `json:"local_port"`
	ChassisID         string           `json:"chassis_id"`
	PortID            string           `json:"port_id"`
	SystemName        string           `json:"system_name,omitempty"`
	ManagementAddress string           `json:"management_address,omitempty"`
	Capabilities      []LLDPCapability `json:"capabilities,omitempty"`
}

// RuleAction is a PAN-OS security rule action.
type RuleAction string

// Rule actions.
const (
	ActionAllow       RuleAction = "allow"
	ActionDeny        RuleAction = "deny"
	ActionDrop        RuleAction = "drop"
	ActionResetClient RuleAction = "reset-client"
	ActionResetServer RuleAction = "reset-server"
	ActionResetBoth   RuleAction = "reset-both"
)

// SecurityRule is one PAN-OS security rule; list order is rule order.
type SecurityRule struct {
	Name        string     `json:"name"`
	UUID        string     `json:"uuid,omitempty"`
	From        []string   `json:"from,omitempty"`
	To          []string   `json:"to,omitempty"`
	Source      []string   `json:"source,omitempty"`
	Destination []string   `json:"destination,omitempty"`
	SourceUser  []string   `json:"source_user,omitempty"`
	Application []string   `json:"application,omitempty"`
	Service     []string   `json:"service,omitempty"`
	Category    []string   `json:"category,omitempty"`
	Action      RuleAction `json:"action"`
	Disabled    bool       `json:"disabled,omitempty"`
	Description string     `json:"description,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
}

// NATRule is one PAN-OS NAT rule; list order is rule order. Translations
// are the redacted textual form produced by the executor.
type NATRule struct {
	Name                   string   `json:"name"`
	UUID                   string   `json:"uuid,omitempty"`
	From                   []string `json:"from,omitempty"`
	To                     []string `json:"to,omitempty"`
	Source                 []string `json:"source,omitempty"`
	Destination            []string `json:"destination,omitempty"`
	Service                string   `json:"service,omitempty"`
	SourceTranslation      string   `json:"source_translation,omitempty"`
	DestinationTranslation string   `json:"destination_translation,omitempty"`
	Disabled               bool     `json:"disabled,omitempty"`
	Description            string   `json:"description,omitempty"`
	Tags                   []string `json:"tags,omitempty"`
}

// AddressType is the kind of a PAN-OS address object.
type AddressType string

// Address object types.
const (
	AddressNetmask  AddressType = "ip-netmask"
	AddressRange    AddressType = "ip-range"
	AddressWildcard AddressType = "ip-wildcard"
	AddressFQDN     AddressType = "fqdn"
)

// AddressObject is one PAN-OS address object.
type AddressObject struct {
	Name        string      `json:"name"`
	Type        AddressType `json:"type"`
	Value       string      `json:"value"`
	Description string      `json:"description,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
}

// ServiceObject is one PAN-OS service object.
type ServiceObject struct {
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	Port        string   `json:"port"`
	SourcePort  string   `json:"source_port,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Group is one PAN-OS address or service group: static members by name or,
// for address groups only, a dynamic tag filter.
type Group struct {
	Name          string   `json:"name"`
	Static        []string `json:"static,omitempty"`
	DynamicFilter string   `json:"dynamic_filter,omitempty"`
	Description   string   `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
}

// Zone is one PAN-OS zone with its member interfaces.
type Zone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces,omitempty"`
}

// FirewallInterface is one PAN-OS interface or subinterface.
type FirewallInterface struct {
	Name      string   `json:"name"`
	VLANTag   *uint16  `json:"vlan_tag,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Zone      string   `json:"zone,omitempty"`
}

// FirewallPolicy is the PAN-OS policy view of ADR 0010 D4 for the single
// supported vsys.
type FirewallPolicy struct {
	SecurityRules []SecurityRule      `json:"security_rules,omitempty"`
	NATRules      []NATRule           `json:"nat_rules,omitempty"`
	Addresses     []AddressObject     `json:"addresses,omitempty"`
	AddressGroups []Group             `json:"address_groups,omitempty"`
	Services      []ServiceObject     `json:"services,omitempty"`
	ServiceGroups []Group             `json:"service_groups,omitempty"`
	Zones         []Zone              `json:"zones,omitempty"`
	Interfaces    []FirewallInterface `json:"interfaces,omitempty"`
}

// HitCount is the hit counter of one security rule. Absent times were not
// reported by the device (for example a rule that never matched).
type HitCount struct {
	RuleName string     `json:"rule_name"`
	Hits     uint64     `json:"hits"`
	FirstHit *time.Time `json:"first_hit,omitempty"`
	LastHit  *time.Time `json:"last_hit,omitempty"`
	ResetAt  *time.Time `json:"reset_at,omitempty"`
}

// Observation is one validated read result for one device, the unit the
// executor returns, the collector spools and the server ingests. Each
// dataset is optional: absent means "not part of this read". Datasets of
// the other family are refused.
type Observation struct {
	DeviceID        string    `json:"device_id"`
	Family          Family    `json:"family"`
	TrustGeneration uint64    `json:"trust_generation"`
	ObservedAt      time.Time `json:"observed_at"`

	Facts         *Dataset[Facts]          `json:"facts,omitempty"`
	RunningConfig *Dataset[ConfigSnapshot] `json:"running_config,omitempty"`
	// StartupConfig is CBS only.
	StartupConfig *Dataset[ConfigSnapshot] `json:"startup_config,omitempty"`

	// CBS datasets.
	Ports         *Dataset[[]Port]         `json:"ports,omitempty"`
	VLANs         *Dataset[[]VLAN]         `json:"vlans,omitempty"`
	MACTable      *Dataset[[]MACEntry]     `json:"mac_table,omitempty"`
	LLDPNeighbors *Dataset[[]LLDPNeighbor] `json:"lldp_neighbors,omitempty"`

	// PAN-OS datasets.
	FirewallPolicy *Dataset[FirewallPolicy] `json:"firewall_policy,omitempty"`
	HitCounts      *Dataset[[]HitCount]     `json:"hit_counts,omitempty"`
}

// Name lengths are checked against the named constants, not in the regexes.
var (
	macRe           = regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$`)
	interfaceNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9/._:-]*$`)
	panosNameRe     = regexp.MustCompile(`^[A-Za-z0-9_.\- ]+$`)
	uuidRe          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexDigestRe     = fingerprintRe
	portSpecRe      = regexp.MustCompile(`^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$`)
)

// ValidInterfaceName reports whether s is a well-formed CBS or PAN-OS
// interface name.
func ValidInterfaceName(s string) bool {
	return len(s) <= MaxInterfaceNameBytes && interfaceNameRe.MatchString(s)
}

// ValidPANOSName reports whether s satisfies the PAN-OS name rule of
// ADR 0010 D3: 1 to MaxPANOSNameBytes (63) letters, digits, '_', '.', '-'
// and space.
func ValidPANOSName(s string) bool {
	return len(s) <= MaxPANOSNameBytes && panosNameRe.MatchString(s)
}

// ValidMAC reports whether s is a lowercase colon-separated MAC address.
func ValidMAC(s string) bool { return macRe.MatchString(s) }

func validVLAN(v uint16) bool { return v >= 1 && v <= MaxVLANID }

func validIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == "" && a.String() == s
}

func validIPOrPrefix(s string) bool {
	if validIP(s) {
		return true
	}
	p, err := netip.ParsePrefix(s)
	return err == nil && p.String() == s
}

func validTime(t time.Time) bool {
	y := t.UTC().Year()
	return !t.IsZero() && y >= MinObservedYear && y <= MaxObservedYear
}

func validPortSpec(s string) bool {
	if len(s) > MaxLabelBytes || !portSpecRe.MatchString(s) {
		return false
	}
	for part := range strings.SplitSeq(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 != nil || err2 != nil || a > 65535 || b > 65535 || a > b {
			return false
		}
	}
	return true
}

// checkDataset validates the shape of an optional dataset and, when it
// carries a value, the value itself.
func checkDataset[T any](p *problems, name string, d *Dataset[T], allowIncomplete bool, value func(T)) {
	if d == nil {
		return
	}
	if err := d.shape(); err != nil {
		p.add("%s: %v", name, err)
		return
	}
	if d.State == Incomplete && !allowIncomplete {
		p.add("%s: cannot be incomplete; an over-limit %s is refused", name, name)
		return
	}
	if d.State != Unavailable {
		value(d.Value)
	}
}

// ValidateObservation validates o. The returned copy has ObservedAt in UTC;
// datasets are shared with o, which is never mutated.
func ValidateObservation(o Observation) (Observation, error) {
	var p problems
	if !ValidDeviceID(o.DeviceID) {
		p.add("device_id is malformed")
	}
	switch {
	case o.TrustGeneration == 0:
		p.add("trust_generation must be at least 1")
	case o.TrustGeneration > MaxTrustGeneration:
		p.add("trust_generation out of range")
	}
	if !validTime(o.ObservedAt) {
		p.add("observed_at is missing or out of range")
	}

	var cbsOnly, panosOnly bool
	switch o.Family {
	case FamilyCBS:
		panosOnly = o.FirewallPolicy != nil || o.HitCounts != nil
	case FamilyPANOS:
		cbsOnly = o.StartupConfig != nil || o.Ports != nil || o.VLANs != nil ||
			o.MACTable != nil || o.LLDPNeighbors != nil
	default:
		p.add("family %q is unknown", truncate(string(o.Family)))
	}
	if cbsOnly {
		p.add("panos observation carries cbs-only datasets")
	}
	if panosOnly {
		p.add("cbs observation carries panos-only datasets")
	}
	if o.Facts == nil && o.RunningConfig == nil && o.StartupConfig == nil &&
		o.Ports == nil && o.VLANs == nil && o.MACTable == nil &&
		o.LLDPNeighbors == nil && o.FirewallPolicy == nil && o.HitCounts == nil {
		p.add("observation carries no dataset")
	}

	maxLines := MaxConfigLines
	if o.Family == FamilyPANOS {
		maxLines = MaxXMLElements // one element per line after normalization
	}
	checkDataset(&p, "facts", o.Facts, false, func(f Facts) { validateFacts(&p, f) })
	checkDataset(&p, "running_config", o.RunningConfig, false, func(c ConfigSnapshot) {
		validateConfig(&p, "running_config", c, maxLines)
	})
	checkDataset(&p, "startup_config", o.StartupConfig, false, func(c ConfigSnapshot) {
		validateConfig(&p, "startup_config", c, maxLines)
	})
	checkDataset(&p, "ports", o.Ports, true, func(v []Port) { validatePorts(&p, v) })
	checkDataset(&p, "vlans", o.VLANs, true, func(v []VLAN) { validateVLANs(&p, v) })
	checkDataset(&p, "mac_table", o.MACTable, true, func(v []MACEntry) { validateMACTable(&p, v) })
	checkDataset(&p, "lldp_neighbors", o.LLDPNeighbors, true, func(v []LLDPNeighbor) { validateLLDP(&p, v) })
	checkDataset(&p, "firewall_policy", o.FirewallPolicy, true, func(v FirewallPolicy) { validatePolicy(&p, v) })
	checkDataset(&p, "hit_counts", o.HitCounts, true, func(v []HitCount) { validateHitCounts(&p, v) })

	if err := p.err(); err != nil {
		return Observation{}, err
	}
	n := o
	n.ObservedAt = o.ObservedAt.UTC()
	return n, nil
}

// DecodeObservation strictly decodes and validates one observation
// document.
func DecodeObservation(raw []byte) (Observation, error) {
	var o Observation
	if err := decodeStrict(raw, &o); err != nil {
		return Observation{}, decodeError(err)
	}
	return ValidateObservation(o)
}

// MarshalObservation validates o and returns its JSON encoding. It refuses
// an observation whose encoding would exceed MaxDocumentBytes, so that
// every encoded observation decodes again.
func MarshalObservation(o Observation) ([]byte, error) {
	v, err := ValidateObservation(o)
	if err != nil {
		return nil, err
	}
	b, err := encodeJSON(v)
	if err != nil {
		return nil, fmt.Errorf("netdevcontract: encode observation: %w", err)
	}
	if len(b) > MaxDocumentBytes {
		return nil, &ValidationError{Problems: []string{overLimit("document bytes", len(b), MaxDocumentBytes).Error()}, overLimit: true}
	}
	return b, nil
}

// encodeJSON encodes v without HTML escaping, which would inflate
// configuration text sixfold.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func validateFacts(p *problems, f Facts) {
	if f.Model == "" || !validText(f.Model, MaxLabelBytes) {
		p.add("facts: model is missing or not printable text of at most %d bytes", MaxLabelBytes)
	}
	if f.FirmwareVersion == "" || !validText(f.FirmwareVersion, MaxLabelBytes) {
		p.add("facts: firmware_version is missing or not printable text of at most %d bytes", MaxLabelBytes)
	}
	if !validText(f.Serial, MaxLabelBytes) {
		p.add("facts: serial is not printable text of at most %d bytes", MaxLabelBytes)
	}
	if !validText(f.Hostname, MaxLabelBytes) {
		p.add("facts: hostname is not printable text of at most %d bytes", MaxLabelBytes)
	}
	p.count("facts: management_addresses", len(f.ManagementAddresses), MaxManagementAddresses)
	for i, a := range f.ManagementAddresses {
		if !validIP(a) {
			p.add("facts: management_addresses %d is not a canonical IP literal", i)
		}
	}
}

func validateConfig(p *problems, name string, c ConfigSnapshot, maxLines int) {
	if len(c.Lines) == 0 {
		p.add("%s: no lines; an empty or unparseable configuration is not stored", name)
	}
	p.count(name+": lines", len(c.Lines), maxLines)
	total := 0
	for i, l := range c.Lines {
		total += len(l) + 1
		if !validLine(l) {
			p.add("%s: line %d is not valid text of at most %d bytes", name, i, MaxLineBytes)
			if len(l) > MaxLineBytes {
				p.overLimit = true
			}
			return
		}
	}
	if total-1 > MaxRedactedConfigBytes {
		p.overLimit = true
		p.add("%s: %d bytes exceed %d", name, total-1, MaxRedactedConfigBytes)
		return
	}
	if !hexDigestRe.MatchString(c.RawDigest) {
		p.add("%s: raw_digest must be 64 lowercase hex characters", name)
	}
	if !hexDigestRe.MatchString(c.RedactedDigest) {
		p.add("%s: redacted_digest must be 64 lowercase hex characters", name)
	} else if c.RedactedDigest != RedactedDigestOf(c.Lines) {
		p.add("%s: redacted_digest does not match the redacted text", name)
	}
}

func validatePorts(p *problems, ports []Port) {
	p.count("ports", len(ports), MaxInterfacesPerDevice)
	seen := make(map[string]struct{}, len(ports))
	for i, pt := range ports {
		if !ValidInterfaceName(pt.Name) {
			p.add("ports %d: name is malformed", i)
		} else if _, dup := seen[pt.Name]; dup {
			p.add("ports %d: name is duplicated", i)
		}
		seen[pt.Name] = struct{}{}
		for _, s := range []LinkState{pt.AdminState, pt.OperState} {
			switch s {
			case LinkUp, LinkDown, LinkUnknown:
			default:
				p.add("ports %d: link state is unknown", i)
			}
		}
		if pt.SpeedMbps != nil && *pt.SpeedMbps > MaxSpeedMbps {
			p.add("ports %d: speed_mbps out of range", i)
		}
		switch pt.Mode {
		case ModeAccess:
			if pt.NativeVLAN != nil || len(pt.AllowedVLANs) > 0 {
				p.add("ports %d: access port must not carry trunk VLANs", i)
			}
		case ModeTrunk, ModeGeneral:
			if pt.AccessVLAN != nil {
				p.add("ports %d: %s port must not carry an access VLAN", i, pt.Mode)
			}
		case ModeUnknown:
			if pt.AccessVLAN != nil || pt.NativeVLAN != nil || len(pt.AllowedVLANs) > 0 {
				p.add("ports %d: port of unknown mode must not carry VLANs", i)
			}
		default:
			p.add("ports %d: mode is unknown", i)
		}
		if pt.AccessVLAN != nil && !validVLAN(*pt.AccessVLAN) {
			p.add("ports %d: access_vlan out of range", i)
		}
		if pt.NativeVLAN != nil && !validVLAN(*pt.NativeVLAN) {
			p.add("ports %d: native_vlan out of range", i)
		}
		p.count(fmt.Sprintf("ports %d: allowed_vlans", i), len(pt.AllowedVLANs), MaxVLANsPerDevice)
		vseen := map[uint16]struct{}{}
		for _, v := range pt.AllowedVLANs {
			if !validVLAN(v) {
				p.add("ports %d: allowed VLAN out of range", i)
				break
			}
			if _, dup := vseen[v]; dup {
				p.add("ports %d: allowed VLAN duplicated", i)
				break
			}
			vseen[v] = struct{}{}
		}
		if !validText(pt.Description, MaxLabelBytes) {
			p.add("ports %d: description is not printable text of at most %d bytes", i, MaxLabelBytes)
		}
	}
}

func validateVLANs(p *problems, vlans []VLAN) {
	p.count("vlans", len(vlans), MaxVLANsPerDevice)
	seen := make(map[uint16]struct{}, len(vlans))
	for i, v := range vlans {
		if !validVLAN(v.ID) {
			p.add("vlans %d: id out of range", i)
		} else if _, dup := seen[v.ID]; dup {
			p.add("vlans %d: id is duplicated", i)
		}
		seen[v.ID] = struct{}{}
		if !validText(v.Name, MaxLabelBytes) {
			p.add("vlans %d: name is not printable text of at most %d bytes", i, MaxLabelBytes)
		}
	}
}

func validateMACTable(p *problems, entries []MACEntry) {
	p.count("mac_table", len(entries), MaxMACEntriesPerDevice)
	type key struct {
		vlan uint16
		mac  string
	}
	seen := make(map[key]struct{}, len(entries))
	for i, e := range entries {
		if !validVLAN(e.VLAN) {
			p.add("mac_table %d: vlan out of range", i)
		}
		if !ValidMAC(e.MAC) {
			p.add("mac_table %d: mac is malformed", i)
		}
		k := key{e.VLAN, e.MAC}
		if _, dup := seen[k]; dup {
			p.add("mac_table %d: vlan and mac duplicated", i)
		}
		seen[k] = struct{}{}
		if e.Port != "" && !ValidInterfaceName(e.Port) {
			p.add("mac_table %d: port is malformed", i)
		}
		switch e.Type {
		case MACDynamic, MACStatic, MACOther:
		default:
			p.add("mac_table %d: type is unknown", i)
		}
	}
}

func validateLLDP(p *problems, ns []LLDPNeighbor) {
	p.count("lldp_neighbors", len(ns), MaxLLDPNeighborsPerDevice)
	perPort := map[string]int{}
	for i, n := range ns {
		if !ValidInterfaceName(n.LocalPort) {
			p.add("lldp_neighbors %d: local_port is malformed", i)
		} else {
			perPort[n.LocalPort]++
		}
		if n.ChassisID == "" || !validText(n.ChassisID, MaxLabelBytes) {
			p.add("lldp_neighbors %d: chassis_id is missing or not printable text", i)
		}
		if n.PortID == "" || !validText(n.PortID, MaxLabelBytes) {
			p.add("lldp_neighbors %d: port_id is missing or not printable text", i)
		}
		if !validText(n.SystemName, MaxLabelBytes) {
			p.add("lldp_neighbors %d: system_name is not printable text", i)
		}
		if n.ManagementAddress != "" && !validIP(n.ManagementAddress) {
			p.add("lldp_neighbors %d: management_address is not a canonical IP literal", i)
		}
		p.count(fmt.Sprintf("lldp_neighbors %d: capabilities", i), len(n.Capabilities), MaxLLDPCapabilities)
		cseen := map[LLDPCapability]struct{}{}
		for _, c := range n.Capabilities {
			switch c {
			case CapOther, CapRepeater, CapBridge, CapWLANAP, CapRouter, CapTelephone, CapDOCSIS, CapStationOnly:
			default:
				p.add("lldp_neighbors %d: capability is unknown", i)
			}
			if _, dup := cseen[c]; dup {
				p.add("lldp_neighbors %d: capability duplicated", i)
			}
			cseen[c] = struct{}{}
		}
	}
	// The port name is device text and stays out of the message.
	for _, n := range perPort {
		p.count("lldp_neighbors per port", n, MaxLLDPNeighborsPerPort)
	}
}

// members checks a list of names or rule members: count, validity and
// uniqueness.
func members(p *problems, where string, list []string, limit int, valid func(string) bool) {
	p.count(where, len(list), limit)
	seen := make(map[string]struct{}, len(list))
	for _, m := range list {
		if !valid(m) {
			p.add("%s: entry is malformed", where)
			return
		}
		if _, dup := seen[m]; dup {
			p.add("%s: entry duplicated", where)
			return
		}
		seen[m] = struct{}{}
	}
}

func memberText(s string) bool { return s != "" && validText(s, MaxLabelBytes) }

func zoneRef(s string) bool { return s == "any" || ValidPANOSName(s) }

func common(p *problems, where, name, uuid, description string, tags []string, unique map[string]struct{}) {
	if !ValidPANOSName(name) {
		p.add("%s: name is malformed", where)
	} else if _, dup := unique[name]; dup {
		p.add("%s: name is duplicated", where)
	}
	unique[name] = struct{}{}
	if uuid != "" && !uuidRe.MatchString(uuid) {
		p.add("%s: uuid is malformed", where)
	}
	if !validText(description, MaxDescriptionBytes) {
		p.add("%s: description is not printable text of at most %d bytes", where, MaxDescriptionBytes)
	}
	members(p, where+": tags", tags, MaxTagsPerObject, ValidPANOSName)
}

func validatePolicy(p *problems, fp FirewallPolicy) {
	before := p.total
	p.count("security_rules", len(fp.SecurityRules), MaxSecurityRules)
	p.count("nat_rules", len(fp.NATRules), MaxNATRules)
	p.count("addresses", len(fp.Addresses), MaxAddressObjects)
	p.count("services", len(fp.Services), MaxServiceObjects)
	p.count("address_groups", len(fp.AddressGroups), MaxAddressGroups)
	p.count("service_groups", len(fp.ServiceGroups), MaxServiceGroups)
	p.count("zones", len(fp.Zones), MaxZones)
	p.count("interfaces", len(fp.Interfaces), MaxFirewallInterfaces)
	if p.total > before {
		return // do not walk lists that are already too long
	}

	ruleNames := map[string]struct{}{}
	for i, r := range fp.SecurityRules {
		w := fmt.Sprintf("security_rules %d", i)
		common(p, w, r.Name, r.UUID, r.Description, r.Tags, ruleNames)
		members(p, w+": from", r.From, MaxRuleMembers, zoneRef)
		members(p, w+": to", r.To, MaxRuleMembers, zoneRef)
		for _, f := range []struct {
			n string
			v []string
		}{{"source", r.Source}, {"destination", r.Destination}, {"source_user", r.SourceUser},
			{"application", r.Application}, {"service", r.Service}, {"category", r.Category}} {
			members(p, w+": "+f.n, f.v, MaxRuleMembers, memberText)
		}
		switch r.Action {
		case ActionAllow, ActionDeny, ActionDrop, ActionResetClient, ActionResetServer, ActionResetBoth:
		default:
			p.add("%s: action is unknown", w)
		}
	}

	natNames := map[string]struct{}{}
	for i, r := range fp.NATRules {
		w := fmt.Sprintf("nat_rules %d", i)
		common(p, w, r.Name, r.UUID, r.Description, r.Tags, natNames)
		members(p, w+": from", r.From, MaxRuleMembers, zoneRef)
		members(p, w+": to", r.To, MaxRuleMembers, zoneRef)
		members(p, w+": source", r.Source, MaxRuleMembers, memberText)
		members(p, w+": destination", r.Destination, MaxRuleMembers, memberText)
		if r.Service != "" && !memberText(r.Service) {
			p.add("%s: service is malformed", w)
		}
		if !validText(r.SourceTranslation, MaxDescriptionBytes) || !validText(r.DestinationTranslation, MaxDescriptionBytes) {
			p.add("%s: translation is not printable text of at most %d bytes", w, MaxDescriptionBytes)
		}
	}

	// Address objects and address groups share one namespace, as do
	// services and service groups.
	addrNames := map[string]struct{}{}
	for i, a := range fp.Addresses {
		w := fmt.Sprintf("addresses %d", i)
		common(p, w, a.Name, "", a.Description, a.Tags, addrNames)
		if !validAddressValue(a.Type, a.Value) {
			p.add("%s: value does not match type", w)
		}
	}
	addrGroups := groups(p, "address_groups", fp.AddressGroups, addrNames, true)
	nesting(p, "address_groups", fp.AddressGroups, addrGroups)

	svcNames := map[string]struct{}{}
	for i, s := range fp.Services {
		w := fmt.Sprintf("services %d", i)
		common(p, w, s.Name, "", s.Description, s.Tags, svcNames)
		switch s.Protocol {
		case "tcp", "udp", "sctp":
		default:
			p.add("%s: protocol is unknown", w)
		}
		if !validPortSpec(s.Port) {
			p.add("%s: port is malformed", w)
		}
		if s.SourcePort != "" && !validPortSpec(s.SourcePort) {
			p.add("%s: source_port is malformed", w)
		}
	}
	svcGroups := groups(p, "service_groups", fp.ServiceGroups, svcNames, false)
	nesting(p, "service_groups", fp.ServiceGroups, svcGroups)

	zoneNames := map[string]struct{}{}
	for i, z := range fp.Zones {
		w := fmt.Sprintf("zones %d", i)
		common(p, w, z.Name, "", "", nil, zoneNames)
		members(p, w+": interfaces", z.Interfaces, MaxFirewallInterfaces, ValidInterfaceName)
	}

	ifNames := map[string]struct{}{}
	for i, itf := range fp.Interfaces {
		w := fmt.Sprintf("interfaces %d", i)
		if !ValidInterfaceName(itf.Name) {
			p.add("%s: name is malformed", w)
		} else if _, dup := ifNames[itf.Name]; dup {
			p.add("%s: name is duplicated", w)
		}
		ifNames[itf.Name] = struct{}{}
		if itf.VLANTag != nil && !validVLAN(*itf.VLANTag) {
			p.add("%s: vlan_tag out of range", w)
		}
		members(p, w+": addresses", itf.Addresses, MaxAddressesPerInterface, validIPOrPrefix)
		if itf.Zone != "" && !ValidPANOSName(itf.Zone) {
			p.add("%s: zone is malformed", w)
		}
	}
}

// groups validates address or service groups and returns the index of
// each group by name.
func groups(p *problems, where string, gs []Group, namespace map[string]struct{}, dynamicAllowed bool) map[string]int {
	index := make(map[string]int, len(gs))
	for i, g := range gs {
		w := fmt.Sprintf("%s %d", where, i)
		common(p, w, g.Name, "", g.Description, g.Tags, namespace)
		index[g.Name] = i
		members(p, w+": static", g.Static, MaxGroupMembers, ValidPANOSName)
		switch {
		case g.DynamicFilter != "" && !dynamicAllowed:
			p.add("%s: service groups have no dynamic filter", w)
		case g.DynamicFilter != "" && len(g.Static) > 0:
			p.add("%s: static members and dynamic filter are exclusive", w)
		case !validText(g.DynamicFilter, MaxFilterBytes):
			p.add("%s: dynamic_filter is not printable text of at most %d bytes", w, MaxFilterBytes)
		}
	}
	return index
}

// nesting rejects group cycles and groups nested deeper than
// MaxGroupNestingDepth. A group whose static members are all plain
// objects has depth 1.
func nesting(p *problems, where string, gs []Group, index map[string]int) {
	const (
		unvisited = 0
		visiting  = -1
	)
	depth := make([]int, len(gs))
	var visit func(i, level int) int
	visit = func(i, level int) int {
		switch {
		case depth[i] == visiting:
			return visiting
		case depth[i] > 0:
			return depth[i]
		case level > MaxGroupNestingDepth:
			return MaxGroupNestingDepth + 1 // stop descending
		}
		depth[i] = visiting
		d := 1
		for _, m := range gs[i].Static {
			j, ok := index[m]
			if !ok {
				continue
			}
			sub := visit(j, level+1)
			if sub == visiting {
				depth[i] = unvisited
				return visiting
			}
			d = max(d, sub+1)
		}
		depth[i] = d
		return d
	}
	for i := range gs {
		switch d := visit(i, 1); {
		case d == visiting:
			p.add("%s %d: group membership has a cycle", where, i)
			return
		case d > MaxGroupNestingDepth:
			p.count(fmt.Sprintf("%s %d: nesting depth", where, i), MaxGroupNestingDepth+1, MaxGroupNestingDepth)
			return
		}
	}
}

func validAddressValue(t AddressType, v string) bool {
	if v == "" || !validText(v, MaxLabelBytes) {
		return false
	}
	switch t {
	case AddressNetmask:
		return validIPOrPrefix(v)
	case AddressRange:
		lo, hi, ok := strings.Cut(v, "-")
		if !ok || !validIP(lo) || !validIP(hi) {
			return false
		}
		a, b := netip.MustParseAddr(lo), netip.MustParseAddr(hi)
		return a.Is4() == b.Is4() && a.Compare(b) <= 0
	case AddressWildcard:
		addr, mask, ok := strings.Cut(v, "/")
		return ok && validIP(addr) && validIP(mask)
	case AddressFQDN:
		return validDNSName(strings.ToLower(v))
	}
	return false
}

func validateHitCounts(p *problems, hs []HitCount) {
	p.count("hit_counts", len(hs), MaxHitCountEntries)
	seen := make(map[string]struct{}, len(hs))
	for i, h := range hs {
		w := fmt.Sprintf("hit_counts %d", i)
		if !ValidPANOSName(h.RuleName) {
			p.add("%s: rule_name is malformed", w)
		} else if _, dup := seen[h.RuleName]; dup {
			p.add("%s: rule_name is duplicated", w)
		}
		seen[h.RuleName] = struct{}{}
		for _, t := range []*time.Time{h.FirstHit, h.LastHit, h.ResetAt} {
			if t != nil && !validTime(*t) {
				p.add("%s: time out of range", w)
			}
		}
		if h.FirstHit != nil && h.LastHit != nil && h.LastHit.Before(*h.FirstHit) {
			p.add("%s: last_hit before first_hit", w)
		}
		if h.Hits == 0 && (h.FirstHit != nil || h.LastHit != nil) {
			p.add("%s: hit times without hits", w)
		}
	}
}
