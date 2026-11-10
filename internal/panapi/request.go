// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Response size caps (ADR 0010 D3, "PAN-OS (XML API over HTTPS)"), owned by
// internal/netdevcontract (ND-04). The body is capped before it is parsed;
// a response over its cap is refused.
const (
	// MaxConfigResponseBytes caps a configuration subtree response.
	MaxConfigResponseBytes = int64(netdevcontract.MaxPANOSConfigResponseBytes)
	// MaxOtherResponseBytes caps every other response (operational
	// commands, single configuration entries).
	MaxOtherResponseBytes = int64(netdevcontract.MaxPANOSResponseBytes)
	// MaxHitCountResponseBytes caps the rule hit-count response, at
	// transport and in ParseRuleHitCounts alike. It is sized so that a
	// reply with one entry more than MaxHitCountEntries, each with a
	// maximum-length name, every timestamp and the elements PAN-OS adds
	// around them (about 800 bytes per entry), still fits; such a rule
	// base then reaches the Incomplete path instead of failing at
	// transport. It equals the configuration response cap.
	MaxHitCountResponseBytes = int64(netdevcontract.MaxPANOSConfigResponseBytes)
)

// MaxNameLength is the PAN-OS name limit for rules and objects.
const MaxNameLength = netdevcontract.MaxPANOSNameBytes

// Sentinel errors for request construction.
var (
	// ErrInvalidName is returned for a rule or object name that does not
	// follow the PAN-OS name rules. The error never repeats the name.
	ErrInvalidName = errors.New("panapi: invalid rule or object name")

	// ErrInvalidRequest is returned for an unknown subtree, a subtree
	// without named entries, or a zero Request.
	ErrInvalidRequest = errors.New("panapi: invalid request")
)

// Fixed device and vsys anchors. NOS supports a single firewall with a
// single vsys (ADR 0010 D3, Q2); the names are the PAN-OS defaults
// (*verify* in ND-03) and never come from a caller.
const (
	xpathDevice = "/config/devices/entry[@name='localhost.localdomain']"
	xpathVsys   = xpathDevice + "/vsys/entry[@name='vsys1']"
)

// Fixed operational commands (ADR 0010 D3, exact forms *verify* in ND-03).
// None of them takes a parameter.
const (
	cmdSystemInfo     = "<show><system><info/></system></show>"
	cmdPendingChanges = "<show><config><list><changes/></list></config></show>"
	cmdConfigAudit    = "<show><config><audit><info/></audit></config></show>"
	cmdRuleHitCount   = "<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'>" +
		"<rule-base><entry name='security'><rules><all/></rules></entry>" +
		"</rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
)

// Subtree names one fixed configuration subtree the client may read.
type Subtree int

// Readable configuration subtrees. Each maps to a fixed xpath template.
const (
	// SubtreeVsys is the whole vsys configuration of the device.
	SubtreeVsys Subtree = iota + 1
	// SubtreeShared is the shared configuration.
	SubtreeShared
	// SubtreeSecurityRules is the vsys1 security rulebase.
	SubtreeSecurityRules
	// SubtreeNATRules is the vsys1 NAT rulebase.
	SubtreeNATRules
	// SubtreeAddresses holds the vsys1 address objects.
	SubtreeAddresses
	// SubtreeAddressGroups holds the vsys1 address groups.
	SubtreeAddressGroups
	// SubtreeServices holds the vsys1 service objects.
	SubtreeServices
	// SubtreeServiceGroups holds the vsys1 service groups.
	SubtreeServiceGroups
	// SubtreeZones holds the vsys1 zones.
	SubtreeZones
	// SubtreeInterfaces holds the device's network interfaces.
	SubtreeInterfaces
)

// subtreeInfo is the fixed xpath of a subtree and whether its children are
// named <entry> elements that can be addressed one by one.
type subtreeInfo struct {
	xpath   string
	entries bool
}

var subtrees = map[Subtree]subtreeInfo{
	SubtreeVsys:          {xpath: xpathDevice + "/vsys"},
	SubtreeShared:        {xpath: "/config/shared"},
	SubtreeSecurityRules: {xpath: xpathVsys + "/rulebase/security/rules", entries: true},
	SubtreeNATRules:      {xpath: xpathVsys + "/rulebase/nat/rules", entries: true},
	SubtreeAddresses:     {xpath: xpathVsys + "/address", entries: true},
	SubtreeAddressGroups: {xpath: xpathVsys + "/address-group", entries: true},
	SubtreeServices:      {xpath: xpathVsys + "/service", entries: true},
	SubtreeServiceGroups: {xpath: xpathVsys + "/service-group", entries: true},
	SubtreeZones:         {xpath: xpathVsys + "/zone", entries: true},
	SubtreeInterfaces:    {xpath: xpathDevice + "/network/interface"},
}

// Request is one read-only XML API call. Its fields are unexported: a
// Request can only be built by the constructors in this file, so no caller
// can supply an xpath, a cmd string, a request type or a URL (ADR 0010 D3).
type Request struct {
	label    string // operation name for logs; fixed, never caller text
	typ      string // "op" or "config"
	action   string // "show" or "get" for type=config
	xpath    string
	cmd      string
	maxBytes int64
}

// valid reports whether r was built by a constructor.
func (r Request) valid() bool {
	switch r.typ {
	case "op":
		return r.cmd != "" && r.action == "" && r.xpath == "" && r.maxBytes > 0
	case "config":
		return (r.action == "show" || r.action == "get") && r.xpath != "" && r.cmd == "" && r.maxBytes > 0
	}
	return false
}

// body returns the form-encoded POST body. The API key is never part of it;
// it travels in the X-PAN-KEY header only.
func (r Request) body() string {
	v := url.Values{"type": {r.typ}}
	if r.typ == "op" {
		v.Set("cmd", r.cmd)
	} else {
		v.Set("action", r.action)
		v.Set("xpath", r.xpath)
	}
	return v.Encode()
}

// SystemInfoRequest reads system information (`show system info`).
func SystemInfoRequest() Request {
	return Request{label: "system-info", typ: "op", cmd: cmdSystemInfo, maxBytes: MaxOtherResponseBytes}
}

// PendingChangesRequest lists uncommitted candidate changes.
func PendingChangesRequest() Request {
	return Request{label: "pending-changes", typ: "op", cmd: cmdPendingChanges, maxBytes: MaxOtherResponseBytes}
}

// ConfigAuditRequest lists the saved running-config versions.
func ConfigAuditRequest() Request {
	return Request{label: "config-audit", typ: "op", cmd: cmdConfigAudit, maxBytes: MaxOtherResponseBytes}
}

// RuleHitCountRequest reads the hit counts of all vsys1 security rules.
func RuleHitCountRequest() Request {
	return Request{label: "rule-hit-count", typ: "op", cmd: cmdRuleHitCount, maxBytes: MaxHitCountResponseBytes}
}

// RunningConfigRequest reads one subtree of the running configuration
// (type=config, action=show).
func RunningConfigRequest(s Subtree) (Request, error) {
	return configRequest("running-config", "show", s)
}

// CandidateConfigRequest reads one subtree of the candidate configuration
// (type=config, action=get).
func CandidateConfigRequest(s Subtree) (Request, error) {
	return configRequest("candidate-config", "get", s)
}

// RunningEntryRequest reads one named entry (rule, object, group or zone)
// of the running configuration. name is validated with ValidateName.
func RunningEntryRequest(s Subtree, name string) (Request, error) {
	return entryRequest("running-entry", "show", s, name)
}

// CandidateEntryRequest reads one named entry of the candidate
// configuration. name is validated with ValidateName.
func CandidateEntryRequest(s Subtree, name string) (Request, error) {
	return entryRequest("candidate-entry", "get", s, name)
}

func configRequest(label, action string, s Subtree) (Request, error) {
	info, ok := subtrees[s]
	if !ok {
		return Request{}, fmt.Errorf("%w: unknown subtree %d", ErrInvalidRequest, int(s))
	}
	return Request{label: label, typ: "config", action: action, xpath: info.xpath, maxBytes: MaxConfigResponseBytes}, nil
}

func entryRequest(label, action string, s Subtree, name string) (Request, error) {
	info, ok := subtrees[s]
	if !ok || !info.entries {
		return Request{}, fmt.Errorf("%w: subtree %d has no named entries", ErrInvalidRequest, int(s))
	}
	if err := ValidateName(name); err != nil {
		return Request{}, err
	}
	lit, err := xpathLiteral(name)
	if err != nil {
		return Request{}, err
	}
	return Request{
		label:    label,
		typ:      "config",
		action:   action,
		xpath:    info.xpath + "/entry[@name=" + lit + "]",
		maxBytes: MaxOtherResponseBytes,
	}, nil
}

// ValidateName checks a rule or object name against the PAN-OS name rules
// of ADR 0010 D3 (*verify* in ND-03): 1 to MaxNameLength bytes of ASCII
// letters, digits, '_', '.', '-' and space, without a leading or trailing
// space. Everything with a meaning in XPath or XML (quotes, brackets,
// slashes, '<', '&', '@') and every control or non-ASCII byte is refused.
// The error never contains the name.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrInvalidName)
	}
	if len(name) > MaxNameLength {
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidName, MaxNameLength)
	}
	if name[0] == ' ' || name[len(name)-1] == ' ' {
		return fmt.Errorf("%w: leading or trailing space", ErrInvalidName)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '.', c == '-', c == ' ':
		default:
			return fmt.Errorf("%w: disallowed byte at offset %d", ErrInvalidName, i)
		}
	}
	return nil
}

// xpathLiteral quotes a validated name as an XPath 1.0 string literal.
// XPath 1.0 has no escape sequence inside a literal, so a name containing
// the quote character is refused (defence in depth behind ValidateName).
func xpathLiteral(name string) (string, error) {
	if strings.ContainsRune(name, '\'') {
		return "", fmt.Errorf("%w: quote in name", ErrInvalidName)
	}
	return "'" + name + "'", nil
}
