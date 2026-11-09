// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// ErrInvalid marks documents that fail strict decoding or validation.
// Callers can branch on it with errors.Is.
var ErrInvalid = errors.New("netdevcontract: invalid document")

// ValidationError lists the problems found in a device or observation: the
// first MaxProblems, then one entry counting the rest.
type ValidationError struct {
	// Problems describes each failed check; it never contains secrets.
	Problems  []string
	overLimit bool
}

// Error joins all problems.
func (e *ValidationError) Error() string {
	return "netdevcontract: " + strings.Join(e.Problems, "; ")
}

// Is lets callers match with errors.Is(err, ErrInvalid), and with
// ErrOverLimit when a limit caused the failure.
func (e *ValidationError) Is(target error) bool {
	return target == ErrInvalid || (e.overLimit && target == ErrOverLimit)
}

// MaxProblems bounds the problems listed in a ValidationError, so a hostile
// maximum-size observation cannot produce a multi-megabyte error. Further
// problems are counted in one final entry.
const MaxProblems = 32

// MaxProblemBytes bounds the text of one problem. Longer texts (for example
// a decoder error quoting a time string) are cut and marked, so that with
// MaxProblems no error can grow beyond a small fixed size.
const MaxProblemBytes = 256

// truncatedMark ends a problem text cut to MaxProblemBytes.
const truncatedMark = " [truncated]"

// shortProblem returns s cut to at most MaxProblemBytes bytes of valid
// UTF-8. A cut text ends with truncatedMark; invalid UTF-8 is replaced.
func shortProblem(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= MaxProblemBytes {
		return s
	}
	cut := MaxProblemBytes - len(truncatedMark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncatedMark
}

// problems collects validation problems.
type problems struct {
	list      []string
	total     int // problems found, including those beyond MaxProblems
	overLimit bool
}

func (p *problems) add(format string, args ...any) {
	p.total++
	if len(p.list) < MaxProblems {
		p.list = append(p.list, shortProblem(fmt.Sprintf(format, args...)))
	}
}

// count records a list count problem, marked as over limit.
func (p *problems) count(what string, n, limit int) {
	if n > limit {
		p.overLimit = true
		p.add("%s: %d entries exceed %d", what, n, limit)
	}
}

func (p *problems) err() error {
	if p.total == 0 {
		return nil
	}
	list := p.list
	if more := p.total - len(list); more > 0 {
		list = append(slices.Clip(list), fmt.Sprintf("and %d more problems", more))
	}
	return &ValidationError{Problems: list, overLimit: p.overLimit}
}

// decodeError wraps a strict decoding failure so that it matches ErrInvalid
// (and ErrOverLimit when a document limit was hit). The problem text is cut
// to MaxProblemBytes because decoder errors may quote document content.
func decodeError(err error) error {
	return &ValidationError{Problems: []string{shortProblem(err.Error())}, overLimit: errors.Is(err, ErrOverLimit)}
}

// Family is the device family.
type Family string

// Device families. pfSense is later (ADR 0010 D9) and not accepted.
const (
	// FamilyCBS is a Cisco Business switch managed over the SSH CLI.
	FamilyCBS Family = "cbs"
	// FamilyPANOS is a PAN-OS firewall managed over the XML API.
	FamilyPANOS Family = "panos"
)

// PinKind says what the trust pin is a SHA-256 of.
type PinKind string

// Pin kinds (ADR 0010 D1).
const (
	// PinSSHHostKey is the SHA-256 of the SSH host public key in wire
	// format (CBS).
	PinSSHHostKey PinKind = "ssh-host-key"
	// PinTLSLeaf is the SHA-256 of the served leaf certificate DER (PAN-OS).
	PinTLSLeaf PinKind = "tls-leaf"
	// PinTLSCA is the SHA-256 of an admin-imported issuing CA DER (PAN-OS).
	PinTLSCA PinKind = "tls-ca"
)

// Endpoint is one ordered management endpoint, stored and dialled as an IP
// literal (ADR 0010 D1). Public, loopback, link-local, multicast and
// unspecified addresses are refused.
type Endpoint struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Device is the executor-owned identity of one managed network device: an
// immutable device_id, a family, ordered management endpoints, one trust
// pin and a trust generation. Names are labels and never authenticate a
// device; a device is never a managed host. Credentials and per-device keys
// are not part of this contract and never leave the executor.
type Device struct {
	DeviceID string `json:"device_id"`
	// Name is a display label only.
	Name      string     `json:"name,omitempty"`
	Family    Family     `json:"family"`
	Endpoints []Endpoint `json:"endpoints"`
	// TLSServerName is the expected SAN of a PAN-OS management
	// certificate, kept from the name the admin entered; it is never
	// resolved. CBS devices have none.
	TLSServerName   string  `json:"tls_server_name,omitempty"`
	PinKind         PinKind `json:"pin_kind"`
	TrustPin        string  `json:"trust_pin"`
	TrustGeneration uint64  `json:"trust_generation"`
}

var (
	deviceIDRe    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`) // length: MaxDeviceIDBytes
	fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dnsLabelRe    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidDeviceID reports whether s is a well-formed device_id: 1 to
// MaxDeviceIDBytes lowercase letters, digits and inner hyphens.
func ValidDeviceID(s string) bool { return len(s) <= MaxDeviceIDBytes && deviceIDRe.MatchString(s) }

// ValidTrustPin reports whether s is a lowercase hex SHA-256.
func ValidTrustPin(s string) bool { return fingerprintRe.MatchString(s) }

// ValidEndpointAddress reports whether s is a canonical IP literal that a
// device may be dialled at: a private (RFC 1918 or IPv6 ULA) address,
// without zone. Public, loopback, link-local, multicast and unspecified
// addresses are refused, as are host names, which are never dialled.
func ValidEndpointAddress(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.String() != s || a.Is4In6() {
		return false
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	return a.IsPrivate()
}

// validDNSName reports whether s is a lowercase DNS name.
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for l := range strings.SplitSeq(s, ".") {
		if !dnsLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidateDevice validates d and returns a copy with cloned endpoints. It
// never mutates d.
func ValidateDevice(d Device) (Device, error) {
	var p problems
	if !ValidDeviceID(d.DeviceID) {
		p.add("device_id is malformed")
	}
	if !validText(d.Name, MaxLabelBytes) {
		p.add("name is not printable UTF-8 of at most %d bytes", MaxLabelBytes)
	}
	switch d.Family {
	case FamilyCBS:
		if d.PinKind != PinSSHHostKey {
			p.add("cbs device requires pin_kind %q", PinSSHHostKey)
		}
		if d.TLSServerName != "" {
			p.add("cbs device must not have a tls_server_name")
		}
	case FamilyPANOS:
		if d.PinKind != PinTLSLeaf && d.PinKind != PinTLSCA {
			p.add("panos device requires pin_kind %q or %q", PinTLSLeaf, PinTLSCA)
		}
		if d.TLSServerName != "" && !validDNSName(d.TLSServerName) {
			p.add("tls_server_name is not a lowercase DNS name")
		}
	default:
		p.add("family %q is unknown", truncate(string(d.Family)))
	}

	switch {
	case len(d.Endpoints) == 0:
		p.add("at least one endpoint is required")
	case len(d.Endpoints) > MaxEndpointsPerDevice:
		p.count("endpoints", len(d.Endpoints), MaxEndpointsPerDevice)
	default:
		seen := map[Endpoint]struct{}{}
		for i, ep := range d.Endpoints {
			if !ValidEndpointAddress(ep.Address) {
				p.add("endpoint %d: address is not a canonical private IP literal", i)
			}
			if ep.Port == 0 {
				p.add("endpoint %d: port must be in 1..65535", i)
			}
			if _, dup := seen[ep]; dup {
				p.add("endpoint %d: duplicated", i)
			}
			seen[ep] = struct{}{}
		}
	}

	if !ValidTrustPin(d.TrustPin) {
		p.add("trust_pin must be 64 lowercase hex characters")
	}
	switch {
	case d.TrustGeneration == 0:
		p.add("trust_generation must be at least 1")
	case d.TrustGeneration > MaxTrustGeneration:
		p.add("trust_generation out of range")
	}

	if err := p.err(); err != nil {
		return Device{}, err
	}
	n := d
	n.Endpoints = slices.Clone(d.Endpoints)
	return n, nil
}

// DecodeDevice strictly decodes and validates one device document.
func DecodeDevice(raw []byte) (Device, error) {
	var d Device
	if err := decodeStrict(raw, &d); err != nil {
		return Device{}, decodeError(err)
	}
	return ValidateDevice(d)
}

// MarshalDevice validates d and returns its JSON encoding.
func MarshalDevice(d Device) ([]byte, error) {
	v, err := ValidateDevice(d)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// truncate shortens untrusted text quoted in a problem message.
func truncate(s string) string {
	const quoteLimit = 32
	if validText(s, quoteLimit) {
		return s
	}
	return "<invalid or long value>"
}
