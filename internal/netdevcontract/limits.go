// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netdevcontract defines the typed, validated data contracts for
// managed network devices (Cisco CBS switches, PAN-OS firewalls) and their
// phase-1 read observations, together with the named parse limits of
// ADR 0010 D3 (ticket ND-04).
//
// Everything a device returns is untrusted input. Decoding is strict:
// unknown fields, duplicate keys, null values, invalid UTF-8, control
// characters, oversize strings, counts and nesting are rejected. A dataset
// that could not be read is "unavailable" with a reason code, which is
// distinct from an available dataset that is empty, and from a list cut at
// its limit, which is "incomplete" and never silently truncated.
//
// The package has no dependency on the executor, server or proto packages.
package netdevcontract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// ErrOverLimit marks input that exceeds one of the named limits below.
// Callers can branch on it with errors.Is; a validation error caused by a
// limit also matches ErrInvalid.
var ErrOverLimit = errors.New("netdevcontract: over limit")

// Parse limits of ADR 0010 D3 ("Parse limits (both families)"). Bytes are
// capped before parsing, counts and depth while parsing. A list over its
// limit makes the dataset incomplete; a configuration or XML document over
// a limit is refused.
const (
	// MaxLineBytes bounds one line of CBS output (any command) and one line
	// of a redacted configuration.
	MaxLineBytes = 4 << 10
	// MaxConfigLines bounds the lines of a CBS show running-config or show
	// startup-config.
	MaxConfigLines = 100000
	// MaxInterfacesPerDevice bounds switch ports (CBS) per device.
	MaxInterfacesPerDevice = 1024
	// MaxVLANsPerDevice bounds VLANs per device (and allowed VLANs per port).
	MaxVLANsPerDevice = 4094
	// MaxMACEntriesPerDevice bounds MAC address table entries per device.
	MaxMACEntriesPerDevice = 8192
	// MaxLLDPNeighborsPerDevice bounds LLDP neighbors per device.
	MaxLLDPNeighborsPerDevice = 1024
	// MaxLLDPNeighborsPerPort bounds LLDP neighbors per local port.
	MaxLLDPNeighborsPerPort = 16
	// MaxXMLDepth bounds the element nesting depth of a PAN-OS response.
	MaxXMLDepth = 64
	// MaxXMLElements bounds the elements of one PAN-OS response.
	MaxXMLElements = 500000
	// MaxXMLTextBytes bounds the text of one XML element or attribute.
	MaxXMLTextBytes = 4 << 10
	// MaxSecurityRules bounds PAN-OS security rules.
	MaxSecurityRules = 10000
	// MaxNATRules bounds PAN-OS NAT rules.
	MaxNATRules = 5000
	// MaxAddressObjects bounds PAN-OS address objects.
	MaxAddressObjects = 20000
	// MaxServiceObjects bounds PAN-OS service objects.
	MaxServiceObjects = 20000
	// MaxAddressGroups bounds PAN-OS address groups.
	MaxAddressGroups = 5000
	// MaxServiceGroups bounds PAN-OS service groups.
	MaxServiceGroups = 5000
	// MaxGroupMembers bounds the static members of one group.
	MaxGroupMembers = 2500
	// MaxGroupNestingDepth bounds group nesting; a group whose members are
	// all plain objects has depth 1.
	MaxGroupNestingDepth = 8
	// MaxZones bounds PAN-OS zones.
	MaxZones = 256
	// MaxFirewallInterfaces bounds PAN-OS interfaces.
	MaxFirewallInterfaces = 1024
	// MaxHitCountEntries bounds rule hit-count entries; it is the
	// security-rule limit.
	MaxHitCountEntries = MaxSecurityRules
)

// Transport byte caps of ADR 0010 D3, applied before parsing.
const (
	// MaxCBSConfigOutputBytes caps the output of show running-config and
	// show startup-config.
	MaxCBSConfigOutputBytes = 4 << 20
	// MaxCBSCommandOutputBytes caps the output of every other CBS command.
	MaxCBSCommandOutputBytes = 1 << 20
	// MaxPANOSConfigResponseBytes caps one PAN-OS configuration response.
	MaxPANOSConfigResponseBytes = 8 << 20
	// MaxPANOSResponseBytes caps every other PAN-OS response.
	MaxPANOSResponseBytes = 1 << 20
)

// Contract limits added by ND-04 for fields the D3 table does not name.
// They bound the JSON documents exchanged between executor, collector and
// server.
const (
	// MaxDeviceIDBytes bounds a device_id slug.
	MaxDeviceIDBytes = 64
	// MaxLabelBytes bounds labels and short device text (names, model,
	// serial, firmware version, LLDP strings, port descriptions).
	MaxLabelBytes = 255
	// MaxDescriptionBytes bounds a PAN-OS rule or object description.
	MaxDescriptionBytes = 1024
	// MaxFilterBytes bounds a dynamic address group filter.
	MaxFilterBytes = 2048
	// MaxPANOSNameBytes bounds a PAN-OS rule or object name.
	MaxPANOSNameBytes = 63
	// MaxInterfaceNameBytes bounds an interface name.
	MaxInterfaceNameBytes = 64
	// MaxEndpointsPerDevice bounds the ordered management endpoints.
	MaxEndpointsPerDevice = 8
	// MaxManagementAddresses bounds management addresses in device facts.
	MaxManagementAddresses = 16
	// MaxAddressesPerInterface bounds IP addresses of one PAN-OS interface.
	MaxAddressesPerInterface = 16
	// MaxRuleMembers bounds the entries of one rule field (from, to,
	// source, destination, application, service, ...). It equals the group
	// member limit.
	MaxRuleMembers = MaxGroupMembers
	// MaxTagsPerObject bounds tags on one rule or object.
	MaxTagsPerObject = 64
	// MaxLLDPCapabilities bounds capabilities of one LLDP neighbor.
	MaxLLDPCapabilities = 16
	// MaxTrustGeneration bounds a trust generation counter.
	MaxTrustGeneration = uint64(1) << 48
	// MinObservedYear is the earliest accepted UTC year of a timestamp.
	MinObservedYear = 1
	// MaxObservedYear is the latest accepted UTC year of a timestamp.
	MaxObservedYear = 9999
)

// JSON document limits.
const (
	// MaxRedactedConfigBytes bounds the total bytes of one redacted
	// configuration (the larger PAN-OS configuration response cap).
	MaxRedactedConfigBytes = MaxPANOSConfigResponseBytes
	// MaxDocumentBytes bounds one JSON document: an observation may carry a
	// running and a startup configuration whose JSON escaping can at most
	// double them, plus 1 MiB for every other dataset.
	MaxDocumentBytes = 4*MaxRedactedConfigBytes + (1 << 20)
	// MaxJSONNesting bounds JSON nesting depth.
	MaxJSONNesting = 16
	// MaxJSONObjects bounds the JSON objects of one document; the largest
	// legal firewall policy has about 70,000.
	MaxJSONObjects = 200000
	// MaxJSONStringBytes bounds any decoded JSON string.
	MaxJSONStringBytes = MaxLineBytes
)

// overLimit returns an error matching ErrOverLimit.
func overLimit(what string, n, limit int) error {
	return fmt.Errorf("%w: %s: %d exceeds %d", ErrOverLimit, what, n, limit)
}

// CheckCount returns an error matching ErrOverLimit when n exceeds limit.
// Parsers call it while counting list entries.
func CheckCount(what string, n, limit int) error {
	if n > limit {
		return overLimit(what, n, limit)
	}
	return nil
}

// CheckLines enforces MaxLineBytes on every line of text and maxLines on
// the line count (MaxConfigLines for configurations). A trailing newline
// does not start another line. text must already be capped in bytes.
func CheckLines(text []byte, maxLines int) error {
	if !utf8.Valid(text) {
		return errors.New("netdevcontract: text is not valid UTF-8")
	}
	sc := bufio.NewScanner(bytes.NewReader(text))
	// One byte more than the limit plus the newline lets the scanner
	// report an oversize line instead of failing with a generic error.
	sc.Buffer(make([]byte, 0, 4096), MaxLineBytes+2)
	n := 0
	for sc.Scan() {
		n++
		if n > maxLines {
			return overLimit("lines", n, maxLines)
		}
		line := bytes.TrimSuffix(sc.Bytes(), []byte("\r"))
		if len(line) > MaxLineBytes {
			return overLimit("line bytes", len(line), MaxLineBytes)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return overLimit("line bytes", MaxLineBytes+1, MaxLineBytes)
		}
		return fmt.Errorf("netdevcontract: read lines: %w", err)
	}
	return nil
}

// CheckXML enforces the PAN-OS XML limits on one response before it is
// parsed: at most maxBytes bytes (MaxPANOSResponseBytes or
// MaxPANOSConfigResponseBytes), well-formed UTF-8 XML, no DTD or other
// directive, at most MaxXMLDepth nesting, MaxXMLElements elements and
// MaxXMLTextBytes per element text or attribute value.
func CheckXML(data []byte, maxBytes int) error {
	if len(data) > maxBytes {
		return overLimit("response bytes", len(data), maxBytes)
	}
	if !utf8.Valid(data) {
		return errors.New("netdevcontract: XML is not valid UTF-8")
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.CharsetReader = func(label string, _ io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("netdevcontract: XML charset %q refused", label)
	}
	var (
		depth, elements int
		text            []int // text bytes per open element
		root            bool
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("netdevcontract: malformed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if root {
					return errors.New("netdevcontract: XML has more than one root element")
				}
				root = true
			}
			depth++
			if depth > MaxXMLDepth {
				return overLimit("XML depth", depth, MaxXMLDepth)
			}
			elements++
			if elements > MaxXMLElements {
				return overLimit("XML elements", elements, MaxXMLElements)
			}
			for _, a := range t.Attr {
				if len(a.Value) > MaxXMLTextBytes {
					return overLimit("XML attribute bytes", len(a.Value), MaxXMLTextBytes)
				}
			}
			text = append(text, 0)
		case xml.EndElement:
			if depth == 0 {
				return errors.New("netdevcontract: unbalanced XML end element")
			}
			depth--
			text = text[:len(text)-1]
		case xml.CharData:
			if depth == 0 {
				if len(bytes.TrimSpace(t)) > 0 {
					return errors.New("netdevcontract: XML text outside the root element")
				}
				continue
			}
			text[len(text)-1] += len(t)
			if text[len(text)-1] > MaxXMLTextBytes {
				return overLimit("XML text bytes", text[len(text)-1], MaxXMLTextBytes)
			}
		case xml.Directive:
			return errors.New("netdevcontract: XML directives (DTD) are refused")
		case xml.ProcInst, xml.Comment:
			// the XML declaration and comments carry no data
		}
	}
	if depth != 0 {
		return errors.New("netdevcontract: XML ends inside an element")
	}
	if !root {
		return errors.New("netdevcontract: XML has no root element")
	}
	return nil
}

// validText reports whether s is valid UTF-8 of at most max bytes without
// control characters or replacement characters. Untrusted device text is
// always checked with it.
func validText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// validLine is validText for one configuration line, which may contain
// tabs.
func validLine(s string) bool {
	if len(s) > MaxLineBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\t') || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// decodeStrict enforces the document limits on raw and decodes exactly one
// JSON document into v, rejecting unknown fields.
func decodeStrict(raw []byte, v any) error {
	if len(raw) > MaxDocumentBytes {
		return overLimit("document bytes", len(raw), MaxDocumentBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("document is not valid UTF-8")
	}
	if err := walkDocument(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// walkDocument enforces nesting depth, duplicate keys, null values,
// per-string length and the object count, and that raw holds exactly one
// JSON value.
func walkDocument(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	objects := 0
	if err := walkValue(dec, 0, &objects); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

func walkValue(dec *json.Decoder, depth int, objects *int) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	switch v := tok.(type) {
	case nil:
		return errors.New("null values are not allowed")
	case string:
		if len(v) > MaxJSONStringBytes {
			return overLimit("string bytes", len(v), MaxJSONStringBytes)
		}
	case json.Delim:
		if depth >= MaxJSONNesting {
			return overLimit("JSON nesting", depth+1, MaxJSONNesting)
		}
		switch v {
		case '{':
			*objects++
			if *objects > MaxJSONObjects {
				return overLimit("JSON objects", *objects, MaxJSONObjects)
			}
			seen := map[string]struct{}{}
			for dec.More() {
				ktok, err := dec.Token()
				if err != nil {
					return fmt.Errorf("malformed JSON: %w", err)
				}
				key, ok := ktok.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("duplicate key %q", key)
				}
				seen[key] = struct{}{}
				if err := walkValue(dec, depth+1, objects); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walkValue(dec, depth+1, objects); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", v)
		}
		if _, err := dec.Token(); err != nil {
			return fmt.Errorf("malformed JSON: %w", err)
		}
	default:
		// numbers and booleans are range-checked by the typed fields
	}
	return nil
}
