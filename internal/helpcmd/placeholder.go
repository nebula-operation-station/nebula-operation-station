// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// PlaceholderClass is the value class of a documentation placeholder `<name>`
// (ADR 0014 D4, "Matching (V3)"). The table from placeholder names to classes
// is fixed and reviewed; a new name is added by review, never by a suffix
// rule. ClassNone is the zero value and is not a class: a name outside the
// table has no class, and there is no default class.
type PlaceholderClass int

const (
	// ClassNone is the zero value. It is returned for unknown names and is
	// never a valid class for a value check.
	ClassNone PlaceholderClass = iota
	// ClassHost is an IPv4 address or DNS name; an IPv6 literal only as a
	// whole token. Host values are also checked against the trusted host set
	// (V5), which is not part of this file.
	ClassHost
	// ClassDate is a calendar date in the form YYYY-MM-DD.
	ClassDate
	// ClassVersion is a release version such as 1.4.0 or 1.4.0-rc.1.
	ClassVersion
	// ClassID is an identifier with no `.` and no `:`, so it is never a DNS
	// name or an IP literal.
	ClassID
)

// String returns the class name used in messages.
func (c PlaceholderClass) String() string {
	switch c {
	case ClassHost:
		return "host"
	case ClassDate:
		return "date"
	case ClassVersion:
		return "version"
	case ClassID:
		return "id"
	default:
		return "none(" + strconv.Itoa(int(c)) + ")"
	}
}

// ErrNoPlaceholderClass is returned when a value is checked against a name
// that has no class (or against a class value outside the table).
var ErrNoPlaceholderClass = errors.New("placeholder has no class")

// ErrPlaceholderValue is returned when a value does not have the shape of its
// placeholder's class. Callers check it with errors.Is.
var ErrPlaceholderValue = errors.New("value does not match the placeholder class")

// Limits of the placeholder classes, named next to the code that enforces them.
const (
	// maxHostBytes is the longest host value and DNS name, in bytes (ADR 0014 D4).
	maxHostBytes = 253
	// maxDNSLabelBytes is the longest DNS label, in bytes (ADR 0014 D4).
	maxDNSLabelBytes = 63
	// maxIDBytes is the longest id value, in bytes (ADR 0014 D4).
	maxIDBytes = 128
)

// hostForbidden are the characters no host value may contain (ADR 0014 D4).
// `:` is handled separately, because it is allowed in a whole-token IPv6 literal.
const hostForbidden = "/@?#%"

var (
	// versionPattern is the version class of ADR 0014 D4: one to four digits,
	// two more dotted parts, and an optional prerelease of one dot-free word
	// plus at most one digits-only part (e.g. 1.4.0-rc.1).
	versionPattern = regexp.MustCompile(`^[0-9]{1,4}(\.[0-9]{1,4}){2}(-[A-Za-z0-9]{1,16}(\.[0-9]{1,4})?)?$`)
	// datePattern is the date class of ADR 0014 D4: YYYY-MM-DD, shape only.
	datePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	// idPattern is the id alphabet of ADR 0014 D4; the length is checked
	// separately against maxIDBytes.
	idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// LookupPlaceholder returns the class of a placeholder name, given without
// the angle brackets (`host`, not `<host>`). The match is exact: no suffix
// rule, no case folding, no default. An unknown name returns ClassNone and
// false.
func LookupPlaceholder(name string) (PlaceholderClass, bool) {
	switch name {
	case "host", "host-address", "ip", "rp-id", "firewall-mgmt-ip":
		return ClassHost, true
	case "date":
		return ClassDate, true
	case "version":
		return ClassVersion, true
	case "digest", "execution-id", "id":
		return ClassID, true
	default:
		return ClassNone, false
	}
}

// CheckPlaceholderValue checks that the whole of value has the shape of class
// (ADR 0014 D4). wholeToken reports whether the placeholder is the whole
// token of the doc shape; only for ClassHost does it matter, because an IPv6
// literal is a host value only then. It returns ErrNoPlaceholderClass for
// ClassNone and for any class value outside the table, and an error wrapping
// ErrPlaceholderValue when the value is not of the class shape.
func CheckPlaceholderValue(class PlaceholderClass, value string, wholeToken bool) error {
	switch class {
	case ClassHost:
		return checkHostValue(value, wholeToken)
	case ClassDate:
		return checkShape(class, value, datePattern)
	case ClassVersion:
		return checkShape(class, value, versionPattern)
	case ClassID:
		if len(value) > maxIDBytes {
			return fmt.Errorf("%w: id of %d bytes is longer than %d", ErrPlaceholderValue, len(value), maxIDBytes)
		}
		return checkShape(class, value, idPattern)
	default:
		return fmt.Errorf("%w: class %s", ErrNoPlaceholderClass, class)
	}
}

// checkShape reports ErrPlaceholderValue unless the whole value matches pattern.
func checkShape(class PlaceholderClass, value string, pattern *regexp.Regexp) error {
	if !pattern.MatchString(value) {
		return fmt.Errorf("%w: %q is not a %s value", ErrPlaceholderValue, value, class)
	}
	return nil
}

// checkHostValue implements the host class of ADR 0014 D4. A value is an IPv4
// dotted quad or a DNS name; an IPv6 literal only when wholeToken is set.
// Forbidden characters are rejected before the shape is checked.
func checkHostValue(value string, wholeToken bool) error {
	if len(value) == 0 || len(value) > maxHostBytes {
		return fmt.Errorf("%w: host of %d bytes is outside 1..%d", ErrPlaceholderValue, len(value), maxHostBytes)
	}
	if strings.Contains(value, ":") {
		if !wholeToken {
			return fmt.Errorf("%w: host %q contains ':' outside a whole-token IPv6 literal", ErrPlaceholderValue, value)
		}
		return checkIPv6Literal(value)
	}
	if i := strings.IndexAny(value, hostForbidden); i >= 0 {
		return fmt.Errorf("%w: host %q contains forbidden character %q", ErrPlaceholderValue, value, value[i])
	}
	labels := strings.Split(value, ".")
	if len(labels) == 4 && allLabelsNumeric(labels) {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return fmt.Errorf("%w: host %q is not a valid IPv4 address", ErrPlaceholderValue, value)
		}
		return nil
	}
	for _, label := range labels {
		if err := checkDNSLabel(label); err != nil {
			return fmt.Errorf("%w: host %q: %v", ErrPlaceholderValue, value, err)
		}
	}
	return nil
}

// checkIPv6Literal accepts a plain IPv6 address with no zone. The `%` zone
// separator is rejected before parsing, because netip would accept a zone.
func checkIPv6Literal(value string) error {
	if strings.Contains(value, "%") {
		return fmt.Errorf("%w: host %q contains a zone", ErrPlaceholderValue, value)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is6() {
		return fmt.Errorf("%w: host %q is not an IPv6 literal", ErrPlaceholderValue, value)
	}
	return nil
}

// checkDNSLabel accepts one label of 1 to maxDNSLabelBytes bytes from
// [A-Za-z0-9-] that neither starts nor ends with `-`.
func checkDNSLabel(label string) error {
	if len(label) == 0 || len(label) > maxDNSLabelBytes {
		return fmt.Errorf("label of %d bytes is outside 1..%d", len(label), maxDNSLabelBytes)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with '-'", label)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c == '-' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')) {
			return fmt.Errorf("label %q contains a character outside [A-Za-z0-9-]", label)
		}
	}
	return nil
}

// allLabelsNumeric reports whether every label is a non-empty run of ASCII
// digits, the form of a dotted IPv4 address.
func allLabelsNumeric(labels []string) bool {
	for _, label := range labels {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			if label[i] < '0' || label[i] > '9' {
				return false
			}
		}
	}
	return true
}
