// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnver compares package versions the way the distributions do,
// so that NOS can re-check a vulnerability finding's "installed < fixed"
// arithmetic itself (ADR 0011 D4, plan item VU-03).
//
// It implements:
//
//   - dpkg version ordering for Debian and Ubuntu (Debian Policy §5.6.12),
//   - apk version ordering for Alpine,
//   - OSV "ECOSYSTEM" range evaluation for these ecosystems,
//   - the version basis rules of ADR 0011 D4: comparisons use the
//     installed binary's source version, the lowest source version wins
//     when binaries of one source disagree, and the running kernel is
//     identified by its unsigned kernel source package.
//
// The package does no I/O. All inputs are treated as untrusted: they are
// length-limited, must be ASCII in the syntax the distribution allows, and
// anything that does not parse is an error, never a guess. Callers treat an
// error as "unknown", never as "not affected".
package vulnver

import (
	"errors"
	"fmt"
	"strconv"
)

// MaxVersionLen is the longest version string accepted, in bytes.
const MaxVersionLen = 256

// maxQuotedInput bounds how much of a rejected input appears in an error.
const maxQuotedInput = 40

// Sentinel errors. Callers branch on them with errors.Is.
var (
	// ErrInvalidVersion reports a version string that does not parse in
	// the scheme it is compared in.
	ErrInvalidVersion = errors.New("invalid version")
	// ErrUnsupportedEcosystem reports an ecosystem without a version
	// scheme in this package.
	ErrUnsupportedEcosystem = errors.New("unsupported ecosystem")
	// ErrInvalidRange reports a malformed OSV range.
	ErrInvalidRange = errors.New("invalid range")
	// ErrUnsupportedRange reports an OSV range type other than ECOSYSTEM.
	ErrUnsupportedRange = errors.New("unsupported range type")
	// ErrNoBasis reports that no version basis can be determined for a
	// source package (no installed binary, missing or invalid source
	// versions).
	ErrNoBasis = errors.New("no version basis")
	// ErrNotVersionBasis reports a source package whose versions never
	// serve as a basis: signed and meta kernel sources (ADR 0011 D4).
	ErrNotVersionBasis = errors.New("source package is never a version basis")
	// ErrKernelUnknown reports that the running kernel's source version
	// cannot be determined ("kernel version unknown", ADR 0011 D4).
	ErrKernelUnknown = errors.New("kernel version unknown")
)

// Scheme is a version ordering.
type Scheme int

// Supported schemes.
const (
	// SchemeDpkg is the Debian/Ubuntu dpkg ordering.
	SchemeDpkg Scheme = iota + 1
	// SchemeAPK is the Alpine apk ordering.
	SchemeAPK
)

// String returns the scheme name.
func (s Scheme) String() string {
	switch s {
	case SchemeDpkg:
		return "dpkg"
	case SchemeAPK:
		return "apk"
	default:
		return "unknown"
	}
}

// Compare compares a and b in scheme s. It returns -1, 0 or +1.
func Compare(s Scheme, a, b string) (int, error) {
	switch s {
	case SchemeDpkg:
		return CompareDpkg(a, b)
	case SchemeAPK:
		return CompareAPK(a, b)
	default:
		return 0, fmt.Errorf("compare: scheme %d: %w", int(s), ErrUnsupportedEcosystem)
	}
}

// Validate reports whether v parses in scheme s.
func Validate(s Scheme, v string) error {
	switch s {
	case SchemeDpkg:
		_, err := ParseDpkg(v)
		return err
	case SchemeAPK:
		_, err := ParseAPK(v)
		return err
	default:
		return fmt.Errorf("validate: scheme %d: %w", int(s), ErrUnsupportedEcosystem)
	}
}

// Affected reports whether installed < fixed in scheme s. Both versions are
// source versions (ADR 0011 D4); the caller must not pass a binary version.
func Affected(s Scheme, installed, fixed string) (bool, error) {
	c, err := Compare(s, installed, fixed)
	if err != nil {
		return false, fmt.Errorf("affected: %w", err)
	}
	return c < 0, nil
}

// quote renders an untrusted input for an error message: quoted, escaped
// and truncated.
func quote(s string) string {
	if len(s) > maxQuotedInput {
		return strconv.Quote(s[:maxQuotedInput]) + "..."
	}
	return strconv.Quote(s)
}

// sign maps an int to -1, 0 or +1.
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// compareDigits compares two non-empty ASCII digit strings numerically
// without converting them, so arbitrarily long numbers cannot overflow.
func compareDigits(a, b string) int {
	for len(a) > 1 && a[0] == '0' {
		a = a[1:]
	}
	for len(b) > 1 && b[0] == '0' {
		b = b[1:]
	}
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return sign(int(a[i]) - int(b[i]))
		}
	}
	return 0
}
