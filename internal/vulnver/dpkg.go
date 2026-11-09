// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// DpkgVersion is a parsed Debian version [epoch:]upstream[-revision]
// (Debian Policy §5.6.12).
type DpkgVersion struct {
	// Epoch is the epoch; 0 when absent.
	Epoch uint32
	// Upstream is the upstream version; never empty, starts with a digit.
	Upstream string
	// Revision is the Debian revision; empty when absent.
	Revision string

	hasEpoch    bool
	hasRevision bool
}

// String returns the version in its original form.
func (v DpkgVersion) String() string {
	var b strings.Builder
	if v.hasEpoch {
		b.WriteString(strconv.FormatUint(uint64(v.Epoch), 10))
		b.WriteByte(':')
	}
	b.WriteString(v.Upstream)
	if v.hasRevision {
		b.WriteByte('-')
		b.WriteString(v.Revision)
	}
	return b.String()
}

// ParseDpkg parses a Debian version strictly:
//
//   - at most MaxVersionLen bytes, ASCII only, no whitespace;
//   - epoch: decimal digits up to math.MaxInt32 (dpkg's limit);
//   - upstream: non-empty, starts with a digit, characters [A-Za-z0-9.+~-];
//     hyphens only when a revision follows (the last hyphen splits);
//     no colons (current policy);
//   - revision: non-empty when a hyphen is present, characters
//     [A-Za-z0-9.+~].
//
// dpkg accepts some of these with a warning; NOS rejects them, so a version
// it cannot be sure about is "unknown", never compared.
func ParseDpkg(s string) (DpkgVersion, error) {
	var v DpkgVersion
	if len(s) == 0 {
		return v, fmt.Errorf("dpkg version: empty: %w", ErrInvalidVersion)
	}
	if len(s) > MaxVersionLen {
		return v, fmt.Errorf("dpkg version: %d bytes exceeds %d: %w", len(s), MaxVersionLen, ErrInvalidVersion)
	}
	rest := s
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		ep := rest[:i]
		if ep == "" {
			return v, fmt.Errorf("dpkg version %s: empty epoch: %w", quote(s), ErrInvalidVersion)
		}
		for j := 0; j < len(ep); j++ {
			if !isDigit(ep[j]) {
				return v, fmt.Errorf("dpkg version %s: epoch is not a number: %w", quote(s), ErrInvalidVersion)
			}
		}
		n, err := strconv.ParseUint(ep, 10, 32)
		if err != nil || n > math.MaxInt32 {
			return v, fmt.Errorf("dpkg version %s: epoch out of range: %w", quote(s), ErrInvalidVersion)
		}
		v.Epoch = uint32(n)
		v.hasEpoch = true
		rest = rest[i+1:]
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.Revision = rest[i+1:]
		v.hasRevision = true
		rest = rest[:i]
		if v.Revision == "" {
			return v, fmt.Errorf("dpkg version %s: empty revision: %w", quote(s), ErrInvalidVersion)
		}
		for j := 0; j < len(v.Revision); j++ {
			c := v.Revision[j]
			if !isAlnum(c) && c != '.' && c != '+' && c != '~' {
				return v, fmt.Errorf("dpkg version %s: invalid character in revision: %w", quote(s), ErrInvalidVersion)
			}
		}
	}
	v.Upstream = rest
	if v.Upstream == "" {
		return v, fmt.Errorf("dpkg version %s: empty upstream version: %w", quote(s), ErrInvalidVersion)
	}
	if !isDigit(v.Upstream[0]) {
		return v, fmt.Errorf("dpkg version %s: upstream version does not start with a digit: %w", quote(s), ErrInvalidVersion)
	}
	for j := 0; j < len(v.Upstream); j++ {
		c := v.Upstream[j]
		if !isAlnum(c) && c != '.' && c != '+' && c != '~' && c != '-' {
			return v, fmt.Errorf("dpkg version %s: invalid character in upstream version: %w", quote(s), ErrInvalidVersion)
		}
	}
	return v, nil
}

// CompareDpkg compares two Debian versions with dpkg's ordering and returns
// -1, 0 or +1. An unparseable version is an error wrapping
// ErrInvalidVersion.
func CompareDpkg(a, b string) (int, error) {
	va, err := ParseDpkg(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseDpkg(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// Compare compares v with w and returns -1, 0 or +1.
func (v DpkgVersion) Compare(w DpkgVersion) int {
	if v.Epoch != w.Epoch {
		if v.Epoch < w.Epoch {
			return -1
		}
		return 1
	}
	if c := verrevcmp(v.Upstream, w.Upstream); c != 0 {
		return c
	}
	return verrevcmp(v.Revision, w.Revision)
}

// dpkgOrder is dpkg's character weight: '~' sorts before everything,
// including the end of the string; letters sort before other characters.
// Digits and the end of the string weigh 0.
func dpkgOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's lib/dpkg/version.c verrevcmp: alternating non-digit
// and digit runs; non-digit runs compared by dpkgOrder, digit runs
// numerically.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := dpkgOrder(a, i), dpkgOrder(b, j)
			if ac != bc {
				return sign(ac - bc)
			}
			// ac == bc != 0 here, so neither side is at its end or a digit.
			i++
			j++
		}
		si := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		sj := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		da, db := a[si:i], b[sj:j]
		if da == "" {
			da = "0"
		}
		if db == "" {
			db = "0"
		}
		if c := compareDigits(da, db); c != 0 {
			return c
		}
	}
	return 0
}
