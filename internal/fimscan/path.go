// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errBadBase64     = errors.New("not strict standard padded base64")
	errPathEmpty     = errors.New("empty path")
	errPathTooLong   = errors.New("path too long")
	errPathNUL       = errors.New("path contains NUL")
	errPathRelative  = errors.New("path is not absolute")
	errPathComponent = errors.New("path has an empty, . or .. component")
	errPathDepth     = errors.New("path too deep")
	errPathRoot      = errors.New("path is not below a profile root")
	errLinkEmpty     = errors.New("empty symlink target")
	errLinkTooLong   = errors.New("symlink target too long")
	errLinkNUL       = errors.New("symlink target contains NUL")
)

// decodeBase64 decodes strict standard padded base64 (RFC 4648 section 4)
// into at most maxDecoded bytes. Unlike encoding/base64 alone it rejects CR,
// LF and every other byte outside the alphabet, and it checks the length
// before decoding so an oversized value is never allocated.
func decodeBase64(s string, maxDecoded int) ([]byte, error) {
	if len(s) == 0 || len(s)%4 != 0 || len(s) > 4*((maxDecoded+2)/3) {
		return nil, errBadBase64
	}
	pad := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			if pad > 0 {
				return nil, errBadBase64
			}
		case c == '=':
			pad++
			if pad > 2 || i < len(s)-2 {
				return nil, errBadBase64
			}
		default:
			return nil, errBadBase64
		}
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > maxDecoded {
		return nil, errBadBase64
	}
	return b, nil
}

// validatePath checks the record path rules of spec 09 v26-09-01 that do not
// depend on the profile: at most MaxPathBytes, no NUL, absolute, no empty,
// "." or ".." component (so no "//" and no trailing "/"), at most
// MaxPathDepth components.
func validatePath(p []byte) error {
	switch {
	case len(p) == 0:
		return errPathEmpty
	case len(p) > MaxPathBytes:
		return errPathTooLong
	case bytes.IndexByte(p, 0) >= 0:
		return errPathNUL
	case p[0] != '/':
		return errPathRelative
	}
	depth := 0
	for rest := p[1:]; ; {
		i := bytes.IndexByte(rest, '/')
		comp := rest
		if i >= 0 {
			comp = rest[:i]
		}
		if len(comp) == 0 || bytes.Equal(comp, []byte(".")) || bytes.Equal(comp, []byte("..")) {
			return errPathComponent
		}
		depth++
		if depth > MaxPathDepth {
			return errPathDepth
		}
		if i < 0 {
			return nil
		}
		rest = rest[i+1:]
	}
}

// validateLink checks a decoded symlink target. The target is recorded,
// never followed or resolved here, so relative targets and ".." are allowed.
func validateLink(l []byte) error {
	switch {
	case len(l) == 0:
		return errLinkEmpty
	case len(l) > MaxLinkBytes:
		return errLinkTooLong
	case bytes.IndexByte(l, 0) >= 0:
		return errLinkNUL
	}
	return nil
}

// Root is one root of an approved scan profile (ADR 0015 D5). The pattern
// is absolute; a component may be a path.Match pattern (for example
// "/home/*/.ssh/authorized_keys*") that matches exactly one path component.
type Root struct {
	// Pattern is the root as written in the profile, for example "/etc".
	Pattern string
	// Optional marks a root the host may lack; a missing optional root is
	// absent, a missing non-optional root is skipped and the run partial.
	Optional bool
}

// Profile is the approved profile frozen by the read grant. It comes from
// NOS, never from the host.
type Profile struct {
	// ID is the profile ID, for example "fim-default-v1".
	ID string
	// Roots are the profile roots.
	Roots []Root
}

// ErrBadProfile is returned when the caller-supplied profile is unusable.
var ErrBadProfile = errors.New("fimscan: invalid profile")

func (p Profile) validate() error {
	if p.ID == "" || len(p.ID) > MaxProfileIDBytes || !isIDString(p.ID) {
		return fmt.Errorf("%w: bad profile ID", ErrBadProfile)
	}
	if len(p.Roots) == 0 {
		return fmt.Errorf("%w: no roots", ErrBadProfile)
	}
	seen := make(map[string]bool, len(p.Roots))
	for i, r := range p.Roots {
		if err := validatePath([]byte(r.Pattern)); err != nil {
			return fmt.Errorf("%w: root %d: %v", ErrBadProfile, i, err)
		}
		if !utf8.ValidString(r.Pattern) {
			return fmt.Errorf("%w: root %d: not UTF-8", ErrBadProfile, i)
		}
		for _, c := range strings.Split(r.Pattern[1:], "/") {
			if _, err := path.Match(c, ""); err != nil {
				return fmt.Errorf("%w: root %d: %v", ErrBadProfile, i, err)
			}
		}
		if seen[r.Pattern] {
			return fmt.Errorf("%w: duplicate root %d", ErrBadProfile, i)
		}
		seen[r.Pattern] = true
	}
	return nil
}

// matchRoot reports whether p (already checked by validatePath) is the root
// or lies below it, comparing component by component.
func matchRoot(pattern string, p []byte) bool {
	pc := strings.Split(pattern[1:], "/")
	rest := string(p[1:])
	for i, c := range pc {
		var comp string
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			comp, rest = rest, ""
			if i != len(pc)-1 {
				return false
			}
		} else {
			comp, rest = rest[:j], rest[j+1:]
		}
		ok, err := path.Match(c, comp)
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// isIDString reports whether s is a short identifier of [a-z0-9._-].
func isIDString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// EscapePath renders a host-supplied path or symlink target as text
// (ADR 0015 D6 "Display"): valid printable UTF-8 stays as is, every other
// byte becomes \xNN. Format characters (including bidi controls), control
// characters, non-ASCII spaces and the backslash itself are always escaped,
// so the output is unambiguous and contains no terminal or bidi controls.
func EscapePath(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n <= 1 || r == '\\' || !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			for _, c := range b[:max(n, 1)] {
				fmt.Fprintf(&sb, `\x%02x`, c)
			}
			b = b[max(n, 1):]
			continue
		}
		sb.Write(b[:n])
		b = b[n:]
	}
	return sb.String()
}
