// SPDX-License-Identifier: AGPL-3.0-or-later

// Package softwarecat normalizes observed software identifiers (OS
// releases, container image references, package names, systemd units)
// to bounded catalog keys and display names, and persists the software
// catalog (ADR 0009 D5, D6).
//
// The normalizers (FromOSRelease, FromImage, FromPackage, FromUnit) are
// pure functions: no I/O, no network, no global state besides the
// embedded seed map. All inputs are untrusted host data (spec 09):
// processing is bounded, deterministic, and the output is always a
// valid key or the fallback key "unknown". Unknown identifiers are
// reported with Known=false.
//
// Store keeps the catalog in the server database (migration 0032): the
// ingest functions turn core.facts, docker.list, gpu.status and
// service.list results into observations per host, guest or container;
// a key without a catalog entry creates one in state "observed" (the
// unknown queue). Observations never create placements, assets or
// hosts. Admin changes (rename, merge, ignore, icons, per-asset icon
// overrides, rollback) are audited in the same transaction, and every
// icon change is kept in a history that a rollback can return to.
package softwarecat

import (
	"errors"
	"fmt"
	"strings"
)

// Key is a normalized software catalog key. It matches
// [a-z0-9][a-z0-9._-]{0,63}.
type Key string

// ErrInvalidKey reports an identifier that cannot be a catalog key.
var ErrInvalidKey = errors.New("softwarecat: invalid catalog key")

// maxKeyLen is the maximum length of a catalog key in bytes.
const maxKeyLen = 64

// maxInputLen bounds how much of an observed identifier is processed.
// Longer input is truncated before any processing, so hostile multi-KB
// identifiers cannot cause unbounded work.
const maxInputLen = 256

// unknownKey is returned when an identifier sanitizes to nothing.
const unknownKey = "unknown"

// NewKey validates s as a catalog key: 1 to 64 bytes, first byte a
// lowercase ASCII letter or digit, remaining bytes lowercase ASCII
// letters, digits, '.', '_' or '-'.
func NewKey(s string) (Key, error) {
	if len(s) == 0 || len(s) > maxKeyLen {
		return "", fmt.Errorf("softwarecat: key of length %d: %w", len(s), ErrInvalidKey)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			(i > 0 && (c == '.' || c == '_' || c == '-'))
		if !valid {
			return "", fmt.Errorf("softwarecat: key byte %q at position %d: %w", c, i, ErrInvalidKey)
		}
	}
	return Key(s), nil
}

// Result is the outcome of normalizing one observed identifier.
//
// Key is always a valid catalog key. For known identifiers Display is
// the seed map's display name and Known is true; for unknown
// identifiers Display is empty and Known is false, and Key is a
// sanitized form of the identifier suitable for creating an "observed"
// catalog entry.
type Result struct {
	Key     Key
	Display string
	Known   bool
}

// prepare bounds and case-folds an untrusted identifier. It truncates
// to maxInputLen bytes first, before any other processing, and then
// lowercases ASCII letters only. Non-ASCII bytes are left untouched, so
// Unicode case folding can never map a homoglyph (Kelvin sign U+212A,
// dotted capital I U+0130) onto an ASCII seed identifier. Every
// normalizer goes through prepare, so all of them agree on how an
// identifier is folded.
func prepare(s string) string {
	if len(s) > maxInputLen {
		s = s[:maxInputLen]
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// isSep reports whether c is a key separator byte.
func isSep(c byte) bool {
	return c == '-' || c == '.' || c == '_'
}

// sanitize maps an observed identifier onto the key character set.
// The input is passed through prepare (truncation, ASCII-only
// lowercasing), digits and '.', '_', '-' are kept, every other byte
// (control characters, non-ASCII, punctuation) becomes a single '-',
// the result is truncated to maxKeyLen bytes and leading and trailing
// separators are stripped. An empty result becomes "unknown".
func sanitize(s string) string {
	s = prepare(s)
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || isSep(c):
			b = append(b, c)
		default:
			if len(b) > 0 && b[len(b)-1] != '-' {
				b = append(b, '-')
			}
		}
	}
	for len(b) > 0 && isSep(b[0]) {
		b = b[1:]
	}
	if len(b) > maxKeyLen {
		b = b[:maxKeyLen]
	}
	for len(b) > 0 && isSep(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return unknownKey
	}
	return string(b)
}

// lookup resolves a sanitized identifier against the seed map.
func lookup(id string) Result {
	e, ok := seed[id]
	if !ok {
		return Result{Key: Key(id), Known: false}
	}
	return Result{Key: Key(e.key), Display: e.display, Known: true}
}

// FromOSRelease normalizes the ID field of /etc/os-release. If proxmox
// is true the host runs Proxmox VE and the key is "proxmox-ve"
// regardless of the ID field.
func FromOSRelease(id string, proxmox bool) Result {
	if proxmox {
		return lookup("proxmox-ve")
	}
	return lookup(sanitize(id))
}

// FromImage normalizes a container image reference to the final
// repository name: registry host, "library/" namespace, tag and digest
// are stripped. docker.io/library/postgres:16 becomes "postgres",
// ghcr.io/foo/bar@sha256:... becomes "bar", netbirdio/netbird becomes
// "netbird".
func FromImage(ref string) Result {
	ref = prepare(ref)
	// Strip digest.
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	// Strip tag: a ':' counts as a tag separator only after the last
	// '/', so registry ports survive.
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		if j := strings.LastIndexByte(ref, ':'); j > i {
			ref = ref[:j]
		}
	} else if j := strings.LastIndexByte(ref, ':'); j >= 0 {
		ref = ref[:j]
	}
	// Strip registry host: a first path segment containing '.' or ':'
	// is a host (docker.io, ghcr.io, localhost:5000).
	if i := strings.IndexByte(ref, '/'); i >= 0 {
		if strings.ContainsAny(ref[:i], ".:") {
			ref = ref[i+1:]
		}
	}
	// Strip the Docker Hub "library/" namespace.
	if i := strings.IndexByte(ref, '/'); i >= 0 && ref[:i] == "library" {
		ref = ref[i+1:]
	}
	// Final repository name.
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		ref = ref[i+1:]
	}
	return lookup(sanitize(ref))
}

// FromPackage normalizes an OS package name. Version-like trailing
// segments are stripped while looking up the seed map, so
// nvidia-driver-550 maps to "nvidia" and influxdb2 to "influxdb".
// Unknown packages are returned with their version segments stripped
// as well, so different versions of the same unknown software share
// one "observed" key; the version stays in the observation record.
func FromPackage(name string) Result {
	id := sanitize(name)
	if r := lookup(id); r.Known {
		return r
	}
	for {
		i := strings.LastIndexByte(id, '-')
		if i <= 0 || !isVersionSegment(id[i+1:]) {
			break
		}
		id = id[:i]
		if r := lookup(id); r.Known {
			return r
		}
	}
	return Result{Key: Key(id), Known: false}
}

// isVersionSegment reports whether s is a version-like segment:
// digits and dots only, non-empty.
func isVersionSegment(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// unitSuffixes are the systemd unit type suffixes stripped before
// lookup.
var unitSuffixes = []string{
	".service", ".socket", ".timer", ".target", ".path",
	".mount", ".swap", ".slice", ".scope",
}

// FromUnit normalizes a systemd unit name: the template part after '@'
// and the unit type suffix are stripped, so postgresql@16.service
// maps to "postgres" and nginx.service to "nginx".
func FromUnit(name string) Result {
	n := prepare(name)
	if i := strings.IndexByte(n, '@'); i >= 0 {
		n = n[:i]
	}
	for _, suf := range unitSuffixes {
		if strings.HasSuffix(n, suf) {
			n = n[:len(n)-len(suf)]
			break
		}
	}
	return lookup(sanitize(n))
}
