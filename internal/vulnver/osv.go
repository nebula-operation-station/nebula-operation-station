// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnver

import (
	"fmt"
	"sort"
	"strings"
)

// Limits for OSV range evaluation.
const (
	// MaxRanges is the most ranges evaluated for one affected package.
	MaxRanges = 64
	// MaxRangeEvents is the most events in one range.
	MaxRangeEvents = 256
	// maxEcosystemLen bounds an ecosystem identifier.
	maxEcosystemLen = 64
)

// RangeEcosystem is the only OSV range type evaluated: versions ordered by
// the ecosystem's own scheme. SEMVER and GIT ranges are rejected.
const RangeEcosystem = "ECOSYSTEM"

// EventKind is the kind of an OSV range event.
type EventKind int

// OSV range event kinds.
const (
	// EventIntroduced starts an affected window; version "0" means "from
	// the beginning".
	EventIntroduced EventKind = iota + 1
	// EventFixed ends a window, exclusive.
	EventFixed
	// EventLastAffected ends a window, inclusive.
	EventLastAffected
	// EventLimit caps the whole range, exclusive.
	EventLimit
)

// Event is one OSV range event.
type Event struct {
	// Kind is the event kind.
	Kind EventKind
	// Version is the event's version in the ecosystem's scheme.
	Version string
}

// Range is one OSV range of an affected package.
type Range struct {
	// Type is the OSV range type; only RangeEcosystem is evaluated.
	Type string
	// Events are the range's events, in any order.
	Events []Event
}

// SchemeForEcosystem returns the version scheme for a finding ecosystem
// (ADR 0011 D2): "debian:<codename>" and "ubuntu:<release>" use dpkg,
// "alpine:<x.y>" uses apk. Every other ecosystem (language ecosystems,
// vendor, proxmox) is ErrUnsupportedEcosystem: NOS cannot re-check it.
func SchemeForEcosystem(eco string) (Scheme, error) {
	if len(eco) > maxEcosystemLen {
		return 0, fmt.Errorf("ecosystem %s: too long: %w", quote(eco), ErrUnsupportedEcosystem)
	}
	name, release, ok := strings.Cut(eco, ":")
	if !ok || release == "" {
		return 0, fmt.Errorf("ecosystem %s: %w", quote(eco), ErrUnsupportedEcosystem)
	}
	for i := 0; i < len(release); i++ {
		c := release[i]
		if !isAlnum(c) && c != '.' && c != '-' {
			return 0, fmt.Errorf("ecosystem %s: invalid release: %w", quote(eco), ErrUnsupportedEcosystem)
		}
	}
	switch name {
	case "debian", "ubuntu":
		return SchemeDpkg, nil
	case "alpine":
		return SchemeAPK, nil
	default:
		return 0, fmt.Errorf("ecosystem %s: %w", quote(eco), ErrUnsupportedEcosystem)
	}
}

// OSVAffected reports whether version (a source version, ADR 0011 D4) lies
// in any of the OSV ranges, following the OSV schema's evaluation: events
// sorted by version, "introduced" opens a window, "fixed" closes it before
// its version, "last_affected" closes it after its version, and "limit"
// caps the range. Every range must be of type ECOSYSTEM, have at least one
// "introduced" event and not mix "fixed" with "last_affected". Any invalid
// input is an error and the result is then false; callers treat it as
// unknown, never as "not affected".
func OSVAffected(s Scheme, version string, ranges []Range) (bool, error) {
	if err := Validate(s, version); err != nil {
		return false, fmt.Errorf("osv: installed version: %w", err)
	}
	if len(ranges) > MaxRanges {
		return false, fmt.Errorf("osv: %d ranges exceed %d: %w", len(ranges), MaxRanges, ErrInvalidRange)
	}
	affected := false
	for i, r := range ranges {
		in, err := inRange(s, version, r)
		if err != nil {
			return false, fmt.Errorf("osv: range %d: %w", i, err)
		}
		affected = affected || in
	}
	return affected, nil
}

// inRange evaluates one range. It validates the whole range before
// deciding, so a malformed tail is never ignored.
func inRange(s Scheme, version string, r Range) (bool, error) {
	if r.Type != RangeEcosystem {
		return false, fmt.Errorf("type %s: %w", quote(r.Type), ErrUnsupportedRange)
	}
	if len(r.Events) == 0 {
		return false, fmt.Errorf("no events: %w", ErrInvalidRange)
	}
	if len(r.Events) > MaxRangeEvents {
		return false, fmt.Errorf("%d events exceed %d: %w", len(r.Events), MaxRangeEvents, ErrInvalidRange)
	}
	var introduced, fixed, lastAffected bool
	for i, e := range r.Events {
		switch e.Kind {
		case EventIntroduced:
			introduced = true
			if e.Version == "0" {
				continue
			}
		case EventFixed:
			fixed = true
		case EventLastAffected:
			lastAffected = true
		case EventLimit:
		default:
			return false, fmt.Errorf("event %d: unknown kind %d: %w", i, int(e.Kind), ErrInvalidRange)
		}
		if err := Validate(s, e.Version); err != nil {
			return false, fmt.Errorf("event %d: %w", i, err)
		}
	}
	if !introduced {
		return false, fmt.Errorf("no introduced event: %w", ErrInvalidRange)
	}
	if fixed && lastAffected {
		return false, fmt.Errorf("both fixed and last_affected: %w", ErrInvalidRange)
	}

	// All versions are valid now, so cmp cannot fail.
	cmp := func(a, b string) int {
		c, _ := Compare(s, a, b)
		return c
	}
	events := make([]Event, len(r.Events))
	copy(events, r.Events)
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		az, bz := a.Kind == EventIntroduced && a.Version == "0", b.Kind == EventIntroduced && b.Version == "0"
		if az || bz {
			return az && !bz
		}
		if c := cmp(a.Version, b.Version); c != 0 {
			return c < 0
		}
		// At equal versions an introduced event comes first, so that
		// "introduced X, fixed X" is an empty window.
		return a.Kind == EventIntroduced && b.Kind != EventIntroduced
	})

	affected := false
	for _, e := range events {
		switch e.Kind {
		case EventIntroduced:
			if e.Version == "0" || cmp(version, e.Version) >= 0 {
				affected = true
			}
		case EventFixed:
			if cmp(version, e.Version) >= 0 {
				affected = false
			}
		case EventLastAffected:
			if cmp(version, e.Version) > 0 {
				affected = false
			}
		}
	}
	for _, e := range events {
		if e.Kind == EventLimit && cmp(version, e.Version) >= 0 {
			return false, nil
		}
	}
	return affected, nil
}
