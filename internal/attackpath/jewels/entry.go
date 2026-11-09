// SPDX-License-Identifier: AGPL-3.0-or-later

package jewels

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
)

// MaxExposed bounds the nodes one entry class lists as exposed; more are
// cut and the class is marked truncated.
const MaxExposed = attackpath.MaxNodes

// EntryClass is a synthetic attack-path entry (ADR 0011 D10).
type EntryClass string

// Entry classes. NetBird peers are their own class, never part of the
// internet class.
const (
	EntryInternet EntryClass = "internet"
	EntryNetBird  EntryClass = "netbird"
)

// Coverage says whether NOS has the data an entry class needs.
type Coverage string

// Coverage values. Unknown is never read as "not exposed".
const (
	CoverageKnown   Coverage = "known"
	CoverageUnknown Coverage = "unknown"
)

// Exposure is what one data source says an entry class reaches.
type Exposure struct {
	// Nodes are the attack-path node IDs the class reaches directly.
	// Invalid IDs and entry IDs are dropped and counted.
	Nodes []string
}

// EntryInputs are the data sources of the entry classes. A nil source means
// NOS has no such data, and the class is unknown.
type EntryInputs struct {
	// Internet is the exposure from firewall NAT and allow rules from
	// outside (ADR 0010). Until ADR 0010 delivers rule data it is nil.
	Internet *Exposure
	// NetBird is the set of nodes NetBird peers reach.
	NetBird *Exposure
}

// EntryState is one entry class as the attack-path search and the UI see
// it.
type EntryState struct {
	Class EntryClass
	// Node is the attack-path entry node ID.
	Node string
	// Label is the display label.
	Label string
	// Coverage says whether the class has data.
	Coverage Coverage
	// Reason explains an unknown coverage.
	Reason string
	// Exposed are the valid exposed node IDs, sorted and unique.
	Exposed []string
	// Dropped counts invalid node IDs left out of Exposed.
	Dropped int
	// Truncated is set when more than MaxExposed nodes were given.
	Truncated bool
}

// Reasons shown for unknown coverage.
const (
	reasonNoFirewall = "no firewall NAT or allow rule data yet (ADR 0010); internet exposure is unknown, not absent"
	reasonNoNetBird  = "no NetBird peer data; NetBird exposure is unknown, not absent"
)

// EntryClasses returns the states of the internet and NetBird classes, in
// that order.
func EntryClasses(in EntryInputs) []EntryState {
	return []EntryState{
		entryState(EntryInternet, attackpath.InternetID, "Internet", in.Internet, reasonNoFirewall),
		entryState(EntryNetBird, attackpath.NetBirdID, "NetBird peers", in.NetBird, reasonNoNetBird),
	}
}

func entryState(c EntryClass, node, label string, src *Exposure, reason string) EntryState {
	s := EntryState{Class: c, Node: node, Label: label}
	if src == nil {
		s.Coverage, s.Reason = CoverageUnknown, reason
		return s
	}
	s.Coverage = CoverageKnown
	valid := make([]string, 0, min(len(src.Nodes), MaxExposed))
	for _, id := range src.Nodes {
		if err := validExposed(id); err != nil {
			s.Dropped++
			continue
		}
		valid = append(valid, id)
	}
	valid = sortedUnique(valid)
	if len(valid) > MaxExposed {
		valid, s.Truncated = valid[:MaxExposed], true
	}
	s.Exposed = valid
	return s
}

// exposableKinds are the node kinds an entry class can reach: every
// non-entry kind, unmanaged endpoints included.
var exposableKinds = append([]attackpath.NodeKind{attackpath.NodeUnmanaged}, markableKinds...)

// validExposed checks an exposed node ID like NodeKind, but also accepts
// unmanaged endpoints.
func validExposed(id string) error {
	if id == "" || len(id) > attackpath.MaxIDBytes || !utf8.ValidString(id) {
		return fmt.Errorf("exposed node: %w", ErrInvalidNode)
	}
	if strings.IndexFunc(id, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return fmt.Errorf("exposed node: %w", ErrInvalidNode)
	}
	for _, k := range exposableKinds {
		p := k.IDPrefix()
		if strings.HasPrefix(id, p) && len(id) > len(p) {
			return nil
		}
	}
	return fmt.Errorf("exposed node kind: %w", ErrInvalidNode)
}

// exposes reports whether s lists node.
func (s EntryState) exposes(node string) bool {
	_, found := slices.BinarySearch(s.Exposed, node)
	return found
}

// EntryExposure returns the vulnprio exposure the entry classes give node
// (ADR 0011 D7), and false when every class is known and none reaches it,
// so that listener data has to decide between internal and no listener.
// An unknown internet class makes every node not known to be
// internet-facing ExposureUnknown: unknown is never read as internal.
func EntryExposure(states []EntryState, node string) (vulnprio.Exposure, bool) {
	var internet, netbird *EntryState
	for i := range states {
		switch states[i].Class {
		case EntryInternet:
			internet = &states[i]
		case EntryNetBird:
			netbird = &states[i]
		}
	}
	if internet == nil || internet.Coverage != CoverageKnown || internet.Truncated {
		if internet != nil && internet.exposes(node) {
			return vulnprio.ExposureInternet, true
		}
		return vulnprio.ExposureUnknown, true
	}
	if internet.exposes(node) {
		return vulnprio.ExposureInternet, true
	}
	if netbird == nil || netbird.Coverage != CoverageKnown || netbird.Truncated {
		if netbird != nil && netbird.exposes(node) {
			return vulnprio.ExposureVPNEntry, true
		}
		return vulnprio.ExposureUnknown, true
	}
	if netbird.exposes(node) {
		return vulnprio.ExposureVPNEntry, true
	}
	return "", false
}
