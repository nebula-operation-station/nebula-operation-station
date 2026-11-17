// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsfacts builds the fixed projection the ops agent reads (ADR 0016
// D3 to D5). The projection, not the agent, is the security boundary: every
// value that leaves this package is a field of one of the structs in this
// file or in project.go. The external class (ExternalProjection) carries
// counters only.
//
// The package imports no module package. Its inputs are plain values that the
// caller converts from the enum types of vulnprio, vulnfix and inventory; the
// conversion is the caller's, and the enum values here are the same strings.
// Because no module package is reachable, no store (inventory, vulnstore,
// sshtransport, hostrun, ...) can be reached either. The import-boundary test
// enforces both with an allowlist, so a new import fails until it is reviewed.
//
// Every finding, host and listener value is untrusted input. A value that
// fails its check drops only its own finding, host or group; the drop is
// reported to an Auditor. Errors of a source (a failed read) still fail the
// whole projection, because a partial read could hide findings.
package opsfacts

import (
	"context"
	"errors"
)

// Limits. Each is enforced by the code that uses it (ADR 0016 D4). The
// input limits (package, version, vulnerability ID, subject ID) are in
// clean.go, next to their patterns.
const (
	// MaxFindingsPerGroup is the number of findings a group lists, by
	// score. Further findings are counted per tier.
	MaxFindingsPerGroup = 40
	// MaxPortsPerHost is the number of listening ports a host projection
	// lists, lowest number first. Further ports are counted.
	MaxPortsPerHost = 32
	// MaxLabelBytes bounds the host label after cleaning.
	MaxLabelBytes = 64
	// MaxEnvironmentBytes bounds the environment name after cleaning.
	MaxEnvironmentBytes = 32
	// MaxScore is the highest priority score (vu-prio-v1 / v2).
	MaxScore = 100
	// MaxCandidatesPerGroup bounds step candidates; the allowlist has
	// fewer actions than this, so the bound is a guard, not a cut.
	MaxCandidatesPerGroup = 8
	// MaxItemBytes bounds the canonical JSON of one group projection
	// (ADR 0016 D4).
	MaxItemBytes = 32 << 10
)

// Sentinel errors that callers branch on.
var (
	// ErrNoSource is returned by New when a source or the auditor is nil.
	// Projection fails closed rather than projecting from a partial set of
	// sources.
	ErrNoSource = errors.New("opsfacts: missing source")
	// ErrInvalidField is returned for an input value that fails its check.
	ErrInvalidField = errors.New("opsfacts: invalid field")
	// ErrInvalidState is returned for a finding state that is not known.
	ErrInvalidState = errors.New("opsfacts: invalid finding state")
	// ErrInvalidTier is returned for a tier that is not known.
	ErrInvalidTier = errors.New("opsfacts: invalid tier")
	// ErrInvalidOutcome is returned for a "fix with" outcome that is not known.
	ErrInvalidOutcome = errors.New("opsfacts: invalid fix outcome")
	// ErrInvalidLink is returned for a "fix with" link that is not known.
	ErrInvalidLink = errors.New("opsfacts: invalid fix link")
	// ErrDuplicateHost is the rule of the Skip for a host ID that two
	// inventory hosts share. Both hosts are dropped (see hostSet).
	ErrDuplicateHost = errors.New("opsfacts: duplicate host ID")
	// ErrUnknownGroup is returned when a group key names no eligible group.
	ErrUnknownGroup = errors.New("opsfacts: unknown group")
	// ErrStaleDigest is returned when a digest no longer matches the
	// current projection of its group.
	ErrStaleDigest = errors.New("opsfacts: digest does not match the current projection")
	// ErrItemTooLarge is returned when a projection exceeds MaxItemBytes.
	ErrItemTooLarge = errors.New("opsfacts: projection too large")
)

// Tier is the priority tier of a finding (vu-prio, ADR 0011). The values are
// those of vulnprio.Tier.
type Tier string

// Tiers.
const (
	TierLow      Tier = "low"
	TierMedium   Tier = "medium"
	TierHigh     Tier = "high"
	TierCritical Tier = "critical"
)

// rank orders tiers: low = 1 … critical = 4; 0 is not a tier.
func (t Tier) rank() int {
	switch t {
	case TierLow:
		return 1
	case TierMedium:
		return 2
	case TierHigh:
		return 3
	case TierCritical:
		return 4
	}
	return 0
}

// Exposure is the network exposure of a host (vu-prio-v1). The values are
// those of vulnprio.Exposure; the empty value counts as unknown.
type Exposure string

// Exposure levels.
const (
	ExposureInternet   Exposure = "internet"
	ExposureVPNEntry   Exposure = "vpn_entry"
	ExposureUnknown    Exposure = "unknown"
	ExposureInternal   Exposure = "internal"
	ExposureNoListener Exposure = "no_listener"
)

// Criticality is the criticality of an inventory host. The values are those
// of inventory.Criticality.
type Criticality string

// Criticalities.
const (
	CriticalityLow      Criticality = "LOW"
	CriticalityMedium   Criticality = "MEDIUM"
	CriticalityHigh     Criticality = "HIGH"
	CriticalityCritical Criticality = "CRITICAL"
)

// FixOutcome is the outcome of the "fix with" decision of one finding (ADR
// 0011 D8). The values are those of vulnfix.Status, named in snake case.
type FixOutcome string

// Fix outcomes.
const (
	OutcomeNone             FixOutcome = "none"
	OutcomeVerified         FixOutcome = "verified"
	OutcomeNotVerified      FixOutcome = "not_verified"
	OutcomeBelowFixed       FixOutcome = "below_fixed"
	OutcomeNoCandidate      FixOutcome = "no_candidate"
	OutcomeNoFixYet         FixOutcome = "no_fix_yet"
	OutcomeWontFix          FixOutcome = "wont_fix"
	OutcomeUnknown          FixOutcome = "unknown"
	OutcomeImageCandidate   FixOutcome = "image_candidate"
	OutcomeImageNoCandidate FixOutcome = "image_no_candidate"
	OutcomeDeviceNoPatch    FixOutcome = "device_no_patch"
)

// FixLink is the existing flow a "fix with" decision links to. The values
// are those of vulnfix.Action, named in snake case.
type FixLink string

// Fix links.
const (
	LinkNone            FixLink = "none"
	LinkInstallSecurity FixLink = "install_security"
	LinkInstallAll      FixLink = "install_all"
	LinkListUpdates     FixLink = "list_updates"
	LinkContainers      FixLink = "containers"
	LinkCiscoAdvisory   FixLink = "cisco_advisory"
	LinkPANAdvisory     FixLink = "pan_advisory"
)

// FixDecision is the "fix with" decision of one finding as the finding
// source reports it. It holds no free text.
type FixDecision struct {
	Outcome FixOutcome
	Link    FixLink
	// Reboot: the fix takes effect after a reboot (kernel source).
	Reboot bool
}

// FindingState is the NOS state of a finding (ADR 0011).
type FindingState string

// Finding states. Only StateOpen enters a projection; the other two are
// validated and then left out (ADR 0016 D3).
const (
	StateOpen          FindingState = "open"
	StateAcceptedRisk  FindingState = "accepted_risk"
	StateFalsePositive FindingState = "false_positive"
)

// SubjectKind is the kind of subject a finding is about.
type SubjectKind string

// Subject kinds. Each finding belongs to exactly one group (ADR 0016 D3).
const (
	SubjectOS    SubjectKind = "os"
	SubjectImage SubjectKind = "image"
)

// Host is one inventory host as the projection reads it.
type Host struct {
	ID          string
	Label       string
	Environment string
	Criticality Criticality
	Exposure    Exposure
}

// Port is one listening port of a host (ADR 0009 listeners).
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
}

// Finding is one vulnerability finding as the finding source reports it.
type Finding struct {
	Subject      SubjectKind
	HostID       string
	ImageSubject string
	VulnID       string
	Package      string
	Installed    string
	Fixed        string
	Tier         Tier
	Score        int
	KEV          bool
	State        FindingState
	Fix          FixDecision
}

// InventorySource returns every inventory host.
type InventorySource interface {
	Hosts(ctx context.Context) ([]Host, error)
}

// ListenerSource returns the listening ports of one host.
type ListenerSource interface {
	Listeners(ctx context.Context, hostID string) ([]Port, error)
}

// FindingSource returns every finding, in any state.
type FindingSource interface {
	Findings(ctx context.Context) ([]Finding, error)
}

// Catalog tells whether an action ID exists in the NOS action catalog. An
// action that is not in the catalog never becomes a step candidate.
type Catalog interface {
	HasAction(action string) bool
}

// SkipScope names what a Skip left out.
type SkipScope string

// Skip scopes.
const (
	ScopeHost      SkipScope = "host"
	ScopeFinding   SkipScope = "finding"
	ScopeListeners SkipScope = "listeners"
	ScopeGroup     SkipScope = "group"
)

// Skip records one input that the projection left out. Rule is the text of
// the failed check: a fixed message of this package, never input data.
type Skip struct {
	Scope SkipScope
	// HostID is the host ID when it has the shape of a subject ID, and ""
	// otherwise, so no untrusted text reaches the audit log.
	HostID string
	Rule   string
}

// Auditor records every skipped input. A failing Auditor fails the
// projection: the skip must be on record before the group is left out.
type Auditor interface {
	Skipped(ctx context.Context, s Skip) error
}

// Sources holds the inputs of a Projector. All fields are required.
type Sources struct {
	Inventory InventorySource
	Listeners ListenerSource
	Findings  FindingSource
	Catalog   Catalog
	Audit     Auditor
}

// Counts are finding counters: one per tier and the KEV count.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	KEV      int `json:"kev"`
}

// ExternalProjection is the projection of data class external (ADR 0016
// D5). It holds fleet counters and nothing else: no host ID, label,
// package, version, vulnerability ID or port. Every field is an integer;
// a test walks the struct type to keep it that way.
type ExternalProjection struct {
	Fleet Counts `json:"fleet"`
}
