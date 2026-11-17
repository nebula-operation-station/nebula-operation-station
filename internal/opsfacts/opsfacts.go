// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsfacts builds the fixed projection the ops agent reads (ADR 0016
// D3 to D5). The projection, not the agent, is the security boundary: every
// value that leaves this package is a field of one of the structs in this
// file. The external class (LabProjection's counterpart ExternalProjection)
// carries counters only.
//
// The package reads its data through interfaces, so it reaches no store.
// Its direct module imports are fixed by the import-boundary test: vulnfix
// (the "fix with" decision), vulnprio and inventory (their enum types).
// Every finding, host and listener value is untrusted input and is checked
// before it enters a projection.
package opsfacts

import (
	"context"
	"errors"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfix"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
)

// Limits. Each is enforced by the code that uses it (ADR 0016 D4).
const (
	// MaxFindingsPerGroup is the number of findings a group lists, by
	// score. Further findings are counted per tier.
	MaxFindingsPerGroup = 40
	// MaxPortsPerHost is the number of listening ports a host projection
	// lists, lowest number first. Further ports are counted.
	MaxPortsPerHost = 32
	// MaxLabelBytes bounds the host label after cleaning.
	MaxLabelBytes = 64
	// MaxPackageBytes bounds a package name after cleaning.
	MaxPackageBytes = 128
	// MaxVersionBytes bounds an installed or fixed version.
	MaxVersionBytes = 64
	// MaxVulnIDBytes bounds a vulnerability ID.
	MaxVulnIDBytes = 64
	// MaxEnvironmentBytes bounds the environment name after cleaning.
	MaxEnvironmentBytes = 32
	// MaxScore is the highest priority score (vulnprio).
	MaxScore = 100
	// MaxCandidatesPerGroup bounds step candidates; the allowlist has
	// fewer actions than this, so the bound is a guard, not a cut.
	MaxCandidatesPerGroup = 8
	// MaxItemBytes bounds the canonical JSON of one group projection
	// (ADR 0016 D4).
	MaxItemBytes = 32 << 10
	// textScanFactor bounds how much of an untrusted text value cleanText
	// reads: at most this many times its output limit.
	textScanFactor = 8
)

// Sentinel errors that callers branch on.
var (
	// ErrNoSource is returned by New when a source is nil. Projection fails
	// closed rather than projecting from a partial set of sources.
	ErrNoSource = errors.New("opsfacts: missing source")
	// ErrInvalidField is returned for an input value that fails its check.
	ErrInvalidField = errors.New("opsfacts: invalid field")
	// ErrInvalidState is returned for a finding state that is not known.
	ErrInvalidState = errors.New("opsfacts: invalid finding state")
	// ErrInvalidTier is returned for a tier that is not known.
	ErrInvalidTier = errors.New("opsfacts: invalid tier")
	// ErrDuplicateHost is returned when two inventory hosts share an ID.
	ErrDuplicateHost = errors.New("opsfacts: duplicate host ID")
	// ErrUnknownGroup is returned when a group key names no eligible group.
	ErrUnknownGroup = errors.New("opsfacts: unknown group")
	// ErrStaleDigest is returned when a digest no longer matches the
	// current projection of its group.
	ErrStaleDigest = errors.New("opsfacts: digest does not match the current projection")
	// ErrItemTooLarge is returned when a projection exceeds MaxItemBytes.
	ErrItemTooLarge = errors.New("opsfacts: projection too large")
)

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
	Criticality inventory.Criticality
	Exposure    vulnprio.Exposure
}

// Port is one listening port of a host (ADR 0009 listeners).
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
}

// Finding is one vulnerability finding as the finding source reports it.
// Fix is the "fix with" decision of vulnfix for the finding.
type Finding struct {
	Subject      SubjectKind
	HostID       string
	ImageSubject string
	VulnID       string
	Package      string
	Installed    string
	Fixed        string
	Tier         vulnprio.Tier
	Score        int
	KEV          bool
	State        FindingState
	Fix          vulnfix.Result
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

// Sources holds the four inputs of a Projector. All fields are required.
type Sources struct {
	Inventory InventorySource
	Listeners ListenerSource
	Findings  FindingSource
	Catalog   Catalog
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
