// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnfinding is the finding model of ADR 0011 D2: the record Hermes
// posts for one vulnerability on one component of one subject, its strict
// validation, and the finding_key that NOS computes from the validated
// fields. The package is pure: no store, no I/O, no clock.
//
// Every record is untrusted input. ParseRecord rejects oversized bodies,
// invalid UTF-8, duplicate or non-canonical JSON keys, unknown fields (a
// finding_key supplied by Hermes among them) and trailing data before the
// fields are checked against the regular expressions and limits below.
// Error messages name fields, never the rejected values.
package vulnfinding

import "errors"

// Limits enforced by this package (ADR 0011 D2 and D5).
const (
	// MaxRecordBytes bounds one encoded record. A batch is at most 1 MiB
	// (D5); one record may use a larger share for many binaries.
	MaxRecordBytes = 128 << 10
	// MaxAliases is the number of aliases next to the primary ID (D2, D5).
	MaxAliases = 16
	// MaxAssessmentBytes bounds the Hermes assessment text (D2, D5).
	MaxAssessmentBytes = 4 << 10
	// MaxBasisSources bounds evidence.basis_sources. NOS's fixed source
	// list (D5) is shorter; the bound only caps work on malformed input.
	MaxBasisSources = 16
	// MaxBinaries bounds the binary packages listed as context for one
	// source package.
	MaxBinaries = 256
	// maxJSONDepth bounds nesting of the record (the schema needs 4).
	maxJSONDepth = 8
)

// Sentinel errors; callers branch on them with errors.Is.
var (
	// ErrMalformed: not a single well-formed JSON object, a duplicate or
	// non-canonical key, a wrong JSON type, or nesting too deep.
	ErrMalformed = errors.New("malformed finding record")
	// ErrUnknownField: a field the schema does not define, including the
	// NOS-owned finding_key, nos_checked, observer and state.
	ErrUnknownField = errors.New("unknown field in finding record")
	// ErrInvalidUTF8: the body is not strict UTF-8 (raw invalid bytes or an
	// escaped lone surrogate).
	ErrInvalidUTF8 = errors.New("finding record is not valid UTF-8")
	// ErrTooLarge: the body exceeds MaxRecordBytes.
	ErrTooLarge = errors.New("finding record too large")
	// ErrMissingField: a required field is absent or empty.
	ErrMissingField = errors.New("required field missing")
	// ErrInvalidField: a field fails its pattern, enum or limit.
	ErrInvalidField = errors.New("invalid field")
	// ErrEmptyBasisSources: evidence.basis_sources is empty (D2, D5).
	ErrEmptyBasisSources = errors.New("evidence.basis_sources is empty")
	// ErrInconsistent: fields contradict each other (subject kind and
	// ecosystem, match basis and ecosystem, tracker state and fix).
	ErrInconsistent = errors.New("inconsistent finding record")
	// ErrCoverageOnly: the ecosystem reports coverage only and never
	// carries findings (proxmox, D2/D4).
	ErrCoverageOnly = errors.New("ecosystem is coverage only")
	// ErrKernelSourcePackage: a Debian or Ubuntu record keyed on a
	// linux-signed* or linux-meta* source package, which is never a version
	// basis (D4).
	ErrKernelSourcePackage = errors.New("signed or meta kernel source package is not a version basis")
)

// SubjectKind is the kind of subject a finding is about.
type SubjectKind string

// Subject kinds (D2).
const (
	SubjectHost   SubjectKind = "host"
	SubjectImage  SubjectKind = "image"
	SubjectDevice SubjectKind = "device"
)

// SubjectRef names the subject. For hosts and devices ID is the inventory
// ID; for images ID is the host ID and ImageDigest the platform digest.
type SubjectRef struct {
	ID          string `json:"id"`
	ImageDigest string `json:"image_digest,omitempty"`
}

// Binary is one installed binary package of the source package, with its
// binary version; context only, never a version basis.
type Binary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component is the affected component. Host and image records set the
// source package and its installed source version (D4 version basis);
// device records set model and firmware.
type Component struct {
	SourcePackage string   `json:"source_package,omitempty"`
	SourceVersion string   `json:"source_version,omitempty"`
	Binaries      []Binary `json:"binaries,omitempty"`
	Model         string   `json:"model,omitempty"`
	Firmware      string   `json:"firmware,omitempty"`
}

// Vuln is the primary vulnerability ID and its aliases.
type Vuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

// FixState is the fix situation of a finding.
type FixState string

// Fix states (D2).
const (
	FixFixed       FixState = "fixed"
	FixNoFixYet    FixState = "no_fix_yet"
	FixWontFix     FixState = "wont_fix"
	FixNotAffected FixState = "not_affected"
)

// Opens reports whether a record with this fix state may open or update a
// finding. not_affected only ever closes (D2); unknown states open nothing.
func (s FixState) Opens() bool {
	switch s {
	case FixFixed, FixNoFixYet, FixWontFix:
		return true
	default:
		return false
	}
}

// Fix is the fixed source version (State FixFixed) or a fix state without
// version.
type Fix struct {
	State   FixState `json:"state"`
	Version string   `json:"version,omitempty"`
}

// MatchBasis is how Hermes matched the finding.
type MatchBasis string

// Match bases (D2).
const (
	MatchDistroTracker  MatchBasis = "distro_tracker"
	MatchOSVRange       MatchBasis = "osv_range"
	MatchVendorAdvisory MatchBasis = "vendor_advisory"
	MatchCPE            MatchBasis = "cpe"
)

// CVSSSource names where a CVSS score comes from.
type CVSSSource string

// CVSS sources (D2).
const (
	CVSSSourceDistro CVSSSource = "distro"
	CVSSSourceNVD    CVSSSource = "nvd"
	CVSSSourceVendor CVSSSource = "vendor"
)

// CVSS is one CVSS base score with its vector.
type CVSS struct {
	Version   string     `json:"version"`
	Vector    string     `json:"vector"`
	BaseScore float64    `json:"base_score"`
	Source    CVSSSource `json:"source"`
}

// KEV marks a CISA KEV listing; its presence means listed.
type KEV struct {
	DateAdded string `json:"date_added"`
}

// EPSS is a FIRST EPSS score of one day.
type EPSS struct {
	Probability float64 `json:"probability"`
	Percentile  float64 `json:"percentile"`
	Date        string  `json:"date"`
}

// Scores are the optional scores of a finding.
type Scores struct {
	CVSS *CVSS `json:"cvss,omitempty"`
	KEV  *KEV  `json:"kev,omitempty"`
	EPSS *EPSS `json:"epss,omitempty"`
}

// IntegrityMode is the integrity mode of a feed source (D4).
type IntegrityMode string

// Integrity modes (D4).
const (
	IntegritySigned   IntegrityMode = "signed"
	IntegrityChecksum IntegrityMode = "checksum"
	IntegrityNone     IntegrityMode = "none"
)

// BasisSource is one feed source a match rests on.
type BasisSource struct {
	SourceID   string        `json:"source_id"`
	SnapshotID string        `json:"snapshot_id"`
	Integrity  IntegrityMode `json:"integrity"`
}

// Evidence lists the basis sources and the matcher version. nos_checked is
// NOS's own label (D4) and not part of the record.
type Evidence struct {
	BasisSources   []BasisSource `json:"basis_sources"`
	MatcherVersion string        `json:"matcher_version"`
}

// Assessment is the Hermes LLM text and its hint flags; advisory only,
// rendered as text labelled "Hermes assessment (LLM, unverified)".
type Assessment struct {
	Text                string `json:"text,omitempty"`
	BackportChecked     bool   `json:"backport_checked,omitempty"`
	LikelyFalsePositive bool   `json:"likely_false_positive,omitempty"`
	ExploitPublic       bool   `json:"exploit_public,omitempty"`
}

// Record is one finding as Hermes posts it. It has no finding_key, state,
// observer or nos_checked field: NOS owns those.
type Record struct {
	SubjectKind  SubjectKind  `json:"subject_kind"`
	SubjectRef   SubjectRef   `json:"subject_ref"`
	Ecosystem    string       `json:"ecosystem"`
	Component    Component    `json:"component"`
	Vuln         Vuln         `json:"vuln"`
	Fix          Fix          `json:"fix"`
	TrackerState TrackerState `json:"tracker_state,omitempty"`
	MatchBasis   MatchBasis   `json:"match_basis"`
	Scores       Scores       `json:"scores"`
	Evidence     Evidence     `json:"evidence"`
	Assessment   Assessment   `json:"assessment"`
}

// Finding is a validated record with the key NOS computed from it.
type Finding struct {
	// Record is the validated record; CVE IDs are canonicalised to upper
	// case.
	Record Record
	// Key is the NOS-computed finding_key.
	Key Key
	// TrackerNote is NOS's note for the Debian tracker state, from NOS's
	// own table, never from Hermes text; empty when there is none.
	TrackerNote string
}
