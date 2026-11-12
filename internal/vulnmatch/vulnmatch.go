// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnmatch is the deterministic matcher of the vulnerability agent
// (ADR 0011 D4, Amendment 1 A1.3 step 3). It matches the subjects of a
// vuln-inventory-v1 export against parsed feed snapshots and produces
// finding records in the D5 record shape (vulnfinding.Record), each with
// its basis sources and MatcherVersion. NOS computes finding_key; this
// package never sets one.
//
// Rules the matcher keeps:
//
//   - Every version comparison goes through internal/vulnver on the
//     installed source version (source:Version, the D4 version basis),
//     never on a binary version. For a host's kernel the basis is the
//     running kernel's unsigned kernel source package as NOS mapped it.
//   - Debian matches on source package + release + fixed version of the
//     Security Tracker, with the D4 tracker state table (one target per
//     state). Ubuntu matches on the OSV records of its release, Alpine
//     image packages on OSV ranges. Devices match vendor CSAF products of
//     their release train.
//   - A version that does not parse, a range that cannot be evaluated or
//     an ambiguous vendor status is a coverage gap (Result.Gaps), never a
//     claim that the component is fixed or not affected. A fixed version
//     only ever leads to omission (no record) when vulnver says installed
//     ≥ fixed.
//   - Proxmox packages and unmapped running kernels are "coverage
//     unknown", never clean.
//
// The package does no I/O and holds no clock: the same DB, subjects and
// options give the same Result.
package vulnmatch

import (
	"errors"
	"regexp"
)

// MatcherVersion is the version of this matcher, sent as
// evidence.matcher_version with every record. Change it whenever the
// matching rules change.
const MatcherVersion = "vulnmatch-1.0.0"

// Limits of the matcher (A1.3).
const (
	// MaxRecordIDEntries bounds the IDs (primary plus aliases) read from
	// one feed record.
	MaxRecordIDEntries = 1024
	// MaxRecordValidIDs bounds the pattern-valid, deduplicated IDs kept
	// per feed record before the primary is chosen.
	MaxRecordValidIDs = 64
	// MaxAliases is the number of aliases sent next to the primary ID
	// (D2, D5).
	MaxAliases = 16
	// MaxRecordBasisSources bounds evidence.basis_sources of one record
	// (A1.3, the length of NOS's fixed source list rounded up).
	MaxRecordBasisSources = 10
	// MaxFixedVersionLen is the longest fixed version sent; a longer one
	// fails closed to no_fix_yet (A1.3).
	MaxFixedVersionLen = 128
	// MaxDebianEntries bounds the tracker entries held by a DB.
	MaxDebianEntries = 20_000_000
	// MaxOSVRecords bounds the OSV records held by a DB.
	MaxOSVRecords = 2_000_000
	// MaxCSAFAdvisories bounds the CSAF advisories held by a DB.
	MaxCSAFAdvisories = 100_000
	// MaxScoreEntries bounds the KEV, EPSS and NVD entries held by a DB,
	// each.
	MaxScoreEntries = 2_000_000
	// MaxSubjects bounds the subjects of one Match call.
	MaxSubjects = 200_000
	// MaxInstalledKernels bounds the installed-kernel context of a host.
	MaxInstalledKernels = 64
)

// Sentinel errors; callers branch on them with errors.Is.
var (
	// ErrUnknownFeed: a feed name that is not in the vulnfeed table, or a
	// FeedRef whose source ID does not match the table.
	ErrUnknownFeed = errors.New("vulnmatch: unknown feed")
	// ErrNoFeedSnapshot: data was added for a feed whose snapshot has not
	// been set, so no basis source could be named for it.
	ErrNoFeedSnapshot = errors.New("vulnmatch: feed snapshot not set")
	// ErrInvalidFeedRef: a FeedRef with an invalid snapshot ID or
	// integrity mode.
	ErrInvalidFeedRef = errors.New("vulnmatch: invalid feed reference")
	// ErrLimit: a DB or Match limit was exceeded.
	ErrLimit = errors.New("vulnmatch: limit exceeded")
	// ErrIncompleteSubject: export parts of a subject end without its
	// last part, or arrive out of order.
	ErrIncompleteSubject = errors.New("vulnmatch: incomplete subject parts")
)

// Patterns shared with the D2/D5 record validation (vulnfinding).
var (
	vulnIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{1,63}$`)
	cveRe        = regexp.MustCompile(`^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,19}$`)
	versionRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
	snapshotIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$`)
	proxmoxPkgRe = regexp.MustCompile(`^(pve-|proxmox-)`)
	debianEcoRe  = regexp.MustCompile(`^debian:([a-z]{2,32})$`)
	ubuntuEcoRe  = regexp.MustCompile(`^ubuntu:([0-9]{2}\.[0-9]{2})$`)
	alpineEcoRe  = regexp.MustCompile(`^alpine:([0-9]{1,2}\.[0-9]{1,3})$`)
	ciscoEcoRe   = regexp.MustCompile(`^vendor:cisco:[a-z0-9-]{1,32}$`)
)
