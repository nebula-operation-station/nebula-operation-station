// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import "github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"

// Limits (ADR 0015 D6, D7, "Consequences"). The ADR defines no truncation
// for a baseline or a diff, so input beyond a limit is rejected with
// ErrLimit; the number of deviations is bounded by construction.
const (
	// MaxEntries is the maximum number of entries of a baseline and of
	// records of a scan compared with it: 300,000 records per host and run
	// (D6), "about 300,000 records per host at most" for the baseline store.
	MaxEntries = fimscan.MaxRecords
	// MaxPathBytes is the maximum length of a path (D6: 4,096 bytes).
	MaxPathBytes = fimscan.MaxPathBytes
	// MaxLinkBytes is the maximum length of a symlink target (D6: 4,096).
	MaxLinkBytes = fimscan.MaxLinkBytes
	// MaxPathDepth is the maximum number of path components (D6: 64).
	MaxPathDepth = fimscan.MaxPathDepth
	// MaxMounts is the maximum number of mount entries per run (D6: 256).
	MaxMounts = fimscan.MaxMounts
	// MaxFSTypeBytes is the maximum length of a mount's file-system type.
	MaxFSTypeBytes = fimscan.MaxFSTypeBytes
	// MaxProfileIDBytes bounds the profile ID.
	MaxProfileIDBytes = fimscan.MaxProfileIDBytes
	// MaxDeviations bounds the result of Diff: at most one deviation per
	// path of the baseline or the scan, plus one for a /boot/efi
	// file-system type change without a record at that path.
	MaxDeviations = 2*MaxEntries + 1
)
