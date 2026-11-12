// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

// Limits of the fim-scan-v1 document (ADR 0015 D6, spec 09 v26-09-01).
// The first four are the action-specific limits named in the spec; the rest
// are implementation choices of this package.
const (
	// MaxRecords is the number of record entries (valid or not) accepted per
	// host and run. Entries beyond it are discarded and the run is partial.
	MaxRecords = 300_000
	// MaxDocumentBytes is the raw document size limit per run (128 MiB).
	MaxDocumentBytes = 128 << 20
	// MaxPathDepth is the maximum number of components of a path.
	MaxPathDepth = 64
	// MaxRecordBytes bounds the raw bytes of one record, mount, roots entry
	// or scalar top-level member, including the separator and whitespace
	// before it (16 KiB).
	MaxRecordBytes = 16 << 10

	// MaxPathBytes is the maximum decoded length of a path.
	MaxPathBytes = 4096
	// MaxLinkBytes is the maximum decoded length of a symlink target.
	MaxLinkBytes = 4096
	// MaxMounts is the maximum number of mount entries per run.
	MaxMounts = 256
	// MaxFSTypeBytes is the maximum length of a mount's file-system type.
	MaxFSTypeBytes = 64
	// MaxSSHConfigFiles is the maximum number of SSH configuration files.
	MaxSSHConfigFiles = 64
	// MaxSSHConfigBytes is the decoded size limit of all SSH configuration
	// files together (256 KiB).
	MaxSSHConfigBytes = 256 << 10
	// MaxSSHEntryBytes bounds the raw bytes of one SSH configuration entry:
	// the base64 form of MaxSSHConfigBytes plus a padded path and syntax.
	MaxSSHEntryBytes = 4*((MaxSSHConfigBytes+2)/3) + MaxRecordBytes
	// MaxProfileIDBytes bounds the reported profile ID.
	MaxProfileIDBytes = 64

	// maxNestingDepth bounds the nesting of an unknown value inside an
	// entry that is skipped; deeper nesting rejects the document.
	maxNestingDepth = 16
	// maxIntDigits bounds the textual length of an integer, sign included.
	maxIntDigits = 20

	// MinTime and MaxTime bound reported Unix times (years 1 to 9999).
	MinTime int64 = -62135596800
	// MaxTime is the latest accepted Unix time (9999-12-31T23:59:59Z).
	MaxTime int64 = 253402300799
	// MaxMode is the largest accepted permission mode (07777: permission
	// bits plus setuid, setgid and sticky; no file-type bits).
	MaxMode = 0o7777
	// MaxID is the largest accepted uid or gid (2^32-2; 2^32-1 is the
	// kernel's "no id" value).
	MaxID = 1<<32 - 2
)

// limits holds the effective limits. Production code always uses
// defaultLimits; tests lower them to exercise the cut paths cheaply.
type limits struct {
	records     int
	docBytes    int64
	recordBytes int64
	mounts      int
	sshFiles    int
	sshBytes    int
	sshEntry    int64
}

var defaultLimits = limits{
	records:     MaxRecords,
	docBytes:    MaxDocumentBytes,
	recordBytes: MaxRecordBytes,
	mounts:      MaxMounts,
	sshFiles:    MaxSSHConfigFiles,
	sshBytes:    MaxSSHConfigBytes,
	sshEntry:    MaxSSHEntryBytes,
}
