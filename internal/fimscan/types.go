// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import "errors"

// Format is the only accepted value of the document's format member.
const Format = "fim-scan-v1"

// ErrInvalidResult is returned when the document as a whole violates the
// fim-scan-v1 contract. Nothing from such a document is used.
var ErrInvalidResult = errors.New("fimscan: invalid result")

// ErrBadOptions is returned when the caller's options are unusable.
var ErrBadOptions = errors.New("fimscan: invalid options")

// Mode is the scan mode frozen by the read grant.
type Mode string

const (
	// ModeFull hashes every file (within the D5 load limits).
	ModeFull Mode = "full"
	// ModeIncremental may report large files by metadata only.
	ModeIncremental Mode = "incremental"
)

// Type is a record's file type.
type Type uint8

const (
	// TypeFile is a regular file.
	TypeFile Type = iota + 1
	// TypeDir is a directory.
	TypeDir
	// TypeSymlink is a symbolic link (recorded, never followed).
	TypeSymlink
	// TypeOther is any other file type (device, FIFO, socket).
	TypeOther
)

// String returns the wire name of t.
func (t Type) String() string {
	switch t {
	case TypeFile:
		return "file"
	case TypeDir:
		return "dir"
	case TypeSymlink:
		return "symlink"
	case TypeOther:
		return "other"
	default:
		return "invalid"
	}
}

// Record is one validated file record. Path and Link are raw host bytes
// (not necessarily UTF-8); show them only through EscapePath.
type Record struct {
	// Path is the absolute path below a profile root.
	Path []byte
	// Type is the file type.
	Type Type
	// Size is the size in bytes.
	Size int64
	// Mode holds the permission, setuid, setgid and sticky bits (<= 07777).
	Mode uint32
	// UID is the owning user ID.
	UID uint32
	// GID is the owning group ID.
	GID uint32
	// Inode is the inode number.
	Inode uint64
	// Mtime is the host-reported modification time (Unix seconds).
	Mtime int64
	// Ctime is the host-reported change time (Unix seconds).
	Ctime int64
	// Hash is the content hash in its D6 form; Kind is HashNone when the
	// host did not hash the file.
	Hash Hash
	// Link is the symlink target for TypeSymlink, nil otherwise.
	Link []byte
}

// Mount is a mount point the host reported below a profile root. The
// executor, not the host, classifies it (ADR 0015 D5).
type Mount struct {
	// Path is the mount point.
	Path []byte
	// FSType is the reported file-system type ([a-z0-9._-], <= 64 bytes).
	FSType string
}

// SSHConfigFile is one sshd configuration file as sent by the host. The
// content must never be persisted, logged or forwarded (ADR 0015 D6).
type SSHConfigFile struct {
	// Path is the file's path.
	Path []byte
	// Content is the raw file content.
	Content []byte
}

// SSHConfigState is the state of the SSH configuration array.
type SSHConfigState uint8

const (
	// SSHConfigMissing: the array was not in the document (or was cut).
	SSHConfigMissing SSHConfigState = iota
	// SSHConfigInvalid: an entry broke the schema or a limit.
	SSHConfigInvalid
	// SSHConfigInconsistent: an entry has no matching hashed file record.
	SSHConfigInconsistent
	// SSHConfigValid: every entry is valid and matches its file record.
	// The Include checks of ADR 0015 D6 are left to the sshd_config parser.
	SSHConfigValid
)

// RootState is the executor-side classification of a profile root.
type RootState uint8

const (
	// RootSkipped: missing (not optional), unreadable or not reported; the
	// run is partial.
	RootSkipped RootState = iota
	// RootScanned: the host scanned the root.
	RootScanned
	// RootAbsent: an optional root the host does not have.
	RootAbsent
)

// RootStatus is the state of one profile root in this run.
type RootStatus struct {
	// Pattern is the profile root.
	Pattern string
	// State is its classification.
	State RootState
}

// Reason names why a run is partial.
type Reason string

// Reasons a run is partial.
const (
	ReasonDocumentLimit   Reason = "document_limit"
	ReasonEntryLimit      Reason = "entry_limit"
	ReasonRecordLimit     Reason = "record_limit"
	ReasonMountLimit      Reason = "mount_limit"
	ReasonInvalidRecord   Reason = "invalid_record"
	ReasonInvalidMount    Reason = "invalid_mount"
	ReasonInvalidRoot     Reason = "invalid_root_entry"
	ReasonRootSkipped     Reason = "root_skipped"
	ReasonUnreadable      Reason = "unreadable_files"
	ReasonHostTruncated   Reason = "host_truncated"
	ReasonCounterMismatch Reason = "counter_mismatch"
	ReasonSSHConfig       Reason = "ssh_config"
)

// DropReason names why an entry was dropped.
type DropReason string

// Reasons an entry was dropped.
const (
	DropNotObject      DropReason = "not_object"
	DropBadMember      DropReason = "bad_member"
	DropMissingMember  DropReason = "missing_member"
	DropBadPath        DropReason = "bad_path"
	DropOutsideRoots   DropReason = "outside_roots"
	DropBadType        DropReason = "bad_type"
	DropBadInteger     DropReason = "bad_integer"
	DropBadHash        DropReason = "bad_hash"
	DropBadLink        DropReason = "bad_link"
	DropDuplicatePath  DropReason = "duplicate_path"
	DropRootNotScanned DropReason = "root_not_scanned"
	DropOverLimit      DropReason = "over_limit"
	DropBadFSType      DropReason = "bad_fstype"
	DropBadRoot        DropReason = "bad_root"
)

// HostCounters are the counters the host reports at the end of the
// document. They are untrusted and only cross-checked.
type HostCounters struct {
	Records    int64
	Mounts     int64
	SSHConfig  int64
	Unreadable int64
}

// Result is a parsed fim-scan-v1 document.
type Result struct {
	// ProfileID and Mode equal the options; the parser rejects others.
	ProfileID string
	Mode      Mode
	// Started and Ended are host-reported Unix times, informational only.
	Started, Ended int64
	// Records are the validated records, in document order.
	Records []Record
	// Mounts are the validated mount entries.
	Mounts []Mount
	// Roots has one entry per profile root, in profile order.
	Roots []RootStatus
	// SSHConfig holds the SSH configuration files only when SSHConfigState
	// is SSHConfigValid; otherwise it is nil.
	SSHConfig      []SSHConfigFile
	SSHConfigState SSHConfigState
	// Host holds the host counters (zero when the document was cut).
	Host HostCounters
	// Dropped counts dropped records, mounts and roots entries by reason.
	Dropped map[DropReason]int
	// Partial lists why the run is partial; empty means complete.
	Partial []Reason
}

// Complete reports whether the run is complete: no limit reached, no entry
// dropped, every non-optional root scanned and a valid SSH configuration.
// The caller must still treat a non-zero exit status as partial.
func (r *Result) Complete() bool { return len(r.Partial) == 0 }
