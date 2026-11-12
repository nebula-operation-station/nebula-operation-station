// SPDX-License-Identifier: AGPL-3.0-or-later

// Package integrity is the I1 self-check of NOS (ADR 0015 D2, D4): it
// compares the installed NOS files of the running release with the
// installed-files list that the release root signed.
//
// The only reference is an installed-files.json admitted through
// release.VerifyInstalledFiles (IG-02): the manifest signature is checked
// against the caller's durable root state and the list's size and SHA-256
// against the signed manifest. A Reference can only be built by Admit, so
// a list that did not pass that verification can never be checked
// against. This package holds no keys and no other source of trust.
//
// It only reports. Reactions (unlock refusal, refusing a web asset,
// findings and notifications, ADR 0015 Q4) belong to the callers.
package integrity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Check limits (ADR 0015 D4: at most 4,096 files and 1 GiB per run).
const (
	// MaxFiles bounds the listed files one run checks.
	MaxFiles = release.MaxInstalledEntries
	// MaxBytes bounds the bytes one run hashes.
	MaxBytes = 1 << 30
	// DefaultBudget is the time budget of a run when Options.Budget is 0.
	DefaultBudget = 10 * time.Minute
	// MaxBudget bounds Options.Budget; the periodic check runs every 60
	// minutes (ADR 0015 Q2) and must not overlap itself.
	MaxBudget = time.Hour
	// MaxExtras bounds the unlisted /usr/bin/nebula* entries reported.
	MaxExtras = 64
	// maxDirEntries bounds the /usr/bin entries read for the extra scan.
	maxDirEntries = 1 << 16
	// readChunk is the read size while hashing; the time budget and the
	// context are checked between chunks.
	readChunk = 256 << 10
)

// Sentinel errors.
var (
	// ErrNoReference is a Reference that Admit did not return.
	ErrNoReference = errors.New("integrity: no admitted installed-files reference")
	// ErrVersion is a signed list whose release version is not the
	// running version, or a running version that is not SemVer.
	ErrVersion = errors.New("integrity: installed-files list is not for the running version")
	// ErrFlavour is an install flavour the admitted list does not have.
	ErrFlavour = errors.New("integrity: install flavour not in the admitted list")
	// ErrOptions is an invalid Options value.
	ErrOptions = errors.New("integrity: invalid check options")
)

// Reference is an installed-files list admitted through the release
// verifier. The zero value is not usable; only Admit returns one.
type Reference struct {
	admitted bool
	manifest release.Manifest
	list     release.InstalledFiles
}

// Admit verifies the release manifest, its signature and
// installed-files.json with release.VerifyInstalledFiles against state,
// the caller's durable root state (never keys supplied beside the files),
// and requires the release version to be version, the version of the
// running NOS. The executor-owned admitted copy (ADR 0015 D4 "Reference")
// is passed here on every check; it is re-verified each time.
func Admit(state release.RootState, version string, manifest, sig, list []byte) (Reference, error) {
	if !release.ValidReleaseVersion(version) {
		return Reference{}, fmt.Errorf("%w: running version is not a release version", ErrVersion)
	}
	m, l, err := release.VerifyInstalledFiles(state, manifest, sig, list)
	if err != nil {
		return Reference{}, fmt.Errorf("admit installed-files list: %w", err)
	}
	if m.ReleaseVersion != version || l.ReleaseVersion != version {
		return Reference{}, fmt.Errorf("%w: list is for %s, running %s", ErrVersion, m.ReleaseVersion, version)
	}
	return Reference{admitted: true, manifest: m, list: l}, nil
}

// ReleaseVersion is the admitted release version.
func (r Reference) ReleaseVersion() string { return r.manifest.ReleaseVersion }

// ManifestDigest is the SHA-256 of the admitted manifest bytes.
func (r Reference) ManifestDigest() string { return r.manifest.Digest }

// ListDigest is the SHA-256 of the admitted installed-files.json bytes.
func (r Reference) ListDigest() string { return r.list.Digest }

// SignedBy is the ID of the release root that signed the manifest.
func (r Reference) SignedBy() string { return r.manifest.SignedBy.ID }

// Class is the ADR 0015 D4 class of a NOS file. It decides the caller's
// reaction (Q4): a deviation in a class that Locks blocks unlock and
// dispatch; a web asset is refused on its own.
type Class string

// Classes.
const (
	// ClassBinary is /usr/bin/nebula*.
	ClassBinary Class = "binary"
	// ClassUnit is a systemd unit or package-shipped drop-in.
	ClassUnit Class = "unit"
	// ClassModule is the built-in module bundle and module files.
	ClassModule Class = "module"
	// ClassRootKey is a shipped release root key or root rotation.
	ClassRootKey Class = "root-key"
	// ClassWebAsset is a web template or static asset.
	ClassWebAsset Class = "web-asset"
	// ClassCode is any other covered NOS file (deploy scripts,
	// nftables files, documentation). It is treated like a binary.
	ClassCode Class = "code"
)

// Locks reports whether a deviation in this class is one the executor
// answers with the I1 lock (ADR 0015 D4, Q4). Only web assets are refused
// individually; every other class, including unknown ones, locks.
func (c Class) Locks() bool { return c != ClassWebAsset }

// Path prefixes for Classify. Everything else under the covered NOS
// prefixes is ClassCode.
var (
	unitPrefixes   = []string{"/lib/systemd/system/", "/usr/lib/systemd/system/", "/etc/systemd/system/"}
	modulePrefixes = []string{
		"/usr/share/nebula/release/", "/usr/share/nebula/modules/", "/usr/lib/nebula/modules/",
	}
	webPrefixes = []string{
		"/usr/share/nebula/web/", "/usr/lib/nebula/web/",
		"/usr/share/nebula/templates/", "/usr/lib/nebula/templates/",
	}
)

// Classify returns the ADR 0015 D4 class of an installed path.
func Classify(p string) Class {
	if strings.HasPrefix(p, "/usr/bin/") {
		return ClassBinary
	}
	if hasAnyPrefix(p, unitPrefixes) {
		return ClassUnit
	}
	base := p[strings.LastIndexByte(p, '/')+1:]
	if strings.HasPrefix(base, "rootkeys") || strings.HasPrefix(base, "root-rotation") {
		return ClassRootKey
	}
	if hasAnyPrefix(p, modulePrefixes) {
		return ClassModule
	}
	if hasAnyPrefix(p, webPrefixes) {
		return ClassWebAsset
	}
	return ClassCode
}

func hasAnyPrefix(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Status is the outcome for one file.
type Status string

// Statuses.
const (
	// StatusOK matches the signed list.
	StatusOK Status = "ok"
	// StatusDifferent exists but differs; Reason says how.
	StatusDifferent Status = "different"
	// StatusMissing does not exist.
	StatusMissing Status = "missing"
	// StatusUnreadable could not be checked; never treated as ok.
	StatusUnreadable Status = "unreadable"
	// StatusExtra is an unlisted /usr/bin/nebula* entry.
	StatusExtra Status = "extra"
	// StatusNotChecked was not reached before a limit; see
	// Report.Incomplete.
	StatusNotChecked Status = "not-checked"
)

// String returns the status name.
func (s Status) String() string { return string(s) }

// Reason details a StatusDifferent or StatusUnreadable result. It is a
// fixed vocabulary; no host-supplied text is ever placed in a result.
type Reason string

// Reasons.
const (
	// ReasonType: a different file type (a symlink instead of a file, a
	// directory, a FIFO, ...).
	ReasonType Reason = "type"
	// ReasonSize: a different size, or the file changed while read.
	ReasonSize Reason = "size"
	// ReasonSHA256: same size, different bytes.
	ReasonSHA256 Reason = "sha256"
	// ReasonMode: different permission or setuid/setgid/sticky bits.
	ReasonMode Reason = "mode"
	// ReasonOwner: different owner or group.
	ReasonOwner Reason = "owner"
	// ReasonTarget: a symlink with a different target.
	ReasonTarget Reason = "target"
	// ReasonParent: a parent directory is a symlink or not a directory;
	// it is never followed.
	ReasonParent Reason = "parent"
	// ReasonOpen: the file or a parent could not be opened.
	ReasonOpen Reason = "open"
	// ReasonRead: reading the file failed.
	ReasonRead Reason = "read"
	// ReasonOwnerUnknown: the listed owner could not be resolved.
	ReasonOwnerUnknown Reason = "owner-unknown"
)

// FileResult is the outcome for one file.
type FileResult struct {
	// Path is the installed path from the signed list; for StatusExtra
	// the directory entry name with unsafe bytes escaped.
	Path string
	// Class is the ADR 0015 D4 class of Path.
	Class Class
	// Status is the outcome.
	Status Status
	// Reason details StatusDifferent and StatusUnreadable.
	Reason Reason
}

// Incomplete names why a run stopped early.
type Incomplete string

// Reasons for an incomplete run.
const (
	// IncompleteFiles: more listed files than Options.MaxFiles.
	IncompleteFiles Incomplete = "file-limit"
	// IncompleteBytes: the byte budget would be exceeded.
	IncompleteBytes Incomplete = "byte-limit"
	// IncompleteTime: the time budget ran out.
	IncompleteTime Incomplete = "time-budget"
	// IncompleteCanceled: the context was canceled.
	IncompleteCanceled Incomplete = "canceled"
	// IncompleteExtraScan: /usr/bin could not be scanned completely for
	// unlisted NOS binaries.
	IncompleteExtraScan Incomplete = "extra-scan"
)

// Report is the result of one check run.
type Report struct {
	// ReleaseVersion, ManifestDigest and ListDigest identify the
	// admitted reference that was checked against.
	ReleaseVersion string
	// ManifestDigest is the SHA-256 of the admitted manifest.
	ManifestDigest string
	// ListDigest is the SHA-256 of the admitted installed-files.json.
	ListDigest string
	// Flavour is the install flavour checked.
	Flavour string
	// Started and Finished come from Options.Now.
	Started time.Time
	// Finished is when the run ended.
	Finished time.Time
	// Files has one result per listed file, in list order, then the
	// StatusExtra results.
	Files []FileResult
	// Complete is false when a limit, the time budget or cancellation
	// stopped the run; Incomplete says which.
	Complete bool
	// Incomplete is the first reason the run stopped early.
	Incomplete Incomplete
	// BytesHashed counts the bytes read for hashing.
	BytesHashed int64
}

// Clean reports whether the run was complete and every file is ok. An
// incomplete run is never clean (ADR 0015 D4).
func (r Report) Clean() bool {
	if !r.Complete || r.Incomplete != "" {
		return false
	}
	for _, f := range r.Files {
		if f.Status != StatusOK {
			return false
		}
	}
	return true
}

// Options configures a check run.
type Options struct {
	// Root is the absolute directory the listed absolute paths are
	// resolved under; "" means "/". Tests and an offline check of a
	// mounted disk use another root. A symlink as Root is refused.
	Root string
	// Flavour is the install flavour of this installation, for example
	// "deb:amd64". It must be in the admitted list.
	Flavour string
	// MaxFiles bounds the listed files checked; 0 means MaxFiles.
	MaxFiles int
	// MaxBytes bounds the bytes hashed; 0 means MaxBytes.
	MaxBytes int64
	// Budget bounds the run time; 0 means DefaultBudget.
	Budget time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Owners resolves a listed "user:group" to numeric IDs; nil means
	// "root:root" is 0:0 and other names are looked up in the host's
	// user database.
	Owners func(owner string) (uid, gid uint32, err error)
}

func (o Options) withDefaults() (Options, error) {
	if o.Root == "" {
		o.Root = "/"
	}
	if !strings.HasPrefix(o.Root, "/") {
		return o, fmt.Errorf("%w: root must be absolute", ErrOptions)
	}
	switch {
	case o.MaxFiles < 0 || o.MaxFiles > MaxFiles:
		return o, fmt.Errorf("%w: max files must be 0 to %d", ErrOptions, MaxFiles)
	case o.MaxBytes < 0 || o.MaxBytes > MaxBytes:
		return o, fmt.Errorf("%w: max bytes must be 0 to %d", ErrOptions, int64(MaxBytes))
	case o.Budget < 0 || o.Budget > MaxBudget:
		return o, fmt.Errorf("%w: budget must be 0 to %s", ErrOptions, MaxBudget)
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = MaxFiles
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = MaxBytes
	}
	if o.Budget == 0 {
		o.Budget = DefaultBudget
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Owners == nil {
		o.Owners = lookupOwner
	}
	return o, nil
}
