// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trust is the executor-owned built-in module trust storage (spec
// 10, Release signing and Built-in module retention; ADR 0007 E15).
//
// It keeps the durable release-root state and rotation chain, the exact
// bytes of every active built-in module and of its retained predecessors
// with their signed manifest and signature, and an immutable tombstone
// (name, version, size, sha256) for every version ever accepted. It
// produces the local review of a verified release bundle (old/new
// versions, hashes, risks and full script diffs) and admits a reviewed
// bundle atomically under the storage ceilings.
//
// The store lives in a private executor directory: index.json is replaced
// atomically (write, fsync, rename, fsync directory) and objects/ holds
// content-addressed bytes. Retention confers no execution authority;
// trust tuples and confirmation belong to the trust transaction (E16).
package trust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fsguard"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// IndexFormat is the format of index.json.
const IndexFormat = "nebula-builtin-trust-v1"

// Storage ceilings and retention (spec 10, Storage ceiling and admission).
const (
	// MaxTotal is the hard ceiling of the whole store.
	MaxTotal = 2 << 30
	// MaxActive bounds active module tar bytes.
	MaxActive = 512 << 20
	// MaxHistory bounds historical module tar bytes.
	MaxHistory = 1 << 30
	// MaxStaging bounds the module tar bytes of one candidate.
	MaxStaging = 128 << 20
	// MaxMetadata bounds provenance, tombstone and root metadata,
	// including index.json.
	MaxMetadata = 128 << 20
	// MaxNames bounds distinct retained module names, removed included.
	MaxNames = 128
	// MaxTombstones bounds version tombstones.
	MaxTombstones = 200000
	// Retention is the minimum time a superseded version is kept.
	Retention = 90 * 24 * time.Hour
	// KeepPredecessors is how many most recent predecessors are kept
	// regardless of age.
	KeepPredecessors = 2
)

const (
	indexFile  = "index.json"
	objectsDir = "objects"
)

// Errors callers branch on.
var (
	// ErrStateMissing is a store directory that has objects but no
	// index: admission is blocked pending local recovery, never
	// silently bootstrapped.
	ErrStateMissing = errors.New("trust: built-in trust state is missing; local recovery is required")
	// ErrCorrupt is an index that does not validate.
	ErrCorrupt = errors.New("trust: built-in trust state is corrupt")
	// ErrSubstitution is a same-version change of bytes or size against
	// an active, retained or tombstoned version.
	ErrSubstitution = errors.New("trust: same-version bytes changed (substitution)")
	// ErrQuota is an admission that would exceed a storage, count or
	// free-space limit; nothing was changed.
	ErrQuota = errors.New("trust: storage or metadata limit reached; nothing was changed")
	// ErrStale is a review that no longer matches the store or the
	// candidate (concurrent change or substituted bytes).
	ErrStale = errors.New("trust: the review is stale; review again")
)

// VersionRecord is one retained version of a built-in module.
type VersionRecord struct {
	// Version is the module version.
	Version string `json:"version"`
	// Size and SHA256 identify the exact module tar bytes.
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// ManifestDigest names the signed manifest that delivered it.
	ManifestDigest string `json:"manifest_digest"`
	// AcceptedAt is the first acceptance; ActivatedAt the latest
	// activation.
	AcceptedAt  time.Time `json:"accepted_at"`
	ActivatedAt time.Time `json:"activated_at"`
	// SupersededAt is the latest active-to-inactive transition; zero
	// while active.
	SupersededAt time.Time `json:"superseded_at,omitzero"`
	// RetainUntil is the 90-day floor; it is never shortened.
	RetainUntil time.Time `json:"retain_until,omitzero"`
}

// ModuleRecord is a module family. Records are never deleted.
type ModuleRecord struct {
	// Name is the module family.
	Name string `json:"name"`
	// Active is the active version; nil after removal.
	Active *VersionRecord `json:"active,omitempty"`
	// History holds retained predecessors, most recently superseded
	// first.
	History []VersionRecord `json:"history"`
}

// Tombstone is the immutable record of an accepted version. It survives
// byte garbage collection and module removal.
type Tombstone struct {
	// Name, Version, Size and SHA256 identify the version.
	Name    string `json:"name"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	// ManifestDigest is the release that first delivered it.
	ManifestDigest string `json:"manifest_digest"`
	// AcceptedAt is the first acceptance; SupersededAt the latest
	// supersession (zero if never).
	AcceptedAt   time.Time `json:"accepted_at"`
	SupersededAt time.Time `json:"superseded_at,omitzero"`
}

// Provenance records a retained signed manifest.
type Provenance struct {
	// ManifestDigest is the SHA-256 of the manifest bytes (an object).
	ManifestDigest string `json:"manifest_digest"`
	// ManifestSize is the manifest's size.
	ManifestSize int64 `json:"manifest_size"`
	// SignatureSHA256 and SignatureSize name the signature object.
	SignatureSHA256 string `json:"signature_sha256"`
	SignatureSize   int64  `json:"signature_size"`
	// ReleaseVersion is the manifest's release version.
	ReleaseVersion string `json:"release_version"`
	// RootID and RootFingerprint name the signing root; RootSequence is
	// the root state sequence it was verified under.
	RootID          string `json:"root_id"`
	RootFingerprint string `json:"root_fingerprint"`
	RootSequence    int64  `json:"root_sequence"`
	// AdmittedAt is when it was admitted.
	AdmittedAt time.Time `json:"admitted_at"`
}

// RotationRecord records an applied root rotation; the document and its
// signature are kept as objects for historical verification.
type RotationRecord struct {
	// Sequence and Digest identify the document.
	Sequence int64  `json:"sequence"`
	Digest   string `json:"digest"`
	Size     int64  `json:"size"`
	// SignatureSHA256 and SignatureSize name the signature object.
	SignatureSHA256 string `json:"signature_sha256"`
	SignatureSize   int64  `json:"signature_size"`
	// RootID and RootFingerprint name the authorizing root.
	RootID          string `json:"root_id"`
	RootFingerprint string `json:"root_fingerprint"`
	// AppliedAt is when it was applied.
	AppliedAt time.Time `json:"applied_at"`
}

// index is the persisted state.
type index struct {
	Format string `json:"format"`
	// Generation increases with every committed change; reviews bind it.
	Generation int64 `json:"generation"`
	// ClockHighWater is the latest wall-clock time the store has seen.
	ClockHighWater time.Time         `json:"clock_high_water"`
	Roots          release.RootState `json:"roots"`
	Rotations      []RotationRecord  `json:"rotations"`
	Provenance     []Provenance      `json:"provenance"`
	Modules        []ModuleRecord    `json:"modules"`
	Tombstones     []Tombstone       `json:"tombstones"`
}

// Store is the executor's built-in trust storage. Its methods are safe
// for concurrent use; admission is serialized.
type Store struct {
	dir string
	now func() time.Time
	// freeSpace reports free bytes on the store's filesystem; injected
	// for tests.
	freeSpace func(string) (uint64, error)
	// limits are the storage ceilings; tests shrink them.
	limits limits

	mu  sync.Mutex
	idx index
}

// Open opens the store in dir, a private executor-owned directory. A
// directory with neither index nor objects is a fresh installation and is
// bootstrapped from the compiled anchors; objects without an index are
// missing state and block (ErrStateMissing). now is injected.
func Open(dir string, anchors []release.Anchor, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if err := fsguard.EnsurePrivateDir(dir); err != nil {
		return nil, fmt.Errorf("trust: store directory %s: %w", dir, err)
	}
	if err := fsguard.EnsurePrivateDir(filepath.Join(dir, objectsDir)); err != nil {
		return nil, fmt.Errorf("trust: objects directory: %w", err)
	}
	s := &Store{dir: dir, now: now, freeSpace: statfsFree, limits: defaultLimits}
	raw, err := readBounded(filepath.Join(dir, indexFile), MaxMetadata)
	switch {
	case errors.Is(err, os.ErrNotExist):
		entries, derr := os.ReadDir(filepath.Join(dir, objectsDir))
		if derr != nil {
			return nil, fmt.Errorf("trust: list objects: %w", derr)
		}
		if len(entries) > 0 {
			return nil, ErrStateMissing
		}
		roots, berr := release.Bootstrap(anchors)
		if berr != nil {
			return nil, fmt.Errorf("trust: bootstrap root state: %w", berr)
		}
		s.idx = index{Format: IndexFormat, Roots: roots, ClockHighWater: now().UTC(),
			Rotations: []RotationRecord{}, Provenance: []Provenance{}, Modules: []ModuleRecord{}, Tombstones: []Tombstone{}}
		if err := s.persist(s.idx); err != nil {
			return nil, err
		}
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("trust: read index: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var idx index
	if err := dec.Decode(&idx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if dec.More() || !bytes.Equal(bytes.TrimSpace(raw[dec.InputOffset():]), nil) {
		return nil, fmt.Errorf("%w: trailing data after the index", ErrCorrupt)
	}
	if err := idx.validate(); err != nil {
		return nil, err
	}
	s.idx = idx
	return s, nil
}

// validate checks a loaded index for consistency and limits.
func (x index) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
	}
	if x.Format != IndexFormat || x.Generation < 0 {
		return bad("unknown format or generation")
	}
	if err := x.Roots.Validate(); err != nil {
		return bad("root state: %v", err)
	}
	if len(x.Rotations) != int(x.Roots.Sequence) {
		return bad("%d rotation records for sequence %d", len(x.Rotations), x.Roots.Sequence)
	}
	for i, r := range x.Rotations {
		if r.Sequence != int64(i+1) || !validHex(r.Digest) || !validHex(r.SignatureSHA256) {
			return bad("rotation record %d is malformed", i)
		}
	}
	if n := len(x.Rotations); n > 0 && x.Rotations[n-1].Digest != x.Roots.Digest {
		return bad("root state digest does not match the last rotation record")
	}
	if len(x.Modules) > MaxNames || len(x.Tombstones) > MaxTombstones {
		return bad("count limits exceeded")
	}
	prov := map[string]bool{}
	for i, p := range x.Provenance {
		if !validHex(p.ManifestDigest) || !validHex(p.SignatureSHA256) || (i > 0 && x.Provenance[i-1].ManifestDigest >= p.ManifestDigest) {
			return bad("provenance records are malformed or unsorted")
		}
		prov[p.ManifestDigest] = true
	}
	tomb := map[string]Tombstone{}
	for i, t := range x.Tombstones {
		k := t.Name + "\x00" + t.Version
		if !validHex(t.SHA256) || t.Size <= 0 || (i > 0 && tombKey(x.Tombstones[i-1]) >= k) {
			return bad("tombstones are malformed or unsorted")
		}
		tomb[k] = t
	}
	check := func(name string, v VersionRecord) error {
		t, ok := tomb[name+"\x00"+v.Version]
		if !ok || t.SHA256 != v.SHA256 || t.Size != v.Size || !prov[v.ManifestDigest] {
			return bad("module %s %s lacks a matching tombstone or provenance", name, v.Version)
		}
		return nil
	}
	for i, m := range x.Modules {
		if i > 0 && x.Modules[i-1].Name >= m.Name {
			return bad("modules are unsorted")
		}
		seen := map[string]bool{}
		if m.Active != nil {
			if err := check(m.Name, *m.Active); err != nil {
				return err
			}
			seen[m.Active.Version] = true
		}
		for j, h := range m.History {
			if seen[h.Version] || h.SupersededAt.IsZero() || h.RetainUntil.Before(h.SupersededAt.Add(Retention)) ||
				(j > 0 && h.SupersededAt.After(m.History[j-1].SupersededAt)) {
				return bad("module %s history is inconsistent", m.Name)
			}
			seen[h.Version] = true
			if err := check(m.Name, h); err != nil {
				return err
			}
		}
	}
	return nil
}

func tombKey(t Tombstone) string { return t.Name + "\x00" + t.Version }

func validHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == hexLower(s)
}

func hexLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// Roots returns the currently trusted, non-revoked release roots.
func (s *Store) Roots() []release.Root {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idx.Roots.Active()
}

// RootState returns a copy of the durable root state.
func (s *Store) RootState() release.RootState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.idx.Roots
	st.Roots = append([]release.RootRecord(nil), st.Roots...)
	return st
}

// Generation returns the store generation reviews bind to.
func (s *Store) Generation() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idx.Generation
}

// Module returns a copy of a module record.
func (s *Store) Module(name string) (ModuleRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.idx.Modules {
		if m.Name == name {
			return cloneModule(m), true
		}
	}
	return ModuleRecord{}, false
}

// Tombstone returns the tombstone of a version.
func (s *Store) Tombstone(name, version string) (Tombstone, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idx.tombstone(name, version)
}

func (x index) tombstone(name, version string) (Tombstone, bool) {
	k := name + "\x00" + version
	i := sort.Search(len(x.Tombstones), func(i int) bool { return tombKey(x.Tombstones[i]) >= k })
	if i < len(x.Tombstones) && tombKey(x.Tombstones[i]) == k {
		return x.Tombstones[i], true
	}
	return Tombstone{}, false
}

func cloneModule(m ModuleRecord) ModuleRecord {
	out := ModuleRecord{Name: m.Name, History: append([]VersionRecord{}, m.History...)}
	if m.Active != nil {
		a := *m.Active
		out.Active = &a
	}
	return out
}

func (x index) clone() index {
	y := x
	y.Roots.Roots = append([]release.RootRecord(nil), x.Roots.Roots...)
	y.Rotations = append([]RotationRecord{}, x.Rotations...)
	y.Provenance = append([]Provenance{}, x.Provenance...)
	y.Tombstones = append([]Tombstone{}, x.Tombstones...)
	y.Modules = make([]ModuleRecord, len(x.Modules))
	for i, m := range x.Modules {
		y.Modules[i] = cloneModule(m)
	}
	return y
}

// ApplyRotation verifies a signed rotation against the current durable
// root state and persists the new state, the record and the document and
// signature atomically. Replays and competing updates fail closed.
func (s *Store) ApplyRotation(raw, sig []byte) (release.Rotation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, rot, err := s.idx.Roots.ApplyRotation(raw, sig)
	if err != nil {
		return release.Rotation{}, err
	}
	now := s.clock()
	if err := s.reserveMetadata(int64(len(raw) + len(sig))); err != nil {
		return release.Rotation{}, err
	}
	sigSum, err := s.putObject(sig)
	if err != nil {
		return release.Rotation{}, err
	}
	if _, err := s.putObject(raw); err != nil {
		return release.Rotation{}, err
	}
	x := s.idx.clone()
	x.Roots = next
	x.Rotations = append(x.Rotations, RotationRecord{Sequence: rot.Sequence, Digest: rot.Digest, Size: int64(len(raw)),
		SignatureSHA256: sigSum, SignatureSize: int64(len(sig)), RootID: rot.SignedBy.ID,
		RootFingerprint: rot.SignedBy.Fingerprint(), AppliedAt: now})
	x.Generation++
	x.ClockHighWater = maxTime(x.ClockHighWater, now)
	if err := s.persist(x); err != nil {
		return release.Rotation{}, err
	}
	s.idx = x
	return rot, nil
}

// clock returns the current time, never earlier than the high-water mark,
// so a backward clock can only lengthen retention.
func (s *Store) clock() time.Time {
	return maxTime(s.now().UTC(), s.idx.ClockHighWater)
}

// clockBackward reports whether the wall clock is behind the high-water
// mark; garbage collection is skipped then.
func (s *Store) clockBackward() bool { return s.now().UTC().Before(s.idx.ClockHighWater) }

// MaxClockJump is the largest forward wall-clock advance that garbage
// collection trusts in one step; a larger jump is an uncertain clock and
// collection is skipped (spec 10, "uncertain clock").
const MaxClockJump = 730 * 24 * time.Hour

// clockForward reports whether the wall clock jumped implausibly forward
// past the high-water mark; garbage collection is skipped then (spec 10,
// "a detected backward/uncertain clock must not make bytes eligible for
// early deletion").
func (s *Store) clockForward() bool {
	return s.now().UTC().Sub(s.idx.ClockHighWater) > MaxClockJump
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// persist writes x as index.json atomically.
func (s *Store) persist(x index) error {
	raw, err := json.Marshal(x)
	if err != nil {
		return fmt.Errorf("trust: encode index: %w", err)
	}
	if len(raw) > MaxMetadata {
		return fmt.Errorf("%w: index would exceed %d bytes", ErrQuota, MaxMetadata)
	}
	return writeAtomic(s.dir, indexFile, raw)
}

// writeAtomic writes name in dir via a temporary file, fsync and rename,
// then fsyncs the directory.
func writeAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("trust: create %s: %w", name, err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("trust: write %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("trust: sync %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("trust: close %s: %w", name, err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("trust: replace %s: %w", name, err)
	}
	ok = true
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("trust: open directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("trust: sync directory: %w", err)
	}
	return nil
}

// putObject stores data under its SHA-256. An existing object must hold
// exactly the same bytes.
func (s *Store) putObject(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	name := hex.EncodeToString(sum[:])
	dir := filepath.Join(s.dir, objectsDir)
	if got, err := readBounded(filepath.Join(dir, name), int64(len(data))); err == nil {
		if bytes.Equal(got, data) {
			return name, nil
		}
		// A corrupt object is replaced by the verified bytes.
	}
	if err := writeAtomic(dir, name, data); err != nil {
		return "", err
	}
	return name, nil
}

// getObject reads an object and checks its size and hash.
func (s *Store) getObject(sum string, size int64) ([]byte, error) {
	if !validHex(sum) {
		return nil, fmt.Errorf("%w: invalid object name", ErrCorrupt)
	}
	b, err := readBounded(filepath.Join(s.dir, objectsDir, sum), size)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(b)
	if int64(len(b)) != size || hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("%w: object %s does not match its hash", ErrCorrupt, sum)
	}
	return b, nil
}

// readBounded reads a regular file of at most max bytes without
// following a symlink at the final component.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%w: %s is not a regular file of at most %d bytes", ErrCorrupt, filepath.Base(path), max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("%w: read %s", ErrCorrupt, filepath.Base(path))
	}
	return b, nil
}

func statfsFree(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("trust: free space of %s: %w", dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func encodedSize(x index) (int64, error) {
	raw, err := json.Marshal(x)
	if err != nil {
		return 0, fmt.Errorf("trust: encode index: %w", err)
	}
	return int64(len(raw)), nil
}

// reserveMetadata checks that extra metadata bytes fit the metadata
// ceiling and the free disk space, before anything is written.
func (s *Store) reserveMetadata(extra int64) error {
	idxSize, err := encodedSize(s.idx)
	if err != nil {
		return err
	}
	meta := extra + idxSize + 1024
	for _, p := range s.idx.Provenance {
		meta += p.ManifestSize + p.SignatureSize
	}
	for _, r := range s.idx.Rotations {
		meta += r.Size + r.SignatureSize
	}
	if meta > s.limits.metadata {
		return fmt.Errorf("%w: metadata would be %d bytes, limit %d", ErrQuota, meta, s.limits.metadata)
	}
	free, err := s.freeSpace(s.dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQuota, err)
	}
	if need := uint64(extra + 2*idxSize + 1024); free < need {
		return fmt.Errorf("%w: %d bytes free, %d needed", ErrQuota, free, need)
	}
	return nil
}

// limits are the byte ceilings admission enforces.
type limits struct {
	active, history, staging, metadata, total int64
}

var defaultLimits = limits{active: MaxActive, history: MaxHistory, staging: MaxStaging, metadata: MaxMetadata, total: MaxTotal}
