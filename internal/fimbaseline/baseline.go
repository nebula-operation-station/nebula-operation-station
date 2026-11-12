// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// Errors callers branch on.
var (
	// ErrInvalidInput: a baseline or scan breaks a structural rule
	// (nil, bad path, duplicate path, field out of range).
	ErrInvalidInput = errors.New("fimbaseline: invalid input")
	// ErrLimit: an input exceeds a named limit of limits.go.
	ErrLimit = errors.New("fimbaseline: limit exceeded")
	// ErrPartialScan: a baseline can only be built from a complete run
	// (ADR 0015 D7 "Initial baseline": "The first complete scan").
	ErrPartialScan = errors.New("fimbaseline: scan is partial")
	// ErrUnhashedFile: a file record without a content hash cannot enter a
	// baseline until a full run has hashed it (ADR 0015 D7).
	ErrUnhashedFile = errors.New("fimbaseline: file record without content hash")
	// ErrProfileMismatch: the scan was taken with another profile than the
	// baseline.
	ErrProfileMismatch = errors.New("fimbaseline: profile mismatch")
)

// digestDomain separates the baseline digest from every other SHA-256 in
// NOS. A future change of the canonical form must change this string.
const digestDomain = "nebula-fim-baseline-digest-v1"

// Digest is the SHA-256 of a baseline's canonical form.
type Digest [sha256.Size]byte

// String returns the digest as 64 lowercase hex characters.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// Baseline is the approved (or proposed) per-host reference of ADR 0015 D7:
// the records of one complete run, sorted by raw path bytes, plus the
// mount points that run reported. It is immutable after construction.
type Baseline struct {
	profileID string
	entries   []fimscan.Record // sorted by Path, unique
	mounts    []fimscan.Mount  // sorted by Path, unique
	digest    Digest
}

// NewBaseline builds a baseline from a parsed fim-scan-v1 result. The
// result must be complete, every file record must carry a content hash,
// and all limits must hold. The input is deep-copied.
func NewBaseline(scan *fimscan.Result) (*Baseline, error) {
	if scan == nil {
		return nil, fmt.Errorf("new baseline: %w: nil scan", ErrInvalidInput)
	}
	if !scan.Complete() {
		return nil, fmt.Errorf("new baseline: %w", ErrPartialScan)
	}
	if err := checkProfileID(scan.ProfileID); err != nil {
		return nil, fmt.Errorf("new baseline: %w", err)
	}
	entries, err := sortedRecords(scan.Records)
	if err != nil {
		return nil, fmt.Errorf("new baseline: %w", err)
	}
	for i := range entries {
		if entries[i].Type == fimscan.TypeFile && entries[i].Hash.Kind == fimscan.HashNone {
			return nil, fmt.Errorf("new baseline: entry %d: %w", i, ErrUnhashedFile)
		}
	}
	mounts, err := sortedMounts(scan.Mounts)
	if err != nil {
		return nil, fmt.Errorf("new baseline: %w", err)
	}
	b := &Baseline{profileID: scan.ProfileID, entries: entries, mounts: mounts}
	b.digest = sha256.Sum256(b.canonical())
	return b, nil
}

// ProfileID returns the profile the baseline was taken with.
func (b *Baseline) ProfileID() string { return b.profileID }

// Len returns the number of entries.
func (b *Baseline) Len() int { return len(b.entries) }

// Digest returns the SHA-256 over the canonical form.
func (b *Baseline) Digest() Digest { return b.digest }

// Entries returns a deep copy of the entries, sorted by raw path bytes.
func (b *Baseline) Entries() []fimscan.Record {
	out := make([]fimscan.Record, len(b.entries))
	for i := range b.entries {
		out[i] = cloneRecord(b.entries[i])
	}
	return out
}

// Mounts returns a copy of the mount entries, sorted by raw path bytes.
func (b *Baseline) Mounts() []fimscan.Mount {
	out := make([]fimscan.Mount, len(b.mounts))
	for i, m := range b.mounts {
		out[i] = fimscan.Mount{Path: bytes.Clone(m.Path), FSType: m.FSType}
	}
	return out
}

// canonical returns the canonical byte form the digest is computed over.
// All integers are big-endian, all byte strings are length-prefixed, the
// entries and mounts are in raw path byte order:
//
//	domain "\x00" u32 len(profile) profile
//	u64 n, n × entry:
//	  u32 len(path) path, u8 type, i64 size, u32 mode, u32 uid, u32 gid,
//	  u64 inode, i64 mtime, i64 ctime,
//	  u8 hash kind, u8 secret, [32] sum (only when kind != none),
//	  u32 len(link) link
//	u64 m, m × mount: u32 len(path) path, u32 len(fstype) fstype
func (b *Baseline) canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString(digestDomain)
	buf.WriteByte(0)
	putBytes(&buf, []byte(b.profileID))
	putU64(&buf, uint64(len(b.entries)))
	for i := range b.entries {
		e := &b.entries[i]
		putBytes(&buf, e.Path)
		buf.WriteByte(byte(e.Type))
		putU64(&buf, uint64(e.Size))
		putU32(&buf, e.Mode)
		putU32(&buf, e.UID)
		putU32(&buf, e.GID)
		putU64(&buf, e.Inode)
		putU64(&buf, uint64(e.Mtime))
		putU64(&buf, uint64(e.Ctime))
		buf.WriteByte(byte(e.Hash.Kind))
		if e.Hash.Secret {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
		if e.Hash.Kind != fimscan.HashNone {
			buf.Write(e.Hash.Sum[:])
		}
		putBytes(&buf, e.Link)
	}
	putU64(&buf, uint64(len(b.mounts)))
	for _, m := range b.mounts {
		putBytes(&buf, m.Path)
		putBytes(&buf, []byte(m.FSType))
	}
	return buf.Bytes()
}

func putU32(buf *bytes.Buffer, v uint32) {
	buf.Write(binary.BigEndian.AppendUint32(nil, v))
}

func putU64(buf *bytes.Buffer, v uint64) {
	buf.Write(binary.BigEndian.AppendUint64(nil, v))
}

func putBytes(buf *bytes.Buffer, b []byte) {
	putU32(buf, uint32(len(b)))
	buf.Write(b)
}

func checkProfileID(id string) error {
	if id == "" || len(id) > MaxProfileIDBytes {
		return fmt.Errorf("%w: bad profile ID", ErrInvalidInput)
	}
	return nil
}

// checkPath re-checks the D6 path rules that this package relies on, so a
// baseline never holds a path the parser would have rejected.
func checkPath(p []byte) error {
	if len(p) > MaxPathBytes {
		return fmt.Errorf("%w: path of %d bytes", ErrLimit, len(p))
	}
	if len(p) < 2 || p[0] != '/' || p[len(p)-1] == '/' || bytes.IndexByte(p, 0) >= 0 {
		return fmt.Errorf("%w: malformed path", ErrInvalidInput)
	}
	comps := strings.Split(string(p[1:]), "/")
	if len(comps) > MaxPathDepth {
		return fmt.Errorf("%w: path depth %d", ErrLimit, len(comps))
	}
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return fmt.Errorf("%w: malformed path component", ErrInvalidInput)
		}
	}
	return nil
}

func checkRecord(r *fimscan.Record) error {
	if err := checkPath(r.Path); err != nil {
		return err
	}
	if r.Type < fimscan.TypeFile || r.Type > fimscan.TypeOther {
		return fmt.Errorf("%w: bad type", ErrInvalidInput)
	}
	if r.Mode > fimscan.MaxMode || r.Size < 0 {
		return fmt.Errorf("%w: field out of range", ErrInvalidInput)
	}
	if (r.Type == fimscan.TypeSymlink) != (r.Link != nil) {
		return fmt.Errorf("%w: link on wrong type", ErrInvalidInput)
	}
	if r.Link != nil && (len(r.Link) == 0 || bytes.IndexByte(r.Link, 0) >= 0) {
		return fmt.Errorf("%w: malformed link", ErrInvalidInput)
	}
	if len(r.Link) > MaxLinkBytes {
		return fmt.Errorf("%w: link of %d bytes", ErrLimit, len(r.Link))
	}
	if r.Hash.Kind > fimscan.HashKeyed || (r.Hash.Kind != fimscan.HashNone && r.Type != fimscan.TypeFile) {
		return fmt.Errorf("%w: bad hash", ErrInvalidInput)
	}
	return nil
}

// sortedRecords validates and deep-copies recs, sorted by raw path bytes.
func sortedRecords(recs []fimscan.Record) ([]fimscan.Record, error) {
	if len(recs) > MaxEntries {
		return nil, fmt.Errorf("%w: %d records", ErrLimit, len(recs))
	}
	out := make([]fimscan.Record, len(recs))
	for i := range recs {
		if err := checkRecord(&recs[i]); err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		out[i] = cloneRecord(recs[i])
	}
	slices.SortFunc(out, func(a, b fimscan.Record) int { return bytes.Compare(a.Path, b.Path) })
	for i := 1; i < len(out); i++ {
		if bytes.Equal(out[i-1].Path, out[i].Path) {
			return nil, fmt.Errorf("%w: duplicate path", ErrInvalidInput)
		}
	}
	return out, nil
}

// sortedMounts validates and deep-copies ms, sorted by raw path bytes.
func sortedMounts(ms []fimscan.Mount) ([]fimscan.Mount, error) {
	if len(ms) > MaxMounts {
		return nil, fmt.Errorf("%w: %d mounts", ErrLimit, len(ms))
	}
	out := make([]fimscan.Mount, len(ms))
	for i, m := range ms {
		if err := checkPath(m.Path); err != nil {
			return nil, fmt.Errorf("mount %d: %w", i, err)
		}
		if m.FSType == "" || len(m.FSType) > MaxFSTypeBytes {
			return nil, fmt.Errorf("mount %d: %w: bad fstype", i, ErrInvalidInput)
		}
		out[i] = fimscan.Mount{Path: bytes.Clone(m.Path), FSType: m.FSType}
	}
	slices.SortFunc(out, func(a, b fimscan.Mount) int { return bytes.Compare(a.Path, b.Path) })
	for i := 1; i < len(out); i++ {
		if bytes.Equal(out[i-1].Path, out[i].Path) {
			return nil, fmt.Errorf("%w: duplicate mount", ErrInvalidInput)
		}
	}
	return out, nil
}

func cloneRecord(r fimscan.Record) fimscan.Record {
	r.Path = bytes.Clone(r.Path)
	if r.Link != nil {
		r.Link = bytes.Clone(r.Link)
	}
	return r
}
