// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimretain merges one complete fim-scan-v1 run into the records a
// host retains between runs (ADR 0015 D7 and D9).
//
// It is a pure library: no database, no clock, no I/O. Its contract:
//
//   - An incomplete run is rejected and replaces nothing.
//   - A complete full run replaces every retained record.
//   - A complete incremental run replaces a retained content hash only for
//     the paths it hashed. For a path it did not hash, the previous hash is
//     kept while the nine-field metadata tuple (size, mode, uid, gid, inode,
//     mtime, ctime, type, link) is identical, and dropped otherwise. A hash
//     never survives a metadata change.
//   - Paths missing from the run are dropped.
//
// Not covered here: the store, the executor-side approval of a baseline,
// the critical-class classification and the look-back window of the
// incremental runs.
package fimretain

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// Sentinel errors. Callers branch on them with errors.Is.
var (
	// ErrNilRun is returned when no run is given.
	ErrNilRun = errors.New("fimretain: nil run")
	// ErrIncompleteRun is returned for a run that is partial (ADR 0015 D6).
	// Such a run never replaces retained records.
	ErrIncompleteRun = errors.New("fimretain: run is not complete")
	// ErrUnknownMode is returned for a run whose mode is neither full nor
	// incremental.
	ErrUnknownMode = errors.New("fimretain: unknown scan mode")
	// ErrTooManyRecords is returned when an input holds more than
	// fimscan.MaxRecords records.
	ErrTooManyRecords = errors.New("fimretain: too many records")
	// ErrDuplicatePath is returned when one input holds the same path twice.
	ErrDuplicatePath = errors.New("fimretain: duplicate path")
	// ErrInvalidRecord is returned for a record that violates the rules
	// above: a hash on a non-file, or a regular file without a hash in a
	// complete full run.
	ErrInvalidRecord = errors.New("fimretain: invalid record")
)

// Merge returns the retained records after the run prev is merged with run.
// prev and run are not modified; the returned records share no memory with
// them. The result is sorted by raw path bytes and has one record per path
// in run. On error, Merge returns no records and the caller keeps prev.
//
// A regular file that the run did not hash keeps the content hash of its
// previous record only when every field of the metadata tuple matches; see
// the package documentation.
func Merge(prev []fimscan.Record, run *fimscan.Result) ([]fimscan.Record, error) {
	if run == nil {
		return nil, ErrNilRun
	}
	if !run.Complete() {
		return nil, ErrIncompleteRun
	}
	if run.Mode != fimscan.ModeFull && run.Mode != fimscan.ModeIncremental {
		return nil, ErrUnknownMode
	}
	if len(prev) > fimscan.MaxRecords || len(run.Records) > fimscan.MaxRecords {
		return nil, ErrTooManyRecords
	}
	prevIdx, err := index(prev)
	if err != nil {
		return nil, fmt.Errorf("previous records: %w", err)
	}
	if _, err := index(run.Records); err != nil {
		return nil, fmt.Errorf("run: %w", err)
	}
	if run.Mode == fimscan.ModeFull {
		for i := range run.Records {
			r := &run.Records[i]
			if r.Type == fimscan.TypeFile && r.Hash.Kind == fimscan.HashNone {
				return nil, fmt.Errorf("%w: regular file without hash in full run", ErrInvalidRecord)
			}
		}
	}

	out := make([]fimscan.Record, 0, len(run.Records))
	for i := range run.Records {
		cur := &run.Records[i]
		r := cloneRecord(cur)
		if run.Mode == fimscan.ModeIncremental && r.Type == fimscan.TypeFile && r.Hash.Kind == fimscan.HashNone {
			if j, ok := prevIdx[string(cur.Path)]; ok && sameMetadata(&prev[j], cur) {
				r.Hash = prev[j].Hash
			}
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b fimscan.Record) int {
		return bytes.Compare(a.Path, b.Path)
	})
	return out, nil
}

// index maps each path of recs to its position and rejects duplicate paths
// and hashes on anything that is not a regular file.
func index(recs []fimscan.Record) (map[string]int, error) {
	idx := make(map[string]int, len(recs))
	for i := range recs {
		r := &recs[i]
		if r.Hash.Kind != fimscan.HashNone && r.Type != fimscan.TypeFile {
			return nil, fmt.Errorf("%w: hash on %s", ErrInvalidRecord, r.Type)
		}
		if _, dup := idx[string(r.Path)]; dup {
			return nil, ErrDuplicatePath
		}
		idx[string(r.Path)] = i
	}
	return idx, nil
}

// sameMetadata reports whether a and b agree on the whole D9 metadata
// tuple. The comparison is strict: any differing field, including a
// symlink target, makes the tuples differ.
func sameMetadata(a, b *fimscan.Record) bool {
	return a.Size == b.Size &&
		a.Mode == b.Mode &&
		a.UID == b.UID &&
		a.GID == b.GID &&
		a.Inode == b.Inode &&
		a.Mtime == b.Mtime &&
		a.Ctime == b.Ctime &&
		a.Type == b.Type &&
		bytes.Equal(a.Link, b.Link)
}

// cloneRecord returns a copy of r that shares no byte slices with it.
func cloneRecord(r *fimscan.Record) fimscan.Record {
	c := *r
	c.Path = slices.Clone(r.Path)
	c.Link = slices.Clone(r.Link)
	return c
}
