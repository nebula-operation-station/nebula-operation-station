// SPDX-License-Identifier: AGPL-3.0-or-later

package fimretain

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// fuzzPaths is a small path set, so that inputs share paths between the
// previous records and the run. It includes a non-UTF-8 name and a prefix
// of another name, which exercise the raw-byte ordering.
var fuzzPaths = [...]string{"/etc", "/etc/a", "/etc/a\xff", "/etc/b", "/usr/bin/x", "/etc/ssh/sshd_config"}

// fuzzRecBytes is the number of input bytes that encode one record.
const fuzzRecBytes = 8

// fuzzMaxRecords bounds the records decoded from one input.
const fuzzMaxRecords = 32

// decodeFuzzRec turns eight bytes into one record. Every field is taken from
// a small set of values so that equal and differing tuples both occur often.
func decodeFuzzRec(b []byte) fimscan.Record {
	typ := fimscan.Type(b[1]%4) + fimscan.TypeFile
	r := fimscan.Record{
		Path:  []byte(fuzzPaths[int(b[0])%len(fuzzPaths)]),
		Type:  typ,
		Size:  int64(b[3] % 3),
		Mode:  []uint32{0o644, 0o600, 0o4755}[b[4]%3],
		UID:   uint32(b[7]>>3) % 2,
		GID:   0,
		Inode: uint64(b[7]>>4) % 2,
		Mtime: int64(b[5] % 3),
		Ctime: int64(b[6] % 3),
	}
	if b[7]&1 != 0 {
		r.Link = []byte{'x' + b[7]>>1&1}
	}
	// A hash on a non-file is invalid input; it is produced rarely so that
	// most inputs stay valid.
	if (typ == fimscan.TypeFile && b[2]%4 != 0) || b[2] == 0xff {
		r.Hash.Kind = fimscan.HashKeyed
		r.Hash.Sum[0] = b[2] % 4
	}
	return r
}

// decodeFuzz splits data into the previous records and a complete run. The
// first byte selects the mode (bit 0: full) and bit 1 makes the run partial;
// the second byte is the number of previous records. Paths are unique within
// each input, so duplicates do not mask the other rules.
func decodeFuzz(data []byte) ([]fimscan.Record, *fimscan.Result) {
	var flags, nPrev byte
	if len(data) > 0 {
		flags = data[0]
	}
	if len(data) > 1 {
		nPrev = data[1]
	}
	body := []byte{}
	if len(data) > 2 {
		body = data[2:]
	}
	var recs []fimscan.Record
	for len(body) >= fuzzRecBytes && len(recs) < fuzzMaxRecords {
		recs = append(recs, decodeFuzzRec(body[:fuzzRecBytes]))
		body = body[fuzzRecBytes:]
	}
	split := int(nPrev) % (len(recs) + 1)
	prev := uniquePaths(recs[:split])
	mode := fimscan.ModeIncremental
	if flags&1 != 0 {
		mode = fimscan.ModeFull
	}
	run := &fimscan.Result{ProfileID: "p", Mode: mode, Records: uniquePaths(recs[split:])}
	if flags&2 != 0 {
		run.Partial = []fimscan.Reason{fimscan.ReasonHostTruncated}
	}
	return prev, run
}

// uniquePaths keeps the first record of each path.
func uniquePaths(recs []fimscan.Record) []fimscan.Record {
	seen := make(map[string]bool, len(recs))
	out := make([]fimscan.Record, 0, len(recs))
	for _, r := range recs {
		if seen[string(r.Path)] {
			continue
		}
		seen[string(r.Path)] = true
		out = append(out, r)
	}
	return out
}

// sameTupleFields compares the nine D9 fields one by one. It is written out
// here, separately from sameMetadata, so the property check does not simply
// repeat the implementation.
func sameTupleFields(a, b *fimscan.Record) bool {
	if a.Size != b.Size || a.Mode != b.Mode || a.UID != b.UID || a.GID != b.GID {
		return false
	}
	if a.Inode != b.Inode || a.Mtime != b.Mtime || a.Ctime != b.Ctime || a.Type != b.Type {
		return false
	}
	return bytes.Equal(a.Link, b.Link)
}

// checkMergeProperties asserts the rules that hold for every successful merge.
func checkMergeProperties(t *testing.T, prev []fimscan.Record, run *fimscan.Result, got []fimscan.Record) {
	t.Helper()
	if len(got) > len(run.Records) {
		t.Fatalf("output has %d records, the run only %d", len(got), len(run.Records))
	}
	if len(got) != len(run.Records) {
		t.Fatalf("output has %d records, want one per run record (%d)", len(got), len(run.Records))
	}
	runByPath := make(map[string]*fimscan.Record, len(run.Records))
	for i := range run.Records {
		runByPath[string(run.Records[i].Path)] = &run.Records[i]
	}
	prevByPath := make(map[string]*fimscan.Record, len(prev))
	for i := range prev {
		prevByPath[string(prev[i].Path)] = &prev[i]
	}
	for i := range got {
		r := &got[i]
		if i > 0 && bytes.Compare(got[i-1].Path, r.Path) >= 0 {
			t.Fatalf("output not strictly sorted by raw path at index %d", i)
		}
		cur, ok := runByPath[string(r.Path)]
		if !ok {
			t.Fatalf("output path %q is not in the run", r.Path)
		}
		if r.Hash == cur.Hash {
			continue
		}
		// The hash differs from the run's, so it must be a kept hash.
		if run.Mode == fimscan.ModeFull || cur.Hash.Kind != fimscan.HashNone {
			t.Fatalf("hash of %q not taken from the run", r.Path)
		}
		old, ok := prevByPath[string(r.Path)]
		if !ok {
			t.Fatalf("hash kept for %q without a previous record", r.Path)
		}
		if !sameTupleFields(old, cur) {
			t.Fatalf("hash kept for %q across a metadata change", r.Path)
		}
		if old.Hash != r.Hash {
			t.Fatalf("hash of %q differs from the previous record's", r.Path)
		}
	}
}

// FuzzMerge checks the rules of Merge on arbitrary inputs: an error is
// returned only for an input that breaks a documented rule, a successful
// output is sorted and has one record per run record, and a hash is kept
// only from a previous record with an identical tuple. The inputs are never
// modified.
func FuzzMerge(f *testing.F) {
	// Record bytes: [path index, type-1, hash selector, size, mode, mtime,
	// ctime, flags]. Type 0 is a regular file, 1 a directory, 2 a symlink
	// and 3 another type; flags bit 0 is the link, bit 3 the uid.

	// Empty input: a complete incremental run with nothing in it.
	f.Add([]byte{})
	// Complete full run with no records.
	f.Add([]byte{1, 0})
	// Partial run: must be rejected.
	f.Add([]byte{2, 0, 0, 0, 1, 0, 0, 0, 0, 0})
	// Incremental run: one previous hashed file, then an unhashed run record
	// for the same path with an unchanged tuple (the hash is kept).
	f.Add([]byte{0, 1,
		1, 0, 1, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0})
	// Same, but the run record has a changed size (the hash is dropped).
	f.Add([]byte{0, 1,
		1, 0, 1, 0, 0, 0, 0, 0,
		1, 0, 0, 1, 0, 0, 0, 0})
	// Full run whose regular file has no hash (invalid, must be rejected).
	f.Add([]byte{1, 0, 1, 0, 0, 0, 0, 0, 0, 0})
	// Hash on a directory (invalid, must be rejected).
	f.Add([]byte{0, 0, 0, 1, 0xff, 0, 0, 0})
	// Non-UTF-8 path next to its prefix, a symlink with a target, and a
	// previous record for the prefix path that is not in the run.
	f.Add([]byte{0, 2,
		2, 0, 1, 0, 0, 0, 0, 0,
		1, 0, 2, 0, 0, 0, 0, 0,
		2, 0, 0, 0, 0, 0, 0, 0,
		4, 1, 0, 0, 0, 0, 0, 1,
		1, 0, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		prev, run := decodeFuzz(data)
		snapshot := make([]fimscan.Record, len(prev))
		for i := range prev {
			snapshot[i] = cloneRecord(&prev[i])
		}

		got, err := Merge(prev, run)
		if !reflect.DeepEqual(prev, snapshot) {
			t.Fatal("Merge modified the previous records")
		}
		if run.Partial != nil {
			if !errors.Is(err, ErrIncompleteRun) || got != nil {
				t.Fatalf("partial run: got %d records, error %v", len(got), err)
			}
			return
		}
		if err != nil {
			if got != nil {
				t.Fatalf("error %v returned together with %d records", err, len(got))
			}
			return
		}
		checkMergeProperties(t, prev, run, got)
	})
}
