// SPDX-License-Identifier: AGPL-3.0-or-later

package fimretain

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// hashed returns a keyed content hash with the first byte set to b.
func hashed(b byte) fimscan.Hash {
	var h fimscan.Hash
	h.Kind = fimscan.HashKeyed
	h.Sum[0] = b
	return h
}

// fileRec returns a regular-file record with a fixed metadata tuple.
func fileRec(p string, h fimscan.Hash) fimscan.Record {
	return fimscan.Record{
		Path:  []byte(p),
		Type:  fimscan.TypeFile,
		Size:  10,
		Mode:  0o644,
		UID:   0,
		GID:   0,
		Inode: 100,
		Mtime: 1000,
		Ctime: 1000,
		Hash:  h,
	}
}

// dirRec returns a directory record.
func dirRec(p string) fimscan.Record {
	return fimscan.Record{Path: []byte(p), Type: fimscan.TypeDir, Mode: 0o755, Inode: 50, Mtime: 1000, Ctime: 1000}
}

// run returns a complete result of the given mode holding recs.
func run(mode fimscan.Mode, recs ...fimscan.Record) *fimscan.Result {
	return &fimscan.Result{ProfileID: "p", Mode: mode, Records: recs}
}

// partial returns r with a partial-run reason set.
func partial(r *fimscan.Result) *fimscan.Result {
	r.Partial = []fimscan.Reason{fimscan.ReasonRecordLimit}
	return r
}

// TestNonZeroExitWithEmptyPartialKeepsRetainedRecords: a script that exits
// non-zero can leave Result.Partial empty, because fimscan documents that the
// caller must still treat a non-zero exit as partial. Such a run must replace
// nothing, in either mode, whatever the exit status.
func TestNonZeroExitWithEmptyPartialKeepsRetainedRecords(t *testing.T) {
	t.Parallel()
	for _, mode := range []fimscan.Mode{fimscan.ModeFull, fimscan.ModeIncremental} {
		for _, exit := range []int{1, 2, 124, 143, 255} {
			t.Run(fmt.Sprintf("%s exit %d", mode, exit), func(t *testing.T) {
				t.Parallel()
				prev := []fimscan.Record{fileRec("/etc/a", hashed(1))}
				got, err := Merge(prev, run(mode, fileRec("/etc/a", hashed(2))), exit)
				if !errors.Is(err, ErrIncompleteRun) {
					t.Fatalf("Merge error = %v, want ErrIncompleteRun", err)
				}
				if got != nil {
					t.Fatalf("Merge returned %+v with a non-zero exit; want no records", got)
				}
				if !reflect.DeepEqual(prev, []fimscan.Record{fileRec("/etc/a", hashed(1))}) {
					t.Fatal("Merge changed the previous records")
				}
			})
		}
	}
}

// TestMergeZeroExitIsComplete: exit status 0 with an empty Partial is a
// complete run, so the merge succeeds.
func TestMergeZeroExitIsComplete(t *testing.T) {
	t.Parallel()
	got, err := Merge(nil, run(fimscan.ModeFull, fileRec("/etc/a", hashed(2))), 0)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if !reflect.DeepEqual(got, []fimscan.Record{fileRec("/etc/a", hashed(2))}) {
		t.Fatalf("Merge = %+v", got)
	}
}

// TestFullRunIgnoresPreviousRecords: a complete full run does not depend on
// the previous records, so a corrupt retained set must not block it. The
// full run is the one that repairs the set.
func TestFullRunIgnoresPreviousRecords(t *testing.T) {
	t.Parallel()
	corrupt := [][]fimscan.Record{
		{fileRec("/etc/a", hashed(1)), fileRec("/etc/a", hashed(2))},
		{{Path: []byte("/etc"), Type: fimscan.TypeDir, Hash: hashed(1)}},
		make([]fimscan.Record, fimscan.MaxRecords+1),
	}
	for i, prev := range corrupt {
		got, err := Merge(prev, run(fimscan.ModeFull, fileRec("/etc/a", hashed(3))), 0)
		if err != nil {
			t.Fatalf("case %d: full run rejected because of previous records: %v", i, err)
		}
		if !reflect.DeepEqual(got, []fimscan.Record{fileRec("/etc/a", hashed(3))}) {
			t.Fatalf("case %d: Merge = %+v", i, got)
		}
	}
}

func TestMergeRejectsUnusableInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		prev    []fimscan.Record
		run     *fimscan.Result
		exit    int
		wantErr error
	}{
		{
			name:    "nil run is rejected",
			run:     nil,
			wantErr: ErrNilRun,
		},
		{
			name:    "non-zero exit with empty partial is rejected",
			prev:    []fimscan.Record{fileRec("/etc/a", hashed(1))},
			run:     run(fimscan.ModeIncremental, fileRec("/etc/a", fimscan.Hash{})),
			exit:    1,
			wantErr: ErrIncompleteRun,
		},
		{
			name:    "incomplete incremental run replaces nothing",
			prev:    []fimscan.Record{fileRec("/etc/a", hashed(1))},
			run:     partial(run(fimscan.ModeIncremental, fileRec("/etc/a", fimscan.Hash{}))),
			wantErr: ErrIncompleteRun,
		},
		{
			name:    "incomplete full run replaces nothing",
			prev:    []fimscan.Record{fileRec("/etc/a", hashed(1))},
			run:     partial(run(fimscan.ModeFull, fileRec("/etc/a", hashed(2)))),
			wantErr: ErrIncompleteRun,
		},
		{
			name:    "unknown mode is rejected",
			run:     run(fimscan.Mode("bogus")),
			wantErr: ErrUnknownMode,
		},
		{
			name:    "more previous records than MaxRecords is rejected",
			prev:    make([]fimscan.Record, fimscan.MaxRecords+1),
			run:     run(fimscan.ModeIncremental),
			wantErr: ErrTooManyRecords,
		},
		{
			name:    "more run records than MaxRecords is rejected",
			run:     run(fimscan.ModeIncremental, make([]fimscan.Record, fimscan.MaxRecords+1)...),
			wantErr: ErrTooManyRecords,
		},
		{
			name:    "duplicate path in the previous records is rejected",
			prev:    []fimscan.Record{fileRec("/etc/a", hashed(1)), fileRec("/etc/a", hashed(2))},
			run:     run(fimscan.ModeIncremental),
			wantErr: ErrDuplicatePath,
		},
		{
			name:    "duplicate path in the run is rejected",
			run:     run(fimscan.ModeIncremental, fileRec("/etc/a", hashed(1)), fileRec("/etc/a", hashed(2))),
			wantErr: ErrDuplicatePath,
		},
		{
			name:    "hash on a directory is rejected",
			run:     run(fimscan.ModeIncremental, fimscan.Record{Path: []byte("/etc"), Type: fimscan.TypeDir, Hash: hashed(1)}),
			wantErr: ErrInvalidRecord,
		},
		{
			name:    "regular file without hash in a complete full run is rejected",
			run:     run(fimscan.ModeFull, fileRec("/etc/a", fimscan.Hash{})),
			wantErr: ErrInvalidRecord,
		},
		{
			name:    "hash on a previous directory is rejected",
			prev:    []fimscan.Record{{Path: []byte("/etc"), Type: fimscan.TypeDir, Hash: hashed(1)}},
			run:     run(fimscan.ModeIncremental),
			wantErr: ErrInvalidRecord,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Merge(tc.prev, tc.run, tc.exit)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Merge error = %v, want %v", err, tc.wantErr)
			}
			if got != nil {
				t.Fatalf("Merge returned %d records with an error; want none", len(got))
			}
		})
	}
}

func TestMergeKeepsRulesOfD7(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		prev []fimscan.Record
		run  *fimscan.Result
		want []fimscan.Record
	}{
		{
			name: "full run replaces every retained record",
			prev: []fimscan.Record{fileRec("/etc/a", hashed(1)), fileRec("/etc/gone", hashed(2))},
			run:  run(fimscan.ModeFull, fileRec("/etc/a", hashed(3)), dirRec("/etc")),
			want: []fimscan.Record{dirRec("/etc"), fileRec("/etc/a", hashed(3))},
		},
		{
			name: "incremental run takes the new hash of a hashed path",
			prev: []fimscan.Record{fileRec("/etc/a", hashed(1))},
			run:  run(fimscan.ModeIncremental, fileRec("/etc/a", hashed(2))),
			want: []fimscan.Record{fileRec("/etc/a", hashed(2))},
		},
		{
			name: "unhashed file with unchanged metadata keeps the previous hash",
			prev: []fimscan.Record{fileRec("/etc/a", hashed(1))},
			run:  run(fimscan.ModeIncremental, fileRec("/etc/a", fimscan.Hash{})),
			want: []fimscan.Record{fileRec("/etc/a", hashed(1))},
		},
		{
			name: "unhashed file with changed metadata loses the hash",
			prev: []fimscan.Record{fileRec("/etc/a", hashed(1))},
			run: func() *fimscan.Result {
				r := fileRec("/etc/a", fimscan.Hash{})
				r.Size = 11
				return run(fimscan.ModeIncremental, r)
			}(),
			want: func() []fimscan.Record {
				r := fileRec("/etc/a", fimscan.Hash{})
				r.Size = 11
				return []fimscan.Record{r}
			}(),
		},
		{
			name: "unhashed file that the previous records do not know gets no hash",
			prev: nil,
			run:  run(fimscan.ModeIncremental, fileRec("/etc/new", fimscan.Hash{})),
			want: []fimscan.Record{fileRec("/etc/new", fimscan.Hash{})},
		},
		{
			name: "previous record without hash stays without hash",
			prev: []fimscan.Record{fileRec("/etc/a", fimscan.Hash{})},
			run:  run(fimscan.ModeIncremental, fileRec("/etc/a", fimscan.Hash{})),
			want: []fimscan.Record{fileRec("/etc/a", fimscan.Hash{})},
		},
		{
			name: "path missing from the incremental run is dropped",
			prev: []fimscan.Record{fileRec("/etc/a", hashed(1)), fileRec("/etc/b", hashed(2))},
			run:  run(fimscan.ModeIncremental, fileRec("/etc/b", fimscan.Hash{})),
			want: []fimscan.Record{fileRec("/etc/b", hashed(2))},
		},
		{
			name: "directories without hash are kept as metadata",
			prev: []fimscan.Record{dirRec("/etc")},
			run:  run(fimscan.ModeIncremental, dirRec("/etc")),
			want: []fimscan.Record{dirRec("/etc")},
		},
		{
			name: "output is sorted by raw path bytes",
			prev: nil,
			run: run(fimscan.ModeIncremental,
				fileRec("/etc/b", fimscan.Hash{}),
				fileRec("/etc/a\xff", fimscan.Hash{}),
				fileRec("/etc/a", fimscan.Hash{}),
				dirRec("/etc"),
			),
			want: []fimscan.Record{
				dirRec("/etc"),
				fileRec("/etc/a", fimscan.Hash{}),
				fileRec("/etc/a\xff", fimscan.Hash{}),
				fileRec("/etc/b", fimscan.Hash{}),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Merge(tc.prev, tc.run, 0)
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Merge =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}

// TestMergeMetadataFieldChangeDropsHash changes exactly one field of the
// D9 tuple (size, mode, uid, gid, inode, mtime, ctime, type, link) and
// checks that the retained hash is dropped, whichever side carries the
// change.
func TestMergeMetadataFieldChangeDropsHash(t *testing.T) {
	t.Parallel()
	changes := []struct {
		name   string
		mutate func(*fimscan.Record)
	}{
		{"size", func(r *fimscan.Record) { r.Size++ }},
		{"mode permission bits", func(r *fimscan.Record) { r.Mode = 0o600 }},
		{"mode setuid bit only", func(r *fimscan.Record) { r.Mode |= 0o4000 }},
		{"uid", func(r *fimscan.Record) { r.UID = 1000 }},
		{"gid", func(r *fimscan.Record) { r.GID = 1000 }},
		{"inode", func(r *fimscan.Record) { r.Inode++ }},
		{"mtime", func(r *fimscan.Record) { r.Mtime++ }},
		{"ctime", func(r *fimscan.Record) { r.Ctime++ }},
		{"type", func(r *fimscan.Record) { r.Type = fimscan.TypeOther }},
		{"link", func(r *fimscan.Record) { r.Link = []byte("/elsewhere") }},
	}
	for _, c := range changes {
		t.Run(c.name+" changed on the run side", func(t *testing.T) {
			t.Parallel()
			cur := fileRec("/etc/a", fimscan.Hash{})
			c.mutate(&cur)
			got, err := Merge([]fimscan.Record{fileRec("/etc/a", hashed(1))}, run(fimscan.ModeIncremental, cur), 0)
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if len(got) != 1 || got[0].Hash.Kind != fimscan.HashNone {
				t.Fatalf("hash kept across a %s change: %+v", c.name, got)
			}
		})
		// A hashed record must be a regular file, so a type change cannot
		// be placed on the previous side: that input is itself invalid.
		if c.name == "type" {
			continue
		}
		t.Run(c.name+" changed on the previous side", func(t *testing.T) {
			t.Parallel()
			old := fileRec("/etc/a", hashed(1))
			c.mutate(&old)
			got, err := Merge([]fimscan.Record{old}, run(fimscan.ModeIncremental, fileRec("/etc/a", fimscan.Hash{})), 0)
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if len(got) != 1 || got[0].Hash.Kind != fimscan.HashNone {
				t.Fatalf("hash kept across a %s change: %+v", c.name, got)
			}
		})
	}
}

// TestMergeDoesNotAliasInput: the output shares no bytes with either input.
// The run record's path and link are the ones that get copied to the output,
// so an implementation that skipped the copy and returned run.Records
// directly must fail here.
func TestMergeDoesNotAliasInput(t *testing.T) {
	t.Parallel()
	prev := []fimscan.Record{fileRec("/etc/a", hashed(1))}
	prev[0].Link = []byte("x")
	cur := fileRec("/etc/a", fimscan.Hash{})
	cur.Link = []byte("x")
	cur.Mtime = 2000
	res := run(fimscan.ModeIncremental, cur)
	// The tuples differ (Mtime), so no hash is kept and the output is the
	// run record alone, copied.
	got, err := Merge(prev, res, 0)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Merge returned %d records, want 1", len(got))
	}
	got[0].Path[0] = 'X'
	got[0].Link[0] = 'Y'
	if res.Records[0].Path[0] != '/' || res.Records[0].Link[0] != 'x' {
		t.Fatal("output shares memory with the run records")
	}
	if prev[0].Path[0] != '/' || prev[0].Link[0] != 'x' {
		t.Fatal("output shares memory with the previous records")
	}
}
