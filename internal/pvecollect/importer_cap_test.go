// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"golang.org/x/sys/unix"
)

// scriptReads makes the listed generations unreadable or undecodable, leaving
// every other file alone. restore puts the previous read back.
func scriptReads(t *testing.T, s *Spool, unreadable, invalid []uint64) (restore func()) {
	t.Helper()
	read := s.read
	s.read = func(dir *os.File, name string, limit int64) ([]byte, error) {
		_, gen, err := parseSpoolName(name)
		if err != nil {
			return nil, fmt.Errorf("scripted read of %s: %w", name, err)
		}
		switch {
		case slices.Contains(unreadable, gen):
			return nil, unix.EIO
		case slices.Contains(invalid, gen):
			return []byte("{"), nil
		}
		return read(dir, name, limit)
	}
	return func() { s.read = read }
}

// The newest files staying unreadable judges nothing: the file below them may
// be the last valid observation of the remote, so the cap leaves it alone
// while the store fails, and it is still there when things recover.
func TestImporterCapKeepsOlderFilesBelowUnreadableNewest(t *testing.T) {
	f := newKeptFixture(t)
	gens := []uint64{1, 2, 3, 4, 5, 6, 7}
	spoolGenerations(t, f.spool, "remote-a", gens...)
	restore := scriptReads(t, f.spool, []uint64{5, 6, 7}, nil)
	for i := range 4 {
		rep := f.pass(t)
		if rep.Pruned != 0 {
			t.Fatalf("pass %d: report = %+v, want nothing pruned", i, rep)
		}
		if got := f.generations(t, "remote-a"); !equalGens(got, gens) {
			t.Fatalf("pass %d: spool = %v, want %v", i, got, gens)
		}
		f.now = f.now.Add(keptRetryMax)
	}

	restore()
	f.fail = func(pvecontract.Observation) bool { return false }
	f.ingests = nil
	if rep := f.pass(t); !equalGens(f.ingests, []uint64{7}) || rep.Imported != 1 {
		t.Fatalf("ingests = %v, report = %+v, want the newest applied", f.ingests, rep)
	}
}

// With every read failing no file is ever judged, so none is capped away, and
// the backlog resolves once a read works.
func TestImporterKeepsAllFilesWhileReadsFail(t *testing.T) {
	f := newKeptFixture(t)
	gens := []uint64{1, 2, 3, 4, 5, 6, 7}
	spoolGenerations(t, f.spool, "remote-a", gens...)
	restore := failReads(f.spool, unix.EIO)
	f.pass(t)
	rep := f.pass(t)
	if rep.Pruned != 0 || rep.Failed != maxKeptPerRemote || rep.Held != len(gens)-maxKeptPerRemote {
		t.Fatalf("report = %+v, want the newest tried and the rest held", rep)
	}
	spoolGenerations(t, f.spool, "remote-a", 8)
	f.pass(t)
	want := append(slices.Clone(gens), 8)
	if got := f.generations(t, "remote-a"); !equalGens(got, want) {
		t.Fatalf("spool = %v, want %v", got, want)
	}

	restore()
	f.fail = func(pvecontract.Observation) bool { return false }
	f.ingests = nil
	rep = f.pass(t)
	if !equalGens(f.ingests, []uint64{8}) || rep.Imported != 1 || rep.Replayed != len(gens) {
		t.Fatalf("ingests = %v, report = %+v, want the newest applied and the rest superseded", f.ingests, rep)
	}
	if got := f.generations(t, "remote-a"); len(got) != 0 {
		t.Fatalf("spool = %v, want empty", got)
	}
}

// When the newest files prove invalid, the file below them is the remote's
// last valid observation: it is tried in the same pass, survives a store
// failure, and applies once the store recovers. Only what lies below it goes.
func TestImporterAppliesLastValidFileBelowInvalidNewest(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *keptFixture)
	}{
		{"read side", func(t *testing.T, f *keptFixture) {
			scriptReads(t, f.spool, nil, []uint64{5, 6, 7})
		}},
		{"ingest side", func(_ *testing.T, f *keptFixture) {
			ingest := f.im.ingest
			f.im.ingest = func(ctx context.Context, obs pvecontract.Observation) (pveinventory.IngestReport, error) {
				if obs.CollectionGeneration >= 5 {
					return pveinventory.IngestReport{}, fmt.Errorf("test: %w", pvecontract.ErrInvalid)
				}
				return ingest(ctx, obs)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeptFixture(t)
			spoolGenerations(t, f.spool, "remote-a", 1, 2, 3, 4, 5, 6, 7)
			tc.setup(t, f)
			f.pass(t)

			rep := f.pass(t)
			if rep.Rejected != 3 || rep.Partial != 1 || rep.Pruned != 3 {
				t.Fatalf("report = %+v, want 3 rejected, 1 partial, 3 pruned", rep)
			}
			if got := f.generations(t, "remote-a"); !equalGens(got, []uint64{4}) {
				t.Fatalf("spool = %v, want the last valid file", got)
			}

			f.fail = func(pvecontract.Observation) bool { return false }
			f.ingests = nil
			f.now = f.now.Add(keptRetryMax)
			if rep := f.pass(t); !equalGens(f.ingests, []uint64{4}) || rep.Imported != 1 {
				t.Fatalf("ingests = %v, report = %+v, want the last valid file applied", f.ingests, rep)
			}
			if got := f.generations(t, "remote-a"); len(got) != 0 {
				t.Fatalf("spool = %v, want empty", got)
			}
		})
	}
}

// The cap still works around files it cannot judge: once a file is valid, what
// is older goes, while the file itself and the unreadable newer one stay.
func TestImporterCapRemovesOnlyFilesBelowValidFile(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 1, 2, 3, 4, 5, 6, 7)
	scriptReads(t, f.spool, []uint64{7}, []uint64{6})
	f.pass(t)

	rep := f.pass(t)
	if rep.Failed != 1 || rep.Rejected != 1 || rep.Partial != 1 || rep.Pruned != 4 {
		t.Fatalf("report = %+v, want 1 failed, 1 rejected, 1 partial, 4 pruned", rep)
	}
	if got := f.generations(t, "remote-a"); !equalGens(got, []uint64{5, 7}) {
		t.Fatalf("spool = %v, want the valid file and the unreadable one", got)
	}
}

// The judgement outlives its pass: during the back-off, with no attempt at
// all, older files above the cap go, but never the judged file itself.
func TestImporterCapUsesEarlierJudgementDuringBackoff(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 1, 2, 3)
	f.pass(t)
	f.pass(t)
	spoolGenerations(t, f.spool, "remote-a", 4, 5, 6)
	f.ingests = nil

	rep := f.pass(t)
	if len(f.ingests) != 0 || rep.Pruned != 2 || rep.Deferred != 4 {
		t.Fatalf("ingests = %v, report = %+v, want a quiet pass that prunes 2", f.ingests, rep)
	}
	if got := f.generations(t, "remote-a"); !equalGens(got, []uint64{3, 4, 5, 6}) {
		t.Fatalf("spool = %v, want the judged file and the newer ones", got)
	}
}

// A judged file only protects the cap's decision while it waits in the spool:
// once it is gone, nothing covers the older files any more.
func TestImporterCapForgetsJudgedFileThatLeftTheSpool(t *testing.T) {
	cases := []struct {
		name string
		gone func(t *testing.T, f *keptFixture)
	}{
		{"rejected on retry", func(t *testing.T, f *keptFixture) {
			scriptReads(t, f.spool, nil, []uint64{5})
		}},
		{"removed", func(t *testing.T, f *keptFixture) {
			name, err := spoolFileName("remote-a", 5)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.spool.Remove(context.Background(), name); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeptFixture(t)
			spoolGenerations(t, f.spool, "remote-a", 1, 2, 3, 4, 5)
			scriptReads(t, f.spool, []uint64{1, 2, 3, 4}, nil)
			f.pass(t)
			tc.gone(t, f)

			if rep := f.pass(t); rep.Pruned != 0 {
				t.Fatalf("report = %+v, want nothing pruned", rep)
			}
			if got := f.generations(t, "remote-a"); !equalGens(got, []uint64{1, 2, 3, 4}) {
				t.Fatalf("spool = %v, want the older files kept", got)
			}
		})
	}
}
