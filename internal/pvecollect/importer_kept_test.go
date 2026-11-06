// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"golang.org/x/sys/unix"
)

// keptFixture is an importer on a settable clock whose store failure a test
// switches, and which records the generations that reached the store.
type keptFixture struct {
	im      *Importer
	spool   *Spool
	logs    interface{ String() string }
	now     time.Time
	fail    func(pvecontract.Observation) bool
	ingests []uint64
}

func newKeptFixture(t *testing.T) *keptFixture {
	t.Helper()
	im, spool, store, _, logs := newRetryImporter(t)
	f := &keptFixture{im: im, spool: spool, logs: logs, now: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	f.fail = func(pvecontract.Observation) bool { return true }
	im.now = func() time.Time { return f.now }
	im.ingest = func(ctx context.Context, obs pvecontract.Observation) (pveinventory.IngestReport, error) {
		f.ingests = append(f.ingests, obs.CollectionGeneration)
		if f.fail(obs) {
			return pveinventory.IngestReport{}, errors.New("injected-store-failure")
		}
		return store.IngestObservation(ctx, obs)
	}
	return f
}

// pass runs one import pass and returns its report.
func (f *keptFixture) pass(t *testing.T) ImportReport {
	t.Helper()
	rep, err := f.im.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	return rep
}

// generations lists the spooled generations of remote in name order.
func (f *keptFixture) generations(t *testing.T, remote string) []uint64 {
	t.Helper()
	names, err := f.spool.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var gens []uint64
	for _, name := range names {
		if r, gen, err := parseSpoolName(name); err == nil && r == remote {
			gens = append(gens, gen)
		}
	}
	return gens
}

// spoolGenerations spools a valid observation of remote for each generation.
func spoolGenerations(t *testing.T, spool *Spool, remote string, gens ...uint64) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	expectTempDirOwnership(t, root)
	template, err := NewSpool(root)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	defer template.Close()
	oneObservation(t, template)
	names, err := template.List(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("List = %v, %v", names, err)
	}
	obs, err := template.ReadFile(ctx, names[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	obs.RemoteID = remote
	for _, gen := range gens {
		obs.CollectionGeneration = gen
		if _, err := spool.WriteFile(ctx, obs); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
}

func equalGens(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A failing store costs one ingest per retry, however many files wait: the
// retry after the first failure comes on the next pass, then the delay
// doubles up to its cap, and nothing is deleted while it does.
func TestImporterBacksOffRemoteAfterStoreFailure(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 7, 8)

	want := []time.Duration{0, keptRetryBase, 2 * keptRetryBase, 4 * keptRetryBase, keptRetryMax, keptRetryMax, keptRetryMax}
	for i, delay := range want {
		f.ingests = nil
		rep := f.pass(t)
		if len(f.ingests) != 1 || rep.Partial != 1 {
			t.Fatalf("retry %d: ingests = %v, report = %+v, want one attempt", i, f.ingests, rep)
		}
		if rep.Deferred != 1 {
			t.Fatalf("retry %d: report = %+v, want the other file deferred", i, rep)
		}
		if delay > 0 {
			f.now = f.now.Add(delay - time.Second)
			f.ingests = nil
			rep := f.pass(t)
			if len(f.ingests) != 0 || rep.Deferred != 2 || rep.Partial != 0 {
				t.Fatalf("retry %d: ingests = %v, report = %+v, want a quiet pass inside the delay", i, f.ingests, rep)
			}
			f.now = f.now.Add(time.Second)
		}
		if got := f.generations(t, "remote-a"); !equalGens(got, []uint64{7, 8}) {
			t.Fatalf("retry %d: spool = %v, want both files kept", i, got)
		}
	}
}

// Success ends the episode: the next failure starts from the short delay
// again.
func TestImporterResetsBackoffAfterSuccess(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 7)
	for range 3 {
		f.pass(t)
		f.now = f.now.Add(keptRetryMax)
	}
	f.fail = func(pvecontract.Observation) bool { return false }
	if rep := f.pass(t); rep.Imported != 1 {
		t.Fatalf("report = %+v, want 1 imported", rep)
	}

	f.fail = func(pvecontract.Observation) bool { return true }
	spoolGenerations(t, f.spool, "remote-a", 8)
	f.ingests = nil
	f.pass(t)
	f.pass(t)
	if !equalGens(f.ingests, []uint64{8, 8}) {
		t.Fatalf("ingests = %v, want the first failure retried on the next pass", f.ingests)
	}
}

// One remote's trouble does not delay another's.
func TestImporterBacksOffOnlyTheFailingRemote(t *testing.T) {
	f := newKeptFixture(t)
	f.fail = func(obs pvecontract.Observation) bool { return obs.RemoteID == "remote-b" }
	spoolGenerations(t, f.spool, "remote-a", 1)
	spoolGenerations(t, f.spool, "remote-b", 1)
	for range 3 {
		f.pass(t)
	}
	spoolGenerations(t, f.spool, "remote-a", 2)
	if rep := f.pass(t); rep.Imported != 1 || rep.Deferred != 1 {
		t.Fatalf("report = %+v, want remote-a imported, remote-b deferred", rep)
	}
}

// A failing remote keeps its newest files only, whatever fails and however
// long: each is superseded by the generations above it, and the newest stays.
func TestImporterKeepsOnlyNewestFilesOfFailingRemote(t *testing.T) {
	gens := []uint64{1, 2, 3, 4, 5, 6, 7}
	newest := gens[len(gens)-maxKeptPerRemote:]
	cases := []struct {
		name  string
		setup func(f *keptFixture) (restore func())
	}{
		{"store fails", func(*keptFixture) func() { return func() {} }},
		{"reads fail", func(f *keptFixture) func() { return failReads(f.spool, unix.EIO) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeptFixture(t)
			spoolGenerations(t, f.spool, "remote-a", gens...)
			restore := tc.setup(f)
			f.pass(t)
			if got := f.generations(t, "remote-a"); !equalGens(got, gens) {
				t.Fatalf("first failure dropped files: spool = %v", got)
			}

			rep := f.pass(t)
			if rep.Pruned != len(gens)-maxKeptPerRemote {
				t.Fatalf("report = %+v, want the older files pruned", rep)
			}
			if got := f.generations(t, "remote-a"); !equalGens(got, newest) {
				t.Fatalf("spool = %v, want %v", got, newest)
			}
			spoolGenerations(t, f.spool, "remote-a", 8)
			f.now = f.now.Add(keptRetryMax)
			f.pass(t)
			want := append(append([]uint64{}, newest[1:]...), 8)
			if got := f.generations(t, "remote-a"); !equalGens(got, want) {
				t.Fatalf("spool = %v, want %v", got, want)
			}

			restore()
			f.fail = func(pvecontract.Observation) bool { return false }
			f.ingests = nil
			f.now = f.now.Add(keptRetryMax)
			rep = f.pass(t)
			if !equalGens(f.ingests, []uint64{8}) || rep.Imported != 1 || rep.Replayed != len(want)-1 {
				t.Fatalf("ingests = %v, report = %+v, want the newest applied and the rest superseded", f.ingests, rep)
			}
			if got := f.generations(t, "remote-a"); len(got) != 0 {
				t.Fatalf("spool = %v, want empty", got)
			}
		})
	}
}

// The cap is about kept files: a backlog that imports is not thinned out, and
// it applies in generation order.
func TestImporterAppliesHealthyBacklogInOrder(t *testing.T) {
	f := newKeptFixture(t)
	f.fail = func(pvecontract.Observation) bool { return false }
	gens := []uint64{1, 2, 3, 4, 5, 6, 7}
	spoolGenerations(t, f.spool, "remote-a", gens...)
	if rep := f.pass(t); rep.Imported != len(gens) || rep.Pruned != 0 {
		t.Fatalf("report = %+v, want all imported", rep)
	}
	if !equalGens(f.ingests, gens) {
		t.Fatalf("ingests = %v, want %v", f.ingests, gens)
	}
}

// A dataset that keeps failing on every generation must not leave the remote
// lagging behind by the kept files: the retry takes the newest.
func TestImporterRetriesNewestFileFirst(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 1)
	f.pass(t)
	spoolGenerations(t, f.spool, "remote-a", 2, 3)
	f.ingests = nil
	f.pass(t)
	if !equalGens(f.ingests, []uint64{3}) {
		t.Fatalf("ingests = %v, want the newest generation", f.ingests)
	}
}

// An unreadable file must not hold back a readable one, on the first pass or
// a retry, and the import supersedes it.
func TestImporterImportsPastUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	for _, tc := range []struct {
		name       string
		unreadable uint64
	}{
		{"older file", 1},
		{"newest file", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeptFixture(t)
			f.fail = func(pvecontract.Observation) bool { return false }
			spoolGenerations(t, f.spool, "remote-a", 1, 2)
			name, err := spoolFileName("remote-a", tc.unreadable)
			if err != nil {
				t.Fatal(err)
			}
			path := f.spool.ResultsDir() + "/" + name
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(path, spoolFileMode) })

			for range 3 {
				f.pass(t)
			}
			if got := f.ingests; len(got) != 1 || got[0] == tc.unreadable {
				t.Fatalf("ingests = %v, want the readable file once", got)
			}
		})
	}
}

// Failing reads cost at most the kept files per pass, also with a long
// backlog, and never touch the store.
func TestImporterBoundsReadsOfFailingRemote(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 1, 2, 3, 4, 5, 6, 7)
	reads := 0
	f.spool.read = func(*os.File, string, int64) ([]byte, error) {
		reads++
		return nil, unix.EIO
	}
	f.pass(t)
	for range 3 {
		reads = 0
		f.pass(t)
		if reads != maxKeptPerRemote {
			t.Fatalf("reads = %d, want %d", reads, maxKeptPerRemote)
		}
	}
	if len(f.ingests) != 0 {
		t.Fatalf("ingests = %v, want none", f.ingests)
	}
}

// One warning per pass, whatever the backlog: without file names and without
// the store's text.
func TestImporterLogsOneSummaryPerPass(t *testing.T) {
	cases := []struct {
		name, reason string
		setup        func(f *keptFixture)
	}{
		{"store", "store_failed", func(*keptFixture) {}},
		{"read", "read_failed", func(f *keptFixture) { failReads(f.spool, unix.EIO) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newKeptFixture(t)
			spoolGenerations(t, f.spool, "remote-a", 1, 2, 3, 4, 5)
			spoolGenerations(t, f.spool, "remote-b", 1, 2)
			tc.setup(f)
			const passes = 4
			for range passes {
				f.pass(t)
			}
			got := f.logs.String()
			if n := strings.Count(got, `"level":"WARN"`); n != passes {
				t.Fatalf("warnings = %d, want %d:\n%s", n, passes, got)
			}
			if !strings.Contains(got, `"reason":"`+tc.reason+`"`) {
				t.Fatalf("log misses reason %s:\n%s", tc.reason, got)
			}
			if strings.Contains(got, ".gen-") || strings.Contains(got, "injected") {
				t.Fatalf("log must not name files or quote errors:\n%s", got)
			}
		})
	}
}

// The retry state follows the spool, so it cannot outgrow it.
func TestImporterForgetsRemoteWithoutFiles(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 1)
	f.pass(t)
	if len(f.im.kept) != 1 {
		t.Fatalf("kept = %v, want the failing remote", f.im.kept)
	}
	if err := f.spool.Remove(context.Background(), "remote-a.gen-00000000000000000001.json"); err != nil {
		t.Fatal(err)
	}
	f.pass(t)
	if len(f.im.kept) != 0 {
		t.Fatalf("kept = %v, want it forgotten", f.im.kept)
	}
}

// A pruned file the directory refuses to give up is left to the stuck set: it
// is not imported afterwards and the cap costs no further reads.
func TestImporterTreatsUnremovablePrunedFileAsStuck(t *testing.T) {
	f := newKeptFixture(t)
	spoolGenerations(t, f.spool, "remote-a", 1, 2, 3, 4, 5)
	f.pass(t)
	f.im.remove = failRemove
	f.now = f.now.Add(keptRetryMax)
	f.pass(t)
	if len(f.im.stuck) != 2 {
		t.Fatalf("stuck = %v, want the two pruned files", f.im.stuck)
	}
	f.fail = func(pvecontract.Observation) bool { return false }
	f.ingests = nil
	f.now = f.now.Add(keptRetryMax)
	f.pass(t)
	if !equalGens(f.ingests, []uint64{5}) {
		t.Fatalf("ingests = %v, want the newest only", f.ingests)
	}
}
