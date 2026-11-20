// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source for a store under test.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// useClock makes Current and PruneSnapshots read the time from a settable
// clock starting at base, and restores the real clock when the test ends.
// Tests in this file do not run in parallel, so the swap is not shared.
func useClock(t *testing.T) *clock {
	t.Helper()
	c := &clock{t: base}
	prev := nowFunc
	nowFunc = c.now
	t.Cleanup(func() { nowFunc = prev })
	return c
}

func mustCurrent(t *testing.T, s *Store, hosts []string, maxReuse time.Duration, floor int64) Snapshot {
	t.Helper()
	snap, err := s.Current(context.Background(), hosts, maxReuse, floor)
	if err != nil {
		t.Fatalf("Current(%v, %v, %d): %v", hosts, maxReuse, floor, err)
	}
	return snap
}

// readIDs returns the read row IDs of snap in order.
func readIDs(snap Snapshot) []int64 {
	ids := make([]int64, 0, len(snap.Reads))
	for _, r := range snap.Reads {
		ids = append(ids, r.ID)
	}
	return ids
}

func TestCurrentReusesSnapshotWithSameReadsWithinMaxReuse(t *testing.T) {
	s, db := openStore(t)
	c := useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	mustPut(t, s, testRead("h2", true, 0))
	hosts := []string{"h1", "h2"}

	first := mustCurrent(t, s, hosts, time.Hour, 0)
	c.t = base.Add(59 * time.Minute)
	second := mustCurrent(t, s, hosts, time.Hour, 0)

	if second.ID != first.ID || second.Generation != first.Generation {
		t.Fatalf("second = %s gen %d, want reuse of %s gen %d", second.ID, second.Generation, first.ID, first.Generation)
	}
	if n := rowCountTable(t, db, "vuln_inventory_snapshots"); n != 1 {
		t.Fatalf("snapshot rows = %d, want 1", n)
	}
}

func TestCurrentCreatesNewSnapshotAfterNewRead(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	first := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	newer := mustPut(t, s, testRead("h1", true, 10))
	second := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	if second.ID != "nos-inv-2" || second.Generation != 2 {
		t.Fatalf("second = %s gen %d, want nos-inv-2 gen 2", second.ID, second.Generation)
	}
	if got := readIDs(second); !reflect.DeepEqual(got, []int64{newer}) {
		t.Fatalf("second reads = %v, want [%d]", got, newer)
	}
	if first.ID == second.ID {
		t.Fatalf("new read reused snapshot %s", first.ID)
	}
}

func TestCurrentCreatesNewSnapshotAfterMaxReuseExpires(t *testing.T) {
	s, _ := openStore(t)
	c := useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	first := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	c.t = base.Add(time.Hour)
	second := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	if second.ID == first.ID || second.Generation != first.Generation+1 {
		t.Fatalf("second = %s gen %d after first %s gen %d: want a new snapshot",
			second.ID, second.Generation, first.ID, first.Generation)
	}
	if !reflect.DeepEqual(readIDs(second), readIDs(first)) {
		t.Fatalf("same reads expected, got %v and %v", readIDs(first), readIDs(second))
	}
}

func TestCurrentZeroMaxReuseNeverReuses(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	first := mustCurrent(t, s, []string{"h1"}, 0, 0)
	second := mustCurrent(t, s, []string{"h1"}, 0, 0)
	if second.ID == first.ID {
		t.Fatalf("maxReuse 0 reused %s", first.ID)
	}
}

func TestCurrentCreatesNewSnapshotWhenHostRemoved(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	mustPut(t, s, testRead("h2", true, 0))
	both := mustCurrent(t, s, []string{"h1", "h2"}, time.Hour, 0)

	only := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	if only.ID == both.ID || only.Generation != both.Generation+1 {
		t.Fatalf("only h1 = %s gen %d, want a new snapshot after %s gen %d",
			only.ID, only.Generation, both.ID, both.Generation)
	}
	if len(only.Reads) != 1 || only.Reads[0].HostID != "h1" {
		t.Fatalf("only h1 reads = %+v, want exactly h1", only.Reads)
	}
}

func TestCurrentSkipsHostsWithoutRead(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", false, 0))
	snap := mustCurrent(t, s, []string{"h0", "h1", "h9"}, time.Hour, 0)
	if len(snap.Reads) != 1 || snap.Reads[0].HostID != "h1" {
		t.Fatalf("reads = %+v, want only h1", snap.Reads)
	}
}

func TestCurrentUsesNewestReadPerHostInHostOrder(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h2", true, 0))
	old := mustPut(t, s, testRead("h1", true, 0))
	newH1 := mustPut(t, s, testRead("h1", false, 5))
	h2 := mustPut(t, s, testRead("h2", true, 0))
	_ = old

	snap := mustCurrent(t, s, []string{"h2", "h1"}, time.Hour, 0)
	if len(snap.Reads) != 2 {
		t.Fatalf("reads = %d, want 2", len(snap.Reads))
	}
	if snap.Reads[0].HostID != "h1" || snap.Reads[0].ID != newH1 {
		t.Fatalf("reads[0] = %s/%d, want h1/%d (newest read, host order)", snap.Reads[0].HostID, snap.Reads[0].ID, newH1)
	}
	if snap.Reads[1].HostID != "h2" || snap.Reads[1].ID != h2 {
		t.Fatalf("reads[1] = %s/%d, want h2/%d", snap.Reads[1].HostID, snap.Reads[1].ID, h2)
	}
}

func TestCurrentFloorSetsFirstGeneration(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	snap := mustCurrent(t, s, []string{"h1"}, time.Hour, 495000)
	if snap.ID != "nos-inv-495001" || snap.Generation != 495001 {
		t.Fatalf("snapshot = %s gen %d, want nos-inv-495001 gen 495001", snap.ID, snap.Generation)
	}
	next := mustPut(t, s, testRead("h1", true, 1))
	again := mustCurrent(t, s, []string{"h1"}, time.Hour, 495000)
	if again.Generation != 495002 || !reflect.DeepEqual(readIDs(again), []int64{next}) {
		t.Fatalf("again = %s gen %d reads %v, want gen 495002 with read %d",
			again.ID, again.Generation, readIDs(again), next)
	}
}

func TestCurrentFloorBelowStoredGenerationDoesNotLower(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	mustCurrent(t, s, []string{"h1"}, 0, 0)
	mustPut(t, s, testRead("h1", true, 1))
	snap := mustCurrent(t, s, []string{"h1"}, 0, 0)
	if snap.Generation != 2 {
		t.Fatalf("generation = %d, want 2", snap.Generation)
	}
}

func TestCurrentWithoutReadsCreatesEmptySnapshot(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	snap := mustCurrent(t, s, nil, time.Hour, 0)
	if snap.Generation != 1 || len(snap.Reads) != 0 {
		t.Fatalf("snapshot = gen %d with %d reads, want gen 1 and none", snap.Generation, len(snap.Reads))
	}
}

func TestOldSnapshotKeepsItsReadsForever(t *testing.T) {
	s, db := openStore(t)
	useClock(t)
	// An unpinned older read of h1: it is neither the newest nor pinned once
	// the snapshot below is taken, so it may be deleted (iv02 has no Prune;
	// this removes it with SQL to simulate one).
	old := mustPut(t, s, testRead("h1", true, 0))
	pinned := mustPut(t, s, testRead("h1", true, 5))
	first := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)
	if got := readIDs(first); !reflect.DeepEqual(got, []int64{pinned}) {
		t.Fatalf("first reads = %v, want [%d]", got, pinned)
	}
	firstBefore, err := s.Snapshot(context.Background(), first.ID)
	if err != nil {
		t.Fatalf("Snapshot before newer read: %v", err)
	}

	newer := mustPut(t, s, testRead("h1", false, 10))
	mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	if _, err := db.Exec(`DELETE FROM vuln_inventory_reads WHERE id = ?`, old); err != nil {
		t.Fatalf("delete unpinned old read: %v", err)
	}

	after, err := s.Snapshot(context.Background(), first.ID)
	if err != nil {
		t.Fatalf("Snapshot after newer read and delete: %v", err)
	}
	if !reflect.DeepEqual(after, firstBefore) {
		t.Fatalf("snapshot changed:\n before %+v\n after  %+v", firstBefore, after)
	}
	if after.Reads[0].ID != pinned || after.Reads[0].ID == newer {
		t.Fatalf("snapshot read = %d, want pinned %d", after.Reads[0].ID, pinned)
	}
}

func TestSnapshotReturnsReadsWithComponents(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	mustPut(t, s, testRead("h2", true, 0))
	cur := mustCurrent(t, s, []string{"h2", "h1"}, time.Hour, 0)

	got, err := s.Snapshot(context.Background(), cur.ID)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got.ID != cur.ID || got.Generation != cur.Generation || !got.TakenAt.Equal(cur.TakenAt) {
		t.Fatalf("metadata = %s gen %d at %v, want %s gen %d at %v",
			got.ID, got.Generation, got.TakenAt, cur.ID, cur.Generation, cur.TakenAt)
	}
	if len(got.Reads) != 2 || got.Reads[0].HostID != "h1" || got.Reads[1].HostID != "h2" {
		t.Fatalf("reads not in host order: %+v", got.Reads)
	}
	for _, r := range got.Reads {
		if len(r.Components) != 1 || r.Components[0].Source != "openssl" {
			t.Fatalf("read %s has components %+v, want the stored body", r.HostID, r.Components)
		}
	}
}

func TestSnapshotUnknownIDIsGone(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	if _, err := s.Snapshot(context.Background(), "nos-inv-99"); !errors.Is(err, ErrSnapshotGone) {
		t.Fatalf("err = %v, want ErrSnapshotGone", err)
	}
}

func TestPruneSnapshotsRemovesOldAndKeepsNewest(t *testing.T) {
	s, db := openStore(t)
	c := useClock(t)
	ctx := context.Background()
	mustPut(t, s, testRead("h1", true, 0))
	oldest := mustCurrent(t, s, []string{"h1"}, 0, 0)
	mustPut(t, s, testRead("h1", true, 1))
	middle := mustCurrent(t, s, []string{"h1"}, 0, 0)

	c.t = base.Add(48 * time.Hour)
	mustPut(t, s, testRead("h1", true, 2))
	newest := mustCurrent(t, s, []string{"h1"}, 0, 0)

	if err := s.PruneSnapshots(ctx, 24*time.Hour); err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}

	for _, id := range []string{oldest.ID, middle.ID} {
		if _, err := s.Snapshot(ctx, id); !errors.Is(err, ErrSnapshotGone) {
			t.Fatalf("Snapshot(%s) after prune: err = %v, want ErrSnapshotGone", id, err)
		}
	}
	got, err := s.Snapshot(ctx, newest.ID)
	if err != nil {
		t.Fatalf("Snapshot(newest) after prune: %v", err)
	}
	if got.Generation != newest.Generation {
		t.Fatalf("newest generation = %d, want %d", got.Generation, newest.Generation)
	}
	if n := rowCountTable(t, db, "vuln_inventory_snapshot_reads"); n != 1 {
		t.Fatalf("membership rows = %d, want 1 (only the newest snapshot)", n)
	}
}

func TestPruneSnapshotsKeepsNewestEvenWhenOld(t *testing.T) {
	s, _ := openStore(t)
	c := useClock(t)
	ctx := context.Background()
	mustPut(t, s, testRead("h1", true, 0))
	only := mustCurrent(t, s, []string{"h1"}, 0, 0)

	c.t = base.Add(1000 * time.Hour)
	if err := s.PruneSnapshots(ctx, time.Hour); err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}
	if _, err := s.Snapshot(ctx, only.ID); err != nil {
		t.Fatalf("newest snapshot removed: %v", err)
	}
}

func TestPruneSnapshotsRejectsNonPositiveAge(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	for _, age := range []time.Duration{0, -time.Second} {
		if err := s.PruneSnapshots(context.Background(), age); err == nil {
			t.Fatalf("PruneSnapshots(%v) accepted", age)
		}
	}
}

func TestCurrentRejectsInvalidInput(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	ctx := context.Background()
	cases := []struct {
		name     string
		hosts    []string
		maxReuse time.Duration
		floor    int64
	}{
		{"empty host id", []string{""}, time.Hour, 0},
		{"invalid utf-8 host id", []string{"h\xff"}, time.Hour, 0},
		{"host id over limit", []string{fmt.Sprintf("%0129d", 1)}, time.Hour, 0},
		{"negative maxReuse", nil, -time.Second, 0},
		{"negative floor", nil, time.Hour, -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.Current(ctx, c.hosts, c.maxReuse, c.floor); !errors.Is(err, ErrInvalidRead) {
				t.Fatalf("err = %v, want ErrInvalidRead", err)
			}
		})
	}
}

func TestCurrentLimitsHostsToMaxSnapshotHosts(t *testing.T) {
	s, _ := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h00000", true, 0))
	mustPut(t, s, testRead("h00001", true, 0))
	// h10004 sorts after the first MaxSnapshotHosts host IDs and is left out.
	mustPut(t, s, testRead("h10004", true, 0))

	hosts := make([]string, 0, MaxSnapshotHosts+5)
	for i := 0; i < MaxSnapshotHosts+5; i++ {
		hosts = append(hosts, fmt.Sprintf("h%05d", i))
	}
	snap := mustCurrent(t, s, hosts, time.Hour, 0)
	if snap.Omitted != 5 {
		t.Fatalf("omitted = %d, want 5", snap.Omitted)
	}
	if len(snap.Reads) != 2 || snap.Reads[0].HostID != "h00000" || snap.Reads[1].HostID != "h00001" {
		t.Fatalf("reads = %+v, want h00000 and h00001 only", snap.Reads)
	}
}

func TestMaxSnapshotHostsIsTheExportLimit(t *testing.T) {
	if MaxSnapshotHosts != 10000 {
		t.Fatalf("MaxSnapshotHosts = %d, want 10000 (api.MaxExportSubjects, vulnstore.MaxCoveredPerRun)", MaxSnapshotHosts)
	}
}

func TestConcurrentCurrentWithReuseYieldsOneSnapshot(t *testing.T) {
	s, db := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snap, err := s.Current(context.Background(), []string{"h1"}, time.Hour, 0)
			ids[i], errs[i] = snap.ID, err
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("Current %d: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("Current %d = %s, want %s (one snapshot for one read set)", i, ids[i], ids[0])
		}
	}
	if rows := rowCountTable(t, db, "vuln_inventory_snapshots"); rows != 1 {
		t.Fatalf("snapshot rows = %d, want 1", rows)
	}
}

func TestConcurrentCurrentWithoutReuseYieldsUniqueGenerations(t *testing.T) {
	s, db := openStore(t)
	useClock(t)
	mustPut(t, s, testRead("h1", true, 0))
	const n = 8
	var wg sync.WaitGroup
	gens := make([]int64, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snap, err := s.Current(context.Background(), []string{"h1"}, 0, 0)
			gens[i], errs[i] = snap.Generation, err
		}(i)
	}
	wg.Wait()
	seen := map[int64]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("Current %d: %v", i, errs[i])
		}
		if seen[gens[i]] {
			t.Fatalf("generation %d issued twice", gens[i])
		}
		seen[gens[i]] = true
	}
	if rows := rowCountTable(t, db, "vuln_inventory_snapshots"); rows != n {
		t.Fatalf("snapshot rows = %d, want %d", rows, n)
	}
}

// rowCountTable counts the rows of one table. The table names are constants
// chosen by the tests, never input.
func rowCountTable(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
