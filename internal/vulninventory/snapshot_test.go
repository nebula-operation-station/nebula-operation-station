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

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// clock is a settable time source for a store under test.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// useClock gives s a settable clock starting at base. Current, Put and
// PruneSnapshots of s read the time from it.
func useClock(t *testing.T, s *Store) *clock {
	t.Helper()
	c := &clock{t: base}
	s.now = c.now
	return c
}

func mustCurrent(t *testing.T, s *Store, hosts []string, maxReuse time.Duration, floor int64) Snapshot {
	t.Helper()
	snap, err := s.Current(context.Background(), hosts, maxReuse, FixedFloor(floor))
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
	c := useClock(t, s)
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
	useClock(t, s)
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
	c := useClock(t, s)
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
	useClock(t, s)
	mustPut(t, s, testRead("h1", true, 0))
	first := mustCurrent(t, s, []string{"h1"}, 0, 0)
	second := mustCurrent(t, s, []string{"h1"}, 0, 0)
	if second.ID == first.ID {
		t.Fatalf("maxReuse 0 reused %s", first.ID)
	}
}

func TestCurrentCreatesNewSnapshotWhenHostRemoved(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
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
	useClock(t, s)
	mustPut(t, s, testRead("h1", false, 0))
	snap := mustCurrent(t, s, []string{"h0", "h1", "h9"}, time.Hour, 0)
	if len(snap.Reads) != 1 || snap.Reads[0].HostID != "h1" {
		t.Fatalf("reads = %+v, want only h1", snap.Reads)
	}
}

func TestCurrentUsesNewestReadPerHostInHostOrder(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
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
	useClock(t, s)
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
	useClock(t, s)
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
	useClock(t, s)
	snap := mustCurrent(t, s, nil, time.Hour, 0)
	if snap.Generation != 1 || len(snap.Reads) != 0 {
		t.Fatalf("snapshot = gen %d with %d reads, want gen 1 and none", snap.Generation, len(snap.Reads))
	}
}

func TestOldSnapshotKeepsItsReadsForever(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
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
	useClock(t, s)
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
	useClock(t, s)
	if _, err := s.Snapshot(context.Background(), "nos-inv-99"); !errors.Is(err, ErrSnapshotGone) {
		t.Fatalf("err = %v, want ErrSnapshotGone", err)
	}
}

func TestPruneSnapshotsRemovesOldAndKeepsNewest(t *testing.T) {
	s, db := openStore(t)
	c := useClock(t, s)
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
	c := useClock(t, s)
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
	useClock(t, s)
	for _, age := range []time.Duration{0, -time.Second} {
		if err := s.PruneSnapshots(context.Background(), age); err == nil {
			t.Fatalf("PruneSnapshots(%v) accepted", age)
		}
	}
}

func TestCurrentRejectsInvalidInput(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
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
			if _, err := s.Current(ctx, c.hosts, c.maxReuse, FixedFloor(c.floor)); !errors.Is(err, ErrInvalidRead) {
				t.Fatalf("err = %v, want ErrInvalidRead", err)
			}
		})
	}
}

func TestCurrentHostCapCountsOnlyHostsWithReads(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
	// Hosts h00000..h09999 have no read. They must not take the host slots of
	// the three hosts that do have reads.
	hosts := make([]string, 0, MaxSnapshotHosts+5)
	for i := 0; i < MaxSnapshotHosts+5; i++ {
		hosts = append(hosts, fmt.Sprintf("h%05d", i))
	}
	last := []string{"h10002", "h10003", "h10004"}
	for _, h := range last {
		mustPut(t, s, testRead(h, true, 0))
	}
	snap := mustCurrent(t, s, hosts, time.Hour, 0)
	if snap.Omitted != 0 {
		t.Fatalf("omitted = %d, want 0 (only three hosts have reads)", snap.Omitted)
	}
	if len(snap.Reads) != len(last) {
		t.Fatalf("reads = %d, want %d", len(snap.Reads), len(last))
	}
	for i, h := range last {
		if snap.Reads[i].HostID != h {
			t.Fatalf("reads[%d] = %s, want %s", i, snap.Reads[i].HostID, h)
		}
	}
}

// sized returns a latest read of host id with a stored body of n bytes.
func sized(id int64, host string, n int64) sizedRead {
	return sizedRead{Read: Read{ID: id, HostID: host}, bytes: n}
}

func TestSelectSnapshotReads(t *testing.T) {
	big := make([]sizedRead, 0, 17)
	for i := 0; i < 17; i++ {
		big = append(big, sized(int64(i+1), fmt.Sprintf("h%02d", i), MaxBodyBytes))
	}
	many := make([]sizedRead, 0, MaxSnapshotHosts+1)
	for i := 0; i < MaxSnapshotHosts+1; i++ {
		many = append(many, sized(int64(i+1), fmt.Sprintf("h%05d", i), 1))
	}
	cases := []struct {
		name     string
		latest   []sizedRead
		maxHosts int
		maxBytes int64
		wantIDs  []int64
		wantLeft int
	}{
		{"all kept within limits", []sizedRead{sized(1, "a", 3), sized(2, "b", 4)}, 10, 10, []int64{1, 2}, 0},
		{"host cap keeps the first hosts in host order", []sizedRead{sized(1, "a", 1), sized(2, "b", 1), sized(3, "c", 1), sized(4, "d", 1)}, 2, 100, []int64{1, 2}, 2},
		{"byte budget skips a read that does not fit and keeps later ones", []sizedRead{sized(1, "a", 6), sized(2, "b", 5), sized(3, "c", 4)}, 10, 10, []int64{1, 3}, 1},
		{"a read larger than the budget is omitted", []sizedRead{sized(1, "a", 11)}, 10, 10, nil, 1},
		{"seventeen maximum bodies keep sixteen and omit one", big, MaxSnapshotHosts, MaxSnapshotBodyBytes, nil, 1},
		{"host cap at MaxSnapshotHosts omits the host past it", many, MaxSnapshotHosts, MaxSnapshotBodyBytes, nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, left := selectSnapshotReads(tc.latest, tc.maxHosts, tc.maxBytes)
			if left != tc.wantLeft {
				t.Fatalf("omitted = %d, want %d", left, tc.wantLeft)
			}
			var sum int64
			for _, r := range got {
				sum += sizeOf(tc.latest, r.ID)
			}
			if sum > tc.maxBytes {
				t.Fatalf("kept bodies %d bytes, budget %d: a snapshot would be refused by Snapshot", sum, tc.maxBytes)
			}
			if len(got) > tc.maxHosts {
				t.Fatalf("kept %d hosts, cap %d", len(got), tc.maxHosts)
			}
			if tc.wantIDs != nil {
				if ids := readIDs(Snapshot{Reads: got}); !reflect.DeepEqual(ids, tc.wantIDs) {
					t.Fatalf("kept IDs = %v, want %v", ids, tc.wantIDs)
				}
			}
		})
	}
}

// sizeOf returns the body size of read id in latest.
func sizeOf(latest []sizedRead, id int64) int64 {
	for _, s := range latest {
		if s.ID == id {
			return s.bytes
		}
	}
	return -1
}

func TestCurrentClockBackwardsDoesNotExtendReuse(t *testing.T) {
	s, _ := openStore(t)
	c := useClock(t, s)
	mustPut(t, s, testRead("h1", true, 0))
	first := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	// The wall clock jumps back two hours. The snapshot's age is negative: it
	// must not count as younger than maxReuse.
	c.t = base.Add(-2 * time.Hour)
	second := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)
	if second.ID == first.ID || second.Generation != first.Generation+1 {
		t.Fatalf("second = %s gen %d after clock went back: want a new snapshot after %s", second.ID, second.Generation, first.ID)
	}
}

func TestMaxSnapshotHostsIsTheExportLimit(t *testing.T) {
	if MaxSnapshotHosts != api.MaxExportSubjects {
		t.Fatalf("MaxSnapshotHosts = %d, api.MaxExportSubjects = %d: want equal", MaxSnapshotHosts, api.MaxExportSubjects)
	}
	if MaxSnapshotHosts != vulnstore.MaxCoveredPerRun {
		t.Fatalf("MaxSnapshotHosts = %d, vulnstore.MaxCoveredPerRun = %d: want equal", MaxSnapshotHosts, vulnstore.MaxCoveredPerRun)
	}
}

func TestCurrentFloorAgainstReusableSnapshot(t *testing.T) {
	// The newest snapshot pins the same reads and is younger than maxReuse, so
	// only the floor decides whether it may be returned.
	cases := []struct {
		name      string
		floor     int64
		wantGen   int64
		wantReuse bool
	}{
		{"floor below generation reuses", 0, 1, true},
		{"floor equal to generation is not reused", 1, 2, false},
		{"floor above generation is not reused", 495000, 495001, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := openStore(t)
			c := useClock(t, s)
			mustPut(t, s, testRead("h1", true, 0))
			first := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)
			if first.Generation != 1 {
				t.Fatalf("first generation = %d, want 1", first.Generation)
			}

			c.t = base.Add(time.Minute)
			got := mustCurrent(t, s, []string{"h1"}, time.Hour, tc.floor)
			if got.Generation != tc.wantGen {
				t.Fatalf("generation = %d, want %d", got.Generation, tc.wantGen)
			}
			if reused := got.ID == first.ID; reused != tc.wantReuse {
				t.Fatalf("reused = %v (snapshot %s), want %v", reused, got.ID, tc.wantReuse)
			}
			if !reflect.DeepEqual(readIDs(got), readIDs(first)) {
				t.Fatalf("reads = %v, want the same reads %v", readIDs(got), readIDs(first))
			}
			wantRows := 1
			if !tc.wantReuse {
				wantRows = 2
			}
			if n := rowCountTable(t, db, "vuln_inventory_snapshots"); n != wantRows {
				t.Fatalf("snapshot rows = %d, want %d", n, wantRows)
			}
		})
	}
}

func TestCurrentNeverReturnsGenerationAtOrBelowFloor(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
	mustPut(t, s, testRead("h1", true, 0))
	mustCurrent(t, s, []string{"h1"}, time.Hour, 0)
	// nos-inv-1 is stored and young; a vulnstore run has seen generation 495000.
	snap := mustCurrent(t, s, []string{"h1"}, time.Hour, 495000)
	if snap.Generation <= 495000 {
		t.Fatalf("generation = %d (%s), want above floor 495000", snap.Generation, snap.ID)
	}
}

func TestSnapshotPagesReadsInHostOrder(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	hosts := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7"}
	ids := make(map[string]int64, len(hosts))
	for _, h := range hosts {
		ids[h] = mustPut(t, s, testRead(h, true, 0))
	}
	snap := mustCurrent(t, s, hosts, time.Hour, 0)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	// Pages of 3 reads: 7 reads take three queries.
	got, err := loadSnapshotReads(context.Background(), tx, snap.ID, 3, MaxSnapshotBodyBytes)
	if err != nil {
		t.Fatalf("loadSnapshotReads: %v", err)
	}
	if len(got) != len(hosts) {
		t.Fatalf("reads = %d, want %d", len(got), len(hosts))
	}
	for i, r := range got {
		if r.HostID != hosts[i] || r.ID != ids[hosts[i]] {
			t.Fatalf("reads[%d] = %s/%d, want %s/%d", i, r.HostID, r.ID, hosts[i], ids[hosts[i]])
		}
		if len(r.Components) != 1 {
			t.Fatalf("reads[%d] has %d components, want the stored body", i, len(r.Components))
		}
	}
}

func TestSnapshotByteLimitCountsBodiesAcrossPages(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	// Ten reads of one component each: many large-enough bodies to span pages.
	var hosts []string
	for i := 0; i < 10; i++ {
		h := fmt.Sprintf("h%02d", i)
		hosts = append(hosts, h)
		mustPut(t, s, testRead(h, true, 0))
	}
	snap := mustCurrent(t, s, hosts, time.Hour, 0)
	ctx := context.Background()

	var total int64
	if err := db.QueryRow(`SELECT SUM(LENGTH(body)) FROM vuln_inventory_reads`).Scan(&total); err != nil {
		t.Fatalf("sum body bytes: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()

	// Exactly the total fits; one byte less is refused before any body is decoded.
	if got, err := loadSnapshotReads(ctx, tx, snap.ID, 4, total); err != nil || len(got) != 10 {
		t.Fatalf("limit = total %d: reads %d, err %v; want 10 reads", total, len(got), err)
	}
	if _, err := loadSnapshotReads(ctx, tx, snap.ID, 4, total-1); !errors.Is(err, ErrLimit) {
		t.Fatalf("limit = total-1: err = %v, want ErrLimit", err)
	}
}

func TestMaxSnapshotBodyBytesFitsWorstCaseBodies(t *testing.T) {
	// The cap must admit at least one worst-case read, or a single legal read
	// could never be snapshotted.
	if MaxSnapshotBodyBytes < MaxBodyBytes {
		t.Fatalf("MaxSnapshotBodyBytes = %d, want at least MaxBodyBytes %d", MaxSnapshotBodyBytes, MaxBodyBytes)
	}
}

func TestConcurrentCurrentWithReuseYieldsOneSnapshot(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	mustPut(t, s, testRead("h1", true, 0))
	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snap, err := s.Current(context.Background(), []string{"h1"}, time.Hour, FixedFloor(0))
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
	useClock(t, s)
	mustPut(t, s, testRead("h1", true, 0))
	const n = 8
	var wg sync.WaitGroup
	gens := make([]int64, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snap, err := s.Current(context.Background(), []string{"h1"}, 0, FixedFloor(0))
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

func TestLatestSizesQuerySelectsTheSameReadsAsLatestAll(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	mustPut(t, s, testRead("h1", true, 0))
	mustPut(t, s, testRead("h1", true, 5))
	mustPut(t, s, testRead("h2", true, 0))
	mustPut(t, s, testRead("h3", false, 1))

	all, _, err := s.LatestAll(context.Background())
	if err != nil {
		t.Fatalf("LatestAll: %v", err)
	}
	rows, err := db.Query(latestSizesQuery)
	if err != nil {
		t.Fatalf("latestSizesQuery: %v", err)
	}
	defer rows.Close()
	got := map[int64]bool{}
	for rows.Next() {
		var id, n int64
		if err := rows.Scan(&id, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = true
	}
	if len(got) != len(all) {
		t.Fatalf("latestSizesQuery returned %d reads, LatestAll %d", len(got), len(all))
	}
	for _, r := range all {
		if !got[r.ID] {
			t.Fatalf("latestSizesQuery misses read %d of host %s", r.ID, r.HostID)
		}
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
