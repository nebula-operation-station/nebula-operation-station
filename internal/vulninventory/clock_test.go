// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// openStoreOnClock opens a migrated server database and a Store on it whose
// clock is c. It is the store the export builds: one clock for TakenAt, the
// reuse window and the read-time bound.
func openStoreOnClock(t *testing.T, c *clock) (*Store, *sql.DB) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewWithNow(db, c.now)
	if err != nil {
		t.Fatalf("NewWithNow: %v", err)
	}
	return s, db
}

// TestNewWithNowRejectsNilClock: a store without a clock cannot stamp TakenAt
// or judge a reuse window, so the constructor refuses it.
func TestNewWithNowRejectsNilClock(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	defer db.Close()
	if _, err := NewWithNow(db, nil); err == nil {
		t.Fatal("NewWithNow(db, nil) succeeded, want an error")
	}
}

// TestCurrentStampsTakenAtWithStoreClock: TakenAt is the store's clock, not the
// wall clock. The clock is set far from now, so a wall-clock stamp would fail.
func TestCurrentStampsTakenAtWithStoreClock(t *testing.T) {
	c := &clock{t: base}
	s, _ := openStoreOnClock(t, c)
	mustPut(t, s, testRead("h1", true, 0))
	snap := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)
	if !snap.TakenAt.Equal(base) {
		t.Fatalf("TakenAt = %s, want the store clock %s", snap.TakenAt, base)
	}
}

// TestCurrentReuseWindowUsesStoreClock: the reuse window and TakenAt are read
// from the same clock. Moving it past maxReuse expires the snapshot, and the
// stored TakenAt is the moment the clock said.
func TestCurrentReuseWindowUsesStoreClock(t *testing.T) {
	c := &clock{t: base}
	s, _ := openStoreOnClock(t, c)
	mustPut(t, s, testRead("h1", true, 0))
	first := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)

	c.t = base.Add(time.Hour - time.Second)
	if again := mustCurrent(t, s, []string{"h1"}, time.Hour, 0); again.ID != first.ID {
		t.Fatalf("inside the window: %s, want reuse of %s", again.ID, first.ID)
	}

	c.t = base.Add(time.Hour)
	later := mustCurrent(t, s, []string{"h1"}, time.Hour, 0)
	if later.ID == first.ID {
		t.Fatalf("at the window edge: reused %s, want a new snapshot", first.ID)
	}
	if !later.TakenAt.Equal(base.Add(time.Hour)) {
		t.Fatalf("new TakenAt = %s, want %s", later.TakenAt, base.Add(time.Hour))
	}
}

// lockProbe is a GenerationFloor that checks from inside Generation whether
// Current already holds the database write lock. It attempts a write on a
// second connection to the same file, with a short busy timeout. While the
// write lock is held that write is refused; before the lock it would succeed.
type lockProbe struct {
	value int64
	other *sql.DB
	calls int
	txNil bool
	// refused is true when the second connection's write was refused.
	refused bool
}

func (f *lockProbe) Generation(ctx context.Context, tx *sql.Tx) (int64, error) {
	f.calls++
	if tx == nil {
		f.txNil = true
		return 0, nil
	}
	_, err := f.other.ExecContext(ctx, `UPDATE vuln_inventory_snapshots SET taken_at = taken_at WHERE 0`)
	f.refused = err != nil
	return f.value, nil
}

// TestCurrentReadsFloorInsideTransaction: Current asks the floor once, on its
// own transaction, after it has taken the write lock. A floor read before the
// lock could be stale by the time the snapshot is written; the probe sees the
// lock held when Generation runs.
func TestCurrentReadsFloorInsideTransaction(t *testing.T) {
	c := &clock{t: base}
	path := filepath.Join(t.TempDir(), "server.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	other, err := serverdb.OpenWithOptions(path, serverdb.Options{BusyTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	t.Cleanup(func() { other.Close() })
	s, err := NewWithNow(db, c.now)
	if err != nil {
		t.Fatalf("NewWithNow: %v", err)
	}
	mustPut(t, s, testRead("h1", true, 0))
	f := &lockProbe{value: 7, other: other}

	snap, err := s.Current(context.Background(), []string{"h1"}, 0, f)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if f.calls != 1 {
		t.Fatalf("floor read %d times, want once per Current", f.calls)
	}
	if f.txNil {
		t.Fatal("floor was given no transaction")
	}
	if !f.refused {
		t.Fatal("a second connection could write while Current read the floor: the floor was read before the write lock")
	}
	if snap.Generation != 8 {
		t.Fatalf("generation = %d, want 8 (floor 7 plus one)", snap.Generation)
	}
}

// TestCurrentRefusesNilFloor: a Current without a floor is an invalid read, not
// a generation of zero.
func TestCurrentRefusesNilFloor(t *testing.T) {
	c := &clock{t: base}
	s, _ := openStoreOnClock(t, c)
	if _, err := s.Current(context.Background(), nil, time.Hour, nil); !errors.Is(err, ErrInvalidRead) {
		t.Fatalf("err = %v, want ErrInvalidRead", err)
	}
}

// TestConcurrentCurrentNeverLowersGeneration: callers with different floors run
// at the same time. Each snapshot is above its own floor, no two different
// snapshots share a generation, and every snapshot that was handed out is
// stored under its generation, with nothing else stored.
func TestConcurrentCurrentNeverLowersGeneration(t *testing.T) {
	c := &clock{t: base}
	s, db := openStoreOnClock(t, c)
	mustPut(t, s, testRead("h1", true, 0))
	const n = 8
	type result struct {
		floor int64
		snap  Snapshot
		err   error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			floor := int64(i * 10)
			snap, err := s.Current(context.Background(), []string{"h1"}, 0, FixedFloor(floor))
			results[i] = result{floor: floor, snap: snap, err: err}
		}(i)
	}
	wg.Wait()

	byGen := map[int64]string{}
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("Current %d: %v", i, r.err)
		}
		if r.snap.Generation <= r.floor {
			t.Fatalf("Current %d: generation %d not above its floor %d", i, r.snap.Generation, r.floor)
		}
		if prev, ok := byGen[r.snap.Generation]; ok && prev != r.snap.ID {
			t.Fatalf("generation %d given to two snapshots: %s and %s", r.snap.Generation, prev, r.snap.ID)
		}
		byGen[r.snap.Generation] = r.snap.ID
	}
	// The stored snapshots are exactly the ones handed out: one row per call,
	// each under the generation it was given. The highest stored generation is
	// the highest handed out, and it is at least the highest floor plus one.
	if rows := rowCountTable(t, db, "vuln_inventory_snapshots"); rows != n {
		t.Fatalf("stored snapshots = %d, want %d (one per call)", rows, n)
	}
	var maxStored int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(generation), 0) FROM vuln_inventory_snapshots`).Scan(&maxStored); err != nil {
		t.Fatal(err)
	}
	var maxHanded int64
	for gen, id := range byGen {
		maxHanded = max(maxHanded, gen)
		if want := fmt.Sprintf("nos-inv-%d", gen); id != want {
			t.Fatalf("snapshot %s has generation %d, want ID %s", id, gen, want)
		}
	}
	if maxStored != maxHanded {
		t.Fatalf("highest stored generation = %d, highest handed out = %d", maxStored, maxHanded)
	}
	if maxStored < int64((n-1)*10)+1 {
		t.Fatalf("highest stored generation = %d, want at least %d", maxStored, (n-1)*10+1)
	}
}
