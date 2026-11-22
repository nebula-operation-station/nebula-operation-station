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

// fakeFloor records how Current calls it: on which transaction, how many times,
// and what the snapshot table held at that moment.
type fakeFloor struct {
	value    int64
	db       *sql.DB
	calls    int
	rowsSeen int
	txNil    bool
}

func (f *fakeFloor) Generation(_ context.Context, tx *sql.Tx) (int64, error) {
	f.calls++
	if tx == nil {
		f.txNil = true
		return 0, nil
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM vuln_inventory_snapshots`).Scan(&f.rowsSeen); err != nil {
		return 0, err
	}
	return f.value, nil
}

// TestCurrentReadsFloorInsideTransaction: Current asks the floor once, on its
// own transaction, before it writes the new snapshot. A floor that is read
// there bounds the generation of that same write.
func TestCurrentReadsFloorInsideTransaction(t *testing.T) {
	c := &clock{t: base}
	s, db := openStoreOnClock(t, c)
	mustPut(t, s, testRead("h1", true, 0))
	before := rowCountTable(t, db, "vuln_inventory_snapshots")
	f := &fakeFloor{value: 7, db: db}

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
	if f.rowsSeen != before {
		t.Fatalf("floor saw %d snapshot rows, want %d (read before the write)", f.rowsSeen, before)
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
// snapshots share a generation, and the generations rise with the floors.
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
	// The stored generations are exactly the ones handed out, and the highest
	// stored one is at least the highest floor plus one.
	var maxStored int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(generation), 0) FROM vuln_inventory_snapshots`).Scan(&maxStored); err != nil {
		t.Fatal(err)
	}
	if maxStored < int64((n-1)*10)+1 {
		t.Fatalf("highest stored generation = %d, want at least %d", maxStored, (n-1)*10+1)
	}
	for gen, id := range byGen {
		if want := fmt.Sprintf("nos-inv-%d", gen); id != want {
			t.Fatalf("snapshot %s has generation %d, want ID %s", id, gen, want)
		}
	}
}
