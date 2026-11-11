// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Contention tests for withTx (like pveinventory/ingest_contention_test.go):
// another writer on the server database may only delay a store write. A
// transaction that reads first cannot wait for the lock: SQLite refuses
// its read-to-write upgrade at once, so busy_timeout never applies.

package netdevinventory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// holdWriteLock takes the database write lock on its own connection and
// returns the function that releases it. It writes no row.
func holdWriteLock(t *testing.T, s *Store) (release func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, lockWriteSQL); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			if err := tx.Commit(); err != nil {
				t.Errorf("release write lock: %v", err)
			}
		})
	}
	t.Cleanup(release)
	return release
}

func TestStoreWritesWaitForConcurrentWriter(t *testing.T) {
	writes := []struct {
		name string
		run  func(ctx context.Context, s *Store) error
	}{
		{"UpsertDevice", func(ctx context.Context, s *Store) error {
			d := cbsDevice()
			d.TrustGeneration = 3
			return s.UpsertDevice(ctx, d)
		}},
		{"ReplaceDataset", func(ctx context.Context, s *Store) error {
			_, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, 2, testBase.Add(-time.Minute), false, VLANRows{{ID: 1}})
			return err
		}},
		{"MarkStale", func(ctx context.Context, s *Store) error {
			_, err := s.MarkStale(ctx)
			return err
		}},
		{"Prune", func(ctx context.Context, s *Store) error {
			_, err := s.Prune(ctx)
			return err
		}},
	}
	for _, w := range writes {
		t.Run(w.name, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			ctx := context.Background()
			addDevice(t, s, cbsDevice())
			release := holdWriteLock(t, s)

			done := make(chan error, 1)
			go func() { done <- w.run(ctx, s) }()
			select {
			case err := <-done:
				t.Fatalf("write finished while the write lock was held: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			release()
			if err := <-done; err != nil {
				t.Fatalf("%s: %v", w.name, err)
			}
		})
	}
}

// Many writers at once (one per read and device, plus re-pins with the
// same generation) must all succeed: none may fail with a lock upgrade
// error.
func TestConcurrentStoreWritersAllSucceed(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	addDevice(t, s, cbsDevice())
	addDevice(t, s, panosDevice())

	type job struct {
		dev  netdevcontract.Device
		read Read
		rows func(i int) Rows
	}
	jobs := []job{
		{cbsDevice(), ReadVLANs, func(i int) Rows { return VLANRows{{ID: uint16(i + 1)}} }},
		{cbsDevice(), ReadMACTable, func(i int) Rows { return MACRows{mac(byte(i % 10))} }},
		{cbsDevice(), ReadLLDPNeighbors, func(i int) Rows {
			return LLDPRows{{LocalPort: "gi1/0/1", ChassisID: "c", PortID: string(rune('a' + i))}}
		}},
		{panosDevice(), ReadFirewallPolicy, func(i int) Rows { return policy(string(rune('a'+i)) + "-rule") }},
		{panosDevice(), ReadHitCounts, func(i int) Rows {
			return HitCountRows{{RuleName: "rule-a", Hits: uint64(i + 1)}}
		}},
	}
	const rounds = 8
	var wg sync.WaitGroup
	errs := make(chan error, len(jobs)*rounds+rounds)
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				// One poll interval apart: every write creates history.
				at := testBase.Add(-time.Duration(rounds-i) * PollInterval(j.read))
				if _, err := s.ReplaceDataset(ctx, j.dev.DeviceID, j.read, j.dev.TrustGeneration, at, false, j.rows(i)); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := s.UpsertDevice(ctx, cbsDevice()); err != nil {
				errs <- err
			}
			if _, err := s.MarkStale(ctx); err != nil {
				errs <- err
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets`); n != len(jobs)*rounds {
		t.Fatalf("datasets = %d, want %d", n, len(jobs)*rounds)
	}
}

// A refused write must release the lock for the next writer.
func TestRefusedWriteReleasesWriteLock(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	addDevice(t, s, cbsDevice())
	if _, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, 1, testBase, false, VLANRows{{ID: 1}}); !errors.Is(err, ErrTrustGenerationChanged) {
		t.Fatalf("err = %v, want ErrTrustGenerationChanged", err)
	}
	release := holdWriteLock(t, s)
	release()
}
