// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Trust generation tests (ND-16, ADR 0010: a re-pin bumps the generation):
// a dataset observed under another generation than the device's current
// one is refused inside the write transaction, with nothing written.

package netdevinventory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// storeSnapshot is everything a refused write must leave unchanged.
type storeSnapshot struct {
	dataset  Dataset
	device   Device
	datasets int
	vlans    int
}

func snapshot(t *testing.T, s *Store, dev string, read Read) storeSnapshot {
	t.Helper()
	ctx := context.Background()
	ds, err := s.GetDataset(ctx, dev, read)
	if err != nil {
		t.Fatalf("GetDataset: %v", err)
	}
	d, err := s.GetDevice(ctx, dev)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	return storeSnapshot{
		dataset:  ds,
		device:   d,
		datasets: countRows(t, s.db, `SELECT count(*) FROM netdev_datasets`),
		vlans:    countRows(t, s.db, `SELECT count(*) FROM netdev_vlans`),
	}
}

func TestRePinBetweenObservationAndWriteRefusesDataset(t *testing.T) {
	cases := []struct {
		name string
		gen  uint64
		at   time.Time
		rows VLANRows
	}{
		// Observed under the old pin, new content.
		{"old generation", 2, testBase.Add(-time.Hour), VLANRows{{ID: 1}, {ID: 30}}},
		// Observed under the old pin, same content: must not even advance
		// observed_at.
		{"old generation same payload", 2, testBase.Add(-time.Hour), VLANRows{{ID: 1}}},
		// The same dataset delivered again is no longer a no-op success.
		{"old generation replay", 2, testBase.Add(-2 * time.Hour), VLANRows{{ID: 1}}},
		// A generation the server has not recorded yet is refused as well.
		{"newer generation", 4, testBase.Add(-time.Hour), VLANRows{{ID: 1}, {ID: 30}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			ctx := context.Background()
			addDevice(t, s, cbsDevice())
			mustReplace(t, s, "sw-core", ReadVLANs, testBase.Add(-2*time.Hour), false, VLANRows{{ID: 1}})
			repinned := cbsDevice()
			repinned.TrustGeneration = 3
			addDevice(t, s, repinned)
			before := snapshot(t, s, "sw-core", ReadVLANs)

			_, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, c.gen, c.at, false, c.rows)
			if !errors.Is(err, ErrTrustGenerationChanged) {
				t.Fatalf("err = %v, want ErrTrustGenerationChanged", err)
			}
			if after := snapshot(t, s, "sw-core", ReadVLANs); after != before {
				t.Fatalf("store changed:\nbefore %+v\nafter  %+v", before, after)
			}
		})
	}
}

func TestSameTrustGenerationStoresDataset(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	addDevice(t, s, cbsDevice())
	repinned := cbsDevice()
	repinned.TrustGeneration = 3
	addDevice(t, s, repinned)
	res, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, 3, testBase.Add(-time.Minute), false, VLANRows{{ID: 1}})
	if err != nil {
		t.Fatalf("ReplaceDataset: %v", err)
	}
	d, err := s.GetDataset(ctx, "sw-core", ReadVLANs)
	if err != nil || d.ID != res.DatasetID {
		t.Fatalf("dataset = %+v, %v", d, err)
	}
}

// A re-pin that is requested while a write is inside its transaction
// waits for it: the write was checked against the generation that was
// current while it held the lock. Once the re-pin has committed, the old
// generation is refused.
func TestRePinWaitsForRunningWriteThenRefusesOldGeneration(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	addDevice(t, s, cbsDevice())
	repinned := cbsDevice()
	repinned.TrustGeneration = 3

	upsertDone := make(chan error, 1)
	var started sync.Once
	s.hook = func(stage string) error {
		if stage != "dataset" {
			return nil
		}
		started.Do(func() {
			go func() { upsertDone <- s.UpsertDevice(ctx, repinned) }()
		})
		select {
		case err := <-upsertDone:
			t.Errorf("re-pin committed inside the dataset write: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		return nil
	}
	if _, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, 2, testBase.Add(-time.Hour), false, VLANRows{{ID: 1}}); err != nil {
		t.Fatalf("ReplaceDataset: %v", err)
	}
	s.hook = nil
	if err := <-upsertDone; err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	before := snapshot(t, s, "sw-core", ReadVLANs)
	if _, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, 2, testBase.Add(-time.Minute), false, VLANRows{{ID: 9}}); !errors.Is(err, ErrTrustGenerationChanged) {
		t.Fatalf("err = %v, want ErrTrustGenerationChanged", err)
	}
	if after := snapshot(t, s, "sw-core", ReadVLANs); after != before {
		t.Fatalf("store changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

// Writers that keep using the old generation race a re-pin. Every write
// that starts after the re-pin returned must be refused, and no write may
// fail for any other reason than ordering.
func TestConcurrentRePinNeverLetsOldDatasetThrough(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	addDevice(t, s, cbsDevice())
	repinned := cbsDevice()
	repinned.TrustGeneration = 3

	const writers, perWriter = 4, 15
	var seq atomic.Int64
	var bumped atomic.Bool
	var accepted atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter+1)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				n := seq.Add(1)
				at := testBase.Add(-24*time.Hour + time.Duration(n)*time.Minute)
				afterBump := bumped.Load()
				_, err := s.ReplaceDataset(ctx, "sw-core", ReadVLANs, 2, at, false, VLANRows{{ID: uint16(n)}})
				switch {
				case afterBump && !errors.Is(err, ErrTrustGenerationChanged):
					errs <- errors.New("write started after the re-pin was not refused: " + errString(err))
				case err == nil:
					accepted.Add(1)
				case errors.Is(err, ErrOutOfOrder), errors.Is(err, ErrTrustGenerationChanged):
				default:
					errs <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		if err := s.UpsertDevice(ctx, repinned); err != nil {
			errs <- err
			return
		}
		bumped.Store(true)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if !bumped.Load() {
		t.Fatal("re-pin did not happen")
	}
	// Every stored dataset is one of the accepted writes; no refused write
	// left a row behind.
	if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets`); int64(n) > accepted.Load() {
		t.Fatalf("datasets = %d, accepted writes = %d", n, accepted.Load())
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_vlans v
		WHERE NOT EXISTS (SELECT 1 FROM netdev_datasets d WHERE d.id = v.dataset_id)`); n != 0 {
		t.Fatalf("%d orphaned rows", n)
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
