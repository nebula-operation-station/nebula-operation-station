// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"sync"
	"testing"
	"time"
)

// holdWriteLock takes the database write lock on its own connection and
// returns the function that releases it. It writes no row, so only the lock
// itself can affect the ingest under test.
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

// Another writer on the server database must only delay an ingest. A
// transaction that reads first cannot wait for the lock: SQLite refuses its
// upgrade at once, so busy_timeout never applies and every dataset is lost.
func TestIngestWaitsForConcurrentWriter(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	release := holdWriteLock(t, s)

	done := make(chan error, 1)
	go func() {
		_, err := s.IngestObservation(ctx, newObsB().obs)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("ingest finished while the write lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()

	if err := <-done; err != nil {
		t.Fatalf("IngestObservation: %v", err)
	}
	if _, err := s.GetRemote(ctx, "remote-b"); err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
	statuses, err := s.ListDatasetStatus(ctx, "remote-b")
	if err != nil {
		t.Fatalf("ListDatasetStatus: %v", err)
	}
	if len(statuses) != 5 {
		t.Fatalf("dataset statuses = %+v, want all 5", statuses)
	}
}

// Taking the lock first must not change what a stale collection gets, and
// the rejected transaction must release the lock for the next writer.
func TestStaleIngestReleasesWriteLock(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	newer := newObsB().obs
	newer.CollectionGeneration = 2
	if _, err := s.IngestObservation(ctx, newer); err != nil {
		t.Fatalf("IngestObservation: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsB().obs); err == nil {
		t.Fatal("stale observation accepted")
	}
	release := holdWriteLock(t, s)
	release()
}
