// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// newTestImporter builds an importer over a temp spool and a real
// pveinventory store in a temp database.
func newTestImporter(t *testing.T) (*Importer, *Spool, *pveinventory.Store) {
	t.Helper()
	spool, err := NewSpool(t.TempDir())
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("serverdb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := pveinventory.NewWithNow(db, func() time.Time {
		return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	})
	im, err := NewImporter(spool, store, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewImporter: %v", err)
	}
	return im, spool, store
}

// collectInto runs one collector pass over spool with the given fake
// reader, so the spool holds the collector's own valid observations.
func collectInto(t *testing.T, spool *Spool, fr *fakeReader) {
	t.Helper()
	c, err := New(fr, spool, Config{
		Now:                func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) },
		Jitter:             func() float64 { return 0 },
		MaxConcurrentReads: 2,
		ReadTimeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
}

// TestImporterImportsSpooledObservation is the happy path: the collector
// spools an observation, the importer revalidates it, feeds the store and
// removes the file.
func TestImporterImportsSpooledObservation(t *testing.T) {
	im, spool, store := newTestImporter(t)
	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  defaultReadFn,
	})

	rep, err := im.ImportOnce(context.Background())
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Files != 1 || rep.Imported != 1 || rep.Partial != 0 || rep.Replayed != 0 || rep.Rejected != 0 || len(rep.Errors) != 0 {
		t.Fatalf("report = %+v, want 1 file fully imported", rep)
	}

	// The file is consumed.
	names, err := spool.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("spool still has %v, want empty", names)
	}

	// The store holds the data.
	ctx := context.Background()
	node, err := store.GetNode(ctx, "remote-a", "p1")
	if err != nil {
		t.Fatalf("GetNode: %v", err)
	}
	if node.UptimeSeconds != 100 || node.CPUCount != 4 {
		t.Fatalf("node = %+v, want uptime 100 cpu 4", node)
	}
	guests, err := store.ListGuests(ctx, "remote-a", pveinventory.GuestFilter{}, 10)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(guests) != 1 || guests[0].VMID != 100 {
		t.Fatalf("guests = %+v, want one guest with vmid 100", guests)
	}
}

// TestImporterRejectsReplayViaWatermark re-imports an older observation for
// a remote that already has a newer watermark: the in-memory replay guard
// must drop it.
func TestImporterRejectsReplayViaWatermark(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()

	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  defaultReadFn,
	})
	// Keep a copy of the first observation before it is consumed.
	names, _ := spool.List(ctx)
	obs, err := spool.ReadFile(ctx, names[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}

	// Re-spool the same generation with an earlier observedAt: a replay.
	obs.ObservedAt = obs.ObservedAt.Add(-time.Minute)
	if _, err := spool.WriteFile(ctx, obs); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Files != 1 || rep.Replayed != 1 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want 1 replayed", rep)
	}
	names, _ = spool.List(ctx)
	if len(names) != 0 {
		t.Fatalf("spool still has %v, want empty", names)
	}
}

// TestImporterRejectsStaleObservationFromStore covers the durable check: a
// fresh importer (no in-memory watermark) must still reject an observation
// older than what the store already holds.
func TestImporterRejectsStaleObservationFromStore(t *testing.T) {
	_, spool, store := newTestImporter(t)
	ctx := context.Background()

	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  defaultReadFn,
	})
	names, _ := spool.List(ctx)
	obs, err := spool.ReadFile(ctx, names[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Advance the store directly to generation 2.
	obs.CollectionGeneration = 2
	if _, err := store.IngestObservation(ctx, obs); err != nil {
		t.Fatalf("IngestObservation: %v", err)
	}

	// A fresh importer sees the generation-1 file; the store must reject
	// it as stale.
	fresh, err := NewImporter(spool, store, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewImporter: %v", err)
	}
	if err := spool.Remove(ctx, names[0]); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	obs.CollectionGeneration = 1
	obs.ObservedAt = obs.ObservedAt.Add(-time.Minute)
	if _, err := spool.WriteFile(ctx, obs); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep, err := fresh.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Files != 1 || rep.Replayed != 1 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want 1 replayed (stale in store)", rep)
	}
}

// TestImporterRejectsCorruptFile drops a file whose content does not decode
// and leaves the store untouched.
func TestImporterRejectsCorruptFile(t *testing.T) {
	im, spool, store := newTestImporter(t)
	ctx := context.Background()

	name := "remote-a.gen-" + "00000000000000000001" + ".json"
	if err := os.WriteFile(filepath.Join(spool.ResultsDir(), name), []byte("{not json"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Files != 1 || rep.Rejected != 1 || len(rep.Errors) != 1 {
		t.Fatalf("report = %+v, want 1 rejected with one error line", rep)
	}
	names, _ := spool.List(ctx)
	if len(names) != 0 {
		t.Fatalf("spool still has %v, want empty", names)
	}
	if _, err := store.GetNode(ctx, "remote-a", "p1"); !errors.Is(err, pveinventory.ErrNodeNotFound) {
		t.Fatalf("GetNode err = %v, want ErrNodeNotFound (store must stay empty)", err)
	}
}

// TestImporterRejectsOversizeFile drops a file above the size limit.
func TestImporterRejectsOversizeFile(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()

	name := "remote-a.gen-" + "00000000000000000001" + ".json"
	big := make([]byte, maxSpoolFileBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(spool.ResultsDir(), name), big, 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Files != 1 || rep.Rejected != 1 {
		t.Fatalf("report = %+v, want 1 rejected (oversize)", rep)
	}
	if _, err := spool.ReadFile(ctx, name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize file was not removed (ReadFile err = %v)", err)
	}
}

// TestImporterRefusesSymlinkedSpool: a symlink planted in the results
// directory aborts the whole pass; nothing is ingested or removed.
func TestImporterRefusesSymlinkedSpool(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()

	target := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(target, []byte("{}"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(spool.ResultsDir(), "remote-a.gen-00000000000000000001.json")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := im.ImportOnce(ctx); err == nil {
		t.Fatal("ImportOnce returned nil error, want symlink refusal")
	} else if !errors.Is(err, ErrSymlink) {
		t.Fatalf("ImportOnce err = %v, want ErrSymlink", err)
	}
}

// TestImporterRunImportsAndStops verifies the Run loop imports pending
// files and exits on context cancellation.
func TestImporterRunImportsAndStops(t *testing.T) {
	im, spool, store := newTestImporter(t)
	ctx, cancel := context.WithCancel(context.Background())

	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  defaultReadFn,
	})
	done := make(chan error, 1)
	go func() { done <- im.Run(ctx, 10*time.Millisecond) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := store.GetNode(context.Background(), "remote-a", "p1")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Run did not import in time: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestNewImporterRejectsNilArgs guards the constructor.
func TestNewImporterRejectsNilArgs(t *testing.T) {
	spool, err := NewSpool(t.TempDir())
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	if _, err := NewImporter(nil, nil, nil); err == nil {
		t.Fatal("NewImporter(nil, nil) = nil error, want error")
	}
	if _, err := NewImporter(spool, nil, nil); err == nil {
		t.Fatal("NewImporter(spool, nil) = nil error, want error")
	}
}

// TestImporterIgnoresForeignFiles ensures non-spool names in the results
// directory are skipped, not rejected and not removed.
func TestImporterIgnoresForeignFiles(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()

	if err := os.WriteFile(filepath.Join(spool.ResultsDir(), "notes.txt"), []byte("hello"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Files != 0 || len(rep.Errors) != 0 {
		t.Fatalf("report = %+v, want 0 files (foreign name ignored)", rep)
	}
	if _, err := os.Stat(filepath.Join(spool.ResultsDir(), "notes.txt")); err != nil {
		t.Fatalf("foreign file was removed: %v", err)
	}
}
