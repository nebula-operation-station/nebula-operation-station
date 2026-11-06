// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"golang.org/x/sys/unix"
)

// failRemove stands in for the read-only mount of a server that may not
// unlink in the spool yet.
func failRemove(context.Context, string) error { return unix.EROFS }

func oneObservation(t *testing.T, spool *Spool) {
	t.Helper()
	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  defaultReadFn,
	})
}

// A file that cannot be removed is imported once, warned about once and
// then left alone, however many passes follow.
func TestImporterDoesNotReimportFileItCannotRemove(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	im.remove = failRemove
	oneObservation(t, spool)

	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 1 || rep.Skipped != 0 {
		t.Fatalf("first pass = %+v, want 1 imported", rep)
	}
	for range 3 {
		rep, err := im.ImportOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Files != 1 || rep.Imported != 0 || rep.Replayed != 0 || rep.Skipped != 1 {
			t.Fatalf("later pass = %+v, want the file skipped", rep)
		}
	}
	if n := strings.Count(logs.String(), "remove spool file"); n != 1 {
		t.Fatalf("removal failure logged %d times, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "remove_failed") {
		t.Fatalf("log misses the reason code:\n%s", logs.String())
	}
}

// Files rejected on read stay rejected once: no second decode, no second
// error line in the pass report.
func TestImporterSkipsRejectedFileItCannotRemove(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	im.remove = failRemove
	name := "remote-a.gen-00000000000000000001.json"
	if err := os.WriteFile(filepath.Join(spool.ResultsDir(), name), []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Rejected != 1 {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rejected != 0 || rep.Skipped != 1 || len(rep.Errors) != 0 {
		t.Fatalf("second pass = %+v, want the file skipped", rep)
	}
	if n := strings.Count(logs.String(), "remove spool file"); n != 1 {
		t.Fatalf("removal failure logged %d times, want once", n)
	}
}

// Once the server may unlink (wf02b) the backlog drains without a restart
// and without importing anything again.
func TestImporterDrainsBacklogOnceRemovalWorks(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	im.remove = failRemove
	oneObservation(t, spool)
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	im.remove = spool.Remove
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 0 || rep.Skipped != 1 {
		t.Fatalf("drain pass = %+v, want the file skipped", rep)
	}
	if names, err := spool.List(ctx); err != nil || len(names) != 0 {
		t.Fatalf("spool = %v, %v, want empty", names, err)
	}
	if len(im.stuck) != 0 {
		t.Fatalf("stuck = %v, want empty", im.stuck)
	}
}

// The memory of stuck files is bounded by what the directory still lists.
func TestImporterForgetsStuckFileOnceItIsGone(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	im.remove = failRemove
	oneObservation(t, spool)
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(im.stuck) != 1 {
		t.Fatalf("stuck = %v, want one file", im.stuck)
	}
	if err := spool.Remove(ctx, firstName(t, spool)); err != nil {
		t.Fatal(err)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(im.stuck) != 0 {
		t.Fatalf("stuck = %v, want empty", im.stuck)
	}
}

func firstName(t *testing.T, spool *Spool) string {
	t.Helper()
	names, err := spool.List(context.Background())
	if err != nil || len(names) == 0 {
		t.Fatalf("List = %v, %v", names, err)
	}
	return names[0]
}

// A file that vanished between processing and removal needs no attention.
func TestImporterIgnoresFileAlreadyGone(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	im.remove = func(context.Context, string) error { return unix.ENOENT }
	oneObservation(t, spool)
	if _, err := im.ImportOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(im.stuck) != 0 || strings.Contains(logs.String(), "remove_failed") {
		t.Fatalf("stuck = %v, logs:\n%s", im.stuck, logs.String())
	}
}

// Shutdown must not cost data: a cancelled pass leaves pending files alone.
func TestImporterKeepsFilesWhenCancelled(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	oneObservation(t, spool)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := im.ImportOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if names, _ := spool.List(context.Background()); len(names) != 1 {
		t.Fatalf("spool = %v, want the file kept", names)
	}
}

// Ingest fails on a cancelled context with dataset errors; that is the
// shutdown, not a partial observation, so the file stays.
func TestImporterKeepsFileWhenIngestIsInterrupted(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	oneObservation(t, spool)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, _ := im.importFile(ctx, firstName(t, spool)); got != fileInterrupted {
		t.Fatalf("outcome = %v, want fileInterrupted", got)
	}
	if names, _ := spool.List(context.Background()); len(names) != 1 {
		t.Fatalf("spool = %v, want the file kept", names)
	}
}

// A pass that only skips stuck files must not log: the loop runs for the
// server's whole life and the files stay until wf02b.
func TestImporterRunStaysQuietOnSkippedPasses(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	im.remove = failRemove
	oneObservation(t, spool)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := im.Run(ctx, 5*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), "import pass"); n != 1 {
		t.Fatalf("pass logged %d times, want once:\n%s", n, logs.String())
	}
}

func TestImporterRunIsSilentAboutShutdown(t *testing.T) {
	im, _, _ := newTestImporter(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := im.Run(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "import pass failed") {
		t.Fatalf("shutdown logged as a failure:\n%s", logs.String())
	}
}

func TestGuestNetImportDoesNotReimportRecordItCannotRemove(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	im.remove = failRemove
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	if rep, err := im.ImportOnce(ctx); err != nil || rep != (GuestNetImportReport{Files: 1, Imported: 1}) {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}
	// The importer keeps no watermark across restarts, so the guard must
	// hold without one too.
	clear(im.seen)
	for range 3 {
		rep, err := im.ImportOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if rep != (GuestNetImportReport{Files: 1, Skipped: 1}) {
			t.Fatalf("later pass = %+v, want the record skipped", rep)
		}
	}
	if len(sink.got) != 1 {
		t.Fatalf("sink got %d records, want 1", len(sink.got))
	}
	if n := strings.Count(logs.String(), "remove guest nic record"); n != 1 {
		t.Fatalf("removal failure logged %d times, want once:\n%s", n, logs.String())
	}
}

func TestGuestNetImportSkipsRejectedRecordItCannotRemove(t *testing.T) {
	ctx := context.Background()
	w, im, _ := newGuestNetImportFixture(t)
	im.remove = failRemove
	path := guestNetPath(w, "pve-y.obs-00000000001700000000.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\xff\xfe"), 0o640); err != nil {
		t.Fatal(err)
	}
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Rejected != 1 {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}
	if rep, err := im.ImportOnce(ctx); err != nil || rep != (GuestNetImportReport{Files: 1, Skipped: 1}) {
		t.Fatalf("second pass = %+v, %v", rep, err)
	}
}

// A sink failure is not a stuck file: the record was not imported and must
// be tried again even while removal is impossible.
func TestGuestNetImportRetriesSinkFailureWhileRemovalFails(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	im.remove = failRemove
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	sink.fail = errors.New("store busy")
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Failed != 1 {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}
	sink.fail = nil
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Imported != 1 {
		t.Fatalf("second pass = %+v, %v", rep, err)
	}
}

func TestGuestNetImportDrainsBacklogOnceRemovalWorks(t *testing.T) {
	ctx := context.Background()
	w, im, _ := newGuestNetImportFixture(t)
	im.remove = failRemove
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	im.remove = im.spool.RemoveGuestNet
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Skipped != 1 {
		t.Fatalf("drain pass = %+v, %v", rep, err)
	}
	if names, _ := w.ListGuestNet(ctx); len(names) != 0 {
		t.Fatalf("records = %v, want none", names)
	}
	if len(im.stuck) != 0 {
		t.Fatalf("stuck = %v, want empty", im.stuck)
	}
}

// The collector supersedes older pending records itself, so a record can
// disappear before the server removes it; that is not a failure.
func TestGuestNetImportIgnoresRecordAlreadyGone(t *testing.T) {
	ctx := context.Background()
	w, im, _ := newGuestNetImportFixture(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	im.remove = func(context.Context, string) error { return unix.ENOENT }
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(im.stuck) != 0 || strings.Contains(logs.String(), "remove_failed") {
		t.Fatalf("stuck = %v, logs:\n%s", im.stuck, logs.String())
	}
}

func TestGuestNetImporterRunImportsAndStops(t *testing.T) {
	w, im, sink := newGuestNetImportFixture(t)
	if _, err := w.WriteGuestNet(context.Background(), validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- im.Run(ctx, 5*time.Millisecond) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		names, err := w.ListGuestNet(context.Background())
		if err == nil && len(names) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Run did not import in time: %v, %v", names, err)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.got) != 1 {
		t.Fatalf("sink got %d records, want 1", len(sink.got))
	}
}

func TestGuestNetImporterRunLogsListFailure(t *testing.T) {
	w, im, _ := newGuestNetImportFixture(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	path := guestNetPath(w, "pve-q.obs-00000000001700000000.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := im.Run(ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "guest nic import pass failed") {
		t.Fatalf("list failure not logged:\n%s", logs.String())
	}
}
