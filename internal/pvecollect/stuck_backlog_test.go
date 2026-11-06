// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"golang.org/x/sys/unix"
)

// readOnlyDir takes the write bit from dir, which refuses the unlink the way
// a directory outside ReadWritePaths does, and returns the undo.
func readOnlyDir(t *testing.T, dir string) func() {
	t.Helper()
	if err := os.Chmod(dir, 0o550); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)
	return restore
}

// refuseAsRoot simulates the refusal for root, which ignores file modes.
func refuseAsRoot(remove *func(context.Context, string) error) {
	if os.Geteuid() == 0 {
		*remove = failRemove
	}
}

// countRemovals wraps remove and counts its calls.
func countRemovals(n *int, remove func(context.Context, string) error) func(context.Context, string) error {
	return func(ctx context.Context, name string) error {
		*n++
		return remove(ctx, name)
	}
}

// The deployment bug of wf02: a server that can read but not unlink. Real
// directory modes, a read-side spool and restarts of the importer.
func TestImporterHandlesReadOnlyResultsDir(t *testing.T) {
	_, spool, store := newTestImporter(t)
	ctx := context.Background()
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	oneObservation(t, spool)
	oneObservation(t, spool)
	reader, err := OpenSpool(spool.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	start := func() *Importer {
		im, err := NewImporter(reader, store, log)
		if err != nil {
			t.Fatal(err)
		}
		refuseAsRoot(&im.remove)
		return im
	}
	restore := readOnlyDir(t, spool.ResultsDir())

	first := start()
	rep, err := first.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Imported != 2 {
		t.Fatalf("first pass = %+v, want 2 imported", rep)
	}
	names, err := reader.List(ctx)
	if err != nil || len(names) != 2 {
		t.Fatalf("spool = %v, %v, want both files kept", names, err)
	}
	if n := strings.Count(logs.String(), "remove spool file"); n != 1 || !strings.Contains(logs.String(), "files=2") {
		t.Fatalf("want one summary for 2 files, got %d:\n%s", n, logs.String())
	}

	// After a restart the older file is not read at all: garbage in it
	// would be rejected if it were. The newest is imported once more.
	if err := os.WriteFile(filepath.Join(spool.ResultsDir(), names[0]), []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	second := start()
	rep, err = second.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rejected != 0 || rep.Replayed != 1 || rep.Imported != 1 || len(rep.Errors) != 0 {
		t.Fatalf("restart pass = %+v, want the older file skipped undecoded", rep)
	}
	if rep, err = second.ImportOnce(ctx); err != nil || rep.Skipped != 2 {
		t.Fatalf("next pass = %+v, %v, want both skipped", rep, err)
	}
	if n := strings.Count(logs.String(), "remove spool file"); n != 2 {
		t.Fatalf("want one summary per start, got %d:\n%s", n, logs.String())
	}

	restore()
	second.remove = reader.Remove
	if rep, err = second.ImportOnce(ctx); err != nil || rep.Imported != 0 {
		t.Fatalf("drain pass = %+v, %v", rep, err)
	}
	if names, err := reader.List(ctx); err != nil || len(names) != 0 {
		t.Fatalf("spool = %v, %v, want drained", names, err)
	}
}

// A directory that refuses one unlink refuses them all, so a backlog costs
// one failing syscall per pass, and it drains in one pass once it works.
func TestImporterProbesBlockedDirectoryOncePerPass(t *testing.T) {
	for _, errno := range []unix.Errno{unix.EROFS, unix.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			im, spool, _ := newTestImporter(t)
			ctx := context.Background()
			for range 3 {
				oneObservation(t, spool)
			}
			calls := 0
			im.remove = countRemovals(&calls, func(context.Context, string) error { return errno })
			if _, err := im.ImportOnce(ctx); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || len(im.stuck) != 3 {
				t.Fatalf("importing pass: %d unlinks, stuck %v", calls, im.stuck)
			}
			calls = 0
			rep, err := im.ImportOnce(ctx)
			if err != nil || rep.Skipped != 3 || calls != 1 {
				t.Fatalf("skipping pass = %+v, %v, %d unlinks", rep, err, calls)
			}
			im.remove = spool.Remove
			if _, err := im.ImportOnce(ctx); err != nil {
				t.Fatal(err)
			}
			if names, _ := spool.List(ctx); len(names) != 0 || len(im.stuck) != 0 {
				t.Fatalf("spool = %v, stuck = %v, want drained", names, im.stuck)
			}
		})
	}
}

// Only a refusal of the whole directory ends a pass's unlinks: one bad file
// must not hold back the others.
func TestImporterRemovesOthersAroundFileFailure(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	oneObservation(t, spool)
	oneObservation(t, spool)
	bad := firstName(t, spool)
	im.remove = func(ctx context.Context, name string) error {
		if name == bad {
			return unix.EPERM
		}
		return spool.Remove(ctx, name)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	names, err := spool.List(ctx)
	if err != nil || len(names) != 1 || names[0] != bad {
		t.Fatalf("spool = %v, %v, want only %s", names, err, bad)
	}
}

// The summary comes once per episode: a new one after the spool drained.
func TestImporterWarnsAgainAfterDraining(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	for want := 1; want <= 2; want++ {
		im.remove = failRemove
		oneObservation(t, spool)
		for range 2 {
			if _, err := im.ImportOnce(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if n := strings.Count(logs.String(), "remove spool file"); n != want {
			t.Fatalf("logged %d times, want %d:\n%s", n, want, logs.String())
		}
		im.remove = spool.Remove
		if _, err := im.ImportOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// A healthy server drops a superseded file without decoding it and without
// a line per file; the pass counts it.
func TestImporterDropsSupersededFileUnread(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	oneObservation(t, spool)
	oneObservation(t, spool)
	older := firstName(t, spool)
	path := filepath.Join(spool.ResultsDir(), older)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 || rep.Replayed != 1 || rep.Rejected != 0 || len(rep.Errors) != 0 {
		t.Fatalf("pass = %+v, want the file dropped as replayed", rep)
	}
	if names, _ := spool.List(ctx); len(names) != 0 {
		t.Fatalf("spool = %v, want empty", names)
	}
	if strings.Contains(logs.String(), "dropped spool file") {
		t.Fatalf("superseded file logged:\n%s", logs.String())
	}
}

// Watermarks are per remote: a low generation of another remote is new.
func TestImporterComparesGenerationsPerRemote(t *testing.T) {
	im, spool, _ := newTestImporter(t)
	ctx := context.Background()
	oneObservation(t, spool)
	oneObservation(t, spool)
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-b")},
		readFn:  defaultReadFn,
	})
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Imported != 1 {
		t.Fatalf("pass = %+v, %v, want remote-b imported", rep, err)
	}
}

// Guest NIC records have no durable watermark and need none: the collector
// supersedes older pending records, so after a restart at most one record per
// remote is read again. The refusal itself behaves like results/.
func TestGuestNetImportHandlesReadOnlyDir(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	var logs bytes.Buffer
	im.log = slog.New(slog.NewTextHandler(&logs, nil))
	refuseAsRoot(&im.remove)
	other := validGuestNetRecord()
	other.Remote = "pve-other"
	for _, rec := range []GuestNetRecord{validGuestNetRecord(), other} {
		if _, err := w.WriteGuestNet(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	restore := readOnlyDir(t, filepath.Join(w.root, guestNetDirName))
	calls := 0
	im.remove = countRemovals(&calls, im.remove)

	if rep, err := im.ImportOnce(ctx); err != nil || rep != (GuestNetImportReport{Files: 2, Imported: 2}) {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}
	if calls != 1 {
		t.Fatalf("%d unlinks in the importing pass, want 1", calls)
	}
	calls = 0
	if rep, err := im.ImportOnce(ctx); err != nil || rep != (GuestNetImportReport{Files: 2, Skipped: 2}) {
		t.Fatalf("second pass = %+v, %v", rep, err)
	}
	if calls != 1 {
		t.Fatalf("%d unlinks in the skipping pass, want 1", calls)
	}
	if n := strings.Count(logs.String(), "remove guest nic record"); n != 1 || !strings.Contains(logs.String(), "files=2") {
		t.Fatalf("want one summary for 2 records, got %d:\n%s", n, logs.String())
	}
	if len(sink.got) != 2 {
		t.Fatalf("sink got %d records, want 2", len(sink.got))
	}

	restore()
	im.remove = im.spool.RemoveGuestNet
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if names, err := w.ListGuestNet(ctx); err != nil || len(names) != 0 {
		t.Fatalf("records = %v, %v, want drained", names, err)
	}
}
