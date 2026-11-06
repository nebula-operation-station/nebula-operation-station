// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// readFailures are errors of the open and read steps on a file that is fine.
var readFailures = []struct {
	name string
	err  error
}{
	{"open EMFILE", unix.EMFILE},
	{"open ENFILE", unix.ENFILE},
	{"open EACCES", unix.EACCES},
	{"read EIO", &os.PathError{Op: "read", Path: "spool-file", Err: unix.EIO}},
	{"unknown error", errors.New("injected-read-failure")},
}

// failReads makes every read of a pending file fail with err until the
// returned function restores it.
func failReads(s *Spool, err error) (restore func()) {
	read := s.read
	s.read = func(*os.File, string, int64) ([]byte, error) { return nil, err }
	return func() { s.read = read }
}

// A failed read says nothing about the observation: the file must survive
// without any trace of a rejection and apply once it can be read again.
func TestImporterKeepsValidFileItCouldNotRead(t *testing.T) {
	for _, tc := range readFailures {
		t.Run(tc.name, func(t *testing.T) {
			im, spool, store, _, logs := newRetryImporter(t)
			ctx := context.Background()
			oneObservation(t, spool)
			restore := failReads(spool, tc.err)

			for range 2 {
				rep, err := im.ImportOnce(ctx)
				if err != nil {
					t.Fatalf("ImportOnce: %v", err)
				}
				if rep.Failed != 1 || rep.Rejected != 0 || rep.Imported != 0 || rep.Skipped != 0 {
					t.Fatalf("report = %+v, want 1 failed", rep)
				}
				if len(rep.Errors) != 1 || !strings.HasSuffix(rep.Errors[0], ": read_failed") {
					t.Fatalf("errors = %q, want the fixed code", rep.Errors)
				}
				if names, _ := spool.List(ctx); len(names) != 1 {
					t.Fatalf("spool = %v, want the observation kept", names)
				}
			}
			if len(im.stuck) != 0 {
				t.Fatalf("stuck = %v, want an unread file left out", im.stuck)
			}
			got := logs.String()
			if !strings.Contains(got, `"reason":"read_failed"`) ||
				strings.Contains(got, "invalid_observation") || strings.Contains(got, "injected-read-failure") {
				t.Fatalf("log must carry the fixed code only:\n%s", got)
			}

			restore()
			rep, err := im.ImportOnce(ctx)
			if err != nil {
				t.Fatalf("ImportOnce: %v", err)
			}
			if rep.Imported != 1 || rep.Failed != 0 {
				t.Fatalf("retry report = %+v, want 1 imported", rep)
			}
			if names, _ := spool.List(ctx); len(names) != 0 {
				t.Fatalf("spool = %v, want empty after the retry", names)
			}
			if _, err := store.GetRemote(ctx, "remote-a"); err != nil {
				t.Fatalf("GetRemote: %v", err)
			}
		})
	}
}

// A file that could neither be read nor removed was not processed, so a later
// pass must import it instead of only retrying the unlink.
func TestImporterImportsFileWhoseReadAndUnlinkFailed(t *testing.T) {
	im, spool, store, _, _ := newRetryImporter(t)
	ctx := context.Background()
	oneObservation(t, spool)
	im.remove = failRemove
	restore := failReads(spool, unix.EIO)
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Failed != 1 {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}

	restore()
	im.remove = spool.Remove
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Imported != 1 || rep.Skipped != 0 {
		t.Fatalf("second pass = %+v, want the file imported", rep)
	}
	if _, err := store.GetRemote(ctx, "remote-a"); err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
}

func TestGuestNetImportKeepsValidRecordItCouldNotRead(t *testing.T) {
	ctx := context.Background()
	for _, tc := range readFailures {
		t.Run(tc.name, func(t *testing.T) {
			w, im, sink := newGuestNetImportFixture(t)
			if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
				t.Fatal(err)
			}
			restore := failReads(im.spool, tc.err)
			rep, err := im.ImportOnce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rep != (GuestNetImportReport{Files: 1, Failed: 1}) {
				t.Fatalf("report = %+v", rep)
			}
			if names, _ := w.ListGuestNet(ctx); len(names) != 1 {
				t.Fatalf("spool = %v, want the record kept", names)
			}
			if len(im.stuck) != 0 {
				t.Fatalf("stuck = %v, want an unread record left out", im.stuck)
			}

			restore()
			if rep, err := im.ImportOnce(ctx); err != nil || rep != (GuestNetImportReport{Files: 1, Imported: 1}) {
				t.Fatalf("retry = %+v, %v", rep, err)
			}
			if len(sink.got) != 1 {
				t.Fatalf("sink got %+v", sink.got)
			}
		})
	}
}

// The guest NIC counterpart of TestImporterImportsFileWhoseReadAndUnlinkFailed.
func TestGuestNetImportImportsRecordWhoseReadAndUnlinkFailed(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	remove := im.remove
	im.remove = failRemove
	restore := failReads(im.spool, unix.EIO)
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Failed != 1 {
		t.Fatalf("first pass = %+v, %v", rep, err)
	}

	restore()
	im.remove = remove
	if rep, err := im.ImportOnce(ctx); err != nil || rep != (GuestNetImportReport{Files: 1, Imported: 1}) {
		t.Fatalf("second pass = %+v, %v", rep, err)
	}
	if len(sink.got) != 1 {
		t.Fatalf("sink got %+v", sink.got)
	}
}

// afterImportSink runs after once the first record went through, so a test
// can break the spool between the listing and the next read.
type afterImportSink struct {
	fakeGuestNetSink
	after func()
}

func (s *afterImportSink) ImportGuestNet(ctx context.Context, rec GuestNetRecord) error {
	err := s.fakeGuestNetSink.ImportGuestNet(ctx, rec)
	if after := s.after; after != nil {
		s.after = nil
		after()
	}
	return err
}

// ReadGuestNet opens the directory for every record. When that fails, also
// through a swapped-in symlink, the fault lies outside the record: it stays,
// with a real kernel error instead of an injected one.
func TestGuestNetImportKeepsRecordWhenDirectoryOpenFails(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		swap func(t *testing.T, dir string)
	}{
		{"directory missing", func(*testing.T, string) {}},
		{"directory is a symlink", func(t *testing.T, dir string) {
			if err := os.Symlink(dir+".moved", dir); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, im, _ := newGuestNetImportFixture(t)
			sink := &afterImportSink{}
			im.sink = sink
			other := validGuestNetRecord()
			other.Remote = "pve-other"
			var kept string
			for _, rec := range []GuestNetRecord{validGuestNetRecord(), other} {
				name, err := w.WriteGuestNet(ctx, rec)
				if err != nil {
					t.Fatal(err)
				}
				kept = name
			}
			dir := filepath.Join(w.root, guestNetDirName)
			sink.after = func() {
				if err := os.Rename(dir, dir+".moved"); err != nil {
					t.Fatal(err)
				}
				tc.swap(t, dir)
			}

			rep, err := im.ImportOnce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Failed != 1 || rep.Rejected != 0 || rep.Imported != 1 {
				t.Fatalf("report = %+v, want 1 imported and 1 failed", rep)
			}

			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(dir+".moved", dir); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(guestNetPath(w, kept)); err != nil {
				t.Fatalf("record lost: %v", err)
			}
			rep, err = im.ImportOnce(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Imported != 1 || rep.Failed != 0 {
				t.Fatalf("retry = %+v, want the record imported", rep)
			}
			if len(sink.got) != 2 {
				t.Fatalf("sink got %+v, want both records", sink.got)
			}
			if names, _ := w.ListGuestNet(ctx); len(names) != 0 {
				t.Fatalf("spool = %v, want empty after the retry", names)
			}
		})
	}
}

// The readers mark exactly the faults of the file itself as invalid, because
// that mark is what lets an importer discard it.
func TestSpoolReadersMarkOnlyFileFaultsInvalid(t *testing.T) {
	ctx := context.Background()
	const (
		obsName = "remote-a.gen-00000000000000000001.json"
		netName = "pve-lab.obs-00000000001700000000.json"
	)
	cases := []struct {
		name string
		make func(t *testing.T, path string)
	}{
		{"malformed", func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte("{not json"), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversize", func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, make([]byte, MaxGuestNetBytes+1), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, path string) {
			t.Helper()
			if err := unix.Mkfifo(path, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			if err := os.Symlink("/etc/passwd", path); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSpool(t)
			tc.make(t, filepath.Join(s.ResultsDir(), obsName))
			if _, err := s.ReadFile(ctx, obsName); !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("ReadFile = %v, want ErrInvalidObservation", err)
			}
			if _, err := s.guestNetDir(); err != nil {
				t.Fatal(err)
			}
			tc.make(t, guestNetPath(s, netName))
			if _, err := s.ReadGuestNet(ctx, netName); !errors.Is(err, ErrGuestNetInvalid) {
				t.Fatalf("ReadGuestNet = %v, want ErrGuestNetInvalid", err)
			}
		})
	}
	for _, tc := range readFailures {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSpool(t)
			if _, err := s.guestNetDir(); err != nil {
				t.Fatal(err)
			}
			failReads(s, tc.err)
			if _, err := s.ReadFile(ctx, obsName); errors.Is(err, ErrInvalidObservation) || !errors.Is(err, tc.err) {
				t.Fatalf("ReadFile = %v, want %v alone", err, tc.err)
			}
			if _, err := s.ReadGuestNet(ctx, netName); errors.Is(err, ErrGuestNetInvalid) || !errors.Is(err, tc.err) {
				t.Fatalf("ReadGuestNet = %v, want %v alone", err, tc.err)
			}
		})
	}
}

// A valid document under another remote's name is tampering, so the identity
// check counts as a fault of the file.
func TestSpoolReaderMarksIdentityMismatchInvalid(t *testing.T) {
	ctx := context.Background()
	_, spool, _, _, _ := newRetryImporter(t)
	oneObservation(t, spool)
	names, err := spool.List(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("List = %v, %v", names, err)
	}
	const renamed = "remote-b.gen-00000000000000000001.json"
	if err := os.Rename(filepath.Join(spool.ResultsDir(), names[0]), filepath.Join(spool.ResultsDir(), renamed)); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.ReadFile(ctx, renamed); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("ReadFile = %v, want ErrInvalidObservation", err)
	}
}

// The store cannot read back a year outside four digits, so accepting one
// would fail every later ingest of the remote and strand its files. Such a
// file is invalid and goes, and the remote keeps importing.
func TestImporterDropsObservationWithUnstorableTime(t *testing.T) {
	for _, observed := range []string{"0000-01-01T00:00:00+01:00", "9999-12-31T23:30:00-01:00"} {
		t.Run(observed, func(t *testing.T) {
			im, spool, store, _, _ := newRetryImporter(t)
			ctx := context.Background()
			oneObservation(t, spool)
			names, err := spool.List(ctx)
			if err != nil || len(names) != 1 {
				t.Fatalf("List = %v, %v", names, err)
			}
			path := filepath.Join(spool.ResultsDir(), names[0])
			retime(t, path, observed)

			rep, err := im.ImportOnce(ctx)
			if err != nil {
				t.Fatalf("ImportOnce: %v", err)
			}
			if rep.Rejected != 1 || rep.Imported != 0 {
				t.Fatalf("report = %+v, want 1 rejected", rep)
			}
			if names, _ := spool.List(ctx); len(names) != 0 {
				t.Fatalf("spool = %v, want the file dropped", names)
			}

			oneObservation(t, spool)
			rep, err = im.ImportOnce(ctx)
			if err != nil {
				t.Fatalf("ImportOnce: %v", err)
			}
			if rep.Imported != 1 || rep.Partial != 0 {
				t.Fatalf("next collection = %+v, want 1 imported", rep)
			}
			if _, err := store.GetRemote(ctx, "remote-a"); err != nil {
				t.Fatalf("GetRemote: %v", err)
			}
		})
	}
}

// retime rewrites the observed_at of the spool file at path.
func retime(t *testing.T, path, observed string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["observed_at"] = json.RawMessage(fmt.Sprintf("%q", observed))
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
}
