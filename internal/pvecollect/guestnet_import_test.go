// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type fakeGuestNetSink struct {
	got  []GuestNetRecord
	fail error
}

func (f *fakeGuestNetSink) ImportGuestNet(_ context.Context, rec GuestNetRecord) error {
	if f.fail != nil {
		return f.fail
	}
	f.got = append(f.got, rec)
	return nil
}

// newGuestNetImportFixture returns a collector-side spool and an importer
// on a separate read-side spool of the same root, as in production.
func newGuestNetImportFixture(t *testing.T) (*Spool, *GuestNetImporter, *fakeGuestNetSink) {
	t.Helper()
	w := newTestSpool(t)
	r, err := OpenSpool(w.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	sink := &fakeGuestNetSink{}
	im, err := NewGuestNetImporter(r, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	im.Now = func() time.Time { return time.Unix(1_700_000_100, 0) }
	return w, im, sink
}

func TestNewGuestNetImporterRequiresSpoolAndSink(t *testing.T) {
	s := newTestSpool(t)
	if _, err := NewGuestNetImporter(nil, &fakeGuestNetSink{}, nil); err == nil {
		t.Error("nil spool accepted")
	}
	if _, err := NewGuestNetImporter(s, nil, nil); err == nil {
		t.Error("nil sink accepted")
	}
}

func TestGuestNetImportHandsRecordsToSinkAndConsumesThem(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	other := validGuestNetRecord()
	other.Remote = "pve-other"
	for _, rec := range []GuestNetRecord{validGuestNetRecord(), other} {
		if _, err := w.WriteGuestNet(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep != (GuestNetImportReport{Files: 2, Imported: 2}) {
		t.Fatalf("report = %+v", rep)
	}
	if len(sink.got) != 2 || sink.got[0].Remote != "pve-lab" || sink.got[1].Remote != "pve-other" {
		t.Fatalf("sink got %+v", sink.got)
	}
	if names, _ := w.ListGuestNet(ctx); len(names) != 0 {
		t.Fatalf("imported records not consumed: %v", names)
	}
}

func TestGuestNetImportKeepsRecordWhenSinkFails(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	sink.fail = errors.New("store busy")
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep != (GuestNetImportReport{Files: 1, Failed: 1}) {
		t.Fatalf("report = %+v", rep)
	}
	sink.fail = nil
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Imported != 1 {
		t.Fatalf("retry = %+v, %v", rep, err)
	}
}

func TestGuestNetImportDropsReplayedAndFutureRecords(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	rec := validGuestNetRecord()
	if _, err := w.WriteGuestNet(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := im.ImportOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// The same snapshot again (a replayed file) and an older one are stale.
	older := rec
	older.ObservedUnix--
	for _, r := range []GuestNetRecord{rec, older} {
		if _, err := w.WriteGuestNet(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// A snapshot dated beyond the clock skew is refused.
	future := rec
	future.Remote = "pve-other"
	future.ObservedUnix = im.Now().Unix() + int64(GuestNetClockSkew/time.Second) + 1
	if _, err := w.WriteGuestNet(ctx, future); err != nil {
		t.Fatal(err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep != (GuestNetImportReport{Files: 3, Replayed: 2, Rejected: 1}) {
		t.Fatalf("report = %+v", rep)
	}
	if len(sink.got) != 1 {
		t.Fatalf("sink got %d records, want 1", len(sink.got))
	}
	if names, _ := w.ListGuestNet(ctx); len(names) != 0 {
		t.Fatalf("rejected records not dropped: %v", names)
	}
}

func TestGuestNetImportDropsHostileFiles(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"pve-x.obs-00000000001700000000.json": `{"version":1,"remote":"pve-x","observed_unix":1700000000,"nics":[{"vmid":1}]}`,
		"pve-y.obs-00000000001700000000.json": "\xff\xfe",
		"pve-z.obs-00000000001700000000.json": `{"version":1,"remote":"pve-lab","observed_unix":1700000000,"nics":[]}`,
	} {
		if err := os.WriteFile(guestNetPath(w, name), []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep != (GuestNetImportReport{Files: 4, Imported: 1, Rejected: 3}) {
		t.Fatalf("report = %+v", rep)
	}
	if len(sink.got) != 1 || sink.got[0].Remote != "pve-lab" {
		t.Fatalf("sink got %+v", sink.got)
	}
	if names, _ := w.ListGuestNet(ctx); len(names) != 0 {
		t.Fatalf("hostile files not dropped: %v", names)
	}
}

func TestGuestNetImportStopsOnSymlinkedEntry(t *testing.T) {
	ctx := context.Background()
	w, im, sink := newGuestNetImportFixture(t)
	if _, err := w.WriteGuestNet(ctx, validGuestNetRecord()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", guestNetPath(w, "pve-q.obs-00000000001700000000.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := im.ImportOnce(ctx); !errors.Is(err, ErrSymlink) {
		t.Fatalf("err = %v, want ErrSymlink", err)
	}
	if len(sink.got) != 0 {
		t.Fatalf("imported despite tampered directory: %+v", sink.got)
	}
}
