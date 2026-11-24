// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// testRef is a well-formed spool reference for the report tests.
func testRef() SpoolRef {
	return SpoolRef{
		Name:   "sw-core-cbs_version-1700000000000000000-ABCDEFGHIJKLMNOPQRSTUVWXYZ.json",
		Digest: strings.Repeat("ab", 32),
	}
}

// deviceSnapshot is the part of a stored device row a refused write must
// not change.
type deviceSnapshot struct {
	Family   netdevcontract.Family
	Label    string
	Gen      uint64
	LastSeen time.Time
	State    DeviceState
}

func snapshotDevice(t *testing.T, s *Store, id string) deviceSnapshot {
	t.Helper()
	d, err := s.GetDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("GetDevice(%s): %v", id, err)
	}
	return deviceSnapshot{Family: d.Family, Label: d.Label, Gen: d.TrustGeneration, LastSeen: d.LastSeen, State: d.State}
}

// TestMetadataReportNeverMovesLastSeen: a collector metadata report creates
// or updates the row but leaves last_seen to the dataset observations. Only
// a stored dataset moves it, and never backwards.
func TestMetadataReportNeverMovesLastSeen(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatalf("UpsertDeviceReported: %v", err)
	}
	for i := 1; i <= 3; i++ {
		*clock = clock.Add(time.Minute)
		if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.IsZero() {
		t.Fatalf("LastSeen after metadata reports only = %v, want zero", got.LastSeen)
	}

	observed := *clock
	mustReplace(t, s, "sw-core", ReadVLANs, observed, false, VLANRows{{ID: 1, Name: "default"}})
	*clock = clock.Add(time.Minute)
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(observed) {
		t.Fatalf("LastSeen = %v, want dataset observation %v (a later report must not move it)", got.LastSeen, observed)
	}
}

// TestSpoolRefNameAlphabet: the spool record name is an ASCII name from
// letters, digits, '-', '_' and '.', with no "..". Anything else (path
// separators, control or Unicode format characters, non-ASCII letters) is
// refused, so a name can never escape a directory or spoof a display.
func TestSpoolRefNameAlphabet(t *testing.T) {
	good := testRef().Digest
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{"typical record name", "sw-core-cbs_version-1700000000000000000-ABC.json", false},
		{"digits and dots", "a.1.2.json", false},
		{"single letter", "a", false},
		{"maximum length", strings.Repeat("a", MaxSpoolRefName), false},
		{"over the limit", strings.Repeat("a", MaxSpoolRefName+1), true},
		{"empty", "", true},
		{"slash path", "dir/sw.json", true},
		{"leading slash", "/etc/sw.json", true},
		{"backslash", `dir\sw.json`, true},
		{"parent traversal", "../sw.json", true},
		{"double dot inside name", "sw..json", true},
		{"only double dots", "..", true},
		{"right-to-left override", "sw‮json.exe", true},
		{"zero-width space", "sw​core.json", true},
		{"byte order mark", "\xef\xbb\xbfsw.json", true},
		{"non-ASCII letter", "sé.json", true},
		{"full-width solidus", "dir／sw.json", true},
		{"space", "sw core.json", true},
		{"colon", "sw:core.json", true},
		{"NUL", "sw\x00core.json", true},
		{"DEL", "sw\x7fcore.json", true},
		{"newline", "sw\ncore.json", true},
		{"invalid UTF-8", "sw\xffcore.json", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SpoolRef{Name: tt.file, Digest: good}.validate()
			if tt.wantErr && !errors.Is(err, ErrBadSpoolRef) {
				t.Fatalf("validate(%q) = %v, want ErrBadSpoolRef", tt.file, err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validate(%q) = %v, want nil", tt.file, err)
			}
		})
	}
}

// TestUpsertDeviceReportedRejectsBadSpoolRef: a report whose spool reference
// is missing or malformed is refused with ErrBadSpoolRef and creates no row.
func TestUpsertDeviceReportedRejectsBadSpoolRef(t *testing.T) {
	ctx := context.Background()
	good := testRef()
	tests := []struct {
		name string
		ref  SpoolRef
	}{
		{"empty name", SpoolRef{Name: "", Digest: good.Digest}},
		{"name over the limit", SpoolRef{Name: strings.Repeat("a", MaxSpoolRefName+1), Digest: good.Digest}},
		{"name with control character", SpoolRef{Name: "sw\x00core.json", Digest: good.Digest}},
		{"name not valid UTF-8", SpoolRef{Name: "sw\xffcore.json", Digest: good.Digest}},
		{"name with path separator", SpoolRef{Name: "dir/sw.json", Digest: good.Digest}},
		{"name with parent traversal", SpoolRef{Name: "../sw.json", Digest: good.Digest}},
		{"name with bidi override", SpoolRef{Name: "sw‮json.exe", Digest: good.Digest}},
		{"empty digest", SpoolRef{Name: good.Name, Digest: ""}},
		{"short digest", SpoolRef{Name: good.Name, Digest: good.Digest[:63]}},
		{"uppercase digest", SpoolRef{Name: good.Name, Digest: strings.ToUpper(good.Digest)}},
		{"non-hex digest", SpoolRef{Name: good.Name, Digest: strings.Repeat("g", 64)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			err := s.UpsertDeviceReported(ctx, cbsDevice(), tt.ref)
			if !errors.Is(err, ErrBadSpoolRef) {
				t.Fatalf("err = %v, want ErrBadSpoolRef", err)
			}
			if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 0 {
				t.Fatalf("rows = %d, want 0 after refusal", n)
			}
		})
	}
}

// TestTrustGenerationRegressionChangesNothing: a record with a lower trust
// generation is refused with ErrTrustGenerationRegressed and the stored row
// stays exactly as it was.
func TestTrustGenerationRegressionChangesNothing(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	before := snapshotDevice(t, s, "sw-core")

	evil := cbsDevice()
	evil.TrustGeneration = 1
	evil.Name = "attacker label"
	*clock = clock.Add(5 * time.Minute)
	err := s.UpsertDeviceReported(ctx, evil, testRef())
	if !errors.Is(err, ErrTrustGenerationRegressed) {
		t.Fatalf("err = %v, want ErrTrustGenerationRegressed", err)
	}
	if after := snapshotDevice(t, s, "sw-core"); after != before {
		t.Fatalf("row changed by refused record: before %+v, after %+v", before, after)
	}
}

// TestFamilyChangeChangesNothing: a record that would change the immutable
// family is refused and the row stays as it was.
func TestFamilyChangeChangesNothing(t *testing.T) {
	s, db, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	before := snapshotDevice(t, s, "sw-core")

	other := panosDevice()
	other.DeviceID = "sw-core"
	other.TrustGeneration = 9
	*clock = clock.Add(time.Minute)
	if err := s.UpsertDeviceReported(ctx, other, testRef()); !errors.Is(err, ErrFamilyChanged) {
		t.Fatalf("err = %v, want ErrFamilyChanged", err)
	}
	if after := snapshotDevice(t, s, "sw-core"); after != before {
		t.Fatalf("row changed by refused record: before %+v, after %+v", before, after)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

// TestDeviceReadReportsOriginAndAge: the read tells the page that the row
// is collector-reported (not confirmed) and how old the last sighting is, and
// turns stale once it is not refreshed for StaleAfterIntervals intervals.
func TestDeviceReadReportsOriginAndAge(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	base := *clock
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	staleAfter := StaleAfterIntervals * SwitchInterval

	tests := []struct {
		name      string
		at        time.Duration
		wantAge   time.Duration
		wantState DeviceState
	}{
		{"just reported", 0, 0, DeviceFresh},
		{"two minutes later", 2 * time.Minute, 2 * time.Minute, DeviceFresh},
		{"just inside the stale window", staleAfter, staleAfter, DeviceFresh},
		{"past the stale window", staleAfter + time.Minute, staleAfter + time.Minute, DeviceStale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*clock = base.Add(tt.at)
			got, err := s.GetDevice(ctx, "sw-core")
			if err != nil {
				t.Fatal(err)
			}
			if got.Origin != OriginCollectorReported {
				t.Fatalf("Origin = %q, want %q", got.Origin, OriginCollectorReported)
			}
			if got.Age != tt.wantAge {
				t.Fatalf("Age = %v, want %v", got.Age, tt.wantAge)
			}
			if got.State != tt.wantState {
				t.Fatalf("State = %v, want %v", got.State, tt.wantState)
			}
		})
	}
}

// TestMetadataReportKeepsStaleAndDatasetRevives: a metadata report does not
// revive a device that MarkStale marked stale, because only a dataset
// observation counts as seen. A dataset observation does revive it.
func TestMetadataReportKeepsStaleAndDatasetRevives(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(StaleAfterIntervals*SwitchInterval + time.Minute)
	if _, err := s.MarkStale(ctx); err != nil {
		t.Fatalf("MarkStale: %v", err)
	}
	if got := snapshotDevice(t, s, "sw-core"); got.State != DeviceStale {
		t.Fatalf("State after MarkStale = %v, want stale", got.State)
	}

	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	if got := snapshotDevice(t, s, "sw-core"); got.State != DeviceStale {
		t.Fatalf("State after metadata report = %v, want stale", got.State)
	}

	mustReplace(t, s, "sw-core", ReadVLANs, *clock, false, VLANRows{{ID: 1, Name: "default"}})
	if got := snapshotDevice(t, s, "sw-core"); got.State != DeviceFresh {
		t.Fatalf("State after dataset = %v, want fresh", got.State)
	}
}

// TestLaterReportKeepsDatasetLastSeen: a later report (label change) does not
// clear or move the dataset last_seen.
func TestLaterReportKeepsDatasetLastSeen(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	observed := *clock
	mustReplace(t, s, "sw-core", ReadVLANs, observed, false, VLANRows{{ID: 1, Name: "default"}})
	renamed := cbsDevice()
	renamed.Name = "renamed"
	if err := s.UpsertDeviceReported(ctx, renamed, testRef()); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(observed) || got.Label != "renamed" {
		t.Fatalf("device = %+v, want LastSeen %v and label renamed", got, observed)
	}
}

// TestLegacyUnreportedRowReadsAsUnreported: a row whose origin is unreported
// (no spool record, e.g. one that predates migration 0057) reads as unreported
// and not as collector reported. GetDevice takes the origin from the row, so
// a valid report then turns it into a collector-reported row.
func TestLegacyUnreportedRowReadsAsUnreported(t *testing.T) {
	s, db, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE netdev_devices_seen
		SET origin = 'unreported', spool_name = NULL, spool_sha256 = NULL, reported_at = NULL
		WHERE device_id = 'sw-core'`); err != nil {
		t.Fatalf("make row unreported: %v", err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != OriginUnreported {
		t.Fatalf("Origin = %q, want %q", got.Origin, OriginUnreported)
	}
	if got.Spool != (SpoolRef{}) || !got.ReportedAt.IsZero() {
		t.Fatalf("Spool = %+v ReportedAt = %v, want none for an unreported row", got.Spool, got.ReportedAt)
	}

	*clock = clock.Add(time.Minute)
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != OriginCollectorReported || got.Spool != testRef() {
		t.Fatalf("after report: Origin %q Spool %+v, want collector reported with the record", got.Origin, got.Spool)
	}
}

// TestReportedRowCarriesSpoolReference: a report stores the spool record it
// came from and when it was accepted, and a newer report replaces both.
func TestReportedRowCarriesSpoolReference(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	first := micros(*clock)
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != OriginCollectorReported || got.Spool != testRef() || !got.ReportedAt.Equal(fromMicros(first)) {
		t.Fatalf("after report: Origin %q Spool %+v ReportedAt %v", got.Origin, got.Spool, got.ReportedAt)
	}

	newer := SpoolRef{Name: "sw-core-cbs_version-1800000000000000000-ZZZ.json", Digest: strings.Repeat("cd", 32)}
	*clock = clock.Add(time.Minute)
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), newer); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.Spool != newer || !got.ReportedAt.Equal(fromMicros(micros(*clock))) {
		t.Fatalf("after newer report: Spool %+v ReportedAt %v, want %+v at %v", got.Spool, got.ReportedAt, newer, *clock)
	}
}

// TestPlainUpsertRefusesAndWritesNothing: the plain UpsertDevice path refuses
// every write with ErrUnreportedDevice. It creates no row, and on an existing
// row it changes neither the label, the trust generation, the origin, the
// spool reference, the report time nor last_seen and state.
func TestPlainUpsertRefusesAndWritesNothing(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDevice(ctx, cbsDevice()); !errors.Is(err, ErrUnreportedDevice) {
		t.Fatalf("plain upsert on empty store err = %v, want ErrUnreportedDevice", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 0 {
		t.Fatalf("plain upsert created %d rows, want 0", n)
	}

	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	renamed := cbsDevice()
	renamed.Name = "renamed"
	renamed.TrustGeneration = 9
	if err := s.UpsertDevice(ctx, renamed); !errors.Is(err, ErrUnreportedDevice) {
		t.Fatalf("plain upsert on existing row err = %v, want ErrUnreportedDevice", err)
	}
	after, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("plain upsert changed the row:\nbefore %+v\nafter  %+v", before, after)
	}
}

// TestSchemaRejectsInconsistentOrigin: the schema refuses a collector-reported
// row without its spool record and report time, and an unreported row that
// names a spool record, even for a direct SQL write.
func TestSchemaRejectsInconsistentOrigin(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		sql  string
	}{
		{"reported without spool record", `UPDATE netdev_devices_seen SET spool_name = NULL, spool_sha256 = NULL WHERE device_id = 'sw-core'`},
		{"reported without report time", `UPDATE netdev_devices_seen SET reported_at = NULL WHERE device_id = 'sw-core'`},
		{"unreported with spool record", `UPDATE netdev_devices_seen SET origin = 'unreported' WHERE device_id = 'sw-core'`},
		{"bad digest", `UPDATE netdev_devices_seen SET origin = 'collector_reported', spool_name = 'a.json', spool_sha256 = 'XYZ', reported_at = 1 WHERE device_id = 'sw-core'`},
		{"unknown origin", `UPDATE netdev_devices_seen SET origin = 'confirmed' WHERE device_id = 'sw-core'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := db.Exec(tt.sql); err == nil {
				t.Fatalf("write accepted, want a CHECK failure: %s", tt.sql)
			}
		})
	}
	if got, err := s.GetDevice(ctx, "sw-core"); err != nil || got.Origin != OriginCollectorReported {
		t.Fatalf("row after refused writes: Origin %q, err %v; want collector reported", got.Origin, err)
	}
}

// TestNoDeviceRowWithoutReport: the only row creation the import path
// reaches is a valid report. A dataset for an unreported device is refused,
// and a refused report creates no row.
func TestNoDeviceRowWithoutReport(t *testing.T) {
	s, db, clock := newTestStore(t)
	ctx := context.Background()
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 0 {
		t.Fatalf("fresh store has %d device rows", n)
	}
	_, err := s.ReplaceDataset(ctx, "sw-core", ReadFacts, cbsDevice().TrustGeneration, *clock, false, FactsRows{})
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("ReplaceDataset err = %v, want ErrDeviceNotFound", err)
	}
	if _, err := s.GetDevice(ctx, "sw-core"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("GetDevice err = %v, want ErrDeviceNotFound", err)
	}
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), SpoolRef{Name: "", Digest: testRef().Digest}); !errors.Is(err, ErrBadSpoolRef) {
		t.Fatalf("refused report err = %v, want ErrBadSpoolRef", err)
	}
	if err := s.UpsertDevice(ctx, cbsDevice()); !errors.Is(err, ErrUnreportedDevice) {
		t.Fatalf("plain UpsertDevice err = %v, want ErrUnreportedDevice", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 0 {
		t.Fatalf("rows = %d, want 0 after refused writes", n)
	}

	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 1 {
		t.Fatalf("rows = %d, want 1 after a valid report", n)
	}
}
