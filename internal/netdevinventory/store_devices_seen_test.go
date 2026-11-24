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

// TestUpsertDeviceLeavesLastSeenUnset: the plain UpsertDevice path does not
// stamp last_seen, which stays the newest dataset observation (zero before
// any dataset).
func TestUpsertDeviceLeavesLastSeenUnset(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDevice(ctx, cbsDevice()); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.IsZero() {
		t.Fatalf("LastSeen = %v, want zero", got.LastSeen)
	}
}

// TestLaterReportKeepsDatasetLastSeen: a later report or plain upsert (label
// change) does not clear or move the dataset last_seen.
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
	if err := s.UpsertDevice(ctx, renamed); err != nil {
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

// TestPlainUpsertDeviceRowIsUnreported: a row written by the plain UpsertDevice
// path has no spool record, so it reads as unreported, never as collector
// reported.
func TestPlainUpsertDeviceRowIsUnreported(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDevice(ctx, cbsDevice()); err != nil {
		t.Fatal(err)
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

// TestPlainUpsertKeepsReportedOrigin: the plain UpsertDevice path never
// downgrades a row that a spool record wrote, nor clears its reference.
func TestPlainUpsertKeepsReportedOrigin(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), testRef()); err != nil {
		t.Fatal(err)
	}
	renamed := cbsDevice()
	renamed.Name = "renamed"
	if err := s.UpsertDevice(ctx, renamed); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != OriginCollectorReported || got.Spool != testRef() || got.ReportedAt.IsZero() {
		t.Fatalf("plain upsert changed the report: Origin %q Spool %+v ReportedAt %v", got.Origin, got.Spool, got.ReportedAt)
	}
}

// TestSchemaRejectsInconsistentOrigin: the schema refuses a collector-reported
// row without its spool record and report time, and an unreported row that
// names a spool record, even for a direct SQL write.
func TestSchemaRejectsInconsistentOrigin(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDevice(ctx, cbsDevice()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		sql  string
	}{
		{"reported without spool record", `UPDATE netdev_devices_seen SET origin = 'collector_reported' WHERE device_id = 'sw-core'`},
		{"reported without report time", `UPDATE netdev_devices_seen SET origin = 'collector_reported', spool_name = 'a.json', spool_sha256 = '` + strings.Repeat("a", 64) + `' WHERE device_id = 'sw-core'`},
		{"unreported with spool record", `UPDATE netdev_devices_seen SET spool_name = 'a.json', spool_sha256 = '` + strings.Repeat("a", 64) + `', reported_at = 1 WHERE device_id = 'sw-core'`},
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
	if got, err := s.GetDevice(ctx, "sw-core"); err != nil || got.Origin != OriginUnreported {
		t.Fatalf("row after refused writes: Origin %q, err %v; want unreported", got.Origin, err)
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
