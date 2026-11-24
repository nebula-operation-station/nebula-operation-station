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
