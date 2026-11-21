// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

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

// TestDeviceRowCarriesCollectorReportTime: the row's last_seen is the time
// the collector reported the device, and each newer record moves it on.
func TestDeviceRowCarriesCollectorReportTime(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	base := *clock

	first := base.Add(-10 * time.Minute)
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), first); err != nil {
		t.Fatalf("UpsertDeviceReported: %v", err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(first) {
		t.Fatalf("LastSeen after first record = %v, want %v", got.LastSeen, first)
	}

	prev := got.LastSeen
	for i := 1; i <= 3; i++ {
		at := base.Add(time.Duration(i) * time.Minute)
		if err := s.UpsertDeviceReported(ctx, cbsDevice(), at); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		got, err = s.GetDevice(ctx, "sw-core")
		if err != nil {
			t.Fatal(err)
		}
		if !got.LastSeen.Equal(at) || !got.LastSeen.After(prev) {
			t.Fatalf("record %d: LastSeen = %v, want %v (after %v)", i, got.LastSeen, at, prev)
		}
		prev = got.LastSeen
	}
}

// TestOlderReportNeverMovesLastSeenBack: a delayed spool record must not
// roll last_seen back.
func TestOlderReportNeverMovesLastSeenBack(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	newer := *clock
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), newer); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), newer.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(newer) {
		t.Fatalf("LastSeen = %v, want %v (older report must not move it back)", got.LastSeen, newer)
	}
}

// TestUpsertDeviceReportRejectsZeroAndFutureTime: a report without a usable
// time is refused and creates no row.
func TestUpsertDeviceReportRejectsZeroAndFutureTime(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		at   func(now time.Time) time.Time
		want error
	}{
		{"zero time", func(time.Time) time.Time { return time.Time{} }, nil},
		{"beyond future skew", func(now time.Time) time.Time { return now.Add(MaxFutureSkew + time.Second) }, ErrFutureObservation},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, db, clock := newTestStore(t)
			err := s.UpsertDeviceReported(ctx, cbsDevice(), tt.at(*clock))
			if err == nil {
				t.Fatal("expected refusal")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
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
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), *clock); err != nil {
		t.Fatal(err)
	}
	before := snapshotDevice(t, s, "sw-core")

	evil := cbsDevice()
	evil.TrustGeneration = 1
	evil.Name = "attacker label"
	*clock = clock.Add(5 * time.Minute)
	err := s.UpsertDeviceReported(ctx, evil, *clock)
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
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), *clock); err != nil {
		t.Fatal(err)
	}
	before := snapshotDevice(t, s, "sw-core")

	other := panosDevice()
	other.DeviceID = "sw-core"
	other.TrustGeneration = 9
	*clock = clock.Add(time.Minute)
	if err := s.UpsertDeviceReported(ctx, other, *clock); !errors.Is(err, ErrFamilyChanged) {
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
// is collector-reported (not confirmed) and how old the last report is, and
// turns stale once it is not refreshed for StaleAfterIntervals intervals.
func TestDeviceReadReportsOriginAndAge(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	base := *clock
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), base); err != nil {
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

// TestUpsertDeviceUsesServerClock: the unchanged UpsertDevice entry point
// stamps the report with the server clock.
func TestUpsertDeviceUsesServerClock(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertDevice(ctx, cbsDevice()); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSeen.Equal(*clock) {
		t.Fatalf("LastSeen = %v, want server clock %v", got.LastSeen, *clock)
	}
}

// TestNoDeviceRowWithoutReport: no device row exists unless a report wrote
// it, and a dataset cannot be stored for a device that was never reported.
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
	if n := countRows(t, db, `SELECT COUNT(*) FROM netdev_devices_seen`); n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}
