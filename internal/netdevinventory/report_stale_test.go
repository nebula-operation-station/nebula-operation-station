// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"testing"
	"time"
)

// TestDeviceReportStalenessIsByNewestReport: a device whose newest collector
// report is older than DeviceReportStaleAfter reads as stale, while its
// datasets keep their own state. The dataset is refreshed at every step, so
// only the report age decides the device state.
func TestDeviceReportStalenessIsByNewestReport(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	base := *clock
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), refAt(base)); err != nil {
		t.Fatal(err)
	}
	rows := VLANRows{{ID: 1, Name: "default"}}
	mustReplace(t, s, "sw-core", ReadVLANs, base, false, rows)

	tests := []struct {
		name      string
		at        time.Duration
		wantState DeviceState
	}{
		{"just reported", 0, DeviceFresh},
		{"inside the report window", DeviceReportStaleAfter - time.Minute, DeviceFresh},
		{"past the report window", DeviceReportStaleAfter + time.Minute, DeviceStale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*clock = base.Add(tt.at)
			mustReplace(t, s, "sw-core", ReadVLANs, *clock, false, rows)
			got, err := s.GetDevice(ctx, "sw-core")
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tt.wantState {
				t.Fatalf("State = %v, want %v", got.State, tt.wantState)
			}
			ds, err := s.GetDataset(ctx, "sw-core", ReadVLANs)
			if err != nil {
				t.Fatal(err)
			}
			if ds.State != StateFresh {
				t.Fatalf("dataset State = %v, want fresh: a report age must not change it", ds.State)
			}
		})
	}
}

// TestNewReportRevivesReportStaleDevice: a newer report puts a report-stale
// device back to fresh; the report time moves, the dataset does not need to.
func TestNewReportRevivesReportStaleDevice(t *testing.T) {
	s, _, clock := newTestStore(t)
	ctx := context.Background()
	base := *clock
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), refAt(base)); err != nil {
		t.Fatal(err)
	}
	*clock = base.Add(DeviceReportStaleAfter + time.Hour)
	mustReplace(t, s, "sw-core", ReadVLANs, *clock, false, VLANRows{{ID: 1, Name: "default"}})
	if got := snapshotDevice(t, s, "sw-core"); got.State != DeviceStale {
		t.Fatalf("State with old report = %v, want stale", got.State)
	}
	if err := s.UpsertDeviceReported(ctx, cbsDevice(), refAt(*clock)); err != nil {
		t.Fatal(err)
	}
	if got := snapshotDevice(t, s, "sw-core"); got.State != DeviceFresh {
		t.Fatalf("State after newer report = %v, want fresh", got.State)
	}
}

// TestReportStaleIgnoresZeroTime: a row no spool record wrote has no report
// time (Device.ReportedAt is zero), and the report rule never judges it.
func TestReportStaleIgnoresZeroTime(t *testing.T) {
	var zero time.Time
	if reportStale(zero, testBase.Add(1000*DeviceReportStaleAfter)) {
		t.Fatal("zero ReportedAt must not be report stale")
	}
}
