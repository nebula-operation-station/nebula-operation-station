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

// metaRecord is a valid metadata record for sw-core at trust generation 1.
func metaRecord() DeviceMetadataRecord {
	return DeviceMetadataRecord{
		DeviceID:        "sw-core",
		Family:          netdevcontract.FamilyCBS,
		Label:           "Core switch",
		TrustGeneration: 1,
	}
}

// TestUpsertDeviceMetadataCreatesCollectorReportedRow: a metadata record
// creates a row that carries its label, family, trust generation and spool
// reference, is marked collector-reported and has no data beyond those
// fields. The dataset and last_seen stay untouched.
func TestUpsertDeviceMetadataCreatesCollectorReportedRow(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	ref := testRef()
	if err := s.UpsertDeviceMetadata(ctx, metaRecord(), ref); err != nil {
		t.Fatalf("UpsertDeviceMetadata: %v", err)
	}

	d, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.Label != "Core switch" || d.Family != netdevcontract.FamilyCBS || d.TrustGeneration != 1 {
		t.Fatalf("row %+v, want label, family and trust generation from the record", d)
	}
	if d.Origin != OriginCollectorReported {
		t.Fatalf("origin %q, want %q", d.Origin, OriginCollectorReported)
	}
	if d.Spool != spoolRefOf(ref) || !d.ReportedAt.Equal(ref.RecordedAt) {
		t.Fatalf("spool ref %+v reported %v, want %+v at %v", d.Spool, d.ReportedAt, spoolRefOf(ref), ref.RecordedAt)
	}
	if !d.LastSeen.IsZero() {
		t.Fatalf("last_seen %v set by a metadata record, want none", d.LastSeen)
	}

	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM netdev_datasets WHERE device_id = 'sw-core'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("metadata record wrote %d datasets, want none", rows)
	}
}

// TestUpsertDeviceMetadataUpdatesOnlyMetadata: a newer record at the same
// trust generation replaces the label and spool reference and leaves the
// stored device data (datasets, last_seen) alone.
func TestUpsertDeviceMetadataUpdatesOnlyMetadata(t *testing.T) {
	ctx := context.Background()
	s, db, clock := newTestStore(t)
	addDevice(t, s, cbsDevice())
	mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1, Name: "default"}})
	before, err := s.GetDataset(ctx, "sw-core", ReadVLANs)
	if err != nil {
		t.Fatal(err)
	}
	var lastBefore int64
	if err := db.QueryRow(`SELECT last_seen FROM netdev_devices_seen WHERE device_id = 'sw-core'`).Scan(&lastBefore); err != nil {
		t.Fatal(err)
	}

	*clock = testBase.Add(time.Minute)
	m := metaRecord()
	m.TrustGeneration = 2 // the stored generation of cbsDevice
	m.Label = "Renamed core"
	newer := refAt(testBase.Add(time.Minute))
	if err := s.UpsertDeviceMetadata(ctx, m, newer); err != nil {
		t.Fatalf("UpsertDeviceMetadata: %v", err)
	}

	d, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if d.Label != "Renamed core" || d.Spool != spoolRefOf(newer) {
		t.Fatalf("row %+v, want the renamed label and the newer spool reference", d)
	}
	after, err := s.GetDataset(ctx, "sw-core", ReadVLANs)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID || after.RowCount != before.RowCount {
		t.Fatalf("dataset changed by a metadata record: before %+v after %+v", before, after)
	}
	var lastAfter int64
	if err := db.QueryRow(`SELECT last_seen FROM netdev_devices_seen WHERE device_id = 'sw-core'`).Scan(&lastAfter); err != nil {
		t.Fatal(err)
	}
	if lastAfter != lastBefore {
		t.Fatalf("last_seen moved from %d to %d on a metadata record", lastBefore, lastAfter)
	}
}

// TestUpsertDeviceMetadataRefusesBadInput: every rejection writes nothing and
// returns an error the caller can branch on.
func TestUpsertDeviceMetadataRefusesBadInput(t *testing.T) {
	long := strings.Repeat("x", netdevcontract.MaxLabelBytes+1)
	cases := []struct {
		name   string
		mutate func(*DeviceMetadataRecord, *SpoolRef)
		want   error
	}{
		{"empty device id", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.DeviceID = "" }, ErrInvalidMetadata},
		{"device id with slash", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.DeviceID = "sw/core" }, ErrInvalidMetadata},
		{"empty family", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Family = "" }, ErrInvalidMetadata},
		{"unknown family", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Family = "junos" }, ErrInvalidMetadata},
		{"label too long", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Label = long }, ErrInvalidMetadata},
		{"label with control character", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Label = "core\x00" }, ErrInvalidMetadata},
		{"label not UTF-8", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Label = "core\xff" }, ErrInvalidMetadata},
		{"trust generation zero", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.TrustGeneration = 0 }, ErrInvalidMetadata},
		{"trust generation out of range", func(m *DeviceMetadataRecord, _ *SpoolRef) {
			m.TrustGeneration = netdevcontract.MaxTrustGeneration + 1
		}, ErrInvalidMetadata},
		{"blocked device", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Blocked = true }, ErrBlockedDevice},
		{"block reason without block", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.BlockReason = "manual" }, ErrInvalidMetadata},
		{"bad spool name", func(_ *DeviceMetadataRecord, r *SpoolRef) { r.Name = "../x.json" }, ErrBadSpoolRef},
		{"record in the future", func(_ *DeviceMetadataRecord, r *SpoolRef) {
			r.RecordedAt = testBase.Add(time.Hour)
		}, ErrRecordedInFuture},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s, db, _ := newTestStore(t)
			m, ref := metaRecord(), testRef()
			tc.mutate(&m, &ref)
			err := s.UpsertDeviceMetadata(ctx, m, ref)
			if !errors.Is(err, tc.want) {
				t.Fatalf("UpsertDeviceMetadata: err %v, want %v", err, tc.want)
			}
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM netdev_devices_seen`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatalf("rejected record left %d device rows", n)
			}
		})
	}
}

// TestUpsertDeviceMetadataRefusesStaleAndForeignRecords: the trust generation
// may not go down, a record must be strictly newer at the same generation,
// and the family is immutable. A refusal leaves the stored row unchanged.
func TestUpsertDeviceMetadataRefusesStaleAndForeignRecords(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	d := cbsDevice()
	d.TrustGeneration = 3
	if err := s.UpsertDeviceReported(ctx, d, refAt(testBase.Add(-2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	stored, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}

	lower := metaRecord()
	lower.TrustGeneration = 2
	if err := s.UpsertDeviceMetadata(ctx, lower, refAt(testBase.Add(-time.Hour))); !errors.Is(err, ErrTrustGenerationRegressed) {
		t.Fatalf("lower generation: err %v, want ErrTrustGenerationRegressed", err)
	}

	same := metaRecord()
	same.TrustGeneration = 3
	if err := s.UpsertDeviceMetadata(ctx, same, refAt(testBase.Add(-2*time.Hour))); !errors.Is(err, ErrReportNotNewer) {
		t.Fatalf("equal record time: err %v, want ErrReportNotNewer", err)
	}
	if err := s.UpsertDeviceMetadata(ctx, same, refAt(testBase.Add(-3*time.Hour))); !errors.Is(err, ErrReportNotNewer) {
		t.Fatalf("older record time: err %v, want ErrReportNotNewer", err)
	}

	foreign := metaRecord()
	foreign.TrustGeneration = 4
	foreign.Family = netdevcontract.FamilyPANOS
	if err := s.UpsertDeviceMetadata(ctx, foreign, refAt(testBase.Add(-time.Hour))); !errors.Is(err, ErrFamilyChanged) {
		t.Fatalf("family change: err %v, want ErrFamilyChanged", err)
	}

	after, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if after.Label != stored.Label || after.TrustGeneration != stored.TrustGeneration || after.Spool != stored.Spool {
		t.Fatalf("refused records changed the row: before %+v after %+v", stored, after)
	}
}

// TestUpsertDeviceMetadataAcceptsNewerGeneration: a higher trust generation
// with a newer record is written, and the family stays as stored.
func TestUpsertDeviceMetadataAcceptsNewerGeneration(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())

	m := metaRecord()
	m.TrustGeneration = 2
	if err := s.UpsertDeviceMetadata(ctx, m, refAt(testBase.Add(-time.Minute))); err != nil {
		t.Fatalf("UpsertDeviceMetadata: %v", err)
	}
	d, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if d.TrustGeneration != 2 || d.Family != netdevcontract.FamilyCBS {
		t.Fatalf("row %+v, want generation 2 and family cbs", d)
	}
}
