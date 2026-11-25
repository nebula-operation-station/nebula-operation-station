// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"slices"
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
// returns an error the caller can branch on. Label cases name each character
// under test by its code point in a comment; the bytes are the UTF-8 encoding.
func TestUpsertDeviceMetadataRefusesBadInput(t *testing.T) {
	long := strings.Repeat("x", netdevcontract.MaxLabelBytes+1)
	label := func(s string) func(*DeviceMetadataRecord, *SpoolRef) {
		return func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Label = s }
	}
	cases := []struct {
		name   string
		mutate func(*DeviceMetadataRecord, *SpoolRef)
		want   error
	}{
		{"empty device id", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.DeviceID = "" }, ErrInvalidMetadata},
		{"device id with slash", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.DeviceID = "sw/core" }, ErrInvalidMetadata},
		{"empty family", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Family = "" }, ErrInvalidMetadata},
		{"unknown family", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.Family = "junos" }, ErrInvalidMetadata},
		{"label too long", label(long), ErrInvalidMetadata},
		{"label with control character", label("core\x00"), ErrInvalidMetadata},
		{"label not UTF-8", label("core\xff"), ErrInvalidMetadata},
		// U+202E RIGHT-TO-LEFT OVERRIDE (format character, the bidi case the doc names)
		{"label with bidi override U+202E", label("core\xe2\x80\xae"), ErrInvalidMetadata},
		// U+200B ZERO WIDTH SPACE (format character)
		{"label with zero-width space U+200B", label("co\xe2\x80\x8bre"), ErrInvalidMetadata},
		// U+200E LEFT-TO-RIGHT MARK (format character)
		{"label with left-to-right mark U+200E", label("core\xe2\x80\x8e"), ErrInvalidMetadata},
		// U+2028 LINE SEPARATOR
		{"label with line separator U+2028", label("core\xe2\x80\xa8x"), ErrInvalidMetadata},
		// U+2029 PARAGRAPH SEPARATOR
		{"label with paragraph separator U+2029", label("core\xe2\x80\xa9x"), ErrInvalidMetadata},
		// U+E000 private use
		{"label with private use character U+E000", label("core\xee\x80\x80"), ErrInvalidMetadata},
		// U+FFFD REPLACEMENT CHARACTER
		{"label with replacement character U+FFFD", label("core\xef\xbf\xbd"), ErrInvalidMetadata},
		// U+0378 unassigned code point
		{"label with unassigned code point U+0378", label("core\xcd\xb8"), ErrInvalidMetadata},
		// U+00A0 NO-BREAK SPACE
		{"label with no-break space U+00A0", label("core\xc2\xa0x"), ErrInvalidMetadata},
		// U+3000 IDEOGRAPHIC SPACE
		{"label with ideographic space U+3000", label("core\xe3\x80\x80x"), ErrInvalidMetadata},
		{"trust generation zero", func(m *DeviceMetadataRecord, _ *SpoolRef) { m.TrustGeneration = 0 }, ErrInvalidMetadata},
		{"trust generation out of range", func(m *DeviceMetadataRecord, _ *SpoolRef) {
			m.TrustGeneration = netdevcontract.MaxTrustGeneration + 1
		}, ErrInvalidMetadata},
		{"block reason too long", func(m *DeviceMetadataRecord, _ *SpoolRef) {
			m.Blocked = true
			m.BlockReason = strings.Repeat("r", MaxBlockReasonBytes+1)
		}, ErrInvalidMetadata},
		{"block reason with control character", func(m *DeviceMetadataRecord, _ *SpoolRef) {
			m.Blocked = true
			m.BlockReason = "op\x07"
		}, ErrInvalidMetadata},
		// U+202E RIGHT-TO-LEFT OVERRIDE
		{"block reason with bidi override", func(m *DeviceMetadataRecord, _ *SpoolRef) {
			m.Blocked = true
			m.BlockReason = "op\xe2\x80\xae"
		}, ErrInvalidMetadata},
		{"block reason not UTF-8", func(m *DeviceMetadataRecord, _ *SpoolRef) {
			m.Blocked = true
			m.BlockReason = "op\xff"
		}, ErrInvalidMetadata},
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

// TestUpsertDeviceMetadataBlockedMarksRow: a blocked record is written and
// marks the stored row blocked with its reason, so the device list shows the
// block and BlockedDeviceIDs names the device. A newer unblocked record
// clears the block.
func TestUpsertDeviceMetadataBlockedMarksRow(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())

	m := metaRecord()
	m.TrustGeneration = 2
	m.Label = "Blocked core"
	m.Blocked = true
	m.BlockReason = "manual"
	if err := s.UpsertDeviceMetadata(ctx, m, refAt(testBase.Add(time.Minute))); err != nil {
		t.Fatalf("blocked record: %v", err)
	}
	after, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !after.Blocked || after.BlockReason != "manual" || after.Label != "Blocked core" {
		t.Fatalf("row %+v, want blocked with reason manual and the new label", after)
	}
	listed, err := s.ListDevices(ctx, MaxListDevices)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || !listed[0].Blocked || listed[0].BlockReason != "manual" {
		t.Fatalf("ListDevices = %+v, want the row blocked", listed)
	}
	ids, err := s.BlockedDeviceIDs(ctx)
	if err != nil || !slices.Equal(ids, []string{"sw-core"}) {
		t.Fatalf("BlockedDeviceIDs = %v, %v; want [sw-core]", ids, err)
	}

	m.Blocked, m.BlockReason = false, ""
	if err := s.UpsertDeviceMetadata(ctx, m, refAt(testBase.Add(2*time.Minute))); err != nil {
		t.Fatalf("unblocked record: %v", err)
	}
	after, err = s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if after.Blocked || after.BlockReason != "" {
		t.Fatalf("row %+v, want the block cleared", after)
	}
	if ids, err := s.BlockedDeviceIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("BlockedDeviceIDs = %v, %v; want none", ids, err)
	}
}

// TestUpsertDeviceMetadataBlockedNewDevice: a blocked record of a device with
// no row creates the row already blocked; it is never shown unblocked.
func TestUpsertDeviceMetadataBlockedNewDevice(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	m := metaRecord()
	m.Blocked = true
	if err := s.UpsertDeviceMetadata(ctx, m, testRef()); err != nil {
		t.Fatalf("blocked record: %v", err)
	}
	d, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Blocked || d.BlockReason != "" {
		t.Fatalf("row %+v, want blocked with an empty reason", d)
	}
}

// TestUpsertDeviceReportedKeepsBlock: the contract-device writer has no block
// field, so it never lifts a block the metadata writer set.
func TestUpsertDeviceReportedKeepsBlock(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	m := metaRecord()
	m.Blocked, m.BlockReason = true, "manual"
	if err := s.UpsertDeviceMetadata(ctx, m, refAt(testBase.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	d := cbsDevice()
	d.TrustGeneration = 2
	if err := s.UpsertDeviceReported(ctx, d, refAt(testBase.Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "sw-core")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Blocked || got.BlockReason != "manual" {
		t.Fatalf("row %+v, want the block kept", got)
	}
}

// TestBlockColumnsRefuseInconsistentRow: migration 0059 ties block_reason to
// blocked, so a direct write cannot store a reason without a block or a block
// without a reason column value.
func TestBlockColumnsRefuseInconsistentRow(t *testing.T) {
	ctx := context.Background()
	s, db, _ := newTestStore(t)
	if err := s.UpsertDeviceMetadata(ctx, metaRecord(), testRef()); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE netdev_devices_seen SET block_reason = 'x'`,
		`UPDATE netdev_devices_seen SET blocked = 1`,
		`UPDATE netdev_devices_seen SET blocked = 2, block_reason = 'x'`,
		`UPDATE netdev_devices_seen SET blocked = 1, block_reason = '` + strings.Repeat("r", MaxBlockReasonBytes+1) + `'`,
	} {
		if _, err := db.ExecContext(ctx, q); err == nil {
			t.Errorf("%.60s: accepted, want a CHECK failure", q)
		}
	}
}

// TestValidLabelMatchesContractText: validLabel accepts exactly the labels
// the netdevcontract device rule accepts for the same column, checked rune
// by rune against netdevcontract.ValidateDevice, so the two cannot drift.
// Runes are given as code points so that the source stays ASCII.
func TestValidLabelMatchesContractText(t *testing.T) {
	runes := []rune{
		0x61, 0x20, 0x09, 0x0a, 0x00, 0x7f, 0x80, 0xa0, 0xad, 0x378,
		0x200b, 0x200e, 0x202e, 0x2028, 0x2029, 0x3000, 0xfeff,
		0xe000, 0xf0000, 0xd7ff, 0xfffd, 0x1f600, 0xe9,
	}
	for _, r := range runes {
		label := "a" + string(r) + "b"
		d := cbsDevice()
		d.Name = label
		_, contractErr := netdevcontract.ValidateDevice(d)
		contractOK := contractErr == nil
		if got := validLabel(label); got != contractOK {
			t.Errorf("rune %#U: validLabel %v, contract accepts %v", r, got, contractOK)
		}
	}
}
