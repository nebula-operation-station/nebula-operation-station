// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// TestHitCountsEmptyWhenNoDataset: a device without a stored hit count read
// returns ErrDatasetNotFound, and so does an unknown device.
func TestHitCountsEmptyWhenNoDataset(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())

	if _, err := s.HitCounts(ctx, "fw-edge"); !errors.Is(err, ErrDatasetNotFound) {
		t.Fatalf("device without hit counts: err %v, want ErrDatasetNotFound", err)
	}
	if _, err := s.HitCounts(ctx, "fw-unknown"); !errors.Is(err, ErrDatasetNotFound) {
		t.Fatalf("unknown device: err %v, want ErrDatasetNotFound", err)
	}
}

// TestHitCountsOneDeviceReturnsStoredCounters: one stored read comes back in
// stored order with its counters and times. Absent times stay nil.
func TestHitCountsOneDeviceReturnsStoredCounters(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	first := testBase.Add(-48 * time.Hour).In(time.FixedZone("CET", 3600))
	last := testBase.Add(-time.Hour)
	mustReplace(t, s, "fw-edge", ReadHitCounts, testBase, false, HitCountRows{
		{RuleName: "allow-dns", Hits: 42, FirstHit: &first, LastHit: &last},
		{RuleName: "unused"},
	})

	got, err := s.HitCounts(ctx, "fw-edge")
	if err != nil {
		t.Fatalf("HitCounts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d hit counts, want 2: %+v", len(got), got)
	}
	a := got[0]
	if a.RuleName != "allow-dns" || a.Hits != 42 {
		t.Fatalf("first row %+v, want allow-dns with 42 hits", a)
	}
	if a.FirstHit == nil || !a.FirstHit.Equal(first) || a.FirstHit.Location() != time.UTC {
		t.Fatalf("first hit %v, want %v in UTC", a.FirstHit, first)
	}
	if a.LastHit == nil || !a.LastHit.Equal(last) {
		t.Fatalf("last hit %v, want %v", a.LastHit, last)
	}
	if a.ResetAt != nil {
		t.Fatalf("reset_at %v, want nil", a.ResetAt)
	}
	b := got[1]
	if b.RuleName != "unused" || b.Hits != 0 || b.FirstHit != nil || b.LastHit != nil {
		t.Fatalf("second row %+v, want unused with no times", b)
	}
}

// TestHitCountsLeavesOutRowsOfReplacedRead: a rule the newest complete read
// no longer contains is not returned.
func TestHitCountsLeavesOutRowsOfReplacedRead(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	mustReplace(t, s, "fw-edge", ReadHitCounts, testBase, false, HitCountRows{
		{RuleName: "old-rule", Hits: 1}, {RuleName: "kept", Hits: 2},
	})
	mustReplace(t, s, "fw-edge", ReadHitCounts, testBase.Add(time.Minute), false, HitCountRows{
		{RuleName: "kept", Hits: 3},
	})

	got, err := s.HitCounts(ctx, "fw-edge")
	if err != nil {
		t.Fatalf("HitCounts: %v", err)
	}
	if len(got) != 1 || got[0].RuleName != "kept" || got[0].Hits != 3 {
		t.Fatalf("HitCounts after replacement: %+v, want only kept with 3 hits", got)
	}
}

// TestHitCountsBoundedAtContractMaximum: a stored read at the contract
// maximum comes back whole, and a read above it is refused on write, so the
// read never returns more than MaxHitCountEntries rows.
func TestHitCountsBoundedAtContractMaximum(t *testing.T) {
	ctx := context.Background()
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())

	full := make(HitCountRows, netdevcontract.MaxHitCountEntries)
	for i := range full {
		full[i] = netdevcontract.HitCount{RuleName: fmt.Sprintf("rule-%05d", i), Hits: uint64(i)}
	}
	mustReplace(t, s, "fw-edge", ReadHitCounts, testBase, false, full)
	got, err := s.HitCounts(ctx, "fw-edge")
	if err != nil {
		t.Fatalf("HitCounts at maximum: %v", err)
	}
	if len(got) != netdevcontract.MaxHitCountEntries {
		t.Fatalf("HitCounts at maximum returned %d rows, want %d", len(got), netdevcontract.MaxHitCountEntries)
	}

	over := append(full, netdevcontract.HitCount{RuleName: "one-too-many"})
	d, err := s.GetDevice(ctx, "fw-edge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReplaceDataset(ctx, "fw-edge", ReadHitCounts, d.TrustGeneration, testBase.Add(time.Minute), false, over); err == nil {
		t.Fatalf("ReplaceDataset above the maximum succeeded, want an error")
	}
}
