// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"math"
	"testing"
	"time"
)

func TestSplitHoursSharesAddUp(t *testing.T) {
	from := time.Date(2026, 11, 5, 9, 50, 0, 0, time.UTC)
	to := from.Add(20 * time.Minute)
	parts := splitHours(from, to)
	if len(parts) != 2 {
		t.Fatalf("parts = %d, want 2", len(parts))
	}
	if !parts[0].start.Equal(time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)) || !parts[1].start.Equal(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("hours = %v %v", parts[0].start, parts[1].start)
	}
	for _, v := range []uint64{0, 1, 7, 1000, math.MaxUint64} {
		var sum uint64
		for _, p := range parts {
			sum += p.share(v)
		}
		if sum != v {
			t.Fatalf("shares of %d add up to %d", v, sum)
		}
	}
	if got := parts[0].share(1000); got != 500 {
		t.Fatalf("first half = %d, want 500", got)
	}
}

func TestSplitHoursEndOnBoundaryAndZeroLength(t *testing.T) {
	from := time.Date(2026, 11, 5, 9, 55, 0, 0, time.UTC)
	to := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	if parts := splitHours(from, to); len(parts) != 1 || parts[0].share(9) != 9 {
		t.Fatalf("boundary parts = %+v", parts)
	}
	if parts := splitHours(to, to); len(parts) != 1 || !parts[0].start.Equal(to) || parts[0].share(5) != 5 {
		t.Fatalf("zero-length parts = %+v", parts)
	}
}
