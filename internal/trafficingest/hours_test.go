// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"math"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
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

// fuzzSeeds are shared starting points for the split fuzz targets: an
// empty interval, a full hour across the epoch, and a value at the top of
// the uint64 range.
var fuzzSeeds = []struct {
	fromNs, durNs int64
	v             uint64
}{
	{0, 0, 0},
	{1_700_000_000_000_000_000, int64(time.Hour), math.MaxUint64},
	{-1, 1, 1},
	{-int64(time.Hour), int64(time.Hour), math.MaxUint64},
	{int64(time.Hour) - 1, int64(time.Hour), 12345},
}

// fuzzInterval maps raw fuzz input to a report interval: from is any
// instant (before or after 1970, any nanosecond), and the length runs from
// zero up to flowagg.DefaultMaxInterval.
func fuzzInterval(fromNs, durNs int64) (from, to time.Time) {
	from = time.Unix(0, fromNs).UTC()
	d := time.Duration(uint64(durNs) % uint64(flowagg.DefaultMaxInterval+1))
	return from, from.Add(d)
}

// hourFloor returns the start of the UTC hour containing t. It is computed
// here independently of splitHours.
func hourFloor(t time.Time) time.Time {
	s := t.Unix() // floor for times before 1970; nanoseconds are never negative
	return time.Unix(s-((s%3600)+3600)%3600, 0).UTC()
}

// bigFloorMul returns floor(v*n/d) without overflow.
func bigFloorMul(v, n, d uint64) *big.Int {
	x := new(big.Int).Mul(new(big.Int).SetUint64(v), new(big.Int).SetUint64(n))
	return x.Quo(x, new(big.Int).SetUint64(d))
}

// sumShares adds the shares of v over parts exactly, without wrap-around.
func sumShares(parts []hourPart, v uint64) *big.Int {
	sum := new(big.Int)
	for _, p := range parts {
		sum.Add(sum, new(big.Int).SetUint64(p.share(v)))
	}
	return sum
}

// checkSplitInvariants checks splitHours(from, to) against an independent
// model of the split and checks that the shares of v add up to v exactly.
func checkSplitInvariants(t *testing.T, from, to time.Time, v uint64) {
	t.Helper()
	parts := splitHours(from, to)
	total := to.Sub(from)
	want := new(big.Int).SetUint64(v)
	if total <= 0 {
		if len(parts) != 1 || !parts[0].start.Equal(hourFloor(to)) {
			t.Fatalf("split %v..%v: parts %+v, want one part in the hour of to", from, to, parts)
		}
		if sumShares(parts, v).Cmp(want) != 0 {
			t.Fatalf("zero-length split %v..%v: shares of %d do not add up", from, to, v)
		}
		return
	}
	// ceil(total/1h)+1 parts at most; an interval that ends on a boundary
	// does not touch the following hour.
	const hourNs = int64(time.Hour)
	if maxParts := (int64(total)+hourNs-1)/hourNs + 1; int64(len(parts)) < 1 || int64(len(parts)) > maxParts {
		t.Fatalf("split %v..%v: %d parts, want 1..%d", from, to, len(parts), maxParts)
	}
	var done uint64
	hour := hourFloor(from)
	for i, p := range parts {
		if !p.start.Equal(hour) {
			t.Fatalf("split %v..%v: part %d starts %v, want hour %v", from, to, i, p.start, hour)
		}
		lo, hi := from, hour.Add(time.Hour)
		if hour.After(lo) {
			lo = hour
		}
		if to.Before(hi) {
			hi = to
		}
		seg := hi.Sub(lo)
		if seg <= 0 {
			t.Fatalf("split %v..%v: part %d covers no time", from, to, i)
		}
		if p.num != uint64(seg) || p.den != uint64(total) || p.done != done {
			t.Fatalf("split %v..%v: part %d = num %d den %d done %d, want num %d den %d done %d",
				from, to, i, p.num, p.den, p.done, seg, total, done)
		}
		// The share is the exact proportion of the interval up to this hour
		// minus the exact proportion up to the previous hour.
		wantShare := new(big.Int).Sub(bigFloorMul(v, done+p.num, uint64(total)), bigFloorMul(v, done, uint64(total)))
		if got := new(big.Int).SetUint64(p.share(v)); got.Cmp(wantShare) != 0 {
			t.Fatalf("split %v..%v: part %d share of %d = %s, want %s", from, to, i, v, got, wantShare)
		}
		done += p.num
		hour = hour.Add(time.Hour)
	}
	if done != uint64(total) {
		t.Fatalf("split %v..%v: parts cover %d ns of %d", from, to, done, total)
	}
	if sumShares(parts, v).Cmp(want) != 0 {
		t.Fatalf("split %v..%v: shares of %d do not add up to %d", from, to, v, v)
	}
}

// checkFlowaggSameHours reports one observation over [from, to) to
// flowagg.Aggregator through its exported API and checks that it puts
// exactly the bytes that splitHours assigns to each hour into that hour,
// and into no other hour.
func checkFlowaggSameHours(t *testing.T, from, to time.Time, ab, ba uint64) {
	t.Helper()
	key := flowagg.FlowKey{
		A: netip.MustParseAddr("10.0.0.1"), B: netip.MustParseAddr("10.0.0.2"),
		Proto: flowagg.TCP, ServerPort: 22, Server: flowagg.SideB, Tier: flowagg.TierSocket,
	}
	agg := flowagg.NewAggregator(flowagg.Limits{}, func() time.Time { return to })
	res, err := agg.Ingest(flowagg.Report{
		Host: "srv-b", Tier: flowagg.TierSocket, From: from, To: to,
		Observations: []flowagg.Observation{{Key: key, BytesAB: ab, BytesBA: ba, ServerReported: true}},
	}, []netip.Addr{key.B})
	if err != nil {
		t.Fatalf("ingest %v..%v: %v", from, to, err)
	}
	parts := splitHours(from, to)
	if res.Applied != len(parts) || agg.Buckets() != len(parts) {
		t.Fatalf("flowagg %v..%v: applied %d, buckets %d, want %d hours", from, to, res.Applied, agg.Buckets(), len(parts))
	}
	for _, p := range parts {
		got := agg.TopN(key.B, flowagg.Window{From: p.start, To: p.start.Add(time.Hour)}, 1)
		if len(got) != 1 {
			t.Fatalf("flowagg %v..%v: no bucket in hour %v", from, to, p.start)
		}
		if got[0].BytesAB != p.share(ab) || got[0].BytesBA != p.share(ba) {
			t.Fatalf("flowagg %v..%v: hour %v has %d/%d bytes, splitHours gives %d/%d",
				from, to, p.start, got[0].BytesAB, got[0].BytesBA, p.share(ab), p.share(ba))
		}
	}
}

// FuzzSplitHours checks the hourly split for any interval up to
// flowagg.DefaultMaxInterval and any value: the parts are contiguous, hour
// aligned and in order, their count is bounded, their shares add up to the
// value exactly, and flowagg places the same bytes in the same hours.
func FuzzSplitHours(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s.fromNs, s.durNs, s.v)
	}
	f.Fuzz(func(t *testing.T, fromNs, durNs int64, v uint64) {
		from, to := fuzzInterval(fromNs, durNs)
		checkSplitInvariants(t, from, to, v)
		checkFlowaggSameHours(t, from, to, v, ^v)
	})
}

// TestSplitHoursEdgeCases pins the boundary cases of the split: zero
// length, an end exactly on an hour boundary, an end before the start,
// the top of the uint64 range, and intervals across the epoch.
func TestSplitHoursEdgeCases(t *testing.T) {
	at := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return ts
	}
	cases := []struct {
		name      string
		from, to  time.Time
		wantParts int
	}{
		{"zero length mid hour", at("2026-11-05T09:30:00Z"), at("2026-11-05T09:30:00Z"), 1},
		{"zero length on boundary", at("2026-11-05T10:00:00Z"), at("2026-11-05T10:00:00Z"), 1},
		{"to exactly on boundary", at("2026-11-05T09:50:00Z"), at("2026-11-05T10:00:00Z"), 1},
		{"from and to on boundaries", at("2026-11-05T09:00:00Z"), at("2026-11-05T10:00:00Z"), 1},
		{"to before from", at("2026-11-05T10:00:00Z"), at("2026-11-05T09:30:00Z"), 1},
		{"one nanosecond across boundary", at("2026-11-05T09:59:59.999999999Z"), at("2026-11-05T10:00:00.000000001Z"), 2},
		{"full hour off boundary", at("2026-11-05T09:00:00.5Z"), at("2026-11-05T10:00:00.5Z"), 2},
		{"across the epoch", at("1969-12-31T23:30:00Z"), at("1970-01-01T00:30:00Z"), 2},
		{"before the epoch on boundary", at("1969-12-31T23:00:00Z"), at("1970-01-01T00:00:00Z"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parts := splitHours(tc.from, tc.to)
			if len(parts) != tc.wantParts {
				t.Fatalf("parts = %d, want %d", len(parts), tc.wantParts)
			}
			for _, v := range []uint64{0, 1, math.MaxUint64} {
				checkSplitInvariants(t, tc.from, tc.to, v)
			}
			if !tc.to.Before(tc.from) {
				checkFlowaggSameHours(t, tc.from, tc.to, math.MaxUint64, math.MaxUint64)
				checkFlowaggSameHours(t, tc.from, tc.to, 1, 0)
			}
		})
	}
}
