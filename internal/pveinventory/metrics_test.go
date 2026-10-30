// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for PVE metric retention and server-side averages (ADR 0006,
// ticket P1-25; spec v2.3 12-inventory "Metric sources and retention").
//
// They cover the P1-25 acceptance criteria with an injected clock:
//   - 288 five-minute buckets per metric per box (24 h) and a sliding window;
//   - server-side averages computed from valid collected buckets only;
//   - coverage reported, so a short history is never a full-day average;
//   - missing samples are never treated as zero;
//   - live (10 s) values share the same 5-min bucket and update the current
//     value, never an unbounded raw history;
//   - retention prunes buckets older than 24 h;
//   - an identity/generation (incarnation) change starts a new series;
//   - node vs guest and cross-target isolation;
//   - rejection of malformed targets, metric names and values.

package pveinventory

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

// approxEqual reports whether a and b are equal within a small epsilon.
func approxEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func nodeTarget() MetricTarget {
	return MetricTarget{RemoteID: "remote-a", Kind: MetricTargetNode, Node: "p1"}
}

func guestTarget(gen uint64) MetricTarget {
	return MetricTarget{RemoteID: "remote-a", Kind: MetricTargetGuest, VMID: 101, Generation: gen}
}

// TestRecordSampleAndSummary records one sample and checks the summary
// reflects it (valid, average, current, samples, one valid bucket).
func TestRecordSampleAndSummary(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()

	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.25, "test-collector"); err != nil {
		t.Fatalf("record sample: %v", err)
	}

	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if !sum.Valid {
		t.Fatalf("expected valid summary, got %+v", sum)
	}
	if !approxEqual(sum.Average, 0.25) {
		t.Errorf("average = %v, want 0.25", sum.Average)
	}
	if !approxEqual(sum.Current, 0.25) {
		t.Errorf("current = %v, want 0.25", sum.Current)
	}
	if sum.Samples != 1 {
		t.Errorf("samples = %d, want 1", sum.Samples)
	}
	if sum.BucketsValid != 1 {
		t.Errorf("buckets valid = %d, want 1", sum.BucketsValid)
	}
	if sum.BucketsTotal != RetentionBuckets {
		t.Errorf("buckets total = %d, want %d", sum.BucketsTotal, RetentionBuckets)
	}
	if !approxEqual(sum.Coverage, 1.0/RetentionBuckets) {
		t.Errorf("coverage = %v, want %v", sum.Coverage, 1.0/RetentionBuckets)
	}
	if !sum.CurrentAt.Equal(*now) {
		t.Errorf("current at = %v, want %v", sum.CurrentAt, *now)
	}
	if sum.Age != 0 {
		t.Errorf("age = %v, want 0", sum.Age)
	}
}

// TestMissingSamplesNotZero records a single max sample and checks the
// average is that sample (not diluted by the 287 empty buckets) and the
// coverage is tiny. Missing samples must never be filled with zero.
func TestMissingSamplesNotZero(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.RecordSample(ctx, nodeTarget(), MetricRAM, 1.0, "c"); err != nil {
		t.Fatalf("record: %v", err)
	}
	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricRAM)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if !approxEqual(sum.Average, 1.0) {
		t.Errorf("average = %v, want 1.0 (missing buckets must not zero-fill)", sum.Average)
	}
	if sum.BucketsValid != 1 {
		t.Errorf("buckets valid = %d, want 1", sum.BucketsValid)
	}
	if !approxEqual(sum.Coverage, 1.0/RetentionBuckets) {
		t.Errorf("coverage = %v, want 1/%d", sum.Coverage, RetentionBuckets)
	}
}

// TestNoDataSummary checks that a target/metric with no samples yields an
// invalid summary (missing, not zero) and no error.
func TestNoDataSummary(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricDisk)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Valid {
		t.Errorf("expected invalid (no data) summary, got %+v", sum)
	}
	if sum.Average != 0 || sum.Samples != 0 || sum.BucketsValid != 0 {
		t.Errorf("expected zeroed aggregates, got %+v", sum)
	}
	if !approxEqual(sum.Coverage, 0) {
		t.Errorf("coverage = %v, want 0", sum.Coverage)
	}
}

// TestAgeGrowsWithClock records a sample, advances the injected clock, and
// checks the current value's age tracks the clock.
func TestAgeGrowsWithClock(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()

	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.5, "c"); err != nil {
		t.Fatalf("record: %v", err)
	}
	*now = now.Add(time.Hour)
	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Age != time.Hour {
		t.Errorf("age = %v, want 1h", sum.Age)
	}
}

// TestLiveSharesBucket records a 5-min history sample and a 10 s live sample
// in the same bucket and checks they share the bucket (count 2) and the live
// sample becomes the current value.
func TestLiveSharesBucket(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()

	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.5, "history"); err != nil {
		t.Fatalf("record history: %v", err)
	}
	*now = now.Add(10 * time.Second) // still inside the same 5-min bucket
	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.6, "live"); err != nil {
		t.Fatalf("record live: %v", err)
	}

	buckets, err := s.GetMetricBuckets(ctx, nodeTarget(), MetricCPU, 0)
	if err != nil {
		t.Fatalf("buckets: %v", err)
	}
	if len(buckets) != 1 {
		t.Fatalf("buckets = %d, want 1 (live and history share one bucket)", len(buckets))
	}
	if buckets[0].Count != 2 {
		t.Errorf("bucket count = %d, want 2", buckets[0].Count)
	}
	if !approxEqual(buckets[0].Average, 0.55) {
		t.Errorf("bucket average = %v, want 0.55", buckets[0].Average)
	}

	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if !approxEqual(sum.Current, 0.6) {
		t.Errorf("current = %v, want 0.6 (live value wins)", sum.Current)
	}
	if sum.Samples != 2 {
		t.Errorf("samples = %d, want 2", sum.Samples)
	}
}

// Test288BucketsAndSlidingWindow fills one sample per 5-min bucket for 24 h
// (288 buckets), checks full coverage, then adds a 289th sample and checks
// the window slides (oldest bucket excluded from the average) and pruning
// removes exactly the out-of-window bucket.
func Test288BucketsAndSlidingWindow(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	base := *now

	// Fill 288 buckets with values 1..288 (one per 5-min step).
	for i := 0; i < RetentionBuckets; i++ {
		*now = base.Add(time.Duration(i) * BucketDuration)
		if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, float64(i+1), "c"); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	var fullSum float64
	for i := 1; i <= RetentionBuckets; i++ {
		fullSum += float64(i)
	}
	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.BucketsValid != RetentionBuckets {
		t.Errorf("buckets valid = %d, want %d", sum.BucketsValid, RetentionBuckets)
	}
	if !approxEqual(sum.Coverage, 1.0) {
		t.Errorf("coverage = %v, want 1.0", sum.Coverage)
	}
	if sum.Samples != RetentionBuckets {
		t.Errorf("samples = %d, want %d", sum.Samples, RetentionBuckets)
	}
	if !approxEqual(sum.Average, fullSum/RetentionBuckets) {
		t.Errorf("average = %v, want %v", sum.Average, fullSum/RetentionBuckets)
	}

	// A 289th sample slides the window: the oldest bucket (value 1) drops
	// out of the 24 h window.
	*now = base.Add(RetentionBuckets * BucketDuration)
	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 999, "c"); err != nil {
		t.Fatalf("record 289: %v", err)
	}
	var slideSum float64
	for i := 2; i <= RetentionBuckets; i++ {
		slideSum += float64(i)
	}
	slideSum += 999
	sum, err = s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("summary after slide: %v", err)
	}
	if sum.BucketsValid != RetentionBuckets {
		t.Errorf("buckets valid after slide = %d, want %d", sum.BucketsValid, RetentionBuckets)
	}
	if sum.Samples != RetentionBuckets {
		t.Errorf("samples after slide = %d, want %d (oldest excluded)", sum.Samples, RetentionBuckets)
	}
	if !approxEqual(sum.Average, slideSum/RetentionBuckets) {
		t.Errorf("average after slide = %v, want %v", sum.Average, slideSum/RetentionBuckets)
	}

	// Pruning removes exactly the out-of-window bucket.
	n, err := s.PruneMetrics(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
}

// TestPruneMetrics removes buckets older than 24 h using the injected clock.
func TestPruneMetrics(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	base := *now

	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.3, "c"); err != nil {
		t.Fatalf("record: %v", err)
	}
	*now = base.Add(25 * time.Hour) // the sample's bucket is now out of window
	n, err := s.PruneMetrics(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	sum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Valid {
		t.Errorf("expected invalid summary after prune, got %+v", sum)
	}
	// The current value row is retained (it is bounded, not raw history);
	// its age now reflects the 25 h gap.
	if sum.Age != 25*time.Hour {
		t.Errorf("current age = %v, want 25h", sum.Age)
	}
}

// TestIncarnationReset checks that a new guest generation starts a fresh
// series: no carry-over from the old incarnation, and the old series is
// unchanged.
func TestIncarnationReset(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	base := *now

	// Old incarnation (generation 1): three buckets, values 0.1/0.2/0.3.
	for i, v := range []float64{0.1, 0.2, 0.3} {
		*now = base.Add(time.Duration(i) * BucketDuration)
		if err := s.RecordSample(ctx, guestTarget(1), MetricRAM, v, "c"); err != nil {
			t.Fatalf("record gen1 %d: %v", i, err)
		}
	}
	gen1, err := s.GetMetricSummary(ctx, guestTarget(1), MetricRAM)
	if err != nil {
		t.Fatalf("summary gen1: %v", err)
	}
	if !approxEqual(gen1.Average, 0.2) || gen1.BucketsValid != 3 {
		t.Fatalf("gen1 summary = %+v, want average 0.2 / 3 buckets", gen1)
	}

	// New incarnation (generation 2): a single sample. It must be an
	// independent series, not merged with generation 1.
	*now = base.Add(3 * BucketDuration)
	if err := s.RecordSample(ctx, guestTarget(2), MetricRAM, 0.9, "c"); err != nil {
		t.Fatalf("record gen2: %v", err)
	}
	gen2, err := s.GetMetricSummary(ctx, guestTarget(2), MetricRAM)
	if err != nil {
		t.Fatalf("summary gen2: %v", err)
	}
	if !approxEqual(gen2.Average, 0.9) || gen2.BucketsValid != 1 || gen2.Samples != 1 {
		t.Errorf("gen2 summary = %+v, want average 0.9 / 1 bucket / 1 sample", gen2)
	}

	// The old incarnation is unchanged (no carry-over either direction).
	again, err := s.GetMetricSummary(ctx, guestTarget(1), MetricRAM)
	if err != nil {
		t.Fatalf("summary gen1 again: %v", err)
	}
	if !approxEqual(again.Average, 0.2) || again.BucketsValid != 3 {
		t.Errorf("gen1 after gen2 = %+v, want unchanged (average 0.2 / 3 buckets)", again)
	}
}

// TestTargetIsolation checks that node and guest series (and different
// remotes) never share buckets.
func TestTargetIsolation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.1, "c"); err != nil {
		t.Fatalf("record node: %v", err)
	}
	// A guest with the same metric must be a separate series.
	if err := s.RecordSample(ctx, guestTarget(1), MetricCPU, 0.8, "c"); err != nil {
		t.Fatalf("record guest: %v", err)
	}
	nodeSum, err := s.GetMetricSummary(ctx, nodeTarget(), MetricCPU)
	if err != nil {
		t.Fatalf("node summary: %v", err)
	}
	guestSum, err := s.GetMetricSummary(ctx, guestTarget(1), MetricCPU)
	if err != nil {
		t.Fatalf("guest summary: %v", err)
	}
	if !approxEqual(nodeSum.Average, 0.1) || !approxEqual(guestSum.Average, 0.8) {
		t.Errorf("node/guest averages = %v/%v, want 0.1/0.8 (isolated)", nodeSum.Average, guestSum.Average)
	}

	// A different remote with the same node name is also isolated.
	other := MetricTarget{RemoteID: "remote-b", Kind: MetricTargetNode, Node: "p1"}
	if err := s.RecordSample(ctx, other, MetricCPU, 0.5, "c"); err != nil {
		t.Fatalf("record other remote: %v", err)
	}
	otherSum, err := s.GetMetricSummary(ctx, other, MetricCPU)
	if err != nil {
		t.Fatalf("other summary: %v", err)
	}
	if !approxEqual(otherSum.Average, 0.5) || !approxEqual(nodeSum.Average, 0.1) {
		t.Errorf("cross-remote averages leaked: %v vs %v", otherSum.Average, nodeSum.Average)
	}
}

// TestListMetricSummaries returns all known metrics for a target in a stable
// order, with unrecorded metrics reported as invalid (not zero-filled).
func TestListMetricSummaries(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, 0.4, "c"); err != nil {
		t.Fatalf("record cpu: %v", err)
	}
	if err := s.RecordSample(ctx, nodeTarget(), MetricRAM, 0.6, "c"); err != nil {
		t.Fatalf("record ram: %v", err)
	}
	out, err := s.ListMetricSummaries(ctx, nodeTarget())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	wantOrder := []MetricName{MetricCPU, MetricRAM, MetricDisk}
	for i, m := range wantOrder {
		if out[i].Metric != m {
			t.Errorf("order[%d] = %v, want %v", i, out[i].Metric, m)
		}
	}
	if !out[0].Valid || !out[1].Valid || out[2].Valid {
		t.Errorf("validity = [%v %v %v], want [true true false]", out[0].Valid, out[1].Valid, out[2].Valid)
	}
	if !approxEqual(out[0].Average, 0.4) || !approxEqual(out[1].Average, 0.6) {
		t.Errorf("averages = %v/%v, want 0.4/0.6", out[0].Average, out[1].Average)
	}
}

// TestGetMetricBucketsLimit bounds the bucket query and returns the newest
// buckets when the limit is smaller than the window.
func TestGetMetricBucketsLimit(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	base := *now

	for i := 0; i < 5; i++ {
		*now = base.Add(time.Duration(i) * BucketDuration)
		if err := s.RecordSample(ctx, nodeTarget(), MetricCPU, float64(i), "c"); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	all, err := s.GetMetricBuckets(ctx, nodeTarget(), MetricCPU, 0)
	if err != nil {
		t.Fatalf("all buckets: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("all = %d, want 5", len(all))
	}
	// Oldest first.
	for i := 1; i < len(all); i++ {
		if !all[i].Start.After(all[i-1].Start) {
			t.Fatalf("buckets not ordered oldest-first at %d", i)
		}
	}
	limited, err := s.GetMetricBuckets(ctx, nodeTarget(), MetricCPU, 3)
	if err != nil {
		t.Fatalf("limited buckets: %v", err)
	}
	if len(limited) != 3 {
		t.Fatalf("limited = %d, want 3", len(limited))
	}
	// The newest three are the last three of the full list.
	for i := 0; i < 3; i++ {
		if !limited[i].Start.Equal(all[len(all)-3+i].Start) {
			t.Errorf("limited[%d] start = %v, want %v (newest kept)", i, limited[i].Start, all[len(all)-3+i].Start)
		}
	}
	if _, err := s.GetMetricBuckets(ctx, nodeTarget(), MetricCPU, MaxMetricBucketsQuery+1); err == nil {
		t.Errorf("limit above max must be rejected")
	}
}

// TestRecordSampleValidation rejects malformed targets, metric names and
// values (security-relevant rejections of untrusted input).
func TestRecordSampleValidation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		target  MetricTarget
		metric  MetricName
		value   float64
		wantErr error
	}{
		{"empty remote", MetricTarget{Kind: MetricTargetNode, Node: "p1"}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"node empty name", MetricTarget{RemoteID: "r", Kind: MetricTargetNode}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"node with vmid", MetricTarget{RemoteID: "r", Kind: MetricTargetNode, Node: "p1", VMID: 1}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"guest empty vmid", MetricTarget{RemoteID: "r", Kind: MetricTargetGuest, Generation: 1}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"guest empty generation", MetricTarget{RemoteID: "r", Kind: MetricTargetGuest, VMID: 1}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"guest with node", MetricTarget{RemoteID: "r", Kind: MetricTargetGuest, Node: "p1", VMID: 1, Generation: 1}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"unknown kind", MetricTarget{RemoteID: "r", Kind: "host"}, MetricCPU, 0.5, ErrInvalidMetricTarget},
		{"unknown metric", nodeTarget(), MetricName("net"), 0.5, ErrInvalidMetricName},
		{"empty metric", nodeTarget(), MetricName(""), 0.5, ErrInvalidMetricName},
		{"nan value", nodeTarget(), MetricCPU, math.NaN(), ErrInvalidMetricValue},
		{"inf value", nodeTarget(), MetricCPU, math.Inf(1), ErrInvalidMetricValue},
		{"negative value", nodeTarget(), MetricCPU, -0.1, ErrInvalidMetricValue},
		{"above one", nodeTarget(), MetricCPU, 1.1, ErrInvalidMetricValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.RecordSample(ctx, tc.target, tc.metric, tc.value, "c")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("RecordSample err = %v, want %v", err, tc.wantErr)
			}
		})
	}

	// Boundary values are accepted.
	for _, v := range []float64{0, 1} {
		if err := s.RecordSample(ctx, nodeTarget(), MetricDisk, v, "c"); err != nil {
			t.Errorf("value %v must be accepted, got %v", v, err)
		}
	}
}

// TestSummaryValidation rejects malformed targets and metric names on the
// read path as well.
func TestSummaryValidation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if _, err := s.GetMetricSummary(ctx, MetricTarget{Kind: MetricTargetNode}, MetricCPU); !errors.Is(err, ErrInvalidMetricTarget) {
		t.Errorf("summary target err = %v, want ErrInvalidMetricTarget", err)
	}
	if _, err := s.GetMetricSummary(ctx, nodeTarget(), MetricName("bogus")); !errors.Is(err, ErrInvalidMetricName) {
		t.Errorf("summary metric err = %v, want ErrInvalidMetricName", err)
	}
	if _, err := s.ListMetricSummaries(ctx, MetricTarget{Kind: MetricTargetGuest}); !errors.Is(err, ErrInvalidMetricTarget) {
		t.Errorf("list target err = %v, want ErrInvalidMetricTarget", err)
	}
	if _, err := s.GetMetricBuckets(ctx, MetricTarget{Kind: MetricTargetNode}, MetricCPU, 0); !errors.Is(err, ErrInvalidMetricTarget) {
		t.Errorf("buckets target err = %v, want ErrInvalidMetricTarget", err)
	}
}
