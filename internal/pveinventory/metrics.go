// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Metric retention and server-side averages for PVE box metrics (ADR 0006,
// ticket P1-25; spec v2.3 12-inventory "Metric sources and retention").
//
// The collector spools fraction-valued box metrics (cpu, ram, disk in [0,1]).
// This package keeps exactly two bounded paths per series, never an unbounded
// raw history:
//
//   - a ring of 288 five-minute buckets (24 h) of (sum, count) aggregates,
//     used for server-side averages and coverage;
//   - one current row holding the most recent value (the live 10 s sample
//     shares the current 5-min bucket and updates this row).
//
// Averages are computed only from buckets that actually have samples; empty
// buckets are never filled with zero. Coverage reports how many of the 288
// buckets carry data, so a short history is never presented as a full-day
// average. All bucketing, windowing and age math is driven by the injected
// store clock (s.now), so behaviour is deterministic under test.

package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// BucketDuration is the width of one metric bucket (five minutes).
const BucketDuration = 5 * time.Minute

// RetentionBuckets is the number of five-minute buckets kept per series:
// 288 buckets is 24 hours of history.
const RetentionBuckets = 288

// MaxMetricBucketsQuery bounds a bucket query to the full retention window.
const MaxMetricBucketsQuery = RetentionBuckets

// MetricTargetKind distinguishes the two kinds of metric series.
type MetricTargetKind string

const (
	// MetricTargetNode is a series for one PVE node.
	MetricTargetNode MetricTargetKind = "node"
	// MetricTargetGuest is a series for one guest incarnation.
	MetricTargetGuest MetricTargetKind = "guest"
)

// MetricName names one bounded, fraction-valued box metric.
type MetricName string

const (
	// MetricCPU is the CPU utilisation fraction.
	MetricCPU MetricName = "cpu"
	// MetricRAM is the RAM utilisation fraction.
	MetricRAM MetricName = "ram"
	// MetricDisk is the disk utilisation fraction.
	MetricDisk MetricName = "disk"
)

// MetricTarget identifies one box series. For nodes, Node is set and
// VMID/Generation are zero; for guests, VMID and Generation (the incarnation)
// are set and Node is empty. A guest VMID reused after deletion is a new
// Generation and therefore a fresh series.
type MetricTarget struct {
	RemoteID   string
	Kind       MetricTargetKind
	Node       string
	VMID       uint64
	Generation uint64
}

// MetricSummary is the server-side 24 h aggregate for one target/metric.
// Valid is false when the window has no samples (missing, not zero).
type MetricSummary struct {
	Target       MetricTarget
	Metric       MetricName
	Valid        bool
	Average      float64 // mean over valid samples; 0 when !Valid
	Current      float64 // most recent value; 0 when never recorded
	CurrentAt    time.Time
	Samples      int // samples in the window
	BucketsValid int // 5-min buckets with at least one sample
	BucketsTotal int // always RetentionBuckets
	Coverage     float64
	Age          time.Duration // now - CurrentAt; 0 when never recorded
}

// MetricBucket is one five-minute bucket's aggregate.
type MetricBucket struct {
	Start   time.Time
	Average float64
	Count   int
}

// Sentinel errors for metric input validation (untrusted input from a
// managed host).
var (
	// ErrInvalidMetricTarget is returned for a malformed metric target.
	ErrInvalidMetricTarget = errors.New("pveinventory: invalid metric target")
	// ErrInvalidMetricName is returned for an unknown metric name.
	ErrInvalidMetricName = errors.New("pveinventory: invalid metric name")
	// ErrInvalidMetricValue is returned for a value outside [0,1] or not
	// finite.
	ErrInvalidMetricValue = errors.New("pveinventory: invalid metric value")
	// ErrInvalidMetricSource is returned for an oversized or non-UTF-8 source.
	ErrInvalidMetricSource = errors.New("pveinventory: invalid metric source")
)

// keyFields returns the storage key columns for a target.
func (t MetricTarget) keyFields() (kind, node string, vmid, generation uint64) {
	return string(t.Kind), t.Node, t.VMID, t.Generation
}

// validateTarget rejects malformed metric targets.
func validateTarget(t MetricTarget) error {
	if len(t.RemoteID) > pvecontract.MaxRemoteIDBytes || !utf8.ValidString(t.RemoteID) {
		return fmt.Errorf("%w: remote_id exceeds limit or is not UTF-8", ErrInvalidMetricTarget)
	}
	if len(t.Node) > pvecontract.MaxNodeNameBytes || !utf8.ValidString(t.Node) {
		return fmt.Errorf("%w: node exceeds limit or is not UTF-8", ErrInvalidMetricTarget)
	}
	if t.RemoteID == "" {
		return fmt.Errorf("%w: empty remote_id", ErrInvalidMetricTarget)
	}
	switch t.Kind {
	case MetricTargetNode:
		if t.Node == "" {
			return fmt.Errorf("%w: node target requires a node", ErrInvalidMetricTarget)
		}
		if t.VMID != 0 || t.Generation != 0 {
			return fmt.Errorf("%w: node target must not set vmid/generation", ErrInvalidMetricTarget)
		}
	case MetricTargetGuest:
		if t.VMID == 0 {
			return fmt.Errorf("%w: guest target requires a vmid", ErrInvalidMetricTarget)
		}
		if t.Generation == 0 {
			return fmt.Errorf("%w: guest target requires a generation", ErrInvalidMetricTarget)
		}
		if t.Node != "" {
			return fmt.Errorf("%w: guest target must not set a node", ErrInvalidMetricTarget)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidMetricTarget, t.Kind)
	}
	return nil
}

// validateMetric rejects unknown metric names.
func validateMetric(m MetricName) error {
	switch m {
	case MetricCPU, MetricRAM, MetricDisk:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidMetricName, m)
	}
}

// validateMetricValue rejects values that are not a finite fraction in [0,1].
func validateMetricValue(v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("%w: not finite", ErrInvalidMetricValue)
	}
	if v < 0 || v > 1 {
		return fmt.Errorf("%w: %g outside [0,1]", ErrInvalidMetricValue, v)
	}
	return nil
}

// windowStart returns the start of the oldest retained bucket as of now:
// the start of the bucket containing now, minus (RetentionBuckets-1) buckets.
func (s *Store) windowStart() (curStart, windowStart time.Time) {
	now := s.now()
	curStart = now.Truncate(BucketDuration)
	windowStart = curStart.Add(-time.Duration(RetentionBuckets-1) * BucketDuration)
	return curStart, windowStart
}

// RecordSample records one fraction-valued sample for a target/metric into
// the current five-minute bucket (and the current-value row). The sample is
// bucketed by the injected clock. It is idempotent per (series, bucket):
// repeated samples in the same bucket accumulate into the bucket aggregate.
func (s *Store) RecordSample(ctx context.Context, t MetricTarget, m MetricName, value float64, source string) error {
	if err := validateTarget(t); err != nil {
		return err
	}
	if err := validateMetric(m); err != nil {
		return err
	}
	if err := validateMetricValue(value); err != nil {
		return err
	}
	if len(source) > pvecontract.MaxTextFieldBytes || !utf8.ValidString(source) {
		return fmt.Errorf("%w: exceeds text limit or is not UTF-8", ErrInvalidMetricSource)
	}
	curStart, _ := s.windowStart()
	kind, node, vmid, generation := t.keyFields()
	bucketStartUnix := curStart.Unix()

	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
        INSERT INTO pve_metric_buckets
            (remote_id, target_kind, node, vmid, generation, metric, bucket_start_unix, sum, count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT (remote_id, target_kind, node, vmid, generation, metric, bucket_start_unix)
        DO UPDATE SET
            sum   = pve_metric_buckets.sum + excluded.sum,
            count = pve_metric_buckets.count + 1`,
			t.RemoteID, kind, node, vmid, generation, string(m), bucketStartUnix, value); err != nil {
			return fmt.Errorf("pveinventory: record sample %s/%s: %w", t.RemoteID, m, err)
		}

		observedAt := s.formatTime(s.now())
		if _, err := tx.ExecContext(ctx, `
        INSERT INTO pve_metric_current
            (remote_id, target_kind, node, vmid, generation, metric, value, observed_at, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (remote_id, target_kind, node, vmid, generation, metric)
        DO UPDATE SET
            value       = CASE WHEN excluded.observed_at >= pve_metric_current.observed_at
                               THEN excluded.value ELSE pve_metric_current.value END,
            observed_at = CASE WHEN excluded.observed_at >= pve_metric_current.observed_at
                               THEN excluded.observed_at ELSE pve_metric_current.observed_at END,
            source      = CASE WHEN excluded.observed_at >= pve_metric_current.observed_at
                               THEN excluded.source ELSE pve_metric_current.source END`,
			t.RemoteID, kind, node, vmid, generation, string(m), value, observedAt, source); err != nil {
			return fmt.Errorf("pveinventory: record current %s/%s: %w", t.RemoteID, m, err)
		}
		return nil
	})
}

// GetMetricSummary returns the server-side 24 h aggregate for one
// target/metric: the average over valid samples, the current value and its
// age, and the bucket coverage. A target/metric with no samples returns an
// invalid summary (missing, not zero) and no error.
func (s *Store) GetMetricSummary(ctx context.Context, t MetricTarget, m MetricName) (MetricSummary, error) {
	if err := validateTarget(t); err != nil {
		return MetricSummary{}, err
	}
	if err := validateMetric(m); err != nil {
		return MetricSummary{}, err
	}
	curStart, windowStart := s.windowStart()
	kind, node, vmid, generation := t.keyFields()
	windowStartUnix := windowStart.Unix()

	sum := MetricSummary{Target: t, Metric: m, BucketsTotal: RetentionBuckets}
	row := s.db.QueryRowContext(ctx, `
        SELECT COALESCE(SUM(sum), 0), COALESCE(SUM(count), 0), COUNT(*)
        FROM pve_metric_buckets
        WHERE remote_id = ? AND target_kind = ? AND node = ? AND vmid = ?
          AND generation = ? AND metric = ? AND bucket_start_unix >= ? AND bucket_start_unix <= ?`,
		t.RemoteID, kind, node, vmid, generation, string(m), windowStartUnix, curStart.Unix())
	var totalSum float64
	var totalSamples int64
	var bucketsValid int64
	if err := row.Scan(&totalSum, &totalSamples, &bucketsValid); err != nil {
		return MetricSummary{}, fmt.Errorf("pveinventory: summary %s/%s: %w", t.RemoteID, m, err)
	}
	sum.Samples = int(totalSamples)
	sum.BucketsValid = int(bucketsValid)
	if totalSamples > 0 {
		sum.Valid = true
		sum.Average = totalSum / float64(totalSamples)
	}
	sum.Coverage = float64(sum.BucketsValid) / float64(RetentionBuckets)

	crow := s.db.QueryRowContext(ctx, `
        SELECT value, observed_at
        FROM pve_metric_current
        WHERE remote_id = ? AND target_kind = ? AND node = ? AND vmid = ?
          AND generation = ? AND metric = ?`,
		t.RemoteID, kind, node, vmid, generation, string(m))
	var cval float64
	var cobs string
	if err := crow.Scan(&cval, &cobs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sum, nil
		}
		return MetricSummary{}, fmt.Errorf("pveinventory: summary current %s/%s: %w", t.RemoteID, m, err)
	}
	sum.Current = cval
	sum.CurrentAt, _ = time.Parse(time.RFC3339, cobs)
	sum.Age = s.age(sum.CurrentAt)
	return sum, nil
}

// ListMetricSummaries returns the summaries for all known metrics of a
// target in a stable order (cpu, ram, disk).
func (s *Store) ListMetricSummaries(ctx context.Context, t MetricTarget) ([]MetricSummary, error) {
	if err := validateTarget(t); err != nil {
		return nil, err
	}
	out := make([]MetricSummary, 0, 3)
	for _, m := range []MetricName{MetricCPU, MetricRAM, MetricDisk} {
		sum, err := s.GetMetricSummary(ctx, t, m)
		if err != nil {
			return nil, err
		}
		out = append(out, sum)
	}
	return out, nil
}

// GetMetricBuckets returns the five-minute bucket aggregates for a
// target/metric within the 24 h window, oldest first. A non-positive limit
// returns the whole window; a limit above MaxMetricBucketsQuery is an error.
// When the limit is smaller than the window, the newest buckets are kept.
func (s *Store) GetMetricBuckets(ctx context.Context, t MetricTarget, m MetricName, limit int) ([]MetricBucket, error) {
	if err := validateTarget(t); err != nil {
		return nil, err
	}
	if err := validateMetric(m); err != nil {
		return nil, err
	}
	limit, err := checkLimit(limit, MaxMetricBucketsQuery)
	if err != nil {
		return nil, err
	}
	curStart, windowStart := s.windowStart()
	kind, node, vmid, generation := t.keyFields()
	windowStartUnix := windowStart.Unix()

	var total int
	if err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(*)
        FROM pve_metric_buckets
        WHERE remote_id = ? AND target_kind = ? AND node = ? AND vmid = ?
          AND generation = ? AND metric = ? AND bucket_start_unix >= ? AND bucket_start_unix <= ?`,
		t.RemoteID, kind, node, vmid, generation, string(m), windowStartUnix, curStart.Unix()).Scan(&total); err != nil {
		return nil, fmt.Errorf("pveinventory: buckets count %s/%s: %w", t.RemoteID, m, err)
	}
	offset := 0
	if limit < total {
		offset = total - limit
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT bucket_start_unix, sum, count
        FROM pve_metric_buckets
        WHERE remote_id = ? AND target_kind = ? AND node = ? AND vmid = ?
          AND generation = ? AND metric = ? AND bucket_start_unix >= ? AND bucket_start_unix <= ?
        ORDER BY bucket_start_unix ASC
        LIMIT ? OFFSET ?`,
		t.RemoteID, kind, node, vmid, generation, string(m), windowStartUnix, curStart.Unix(), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: buckets %s/%s: %w", t.RemoteID, m, err)
	}
	defer rows.Close()

	out := make([]MetricBucket, 0, limit)
	for rows.Next() {
		var b MetricBucket
		var startUnix int64
		var bsum float64
		var bcount int64
		if err := rows.Scan(&startUnix, &bsum, &bcount); err != nil {
			return nil, fmt.Errorf("pveinventory: buckets %s/%s: %w", t.RemoteID, m, err)
		}
		b.Start = time.Unix(startUnix, 0).UTC()
		b.Count = int(bcount)
		if bcount > 0 {
			b.Average = bsum / float64(bcount)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pveinventory: buckets %s/%s: %w", t.RemoteID, m, err)
	}
	return out, nil
}

// PruneMetrics removes bucket rows older than the 24 h window and returns the
// number of rows removed. It retains current-value rows; Prune removes
// retired guest series when their incarnation tombstones expire.
func (s *Store) PruneMetrics(ctx context.Context) (int64, error) {
	_, windowStart := s.windowStart()
	res, err := s.db.ExecContext(ctx, `
        DELETE FROM pve_metric_buckets WHERE bucket_start_unix < ?`,
		windowStart.Unix())
	if err != nil {
		return 0, fmt.Errorf("pveinventory: prune metrics: %w", err)
	}
	return res.RowsAffected()
}
