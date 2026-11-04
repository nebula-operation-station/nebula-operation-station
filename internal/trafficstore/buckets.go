// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Bucket is one reporter's observation of one flow in one hour.
type Bucket struct {
	// Hour is the hour the observation falls into; it is floored to the
	// hour start.
	Hour time.Time
	// Key is the flow key in flowagg canonical form (A < B).
	Key flowagg.FlowKey
	// Reporter is the host that reported the observation.
	Reporter string
	// ServerReported is set when the reporter is the server end of the
	// flow.
	ServerReported bool
	// BytesAB flows from A to B, BytesBA from B to A.
	BytesAB, BytesBA uint64
	// Connections counts sockets that started (or were reset) in the
	// hour.
	Connections uint64
	// LowerBound is set when the hour may miss bytes.
	LowerBound bool
}

// validKey revalidates a flow key in flowagg canonical form.
func validKey(k flowagg.FlowKey) error {
	a := k.A.Unmap().WithZone("")
	b := k.B.Unmap().WithZone("")
	switch {
	case !a.IsValid() || !b.IsValid():
		return errors.New("invalid endpoint")
	case a.IsUnspecified() || b.IsUnspecified() || a.IsLoopback() || b.IsLoopback():
		return errors.New("unspecified or loopback endpoint")
	case a.Compare(b) >= 0:
		return errors.New("endpoints not in canonical order")
	case k.Proto != flowagg.TCP && k.Proto != flowagg.UDP:
		return fmt.Errorf("unsupported protocol %d", uint8(k.Proto))
	case k.ServerPort == 0:
		return errors.New("server port 0")
	case k.Server != flowagg.SideA && k.Server != flowagg.SideB:
		return fmt.Errorf("invalid server side %d", uint8(k.Server))
	}
	if !validTier(k.Tier) {
		return fmt.Errorf("unknown tier %q", k.Tier)
	}
	return nil
}

func validateBucket(b *Bucket) error {
	if err := validKey(b.Key); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBucket, err)
	}
	if err := validName(b.Reporter, flowagg.MaxHostIDLen, false); err != nil {
		return fmt.Errorf("%w: reporter: %v", ErrInvalidBucket, err)
	}
	if b.Hour.IsZero() {
		return fmt.Errorf("%w: zero hour", ErrInvalidBucket)
	}
	if b.BytesAB > uint64(maxStoredCounter) || b.BytesBA > uint64(maxStoredCounter) || b.Connections > uint64(maxStoredCounter) {
		return fmt.Errorf("%w: counter exceeds the stored range", ErrInvalidBucket)
	}
	return nil
}

// UpsertBucket stores one reporter's observation of one flow in one
// hour.
//
// The row is keyed by (hour, key, reporter): repeated observations of
// the same tuple accumulate (a report interval can contribute several
// parts to one hour), counters saturate at the stored range, and
// lower_bound is ORed. The hour must lie within the retention window and
// not in the future.
//
// A new row is refused with ErrLimit when it would exceed MaxBuckets in
// total or MaxBucketsPerReporter for its reporter (ADR 0009 D7): existing
// rows keep accepting data and other reporters' rows are never evicted.
func (s *Store) UpsertBucket(ctx context.Context, b Bucket) error {
	if err := validateBucket(&b); err != nil {
		return err
	}
	now := s.now()
	hour := hourOf(b.Hour)
	cutoff := now.Add(-s.retention).Unix()
	if (hour+1)*secondsPerHour <= cutoff {
		return fmt.Errorf("%w: hour %s is older than the retention", ErrOutOfRange, b.Hour.UTC().Format(time.RFC3339))
	}
	if hour > hourOf(now) {
		return fmt.Errorf("%w: hour %s is in the future", ErrOutOfRange, b.Hour.UTC().Format(time.RFC3339))
	}

	s.autoPrune(ctx)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("trafficstore: begin upsert bucket: %w", err)
	}
	defer tx.Rollback()

	var exists int
	err = tx.QueryRowContext(ctx, `
		SELECT 1 FROM flow_buckets
		WHERE hour = ? AND a = ? AND b = ? AND proto = ? AND server_port = ?
		  AND server_side = ? AND tier = ? AND reporter = ?`,
		hour, b.Key.A.String(), b.Key.B.String(), int64(b.Key.Proto), int64(b.Key.ServerPort),
		int64(b.Key.Server), b.Key.Tier, b.Reporter).Scan(&exists)
	switch {
	case err == nil:
		// Existing row: it keeps accepting data (D7).
	case errors.Is(err, sql.ErrNoRows):
		var total, perReporter int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_buckets`).Scan(&total); err != nil {
			return fmt.Errorf("trafficstore: count buckets: %w", err)
		}
		if total >= s.bucketCap {
			return fmt.Errorf("%w: %d flow bucket rows held, limit %d", ErrLimit, total, s.bucketCap)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_buckets WHERE reporter = ?`, b.Reporter).Scan(&perReporter); err != nil {
			return fmt.Errorf("trafficstore: count buckets of reporter %s: %w", b.Reporter, err)
		}
		if perReporter >= s.bucketCapReporter {
			return fmt.Errorf("%w: reporter %s already has %d flow bucket rows, limit %d", ErrLimit, b.Reporter, perReporter, s.bucketCapReporter)
		}
	default:
		return fmt.Errorf("trafficstore: look up bucket: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier,
		                          bytes_ab, bytes_ba, connections, lower_bound, reporter, server_reported)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (hour, a, b, proto, server_port, server_side, tier, reporter)
		DO UPDATE SET
			bytes_ab        = CASE WHEN bytes_ab > `+fmt.Sprint(maxStoredCounter)+` - excluded.bytes_ab
			                    THEN `+fmt.Sprint(maxStoredCounter)+` ELSE bytes_ab + excluded.bytes_ab END,
			bytes_ba        = CASE WHEN bytes_ba > `+fmt.Sprint(maxStoredCounter)+` - excluded.bytes_ba
			                    THEN `+fmt.Sprint(maxStoredCounter)+` ELSE bytes_ba + excluded.bytes_ba END,
			connections    = CASE WHEN connections > `+fmt.Sprint(maxStoredCounter)+` - excluded.connections
			                     THEN `+fmt.Sprint(maxStoredCounter)+` ELSE connections + excluded.connections END,
			lower_bound     = CASE WHEN lower_bound = 1 OR excluded.lower_bound = 1 THEN 1 ELSE 0 END,
			server_reported = CASE WHEN server_reported = 1 OR excluded.server_reported = 1 THEN 1 ELSE 0 END`,
		hour, b.Key.A.String(), b.Key.B.String(), int64(b.Key.Proto), int64(b.Key.ServerPort),
		int64(b.Key.Server), b.Key.Tier,
		int64(b.BytesAB), int64(b.BytesBA), int64(b.Connections),
		boolInt(b.LowerBound), b.Reporter, boolInt(b.ServerReported)); err != nil {
		return fmt.Errorf("trafficstore: upsert bucket: %w", err)
	}
	return tx.Commit()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CountBuckets returns the number of stored flow bucket rows.
func (s *Store) CountBuckets(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_buckets`).Scan(&n); err != nil {
		return 0, fmt.Errorf("trafficstore: count buckets: %w", err)
	}
	return n, nil
}
