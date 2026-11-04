// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Bucket is one reporter's observation of one flow in one hour.
type Bucket struct {
	// Hour is the hour the observation falls into; it is floored to the
	// hour start.
	Hour time.Time
	// Key is the flow key in flowagg canonical form: A < B, both
	// normalized (no zone, no IPv4-mapped IPv6), as flowagg produces it.
	Key flowagg.FlowKey
	// Reporter is the host that reported the observation.
	Reporter string
	// ServerReported is set when the reporter is the server end of the
	// flow; otherwise the reporter is the client end.
	ServerReported bool
	// BytesAB flows from A to B, BytesBA from B to A. Values above the
	// stored range saturate.
	BytesAB, BytesBA uint64
	// Connections counts sockets that started (or were reset) in the
	// hour.
	Connections uint64
	// LowerBound is set when the hour may miss bytes.
	LowerBound bool
}

// validKeyAddr checks one flow key end: valid, already normalized and
// neither unspecified nor loopback. A zone or an IPv4-mapped form is
// refused instead of normalized, as in flowagg: the store keeps exactly
// the value it validated, and stripping a zone could merge link-local
// flows of different links.
func validKeyAddr(a netip.Addr) error {
	switch {
	case !a.IsValid():
		return errors.New("invalid endpoint")
	case a.Zone() != "" || a.Is4In6():
		return errors.New("endpoint not normalized")
	case a.IsUnspecified() || a.IsLoopback():
		return errors.New("unspecified or loopback endpoint")
	}
	return nil
}

// validKey revalidates a flow key in flowagg canonical form.
func validKey(k flowagg.FlowKey) error {
	if err := validKeyAddr(k.A); err != nil {
		return fmt.Errorf("a: %w", err)
	}
	if err := validKeyAddr(k.B); err != nil {
		return fmt.Errorf("b: %w", err)
	}
	switch {
	case k.A.Compare(k.B) >= 0:
		return errors.New("endpoints not in canonical order")
	case k.Proto != flowagg.TCP && k.Proto != flowagg.UDP:
		return fmt.Errorf("unsupported protocol %d", uint8(k.Proto))
	case k.ServerPort == 0:
		return errors.New("server port 0")
	case k.Server != flowagg.SideA && k.Server != flowagg.SideB:
		return fmt.Errorf("invalid server side %d", uint8(k.Server))
	case !validTier(k.Tier):
		return fmt.Errorf("unknown tier %q", k.Tier)
	}
	return nil
}

// claimedEnd returns the address of the flow end the observation claims
// for its reporter: the server end when ServerReported, otherwise the
// client end (flowagg's reporterEnd).
func claimedEnd(b *Bucket) netip.Addr {
	server := b.Key.ServerAddr()
	if b.ServerReported {
		return server
	}
	if server == b.Key.A {
		return b.Key.B
	}
	return b.Key.A
}

// ownsEnd validates own (as flowagg.Aggregator.Ingest does) and reports
// whether end is one of the addresses.
func ownsEnd(own []netip.Addr, end netip.Addr) (bool, error) {
	if len(own) == 0 {
		return false, errors.New("no reporter addresses")
	}
	if len(own) > flowagg.MaxHostAddrs {
		return false, fmt.Errorf("%d reporter addresses exceed limit %d", len(own), flowagg.MaxHostAddrs)
	}
	found := false
	for i, a := range own {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() {
			return false, fmt.Errorf("reporter address %d invalid", i)
		}
		if a == end {
			found = true
		}
	}
	return found, nil
}

func clampCounter(v uint64) int64 {
	if v > uint64(maxStoredCounter) {
		return maxStoredCounter
	}
	return int64(v)
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
	return nil
}

// upsertBucketSQL adds to an existing row, saturating each counter at
// maxStoredCounter.
var upsertBucketSQL = fmt.Sprintf(`
	UPDATE flow_buckets SET
		bytes_ab    = CASE WHEN bytes_ab > %[1]d - ?1 THEN %[1]d ELSE bytes_ab + ?1 END,
		bytes_ba    = CASE WHEN bytes_ba > %[1]d - ?2 THEN %[1]d ELSE bytes_ba + ?2 END,
		connections = CASE WHEN connections > %[1]d - ?3 THEN %[1]d ELSE connections + ?3 END,
		lower_bound = MAX(lower_bound, ?4)
	WHERE hour = ?5 AND a = ?6 AND b = ?7 AND proto = ?8 AND server_port = ?9
	  AND server_side = ?10 AND tier = ?11 AND server_reported = ?12`, maxStoredCounter)

// UpsertBucket stores one reporter's observation of one flow in one
// hour.
//
// own lists the addresses of the reporting host b.Reporter. As for
// flowagg.Aggregator.Ingest, the caller takes them from the server's own
// records of that managed host, never from the report, and leaves out
// addresses more than one host claims. The observation is refused with
// ErrForeign unless the end it claims (the server end if ServerReported,
// otherwise the client end) is one of them, so a host speaks only for its
// own end of its own flows.
//
// There is at most one row per (hour, key, side). The first reporter of
// a side holds it: its repeated observations accumulate (a report
// interval can contribute several parts to one hour), counters saturate
// at the stored range, and lower_bound is ORed. Another reporter's
// observation of the same side is refused with ErrConflict, so it can
// neither replace nor add to the holder's bytes. The hour must lie within
// the retention window and start no later than now plus
// flowagg.DefaultMaxClockSkew.
//
// A new row is refused with ErrLimit when it would exceed MaxBuckets in
// total or MaxBucketsPerReporter for its reporter (ADR 0009 D7): existing
// rows keep accepting data and other reporters' rows are never evicted.
func (s *Store) UpsertBucket(ctx context.Context, b Bucket, own []netip.Addr) error {
	if err := validateBucket(&b); err != nil {
		return err
	}
	mine, err := ownsEnd(own, claimedEnd(&b))
	if err != nil {
		return fmt.Errorf("%w: reporter %s: %v", ErrInvalidBucket, b.Reporter, err)
	}
	if !mine {
		return fmt.Errorf("%w: reporter %s does not own %s", ErrForeign, b.Reporter, claimedEnd(&b))
	}
	now := s.now()
	hour := hourOf(b.Hour)
	if hour <= pruneHourBound(now.Add(-s.retention).Unix()) {
		return fmt.Errorf("%w: hour %s is older than the retention", ErrOutOfRange, b.Hour.UTC().Format(time.RFC3339))
	}
	if hour > hourOf(now.Add(maxClockSkew)) {
		return fmt.Errorf("%w: hour %s is in the future", ErrOutOfRange, b.Hour.UTC().Format(time.RFC3339))
	}

	s.autoPrune(ctx)

	a, bb := b.Key.A.String(), b.Key.B.String()
	abKey := addrOrderKey(b.Key.A, b.Key.B)
	key := []any{hour, a, bb, int64(b.Key.Proto), int64(b.Key.ServerPort), int64(b.Key.Server), b.Key.Tier, boolInt(b.ServerReported)}
	ab, ba, conns := clampCounter(b.BytesAB), clampCounter(b.BytesBA), clampCounter(b.Connections)
	return s.writeTx(ctx, "upsert bucket", func(tx *sql.Tx) error {
		var holder string
		err := tx.QueryRowContext(ctx, `
			SELECT reporter FROM flow_buckets
			WHERE hour = ? AND a = ? AND b = ? AND proto = ? AND server_port = ?
			  AND server_side = ? AND tier = ? AND server_reported = ?`, key...).Scan(&holder)
		switch {
		case err == nil:
			if holder != b.Reporter {
				return fmt.Errorf("%w: reporter %s, held by %s", ErrConflict, b.Reporter, holder)
			}
			args := append([]any{ab, ba, conns, boolInt(b.LowerBound)}, key...)
			if _, err := tx.ExecContext(ctx, upsertBucketSQL, args...); err != nil {
				return fmt.Errorf("trafficstore: update bucket: %w", err)
			}
			return nil
		case errors.Is(err, sql.ErrNoRows):
		default:
			return fmt.Errorf("trafficstore: look up bucket: %w", err)
		}
		total, err := readCount(ctx, tx, countBuckets, countTotal)
		if err != nil {
			return err
		}
		if total >= s.bucketCap {
			return fmt.Errorf("%w: %d flow bucket rows held, limit %d", ErrLimit, total, s.bucketCap)
		}
		perReporter, err := readCount(ctx, tx, countBuckets, b.Reporter)
		if err != nil {
			return err
		}
		if perReporter >= s.bucketCapReporter {
			return fmt.Errorf("%w: reporter %s already has %d flow bucket rows, limit %d", ErrLimit, b.Reporter, perReporter, s.bucketCapReporter)
		}
		args := append(key, b.Reporter, ab, ba, conns, boolInt(b.LowerBound), abKey)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO flow_buckets (hour, a, b, proto, server_port, server_side, tier, server_reported,
			                          reporter, bytes_ab, bytes_ba, connections, lower_bound, ab_key)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...); err != nil {
			return fmt.Errorf("trafficstore: insert bucket: %w", err)
		}
		return nil
	})
}

// addrOrderKey encodes (a, b) so that byte order (SQLite BLOB
// comparison) equals ordering by a, then b, with netip.Addr.Compare: per
// address the bit length (IPv4 before IPv6), then the 16-byte form. Keys
// carry no zones.
func addrOrderKey(a, b netip.Addr) []byte {
	out := make([]byte, 0, 34)
	for _, x := range []netip.Addr{a, b} {
		out = append(out, byte(x.BitLen()/8))
		b16 := x.As16()
		out = append(out, b16[:]...)
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CountBuckets returns the number of stored flow bucket rows, as
// maintained for the caps.
func (s *Store) CountBuckets(ctx context.Context) (int, error) {
	return readCount(ctx, s.db, countBuckets, countTotal)
}
