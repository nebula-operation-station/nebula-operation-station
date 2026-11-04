// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficstore persists the traffic map's observed endpoints and
// hourly flow buckets in the server database (ADR 0009, TM11; decisions
// D2, D3, D7).
//
// It is the durable mirror of internal/flowagg's in-memory aggregator:
//
//   - net_endpoints holds the deduplicated endpoints observed on the
//     network (one row per MAC, or per first-seen address when no MAC is
//     known), with the addresses, VLAN, vendor OUI, hostname, first/last
//     seen, source tier, reporter, and the link to the matching IPAM
//     asset or managed host;
//   - flow_buckets holds one row per (hour, flow key, reporter) with the
//     bytes and connections that reporter attributed to the flow in that
//     hour.
//
// Every value comes from a managed host and is untrusted input: it is
// validated against explicit limits before it touches the database.
//
// Retention (D3): default 21 days, configurable lower only. Prune
// removes flow bucket rows whose hour ends at or before now-retention
// and endpoint rows whose last_seen lies before it. The store runs Prune
// at most once per clock hour on writes; the server schedule invokes it
// hourly.
//
// Caps (D7): the total number of endpoint and bucket rows, and the number
// of rows per reporter, are bounded. A reporter that reaches its cap is
// refused; other reporters' rows are never evicted.
//
// Queries (TopN, OverviewUnion) take internal/flowagg types and merge
// the stored rows with flowagg semantics: per flow and hour the server
// end's report is used when present, otherwise the client end's.
package trafficstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// Retention and cap bounds, next to the code that enforces them.
const (
	// DefaultRetention is how long hourly flow buckets and endpoint
	// observations are kept (ADR 0009: 21 days).
	DefaultRetention = flowagg.Retention
	// MaxEndpoints bounds the observed endpoints held.
	MaxEndpoints = 100_000
	// MaxEndpointsPerReporter bounds the endpoints one reporter may
	// create (ADR 0009 D7: per-host bounds).
	MaxEndpointsPerReporter = 5_000
	// MaxAddressesPerEndpoint bounds the addresses of one endpoint.
	MaxAddressesPerEndpoint = 64
	// MaxBuckets bounds the persisted flow bucket rows; it matches the
	// in-memory aggregator's bound.
	MaxBuckets = flowagg.DefaultMaxBuckets
	// MaxBucketsPerReporter bounds the rows one reporter may create; it
	// matches the in-memory aggregator's bound.
	MaxBucketsPerReporter = flowagg.DefaultMaxBucketsPerReporter
	// maxClockSkew is how far a reported observation time may lie in the
	// future (matches flowagg.DefaultMaxClockSkew).
	maxClockSkew = 5 * time.Minute
	// maxHostnameLen bounds the observed hostname.
	maxHostnameLen = 255
	// maxIDLen bounds the IPAM asset and managed host links.
	maxIDLen = 128
	// secondsPerHour is the hour grain of flow_buckets.
	secondsPerHour = 3600
	// maxStoredCounter is the largest counter value a row may hold;
	// SQLite stores counters as signed 64-bit integers and upserts
	// saturate at this value.
	maxStoredCounter = math.MaxInt64
)

// Sentinel errors callers branch on.
var (
	// ErrInvalidEndpoint marks a malformed endpoint.
	ErrInvalidEndpoint = errors.New("trafficstore: invalid endpoint")
	// ErrInvalidBucket marks a malformed flow bucket.
	ErrInvalidBucket = errors.New("trafficstore: invalid flow bucket")
	// ErrInvalidWindow marks a query window that is empty or wider than
	// the retention.
	ErrInvalidWindow = errors.New("trafficstore: invalid query window")
	// ErrOutOfRange marks data outside the retention window.
	ErrOutOfRange = errors.New("trafficstore: outside the retention window")
	// ErrLimit marks a write that would exceed an endpoint or bucket cap.
	ErrLimit = errors.New("trafficstore: storage limit reached")
	// ErrNotFound marks a missing endpoint.
	ErrNotFound = errors.New("trafficstore: not found")
)

// Store persists traffic map data in the server database.
type Store struct {
	db        *sql.DB
	now       func() time.Time
	retention time.Duration
	mu        sync.Mutex
	// lastPruneHour is the hour of now at the last automatic prune.
	lastPruneHour int64
	// caps, defaulted from the constants above; tests may lower them.
	endpointCap         int
	endpointCapReporter int
	bucketCap           int
	bucketCapReporter   int
}

// New opens a Store over an open server database, keeping data for
// DefaultRetention and using time.Now.
func New(db *sql.DB) *Store {
	return newStore(db, time.Now, DefaultRetention)
}

// NewWithNow is like New but injects the clock; now must not be nil.
func NewWithNow(db *sql.DB, now func() time.Time) *Store {
	return newStore(db, now, DefaultRetention)
}

// NewWithRetention is like New but keeps data for retention instead of
// DefaultRetention. retention must be positive and at most
// DefaultRetention: the retention is configurable lower only (ADR 0009
// D3), never higher than the 21-day bound the caps are sized for.
func NewWithRetention(db *sql.DB, retention time.Duration) (*Store, error) {
	if retention <= 0 || retention > DefaultRetention {
		return nil, fmt.Errorf("trafficstore: retention must be in (0, %s], got %s", DefaultRetention, retention)
	}
	return newStore(db, time.Now, retention), nil
}

// NewWithNowAndRetention is like NewWithRetention but also injects the
// clock; now must not be nil.
func NewWithNowAndRetention(db *sql.DB, now func() time.Time, retention time.Duration) (*Store, error) {
	if retention <= 0 || retention > DefaultRetention {
		return nil, fmt.Errorf("trafficstore: retention must be in (0, %s], got %s", DefaultRetention, retention)
	}
	return newStore(db, now, retention), nil
}

func newStore(db *sql.DB, now func() time.Time, retention time.Duration) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		db:                  db,
		now:                 now,
		retention:           retention,
		endpointCap:         MaxEndpoints,
		endpointCapReporter: MaxEndpointsPerReporter,
		bucketCap:           MaxBuckets,
		bucketCapReporter:   MaxBucketsPerReporter,
	}
}

// Open opens (and migrates) the server database at path and returns a
// Store over it using time.Now. The caller closes the returned database.
func Open(path string) (*Store, *sql.DB, error) {
	db, err := serverdb.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("trafficstore: open %s: %w", path, err)
	}
	return New(db), db, nil
}

// hourOf returns the hour start of t as unix seconds.
func hourOf(t time.Time) int64 {
	s := t.Unix()
	h := s / secondsPerHour
	if s%secondsPerHour < 0 {
		h--
	}
	return h
}

// autoPrune runs Prune at most once per clock hour, before a write, so
// expired rows do not keep new ones out under a cap. A failed prune does
// not fail the write; the server schedule invokes Prune hourly anyway.
func (s *Store) autoPrune(ctx context.Context) {
	h := hourOf(s.now())
	s.mu.Lock()
	if h == s.lastPruneHour {
		s.mu.Unlock()
		return
	}
	s.lastPruneHour = h
	s.mu.Unlock()
	_, _, _ = s.Prune(ctx)
}

// Prune removes flow bucket rows whose hour ends at or before
// now-retention and endpoint rows whose last_seen lies before
// now-retention, and returns the number of removed rows per table. It is
// idempotent and safe to call more often than hourly; the store also
// runs it automatically at most once per clock hour on writes.
func (s *Store) Prune(ctx context.Context) (buckets, endpoints int64, err error) {
	cutoff := s.now().Add(-s.retention).Unix()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM flow_buckets WHERE hour * ? + ? <= ?`, secondsPerHour, secondsPerHour, cutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("trafficstore: prune flow_buckets: %w", err)
	}
	buckets, err = res.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("trafficstore: prune flow_buckets: %w", err)
	}
	res, err = s.db.ExecContext(ctx,
		`DELETE FROM net_endpoints WHERE last_seen < ?`, cutoff)
	if err != nil {
		return buckets, 0, fmt.Errorf("trafficstore: prune net_endpoints: %w", err)
	}
	endpoints, err = res.RowsAffected()
	if err != nil {
		return buckets, 0, fmt.Errorf("trafficstore: prune net_endpoints: %w", err)
	}
	return buckets, endpoints, nil
}
