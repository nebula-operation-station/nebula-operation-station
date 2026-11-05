// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficstore persists the traffic map's observed endpoints and
// hourly flow buckets in the server database (ADR 0009, TM11; decisions
// D2, D3, D7).
//
// It is the durable mirror of internal/flowagg's in-memory aggregator:
//
//   - net_endpoints holds the deduplicated endpoints observed on the
//     network (at most one row per MAC, otherwise one per address-only
//     observation) with the server-derived values: MAC and OUI,
//     last_seen, the authoritative owner and the links to the matching
//     IPAM asset or managed host; net_endpoint_reporters is the seen-by
//     set with each reporter's own claims (tier, VLAN, hostname, OUI,
//     first/last seen) and net_endpoint_addresses attributes every
//     address to the reporter that saw it;
//   - flow_buckets holds at most one row per (hour, flow key, reporting
//     side) with the bytes and connections that side's reporter
//     attributed to the flow in that hour.
//
// Every value comes from a managed host and is untrusted input: it is
// validated against explicit limits before it touches the database.
//
// Ownership (D7 "never affect other reporters"): a flow observation is
// accepted only when the end it claims belongs to the reporter (the
// caller passes the reporter's addresses from the server's own records,
// as for flowagg.Aggregator.Ingest), and the first reporter of a side
// holds it. An endpoint's owner is the managed host that has its MAC on
// its own interface by the server's records (the caller passes the
// reporter's Identity), never the first reporter; every reporter's
// claims are kept under its own name and caps, reads prefer the owner's
// and flag disagreements, and identity links come only from the server.
// ReconcileIdentities drops ownership and owner attestations the
// server's current records no longer back, also for hosts that stopped
// reporting.
//
// Retention (D3): default 21 days, configurable lower only. Prune
// removes flow bucket rows whose hour ends at or before now-retention
// and endpoint observations whose last_seen lies before it. The store
// runs Prune at most once per clock hour on writes; the server schedule
// invokes it hourly.
//
// Caps (D7): the total number of endpoint and bucket rows, and the number
// of rows per reporter, are bounded. The counts are kept by triggers in
// traffic_counts, so a cap check is a primary-key lookup. A reporter that
// reaches its cap is refused; other reporters' rows are never evicted.
// An endpoint's seen-by set has one slot reserved for its authoritative
// owner (MaxReportersPerEndpoint non-owners plus the owner), so the owner
// is always admitted without evicting anyone.
//
// Provider guest NICs (ADR 0009 D1 tier 2, TM14; guestnics.go) live in
// their own bounded tables under the source SourceProvider and are
// matched to observed endpoints by MAC at read time only; they never
// create endpoints or carry addresses.
//
// Queries (TopN, OverviewUnion) return internal/flowagg types and merge
// the stored rows with flowagg semantics in SQL: per flow and hour the
// server end's report is used when present, otherwise the client end's.
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
	// MaxAddressesPerEndpoint bounds the addresses one reporter attaches
	// to one endpoint.
	MaxAddressesPerEndpoint = 64
	// MaxReportersPerEndpoint bounds the non-owner reporters in the
	// seen-by set of one endpoint; the owner has a reserved slot on top.
	MaxReportersPerEndpoint = 32
	// MaxBuckets bounds the persisted flow bucket rows; it matches the
	// in-memory aggregator's bound.
	MaxBuckets = flowagg.DefaultMaxBuckets
	// MaxBucketsPerReporter bounds the rows one reporter may create; it
	// matches the in-memory aggregator's bound.
	MaxBucketsPerReporter = flowagg.DefaultMaxBucketsPerReporter
	// maxClockSkew is how far a reported observation time may lie in the
	// future.
	maxClockSkew = flowagg.DefaultMaxClockSkew
	// maxHostnameLen bounds the observed hostname.
	maxHostnameLen = 255
	// maxIDLen bounds the IPAM asset and managed host links.
	maxIDLen = 128
	// secondsPerHour is the hour grain of flow_buckets.
	secondsPerHour = 3600
	// counterHeadroom is how many stored counters the queries may add
	// up in SQLite's signed 64-bit integers: both directions of every
	// hour of a window no wider than DefaultRetention.
	counterHeadroom = 1024
	// maxStoredCounter is the largest counter value a row may hold
	// (about 9 PB per flow and hour). Inputs and upserts saturate at it,
	// so the SQL sums of TopN can never overflow.
	maxStoredCounter = math.MaxInt64 / counterHeadroom
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
	// ErrInvalidQuery marks a query with an invalid node or result size,
	// or too many nodes.
	ErrInvalidQuery = errors.New("trafficstore: invalid query")
	// ErrForeign marks a flow observation whose claimed end is not one of
	// the reporter's own addresses (flowagg's Foreign).
	ErrForeign = errors.New("trafficstore: observation for a foreign flow end")
	// ErrConflict marks a flow observation for a side another reporter
	// already holds in that hour (flowagg's Conflicts).
	ErrConflict = errors.New("trafficstore: flow side held by another reporter")
	// ErrNotFound marks a missing endpoint.
	ErrNotFound = errors.New("trafficstore: not found")
	// ErrAmbiguous marks an address lookup that matches several
	// endpoints at the same level of authority.
	ErrAmbiguous = errors.New("trafficstore: ambiguous endpoint lookup")
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
	guestNICCap         int
	guestNICCapRemote   int
	guestRemoteCap      int
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

// Retention returns how long the store keeps flow data; query windows
// may be at most this wide.
func (s *Store) Retention() time.Duration { return s.retention }

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
		guestNICCap:         MaxGuestNICs,
		guestNICCapRemote:   MaxGuestNICsPerRemote,
		guestRemoteCap:      MaxGuestNICRemotes,
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

// hourOf returns the hour index of t: unix seconds divided by 3600,
// floored. It is what flow_buckets.hour stores.
func hourOf(t time.Time) int64 {
	return floorDiv(t.Unix(), secondsPerHour)
}

// querier is the subset of *sql.Tx the write helpers use.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// writeTx runs fn in a transaction that takes the database write lock
// with its first statement, before any read: concurrent writers wait on
// the busy timeout and are serialized instead of failing a read-to-write
// upgrade, and the cap checks read counts no other writer can change
// before the commit.
func (s *Store) writeTx(ctx context.Context, what string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("trafficstore: begin %s: %w", what, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE traffic_store_lock SET id = 1 WHERE id = 1`); err != nil {
		return fmt.Errorf("trafficstore: lock for %s: %w", what, err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("trafficstore: commit %s: %w", what, err)
	}
	return nil
}

// Counter names in traffic_counts (see migration 0031).
const (
	countBuckets      = "buckets"
	countEndpoints    = "endpoints"
	countEndpointSeen = "endpoint_seen"
	// countTotal is the reporter key of a total; reporter names are
	// never empty.
	countTotal = ""
)

// readCount returns the maintained row count name/reporter (0 when
// there is none).
func readCount(ctx context.Context, q querier, name, reporter string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT n FROM traffic_counts WHERE name = ? AND reporter = ?`, name, reporter).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("trafficstore: read count %s: %w", name, err)
	}
	return n, nil
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

// SQL of Prune; package-level so the tests can check the query plans.
const (
	// pruneBucketsSQL compares the hour column itself with a precomputed
	// bound, so the primary key's leading hour column serves it.
	pruneBucketsSQL      = `DELETE FROM flow_buckets WHERE hour <= ?`
	pruneEndpointSeenSQL = `DELETE FROM net_endpoint_reporters WHERE last_seen < ?`
	pruneEndpointsSQL    = `DELETE FROM net_endpoints WHERE last_seen < ?`
	// clearOwnerSQL drops the ownership of endpoints whose owner's
	// observation expired; ownership never passes to another reporter.
	clearOwnerSQL = `
		UPDATE net_endpoints SET owner = ''
		WHERE owner != '' AND NOT EXISTS (
			SELECT 1 FROM net_endpoint_reporters r
			WHERE r.endpoint_id = net_endpoints.id AND r.reporter = net_endpoints.owner)`
)

// pruneHourBound returns the largest hour whose end lies at or before
// cutoff (unix seconds): (hour+1)*3600 <= cutoff.
func pruneHourBound(cutoff int64) int64 {
	return floorDiv(cutoff, secondsPerHour) - 1
}

// Prune removes flow bucket rows whose hour ends at or before
// now-retention, seen-by rows (with their addresses) whose last_seen
// lies before now-retention, and endpoints no reporter has seen since,
// and returns the number of removed bucket and endpoint rows. An
// endpoint whose owner's observation expired while other reporters
// still see it has no owner until its owner reports again. Provider
// guest NIC snapshots observed before now-retention are removed with
// their NICs (not counted in the result). Prune is idempotent and safe to call more often than hourly; the store also
// runs it automatically at most once per clock hour on writes.
func (s *Store) Prune(ctx context.Context) (buckets, endpoints int64, err error) {
	cutoff := s.now().Add(-s.retention).Unix()
	err = s.writeTx(ctx, "prune", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, pruneBucketsSQL, pruneHourBound(cutoff))
		if err != nil {
			return fmt.Errorf("trafficstore: prune flow_buckets: %w", err)
		}
		if buckets, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("trafficstore: prune flow_buckets: %w", err)
		}
		res, err = tx.ExecContext(ctx, pruneEndpointSeenSQL, cutoff)
		if err != nil {
			return fmt.Errorf("trafficstore: prune net_endpoint_reporters: %w", err)
		}
		seen, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("trafficstore: prune net_endpoint_reporters: %w", err)
		}
		res, err = tx.ExecContext(ctx, pruneEndpointsSQL, cutoff)
		if err != nil {
			return fmt.Errorf("trafficstore: prune net_endpoints: %w", err)
		}
		if endpoints, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("trafficstore: prune net_endpoints: %w", err)
		}
		if seen > 0 {
			if _, err := tx.ExecContext(ctx, clearOwnerSQL); err != nil {
				return fmt.Errorf("trafficstore: clear expired endpoint owners: %w", err)
			}
		}
		// Provider guest NIC snapshots expire with the same retention;
		// their NICs cascade.
		if _, err := tx.ExecContext(ctx, pruneGuestSnapshotsSQL, cutoff); err != nil {
			return fmt.Errorf("trafficstore: prune net_guest_nic_snapshots: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return buckets, endpoints, nil
}
