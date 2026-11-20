// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"
)

// MaxSnapshotHosts bounds the hosts of one inventory snapshot. It equals
// api.MaxExportSubjects and vulnstore.MaxCoveredPerRun, because the two limits
// describe the same thing: one snapshot holds at most this many subjects, and
// one run covers at most this many. The export serves a snapshot in pages of
// api.MaxSubjectsPerPage (1,000) subjects, so a full snapshot is ten pages
// (ADR 0011 D3). The 1,000 is the page size, the 10,000 the total over all
// pages; they do not conflict. Hosts past the limit are left out in host-ID
// order and counted in Snapshot.Omitted.
const MaxSnapshotHosts = 10000

// snapshotPageReads is how many reads Snapshot loads per query.
const snapshotPageReads = 100

// MaxSnapshotBodyBytes bounds the stored bodies that Snapshot returns: the sum
// of the body lengths of the reads of one snapshot. It is sixteen worst-case
// bodies (MaxBodyBytes each, about 200 MB), so a snapshot of typical hosts is
// far below it, while a snapshot of hostile maximum-size bodies is refused
// with ErrLimit before any body is decoded.
const MaxSnapshotBodyBytes = 16 * MaxBodyBytes

// maxSnapshotIDBytes matches the snapshot ID column (0052: 1 to 64 bytes).
const maxSnapshotIDBytes = 64

// snapshotIDPrefix starts every snapshot ID: nos-inv-<generation>. The ID
// matches the export's snapshot ID pattern (exportSnapshotIDRe).
const snapshotIDPrefix = "nos-inv-"

// ErrSnapshotGone is returned by Snapshot for an unknown or pruned snapshot ID.
var ErrSnapshotGone = errors.New("vulninventory: snapshot gone")

// nowFunc is the clock of Current and PruneSnapshots. Tests replace it. It is
// a package variable because Store is defined in store.go and carries no clock.
var nowFunc = time.Now

// snapshotMu serialises Current and PruneSnapshots within the process, so two
// callers cannot both see the same newest snapshot and both insert the next
// generation. The UNIQUE constraint on generation is the backstop.
var snapshotMu sync.Mutex

// Snapshot is an immutable set of inventory reads: one newest read per host,
// with a generation that never falls below one the store has seen (ADR 0011
// D3, D5).
type Snapshot struct {
	// ID is nos-inv-<Generation>. A snapshot is immutable for its ID.
	ID string
	// Generation rises with every new snapshot.
	Generation int64
	// TakenAt is when the snapshot was created (Unix seconds, UTC).
	TakenAt time.Time
	// Reads are the pinned reads in host-ID order, one per host. Current
	// returns them without components; Snapshot returns them with components.
	Reads []Read
	// Omitted counts the hosts past MaxSnapshotHosts that Current left out.
	// It is set only by Current and is not stored, so Snapshot reports 0.
	Omitted int
}

// wantedHosts validates hosts, removes duplicates and keeps the first
// MaxSnapshotHosts host IDs in host-ID order. It returns the kept set and the
// number of hosts left out.
func wantedHosts(hosts []string) (map[string]bool, int, error) {
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if err := checkText("host id", h, maxHostIDBytes, true); err != nil {
			return nil, 0, err
		}
		set[h] = true
	}
	if len(set) <= MaxSnapshotHosts {
		return set, 0, nil
	}
	ids := make([]string, 0, len(set))
	for h := range set {
		ids = append(ids, h)
	}
	sort.Strings(ids)
	keep := make(map[string]bool, MaxSnapshotHosts)
	for _, h := range ids[:MaxSnapshotHosts] {
		keep[h] = true
	}
	return keep, len(ids) - MaxSnapshotHosts, nil
}

// newestReads returns the newest read of every host in want, in host-ID order.
// Hosts without a read are absent. It runs on q, so it sees the state of the
// caller's transaction.
func newestReads(ctx context.Context, q *sql.Tx, want map[string]bool) ([]Read, error) {
	rows, err := q.QueryContext(ctx, latestAllQuery)
	if err != nil {
		return nil, fmt.Errorf("newest reads: %w", err)
	}
	defer rows.Close()
	var out []Read
	for rows.Next() {
		r, err := scanRead(rows, false)
		if err != nil {
			return nil, fmt.Errorf("newest reads: %w", err)
		}
		if want[r.HostID] {
			out = append(out, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("newest reads: %w", err)
	}
	// latestAllQuery is not ordered by host; sort the few rows here.
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out, nil
}

// Current returns the snapshot of the newest read of each host in hosts.
//
// The current snapshot is reused when it pins exactly the same reads and was
// taken less than maxReuse ago. Otherwise a new snapshot is written with
// generation max(highest stored generation, floor) + 1. floor is the lowest
// generation the caller allows: the caller passes the highest inventory
// generation a vulnstore run has seen, so a run is never rejected for a
// regression (ADR 0011 D5). Hosts without a read are left out; hosts past
// MaxSnapshotHosts are left out and counted in Omitted.
//
// Reads are returned without components; use Snapshot for the bodies.
func (s *Store) Current(ctx context.Context, hosts []string, maxReuse time.Duration, floor int64) (Snapshot, error) {
	if maxReuse < 0 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w: negative max reuse", ErrInvalidRead)
	}
	if floor < 0 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w: negative floor", ErrInvalidRead)
	}
	want, omitted, err := wantedHosts(hosts)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	}

	snapshotMu.Lock()
	defer snapshotMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: begin: %w", err)
	}
	defer tx.Rollback()
	// The first write starts the write transaction, so the reads below see
	// the state that the write lock protects. The statement matches no row.
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_inventory_snapshots SET taken_at = taken_at WHERE 0`); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: lock: %w", err)
	}

	reads, err := newestReads(ctx, tx, want)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	}
	ids := make([]int64, 0, len(reads))
	for _, r := range reads {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)

	now := nowFunc().UTC()
	if snap, ok, err := reusable(ctx, tx, reads, ids, now, maxReuse, floor); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	} else if ok {
		snap.Omitted = omitted
		return snap, nil
	}

	var maxStored int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation), 0) FROM vuln_inventory_snapshots`).Scan(&maxStored); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: generation: %w", err)
	}
	top := max(maxStored, floor)
	if top == math.MaxInt64 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: generation overflow")
	}
	gen := top + 1
	snap := Snapshot{
		ID:         snapshotIDPrefix + strconv.FormatInt(gen, 10),
		Generation: gen,
		TakenAt:    time.Unix(now.Unix(), 0).UTC(),
		Reads:      reads,
		Omitted:    omitted,
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_inventory_snapshots (id, generation, taken_at) VALUES (?, ?, ?)`,
		snap.ID, snap.Generation, snap.TakenAt.Unix()); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: insert snapshot: %w", err)
	}
	for _, r := range reads {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES (?, ?)`,
			snap.ID, r.ID); err != nil {
			return Snapshot{}, fmt.Errorf("vulninventory: current: insert member: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: commit: %w", err)
	}
	return snap, nil
}

// reusable returns the newest snapshot when it pins exactly ids (sorted), was
// taken less than maxReuse before now, and its generation is above floor. The
// floor check is part of reuse: a snapshot at or below a generation that
// vulnstore has seen must never be handed out again (ADR 0011 D5). The
// snapshot's reads are reads.
func reusable(ctx context.Context, tx *sql.Tx, reads []Read, ids []int64, now time.Time, maxReuse time.Duration, floor int64) (Snapshot, bool, error) {
	var snap Snapshot
	var takenAt int64
	err := tx.QueryRowContext(ctx, `SELECT id, generation, taken_at FROM vuln_inventory_snapshots
		ORDER BY generation DESC LIMIT 1`).Scan(&snap.ID, &snap.Generation, &takenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("newest snapshot: %w", err)
	}
	if snap.Generation <= floor || now.Sub(time.Unix(takenAt, 0).UTC()) >= maxReuse {
		return Snapshot{}, false, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ? ORDER BY read_id`, snap.ID)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("snapshot members: %w", err)
	}
	defer rows.Close()
	var members []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return Snapshot{}, false, fmt.Errorf("snapshot members: %w", err)
		}
		members = append(members, id)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, false, fmt.Errorf("snapshot members: %w", err)
	}
	if !slices.Equal(members, ids) {
		return Snapshot{}, false, nil
	}
	snap.TakenAt = time.Unix(takenAt, 0).UTC()
	snap.Reads = reads
	return snap, true, nil
}

// Snapshot returns the snapshot with the given ID: exactly the reads that
// were pinned when it was taken, with their components, in host-ID order.
// It returns ErrSnapshotGone when the ID is unknown or was pruned.
func (s *Store) Snapshot(ctx context.Context, id string) (Snapshot, error) {
	if err := checkText("snapshot id", id, maxSnapshotIDBytes, true); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: begin: %w", err)
	}
	defer tx.Rollback()

	var snap Snapshot
	var takenAt int64
	err = tx.QueryRowContext(ctx, `SELECT id, generation, taken_at FROM vuln_inventory_snapshots WHERE id = ?`, id).
		Scan(&snap.ID, &snap.Generation, &takenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: %w", ErrSnapshotGone)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: %w", err)
	}
	snap.TakenAt = time.Unix(takenAt, 0).UTC()

	reads, err := loadSnapshotReads(ctx, tx, snap.ID, snapshotPageReads, MaxSnapshotBodyBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: %w", err)
	}
	snap.Reads = reads
	return snap, nil
}

// loadSnapshotReads returns the reads pinned by snapshot id, with their
// components, in host-ID order. Before any body is decoded it sums the stored
// body lengths and refuses a total above byteLimit with ErrLimit. Then it loads
// pageReads reads per query, keyset-paged on (host_id, id), so no single query
// returns more than pageReads bodies.
func loadSnapshotReads(ctx context.Context, q *sql.Tx, id string, pageReads int, byteLimit int64) ([]Read, error) {
	if pageReads <= 0 {
		return nil, fmt.Errorf("snapshot reads: page size %d: must be positive", pageReads)
	}
	const members = `SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ?`
	var total int64
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(SUM(LENGTH(body)), 0) FROM vuln_inventory_reads WHERE id IN (`+members+`)`, id).Scan(&total); err != nil {
		return nil, fmt.Errorf("snapshot body bytes: %w", err)
	}
	if total > byteLimit {
		return nil, fmt.Errorf("snapshot bodies: %w: %d bytes, limit %d", ErrLimit, total, byteLimit)
	}

	var out []Read
	afterHost, afterID := "", int64(0)
	for {
		page, err := scanSnapshotPage(ctx, q, id, afterHost, afterID, pageReads)
		if err != nil {
			return nil, fmt.Errorf("snapshot reads: %w", err)
		}
		out = append(out, page...)
		if len(page) < pageReads {
			return out, nil
		}
		last := page[len(page)-1]
		afterHost, afterID = last.HostID, last.ID
	}
}

// scanSnapshotPage returns up to limit reads of snapshot id that sort after
// (afterHost, afterID) in (host_id, id) order, with their components.
func scanSnapshotPage(ctx context.Context, q *sql.Tx, id, afterHost string, afterID int64, limit int) ([]Read, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+fullColumns+` FROM vuln_inventory_reads
		WHERE id IN (SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ?)
		AND (host_id, id) > (?, ?)
		ORDER BY host_id, id LIMIT ?`, id, afterHost, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page []Read
	for rows.Next() {
		r, err := scanRead(rows, true)
		if err != nil {
			return nil, err
		}
		page = append(page, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return page, nil
}

// PruneSnapshots deletes the snapshots taken more than maxAge ago, with their
// membership rows. The newest snapshot is always kept: its generation is the
// floor of the next one. The reads stay in the store (a read is deleted only
// under decision E1, which is not made here), so a pruned snapshot's reads are
// not lost by this call. The caller passes the export's maximum age
// (vulnstore.MaxInventoryAge).
func (s *Store) PruneSnapshots(ctx context.Context, maxAge time.Duration) error {
	if maxAge <= 0 {
		return fmt.Errorf("vulninventory: prune snapshots: %w: max age must be positive", ErrInvalidRead)
	}
	snapshotMu.Lock()
	defer snapshotMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_inventory_snapshots SET taken_at = taken_at WHERE 0`); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: lock: %w", err)
	}
	cutoff := nowFunc().UTC().Add(-maxAge).Unix()
	const expired = `SELECT id FROM vuln_inventory_snapshots
		WHERE taken_at < ? AND generation < (SELECT MAX(generation) FROM vuln_inventory_snapshots)`
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_inventory_snapshot_reads WHERE snapshot_id IN (`+expired+`)`, cutoff); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: members: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_inventory_snapshots
		WHERE taken_at < ? AND generation < (SELECT MAX(generation) FROM vuln_inventory_snapshots)`, cutoff); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: snapshots: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: commit: %w", err)
	}
	return nil
}
