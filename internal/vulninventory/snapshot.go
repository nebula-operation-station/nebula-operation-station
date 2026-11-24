// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxSnapshotHosts bounds the hosts of one inventory snapshot. It equals
// api.MaxExportSubjects and vulnstore.MaxCoveredPerRun, because the two limits
// describe the same thing: one snapshot holds at most this many subjects, and
// one run covers at most this many. The export serves a snapshot in pages of
// api.MaxSubjectsPerPage (1,000) subjects, so a full snapshot is ten pages
// (ADR 0011 D3). The 1,000 is the page size, the 10,000 the total over all
// pages; they do not conflict. Only hosts that have a read take a slot; hosts
// past the limit are left out in host-ID order and counted in Snapshot.Omitted.
const MaxSnapshotHosts = 10000

// snapshotPageReads is how many reads Snapshot loads per query.
const snapshotPageReads = 100

// MaxSnapshotBodyBytes bounds the stored bodies of one snapshot: the sum of the
// body lengths of its reads. It is sixteen worst-case bodies (MaxBodyBytes
// each, about 200 MB). Current enforces it when it creates a snapshot, so every
// snapshot it returns can be read back by Snapshot: when the newest reads
// would exceed the bound, the reads in host-ID order that fit are kept and the
// rest are left out and counted in Omitted. Hostile maximum-size bodies can
// therefore shrink a snapshot, but never make its ID fail with ErrLimit.
const MaxSnapshotBodyBytes = 16 * MaxBodyBytes

// MaxSnapshotImages bounds the image reads of one snapshot. A snapshot pins the
// newest image read of each (host, digest) of its hosts. The count is shared
// out per host in round-robin order: each host's newest digest comes before
// any host's second one, so one host with many digests cannot push the images
// of the other hosts out. Current loads no more than this count of rows, and
// the image reads it does not pin are counted in Snapshot.OmittedImages. The
// image bodies share MaxSnapshotBodyBytes with the host reads.
const MaxSnapshotImages = 2000

// maxSnapshotIDBytes matches the snapshot ID column (0052: 1 to 64 bytes).
const maxSnapshotIDBytes = 64

// snapshotIDPrefix starts every snapshot ID: nos-inv-<generation>. The ID
// matches the export's snapshot ID pattern (exportSnapshotIDRe).
const snapshotIDPrefix = "nos-inv-"

// ErrSnapshotGone is returned by Snapshot for an unknown or pruned snapshot ID.
var ErrSnapshotGone = errors.New("vulninventory: snapshot gone")

// GenerationFloor supplies the lowest generation Current may return. Current
// calls Generation once per call, on its own transaction, after it has taken
// the write lock and before it decides between reuse and a new snapshot. The
// value is therefore read in the same serialised state as the snapshot it
// bounds: a run floor recorded by another writer is either seen or waits for
// the commit.
type GenerationFloor interface {
	Generation(ctx context.Context, tx *sql.Tx) (int64, error)
}

// FixedFloor is a GenerationFloor with a constant value. It is for callers
// that have no run floor to read.
type FixedFloor int64

// Generation returns the constant value.
func (f FixedFloor) Generation(context.Context, *sql.Tx) (int64, error) {
	return int64(f), nil
}

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
	// Omitted counts the hosts that have a newest read but that Current left
	// out, because the snapshot was full (MaxSnapshotHosts) or because their
	// bodies did not fit in MaxSnapshotBodyBytes. It is set only by Current and
	// is not stored, so Snapshot reports 0.
	Omitted int
	// Images are the pinned image reads: the newest read of each (host,
	// digest) of the wanted hosts, in host-ID then digest order. Current
	// returns them without packages; Snapshot returns them with packages.
	Images []ImageRead
	// OmittedImages counts the image reads that Current left out, because the
	// snapshot held MaxSnapshotImages or their bodies did not fit in the bytes
	// the host reads left of MaxSnapshotBodyBytes. Like Omitted, it is set only
	// by Current.
	OmittedImages int
}

// sizedRead is the newest read of a host with the stored length of its body.
// Current needs the length to apply MaxSnapshotBodyBytes before it creates a
// snapshot.
type sizedRead struct {
	Read
	bytes int64
}

// sizedImage is the newest image read of a (host, digest) with the stored
// length of its body, for the same budget as sizedRead.
type sizedImage struct {
	ImageRead
	bytes int64
}

// wantedHosts validates hosts and removes duplicates. It returns the set of
// host IDs. Hosts without a read are kept in the set and simply match nothing.
func wantedHosts(hosts []string) (map[string]bool, error) {
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if err := checkText("host id", h, maxHostIDBytes, true); err != nil {
			return nil, err
		}
		set[h] = true
	}
	return set, nil
}

// selectSnapshotReads chooses the reads of one snapshot from latest, which is
// sorted by host ID. It walks the reads in host-ID order and keeps a read when
// fewer than maxHosts reads are kept so far and its body still fits in the
// remaining maxBytes; a read that does not fit is skipped, and later smaller
// reads may still be kept. It returns the kept reads (without sizes) and the
// number of reads left out. The result is deterministic, and the bodies of the
// kept reads never add up to more than maxBytes.
func selectSnapshotReads(latest []sizedRead, maxHosts int, maxBytes int64) ([]Read, int) {
	kept, _, omitted := selectSnapshotReadsUsed(latest, maxHosts, maxBytes)
	return kept, omitted
}

// selectSnapshotReadsUsed is selectSnapshotReads that also returns the bytes
// the kept reads use, so that the image bodies can share the remaining budget.
func selectSnapshotReadsUsed(latest []sizedRead, maxHosts int, maxBytes int64) ([]Read, int64, int) {
	kept := make([]Read, 0, min(len(latest), maxHosts))
	var used int64
	omitted := 0
	for _, s := range latest {
		if len(kept) >= maxHosts || s.bytes > maxBytes-used {
			omitted++
			continue
		}
		used += s.bytes
		kept = append(kept, s.Read)
	}
	return kept, used, omitted
}

// selectSnapshotImages chooses the image reads of one snapshot from latest,
// which is in round-robin order (see latestImagesQuery). It applies the same
// rule as selectSnapshotReads with maxCount and maxBytes: a read is kept when
// fewer than maxCount are kept and its body fits in the remaining bytes. It
// returns the kept reads (without sizes), in the order of latest, and the
// number of loaded reads left out. Current counts the omitted reads itself, so
// that reads never loaded are counted too.
func selectSnapshotImages(latest []sizedImage, maxCount int, maxBytes int64) ([]ImageRead, int) {
	kept := make([]ImageRead, 0, min(len(latest), maxCount))
	var used int64
	omitted := 0
	for _, s := range latest {
		if len(kept) >= maxCount || s.bytes > maxBytes-used {
			omitted++
			continue
		}
		used += s.bytes
		kept = append(kept, s.ImageRead)
	}
	return kept, omitted
}

// latestImagesQuery is the newest image read of every (host, digest) of the
// hosts in the JSON array bound to its first parameter, without packages, with
// the length of its body. The host filter runs before the window functions, so
// the work grows with the wanted hosts, not with every stored image read.
//
// Rows come in round-robin order: round k holds the k-th most recent digest of
// each host, and within a round the hosts are in ID order. The first parameter
// bounds the total number of rows, so the load never exceeds the snapshot cap,
// and the cap is shared out fairly: a host with many digests cannot take the
// whole cap before the other hosts have had their first digest. "Newest" is the
// order of ImageReads: read time, then ID.
const latestImagesQuery = `WITH newest AS (SELECT id, host_id, digest, read_at, ROW_NUMBER() OVER (PARTITION BY host_id, digest
		ORDER BY read_at DESC, id DESC) AS rn FROM vuln_image_reads
		WHERE host_id IN (SELECT value FROM json_each(?))),
	ranked AS (SELECT id, host_id, digest, ROW_NUMBER() OVER (PARTITION BY host_id
		ORDER BY read_at DESC, id DESC) AS round FROM newest WHERE rn = 1)
	SELECT r.id, r.repository, r.digest, r.host_id, r.execution_id, r.read_at, r.complete,
	r.reason, r.os_family, r.os_name, LENGTH(r.body) FROM ranked AS k
	JOIN vuln_image_reads AS r ON r.id = k.id
	ORDER BY k.round, k.host_id, k.digest LIMIT ?`

// countImagesQuery counts the distinct (host, digest) pairs of the hosts in the
// JSON array bound to its first parameter: the number of image reads Current
// would pin with no limit.
const countImagesQuery = `SELECT COUNT(*) FROM (SELECT 1 FROM vuln_image_reads
	WHERE host_id IN (SELECT value FROM json_each(?)) GROUP BY host_id, digest)`

// wantedHostsJSON encodes the hosts of want as the JSON array the image queries
// take.
func wantedHostsJSON(want map[string]bool) (string, error) {
	hosts := make([]string, 0, len(want))
	for h := range want {
		hosts = append(hosts, h)
	}
	b, err := json.Marshal(hosts)
	if err != nil {
		return "", fmt.Errorf("hosts: %w", err)
	}
	return string(b), nil
}

// newestImages returns at most limit newest image reads of the (host, digest)
// pairs of want, in round-robin order (see latestImagesQuery), each with its
// body length. It runs on q, so it sees the state of the caller's transaction.
func newestImages(ctx context.Context, q *sql.Tx, want map[string]bool, limit int) ([]sizedImage, error) {
	hostsJSON, err := wantedHostsJSON(want)
	if err != nil {
		return nil, fmt.Errorf("newest images: %w", err)
	}
	rows, err := q.QueryContext(ctx, latestImagesQuery, hostsJSON, limit)
	if err != nil {
		return nil, fmt.Errorf("newest images: %w", err)
	}
	defer rows.Close()
	var out []sizedImage
	for rows.Next() {
		var r ImageRead
		var readAt, n int64
		var complete int
		if err := rows.Scan(&r.ID, &r.Repository, &r.Digest, &r.HostID, &r.ExecutionID, &readAt, &complete,
			&r.Reason, &r.OSFamily, &r.OSName, &n); err != nil {
			return nil, fmt.Errorf("newest images: %w", err)
		}
		r.ReadAt = time.Unix(readAt, 0).UTC()
		r.Complete = complete == 1
		out = append(out, sizedImage{ImageRead: r, bytes: n})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("newest images: %w", err)
	}
	return out, nil
}

// countImages returns the number of distinct (host, digest) pairs of want, that
// is, how many image reads Current would pin without any limit. It runs on q,
// in the same transaction as newestImages.
func countImages(ctx context.Context, q *sql.Tx, want map[string]bool) (int, error) {
	hostsJSON, err := wantedHostsJSON(want)
	if err != nil {
		return 0, fmt.Errorf("count images: %w", err)
	}
	var n int
	if err := q.QueryRowContext(ctx, countImagesQuery, hostsJSON).Scan(&n); err != nil {
		return 0, fmt.Errorf("count images: %w", err)
	}
	return n, nil
}

// memberIDs runs query, which selects one integer column for snapshot id, and
// returns the values in the order the query gives.
func memberIDs(ctx context.Context, q *sql.Tx, query, id string) ([]int64, error) {
	rows, err := q.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// latestSizesQuery is the newest read of every host with its body length. Its
// selection is the same as latestAllQuery (store.go); a test checks that both
// return the same reads. It is needed because scanRead has no body length
// column.
const latestSizesQuery = `SELECT id, LENGTH(body) FROM vuln_inventory_reads
	WHERE id IN (SELECT (SELECT n.id FROM vuln_inventory_reads AS n WHERE n.host_id = h.host_id
		ORDER BY n.read_at DESC, n.id DESC LIMIT 1)
		FROM (SELECT host_id FROM vuln_inventory_reads GROUP BY host_id) AS h)`

// newestReads returns the newest read of every host in want, sorted by host
// ID, each with its body length. Hosts without a read are absent. It runs on
// q, so it sees the state of the caller's transaction.
func newestReads(ctx context.Context, q *sql.Tx, want map[string]bool) ([]sizedRead, error) {
	sizes := make(map[int64]int64)
	srows, err := q.QueryContext(ctx, latestSizesQuery)
	if err != nil {
		return nil, fmt.Errorf("newest read sizes: %w", err)
	}
	defer srows.Close()
	for srows.Next() {
		var id, n int64
		if err := srows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("newest read sizes: %w", err)
		}
		sizes[id] = n
	}
	if err := srows.Err(); err != nil {
		return nil, fmt.Errorf("newest read sizes: %w", err)
	}

	rows, err := q.QueryContext(ctx, latestAllQuery)
	if err != nil {
		return nil, fmt.Errorf("newest reads: %w", err)
	}
	defer rows.Close()
	var out []sizedRead
	for rows.Next() {
		r, err := scanRead(rows, false)
		if err != nil {
			return nil, fmt.Errorf("newest reads: %w", err)
		}
		if !want[r.HostID] {
			continue
		}
		n, ok := sizes[r.ID]
		if !ok {
			return nil, fmt.Errorf("newest reads: read %d has no body length", r.ID)
		}
		out = append(out, sizedRead{Read: r, bytes: n})
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
// taken less than maxReuse ago (a snapshot whose time lies in the future, after
// a backwards clock step, counts as expired). Otherwise a new snapshot is
// written with generation max(highest stored generation, floor) + 1, where
// floor is read from the GenerationFloor inside the transaction (see that
// type). A floor is a generation that a vulnstore run has seen: every
// generation Current returns is greater than it, so a run is never handed a
// snapshot at or below one it has seen (ADR 0011 D5). Generations never fall:
// the transaction is serialised within the process (snapshotMu) and by the
// database write lock. Hosts without a read are left out. Of the hosts with
// a read, the first MaxSnapshotHosts in host-ID order are kept and the bodies
// are limited to MaxSnapshotBodyBytes (see selectSnapshotReads); the hosts
// left out are counted in Omitted.
//
// Reads are returned without components; use Snapshot for the bodies.
func (s *Store) Current(ctx context.Context, hosts []string, maxReuse time.Duration, floor GenerationFloor) (Snapshot, error) {
	if maxReuse < 0 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w: negative max reuse", ErrInvalidRead)
	}
	if floor == nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w: nil generation floor", ErrInvalidRead)
	}
	want, err := wantedHosts(hosts)
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
	floorGen, err := floor.Generation(ctx, tx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: floor: %w", err)
	}
	if floorGen < 0 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w: negative floor", ErrInvalidRead)
	}

	latest, err := newestReads(ctx, tx, want)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	}
	reads, hostBytes, omitted := selectSnapshotReadsUsed(latest, MaxSnapshotHosts, MaxSnapshotBodyBytes)
	ids := make([]int64, 0, len(reads))
	for _, r := range reads {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)

	// The load is bounded by the cap itself, shared out per host in
	// round-robin order (see latestImagesQuery). The image bodies share the
	// budget that the host bodies left.
	newest, err := newestImages(ctx, tx, want, MaxSnapshotImages)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	}
	images, _ := selectSnapshotImages(newest, MaxSnapshotImages, MaxSnapshotBodyBytes-hostBytes)
	// Every image read that is not pinned is omitted, including those that
	// were never loaded, so the count is taken from the table.
	total, err := countImages(ctx, tx, want)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	}
	omittedImages := total - len(images)
	if omittedImages < 0 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: image count %d below pinned %d", total, len(images))
	}
	slices.SortFunc(images, func(a, b ImageRead) int {
		if c := strings.Compare(a.HostID, b.HostID); c != 0 {
			return c
		}
		return strings.Compare(a.Digest, b.Digest)
	})
	imgIDs := make([]int64, 0, len(images))
	for _, r := range images {
		imgIDs = append(imgIDs, r.ID)
	}
	slices.Sort(imgIDs)

	now := s.now().UTC()
	if snap, ok, err := reusable(ctx, tx, reads, ids, images, imgIDs, now, maxReuse, floorGen); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: %w", err)
	} else if ok {
		snap.Omitted = omitted
		snap.OmittedImages = omittedImages
		return snap, nil
	}

	var maxStored int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation), 0) FROM vuln_inventory_snapshots`).Scan(&maxStored); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: generation: %w", err)
	}
	top := max(maxStored, floorGen)
	if top == math.MaxInt64 {
		return Snapshot{}, fmt.Errorf("vulninventory: current: generation overflow")
	}
	gen := top + 1
	snap := Snapshot{
		ID:            snapshotIDPrefix + strconv.FormatInt(gen, 10),
		Generation:    gen,
		TakenAt:       time.Unix(now.Unix(), 0).UTC(),
		Reads:         reads,
		Omitted:       omitted,
		Images:        images,
		OmittedImages: omittedImages,
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
	for _, r := range images {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_inventory_snapshot_image_reads (snapshot_id, image_read_id) VALUES (?, ?)`,
			snap.ID, r.ID); err != nil {
			return Snapshot{}, fmt.Errorf("vulninventory: current: insert image member: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: current: commit: %w", err)
	}
	return snap, nil
}

// reusable returns the newest snapshot when it pins exactly ids and imageIDs
// (both sorted), was taken less than maxReuse before now, and its generation
// is above floor. A negative age (the clock went back past the snapshot)
// counts as expired, so a backwards clock step never extends reuse. The floor
// check is part of reuse: a snapshot at or below a generation that vulnstore
// has seen must never be handed out again (ADR 0011 D5). The snapshot's reads
// and images are reads and images.
func reusable(ctx context.Context, tx *sql.Tx, reads []Read, ids []int64, images []ImageRead, imageIDs []int64, now time.Time, maxReuse time.Duration, floor int64) (Snapshot, bool, error) {
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
	age := now.Sub(time.Unix(takenAt, 0).UTC())
	if snap.Generation <= floor || age < 0 || age >= maxReuse {
		return Snapshot{}, false, nil
	}
	members, err := memberIDs(ctx, tx, `SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ? ORDER BY read_id`, snap.ID)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("snapshot members: %w", err)
	}
	imageMembers, err := memberIDs(ctx, tx, `SELECT image_read_id FROM vuln_inventory_snapshot_image_reads WHERE snapshot_id = ? ORDER BY image_read_id`, snap.ID)
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("snapshot image members: %w", err)
	}
	if !slices.Equal(members, ids) || !slices.Equal(imageMembers, imageIDs) {
		return Snapshot{}, false, nil
	}
	snap.TakenAt = time.Unix(takenAt, 0).UTC()
	snap.Reads = reads
	snap.Images = images
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

	// The host and image bodies share one limit, checked before any body is
	// decoded, as Current bounds them.
	var total int64
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT COALESCE(SUM(LENGTH(body)), 0) FROM vuln_inventory_reads WHERE id IN (SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ?)) +
		(SELECT COALESCE(SUM(LENGTH(body)), 0) FROM vuln_image_reads WHERE id IN (SELECT image_read_id FROM vuln_inventory_snapshot_image_reads WHERE snapshot_id = ?))`,
		snap.ID, snap.ID).Scan(&total); err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: body bytes: %w", err)
	}
	if total > MaxSnapshotBodyBytes {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: bodies: %w: %d bytes, limit %d", ErrLimit, total, MaxSnapshotBodyBytes)
	}

	reads, err := loadSnapshotReads(ctx, tx, snap.ID, snapshotPageReads, MaxSnapshotBodyBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: %w", err)
	}
	images, err := loadSnapshotImages(ctx, tx, snap.ID, snapshotPageReads)
	if err != nil {
		return Snapshot{}, fmt.Errorf("vulninventory: snapshot: %w", err)
	}
	snap.Reads = reads
	snap.Images = images
	return snap, nil
}

// loadSnapshotImages returns the image reads pinned by snapshot id, with their
// packages, in (host ID, digest) order. It loads pageSize reads per query,
// keyset-paged on (host_id, digest, id). A body that does not decode is an
// error: the snapshot is not returned with that image missing.
func loadSnapshotImages(ctx context.Context, q *sql.Tx, id string, pageSize int) ([]ImageRead, error) {
	if pageSize <= 0 {
		return nil, fmt.Errorf("snapshot images: page size %d: must be positive", pageSize)
	}
	const members = `SELECT image_read_id FROM vuln_inventory_snapshot_image_reads WHERE snapshot_id = ?`
	var count int64
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM vuln_image_reads WHERE id IN (`+members+`)`, id).Scan(&count); err != nil {
		return nil, fmt.Errorf("snapshot image count: %w", err)
	}
	if count > MaxSnapshotImages {
		return nil, fmt.Errorf("snapshot images: %w: %d images, limit %d", ErrLimit, count, MaxSnapshotImages)
	}

	out := make([]ImageRead, 0, count)
	afterHost, afterDigest, afterID := "", "", int64(0)
	for {
		before := len(out)
		rows, err := q.QueryContext(ctx, `SELECT id, repository, digest, host_id, execution_id, read_at, complete,
			reason, os_family, os_name, body FROM vuln_image_reads
			WHERE id IN (`+members+`) AND (host_id, digest, id) > (?, ?, ?)
			ORDER BY host_id, digest, id LIMIT ?`, id, afterHost, afterDigest, afterID, pageSize)
		if err != nil {
			return nil, fmt.Errorf("snapshot images: %w", err)
		}
		for rows.Next() {
			var r ImageRead
			var readAt int64
			var complete int
			var body []byte
			if err := rows.Scan(&r.ID, &r.Repository, &r.Digest, &r.HostID, &r.ExecutionID, &readAt, &complete,
				&r.Reason, &r.OSFamily, &r.OSName, &body); err != nil {
				rows.Close()
				return nil, fmt.Errorf("snapshot images: %w", err)
			}
			r.ReadAt = time.Unix(readAt, 0).UTC()
			r.Complete = complete == 1
			pkgs, err := decodeImageBody(body)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("snapshot image %d: %w", r.ID, err)
			}
			r.Packages = pkgs
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("snapshot images: %w", err)
		}
		rows.Close()
		if len(out)-before < pageSize {
			return out, nil
		}
		last := out[len(out)-1]
		afterHost, afterDigest, afterID = last.HostID, last.Digest, last.ID
	}
}

// loadSnapshotReads returns the reads pinned by snapshot id, with their
// components, in host-ID order. Before any body is decoded it sums the stored
// body lengths and refuses a total above byteLimit with ErrLimit. Then it loads
// pageReads reads per query, keyset-paged on (host_id, id). Each page is
// decoded straight into the result slice, which is allocated once, from the
// read count, so no page is kept on its own and the slice is never copied to
// grow it.
func loadSnapshotReads(ctx context.Context, q *sql.Tx, id string, pageReads int, byteLimit int64) ([]Read, error) {
	if pageReads <= 0 {
		return nil, fmt.Errorf("snapshot reads: page size %d: must be positive", pageReads)
	}
	const members = `SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ?`
	var count, total int64
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(LENGTH(body)), 0) FROM vuln_inventory_reads WHERE id IN (`+members+`)`, id).Scan(&count, &total); err != nil {
		return nil, fmt.Errorf("snapshot body bytes: %w", err)
	}
	if total > byteLimit {
		return nil, fmt.Errorf("snapshot bodies: %w: %d bytes, limit %d", ErrLimit, total, byteLimit)
	}

	out := make([]Read, 0, min(count, MaxSnapshotHosts))
	afterHost, afterID := "", int64(0)
	for {
		before := len(out)
		var err error
		out, err = appendSnapshotPage(ctx, q, out, id, afterHost, afterID, pageReads)
		if err != nil {
			return nil, fmt.Errorf("snapshot reads: %w", err)
		}
		if len(out)-before < pageReads {
			return out, nil
		}
		last := out[len(out)-1]
		afterHost, afterID = last.HostID, last.ID
	}
}

// appendSnapshotPage appends up to limit reads of snapshot id that sort after
// (afterHost, afterID) in (host_id, id) order, with their components, to out.
func appendSnapshotPage(ctx context.Context, q *sql.Tx, out []Read, id, afterHost string, afterID int64, limit int) ([]Read, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+fullColumns+` FROM vuln_inventory_reads
		WHERE id IN (SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ?)
		AND (host_id, id) > (?, ?)
		ORDER BY host_id, id LIMIT ?`, id, afterHost, afterID, limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRead(rows, true)
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// PruneSnapshots deletes the snapshots taken more than maxAge ago, with their
// membership rows. The newest snapshot is always kept: its generation is the
// floor of the next one. The reads stay in the store (a read is deleted only
// under decision E1, which is not made here), so a pruned snapshot's reads are
// not lost by this call. Image reads are deleted when no snapshot pins them and
// they are beyond the ImageReadsKept newest of their host and digest; a pinned
// image read beyond that count stays until the snapshot that pins it is pruned.
// The caller passes the export's maximum age (vulnstore.MaxInventoryAge).
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
	cutoff := s.now().UTC().Add(-maxAge).Unix()
	const expired = `SELECT id FROM vuln_inventory_snapshots
		WHERE taken_at < ? AND generation < (SELECT MAX(generation) FROM vuln_inventory_snapshots)`
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_inventory_snapshot_reads WHERE snapshot_id IN (`+expired+`)`, cutoff); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: members: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_inventory_snapshot_image_reads WHERE snapshot_id IN (`+expired+`)`, cutoff); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: image members: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_inventory_snapshots
		WHERE taken_at < ? AND generation < (SELECT MAX(generation) FROM vuln_inventory_snapshots)`, cutoff); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: snapshots: %w", err)
	}
	// An image read is kept while a snapshot pins it or while it is one of
	// the ImageReadsKept newest of its host and digest. Once the expired
	// snapshots are gone, the older unpinned reads go.
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_image_reads WHERE id NOT IN (
		SELECT image_read_id FROM vuln_inventory_snapshot_image_reads)
		AND id NOT IN (SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY host_id, digest
			ORDER BY read_at DESC, id DESC) AS rn FROM vuln_image_reads) WHERE rn <= ?)`, ImageReadsKept); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: image reads: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vulninventory: prune snapshots: commit: %w", err)
	}
	return nil
}
