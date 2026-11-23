// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// mustPutImage stores r and returns its row ID, failing the test on error.
func mustPutImage(t *testing.T, s *Store, r ImageRead) int64 {
	t.Helper()
	id, err := s.PutImage(context.Background(), r)
	if err != nil {
		t.Fatalf("PutImage(%s, %s, %s): %v", r.HostID, r.Digest, r.ExecutionID, err)
	}
	return id
}

// imageIDs returns the image row IDs of snap in order.
func imageIDs(snap Snapshot) []int64 {
	ids := make([]int64, 0, len(snap.Images))
	for _, r := range snap.Images {
		ids = append(ids, r.ID)
	}
	return ids
}

// sizedImageOf is the newest image read of a (host, digest) with the stored
// length of its body, as Current sees it.
func sizedImageOf(id int64, host, digest string, n int64) sizedImage {
	return sizedImage{ImageRead: ImageRead{ID: id, HostID: host, Digest: digest}, bytes: n}
}

// TestCurrentPinsNewestImageReadPerHostAndDigest checks that Current pins, for
// each (host, digest) of the wanted hosts, the newest image read, in host-ID
// then digest order, and that images of other hosts are left out.
func TestCurrentPinsNewestImageReadPerHostAndDigest(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
	idA10 := mustPutImage(t, s, testImageReadOn("host-1", imgRepo, 10))
	idA11 := mustPutImage(t, s, testImageReadOn("host-1", "web", 11))
	b := testImageReadOn("host-1", imgRepo, 5)
	b.Digest = imgDigest("b")
	idB5 := mustPutImage(t, s, b)
	idH2 := mustPutImage(t, s, testImageReadOn("host-2", imgRepo, 7))
	mustPutImage(t, s, testImageReadOn("host-3", imgRepo, 9))

	snap := mustCurrent(t, s, []string{"host-2", "host-1"}, 0, 0)
	want := []int64{idA11, idB5, idH2}
	if got := imageIDs(snap); !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned images %v, want %v (newest per host and digest, host-ID then digest order)", got, want)
	}
	for _, r := range snap.Images {
		if r.ID == idA10 {
			t.Errorf("older read %d of host-1 digest a is pinned, want only the newest", idA10)
		}
		if r.Packages != nil {
			t.Errorf("Current returned packages for image read %d; Current returns images without packages", r.ID)
		}
	}
	if snap.OmittedImages != 0 {
		t.Errorf("OmittedImages = %d, want 0", snap.OmittedImages)
	}
}

// TestSnapshotKeepsPinnedImageReadAfterFourthRead checks that a snapshot stays
// immutable for its ID: a fourth read of the same image pushes the pinned
// read out of the three kept reads, but Snapshot still returns it with its
// packages, and the store keeps the pinned row.
func TestSnapshotKeepsPinnedImageReadAfterFourthRead(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	ctx := context.Background()
	pinned := mustPutImage(t, s, testImageRead(imgRepo, 10))
	snap := mustCurrent(t, s, []string{"host-1"}, 0, 0)
	if got := imageIDs(snap); !reflect.DeepEqual(got, []int64{pinned}) {
		t.Fatalf("pinned %v, want [%d]", got, pinned)
	}
	before, err := s.Snapshot(ctx, snap.ID)
	if err != nil {
		t.Fatalf("Snapshot before fourth read: %v", err)
	}
	for _, at := range []int64{11, 12, 13} {
		mustPutImage(t, s, testImageRead(imgRepo, at))
	}
	after, err := s.Snapshot(ctx, snap.ID)
	if err != nil {
		t.Fatalf("Snapshot after fourth read: %v", err)
	}
	if !reflect.DeepEqual(before.Images, after.Images) {
		t.Fatalf("snapshot %s changed after a new image read:\nbefore %+v\nafter  %+v", snap.ID, before.Images, after.Images)
	}
	if len(after.Images) != 1 || after.Images[0].ID != pinned {
		t.Fatalf("snapshot images %v, want [%d]", imageIDs(after), pinned)
	}
	if len(after.Images[0].Packages) != 1 || after.Images[0].Packages[0].Name != "libc6" {
		t.Fatalf("pinned image lost its packages: %+v", after.Images[0].Packages)
	}
	kept, err := s.ImageReads(ctx, "host-1", imgDigest("a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != ImageReadsKept {
		t.Fatalf("kept %d reads of host-1 digest a, want %d", len(kept), ImageReadsKept)
	}
	for i, want := range []int64{13, 12, 11} {
		if got := kept[i].ReadAt.Unix() - base.Unix(); got != want {
			t.Errorf("kept read %d at %d, want %d", i, got, want)
		}
	}
	if n := rowCountTable(t, db, "vuln_image_reads"); n != 4 {
		t.Fatalf("image rows = %d, want 4 (three kept reads and the pinned one)", n)
	}
	mustPutImage(t, s, testImageRead(imgRepo, 14))
	if n := rowCountTable(t, db, "vuln_image_reads"); n != 4 {
		t.Fatalf("image rows after fifth read = %d, want 4", n)
	}
	again, err := s.Snapshot(ctx, snap.ID)
	if err != nil || !reflect.DeepEqual(before.Images, again.Images) {
		t.Fatalf("snapshot after fifth read: err %v, images %+v", err, again.Images)
	}
}

// TestPinnedImageReadIsDeletedOnlyByPruneSnapshots checks that a pinned image
// read survives PutImage and is deleted only after PruneSnapshots has removed
// the snapshot that pins it, while the three newest reads are never deleted.
func TestPinnedImageReadIsDeletedOnlyByPruneSnapshots(t *testing.T) {
	s, db := openStore(t)
	c := useClock(t, s)
	ctx := context.Background()
	for _, at := range []int64{10, 11} {
		mustPutImage(t, s, testImageRead(imgRepo, at))
	}
	pinned := mustPutImage(t, s, testImageRead(imgRepo, 12))
	old := mustCurrent(t, s, []string{"host-1"}, 0, 0)
	if got := imageIDs(old); !reflect.DeepEqual(got, []int64{pinned}) {
		t.Fatalf("first snapshot pins %v, want [%d]", got, pinned)
	}
	for _, at := range []int64{13, 14, 15} {
		mustPutImage(t, s, testImageRead(imgRepo, at))
	}
	if n := imageRowExists(t, db, pinned); n != 1 {
		t.Fatalf("pinned read %d deleted by PutImage", pinned)
	}

	c.t = base.Add(2 * time.Hour)
	newest := mustCurrent(t, s, []string{"host-1"}, 0, 0)
	if len(newest.Images) != 1 || newest.Images[0].ReadAt.Unix() != base.Unix()+15 {
		t.Fatalf("newest snapshot pins %v, want the read at 15", imageIDs(newest))
	}
	if n := imageRowExists(t, db, pinned); n != 1 {
		t.Fatalf("pinned read %d deleted before PruneSnapshots", pinned)
	}

	if err := s.PruneSnapshots(ctx, time.Hour); err != nil {
		t.Fatalf("PruneSnapshots: %v", err)
	}
	if _, err := s.Snapshot(ctx, old.ID); !errors.Is(err, ErrSnapshotGone) {
		t.Fatalf("pruned snapshot: err %v, want ErrSnapshotGone", err)
	}
	if n := imageRowExists(t, db, pinned); n != 0 {
		t.Fatalf("read %d still stored after its snapshot was pruned", pinned)
	}
	kept, err := s.ImageReads(ctx, "host-1", imgDigest("a"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int64{15, 14, 13} {
		if len(kept) != ImageReadsKept || kept[i].ReadAt.Unix() != base.Unix()+want {
			t.Fatalf("kept reads after prune: %d reads, want 15, 14, 13 newest first", len(kept))
		}
	}
	if n := rowCountTable(t, db, "vuln_image_reads"); n != ImageReadsKept {
		t.Fatalf("image rows after prune = %d, want %d", n, ImageReadsKept)
	}
	if got, err := s.Snapshot(ctx, newest.ID); err != nil || len(got.Images) != 1 {
		t.Fatalf("newest snapshot after prune: err %v, images %v", err, imageIDs(got))
	}
}

// imageRowExists returns 1 when vuln_image_reads holds row id, else 0.
func imageRowExists(t *testing.T, db *sql.DB, id int64) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_image_reads WHERE id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestMaxSnapshotImagesCountsOmittedImages checks the image cap: a snapshot
// holds MaxSnapshotImages images, in (host, digest) order, and counts the rest
// in OmittedImages. Its images are readable again by Snapshot.
func TestMaxSnapshotImagesCountsOmittedImages(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id,
		read_at, complete, reason, os_family, os_name, packages, body)
		VALUES (?, ?, 'host-1', ?, ?, 1, '', '', '', 0, CAST('[]' AS BLOB))`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxSnapshotImages+1; i++ {
		if _, err := stmt.ExecContext(ctx, imgRepo, fmt.Sprintf("sha256:%064x", i),
			fmt.Sprintf("exec-%d", i), base.Unix()+int64(i)); err != nil {
			t.Fatalf("insert image %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	snap := mustCurrent(t, s, []string{"host-1"}, 0, 0)
	if len(snap.Images) != MaxSnapshotImages {
		t.Fatalf("pinned %d images, want MaxSnapshotImages = %d", len(snap.Images), MaxSnapshotImages)
	}
	if snap.OmittedImages != 1 {
		t.Fatalf("OmittedImages = %d, want 1", snap.OmittedImages)
	}
	// The omitted image is the oldest read of the host, digest 0 here, so the
	// snapshot keeps the newest reads.
	old := fmt.Sprintf("sha256:%064x", 0)
	newest := fmt.Sprintf("sha256:%064x", MaxSnapshotImages)
	var hasOld, hasNewest bool
	for _, r := range snap.Images {
		hasOld = hasOld || r.Digest == old
		hasNewest = hasNewest || r.Digest == newest
	}
	if hasOld {
		t.Errorf("the oldest digest was pinned; the omitted one must be the oldest read")
	}
	if !hasNewest {
		t.Errorf("the newest digest was not pinned")
	}
	got, err := s.Snapshot(ctx, snap.ID)
	if err != nil {
		t.Fatalf("Snapshot of a full image set: %v", err)
	}
	if len(got.Images) != MaxSnapshotImages || got.OmittedImages != 0 {
		t.Fatalf("Snapshot returned %d images, OmittedImages %d", len(got.Images), got.OmittedImages)
	}
}

// TestSelectSnapshotImages checks the image selection on its own: the count
// cap and the byte budget that the image bodies share with the host reads.
func TestSelectSnapshotImages(t *testing.T) {
	d := imgDigest("a")
	cases := []struct {
		name     string
		latest   []sizedImage
		maxCount int
		maxBytes int64
		wantIDs  []int64
		wantLeft int
	}{
		{"all kept within limits", []sizedImage{sizedImageOf(1, "a", d, 3), sizedImageOf(2, "b", d, 4)}, 10, 10, []int64{1, 2}, 0},
		{"count cap keeps the first images in order", []sizedImage{sizedImageOf(1, "a", d, 1), sizedImageOf(2, "b", d, 1), sizedImageOf(3, "c", d, 1)}, 2, 100, []int64{1, 2}, 1},
		{"byte budget skips an image that does not fit and keeps later ones", []sizedImage{sizedImageOf(1, "a", d, 6), sizedImageOf(2, "b", d, 5), sizedImageOf(3, "c", d, 4)}, 10, 10, []int64{1, 3}, 1},
		{"an image larger than the remaining budget is omitted", []sizedImage{sizedImageOf(1, "a", d, 11)}, 10, 10, []int64{}, 1},
		{"no budget left omits every image", []sizedImage{sizedImageOf(1, "a", d, 1)}, 10, 0, []int64{}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, left := selectSnapshotImages(tc.latest, tc.maxCount, tc.maxBytes)
			if left != tc.wantLeft {
				t.Fatalf("omitted = %d, want %d", left, tc.wantLeft)
			}
			if len(got) > tc.maxCount {
				t.Fatalf("kept %d images, cap %d", len(got), tc.maxCount)
			}
			var sum int64
			for _, r := range got {
				for _, s := range tc.latest {
					if s.ID == r.ID {
						sum += s.bytes
					}
				}
			}
			if sum > tc.maxBytes {
				t.Fatalf("kept bodies %d bytes, budget %d", sum, tc.maxBytes)
			}
			if ids := imageIDs(Snapshot{Images: got}); !reflect.DeepEqual(ids, tc.wantIDs) {
				t.Fatalf("kept IDs = %v, want %v", ids, tc.wantIDs)
			}
		})
	}
}

// TestCurrentReusesOnlyWhilePinnedImageReadsAreEqual checks the reuse rule: a
// snapshot is reused only when it pins the same host reads and the same image
// reads; a new image read starts the next generation.
func TestCurrentReusesOnlyWhilePinnedImageReadsAreEqual(t *testing.T) {
	s, _ := openStore(t)
	useClock(t, s)
	mustPutImage(t, s, testImageRead(imgRepo, 10))
	first := mustCurrent(t, s, []string{"host-1"}, time.Hour, 0)
	again := mustCurrent(t, s, []string{"host-1"}, time.Hour, 0)
	if again.ID != first.ID {
		t.Fatalf("same pins gave %s, want the reused %s", again.ID, first.ID)
	}
	mustPutImage(t, s, testImageRead(imgRepo, 11))
	next := mustCurrent(t, s, []string{"host-1"}, time.Hour, 0)
	if next.ID == first.ID || next.Generation <= first.Generation {
		t.Fatalf("new image read gave %s (generation %d), want a new generation after %s (%d)",
			next.ID, next.Generation, first.ID, first.Generation)
	}
	if len(next.Images) != 1 || next.Images[0].ReadAt.Unix() != base.Unix()+11 {
		t.Fatalf("new snapshot pins %v, want the read at 11", imageIDs(next))
	}
}

// TestSnapshotRefusesUndecodableImageBody checks that a stored image body that
// does not decode is an error, not an empty image.
func TestSnapshotRefusesUndecodableImageBody(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id,
		read_at, complete, reason, os_family, os_name, packages, body)
		VALUES (?, ?, 'host-bad', 'exec-bad', ?, 1, '', '', '', 0, CAST(? AS BLOB))`,
		imgRepo, imgDigest("a"), base.Unix(), `[{"ecosystem":`); err != nil {
		t.Fatalf("insert fixture: %v", err)
	}
	snap := mustCurrent(t, s, []string{"host-bad"}, 0, 0)
	if len(snap.Images) != 1 {
		t.Fatalf("Current pinned %d images, want 1", len(snap.Images))
	}
	got, err := s.Snapshot(ctx, snap.ID)
	if err == nil {
		t.Fatalf("Snapshot with an undecodable image body returned %d images, want an error", len(got.Images))
	}
	if errors.Is(err, ErrSnapshotGone) {
		t.Fatalf("Snapshot: %v, want a decode error", err)
	}
}

// TestPinnedImageReadCannotBeDeletedBySQL checks that the pin table holds the
// image read: a SQL delete of a pinned row is refused (ON DELETE RESTRICT).
func TestPinnedImageReadCannotBeDeletedBySQL(t *testing.T) {
	s, db := openStore(t)
	id := mustPutImage(t, s, testImageRead(imgRepo, 10))
	mustCurrent(t, s, []string{"host-1"}, 0, 0)
	if _, err := db.Exec(`DELETE FROM vuln_image_reads WHERE id = ?`, id); err == nil {
		t.Fatal("deleting a pinned image read succeeded; want the pin to restrict it")
	}
	if n := imageRowExists(t, db, id); n != 1 {
		t.Fatalf("pinned read %d was deleted", id)
	}
}

// TestSnapshotImageMigrationAddsPinTableAndIndex checks migration 0056: the
// pin table exists with its index on image_read_id, and the migration has no
// other statements than the table and the index (it is additive).
func TestSnapshotImageMigrationAddsPinTableAndIndex(t *testing.T) {
	raw, err := os.ReadFile("../serverdb/migrations/0056_vuln_snapshot_image_reads.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, want := range []string{
		"CREATE TABLE vuln_inventory_snapshot_image_reads",
		"REFERENCES vuln_inventory_snapshots (id) ON DELETE CASCADE",
		"REFERENCES vuln_image_reads (id) ON DELETE RESTRICT",
		"PRIMARY KEY (snapshot_id, image_read_id)",
		"CREATE INDEX vuln_inventory_snapshot_image_reads_read ON vuln_inventory_snapshot_image_reads (image_read_id)",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration 0056 lacks %q", want)
		}
	}
	// Only statements count: the comment lines explain the rules in words.
	var stmts []string
	for _, line := range strings.Split(sql, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			stmts = append(stmts, line)
		}
	}
	// ON DELETE CASCADE and ON DELETE RESTRICT are part of the foreign keys,
	// not a DELETE statement.
	code := strings.ReplaceAll(strings.ToUpper(strings.Join(stmts, "\n")), "ON DELETE", "ON")
	for _, banned := range []string{"DROP", "ALTER", "UPDATE", "DELETE"} {
		if strings.Contains(code, banned) {
			t.Errorf("migration 0056 contains %q; it must be additive", banned)
		}
	}
	_, db := openStore(t)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`,
		"vuln_inventory_snapshot_image_reads_read").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("index on image_read_id not present after migrations")
	}
}

// insertHostReadBody stores a host read of host whose body is n zero bytes. The
// body comes from zeroblob, so no body of that size is built in Go. Current and
// the byte sums read only the body length, so the body need not decode.
func insertHostReadBody(t *testing.T, db *sql.DB, host string, n int64) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason,
		dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
		VALUES (?, ?, ?, 1, '', 0, '', '', '', '', '', 0, 0, zeroblob(?))`, host, "exec-"+host, base.Unix(), n)
	if err != nil {
		t.Fatalf("insert host read of %s with %d bytes: %v", host, n, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// insertImageRows stores n image reads on host-1 with distinct digests and the
// smallest valid body, "[]", and returns their row IDs in digest order.
func insertImageRows(t *testing.T, db *sql.DB, n int) []int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id,
		read_at, complete, reason, os_family, os_name, packages, body)
		VALUES (?, ?, 'host-1', ?, ?, 1, '', '', '', 0, CAST('[]' AS BLOB))`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		res, err := stmt.ExecContext(ctx, imgRepo, fmt.Sprintf("sha256:%064x", i),
			fmt.Sprintf("exec-%d", i), base.Unix()+int64(i))
		if err != nil {
			t.Fatalf("insert image %d: %v", i, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ids
}

// pinSnapshotRows stores a snapshot with the given ID and generation and pins
// the given reads and images. It writes through SQL, without the budget or the
// limits Current applies, so a test can hold a stored snapshot that Current
// would never return.
func pinSnapshotRows(t *testing.T, db *sql.DB, id string, generation int64, reads, images []int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_inventory_snapshots (id, generation, taken_at) VALUES (?, ?, ?)`,
		id, generation, base.Unix()); err != nil {
		t.Fatalf("insert snapshot %s: %v", id, err)
	}
	for _, r := range reads {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES (?, ?)`, id, r); err != nil {
			t.Fatalf("pin read %d: %v", r, err)
		}
	}
	for _, r := range images {
		if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_inventory_snapshot_image_reads (snapshot_id, image_read_id) VALUES (?, ?)`, id, r); err != nil {
			t.Fatalf("pin image %d: %v", r, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// snapshotBodyBytes returns the stored body bytes that snapshot id pins, host
// and image bodies together: the sum that Current and Snapshot bound by
// MaxSnapshotBodyBytes.
func snapshotBodyBytes(t *testing.T, db *sql.DB, id string) int64 {
	t.Helper()
	var total int64
	if err := db.QueryRow(`SELECT
		(SELECT COALESCE(SUM(LENGTH(body)), 0) FROM vuln_inventory_reads WHERE id IN (SELECT read_id FROM vuln_inventory_snapshot_reads WHERE snapshot_id = ?)) +
		(SELECT COALESCE(SUM(LENGTH(body)), 0) FROM vuln_image_reads WHERE id IN (SELECT image_read_id FROM vuln_inventory_snapshot_image_reads WHERE snapshot_id = ?))`,
		id, id).Scan(&total); err != nil {
		t.Fatalf("body bytes of %s: %v", id, err)
	}
	return total
}

// TestCurrentImageBodiesShareTheByteBudget is the end-to-end check of the byte
// budget that Current shares between host and image bodies. Sixteen host reads
// of MaxBodyBytes fill MaxSnapshotBodyBytes exactly, so no image body fits: the
// image must be omitted and counted in OmittedImages, and the stored snapshot
// must hold at most MaxSnapshotBodyBytes, or Snapshot would refuse its ID with
// ErrLimit. Passing the full MaxSnapshotBodyBytes to the image selection pins
// the image and fails this test.
func TestCurrentImageBodiesShareTheByteBudget(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	var hosts []string
	for i := 0; i < 16; i++ {
		h := fmt.Sprintf("host-%02d", i)
		hosts = append(hosts, h)
		insertHostReadBody(t, db, h, MaxBodyBytes)
	}
	hosts = append(hosts, "img-host")
	mustPutImage(t, s, testImageReadOn("img-host", imgRepo, 10))

	snap := mustCurrent(t, s, hosts, 0, 0)
	if len(snap.Reads) != 16 {
		t.Fatalf("pinned %d host reads, want 16", len(snap.Reads))
	}
	if len(snap.Images) != 0 || snap.OmittedImages != 1 {
		t.Fatalf("pinned %d images, OmittedImages %d; want 0 pinned and 1 omitted, the host bodies fill the budget",
			len(snap.Images), snap.OmittedImages)
	}
	if got := snapshotBodyBytes(t, db, snap.ID); got > MaxSnapshotBodyBytes {
		t.Fatalf("stored snapshot %s holds %d body bytes, limit %d: Snapshot would refuse its ID with ErrLimit",
			snap.ID, got, MaxSnapshotBodyBytes)
	}
}

// TestSnapshotRefusesHostAndImageBodiesAboveLimit checks the combined bound in
// Snapshot: host and image bodies of one snapshot share MaxSnapshotBodyBytes.
// Sixteen host bodies of MaxBodyBytes fill the limit, so the host bodies alone
// pass the host check; one image body on top must be refused with ErrLimit
// before any body is decoded.
func TestSnapshotRefusesHostAndImageBodiesAboveLimit(t *testing.T) {
	s, db := openStore(t)
	var reads []int64
	for i := 0; i < 16; i++ {
		reads = append(reads, insertHostReadBody(t, db, fmt.Sprintf("host-%02d", i), MaxBodyBytes))
	}
	images := insertImageRows(t, db, 1)
	pinSnapshotRows(t, db, "nos-inv-1", 1, reads, images)
	if got, want := snapshotBodyBytes(t, db, "nos-inv-1"), int64(MaxSnapshotBodyBytes)+2; got != want {
		t.Fatalf("fixture holds %d body bytes, want %d", got, want)
	}

	_, err := s.Snapshot(context.Background(), "nos-inv-1")
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("Snapshot with host and image bodies above the limit: err %v, want ErrLimit", err)
	}
}

// TestSnapshotRefusesMoreImagesThanMaxSnapshotImages checks the image count in
// Snapshot. Current never pins more than MaxSnapshotImages, so the snapshots
// are pinned through SQL: MaxSnapshotImages+1 image reads are refused with
// ErrLimit, and exactly MaxSnapshotImages are accepted.
func TestSnapshotRefusesMoreImagesThanMaxSnapshotImages(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	images := insertImageRows(t, db, MaxSnapshotImages+1)
	pinSnapshotRows(t, db, "nos-inv-1", 1, nil, images)
	pinSnapshotRows(t, db, "nos-inv-2", 2, nil, images[:MaxSnapshotImages])

	if _, err := s.Snapshot(ctx, "nos-inv-1"); !errors.Is(err, ErrLimit) {
		t.Fatalf("Snapshot of %d images: err %v, want ErrLimit", len(images), err)
	}
	got, err := s.Snapshot(ctx, "nos-inv-2")
	if err != nil {
		t.Fatalf("Snapshot of MaxSnapshotImages images: %v", err)
	}
	if len(got.Images) != MaxSnapshotImages {
		t.Fatalf("Snapshot returned %d images, want %d", len(got.Images), MaxSnapshotImages)
	}
}
