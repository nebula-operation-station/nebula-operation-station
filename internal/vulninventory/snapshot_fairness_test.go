// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// insertImageBodies stores n image reads on host with distinct digests, read
// at base+i seconds, and bodies of size bytes. The bodies come from zeroblob,
// so no body is built in Go. Current reads only the body length, so the bodies
// need not decode; Snapshot would refuse them, and these tests do not call it.
func insertImageBodies(t *testing.T, db *sql.DB, host string, n int, size int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id,
		read_at, complete, reason, os_family, os_name, packages, body)
		VALUES (?, ?, ?, ?, ?, 1, '', '', '', 0, zeroblob(?))`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for i := 0; i < n; i++ {
		if _, err := stmt.ExecContext(ctx, imgRepo, fmt.Sprintf("sha256:%064x", i), host,
			fmt.Sprintf("exec-%s-%d", host, i), base.Unix()+int64(i), size); err != nil {
			t.Fatalf("insert image %d on %s: %v", i, host, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// pinnedCount returns how many images of snap are on host.
func pinnedCount(snap Snapshot, host string) int {
	n := 0
	for _, r := range snap.Images {
		if r.HostID == host {
			n++
		}
	}
	return n
}

// TestCurrentHostileHostDoesNotEvictSecondHostImages checks the fair share of
// the image count cap. Host-00 has the lowest host ID and 3000 digests, which
// is more than MaxSnapshotImages; host-01 has one image. Filling the cap in
// host-ID order would leave host-01's image out of the snapshot. With a share
// per host, host-01 keeps its image and host-00 gets the rest of the cap.
func TestCurrentHostileHostDoesNotEvictSecondHostImages(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	insertImageBodies(t, db, "host-00", 3000, 2)
	insertImageBodies(t, db, "host-01", 1, 2)

	snap := mustCurrent(t, s, []string{"host-00", "host-01"}, 0, 0)
	if got := pinnedCount(snap, "host-01"); got != 1 {
		t.Fatalf("host-01 pinned %d images, want its one image in the snapshot", got)
	}
	if got := pinnedCount(snap, "host-00"); got != MaxSnapshotImages-1 {
		t.Fatalf("host-00 pinned %d images, want %d (the cap minus host-01's image)", got, MaxSnapshotImages-1)
	}
	if len(snap.Images) != MaxSnapshotImages {
		t.Fatalf("pinned %d images, want MaxSnapshotImages = %d", len(snap.Images), MaxSnapshotImages)
	}
	if want := 3001 - MaxSnapshotImages; snap.OmittedImages != want {
		t.Fatalf("OmittedImages = %d, want %d", snap.OmittedImages, want)
	}
}

// TestCurrentOmitsExactlyTheImagesNotKept checks OmittedImages on a host with
// 3000 digests: the snapshot keeps MaxSnapshotImages and the count of the rest
// is exact, not the number of digests Current happened to load.
func TestCurrentOmitsExactlyTheImagesNotKept(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	insertImageBodies(t, db, "host-1", 3000, 2)

	snap := mustCurrent(t, s, []string{"host-1"}, 0, 0)
	if len(snap.Images) != MaxSnapshotImages {
		t.Fatalf("pinned %d images, want %d", len(snap.Images), MaxSnapshotImages)
	}
	if want := 3000 - MaxSnapshotImages; snap.OmittedImages != want {
		t.Fatalf("OmittedImages = %d, want %d", snap.OmittedImages, want)
	}
}

// TestCurrentOmittedImagesCountsDigestsOfEveryWantedHost checks that
// OmittedImages sums the digests of all wanted hosts, not only those Current
// loads. Two hosts with 2000 digests each keep 2000 images and omit 2000.
func TestCurrentOmittedImagesCountsDigestsOfEveryWantedHost(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	insertImageBodies(t, db, "host-1", 2000, 2)
	insertImageBodies(t, db, "host-2", 2000, 2)

	snap := mustCurrent(t, s, []string{"host-1", "host-2"}, 0, 0)
	if len(snap.Images) != MaxSnapshotImages {
		t.Fatalf("pinned %d images, want %d", len(snap.Images), MaxSnapshotImages)
	}
	if snap.OmittedImages != 2000 {
		t.Fatalf("OmittedImages = %d, want 2000", snap.OmittedImages)
	}
}

// TestNewestImagesLoadsAtMostTheLimit checks the load bound: newestImages
// returns at most the limit it is given in total, not per host, so a load of
// MaxSnapshotImages rows is never more than the snapshot cap, however many
// hosts and digests there are. Host-01 has 3000 digests and host-02 one; the
// one of host-02 is in the first round and so is loaded.
func TestNewestImagesLoadsAtMostTheLimit(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	insertImageBodies(t, db, "host-01", 3000, 2)
	insertImageBodies(t, db, "host-02", 1, 2)

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	got, err := newestImages(context.Background(), tx, map[string]bool{"host-01": true, "host-02": true}, MaxSnapshotImages)
	if err != nil {
		t.Fatalf("newestImages: %v", err)
	}
	if len(got) != MaxSnapshotImages {
		t.Fatalf("loaded %d images, want exactly the limit %d", len(got), MaxSnapshotImages)
	}
	var hostTwo int
	for _, r := range got {
		if r.HostID == "host-02" {
			hostTwo++
		}
	}
	if hostTwo != 1 {
		t.Fatalf("loaded %d images of host-02, want its one image", hostTwo)
	}
}
