// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
)

// TestImageReplayOfGrantStoresOneRead checks that a replayed ObserveImage of
// one execution stores its read once: the second call is a duplicate and
// writes nothing (migration 0054).
func TestImageReplayOfGrantStoresOneRead(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, imageResult("debian", "12.8", "debian"))
	for range 3 {
		svc.ObserveImage(context.Background(), "host-1", execN(2))
	}
	if reads := storedReads(t, st, "host-1"); len(reads) != 1 {
		t.Fatalf("stored %d reads after three stores of one execution, want 1", len(reads))
	}
}

// TestImageReplayDoesNotPushOutKeptReads checks the failure the replay caused:
// with three kept reads, replays of the oldest execution must not fill the
// budget with copies and push out the reads of the other executions.
func TestImageReplayDoesNotPushOutKeptReads(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	for i := range vulninventory.ImageReadsKept {
		at := imgClock.Add(time.Duration(i) * time.Minute)
		grantRun(t, db, 10+i, "host-1", imgRef, at, imageResult("debian", "12.8", "debian"))
		svc.ObserveImage(context.Background(), "host-1", execN(10+i))
	}
	for range 5 {
		svc.ObserveImage(context.Background(), "host-1", execN(10))
	}
	reads := storedReads(t, st, "host-1")
	if len(reads) != vulninventory.ImageReadsKept {
		t.Fatalf("kept %d reads after replays, want %d", len(reads), vulninventory.ImageReadsKept)
	}
	for i, r := range reads {
		if want := imgClock.Add(time.Duration(vulninventory.ImageReadsKept-1-i) * time.Minute); !r.ReadAt.Equal(want) {
			t.Fatalf("kept read %d at %v, want %v", i, r.ReadAt, want)
		}
	}
}

// TestImageReadTakesResultFromStoredRun checks that the packages come from the
// result the grant's execution stored: a grant that stored no result stores no
// read, whatever the host returned to anyone else.
func TestImageReadTakesResultFromStoredRun(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
	svc.ObserveImage(context.Background(), "host-1", execN(2))
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads for a run with no stored result, want 0", len(reads))
	}
}

// TestImageReadRefusesOversizedStoredResult checks that a stored result larger
// than hostrun.MaxResult is not read at all.
func TestImageReadRefusesOversizedStoredResult(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	big := []byte(strings.Repeat("x", hostrun.MaxResult+1))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, big)
	svc.ObserveImage(context.Background(), "host-1", execN(2))
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads from an oversized result, want 0", len(reads))
	}
}

// TestInspectFinishedAfterReadDoesNotCount checks that an inspect which
// finished after the grant's finish time does not name the image for the read:
// the read is the state of the image at the grant, not after it. An inspect
// that finished exactly at the grant's finish time counts.
func TestInspectFinishedAfterReadDoesNotCount(t *testing.T) {
	cases := []struct {
		name   string
		finish time.Time
		stored bool
	}{
		{"inspect one second after the read", imgClock.Add(time.Second), false},
		{"inspect at the read time", imgClock, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, db := imageServer(t)
			inspectRun(t, db, 1, "host-1", tc.finish, inspectResult(imgHex))
			grantRun(t, db, 2, "host-1", imgRef, imgClock, imageResult("debian", "12.8", "debian"))
			svc.ObserveImage(context.Background(), "host-1", execN(2))
			if got := len(storedReads(t, st, "host-1")) == 1; got != tc.stored {
				t.Fatalf("stored = %v, want %v", got, tc.stored)
			}
		})
	}
}

// TestInspectAgeIsMeasuredFromGrant checks that ImageInspectMaxAge counts back
// from the grant's finish time, not from the time of the store. The grant
// finished two days before the store clock, and its inspect finished an hour
// before the grant: the read is stored, and it carries the grant's finish time.
func TestInspectAgeIsMeasuredFromGrant(t *testing.T) {
	svc, st, db := imageServer(t)
	grant := imgClock.Add(-48 * time.Hour)
	inspectRun(t, db, 1, "host-1", grant.Add(-time.Hour), inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, grant, imageResult("debian", "12.8", "debian"))
	svc.ObserveImage(context.Background(), "host-1", execN(2))
	reads := storedReads(t, st, "host-1")
	if len(reads) != 1 {
		t.Fatalf("stored %d reads, want 1", len(reads))
	}
	if !reads[0].ReadAt.Equal(grant) {
		t.Fatalf("read time %v, want the grant's finish time %v", reads[0].ReadAt, grant)
	}
}

// TestInspectLookupUsesHostIndex pins the plan of the docker.inspect lookup:
// it must start from the host's execution_hosts rows through the index of
// migration 0054, and must not walk the executions of the action.
func TestInspectLookupUsesHostIndex(t *testing.T) {
	_, _, db := imageServer(t)
	rows, err := db.Query("EXPLAIN QUERY PLAN "+inspectResultsQuery,
		"host-1", int64(1), int64(2), inspectActionID, hostrun.MaxResult, 500)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	// execution_hosts is the outer loop, searched through the host index; the
	// executions are then reached by ID (the covering action index is only a
	// point lookup per row), never scanned.
	if !strings.Contains(joined, "SEARCH h USING INDEX execution_hosts_inspect") {
		t.Fatalf("inspect lookup does not start from execution_hosts_inspect:\n%s", joined)
	}
	if strings.Contains(joined, "SCAN") {
		t.Fatalf("inspect lookup scans a table:\n%s", joined)
	}
}

// TestImageReadRefusedWhenInspectSinceGrantIsOld checks the window's lower
// bound with the grant as the reference: an inspect older than
// ImageInspectMaxAge before the grant does not name the image.
func TestImageReadRefusedWhenInspectSinceGrantIsOld(t *testing.T) {
	svc, st, db := imageServer(t)
	grant := imgClock.Add(-48 * time.Hour)
	inspectRun(t, db, 1, "host-1", grant.Add(-ImageInspectMaxAge-time.Minute), inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, grant, imageResult("debian", "12.8", "debian"))
	svc.ObserveImage(context.Background(), "host-1", execN(2))
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads with an inspect older than the bound, want 0", len(reads))
	}
}
