// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestImageReplayOfExecutionIsNotStored checks that one execution of one host
// is stored at most once: a replay of the same execution (a retried or
// replayed ObserveImage) is refused with ErrDuplicateRead, writes no row and
// runs no retention, so the kept reads are not pushed out by copies of one
// read. The replay is refused whatever its read time or digest.
func TestImageReplayOfExecutionIsNotStored(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	for _, at := range []int64{1, 2, 3} {
		if _, err := s.PutImage(ctx, testImageRead(imgRepo, at)); err != nil {
			t.Fatalf("put read %d: %v", at, err)
		}
	}
	replays := []ImageRead{
		testImageRead(imgRepo, 3),
		testImageRead(imgRepo, 3),
		testImageRead(imgRepo, 3),
	}
	later := testImageRead(imgRepo, 9)
	later.ExecutionID = "exec-3"
	replays = append(replays, later)
	for i, r := range replays {
		id, err := s.PutImage(ctx, r)
		if !errors.Is(err, ErrDuplicateRead) {
			t.Fatalf("replay %d: err = %v, want ErrDuplicateRead", i, err)
		}
		if id != 0 {
			t.Fatalf("replay %d: id = %d, want 0", i, id)
		}
	}
	reads, err := s.ImageReads(ctx, "host-1", imgDigest("a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != ImageReadsKept {
		t.Fatalf("kept %d reads after replays, want %d", len(reads), ImageReadsKept)
	}
	oldest := base.Add(time.Second)
	if !reads[len(reads)-1].ReadAt.Equal(oldest) {
		t.Fatalf("oldest kept read at %v, want %v: a replay pushed it out", reads[len(reads)-1].ReadAt, oldest)
	}
}

// TestImageReadOfSameExecutionOnAnotherHostIsStored checks that the key is
// the host and the execution: one execution id on two hosts stores one read on
// each.
func TestImageReadOfSameExecutionOnAnotherHostIsStored(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	if _, err := s.PutImage(ctx, testImageRead(imgRepo, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutImage(ctx, testImageReadOn("host-2", imgRepo, 1)); err != nil {
		t.Fatalf("same execution on host-2: %v", err)
	}
}
