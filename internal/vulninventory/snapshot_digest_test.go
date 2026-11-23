// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"reflect"
	"testing"
)

// TestNewestImagesRoundRobinAcrossHosts checks the order and the bound of the
// image load Current makes: rows come round by round, so each host's newest
// digest is loaded before any host's second one, and the total never exceeds
// the limit. A digest that a host stopped reading is loaded only when its
// round is reached.
func TestNewestImagesRoundRobinAcrossHosts(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	ctx := context.Background()
	// host-1: digest a is oldest (read at 10), then b (11) and c (12).
	mustPutImage(t, s, testImageReadOn("host-1", imgRepo, 10))
	for _, c := range []struct {
		digest string
		at     int64
	}{{"b", 11}, {"c", 12}} {
		r := testImageReadOn("host-1", imgRepo, c.at)
		r.Digest = imgDigest(c.digest)
		mustPutImage(t, s, r)
	}
	mustPutImage(t, s, testImageReadOn("host-2", imgRepo, 5))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	type key struct{ host, digest string }
	load := func(limit int) []key {
		t.Helper()
		got, err := newestImages(ctx, tx, map[string]bool{"host-1": true, "host-2": true}, limit)
		if err != nil {
			t.Fatalf("newestImages: %v", err)
		}
		var keys []key
		for _, r := range got {
			keys = append(keys, key{r.HostID, r.Digest})
		}
		return keys
	}
	// Round one is the newest digest of each host, round two the next one:
	// host-1 c (12) and host-2 a (5) come before host-1 b (11).
	if got, want := load(3), []key{
		{"host-1", imgDigest("c")},
		{"host-2", imgDigest("a")},
		{"host-1", imgDigest("b")},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded %v, want %v in round-robin order", got, want)
	}
	// With a limit of two the second round is not loaded, and the old digest a
	// of host-1 is never loaded at all.
	if got, want := load(2), []key{
		{"host-1", imgDigest("c")},
		{"host-2", imgDigest("a")},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded %v with limit 2, want %v", got, want)
	}
}

// TestCountImagesCountsDistinctDigestsOfWantedHosts checks the exact count
// that OmittedImages is computed from: one per (host, digest) of the wanted
// hosts, whatever the load limit.
func TestCountImagesCountsDistinctDigestsOfWantedHosts(t *testing.T) {
	s, db := openStore(t)
	useClock(t, s)
	ctx := context.Background()
	mustPutImage(t, s, testImageReadOn("host-1", imgRepo, 10))
	for _, c := range []struct {
		digest string
		at     int64
	}{{"b", 11}, {"c", 12}} {
		r := testImageReadOn("host-1", imgRepo, c.at)
		r.Digest = imgDigest(c.digest)
		mustPutImage(t, s, r)
	}
	mustPutImage(t, s, testImageReadOn("host-2", imgRepo, 5))
	mustPutImage(t, s, testImageReadOn("host-3", imgRepo, 5))

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	got, err := countImages(ctx, tx, map[string]bool{"host-1": true, "host-2": true})
	if err != nil {
		t.Fatalf("countImages: %v", err)
	}
	if got != 4 {
		t.Fatalf("countImages = %d, want 4 (host-1 has three digests, host-2 one; host-3 is not wanted)", got)
	}
}
