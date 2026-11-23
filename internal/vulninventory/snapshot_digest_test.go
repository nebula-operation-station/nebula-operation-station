// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"reflect"
	"testing"
)

// TestNewestImagesLoadsOnlyTheNewestDigestsPerHost checks the bound on the
// image metadata that Current loads: per host, only the perHost digests whose
// newest read is most recent are loaded. A digest that the host stopped
// reading is not loaded once perHost newer digests exist, and the bound is per
// host, so another host keeps its own digests.
func TestNewestImagesLoadsOnlyTheNewestDigestsPerHost(t *testing.T) {
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
	got, err := newestImages(ctx, tx, map[string]bool{"host-1": true, "host-2": true}, 2)
	if err != nil {
		t.Fatalf("newestImages: %v", err)
	}
	type key struct{ host, digest string }
	var keys []key
	for _, r := range got {
		keys = append(keys, key{r.HostID, r.Digest})
	}
	want := []key{
		{"host-1", imgDigest("b")},
		{"host-1", imgDigest("c")},
		{"host-2", imgDigest("a")},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("loaded %v, want the two newest digests of host-1 and the one of host-2 (the old digest a of host-1 must not be loaded)", keys)
	}
}
