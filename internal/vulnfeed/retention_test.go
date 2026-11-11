// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// objectPath is where the store keeps feed's object with digest sum.
func objectPath(dir, feed, sum string) string {
	return filepath.Join(dir, objectsDir, feed, sum)
}

// objectFiles lists committed (non-temporary) object names over all feeds.
func objectFiles(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, objs := range feedObjectFiles(t, dir) {
		maps.Copy(out, objs)
	}
	return out
}

// feedObjectFiles lists committed (non-temporary) object names per feed.
func feedObjectFiles(t *testing.T, dir string) map[string]map[string]int64 {
	t.Helper()
	feeds, err := os.ReadDir(filepath.Join(dir, objectsDir))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]int64{}
	for _, fd := range feeds {
		if !fd.IsDir() {
			continue
		}
		ents, err := os.ReadDir(filepath.Join(dir, objectsDir, fd.Name()))
		if err != nil {
			t.Fatal(err)
		}
		objs := map[string]int64{}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), tmpPrefix) {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			objs[e.Name()] = fi.Size()
		}
		out[fd.Name()] = objs
	}
	return out
}

func TestSnapshotDiskUseBoundedOverManyChangedSyncs(t *testing.T) {
	e := newSyncEnv(t)
	f := e.feed("kev", "/kev.json", DateKindDated)
	const syncs = 25
	const bodySize = 1000
	var last Manifest
	for i := range syncs {
		d := day1.Add(time.Duration(i) * time.Hour)
		body := dated(d, fmt.Sprintf("%04d", i)+strings.Repeat("x", bodySize))
		e.fs.set("/kev.json", body)
		res, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
		if err != nil || res.NotModified {
			t.Fatalf("sync %d: %+v %v", i, res, err)
		}
		last = res.Manifest
		objs := objectFiles(t, e.dir)
		if want := min(i+1, SnapshotRetention); len(objs) != want {
			t.Fatalf("sync %d: %d objects, want %d", i, len(objs), want)
		}
		var total int64
		for _, n := range objs {
			total += n
		}
		if limit := int64(SnapshotRetention) * f.MaxBytes; total > limit {
			t.Fatalf("sync %d: %d bytes on disk, bound %d", i, total, limit)
		}
	}
	// The kept objects are exactly the current snapshot and its retained
	// predecessors, newest first, and all of them verify.
	if len(last.Previous) != SnapshotRetention-1 {
		t.Fatalf("previous %d, want %d", len(last.Previous), SnapshotRetention-1)
	}
	objs := objectFiles(t, e.dir)
	if _, ok := objs[last.SHA256]; !ok {
		t.Fatal("current object removed")
	}
	for i, p := range last.Previous {
		if _, ok := objs[p.SHA256]; !ok {
			t.Fatalf("retained object %d removed", i)
		}
		if err := e.store.Verify(Manifest{Feed: f.Name, SHA256: p.SHA256, Size: p.Size}); err != nil {
			t.Fatalf("retained %d: %v", i, err)
		}
		if i > 0 && !p.ContentDate.Before(last.Previous[i-1].ContentDate) {
			t.Fatalf("previous not newest first: %+v", last.Previous)
		}
	}
	loaded, err := e.store.Load(f.Name)
	if err != nil || len(loaded.Previous) != SnapshotRetention-1 {
		t.Fatalf("load %+v %v", loaded, err)
	}
}

func TestPruneKeepsObjectsOfEveryFeed(t *testing.T) {
	s, _, dir := newTestStore(t)
	a := testFeed(DateKindDated)
	a.Name = "feed-a"
	b := testFeed(DateKindDated)
	b.Name = "feed-b"
	ma, err := commitBytes(t, s, a, "a-only", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	// Feed b changes many times; feed a's single object must survive.
	for i := range SnapshotRetention + 3 {
		if _, err := commitBytes(t, s, b, fmt.Sprintf("b-%d", i), Accept{ContentDate: day1.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Verify(ma); err != nil {
		t.Fatalf("feed a object pruned: %v", err)
	}
	if n := len(objectFiles(t, dir)); n != 1+SnapshotRetention {
		t.Fatalf("%d objects, want %d", n, 1+SnapshotRetention)
	}
}

func TestSameContentOnTwoFeedsSurvivesOtherFeedsPrune(t *testing.T) {
	s, _, dir := newTestStore(t)
	a := testFeed(DateKindDated)
	a.Name = "feed-a"
	b := testFeed(DateKindDated)
	b.Name = "feed-b"
	ma, err := commitBytes(t, s, a, "same", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	mb, err := commitBytes(t, s, b, "same", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	if ma.SHA256 != mb.SHA256 {
		t.Fatal("same bytes, different digest")
	}
	// b moves on and prunes its copy; a's snapshot of the same bytes stays.
	for i := range SnapshotRetention + 1 {
		if _, err := commitBytes(t, s, b, fmt.Sprintf("b-%d", i), Accept{ContentDate: day2.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := feedObjectFiles(t, dir)[a.Name][ma.SHA256]; !ok {
		t.Fatal("feed-a object removed by feed-b's prune")
	}
	if err := s.Verify(ma); err != nil {
		t.Fatalf("feed-a snapshot: %v", err)
	}
	if _, ok := feedObjectFiles(t, dir)[b.Name][mb.SHA256]; ok {
		t.Fatal("feed-b's expired copy kept")
	}
}

func TestRecommitOfSameBytesDoesNotDuplicateHistory(t *testing.T) {
	s, _, _ := newTestStore(t)
	f := testFeed(DateKindDated)
	for i := range 4 {
		if _, err := commitBytes(t, s, f, "same bytes", Accept{ContentDate: day1.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := s.Load(f.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Previous) != 0 {
		t.Fatalf("previous %+v, want none for unchanged bytes", m.Previous)
	}
}

func TestPruneWithCorruptManifestSkipsOnlyThatFeed(t *testing.T) {
	// Prune walks the feeds in directory (name) order. The corrupt manifest
	// is placed on the first, a middle and the last feed in turn, so an
	// implementation that stops at the first unreadable manifest leaves the
	// orphans of a later feed behind and fails.
	names := []string{"feed-a", "feed-b", "feed-c"}
	for _, corrupt := range names {
		t.Run(corrupt, func(t *testing.T) {
			s, _, dir := newTestStore(t)
			feeds := map[string]Feed{}
			current := map[string]string{}
			orphans := map[string]string{}
			for i, name := range names {
				f := testFeed(DateKindDated)
				f.Name = name
				m, err := commitBytes(t, s, f, name+"-1", Accept{ContentDate: day1})
				if err != nil {
					t.Fatal(err)
				}
				feeds[name], current[name] = f, m.SHA256
				// An unreferenced object (e.g. left by a crash between
				// object rename and manifest write).
				orphans[name] = strings.Repeat(fmt.Sprintf("%02x", 0xa0+i), 32)
				if err := os.WriteFile(objectPath(dir, name, orphans[name]), []byte("orphan"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			manifest := filepath.Join(dir, manifestsDir, corrupt+".json")
			if err := os.WriteFile(manifest, []byte(`{"feed":`), 0o600); err != nil {
				t.Fatal(err)
			}
			err := s.Prune()
			if !errors.Is(err, ErrCorruptManifest) || !errors.Is(err, ErrPruneFailed) {
				t.Fatalf("prune %v, want ErrPruneFailed and ErrCorruptManifest", err)
			}
			objs := feedObjectFiles(t, dir)
			for _, name := range names {
				if _, ok := objs[name][current[name]]; !ok {
					t.Fatalf("%s current object removed", name)
				}
				_, kept := objs[name][orphans[name]]
				switch {
				case name == corrupt && !kept:
					t.Fatalf("%s object removed although its manifest is unreadable", name)
				case name != corrupt && kept:
					t.Fatalf("%s orphan kept: corrupt %s manifest blocked it", name, corrupt)
				}
			}
			// Commits of the healthy feeds keep succeeding without a
			// prune error.
			for _, name := range names {
				if name == corrupt {
					continue
				}
				if _, err := commitBytes(t, s, feeds[name], name+"-2", Accept{ContentDate: day2}); err != nil {
					t.Fatalf("%s commit with corrupt %s manifest: %v", name, corrupt, err)
				}
			}
			// Once the manifest is gone, the feed's objects are orphans
			// and collected.
			if err := os.Remove(manifest); err != nil {
				t.Fatal(err)
			}
			if err := s.Prune(); err != nil {
				t.Fatal(err)
			}
			if n := len(feedObjectFiles(t, dir)[corrupt]); n != 0 {
				t.Fatalf("%s: %d orphan objects kept", corrupt, n)
			}
		})
	}
}

func TestPruneIgnoresStrayFiles(t *testing.T) {
	s, _, dir := newTestStore(t)
	a := testFeed(DateKindDated)
	a.Name = "feed-a"
	if _, err := commitBytes(t, s, a, "a-1", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	// The orphan sorts after every in-feed stray, and feed-a after the
	// stray entries of the objects directory, so an implementation that
	// stops (returns or breaks) at the first stray never reaches it.
	orphan := strings.Repeat("ef", 32)
	if err := os.WriteFile(objectPath(dir, a.Name, orphan), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	strays := []string{
		filepath.Join(dir, manifestsDir, ".feed-a.json.swp"),
		filepath.Join(dir, manifestsDir, "feed-a.json.bak"),
		filepath.Join(dir, manifestsDir, "README"),
		filepath.Join(dir, objectsDir, "a-notes"), // feed-like name, but a file
		filepath.Join(dir, objectsDir, "notes.txt"),
		filepath.Join(dir, objectsDir, a.Name, ".keep"),
		filepath.Join(dir, objectsDir, a.Name, "0.bak"),
		filepath.Join(dir, objectsDir, a.Name, strings.Repeat("AB", 32)), // upper-case digest
		filepath.Join(dir, objectsDir, a.Name, strings.Repeat("ab", 31)), // too short
		filepath.Join(dir, objectsDir, a.Name, "keep.bak"),
	}
	for _, p := range strays {
		if err := os.WriteFile(p, []byte("stray"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, objectsDir, "Not_A_Feed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(); err != nil {
		t.Fatalf("prune with stray files: %v", err)
	}
	if _, ok := feedObjectFiles(t, dir)[a.Name][orphan]; ok {
		t.Fatal("orphan kept: stray files blocked GC")
	}
	for _, p := range strays {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("stray file touched: %v", err)
		}
	}
	// A commit also prunes, without error.
	if _, err := commitBytes(t, s, a, "a-2", Accept{ContentDate: day2}); err != nil {
		t.Fatalf("commit with stray files: %v", err)
	}
}

func TestCommitReportsPruneFailure(t *testing.T) {
	s, _, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	if _, err := commitBytes(t, s, f, "v1", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	// An unremovable entry with an object name: a non-empty directory
	// (os.Remove fails even as root).
	stuck := strings.Repeat("0f", 32)
	if err := os.MkdirAll(filepath.Join(objectPath(dir, f.Name, stuck), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Orphans on both sides of the stuck entry in sort order: removal must
	// go on after a failure, not stop at it.
	orphans := []string{strings.Repeat("00", 32), strings.Repeat("ff", 32)}
	writeOrphans := func(feed string) {
		t.Helper()
		for _, o := range orphans {
			if err := os.WriteFile(objectPath(dir, feed, o), []byte("orphan"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	checkCollected := func(feed string) {
		t.Helper()
		objs := feedObjectFiles(t, dir)[feed]
		for _, o := range orphans {
			if _, ok := objs[o]; ok {
				t.Fatalf("%s orphan %.8s kept after a failed removal", feed, o)
			}
		}
	}
	writeOrphans(f.Name)
	m1 := sha256Hex("v1")
	m, err := commitBytes(t, s, f, "v2", Accept{ContentDate: day2})
	if !errors.Is(err, ErrPruneFailed) {
		t.Fatalf("commit %v, want ErrPruneFailed", err)
	}
	// The commit itself is durable and the manifest is returned.
	cur, lerr := s.Load(f.Name)
	if lerr != nil || cur.SHA256 != sha256Hex("v2") || m.SHA256 != cur.SHA256 {
		t.Fatalf("committed manifest %+v, loaded %+v %v", m, cur, lerr)
	}
	checkCollected(f.Name)
	objs := feedObjectFiles(t, dir)[f.Name]
	for _, keep := range []string{m.SHA256, m1, stuck} {
		if _, ok := objs[keep]; !ok {
			t.Fatalf("object %.8s removed", keep)
		}
	}

	// Prune: the failing feed sorts first ("test-feed" < "zz-feed"); its
	// failure must not stop the orphans of the other feed being collected.
	other := testFeed(DateKindDated)
	other.Name = "zz-feed"
	if _, err := commitBytes(t, s, other, "z1", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	writeOrphans(f.Name)
	writeOrphans(other.Name)
	if err := s.Prune(); !errors.Is(err, ErrPruneFailed) {
		t.Fatalf("prune %v, want ErrPruneFailed", err)
	}
	checkCollected(f.Name)
	checkCollected(other.Name)
}

func TestSyncReportsPruneFailure(t *testing.T) {
	e := newSyncEnv(t)
	f := e.feed("kev", "/kev.json", DateKindDated)
	e.fs.set("/kev.json", dated(day1, "v1"))
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); err != nil {
		t.Fatal(err)
	}
	stuck := strings.Repeat("0f", 32)
	if err := os.MkdirAll(filepath.Join(objectPath(e.dir, f.Name, stuck), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := dated(day2, "v2")
	e.fs.set("/kev.json", body)
	res, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
	if !errors.Is(err, ErrPruneFailed) {
		t.Fatalf("sync %v, want ErrPruneFailed", err)
	}
	if res.Manifest.SHA256 != sha256Hex(body) {
		t.Fatalf("committed manifest not returned with the prune error: %+v", res.Manifest)
	}
}

func TestCrashBeforeManifestCommitKeepsOldSnapshot(t *testing.T) {
	// A crash after the object rename but before the manifest replace leaves
	// an unreferenced object; the old snapshot stays valid and the next
	// commit collects the orphan.
	s, clk, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	m1, err := commitBytes(t, s, f, "v1", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	orphan := sha256Hex("v2-crashed")
	if err := os.WriteFile(objectPath(dir, f.Name, orphan), []byte("v2-crashed"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s2.Load(f.Name)
	if err != nil || cur.SHA256 != m1.SHA256 || s2.Verify(cur) != nil {
		t.Fatalf("old snapshot lost: %+v %v", cur, err)
	}
	if _, err := commitBytes(t, s2, f, "v3", Accept{ContentDate: day2}); err != nil {
		t.Fatal(err)
	}
	objs := objectFiles(t, dir)
	if _, ok := objs[orphan]; ok {
		t.Fatal("orphan object not collected")
	}
	if _, ok := objs[m1.SHA256]; !ok {
		t.Fatal("retained previous snapshot removed")
	}
}

func TestPruneLeavesStagedTempFiles(t *testing.T) {
	s, _, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	st, err := s.Stage(f)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Abort()
	if _, err := st.Write([]byte("in flight")); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if len(tmpFiles(t, dir)) != 1 {
		t.Fatal("prune removed an in-flight staged file")
	}
}

func TestManifestWithOverlongHistoryIsCorrupt(t *testing.T) {
	s, _, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	if _, err := commitBytes(t, s, f, "x", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	ref := `{"sha256":"` + strings.Repeat("a", 64) + `","size":1}`
	refs := strings.TrimSuffix(strings.Repeat(ref+",", SnapshotRetention), ",")
	bad := map[string]string{
		"too many": `{"feed":"test-feed","source_id":"osv","sha256":"` + strings.Repeat("b", 64) + `","size":1,"date_kind":"dated","integrity":"none","fetched_at":"2026-11-01T00:00:00Z","previous":[` + refs + `]}`,
		"bad sha":  `{"feed":"test-feed","source_id":"osv","sha256":"` + strings.Repeat("b", 64) + `","size":1,"date_kind":"dated","integrity":"none","fetched_at":"2026-11-01T00:00:00Z","previous":[{"sha256":"../x","size":1}]}`,
	}
	for name, body := range bad {
		if err := os.WriteFile(filepath.Join(dir, manifestsDir, f.Name+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(f.Name); !errors.Is(err, ErrCorruptManifest) {
			t.Errorf("%s: %v, want ErrCorruptManifest", name, err)
		}
	}
}
