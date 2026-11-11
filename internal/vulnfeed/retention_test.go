// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// objectFiles lists committed (non-temporary) object names.
func objectFiles(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, objectsDir))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fi.Size()
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

func TestSameContentOnTwoFeedsSharesObject(t *testing.T) {
	s, _, dir := newTestStore(t)
	a := testFeed(DateKindDated)
	a.Name = "feed-a"
	b := testFeed(DateKindDated)
	b.Name = "feed-b"
	if _, err := commitBytes(t, s, a, "same", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	mb, err := commitBytes(t, s, b, "same", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	// b moves on; the shared object is still referenced by a.
	for i := range SnapshotRetention + 1 {
		if _, err := commitBytes(t, s, b, fmt.Sprintf("b-%d", i), Accept{ContentDate: day2.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := objectFiles(t, dir)[mb.SHA256]; !ok {
		t.Fatal("object shared with feed-a removed")
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

func TestPruneWithCorruptManifestRemovesNothing(t *testing.T) {
	s, _, dir := newTestStore(t)
	a := testFeed(DateKindDated)
	a.Name = "feed-a"
	if _, err := commitBytes(t, s, a, "a-1", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	// An unreferenced object (e.g. left by a crash between object rename and
	// manifest write) plus a corrupt manifest for another feed: its
	// references are unknown, so nothing may be removed.
	orphan := strings.Repeat("ab", 32)
	if err := os.WriteFile(filepath.Join(dir, objectsDir, orphan), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestsDir, "feed-b.json"), []byte(`{"feed":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(); !errors.Is(err, ErrCorruptManifest) {
		t.Fatalf("prune %v, want ErrCorruptManifest", err)
	}
	if _, ok := objectFiles(t, dir)[orphan]; !ok {
		t.Fatal("object removed although a manifest is unreadable")
	}
	// Once the manifest is gone, the orphan is collected.
	if err := os.Remove(filepath.Join(dir, manifestsDir, "feed-b.json")); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := objectFiles(t, dir)[orphan]; ok {
		t.Fatal("orphan object kept")
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
	if err := os.WriteFile(filepath.Join(dir, objectsDir, orphan), []byte("v2-crashed"), 0o600); err != nil {
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
