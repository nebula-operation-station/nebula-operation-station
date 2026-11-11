// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// testClock is an injectable clock.
type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time { return c.t }

var (
	day1 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	day2 = day1.Add(24 * time.Hour)
	day3 = day2.Add(24 * time.Hour)
)

func newTestStore(t *testing.T) (*Store, *testClock, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "feeds")
	clk := &testClock{t: day3.Add(5 * 24 * time.Hour)} // fetch time far from any content date
	s, err := OpenStore(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	return s, clk, dir
}

func testFeed(kind DateKind) Feed {
	f := Feed{Name: "test-feed", SourceID: "osv", URL: "https://127.0.0.1:1/feed.json",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: 1 << 20, DateKind: kind}
	if kind == DateKindProxy {
		f.ProxyCompanions = []string{"test-dsa", "test-dla"}
	}
	return f
}

// commitBytes stages b and commits it.
func commitBytes(t *testing.T, s *Store, f Feed, b string, a Accept) (Manifest, error) {
	t.Helper()
	st, err := s.Stage(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte(b)); err != nil {
		t.Fatal(err)
	}
	return s.Commit(f, st, a)
}

// tmpFiles lists leftover temporary files in the store.
func tmpFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	dirs := []string{filepath.Join(dir, objectsDir), filepath.Join(dir, manifestsDir)}
	feeds, err := os.ReadDir(filepath.Join(dir, objectsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range feeds {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(dir, objectsDir, e.Name()))
		}
	}
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), tmpPrefix) {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

func TestCommitIsContentAddressed(t *testing.T) {
	s, clk, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	m, err := commitBytes(t, s, f, "feed bytes", Accept{ContentDate: day1, Validators: Validators{ETag: `"e"`}})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("feed bytes"))
	want := hex.EncodeToString(sum[:])
	if m.SHA256 != want || m.Size != int64(len("feed bytes")) || m.SnapshotID() != "sha256:"+want {
		t.Fatalf("manifest %+v", m)
	}
	got, err := os.ReadFile(objectPath(dir, f.Name, want))
	if err != nil || string(got) != "feed bytes" {
		t.Fatalf("object %q %v", got, err)
	}
	if !m.FetchedAt.Equal(clk.Now()) || !m.ContentDate.Equal(day1) {
		t.Fatalf("fetched_at %v content_date %v", m.FetchedAt, m.ContentDate)
	}
	if m.ContentDate.Equal(m.FetchedAt) {
		t.Fatal("content date equals fetch time")
	}
	loaded, err := s.Load(f.Name)
	if err != nil || loaded.SHA256 != want || loaded.Validators.ETag != `"e"` || !loaded.HighWater.ContentDate.Equal(day1) {
		t.Fatalf("load %+v %v", loaded, err)
	}
	if err := s.Verify(loaded); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(tmpFiles(t, dir)) != 0 {
		t.Fatalf("temp files left: %v", tmpFiles(t, dir))
	}
	if len(m.SnapshotID()) > 80 {
		t.Fatalf("snapshot ID longer than 80 bytes")
	}
}

func TestCommitDatedWithoutContentDateRejected(t *testing.T) {
	// Fetch time is never a content date: a dated or proxy feed without a
	// date from the data is rejected, not dated by the clock.
	for _, kind := range []DateKind{DateKindDated, DateKindProxy} {
		s, _, dir := newTestStore(t)
		_, err := commitBytes(t, s, testFeed(kind), "x", Accept{})
		if !errors.Is(err, ErrNoContentDate) {
			t.Fatalf("%s: %v, want ErrNoContentDate", kind, err)
		}
		if _, err := s.Load("test-feed"); !errors.Is(err, ErrNoSnapshot) {
			t.Fatalf("%s: manifest written: %v", kind, err)
		}
		if len(tmpFiles(t, dir)) != 0 {
			t.Fatalf("temp file left after rejection")
		}
	}
}

func TestCommitUndatedHasNoContentDate(t *testing.T) {
	s, _, _ := newTestStore(t)
	f := testFeed(DateKindUndated)
	if _, err := commitBytes(t, s, f, "x", Accept{ContentDate: day1}); !errors.Is(err, ErrInvalidContentDate) {
		t.Fatalf("undated with date: %v", err)
	}
	m, err := commitBytes(t, s, f, "x", Accept{})
	if err != nil || !m.ContentDate.IsZero() || m.DateKind != DateKindUndated {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestCommitRollbackRejectedKeepsPrevious(t *testing.T) {
	s, _, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	if _, err := commitBytes(t, s, f, "day1", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	m3, err := commitBytes(t, s, f, "day3", Accept{ContentDate: day3})
	if err != nil {
		t.Fatal(err)
	}
	// Older than the newest ever accepted (day3), though newer than day1.
	if _, err := commitBytes(t, s, f, "day2", Accept{ContentDate: day2}); !errors.Is(err, ErrRollback) {
		t.Fatalf("%v, want ErrRollback", err)
	}
	if _, err := commitBytes(t, s, f, "day1 again", Accept{ContentDate: day1}); !errors.Is(err, ErrRollback) {
		t.Fatalf("%v, want ErrRollback", err)
	}
	cur, err := s.Load(f.Name)
	if err != nil || cur.SHA256 != m3.SHA256 || !cur.ContentDate.Equal(day3) {
		t.Fatalf("previous snapshot not kept: %+v %v", cur, err)
	}
	if len(tmpFiles(t, dir)) != 0 {
		t.Fatal("temp file left after rollback rejection")
	}
	// Same content date (re-publication on the same day) is accepted.
	if _, err := commitBytes(t, s, f, "day3 v2", Accept{ContentDate: day3}); err != nil {
		t.Fatalf("same date: %v", err)
	}
}

func TestCommitSequenceMustIncrease(t *testing.T) {
	s, _, _ := newTestStore(t)
	f := testFeed(DateKindDated)
	if _, err := commitBytes(t, s, f, "a", Accept{ContentDate: day1, Sequence: 5}); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{5, 4, 0} {
		if _, err := commitBytes(t, s, f, "b", Accept{ContentDate: day2, Sequence: seq}); !errors.Is(err, ErrRollback) {
			t.Fatalf("sequence %d: %v, want ErrRollback", seq, err)
		}
	}
	m, err := commitBytes(t, s, f, "c", Accept{ContentDate: day2, Sequence: 6})
	if err != nil || m.HighWater.Sequence != 6 {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestCommitFutureContentDateRejected(t *testing.T) {
	s, clk, _ := newTestStore(t)
	f := testFeed(DateKindDated)
	if _, err := commitBytes(t, s, f, "x", Accept{ContentDate: clk.Now().Add(MaxFutureSkew + time.Second)}); !errors.Is(err, ErrFutureContentDate) {
		t.Fatalf("%v, want ErrFutureContentDate", err)
	}
	if _, err := s.Load(f.Name); !errors.Is(err, ErrNoSnapshot) {
		t.Fatal("future-dated snapshot raised the mark")
	}
	if _, err := commitBytes(t, s, f, "x", Accept{ContentDate: clk.Now().Add(MaxFutureSkew)}); err != nil {
		t.Fatalf("within skew: %v", err)
	}
}

func TestCrashLeftoverTempFilesIgnored(t *testing.T) {
	s, clk, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	m, err := commitBytes(t, s, f, "good", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash mid-write: a partial object and a partial manifest
	// left as temp files, plus a staged file never committed.
	if err := os.WriteFile(filepath.Join(dir, objectsDir, tmpPrefix+"123"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, manifestsDir, tmpPrefix+"456"), []byte(`{"feed":"test-feed","sha2`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stage(f)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.Write([]byte("never committed"))

	// The running store ignores them.
	cur, err := s.Load(f.Name)
	if err != nil || cur.SHA256 != m.SHA256 {
		t.Fatalf("load with leftovers: %+v %v", cur, err)
	}
	// Reopening (restart) removes them and keeps the snapshot.
	s2, err := OpenStore(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	if left := tmpFiles(t, dir); len(left) != 0 {
		t.Fatalf("leftovers not cleaned: %v", left)
	}
	cur, err = s2.Load(f.Name)
	if err != nil || cur.SHA256 != m.SHA256 {
		t.Fatalf("reopen: %+v %v", cur, err)
	}
	if err := s2.Verify(cur); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptManifestFailsClosed(t *testing.T) {
	s, _, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	if _, err := commitBytes(t, s, f, "good", Accept{ContentDate: day2}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"truncated":     `{"feed":"test-feed"`,
		"unknown field": `{"feed":"test-feed","extra":1}`,
		"bad sha":       `{"feed":"test-feed","source_id":"osv","sha256":"../../etc/passwd","size":1,"date_kind":"dated","integrity":"none"}`,
		"other feed":    `{"feed":"other","source_id":"osv","sha256":"` + strings.Repeat("a", 64) + `","size":1,"date_kind":"dated","integrity":"none"}`,
		"oversize":      strings.Repeat(" ", MaxManifestBytes+1),
	}
	for name, body := range cases {
		if err := os.WriteFile(filepath.Join(dir, manifestsDir, f.Name+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(f.Name); !errors.Is(err, ErrCorruptManifest) {
			t.Errorf("%s: load %v, want ErrCorruptManifest", name, err)
		}
		// A lost high-water mark must not let an older snapshot in.
		if _, err := commitBytes(t, s, f, "old", Accept{ContentDate: day1}); !errors.Is(err, ErrCorruptManifest) {
			t.Errorf("%s: commit %v, want ErrCorruptManifest", name, err)
		}
	}
}

func TestVerifyDetectsTamperedObject(t *testing.T) {
	s, _, dir := newTestStore(t)
	m, err := commitBytes(t, s, testFeed(DateKindDated), "good", Accept{ContentDate: day1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath(dir, m.Feed, m.SHA256), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(m); !errors.Is(err, ErrCorruptSnapshot) {
		t.Fatalf("%v, want ErrCorruptSnapshot", err)
	}
}

func TestStageOverCapRejected(t *testing.T) {
	s, _, dir := newTestStore(t)
	f := testFeed(DateKindDated)
	f.MaxBytes = 4
	st, err := s.Stage(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("12345")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v, want ErrTooLarge", err)
	}
	st.Abort()
	if len(tmpFiles(t, dir)) != 0 {
		t.Fatal("aborted stage left a file")
	}
}

func TestProxyDateIsNewestCompanionDate(t *testing.T) {
	s, _, _ := newTestStore(t)
	dsa := testFeed(DateKindDated)
	dsa.Name = "test-dsa"
	dla := testFeed(DateKindDated)
	dla.Name = "test-dla"
	tracker := testFeed(DateKindProxy)
	if _, err := s.ProxyDate(tracker); !errors.Is(err, ErrNoContentDate) {
		t.Fatalf("no companions: %v, want ErrNoContentDate", err)
	}
	if _, err := commitBytes(t, s, dsa, "dsa", Accept{ContentDate: day1}); err != nil {
		t.Fatal(err)
	}
	if _, err := commitBytes(t, s, dla, "dla", Accept{ContentDate: day2}); err != nil {
		t.Fatal(err)
	}
	d, err := s.ProxyDate(tracker)
	if err != nil || !d.Equal(day2) {
		t.Fatalf("proxy date %v %v, want %v", d, err, day2)
	}
	if _, err := s.ProxyDate(dsa); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("proxy date of a dated feed: %v", err)
	}
}
