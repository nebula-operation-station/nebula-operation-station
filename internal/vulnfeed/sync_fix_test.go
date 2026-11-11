// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestSyncSlowChecksumCompanionTimesOut(t *testing.T) {
	body := dated(day1, "payload")
	release := make(chan struct{})
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/data/feed.json":
			_, _ = io.WriteString(w, body)
		case "/data/feed.json.sha256":
			// Slow drip: headers and one byte, then nothing.
			_, _ = io.WriteString(w, "a")
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	})
	t.Cleanup(func() { close(release) }) // runs before srv.Close
	f := newTestFetcher(t, pool, 0, srv) // whole-request timeout: DefaultFetchTimeout
	st, _, _ := newTestStore(t)
	sy, err := NewSyncer(f, st)
	if err != nil {
		t.Fatal(err)
	}
	sy.checksumTimeout = 200 * time.Millisecond
	feed := Feed{Name: "sum", SourceID: "osv", URL: srv.URL + "/data/feed.json", Integrity: vulnfinding.IntegrityChecksum,
		Checksum: ChecksumSHA256, MaxBytes: 1 << 16, DateKind: DateKindDated}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := sy.Sync(context.Background(), feed, SyncOptions{ContentDate: firstLineDate})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%v, want context.DeadlineExceeded", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("slow checksum companion was not bounded by a short timeout")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %v", el)
	}
	if _, err := st.Load("sum"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatal("accepted without a checksum")
	}
}

func TestNewSyncerSetsChecksumTimeout(t *testing.T) {
	srv, pool := tlsServer(t, func(http.ResponseWriter, *http.Request) {})
	st, _, _ := newTestStore(t)
	sy, err := NewSyncer(newTestFetcher(t, pool, 0, srv), st)
	if err != nil {
		t.Fatal(err)
	}
	if sy.checksumTimeout != ChecksumFetchTimeout || ChecksumFetchTimeout <= 0 || ChecksumFetchTimeout > 2*time.Minute {
		t.Fatalf("checksum timeout %v", sy.checksumTimeout)
	}
}

func TestSyncNotModifiedProxyFeedPicksUpNewerCompanionDate(t *testing.T) {
	e := newSyncEnv(t)
	dsa := e.feed("test-dsa", "/dsa", DateKindDated)
	tracker := e.feed("test-tracker", "/tracker.json", DateKindProxy)
	tracker.ProxyCompanions = []string{"test-dsa", "test-dla"}
	e.fs.set("/tracker.json", `{"tracker": 1}`)
	e.fs.set("/dsa", dated(day1, "DSA 1"))
	ctx := context.Background()
	opt := SyncOptions{ContentDate: firstLineDate}
	if _, err := e.syncer.Sync(ctx, dsa, opt); err != nil {
		t.Fatal(err)
	}
	first, err := e.syncer.Sync(ctx, tracker, opt)
	if err != nil || !first.Manifest.ContentDate.Equal(day1) {
		t.Fatalf("%+v %v", first.Manifest, err)
	}

	// DSA moves forward; the tracker itself is unchanged (304).
	e.clk.t = e.clk.t.Add(time.Hour)
	e.fs.set("/dsa", dated(day2, "DSA 2"))
	if _, err := e.syncer.Sync(ctx, dsa, opt); err != nil {
		t.Fatal(err)
	}
	res, err := e.syncer.Sync(ctx, tracker, opt)
	if err != nil || !res.NotModified {
		t.Fatalf("%+v %v", res, err)
	}
	m := res.Manifest
	if !m.ContentDate.Equal(day2) || !m.HighWater.ContentDate.Equal(day2) {
		t.Fatalf("content date %v high water %v, want %v", m.ContentDate, m.HighWater.ContentDate, day2)
	}
	if m.SHA256 != first.Manifest.SHA256 || m.Size != first.Manifest.Size || m.Validators != first.Manifest.Validators || len(m.Previous) != 0 {
		t.Fatalf("content fields changed on 304: %+v", m)
	}
	if !m.FetchedAt.Equal(e.clk.Now()) {
		t.Fatalf("fetched_at %v, want %v", m.FetchedAt, e.clk.Now())
	}
	loaded, err := e.store.Load(tracker.Name)
	if err != nil || !loaded.ContentDate.Equal(day2) {
		t.Fatalf("not persisted: %+v %v", loaded, err)
	}
	if err := e.store.Verify(loaded); err != nil {
		t.Fatal(err)
	}

	// A further 304 with no newer companion date leaves the manifest alone.
	e.clk.t = e.clk.t.Add(time.Hour)
	again, err := e.syncer.Sync(ctx, tracker, opt)
	if err != nil || !again.NotModified || !again.Manifest.FetchedAt.Equal(m.FetchedAt) {
		t.Fatalf("%+v %v", again.Manifest, err)
	}
}

func TestRedateProxyRules(t *testing.T) {
	s, clk, _ := newTestStore(t)
	tracker := testFeed(DateKindProxy)
	if _, err := s.RedateProxy(tracker, day1); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("no snapshot: %v", err)
	}
	if _, err := commitBytes(t, s, tracker, "t", Accept{ContentDate: day2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedateProxy(tracker, day1); !errors.Is(err, ErrRollback) {
		t.Fatalf("older date: %v, want ErrRollback", err)
	}
	if _, err := s.RedateProxy(tracker, clk.Now().Add(MaxFutureSkew+time.Second)); !errors.Is(err, ErrFutureContentDate) {
		t.Fatalf("future date: %v, want ErrFutureContentDate", err)
	}
	if _, err := s.RedateProxy(tracker, time.Time{}); !errors.Is(err, ErrNoContentDate) {
		t.Fatalf("zero date: %v, want ErrNoContentDate", err)
	}
	if _, err := s.RedateProxy(testFeed(DateKindDated), day3); !errors.Is(err, ErrInvalidFeed) {
		t.Fatalf("dated feed: %v, want ErrInvalidFeed", err)
	}
	cur, err := s.Load(tracker.Name)
	if err != nil || !cur.ContentDate.Equal(day2) {
		t.Fatalf("rejected redate changed the manifest: %+v %v", cur, err)
	}
	m, err := s.RedateProxy(tracker, day3)
	if err != nil || !m.ContentDate.Equal(day3) || !m.HighWater.ContentDate.Equal(day3) || m.SHA256 != cur.SHA256 {
		t.Fatalf("%+v %v", m, err)
	}
}

// TestSyncRefetchesWhenCachedObjectInvalid: when the previous snapshot's
// object is missing or no longer verifies, the stored validators must not
// be sent, so the origin cannot answer 304 and leave a broken snapshot in
// use; the feed is fetched again and the object restored.
func TestSyncRefetchesWhenCachedObjectInvalid(t *testing.T) {
	for name, damage := range map[string]func(path string) error{
		"missing":  os.Remove,
		"tampered": func(p string) error { return os.WriteFile(p, []byte("evil"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newSyncEnv(t)
			f := e.feed("kev", "/kev.json", DateKindDated)
			body := dated(day1, "x")
			e.fs.set("/kev.json", body)
			first, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
			if err != nil {
				t.Fatal(err)
			}
			if err := damage(objectPath(e.dir, f.Name, first.Manifest.SHA256)); err != nil {
				t.Fatal(err)
			}
			res, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
			if err != nil {
				t.Fatal(err)
			}
			if res.NotModified || !res.PreviousInvalid {
				t.Fatalf("304 accepted over an invalid object: %+v", res)
			}
			if res.Manifest.SHA256 != sha256Hex(body) {
				t.Fatalf("manifest %+v", res.Manifest)
			}
			if err := e.store.Verify(res.Manifest); err != nil {
				t.Fatalf("object not restored: %v", err)
			}
			// With the object intact again, the next sync is a plain 304.
			res, err = e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
			if err != nil || !res.NotModified || res.PreviousInvalid {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}
