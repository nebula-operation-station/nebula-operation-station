// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// feedServer serves mutable feed bodies over loopback TLS.
type feedServer struct {
	mu       sync.Mutex
	files    map[string]string // path → body
	requests atomic.Int32
}

func (fs *feedServer) set(path, body string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.files[path] = body
}

func (fs *feedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fs.requests.Add(1)
	fs.mu.Lock()
	body, ok := fs.files[r.URL.Path]
	fs.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := `"` + sha256Hex(body)[:16] + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	_, _ = io.WriteString(w, body)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha512Hex(s string) string {
	h := sha512.Sum512([]byte(s))
	return hex.EncodeToString(h[:])
}

// firstLineDate reads the content date from the first line of the body,
// standing in for the va04 parsers.
func firstLineDate(r io.Reader) (time.Time, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && line == "" {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339, strings.TrimSpace(line))
}

type syncEnv struct {
	fs     *feedServer
	url    string
	syncer *Syncer
	store  *Store
	clk    *testClock
	dir    string
}

func newSyncEnv(t *testing.T) *syncEnv {
	t.Helper()
	fs := &feedServer{files: map[string]string{}}
	srv, pool := tlsServer(t, fs.ServeHTTP)
	f := newTestFetcher(t, pool, 0, srv)
	st, clk, dir := newTestStore(t)
	sy, err := NewSyncer(f, st)
	if err != nil {
		t.Fatal(err)
	}
	return &syncEnv{fs: fs, url: srv.URL, syncer: sy, store: st, clk: clk, dir: dir}
}

func (e *syncEnv) feed(name, path string, kind DateKind) Feed {
	f := Feed{Name: name, SourceID: "osv", URL: e.url + path, Integrity: vulnfinding.IntegrityNone, MaxBytes: 1 << 16, DateKind: kind}
	return f
}

func dated(d time.Time, rest string) string { return d.Format(time.RFC3339) + "\n" + rest }

func TestSyncAcceptsDatedFeed(t *testing.T) {
	e := newSyncEnv(t)
	body := dated(day1, "data")
	e.fs.set("/kev.json", body)
	res, err := e.syncer.Sync(context.Background(), e.feed("kev", "/kev.json", DateKindDated), SyncOptions{ContentDate: firstLineDate})
	if err != nil {
		t.Fatal(err)
	}
	m := res.Manifest
	if m.SHA256 != sha256Hex(body) || !m.ContentDate.Equal(day1) || !m.FetchedAt.Equal(e.clk.Now()) || m.Validators.ETag == "" {
		t.Fatalf("manifest %+v", m)
	}
}

func TestSyncDatedFeedNeedsDateFromData(t *testing.T) {
	e := newSyncEnv(t)
	e.fs.set("/kev.json", "no date here\n")
	f := e.feed("kev", "/kev.json", DateKindDated)
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{}); !errors.Is(err, ErrNoContentDate) {
		t.Fatalf("no date func: %v, want ErrNoContentDate", err)
	}
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, ErrNoContentDate) {
		t.Fatalf("unparseable date: %v, want ErrNoContentDate", err)
	}
	if _, err := e.store.Load("kev"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatal("snapshot accepted without a content date")
	}
	if len(tmpFiles(t, e.dir)) != 0 {
		t.Fatal("temp file left")
	}
}

func TestSyncOversizeKeepsPrevious(t *testing.T) {
	e := newSyncEnv(t)
	f := e.feed("kev", "/kev.json", DateKindDated)
	f.MaxBytes = 64
	e.fs.set("/kev.json", dated(day1, "small"))
	prev, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
	if err != nil {
		t.Fatal(err)
	}
	e.fs.set("/kev.json", dated(day2, strings.Repeat("x", 100)))
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v, want ErrTooLarge", err)
	}
	cur, err := e.store.Load("kev")
	if err != nil || cur.SHA256 != prev.Manifest.SHA256 {
		t.Fatalf("previous not kept: %+v %v", cur, err)
	}
	if len(tmpFiles(t, e.dir)) != 0 {
		t.Fatal("temp file left after oversize")
	}
}

func TestSyncRollbackRejectedKeepsPrevious(t *testing.T) {
	e := newSyncEnv(t)
	f := e.feed("kev", "/kev.json", DateKindDated)
	e.fs.set("/kev.json", dated(day2, "new"))
	prev, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
	if err != nil {
		t.Fatal(err)
	}
	e.fs.set("/kev.json", dated(day1, "replayed old"))
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, ErrRollback) {
		t.Fatalf("%v, want ErrRollback", err)
	}
	cur, _ := e.store.Load("kev")
	if cur.SHA256 != prev.Manifest.SHA256 || !cur.ContentDate.Equal(day2) {
		t.Fatalf("previous not kept: %+v", cur)
	}
}

func TestSyncFutureContentDateRejected(t *testing.T) {
	e := newSyncEnv(t)
	f := e.feed("kev", "/kev.json", DateKindDated)
	e.fs.set("/kev.json", dated(e.clk.Now().Add(time.Hour), "future"))
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, ErrFutureContentDate) {
		t.Fatalf("%v, want ErrFutureContentDate", err)
	}
}

func TestSyncNotModifiedKeepsManifest(t *testing.T) {
	e := newSyncEnv(t)
	f := e.feed("kev", "/kev.json", DateKindDated)
	e.fs.set("/kev.json", dated(day1, "x"))
	first, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
	if err != nil {
		t.Fatal(err)
	}
	e.clk.t = e.clk.t.Add(time.Hour)
	res, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
	if err != nil || !res.NotModified || !reflect.DeepEqual(res.Manifest, first.Manifest) {
		t.Fatalf("%+v %v", res, err)
	}
	if len(tmpFiles(t, e.dir)) != 0 {
		t.Fatal("temp file left after 304")
	}
}

func TestSyncProxyDatedTracker(t *testing.T) {
	e := newSyncEnv(t)
	dsa := e.feed("test-dsa", "/dsa", DateKindDated)
	dla := e.feed("test-dla", "/dla", DateKindDated)
	tracker := e.feed("test-tracker", "/tracker.json", DateKindProxy)
	tracker.ProxyCompanions = []string{"test-dsa", "test-dla"}
	e.fs.set("/tracker.json", `{"undated": true}`)
	if _, err := e.syncer.Sync(context.Background(), tracker, SyncOptions{}); !errors.Is(err, ErrNoContentDate) {
		t.Fatalf("tracker without companions: %v, want ErrNoContentDate", err)
	}
	e.fs.set("/dsa", dated(day1, "DSA"))
	e.fs.set("/dla", dated(day2, "DLA"))
	for _, f := range []Feed{dsa, dla} {
		if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := e.syncer.Sync(context.Background(), tracker, SyncOptions{ContentDate: firstLineDate})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Manifest.ContentDate.Equal(day2) || res.Manifest.ContentDate.Equal(res.Manifest.FetchedAt) {
		t.Fatalf("tracker content date %v, want proxy %v", res.Manifest.ContentDate, day2)
	}
}

func TestSyncUndatedFeed(t *testing.T) {
	e := newSyncEnv(t)
	e.fs.set("/u", dated(day1, "a date in the data is ignored for undated feeds"))
	res, err := e.syncer.Sync(context.Background(), e.feed("undated", "/u", DateKindUndated), SyncOptions{ContentDate: firstLineDate})
	if err != nil || !res.Manifest.ContentDate.IsZero() {
		t.Fatalf("%+v %v", res.Manifest, err)
	}
}

func TestSyncSignedFailsClosed(t *testing.T) {
	e := newSyncEnv(t)
	e.fs.set("/csaf.json", dated(day1, "{}"))
	f := e.feed("csaf", "/csaf.json", DateKindDated)
	f.Integrity = vulnfinding.IntegritySigned
	if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, ErrSignedUnsupported) {
		t.Fatalf("%v, want ErrSignedUnsupported", err)
	}
	if e.fs.requests.Load() != 0 {
		t.Fatal("signed feed fetched without a verifier")
	}
}

func checksumFeed(e *syncEnv, alg ChecksumAlg) Feed {
	f := e.feed("sum", "/data/feed.json", DateKindDated)
	f.Integrity = vulnfinding.IntegrityChecksum
	f.Checksum = alg
	return f
}

func TestSyncChecksumMatchAccepted(t *testing.T) {
	for _, tc := range []struct {
		alg ChecksumAlg
		sum func(string) string
	}{{ChecksumSHA256, sha256Hex}, {ChecksumSHA512, sha512Hex}} {
		e := newSyncEnv(t)
		f := checksumFeed(e, tc.alg)
		for i, format := range []func(string) string{
			func(s string) string { return s },
			func(s string) string { return s + "  feed.json\n" },
			func(s string) string { return strings.ToUpper(s) + " *feed.json" },
		} {
			// A new body each round, so no 304 skips the check.
			body := dated(day1, strings.Repeat("p", i+1))
			e.fs.set("/data/feed.json", body)
			companion := format(tc.sum(body))
			e.fs.set("/data/feed.json."+string(tc.alg), companion)
			res, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
			if err != nil || res.Manifest.Integrity != vulnfinding.IntegrityChecksum {
				t.Fatalf("%s %q: %+v %v", tc.alg, companion, res.Manifest, err)
			}
		}
	}
}

func TestSyncChecksumMismatchRejected(t *testing.T) {
	e := newSyncEnv(t)
	good := dated(day1, "payload")
	e.fs.set("/data/feed.json", good)
	e.fs.set("/data/feed.json.sha256", sha256Hex(good))
	f := checksumFeed(e, ChecksumSHA256)
	prev, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate})
	if err != nil {
		t.Fatal(err)
	}
	tampered := dated(day2, "tampered")
	e.fs.set("/data/feed.json", tampered)
	cases := map[string]struct {
		companion string
		want      error
	}{
		"mismatch":      {sha256Hex(good), ErrChecksumMismatch},
		"wrong file":    {sha256Hex(tampered) + "  other.json", ErrChecksumMalformed},
		"sha512 length": {sha512Hex(tampered), ErrChecksumMalformed},
		"not hex":       {strings.Repeat("z", 64), ErrChecksumMalformed},
		"empty":         {"", ErrChecksumMalformed},
		"extra fields":  {sha256Hex(tampered) + " feed.json extra", ErrChecksumMalformed},
		"control chars": {sha256Hex(tampered) + "\x00", ErrChecksumMalformed},
		"oversize":      {sha256Hex(tampered) + strings.Repeat(" ", MaxChecksumBytes), ErrTooLarge},
	}
	for name, tc := range cases {
		e.fs.set("/data/feed.json.sha256", tc.companion)
		if _, err := e.syncer.Sync(context.Background(), f, SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		cur, err := e.store.Load("sum")
		if err != nil || cur.SHA256 != prev.Manifest.SHA256 {
			t.Errorf("%s: previous not kept: %+v %v", name, cur, err)
		}
	}
	if len(tmpFiles(t, e.dir)) != 0 {
		t.Fatal("temp file left after checksum rejection")
	}
}

func TestSyncChecksumCompanionMissingRejected(t *testing.T) {
	e := newSyncEnv(t)
	e.fs.set("/data/feed.json", dated(day1, "payload"))
	if _, err := e.syncer.Sync(context.Background(), checksumFeed(e, ChecksumSHA256), SyncOptions{ContentDate: firstLineDate}); !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("%v, want ErrHTTPStatus", err)
	}
	if _, err := e.store.Load("sum"); !errors.Is(err, ErrNoSnapshot) {
		t.Fatal("accepted without checksum")
	}
}
