// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// ubuntuDeclaredBytes is the size the live sync reported for the OSV
// Ubuntu all.zip (live host .30, 2026-11-20): it exceeded the old 512 MiB
// cap.
const ubuntuDeclaredBytes int64 = 821463306

func TestOSVUbuntuCapFitsLiveArchive(t *testing.T) {
	f, ok := FeedByName("osv-ubuntu")
	if !ok {
		t.Fatal("osv-ubuntu missing from the feed table")
	}
	if f.MaxBytes < ubuntuDeclaredBytes {
		t.Fatalf("osv-ubuntu MaxBytes = %d, below the live archive size %d", f.MaxBytes, ubuntuDeclaredBytes)
	}
	if f.MaxBytes != MaxFeedBytesOSVUbuntu {
		t.Fatalf("osv-ubuntu MaxBytes = %d, want MaxFeedBytesOSVUbuntu", f.MaxBytes)
	}
	if err := f.validate(); err != nil {
		t.Fatalf("osv-ubuntu invalid: %v", err)
	}
}

func TestOtherFeedsKeepDefaultCap(t *testing.T) {
	for _, f := range Feeds() {
		if f.Name == "osv-ubuntu" || f.Name == "nvd-modified" {
			continue
		}
		if f.MaxBytes != MaxFeedBytesDefault {
			t.Errorf("feed %s MaxBytes = %d, want the default %d", f.Name, f.MaxBytes, MaxFeedBytesDefault)
		}
	}
}

func TestFetchStillRefusesDeclaredSizeOverDefaultCap(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(ubuntuDeclaredBytes, 10))
		w.WriteHeader(http.StatusOK)
	})
	f := newTestFetcher(t, pool, 0, srv)
	_, err := f.Fetch(context.Background(), srv.URL+"/Ubuntu/all.zip", MaxFeedBytesDefault, Validators{}, io.Discard)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge under the 512 MiB cap", err)
	}
}

func TestFetchAcceptsDeclaredSizeUnderUbuntuCap(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Declares the live size and sends nothing: the size check must
		// pass, and the body read then fails rather than the size check.
		w.Header().Set("Content-Length", strconv.FormatInt(ubuntuDeclaredBytes, 10))
		w.WriteHeader(http.StatusOK)
	})
	f := newTestFetcher(t, pool, 0, srv)
	_, err := f.Fetch(context.Background(), srv.URL+"/Ubuntu/all.zip", MaxFeedBytesOSVUbuntu, Validators{}, io.Discard)
	if err == nil {
		t.Fatal("Fetch of a truncated body succeeded")
	}
	if errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v: declared live size refused under the Ubuntu cap", err)
	}
}

func TestSyncTruncatedUbuntuDownloadKeepsNoSnapshot(t *testing.T) {
	srv, pool := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "2026-11-20T00:00:00Z\npartial")
	})
	f := newTestFetcher(t, pool, 0, srv)
	st, _, _ := newTestStore(t)
	sy, err := NewSyncer(f, st)
	if err != nil {
		t.Fatal(err)
	}
	feed := Feed{
		Name: "osv-ubuntu", SourceID: "osv", URL: srv.URL + "/Ubuntu/all.zip",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesOSVUbuntu, DateKind: DateKindDated,
	}
	if _, err := sy.Sync(context.Background(), feed, SyncOptions{Sequence: 1, ContentDate: firstLineDate}); err == nil {
		t.Fatal("Sync of a truncated download succeeded")
	}
	if _, err := st.Load(feed.Name); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("Load after truncated download: err = %v, want ErrNoSnapshot", err)
	}
	entries, err := os.ReadDir(st.objectDir(feed.Name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("object directory holds %d leftover file(s) after a failed download", len(entries))
	}
}

func TestParseOSVArchiveSizeGateFollowsUbuntuCap(t *testing.T) {
	ctx := context.Background()
	none := func(OSVRecord) error { return nil }

	if _, err := ParseOSVArchive(ctx, bytes.NewReader(nil), MaxFeedBytesOSVUbuntu+1, none); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("size above the Ubuntu cap: err = %v, want ErrFeedLimit", err)
	}
	// Above the old 512 MiB cap but inside the new one: the size gate
	// passes, so the failure comes from reading the archive, not the gate.
	_, err := ParseOSVArchive(ctx, failingReaderAt{}, ubuntuDeclaredBytes, none)
	if err == nil {
		t.Fatal("unreadable archive parsed")
	}
	if errors.Is(err, ErrFeedLimit) {
		t.Fatalf("live-size archive refused by the size gate: %v", err)
	}
}

// failingReaderAt fails every read.
type failingReaderAt struct{}

func (failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, errors.New("disk gone") }
