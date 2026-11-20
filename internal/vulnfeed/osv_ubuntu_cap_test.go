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
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// ubuntuDeclaredBytes is the compressed size of the OSV Ubuntu all.zip
// as observed by a live sync on 2026-11-20. It exceeds the former 512 MiB
// per-download cap. This is the compressed size only; the uncompressed
// total is not measured (see MaxOSVArchiveBytes).
const ubuntuDeclaredBytes int64 = 821463306

// Measured on 2026-11-20 from the zip central directory of the OSV Ubuntu
// all.zip (range requests, no entry was inflated). The caps in
// parse_osv.go are derived from these values with a 2x reserve.
const (
	// ubuntuMeasuredUncompressedBytes is the sum of the declared
	// uncompressed sizes of all entries (8.00 GiB).
	ubuntuMeasuredUncompressedBytes int64 = 8_591_856_407
	// ubuntuMeasuredEntries is the number of entries in the archive.
	ubuntuMeasuredEntries = 74_879
	// ubuntuMeasuredLargestEntry is the largest declared entry size.
	ubuntuMeasuredLargestEntry int64 = 4_973_117
)

// TestOSVArchiveCapsHaveTwoFoldReserve pins the archive caps to the
// measured live archive: each cap is at least twice the measured value.
func TestOSVArchiveCapsHaveTwoFoldReserve(t *testing.T) {
	if MaxOSVArchiveBytes < 2*ubuntuMeasuredUncompressedBytes {
		t.Errorf("MaxOSVArchiveBytes = %d, below 2x the measured total %d", MaxOSVArchiveBytes, ubuntuMeasuredUncompressedBytes)
	}
	if int64(MaxOSVRecordBytes) < 2*ubuntuMeasuredLargestEntry {
		t.Errorf("MaxOSVRecordBytes = %d, below 2x the largest measured entry %d", MaxOSVRecordBytes, ubuntuMeasuredLargestEntry)
	}
	if MaxOSVArchiveFiles < 2*ubuntuMeasuredEntries {
		t.Errorf("MaxOSVArchiveFiles = %d, below 2x the measured entry count %d", MaxOSVArchiveFiles, ubuntuMeasuredEntries)
	}
}

// TestParseOSVArchiveAcceptsMeasuredLargestEntry: a valid record of the
// largest measured entry size must parse; before the per-entry cap was
// raised it was refused with ErrFeedLimit.
func TestParseOSVArchiveAcceptsMeasuredLargestEntry(t *testing.T) {
	head := `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","details":"`
	tail := `"}`
	pad := int(ubuntuMeasuredLargestEntry) - len(head) - len(tail)
	body := []byte(head + strings.Repeat("a", pad) + tail)
	if int64(len(body)) != ubuntuMeasuredLargestEntry {
		t.Fatalf("test record is %d bytes, want %d", len(body), ubuntuMeasuredLargestEntry)
	}
	data := makeZip(t, zipFile{"OSV-1.json", body})
	sum, err := ParseOSVArchive(context.Background(), bytes.NewReader(data), int64(len(data)), func(OSVRecord) error { return nil })
	if err != nil {
		t.Fatalf("largest measured entry refused: %v", err)
	}
	if sum.Records != 1 {
		t.Fatalf("records = %d, want 1", sum.Records)
	}
}

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
