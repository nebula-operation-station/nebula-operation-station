// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readFixture reads a file under testdata.
func readFixture(t testing.TB, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestBoundedReaderStopsAtTotalLimit(t *testing.T) {
	br := newBoundedReader(strings.NewReader("0123456789"), 9)
	_, err := io.ReadAll(br)
	if !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("err = %v, want ErrFeedLimit", err)
	}
	if !errors.Is(br.fail("x", err), ErrFeedLimit) {
		t.Fatal("fail must keep ErrFeedLimit")
	}
	// Exactly at the limit is fine.
	b, err := io.ReadAll(newBoundedReader(strings.NewReader("0123456789"), 10))
	if err != nil || string(b) != "0123456789" {
		t.Fatalf("at limit: %q, %v", b, err)
	}
}

func TestBoundedReaderWindowLimitsOneRecord(t *testing.T) {
	br := newBoundedReader(strings.NewReader(strings.Repeat("a", 100)), 1000)
	br.resetWindow(10)
	buf := make([]byte, 64)
	n, err := br.Read(buf)
	if n > 11 {
		t.Fatalf("read %d bytes in a 10-byte window", n)
	}
	for err == nil {
		_, err = br.Read(buf)
	}
	if !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("err = %v, want ErrFeedLimit", err)
	}
	// Sticky: later reads fail too, even after a reset.
	br.resetWindow(1000)
	if _, err := br.Read(buf); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("after exceed: %v", err)
	}
}

func TestBoundedReaderKeepsIOError(t *testing.T) {
	ioErr := errors.New("disk gone")
	br := newBoundedReader(io.MultiReader(strings.NewReader("{"), errReader{ioErr}), 100)
	_, err := io.ReadAll(br)
	got := br.fail("x", err)
	if !errors.Is(got, ioErr) || errors.Is(got, ErrFeedMalformed) {
		t.Fatalf("fail = %v, want the I/O error", got)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecompressGzipEnforcesOutputLimit(t *testing.T) {
	bomb := gzipBytes(t, bytes.Repeat([]byte{'0'}, 1<<20))
	zr, err := DecompressGzip(bytes.NewReader(bomb), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	if _, err := io.ReadAll(zr); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("err = %v, want ErrFeedLimit", err)
	}

	zr, err = DecompressGzip(bytes.NewReader(gzipBytes(t, []byte("hello"))), 5)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil || string(b) != "hello" {
		t.Fatalf("got %q, %v", b, err)
	}
}

func TestDecompressGzipRejectsCorruptData(t *testing.T) {
	if _, err := DecompressGzip(strings.NewReader("not gzip"), 100); !errors.Is(err, ErrFeedMalformed) {
		t.Fatalf("header: %v", err)
	}
	gz := gzipBytes(t, []byte(strings.Repeat("abc", 100)))
	gz[len(gz)-5] ^= 0xff // break the CRC/size trailer
	zr, err := DecompressGzip(bytes.NewReader(gz), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(zr); !errors.Is(err, ErrFeedMalformed) {
		t.Fatalf("trailer: %v", err)
	}
	if _, err := DecompressGzip(strings.NewReader(""), 0); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("zero limit: %v", err)
	}
}

func TestCheckJSONShapeRules(t *testing.T) {
	deep := strings.Repeat("[", MaxJSONDepth+1) + strings.Repeat("]", MaxJSONDepth+1)
	okDeep := strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth)
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"object", `{"a":1,"b":[true,null,"x"],"c":{"d":1e999}}`, nil},
		{"max depth", okDeep, nil},
		{"too deep", deep, ErrFeedLimit},
		{"duplicate key", `{"a":1,"a":2}`, ErrFeedMalformed},
		{"case duplicate key", `{"status":"open","Status":"resolved"}`, ErrFeedMalformed},
		{"duplicate key nested", `{"x":{"a":1,"A":2}}`, ErrFeedMalformed},
		{"same key in sibling objects", `[{"a":1},{"a":2}]`, nil},
		{"kelvin sign key", "{\"K\":1}", ErrFeedMalformed},
		{"control in key", "{\"a\\u0001\":1}", ErrFeedMalformed},
		{"empty key", `{"":1}`, ErrFeedMalformed},
		{"long key", `{"` + strings.Repeat("k", maxJSONKeyBytes+1) + `":1}`, ErrFeedMalformed},
		{"trailing data", `{} {}`, ErrFeedMalformed},
		{"truncated", `{"a":`, ErrFeedMalformed},
		{"empty", ``, ErrFeedMalformed},
		{"invalid utf8", "{\"a\":\"\xff\"}", ErrFeedMalformed},
		{"syntax", `{"a" 1}`, ErrFeedMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkJSON([]byte(tc.in), MaxJSONDepth)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCheckTextRejectsControlAndBidi(t *testing.T) {
	good := []string{"plain", "tab\tnew\nline\r\n", "Ümlaut ✓"}
	for _, s := range good {
		if err := checkText(s, 100); err != nil {
			t.Errorf("checkText(%q) = %v", s, err)
		}
	}
	bad := map[string]error{
		"esc\x1b[31m":                    ErrFeedMalformed,
		"del\x7f":                        ErrFeedMalformed,
		"c1\u0085":                       ErrFeedMalformed,
		"rlo" + string(rune(0x202e)):     ErrFeedMalformed,
		"isolate" + string(rune(0x2066)): ErrFeedMalformed,
		"bad\xff":                        ErrFeedMalformed,
		strings.Repeat("x", 101):         ErrFeedLimit,
	}
	for s, want := range bad {
		if err := checkText(s, 100); !errors.Is(err, want) {
			t.Errorf("checkText(%q) = %v, want %v", s, err, want)
		}
	}
	if err := checkToken("a b", 10); !errors.Is(err, ErrFeedMalformed) {
		t.Errorf("token with space: %v", err)
	}
	if err := checkToken("", 10); !errors.Is(err, ErrFeedMalformed) {
		t.Errorf("empty token: %v", err)
	}
}

func TestParseFeedTimeBounds(t *testing.T) {
	got, err := parseFeedTime("2024-10-21T15:00:15+02:00", time.RFC3339)
	if err != nil || !got.Equal(time.Date(2024, 10, 21, 13, 0, 15, 0, time.UTC)) || got.Location() != time.UTC {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, s := range []string{"", "1969-12-31T23:59:59Z", "3000-01-01T00:00:00Z", "yesterday", strings.Repeat("9", maxTimeBytes+1)} {
		if _, err := parseFeedTime(s, time.RFC3339); !errors.Is(err, ErrFeedMalformed) {
			t.Errorf("parseFeedTime(%q) = %v", s, err)
		}
	}
}
