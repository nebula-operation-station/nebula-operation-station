// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// spaceReader yields n spaces without holding them in memory.
type spaceReader struct{ n int64 }

func (s *spaceReader) Read(p []byte) (int, error) {
	if s.n <= 0 {
		return 0, io.EOF
	}
	k := min(int64(len(p)), s.n)
	for i := range p[:k] {
		p[i] = ' '
	}
	s.n -= k
	return int(k), nil
}

// windowMark marks a position between records in the documents below
// where TestTokenReadsOutsideRecordsAreBounded inserts whitespace.
const windowMark = "~"

// spaceRunBytes is the whitespace run a feed must reject between records:
// far beyond recordWindowSlack but below every parser's stream cap, so
// only a token window can stop it.
const spaceRunBytes = 16 << 20

// spaceRunBudgetBytes bounds what a parser may allocate while rejecting a
// spaceRunBytes run: the decoder's buffer must stay near recordWindowSlack.
const spaceRunBudgetBytes = 4 << 20

// TestTokenReadsOutsideRecordsAreBounded: every token read between
// records (the leading '{', the ':' and '[' after a key, the closing
// delimiters and the end-of-input check) skips at most recordWindowSlack
// bytes of whitespace. A short run is accepted; a run far beyond the
// window fails with ErrFeedLimit without growing the decoder's buffer.
func TestTokenReadsOutsideRecordsAreBounded(t *testing.T) {
	nvd := func(r io.Reader) error {
		_, err := ParseNVD(context.Background(), r, func(NVDRecord) error { return nil })
		return err
	}
	kev := func(r io.Reader) error {
		_, err := ParseKEV(context.Background(), r)
		return err
	}
	debian := func(r io.Reader) error {
		_, err := ParseDebianTracker(context.Background(), r, func(DebianEntry) error { return nil })
		return err
	}
	feeds := []struct {
		name  string
		parse func(io.Reader) error
		doc   string
	}{
		{"nvd", nvd, `~{~` + nvdHead + `"vulnerabilities"~:~[~` + nvdItem("CVE-2024-0001", ``) + `~]~}~`},
		{"kev", kev, `~{~"catalogVersion"~:~"2024.10.21","dateReleased":"2024-10-21T15:00:15Z","count":1,"vulnerabilities"~:~[~` +
			kevEntry(``) + `~]~}~`},
		{"debian", debian, `~{~` + debianGoodPackage + `~}~`},
	}
	for _, f := range feeds {
		parts := strings.Split(f.doc, windowMark)
		for i := 1; i < len(parts); i++ {
			before := strings.Join(parts[:i], "")
			after := strings.Join(parts[i:], "")
			t.Run(f.name+"/mark"+strconv.Itoa(i), func(t *testing.T) {
				run := func(n int64) error {
					return f.parse(io.MultiReader(strings.NewReader(before), &spaceReader{n: n}, strings.NewReader(after)))
				}
				if err := run(1024); err != nil {
					t.Fatalf("short whitespace run: %v", err)
				}
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				err := run(spaceRunBytes)
				runtime.ReadMemStats(&after)
				if !errors.Is(err, ErrFeedLimit) {
					t.Fatalf("long whitespace run: err = %v, want ErrFeedLimit", err)
				}
				if got := after.TotalAlloc - before.TotalAlloc; got > spaceRunBudgetBytes {
					t.Fatalf("long whitespace run allocated %d bytes, budget %d", got, spaceRunBudgetBytes)
				}
			})
		}
	}
}

// TestExpectDelimAndEOF covers the error mapping of the window helpers.
func TestExpectDelimAndEOF(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"delimiter", ` {`, nil},
		{"other delimiter", `[`, ErrFeedMalformed},
		{"string", `"x"`, ErrFeedMalformed},
		{"empty", ``, ErrFeedMalformed},
		{"long string", `"` + strings.Repeat("a", recordWindowSlack+1) + `"`, ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run("delim/"+tc.name, func(t *testing.T) {
			br := newBoundedReader(strings.NewReader(tc.in), 1<<30)
			err := expectDelim(json.NewDecoder(br), br, "x", '{')
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == ErrFeedMalformed && errors.Is(err, ErrFeedLimit) {
				t.Fatalf("err = %v, want no ErrFeedLimit", err)
			}
		})
	}
	eof := []struct {
		name string
		in   string
		want error
	}{
		{"end", `{} ` + "\n", nil},
		{"data after", `{} 1`, ErrFeedMalformed},
		{"second value", `{}{}`, ErrFeedMalformed},
		{"syntax after", `{} }`, ErrFeedMalformed},
	}
	for _, tc := range eof {
		t.Run("eof/"+tc.name, func(t *testing.T) {
			br := newBoundedReader(strings.NewReader(tc.in), 1<<30)
			dec := json.NewDecoder(br)
			if err := expectDelim(dec, br, "x", '{'); err != nil {
				t.Fatal(err)
			}
			if err := expectDelim(dec, br, "x", '}'); err != nil {
				t.Fatal(err)
			}
			err := expectEOF(dec, br, "x")
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
