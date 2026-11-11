// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

// Shared bounded decoding for the feed parsers (ADR 0011 D4).
//
// Feed bytes are untrusted. Every parser caps the input size, the size of
// each record, the JSON nesting depth and every collection count before it
// hands a value to a caller. Object keys must be printable ASCII and unique
// per object (compared case-insensitively, the way encoding/json matches
// them), so a duplicated or case-shifted key cannot override a field.
// Fields a parser does not know are skipped by encoding/json and never
// reach the caller; they still count against the size and depth limits.
// Content dates come from the data only; no parser reads a clock.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Parser errors. Callers branch on these with errors.Is; the wrapped
// message never repeats untrusted feed content.
var (
	// ErrFeedMalformed: the feed data breaks its format or a field rule.
	ErrFeedMalformed = errors.New("vulnfeed: malformed feed data")
	// ErrFeedLimit: the feed data exceeds a size, depth or count limit.
	ErrFeedLimit = errors.New("vulnfeed: feed data exceeds a parse limit")
)

const (
	// MaxJSONDepth bounds the nesting of any JSON value a parser accepts,
	// counted from the record (or document) it decodes.
	MaxJSONDepth = 32
	// maxJSONKeyBytes bounds a single object key.
	maxJSONKeyBytes = 256
	// maxTimeBytes bounds a timestamp string before it is parsed.
	maxTimeBytes = 64
	// minFeedYear and maxFeedYear bound every parsed date; the snapshot
	// store applies the real future-skew check against its own clock.
	minFeedYear = 1970
	maxFeedYear = 2999
)

var (
	// cveIDRe is a CVE ID in the canonical upper-case spelling.
	cveIDRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	// feedVulnIDRe is the ADR 0011 D2 vuln_id pattern.
	feedVulnIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{1,63}$`)
	// feedVersionRe is a package version (Debian, OSV ecosystems).
	feedVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_*-]{0,127}$`)
)

// boundedReader caps the total bytes read from a feed and, between calls
// to resetWindow, the bytes read for one record. Once a cap is exceeded
// every further read fails with ErrFeedLimit.
type boundedReader struct {
	r         io.Reader
	total     int64
	maxTotal  int64
	window    int64
	maxWindow int64
	exceeded  bool
	ioErr     error
}

func newBoundedReader(r io.Reader, maxTotal int64) *boundedReader {
	return &boundedReader{r: r, maxTotal: maxTotal, maxWindow: maxTotal}
}

// resetWindow starts a new per-record window of at most max bytes.
func (b *boundedReader) resetWindow(max int64) {
	b.window = 0
	b.maxWindow = max
}

// Read implements io.Reader.
func (b *boundedReader) Read(p []byte) (int, error) {
	if b.exceeded {
		return 0, ErrFeedLimit
	}
	budget := min(b.maxTotal-b.total, b.maxWindow-b.window) + 1
	if budget <= 0 {
		budget = 1
	}
	if int64(len(p)) > budget {
		p = p[:budget]
	}
	n, err := b.r.Read(p)
	b.total += int64(n)
	b.window += int64(n)
	if b.total > b.maxTotal || b.window > b.maxWindow {
		b.exceeded = true
		return n, ErrFeedLimit
	}
	if err != nil && !errors.Is(err, io.EOF) {
		b.ioErr = err
	}
	return n, err
}

// fail turns a decoder or scanner error into the parser's error: a limit
// hit, an I/O error of the underlying reader, or malformed data. The
// original error text is dropped because it can quote feed bytes.
func (b *boundedReader) fail(what string, err error) error {
	switch {
	case b.exceeded || errors.Is(err, ErrFeedLimit):
		return fmt.Errorf("%s: %w", what, ErrFeedLimit)
	case b.ioErr != nil:
		return fmt.Errorf("%s: read feed: %w", what, b.ioErr)
	case errors.Is(err, ErrFeedMalformed):
		return fmt.Errorf("%s: %w", what, err)
	default:
		return fmt.Errorf("%s: %w", what, ErrFeedMalformed)
	}
}

// readAllBounded reads r completely, failing with ErrFeedLimit above max.
func readAllBounded(r io.Reader, max int64) ([]byte, error) {
	br := newBoundedReader(r, max)
	data, err := io.ReadAll(br)
	if err != nil {
		return nil, br.fail("read feed", err)
	}
	return data, nil
}

// DecompressGzip returns a reader of the gzip-compressed stream r that
// fails with ErrFeedLimit once more than maxOut decompressed bytes are
// read (ADR 0011 D4 decompression limit). Close releases the decompressor;
// it does not close r.
func DecompressGzip(r io.Reader, maxOut int64) (io.ReadCloser, error) {
	if maxOut <= 0 {
		return nil, fmt.Errorf("gzip limit: %w", ErrFeedLimit)
	}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip header: %w", ErrFeedMalformed)
	}
	return &gzipBounded{zr: zr, br: newBoundedReader(zr, maxOut)}, nil
}

type gzipBounded struct {
	zr *gzip.Reader
	br *boundedReader
}

// Read implements io.Reader; corrupt compressed data is ErrFeedMalformed.
func (g *gzipBounded) Read(p []byte) (int, error) {
	n, err := g.br.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrFeedLimit) {
		return n, fmt.Errorf("gzip data: %w", ErrFeedMalformed)
	}
	return n, err
}

// Close implements io.Closer.
func (g *gzipBounded) Close() error { return g.zr.Close() }

// checkJSON walks a single JSON value once and enforces the shape rules
// shared by every parser: valid UTF-8, nesting depth at most maxDepth,
// object keys of printable ASCII, at most maxJSONKeyBytes, unique per object
// under ASCII case folding, and nothing after the value.
func checkJSON(data []byte, maxDepth int) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8: %w", ErrFeedMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	var stack []*frame
	seen := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if !seen || len(stack) != 0 {
				return fmt.Errorf("unexpected end of JSON: %w", ErrFeedMalformed)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("JSON syntax: %w", ErrFeedMalformed)
		}
		if seen && len(stack) == 0 {
			return fmt.Errorf("data after the JSON value: %w", ErrFeedMalformed)
		}
		seen = true
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
			continue
		}
		if top != nil && top.object && top.expectKey {
			k, _ := tok.(string)
			if err := checkJSONKey(k); err != nil {
				return err
			}
			folded := strings.ToLower(k)
			if _, dup := top.keys[folded]; dup {
				return fmt.Errorf("duplicate object key: %w", ErrFeedMalformed)
			}
			top.keys[folded] = struct{}{}
			top.expectKey = false
			continue
		}
		if d, ok := tok.(json.Delim); ok { // '{' or '['
			if len(stack) >= maxDepth {
				return fmt.Errorf("JSON nested deeper than %d: %w", maxDepth, ErrFeedLimit)
			}
			f := &frame{object: d == '{', expectKey: d == '{'}
			if f.object {
				f.keys = make(map[string]struct{})
			}
			stack = append(stack, f)
			continue
		}
		if top != nil && top.object {
			top.expectKey = true
		}
	}
}

// checkJSONKey allows only printable ASCII keys, so encoding/json's
// case-insensitive matching cannot apply Unicode folding (for example the
// Kelvin sign for "k") and checkJSON's duplicate rule matches it exactly.
func checkJSONKey(k string) error {
	if k == "" || len(k) > maxJSONKeyBytes {
		return fmt.Errorf("object key length: %w", ErrFeedMalformed)
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return fmt.Errorf("object key not printable ASCII: %w", ErrFeedMalformed)
		}
	}
	return nil
}

// decodeChecked checks the shape of one JSON value and decodes it into v.
// Unknown fields are skipped; a wrong JSON type for a known field fails.
func decodeChecked(data []byte, v any) error {
	if err := checkJSON(data, MaxJSONDepth); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("JSON types: %w", ErrFeedMalformed)
	}
	return nil
}

// checkText validates free text from a feed that is shown as text only:
// valid UTF-8, at most max bytes, no control characters other than tab,
// newline and carriage return, and no bidirectional override or isolate
// characters that could reorder surrounding UI text.
func checkText(s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("text longer than %d bytes: %w", max, ErrFeedLimit)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("text not UTF-8: %w", ErrFeedMalformed)
	}
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
		case r < 0x20 || (r >= 0x7f && r < 0xa0):
			return fmt.Errorf("control character in text: %w", ErrFeedMalformed)
		case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			return fmt.Errorf("bidi control in text: %w", ErrFeedMalformed)
		}
	}
	return nil
}

// checkToken validates a short single-line value (a source name, a tag,
// a URL kept as text): checkText rules, no whitespace, 1..max bytes.
func checkToken(s string, max int) error {
	if s == "" {
		return fmt.Errorf("empty value: %w", ErrFeedMalformed)
	}
	if err := checkText(s, max); err != nil {
		return err
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return fmt.Errorf("whitespace in value: %w", ErrFeedMalformed)
	}
	return nil
}

// parseFeedTime parses a timestamp from feed data with the first matching
// layout. Zone-less layouts are read as UTC. The result is UTC and its year
// lies within [minFeedYear, maxFeedYear].
func parseFeedTime(s string, layouts ...string) (time.Time, error) {
	if s == "" || len(s) > maxTimeBytes {
		return time.Time{}, fmt.Errorf("timestamp length: %w", ErrFeedMalformed)
	}
	for _, l := range layouts {
		t, err := time.Parse(l, s)
		if err != nil {
			continue
		}
		t = t.UTC()
		if y := t.Year(); y < minFeedYear || y > maxFeedYear {
			return time.Time{}, fmt.Errorf("timestamp year out of range: %w", ErrFeedMalformed)
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("timestamp format: %w", ErrFeedMalformed)
}
