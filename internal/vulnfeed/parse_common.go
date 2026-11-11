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
	// MaxJSONMembers bounds the members of any single JSON array or object
	// inside a record; checkJSON enforces it while it walks, before a
	// value is unmarshalled, so a run of tiny elements cannot expand into
	// a large allocation.
	MaxJSONMembers = 65_536
	// maxJSONKeyBytes bounds a single object key.
	maxJSONKeyBytes = 256
	// recordWindowSlack is the room a record window leaves beyond the
	// record limit for the separator and whitespace before the record;
	// the exact record size is checked separately.
	recordWindowSlack = 64 << 10
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

// boundedReader caps the total bytes read from a feed and, while a window
// is open, the bytes of one record. Once a cap is exceeded every further
// read fails with ErrFeedLimit.
//
// A window is anchored at the record's start offset in the stream (the
// json.Decoder's InputOffset), not at the bytes read so far: bytes the
// decoder read ahead before the record started count for that record,
// and reads stop at the window end, so read-ahead is never charged to a
// record it does not belong to. Only a read the decoder needs beyond the
// window end fails.
type boundedReader struct {
	r         io.Reader
	total     int64
	maxTotal  int64
	windowed  bool
	windowEnd int64
	exceeded  bool
	ioErr     error
}

func newBoundedReader(r io.Reader, maxTotal int64) *boundedReader {
	return &boundedReader{r: r, maxTotal: maxTotal}
}

// startWindow limits the stream to max bytes from offset start on, until
// endWindow is called.
func (b *boundedReader) startWindow(start, max int64) {
	b.windowed = true
	b.windowEnd = start + max
}

// endWindow lifts the record window; the total cap stays.
func (b *boundedReader) endWindow() { b.windowed = false }

// Read implements io.Reader.
func (b *boundedReader) Read(p []byte) (int, error) {
	if b.exceeded {
		return 0, ErrFeedLimit
	}
	if len(p) == 0 {
		return 0, nil
	}
	// One byte past the total cap is read to tell "exactly at the cap"
	// from "more data".
	budget := b.maxTotal - b.total + 1
	if b.windowed {
		w := b.windowEnd - b.total
		if w <= 0 {
			b.exceeded = true
			return 0, ErrFeedLimit
		}
		budget = min(budget, w)
	}
	if int64(len(p)) > budget {
		p = p[:budget]
	}
	n, err := b.r.Read(p)
	b.total += int64(n)
	if b.total > b.maxTotal {
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
// shared by every parser: valid UTF-8, nesting depth at most maxDepth, at
// most MaxJSONMembers members per array or object, object keys of
// printable ASCII, at most maxJSONKeyBytes, unique per object under ASCII
// case folding, and nothing after the value.
func checkJSON(data []byte, maxDepth int) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8: %w", ErrFeedMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
		members   int
		keys      map[string]struct{}
	}
	// member counts one more member of the innermost container.
	member := func(f *frame) error {
		if f == nil {
			return nil
		}
		if f.members++; f.members > MaxJSONMembers {
			return fmt.Errorf("JSON container with more than %d members: %w", MaxJSONMembers, ErrFeedLimit)
		}
		return nil
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
			if err := member(top); err != nil {
				return err
			}
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
		if top != nil && !top.object {
			if err := member(top); err != nil {
				return err
			}
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

// recordSkippable reports whether err rejects a single record only: the
// record breaks a field or shape rule (ErrFeedMalformed) but no size,
// depth or count limit. Such a record is skipped and counted; every other
// error (limits, a broken stream, I/O, cancellation, duplicates the
// parser reports as fatal) aborts the feed.
func recordSkippable(err error) bool {
	return errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit)
}

// decodeRecord decodes the next JSON value of dec as raw bytes, reading
// at most max bytes (plus recordWindowSlack for the separator) from the
// value's start. A value longer than max fails with ErrFeedLimit; other
// failures are mapped by br.fail.
func decodeRecord(dec *json.Decoder, br *boundedReader, what string, max int64) (json.RawMessage, error) {
	br.startWindow(dec.InputOffset(), max+recordWindowSlack)
	var raw json.RawMessage
	err := dec.Decode(&raw)
	br.endWindow()
	if err != nil {
		return nil, br.fail(what, err)
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes: %w", what, max, ErrFeedLimit)
	}
	return raw, nil
}

// nextKey reads the next object key of dec within a small window. A key
// that is not a string fails with ErrFeedMalformed; the key's content is
// not checked here.
func nextKey(dec *json.Decoder, br *boundedReader, what string) (string, error) {
	br.startWindow(dec.InputOffset(), maxJSONKeyBytes+recordWindowSlack)
	tok, err := dec.Token()
	br.endWindow()
	if err != nil {
		return "", br.fail(what, err)
	}
	k, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("%s: %w", what, ErrFeedMalformed)
	}
	return k, nil
}

// skipValueRest consumes the rest of a value whose first token first has
// already been read, at most MaxJSONDepth deep. The caller bounds the
// bytes with a window.
func skipValueRest(dec *json.Decoder, first json.Token) error {
	depth := 0
	tok := first
	for {
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if depth++; depth > MaxJSONDepth {
					return fmt.Errorf("JSON nested deeper than %d: %w", MaxJSONDepth, ErrFeedLimit)
				}
			default:
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
		var err error
		if tok, err = dec.Token(); err != nil {
			return err
		}
	}
}

// more reports whether the current array or object of dec has another
// member. The whitespace it skips is bounded by recordWindowSlack, so a
// run of whitespace cannot grow the decoder's buffer; a longer run makes
// the next token fail with ErrFeedLimit.
func more(dec *json.Decoder, br *boundedReader) bool {
	br.startWindow(dec.InputOffset(), recordWindowSlack)
	ok := dec.More()
	br.endWindow()
	return ok
}

// expectDelim reads one token and requires it to be delimiter d.
func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return fmt.Errorf("expected %q: %w", d, ErrFeedMalformed)
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
