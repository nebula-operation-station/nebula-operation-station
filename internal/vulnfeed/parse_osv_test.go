// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseOSVDebianRecord(t *testing.T) {
	rec, err := ParseOSV(readFixture(t, "parse_osv", "dsa.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := OSVRecord{
		ID:        "DSA-5793-1",
		Modified:  time.Date(2024, 10, 22, 8, 15, 30, 123456000, time.UTC),
		Published: time.Date(2024, 10, 21, 0, 0, 0, 0, time.UTC),
		Aliases:   []string{"CVE-2024-10229", "CVE-2024-10230"},
		Affected: []OSVAffected{{
			Ecosystem: "Debian:12", Name: "chromium",
			Ranges: []OSVRange{{Type: OSVRangeEcosystem, Events: []OSVEvent{
				{OSVIntroduced, "0"}, {OSVFixed, "130.0.6723.69-1~deb12u1"},
			}}},
		}},
		SkippedAffected: 1,
	}
	if !reflect.DeepEqual(rec, want) {
		t.Fatalf("record:\n got %+v\nwant %+v", rec, want)
	}
	if got := rec.CVEs(); !slices.Equal(got, []string{"CVE-2024-10229", "CVE-2024-10230"}) {
		t.Fatalf("CVEs %v", got)
	}
}

func TestParseOSVSemverRangesSkipOtherTypes(t *testing.T) {
	rec, err := ParseOSV(readFixture(t, "parse_osv", "go.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Affected) != 1 {
		t.Fatalf("affected %+v", rec.Affected)
	}
	a := rec.Affected[0]
	if a.Ecosystem != "Go" || a.Name != "github.com/example/mod" || a.SkippedRanges != 2 || len(a.Ranges) != 1 {
		t.Fatalf("affected %+v", a)
	}
	wantEv := []OSVEvent{{OSVIntroduced, "0"}, {OSVFixed, "1.2.4"}, {OSVIntroduced, "2.0.0-rc.1"}, {OSVLastAffected, "2.0.1+build.5"}}
	if a.Ranges[0].Type != OSVRangeSemver || !slices.Equal(a.Ranges[0].Events, wantEv) {
		t.Fatalf("range %+v", a.Ranges[0])
	}
	if got := rec.CVEs(); !slices.Equal(got, []string{"CVE-2024-45678"}) {
		t.Fatalf("CVEs %v", got)
	}
}

func TestParseOSVRejectsMalformed(t *testing.T) {
	base := func(affected string) string {
		return `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","affected":[` + affected + `]}`
	}
	pkg := `"package":{"ecosystem":"Debian:12","name":"zlib"}`
	rng := func(typ, events string) string {
		return base(`{` + pkg + `,"ranges":[{"type":"` + typ + `","events":[` + events + `]}]}`)
	}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"not json", `nope`, ErrFeedMalformed},
		{"array", `[]`, ErrFeedMalformed},
		{"missing id", `{"modified":"2024-01-01T00:00:00Z"}`, ErrFeedMalformed},
		{"bad id", `{"id":"../etc","modified":"2024-01-01T00:00:00Z"}`, ErrFeedMalformed},
		{"missing modified", `{"id":"OSV-1"}`, ErrFeedMalformed},
		{"bad modified", `{"id":"OSV-1","modified":"yesterday"}`, ErrFeedMalformed},
		{"bad withdrawn", `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","withdrawn":"x"}`, ErrFeedMalformed},
		{"bad alias", `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":["a b"]}`, ErrFeedMalformed},
		{"alias wrong type", `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":"CVE-2024-1234"}`, ErrFeedMalformed},
		{"too many aliases", `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":[` + strings.TrimSuffix(strings.Repeat(`"CVE-2024-1234",`, MaxOSVAliases+1), ",") + `]}`, ErrRecordLimit},
		{"too many affected", base(strings.TrimSuffix(strings.Repeat(`{},`, MaxOSVAffected+1), ",")), ErrRecordLimit},
		{"too many ranges", base(`{` + pkg + `,"ranges":[` + strings.TrimSuffix(strings.Repeat(`{"type":"GIT","events":[]},`, MaxOSVRanges+1), ",") + `]}`), ErrRecordLimit},
		{"too many events", rng("ECOSYSTEM", strings.TrimSuffix(strings.Repeat(`{"introduced":"0"},`, MaxOSVEvents+1), ",")), ErrRecordLimit},
		{"too many ranges in record", base(strings.TrimSuffix(strings.Repeat(`{"ranges":[`+strings.TrimSuffix(strings.Repeat(`{},`, MaxOSVRanges), ",")+`]},`, MaxOSVRangesPerRecord/MaxOSVRanges+1), ",")), ErrRecordLimit},
		{"too many events in record", base(`{"ranges":[` + strings.TrimSuffix(strings.Repeat(`{"events":[`+strings.TrimSuffix(strings.Repeat(`{},`, MaxOSVEvents), ",")+`]},`, MaxOSVEventsPerRecord/MaxOSVEvents+1), ",") + `]}`), ErrRecordLimit},
		{"long alias", `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":["` + strings.Repeat("A", 65) + `"]}`, ErrRecordLimit},
		{"long id", `{"id":"` + strings.Repeat("A", 65) + `","modified":"2024-01-01T00:00:00Z"}`, ErrRecordLimit},
		{"long event version", rng("ECOSYSTEM", `{"introduced":"`+strings.Repeat("1", 129)+`"}`), ErrRecordLimit},
		{"long package name", base(`{"package":{"ecosystem":"Go","name":"` + strings.Repeat("a", 215) + `"}}`), ErrRecordLimit},
		{"case shadow id", `{"id":"OSV-1","ID":"OSV-2","modified":"2024-01-01T00:00:00Z"}`, ErrFeedMalformed},
		{"bad ecosystem", base(`{"package":{"ecosystem":"","name":"zlib"}}`), ErrFeedMalformed},
		{"bad package", base(`{"package":{"ecosystem":"Go","name":"a b"}}`), ErrFeedMalformed},
		{"two keys in event", rng("ECOSYSTEM", `{"introduced":"0","fixed":"1.0"}`), ErrFeedMalformed},
		{"empty event", rng("ECOSYSTEM", `{"introduced":"0"},{}`), ErrFeedMalformed},
		{"unknown event", rng("ECOSYSTEM", `{"introduced":"0"},{"patched":"1.0"}`), ErrFeedMalformed},
		{"event wrong type", rng("ECOSYSTEM", `{"introduced":0}`), ErrFeedMalformed},
		{"no introduced", rng("ECOSYSTEM", `{"fixed":"1.0"}`), ErrFeedMalformed},
		{"bad ecosystem version", rng("ECOSYSTEM", `{"introduced":"0"},{"fixed":"1.0;rm"}`), ErrFeedMalformed},
		{"bad semver", rng("SEMVER", `{"introduced":"0"},{"fixed":"1.2"}`), ErrFeedMalformed},
		{"semver leading v", rng("SEMVER", `{"introduced":"v1.0.0"}`), ErrFeedMalformed},
		{"too deep", `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","x":` + strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth) + `}`, ErrFeedLimit},
		{"too large", `{"id":"OSV-1","details":"` + strings.Repeat("a", MaxOSVRecordBytes) + `"}`, ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseOSV([]byte(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// A per-record limit only skips the record.
			if errors.Is(tc.want, ErrRecordLimit) && (errors.Is(err, ErrFeedLimit) || !recordSkippable(err)) {
				t.Fatalf("err = %v, want a skippable record error", err)
			}
		})
	}
	// Exactly at the per-record limits the record is accepted.
	evs := strings.TrimSuffix(strings.Repeat(`{"introduced":"0"},`, MaxOSVEvents), ",")
	at := base(`{` + pkg + `,"ranges":[` + strings.TrimSuffix(strings.Repeat(`{"type":"ECOSYSTEM","events":[`+evs+`]},`, MaxOSVEventsPerRecord/MaxOSVEvents), ",") + `]}`)
	rec, err := ParseOSV([]byte(at))
	if err != nil || len(rec.Affected) != 1 || len(rec.Affected[0].Ranges) != MaxOSVEventsPerRecord/MaxOSVEvents {
		t.Fatalf("at the limits: %v", err)
	}
}

// TestParseOSVDecodeStaysWithinFieldCaps: a 4 MiB record of tiny elements
// spread over capped arrays (the shape that made json.Unmarshal build
// about a million empty maps) is rejected during the walk.
func TestParseOSVDecodeStaysWithinFieldCaps(t *testing.T) {
	head := `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","affected":[`
	fill := func(build func(n int) string) []byte {
		// Grow n until the record is just below MaxOSVRecordBytes.
		n := 1
		for len(build(n*2)) < MaxOSVRecordBytes {
			n *= 2
		}
		for step := n / 2; step > 0; step /= 2 {
			if len(build(n+step)) < MaxOSVRecordBytes {
				n += step
			}
		}
		return []byte(build(n))
	}
	join := func(elem string, n int) string { return strings.TrimSuffix(strings.Repeat(elem+",", n), ",") }
	inputs := map[string][]byte{
		// ~20 ranges x 65,536 empty events: the review's example.
		"20 ranges of 65536 events": fill(func(n int) string {
			return head + `{"ranges":[` + join(`{"events":[`+join(`{}`, 65_536)+`]}`, n) + `]}]}`
		}),
		// The same events spread so that no single range exceeds its cap.
		"events spread at the per-range cap": fill(func(n int) string {
			return head + join(`{"ranges":[`+join(`{"events":[`+join(`{}`, MaxOSVEvents)+`]}`, 16)+`]}`, n) + `]}`
		}),
		"empty ranges":   fill(func(n int) string { return head + join(`{"ranges":[`+join(`{}`, MaxOSVRanges)+`]}`, n) + `]}` }),
		"empty affected": fill(func(n int) string { return head + join(`{}`, n) + `]}` }),
		"empty aliases": fill(func(n int) string {
			return `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":[` + join(`""`, n) + `]}`
		}),
		"wide events": fill(func(n int) string {
			var b strings.Builder
			for i := range n {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `"k%d":"0"`, i)
			}
			return head + `{"ranges":[{"events":[{` + b.String() + `}]}]}]}`
		}),
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			if len(in) > MaxOSVRecordBytes || len(in) < MaxOSVRecordBytes/2 {
				t.Fatalf("input is %d bytes", len(in))
			}
			assertRecordDecodeBudget(t, func() error { _, err := ParseOSV(in); return err })
		})
	}
}

func TestParseOSVIgnoresUnknownFields(t *testing.T) {
	in := `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","future":{"a":[{"b":"c"}]},"affected":[{"package":{"ecosystem":"Go","name":"x","new":1},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}],"database_specific":{"z":1}}]}]}`
	rec, err := ParseOSV([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Affected) != 1 || len(rec.Affected[0].Ranges) != 1 {
		t.Fatalf("got %+v", rec)
	}
}

type zipFile struct {
	name string
	body []byte
}

func makeZip(t testing.TB, files ...zipFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func parseZip(data []byte) ([]OSVRecord, OSVArchiveSummary, error) {
	var got []OSVRecord
	sum, err := ParseOSVArchive(context.Background(), bytes.NewReader(data), int64(len(data)), func(r OSVRecord) error {
		got = append(got, r)
		return nil
	})
	return got, sum, err
}

func TestParseOSVArchiveNewestModifiedIsContentDate(t *testing.T) {
	data := makeZip(t,
		zipFile{"DSA-5793-1.json", readFixture(t, "parse_osv", "dsa.json")},
		zipFile{"GO-2024-3000.json", readFixture(t, "parse_osv", "go.json")},
	)
	got, sum, err := parseZip(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || sum.Records != 2 || !sum.Newest.Equal(time.Date(2024, 11, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("summary %+v, records %d", sum, len(got))
	}
}

func TestParseOSVArchiveRejectsBadArchives(t *testing.T) {
	rec := readFixture(t, "parse_osv", "go.json")
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"not zip", []byte("PK nope"), ErrFeedMalformed},
		{"nested path", makeZip(t, zipFile{"a/GO-1.json", rec}), ErrFeedMalformed},
		{"traversal", makeZip(t, zipFile{"../GO-1.json", rec}), ErrFeedMalformed},
		{"not json name", makeZip(t, zipFile{"GO-1.txt", rec}), ErrFeedMalformed},
		{"duplicate name", makeZip(t, zipFile{"a.json", rec}, zipFile{"a.json", rec}), ErrFeedMalformed},
		{"duplicate id", makeZip(t, zipFile{"a.json", rec}, zipFile{"b.json", rec}), ErrFeedMalformed},
		{"record too deep", makeZip(t, zipFile{"a.json", []byte(`{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","x":` +
			strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth) + `}`)}), ErrFeedLimit},
		{"bad name after good file", makeZip(t, zipFile{"a.json", rec}, zipFile{"b/c.json", rec}), ErrFeedMalformed},
		{"data before archive", append([]byte("prefix"), makeZip(t, zipFile{"a.json", rec})...), ErrFeedMalformed},
		{"truncated", makeZip(t, zipFile{"a.json", rec})[:30], ErrFeedMalformed},
		{"record too large", makeZip(t, zipFile{"a.json", bytes.Repeat([]byte(" "), MaxOSVRecordBytes+1)}), ErrFeedLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseZip(tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := ParseOSVArchive(context.Background(), bytes.NewReader(nil), 0, func(OSVRecord) error { return nil }); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("zero size: %v", err)
	}
}

func TestParseOSVArchiveSkipsMalformedRecord(t *testing.T) {
	good := zipFile{"GO-2024-3000.json", readFixture(t, "parse_osv", "go.json")}
	good2 := zipFile{"DSA-5793-1.json", readFixture(t, "parse_osv", "dsa.json")}
	bad := map[string]string{
		"empty object":            `{}`,
		"not json":                `nope`,
		"bad modified":            `{"id":"OSV-1","modified":"yesterday"}`,
		"non-ASCII key":           `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","database_specific":{"ünïcode":1}}`,
		"case duplicate key":      `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","database_specific":{"a":1,"A":2}}`,
		"version outside pattern": `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Debian:12","name":"zlib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0 beta"}]}]}]}`,
		// Per-record field and count limits skip the record, not the archive.
		"too many aliases": `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":[` +
			strings.TrimSuffix(strings.Repeat(`"CVE-2024-1234",`, MaxOSVAliases+1), ",") + `]}`,
		"too many events": `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","affected":[{"ranges":[{"events":[` +
			strings.TrimSuffix(strings.Repeat(`{},`, MaxOSVEvents+1), ",") + `]}]}]}`,
		"long alias": `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","aliases":["` + strings.Repeat("A", 1000) + `"]}`,
		"too many members": `{"id":"OSV-1","modified":"2024-01-01T00:00:00Z","x":[` +
			strings.TrimSuffix(strings.Repeat(`0,`, MaxJSONMembers+1), ",") + `]}`,
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			got, sum, err := parseZip(makeZip(t, good, zipFile{"OSV-1.json", []byte(b)}, good2))
			if err != nil {
				t.Fatalf("err = %v, want the record skipped", err)
			}
			if sum.Records != 2 || sum.Skipped != 1 || len(got) != 2 || got[0].ID != "GO-2024-3000" || got[1].ID != "DSA-5793-1" {
				t.Fatalf("summary %+v, records %d", sum, len(got))
			}
		})
	}
}

// setEOCDCount overwrites the record counts of the (non-zip64) end of
// central directory record of data.
func setEOCDCount(t *testing.T, data []byte, n uint16) {
	t.Helper()
	i := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if i < 0 {
		t.Fatal("no end record")
	}
	binary.LittleEndian.PutUint16(data[i+8:], n)
	binary.LittleEndian.PutUint16(data[i+10:], n)
}

func TestParseOSVArchiveFileLimit(t *testing.T) {
	rec := readFixture(t, "parse_osv", "go.json")
	files := []zipFile{{"a.json", rec}, {"b.json", rec}, {"c.json", rec}}
	visit := func(OSVRecord) error { return nil }
	parse := func(data []byte, max int) (OSVArchiveSummary, error) {
		return parseOSVArchive(context.Background(), bytes.NewReader(data), int64(len(data)), max, visit)
	}
	data := makeZip(t, files...)
	// Same ID three times: at the limit the duplicate stops the parse
	// only after the file count passed.
	if _, err := parse(data, 3); !errors.Is(err, ErrFeedMalformed) {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := parse(data, 2); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("declared count over the limit: %v", err)
	}
	// A directory that declares fewer records than it holds: the walk
	// stops at the limit, before zip.NewReader builds the entries.
	lying := slices.Clone(data)
	setEOCDCount(t, lying, 1)
	if _, err := parse(lying, 2); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("walked count over the limit: %v", err)
	}
	if _, err := parse(lying, 3); !errors.Is(err, ErrFeedMalformed) {
		t.Fatalf("count mismatch: %v", err)
	}
	if MaxOSVArchiveFiles != 1_000_000 {
		t.Fatalf("MaxOSVArchiveFiles = %d", MaxOSVArchiveFiles)
	}
}

func TestParseOSVArchiveZip64DeclaredCountOverLimit(t *testing.T) {
	// A zip64 end record declaring MaxOSVArchiveFiles+1 records with an
	// empty directory: the exported parser rejects it from the end record
	// alone.
	var b []byte
	rec := make([]byte, 56)
	copy(rec, "PK\x06\x06")
	binary.LittleEndian.PutUint64(rec[4:], 44)
	binary.LittleEndian.PutUint64(rec[24:], MaxOSVArchiveFiles+1)
	binary.LittleEndian.PutUint64(rec[32:], MaxOSVArchiveFiles+1)
	b = append(b, rec...)
	loc := make([]byte, 20)
	copy(loc, "PK\x06\x07")
	binary.LittleEndian.PutUint64(loc[8:], 0)
	binary.LittleEndian.PutUint32(loc[16:], 1)
	b = append(b, loc...)
	end := make([]byte, 22)
	copy(end, "PK\x05\x06")
	binary.LittleEndian.PutUint16(end[8:], 0xffff)
	binary.LittleEndian.PutUint16(end[10:], 0xffff)
	binary.LittleEndian.PutUint32(end[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(end[16:], 0xffffffff)
	b = append(b, end...)
	if _, _, err := parseZip(b); !errors.Is(err, ErrFeedLimit) {
		t.Fatalf("err = %v, want ErrFeedLimit", err)
	}
	// The same end record declaring zero records is an empty archive.
	binary.LittleEndian.PutUint64(b[24:], 0)
	binary.LittleEndian.PutUint64(b[32:], 0)
	if _, sum, err := parseZip(b); err != nil || sum.Records != 0 {
		t.Fatalf("empty zip64: %+v, %v", sum, err)
	}
}

func TestParseOSVArchiveByteLimit(t *testing.T) {
	// Files whose declared sizes add up to more than MaxOSVArchiveBytes
	// are rejected before any of them is read.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	n := int(MaxOSVArchiveBytes/MaxOSVRecordBytes) + 1
	for i := range n {
		w, err := zw.CreateRaw(&zip.FileHeader{
			Name: fmt.Sprintf("OSV-%d.json", i), Method: zip.Deflate,
			CompressedSize64: 1, UncompressedSize64: MaxOSVRecordBytes,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	visited := 0
	data := buf.Bytes()
	_, err := ParseOSVArchive(context.Background(), bytes.NewReader(data), int64(len(data)), func(OSVRecord) error {
		visited++
		return nil
	})
	if !errors.Is(err, ErrFeedLimit) || visited != 0 {
		t.Fatalf("err = %v after %d records, want ErrFeedLimit before any", err, visited)
	}
}

func TestParseOSVArchiveRejectsLyingSizeHeader(t *testing.T) {
	// Store the entry uncompressed, then shrink its declared size in both
	// headers: the reader must not deliver more than was declared.
	body := readFixture(t, "parse_osv", "go.json")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "a.json", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	cd := bytes.LastIndex(data, []byte("PK\x01\x02"))
	if cd < 0 {
		t.Fatal("no central directory")
	}
	// Central directory: uncompressed size at offset 24 (little endian).
	data[cd+24], data[cd+25], data[cd+26], data[cd+27] = 10, 0, 0, 0
	if _, _, err := parseZip(data); err == nil {
		t.Fatal("accepted an entry larger than its declared size")
	}
}

func FuzzParseOSV(f *testing.F) {
	f.Add(readFixture(f, "parse_osv", "dsa.json"))
	f.Add(readFixture(f, "parse_osv", "go.json"))
	f.Add([]byte(`{"id":"OSV-1","modified":"2024-01-01T00:00:00Z"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		rec, err := ParseOSV(in)
		if err != nil {
			if !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) {
				t.Fatalf("unexpected error class %v", err)
			}
			return
		}
		if !feedVulnIDRe.MatchString(rec.ID) || rec.Modified.IsZero() {
			t.Fatalf("unvalidated record %+v", rec)
		}
		for _, a := range rec.Affected {
			for _, r := range a.Ranges {
				if len(r.Events) == 0 {
					t.Fatalf("range without events %+v", a)
				}
			}
		}
	})
}

func FuzzParseOSVArchive(f *testing.F) {
	f.Add(makeZip(f, zipFile{"GO-2024-3000.json", readFixture(f, "parse_osv", "go.json")}))
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	f.Fuzz(func(t *testing.T, in []byte) {
		_, err := ParseOSVArchive(context.Background(), bytes.NewReader(in), int64(len(in)), func(OSVRecord) error { return nil })
		if err != nil && !errors.Is(err, ErrFeedMalformed) && !errors.Is(err, ErrFeedLimit) {
			t.Fatalf("unexpected error class %v", err)
		}
	})
}
