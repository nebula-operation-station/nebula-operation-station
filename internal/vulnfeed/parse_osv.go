// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Limits of OSV records and OSV bulk archives (ADR 0011 D4).
const (
	// MaxOSVRecordBytes caps one OSV JSON record.
	MaxOSVRecordBytes = 4 << 20
	// MaxOSVAliases caps the aliases of one record.
	MaxOSVAliases = 256
	// MaxOSVAffected caps the affected entries of one record.
	MaxOSVAffected = 4096
	// MaxOSVRanges caps the ranges of one affected entry.
	MaxOSVRanges = 256
	// MaxOSVEvents caps the events of one range.
	MaxOSVEvents = 4096
	// MaxOSVRangesPerRecord caps the ranges of all affected entries of
	// one record together.
	MaxOSVRangesPerRecord = 8192
	// MaxOSVEventsPerRecord caps the events of all ranges of one record
	// together.
	MaxOSVEventsPerRecord = 32_768
	// MaxOSVArchiveFiles caps the files in one OSV all.zip.
	MaxOSVArchiveFiles = 1_000_000
	// MaxOSVArchiveBytes caps the decompressed bytes of one OSV all.zip.
	MaxOSVArchiveBytes int64 = 4 << 30
)

// OSVRangeType is an OSV range type the matcher uses.
type OSVRangeType string

// OSV range types. GIT and unknown range types are skipped and counted.
const (
	OSVRangeSemver    OSVRangeType = "SEMVER"
	OSVRangeEcosystem OSVRangeType = "ECOSYSTEM"
)

// OSVEventKind is the kind of one OSV range event.
type OSVEventKind string

// OSV event kinds.
const (
	OSVIntroduced   OSVEventKind = "introduced"
	OSVFixed        OSVEventKind = "fixed"
	OSVLastAffected OSVEventKind = "last_affected"
	OSVLimit        OSVEventKind = "limit"
)

var (
	// osvEcosystemRe is an OSV ecosystem, e.g. "Debian:12",
	// "Ubuntu:Pro:22.04:LTS", "Alpine:v3.20", "crates.io", "Go".
	osvEcosystemRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:+-]{0,63}$`)
	// osvPackageRe is an OSV package name (as in vulnfinding).
	osvPackageRe = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._+:~-]{0,213}$`)
	// osvSemverRe is a SEMVER 2.0 version without a leading "v".
	osvSemverRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$`)
)

// OSVEvent is one range event.
type OSVEvent struct {
	// Kind is the event kind.
	Kind OSVEventKind
	// Version is the event version; "0" for introduced means "all".
	Version string
}

// OSVRange is one SEMVER or ECOSYSTEM range of an affected package.
type OSVRange struct {
	// Type is the range type.
	Type OSVRangeType
	// Events are the range events in input order.
	Events []OSVEvent
}

// OSVAffected is one affected package of an OSV record.
type OSVAffected struct {
	// Ecosystem is the OSV ecosystem, e.g. "Debian:12".
	Ecosystem string
	// Name is the package name in that ecosystem.
	Name string
	// Ranges are the SEMVER and ECOSYSTEM ranges.
	Ranges []OSVRange
	// SkippedRanges counts GIT and unknown range types left out.
	SkippedRanges int
}

// OSVRecord is the matcher's view of one OSV record.
type OSVRecord struct {
	// ID is the OSV ID (D2 vuln_id pattern).
	ID string
	// Modified is the record's last modification: its content date.
	Modified time.Time
	// Published and Withdrawn are zero when absent.
	Published, Withdrawn time.Time
	// Aliases are the record's aliases (D2 vuln_id pattern), deduplicated
	// in input order.
	Aliases []string
	// Affected are the affected packages with a package name.
	Affected []OSVAffected
	// SkippedAffected counts affected entries without a package.
	SkippedAffected int
}

// CVEs returns the CVE IDs among the record's ID and aliases.
func (r OSVRecord) CVEs() []string {
	var out []string
	for _, id := range append([]string{r.ID}, r.Aliases...) {
		if cveIDRe.MatchString(id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

type osvJSON struct {
	ID        string            `json:"id"`
	Modified  string            `json:"modified"`
	Published string            `json:"published"`
	Withdrawn string            `json:"withdrawn"`
	Aliases   []string          `json:"aliases"`
	Affected  []osvAffectedJSON `json:"affected"`
}

type osvAffectedJSON struct {
	Package *struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string         `json:"type"`
		Events []osvEventJSON `json:"events"`
	} `json:"ranges"`
}

// osvEventJSON is one range event; exactly one field must be set (an
// event object has at most one member, see osvPaths).
type osvEventJSON struct {
	Introduced   *string `json:"introduced"`
	Fixed        *string `json:"fixed"`
	LastAffected *string `json:"last_affected"`
	Limit        *string `json:"limit"`
}

// osvPaths are the per-record limits checkJSON enforces on an OSV record
// while it walks, before json.Unmarshal builds any slice or string.
var osvPaths = jsonLimits{
	"id":                             {Bytes: 64},
	"modified":                       {Bytes: maxTimeBytes},
	"published":                      {Bytes: maxTimeBytes},
	"withdrawn":                      {Bytes: maxTimeBytes},
	"aliases":                        {Members: MaxOSVAliases},
	"aliases[]":                      {Bytes: 64},
	"affected":                       {Members: MaxOSVAffected},
	"affected[].package.ecosystem":   {Bytes: 64},
	"affected[].package.name":        {Bytes: 214},
	"affected[].ranges":              {Members: MaxOSVRanges, Total: MaxOSVRangesPerRecord},
	"affected[].ranges[].type":       {Bytes: 32},
	"affected[].ranges[].events":     {Members: MaxOSVEvents, Total: MaxOSVEventsPerRecord},
	"affected[].ranges[].events[]":   {Members: 1},
	"affected[].ranges[].events[].*": {Bytes: 128},
}.compile()

// osvTimeLayouts are the RFC 3339 forms OSV uses.
var osvTimeLayouts = []string{time.RFC3339Nano, time.RFC3339}

// ParseOSV decodes and validates one OSV JSON record. Fields the matcher
// does not use (summary, details, severity, database_specific, ...) are
// skipped; they still count against the size and depth limits.
func ParseOSV(data []byte) (OSVRecord, error) {
	if len(data) > MaxOSVRecordBytes {
		return OSVRecord{}, fmt.Errorf("osv record: %w", ErrFeedLimit)
	}
	var j osvJSON
	if err := decodeChecked(data, &j, osvPaths); err != nil {
		return OSVRecord{}, fmt.Errorf("osv record: %w", err)
	}
	if !feedVulnIDRe.MatchString(j.ID) {
		return OSVRecord{}, fmt.Errorf("osv record: id: %w", ErrFeedMalformed)
	}
	where := "osv " + j.ID
	rec := OSVRecord{ID: j.ID}
	var err error
	if rec.Modified, err = parseFeedTime(j.Modified, osvTimeLayouts...); err != nil {
		return OSVRecord{}, fmt.Errorf("%s: modified: %w", where, err)
	}
	if j.Published != "" {
		if rec.Published, err = parseFeedTime(j.Published, osvTimeLayouts...); err != nil {
			return OSVRecord{}, fmt.Errorf("%s: published: %w", where, err)
		}
	}
	if j.Withdrawn != "" {
		if rec.Withdrawn, err = parseFeedTime(j.Withdrawn, osvTimeLayouts...); err != nil {
			return OSVRecord{}, fmt.Errorf("%s: withdrawn: %w", where, err)
		}
	}
	if len(j.Aliases) > MaxOSVAliases {
		return OSVRecord{}, fmt.Errorf("%s: more than %d aliases: %w", where, MaxOSVAliases, ErrRecordLimit)
	}
	for _, a := range j.Aliases {
		if !feedVulnIDRe.MatchString(a) {
			return OSVRecord{}, fmt.Errorf("%s: alias: %w", where, ErrFeedMalformed)
		}
		if a != rec.ID && !slices.Contains(rec.Aliases, a) {
			rec.Aliases = append(rec.Aliases, a)
		}
	}
	if len(j.Affected) > MaxOSVAffected {
		return OSVRecord{}, fmt.Errorf("%s: more than %d affected: %w", where, MaxOSVAffected, ErrRecordLimit)
	}
	for i, a := range j.Affected {
		aff, ok, err := osvAffected(a)
		if err != nil {
			return OSVRecord{}, fmt.Errorf("%s: affected %d: %w", where, i, err)
		}
		if !ok {
			rec.SkippedAffected++
			continue
		}
		rec.Affected = append(rec.Affected, aff)
	}
	return rec, nil
}

// osvAffected validates one affected entry; ok is false for an entry
// without a package (GIT-only), which the caller skips.
func osvAffected(a osvAffectedJSON) (OSVAffected, bool, error) {
	if len(a.Ranges) > MaxOSVRanges {
		return OSVAffected{}, false, fmt.Errorf("more than %d ranges: %w", MaxOSVRanges, ErrRecordLimit)
	}
	if a.Package == nil {
		return OSVAffected{}, false, nil
	}
	out := OSVAffected{Ecosystem: a.Package.Ecosystem, Name: a.Package.Name}
	if !osvEcosystemRe.MatchString(out.Ecosystem) {
		return OSVAffected{}, false, fmt.Errorf("ecosystem: %w", ErrFeedMalformed)
	}
	if !osvPackageRe.MatchString(out.Name) {
		return OSVAffected{}, false, fmt.Errorf("package name: %w", ErrFeedMalformed)
	}
	for i, r := range a.Ranges {
		if len(r.Events) > MaxOSVEvents {
			return OSVAffected{}, false, fmt.Errorf("range %d: more than %d events: %w", i, MaxOSVEvents, ErrRecordLimit)
		}
		typ := OSVRangeType(r.Type)
		if typ != OSVRangeSemver && typ != OSVRangeEcosystem {
			out.SkippedRanges++
			continue
		}
		rg := OSVRange{Type: typ}
		introduced := false
		for _, ev := range r.Events {
			e, err := osvEvent(typ, ev)
			if err != nil {
				return OSVAffected{}, false, fmt.Errorf("range %d: %w", i, err)
			}
			introduced = introduced || e.Kind == OSVIntroduced
			rg.Events = append(rg.Events, e)
		}
		if !introduced {
			return OSVAffected{}, false, fmt.Errorf("range %d: no introduced event: %w", i, ErrFeedMalformed)
		}
		out.Ranges = append(out.Ranges, rg)
	}
	return out, true, nil
}

// osvEvent validates one event object: exactly one known key, and a
// version valid for the range type. The walk already rejected an event
// with more than one member, so an unknown key leaves every field unset.
func osvEvent(typ OSVRangeType, ev osvEventJSON) (OSVEvent, error) {
	var kind OSVEventKind
	var v *string
	for _, f := range []struct {
		kind OSVEventKind
		v    *string
	}{{OSVIntroduced, ev.Introduced}, {OSVFixed, ev.Fixed}, {OSVLastAffected, ev.LastAffected}, {OSVLimit, ev.Limit}} {
		if f.v == nil {
			continue
		}
		if v != nil {
			return OSVEvent{}, fmt.Errorf("event must have exactly one key: %w", ErrFeedMalformed)
		}
		kind, v = f.kind, f.v
	}
	if v == nil {
		return OSVEvent{}, fmt.Errorf("event kind: %w", ErrFeedMalformed)
	}
	switch {
	case kind == OSVIntroduced && *v == "0":
	case kind == OSVLimit && *v == "*":
	case typ == OSVRangeSemver && !osvSemverRe.MatchString(*v):
		return OSVEvent{}, fmt.Errorf("semver version: %w", ErrFeedMalformed)
	case !feedVersionRe.MatchString(*v):
		return OSVEvent{}, fmt.Errorf("version: %w", ErrFeedMalformed)
	}
	return OSVEvent{Kind: kind, Version: *v}, nil
}

// OSVArchiveSummary is the result of ParseOSVArchive.
type OSVArchiveSummary struct {
	// Records counts the records delivered.
	Records int
	// Skipped counts the files left out because their record broke a
	// field rule.
	Skipped int
	// Newest is the newest record "modified" date: the content date of
	// the archive (D4). Zero when the archive has no records.
	Newest time.Time
}

// ParseOSVArchive parses an OSV bulk export (all.zip): every file must be
// a top-level "<name>.json" OSV record. visit is called per valid record
// in archive order.
//
// The central directory is counted before archive/zip builds it, and the
// names and declared sizes of all files are checked before the first
// file is read; sizes are enforced again while a file is decompressed. A
// record that breaks a field rule or a per-record field length or count
// limit (ErrRecordLimit) is skipped and counted in
// OSVArchiveSummary.Skipped; an archive size or file count limit, a record
// over MaxOSVRecordBytes or MaxJSONDepth, a bad file name, a duplicate
// name or ID, or corrupt compressed data fails the archive. On error the
// caller must discard what it has seen.
func ParseOSVArchive(ctx context.Context, ra io.ReaderAt, size int64, visit func(OSVRecord) error) (OSVArchiveSummary, error) {
	return parseOSVArchive(ctx, ra, size, MaxOSVArchiveFiles, visit)
}

// parseOSVArchive is ParseOSVArchive with the file limit as a parameter,
// so tests can reach it with a small archive.
func parseOSVArchive(ctx context.Context, ra io.ReaderAt, size int64, maxFiles int, visit func(OSVRecord) error) (OSVArchiveSummary, error) {
	var sum OSVArchiveSummary
	if size <= 0 || size > MaxFeedBytesDefault {
		return sum, fmt.Errorf("osv archive: size: %w", ErrFeedLimit)
	}
	files, err := countZipDirectory(ctx, ra, size, maxFiles)
	if err != nil {
		return sum, fmt.Errorf("osv archive: %w", err)
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return sum, fmt.Errorf("osv archive: %w", ErrFeedMalformed)
	}
	if len(zr.File) != files {
		return sum, fmt.Errorf("osv archive: directory count mismatch: %w", ErrFeedMalformed)
	}
	var total int64
	names := make(map[string]struct{}, len(zr.File))
	for i, f := range zr.File {
		if err := checkOSVArchiveName(f.Name); err != nil {
			return sum, fmt.Errorf("osv archive file %d: %w", i, err)
		}
		if _, dup := names[f.Name]; dup {
			return sum, fmt.Errorf("osv archive file %d: duplicate name: %w", i, ErrFeedMalformed)
		}
		names[f.Name] = struct{}{}
		if f.UncompressedSize64 > MaxOSVRecordBytes {
			return sum, fmt.Errorf("osv archive file %d: %w", i, ErrFeedLimit)
		}
		total += int64(f.UncompressedSize64)
		if total > MaxOSVArchiveBytes {
			return sum, fmt.Errorf("osv archive: more than %d bytes: %w", MaxOSVArchiveBytes, ErrFeedLimit)
		}
	}
	ids := make(map[string]struct{}, len(zr.File))
	for i, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return sum, fmt.Errorf("osv archive: %w", err)
		}
		data, err := readOSVArchiveFile(f)
		if err != nil {
			return sum, fmt.Errorf("osv archive file %d: %w", i, err)
		}
		rec, err := ParseOSV(data)
		if err != nil {
			if recordSkippable(err) {
				sum.Skipped++
				continue
			}
			return sum, fmt.Errorf("osv archive file %d: %w", i, err)
		}
		if _, dup := ids[rec.ID]; dup {
			return sum, fmt.Errorf("osv archive %s: duplicate id: %w", rec.ID, ErrFeedMalformed)
		}
		ids[rec.ID] = struct{}{}
		if err := visit(rec); err != nil {
			return sum, fmt.Errorf("osv archive %s: %w", rec.ID, err)
		}
		sum.Records++
		if rec.Modified.After(sum.Newest) {
			sum.Newest = rec.Modified
		}
	}
	return sum, nil
}

// Zip structures read by countZipDirectory (PKWARE APPNOTE 4.3).
const (
	zipEOCDLen      = 22
	zipEOCDSig      = "PK\x05\x06"
	zip64LocatorLen = 20
	zip64LocatorSig = "PK\x06\x07"
	zip64EOCDLen    = 56
	zip64EOCDSig    = "PK\x06\x06"
	zipDirHeaderLen = 46
	zipDirHeaderSig = "PK\x01\x02"
	// zipEOCDSearchBytes is the archive tail searched for the end record,
	// the same tail archive/zip searches.
	zipEOCDSearchBytes = 65 * 1024
)

// countZipDirectory counts the central directory records of a zip
// archive without building them, so the file limit fires before
// zip.NewReader allocates one *zip.File per record. archive/zip trusts
// neither the declared count (it compares only its low 16 bits) nor the
// declared directory size: it reads record headers from the directory
// offset until one does not parse. So this function
//
//   - reads the end-of-central-directory record (the zip64 one when the
//     record is marked and a zip64 locator is present), as archive/zip
//     does, and fails with ErrFeedLimit when it declares more than
//     maxFiles records;
//   - requires the directory to end exactly where the end record starts
//     (no data before the archive, the layout zip.Writer and the OSV
//     export produce), so archive/zip starts at the same offset;
//   - walks the record headers inside the declared directory, failing
//     with ErrFeedLimit after maxFiles of them, and requires them to fill
//     the directory exactly and to match the declared count.
//
// The bytes after the directory are the end record, whose signature is
// not a header signature, so archive/zip stops at the same record.
func countZipDirectory(ctx context.Context, ra io.ReaderAt, size int64, maxFiles int) (int, error) {
	tail := make([]byte, min(size, zipEOCDSearchBytes))
	tailOff := size - int64(len(tail))
	if err := readAtFull(ra, tail, tailOff); err != nil {
		return 0, err
	}
	if len(tail) < zipEOCDLen {
		return 0, fmt.Errorf("no end of central directory: %w", ErrFeedMalformed)
	}
	i := bytes.LastIndex(tail[:len(tail)-zipEOCDLen+len(zipEOCDSig)], []byte(zipEOCDSig))
	if i < 0 {
		return 0, fmt.Errorf("no end of central directory: %w", ErrFeedMalformed)
	}
	eocd := tail[i : i+zipEOCDLen]
	if i+zipEOCDLen+int(binary.LittleEndian.Uint16(eocd[20:])) > len(tail) {
		return 0, fmt.Errorf("end of central directory comment: %w", ErrFeedMalformed)
	}
	records := uint64(binary.LittleEndian.Uint16(eocd[10:]))
	dirSize := uint64(binary.LittleEndian.Uint32(eocd[12:]))
	dirOff := uint64(binary.LittleEndian.Uint32(eocd[16:]))
	endOff := tailOff + int64(i)
	if records == 0xffff || dirSize == 0xffff || dirSize == 0xffffffff || dirOff == 0xffffffff {
		p, ok, err := findZip64End(ra, endOff)
		if err != nil {
			return 0, err
		}
		if ok {
			rec := make([]byte, zip64EOCDLen)
			if size < zip64EOCDLen || p > uint64(size-zip64EOCDLen) {
				return 0, fmt.Errorf("zip64 end record offset: %w", ErrFeedMalformed)
			}
			if err := readAtFull(ra, rec, int64(p)); err != nil {
				return 0, err
			}
			if string(rec[:4]) != zip64EOCDSig {
				return 0, fmt.Errorf("zip64 end record: %w", ErrFeedMalformed)
			}
			records = binary.LittleEndian.Uint64(rec[32:])
			dirSize = binary.LittleEndian.Uint64(rec[40:])
			dirOff = binary.LittleEndian.Uint64(rec[48:])
			endOff = int64(p)
		}
	}
	if records > uint64(maxFiles) {
		return 0, fmt.Errorf("more than %d files: %w", maxFiles, ErrFeedLimit)
	}
	if dirOff > uint64(endOff) || dirSize != uint64(endOff)-dirOff {
		return 0, fmt.Errorf("central directory does not end at the end record: %w", ErrFeedMalformed)
	}
	r := bufio.NewReaderSize(io.NewSectionReader(ra, int64(dirOff), int64(dirSize)), 64<<10)
	var hdr [zipDirHeaderLen]byte
	count := 0
	for left := dirSize; left > 0; {
		if count%65536 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		if count >= maxFiles {
			return 0, fmt.Errorf("more than %d files: %w", maxFiles, ErrFeedLimit)
		}
		if left < zipDirHeaderLen {
			return 0, fmt.Errorf("central directory: %w", ErrFeedMalformed)
		}
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return 0, fmt.Errorf("central directory: %w", ErrFeedMalformed)
		}
		if string(hdr[:4]) != zipDirHeaderSig {
			return 0, fmt.Errorf("central directory header: %w", ErrFeedMalformed)
		}
		vars := uint64(binary.LittleEndian.Uint16(hdr[28:])) + uint64(binary.LittleEndian.Uint16(hdr[30:])) +
			uint64(binary.LittleEndian.Uint16(hdr[32:]))
		if vars > left-zipDirHeaderLen {
			return 0, fmt.Errorf("central directory header: %w", ErrFeedMalformed)
		}
		if _, err := r.Discard(int(vars)); err != nil {
			return 0, fmt.Errorf("central directory: %w", ErrFeedMalformed)
		}
		left -= zipDirHeaderLen + vars
		count++
	}
	if uint64(count) != records {
		return 0, fmt.Errorf("central directory count mismatch: %w", ErrFeedMalformed)
	}
	return count, nil
}

// findZip64End reads the zip64 end locator just before the end record at
// endOff. ok is false when there is none, as archive/zip treats it: the
// 32-bit values then stand.
func findZip64End(ra io.ReaderAt, endOff int64) (uint64, bool, error) {
	locOff := endOff - zip64LocatorLen
	if locOff < 0 {
		return 0, false, nil
	}
	loc := make([]byte, zip64LocatorLen)
	if err := readAtFull(ra, loc, locOff); err != nil {
		return 0, false, err
	}
	if string(loc[:4]) != zip64LocatorSig || binary.LittleEndian.Uint32(loc[4:]) != 0 ||
		binary.LittleEndian.Uint32(loc[16:]) != 1 {
		return 0, false, nil
	}
	return binary.LittleEndian.Uint64(loc[8:]), true, nil
}

// readAtFull fills b from ra at off; a short read is malformed data.
func readAtFull(ra io.ReaderAt, b []byte, off int64) error {
	n, err := ra.ReadAt(b, off)
	if n == len(b) {
		return nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read archive: %w", err)
	}
	return fmt.Errorf("archive truncated: %w", ErrFeedMalformed)
}

// checkOSVArchiveName allows only a flat "<name>.json" entry.
func checkOSVArchiveName(name string) error {
	if len(name) > 256 || !strings.HasSuffix(name, ".json") || strings.ContainsAny(name, `/\`) ||
		path.Clean(name) != name || checkToken(name, 256) != nil {
		return fmt.Errorf("file name: %w", ErrFeedMalformed)
	}
	return nil
}

// readOSVArchiveFile decompresses one entry, never more than
// MaxOSVRecordBytes regardless of the declared size.
func readOSVArchiveFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open: %w", ErrFeedMalformed)
	}
	defer func() { _ = rc.Close() }()
	br := newBoundedReader(rc, MaxOSVRecordBytes)
	data, err := io.ReadAll(br)
	if err != nil {
		if br.exceeded {
			return nil, fmt.Errorf("decompress: %w", ErrFeedLimit)
		}
		return nil, fmt.Errorf("decompress: %w", ErrFeedMalformed)
	}
	return data, nil
}
