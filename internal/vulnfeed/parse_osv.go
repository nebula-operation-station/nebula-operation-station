// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"archive/zip"
	"context"
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
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

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
	if err := decodeChecked(data, &j); err != nil {
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
		return OSVRecord{}, fmt.Errorf("%s: more than %d aliases: %w", where, MaxOSVAliases, ErrFeedLimit)
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
		return OSVRecord{}, fmt.Errorf("%s: more than %d affected: %w", where, MaxOSVAffected, ErrFeedLimit)
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
		return OSVAffected{}, false, fmt.Errorf("more than %d ranges: %w", MaxOSVRanges, ErrFeedLimit)
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
			return OSVAffected{}, false, fmt.Errorf("range %d: more than %d events: %w", i, MaxOSVEvents, ErrFeedLimit)
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
// version valid for the range type.
func osvEvent(typ OSVRangeType, ev map[string]string) (OSVEvent, error) {
	if len(ev) != 1 {
		return OSVEvent{}, fmt.Errorf("event must have exactly one key: %w", ErrFeedMalformed)
	}
	for k, v := range ev {
		kind := OSVEventKind(k)
		switch kind {
		case OSVIntroduced, OSVFixed, OSVLastAffected, OSVLimit:
		default:
			return OSVEvent{}, fmt.Errorf("event kind: %w", ErrFeedMalformed)
		}
		switch {
		case kind == OSVIntroduced && v == "0":
		case kind == OSVLimit && v == "*":
		case typ == OSVRangeSemver && !osvSemverRe.MatchString(v):
			return OSVEvent{}, fmt.Errorf("semver version: %w", ErrFeedMalformed)
		case !feedVersionRe.MatchString(v):
			return OSVEvent{}, fmt.Errorf("version: %w", ErrFeedMalformed)
		}
		return OSVEvent{Kind: kind, Version: v}, nil
	}
	return OSVEvent{}, fmt.Errorf("empty event: %w", ErrFeedMalformed) // unreachable
}

// OSVArchiveSummary is the result of ParseOSVArchive.
type OSVArchiveSummary struct {
	// Records counts the records delivered.
	Records int
	// Newest is the newest record "modified" date: the content date of
	// the archive (D4). Zero when the archive has no records.
	Newest time.Time
}

// ParseOSVArchive parses an OSV bulk export (all.zip): every file must be
// a top-level "<name>.json" OSV record. visit is called per record in
// archive order; on error the caller must discard what it has seen.
// Sizes declared in the zip directory are checked before a file is read
// and enforced again while it is decompressed.
func ParseOSVArchive(ctx context.Context, ra io.ReaderAt, size int64, visit func(OSVRecord) error) (OSVArchiveSummary, error) {
	var sum OSVArchiveSummary
	if size <= 0 || size > MaxFeedBytesDefault {
		return sum, fmt.Errorf("osv archive: size: %w", ErrFeedLimit)
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return sum, fmt.Errorf("osv archive: %w", ErrFeedMalformed)
	}
	if len(zr.File) > MaxOSVArchiveFiles {
		return sum, fmt.Errorf("osv archive: more than %d files: %w", MaxOSVArchiveFiles, ErrFeedLimit)
	}
	var total int64
	names := make(map[string]struct{}, len(zr.File))
	ids := make(map[string]struct{}, len(zr.File))
	for i, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return sum, fmt.Errorf("osv archive: %w", err)
		}
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
		data, err := readOSVArchiveFile(f)
		if err != nil {
			return sum, fmt.Errorf("osv archive file %d: %w", i, err)
		}
		rec, err := ParseOSV(data)
		if err != nil {
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
