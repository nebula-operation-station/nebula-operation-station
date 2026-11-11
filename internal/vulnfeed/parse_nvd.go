// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Limits of the NVD CVE JSON 2.0 bulk feed (ADR 0011 D4).
const (
	// MaxNVDFeedBytes caps the decompressed feed.
	MaxNVDFeedBytes = MaxFeedBytesNVD
	// MaxNVDRecordBytes caps the JSON of one CVE item.
	MaxNVDRecordBytes = 4 << 20
	// MaxNVDHeaderValueBytes caps each top-level value besides the
	// vulnerabilities array.
	MaxNVDHeaderValueBytes = 64 << 10
	// MaxNVDRecords caps the CVE items in one feed.
	MaxNVDRecords = 2_000_000
	// MaxNVDMetrics caps the entries of one CVSS metric list.
	MaxNVDMetrics = 64
	// MaxNVDWeaknesses caps the weakness entries and the CWEs per CVE.
	MaxNVDWeaknesses = 64
	// MaxNVDDescriptions caps the description entries per CVE.
	MaxNVDDescriptions = 64
	// MaxNVDDescriptionBytes caps the English description.
	MaxNVDDescriptionBytes = 64 << 10
	// MaxNVDReferences caps the references per CVE.
	MaxNVDReferences = 4096
	// MaxNVDReferenceURLBytes caps one reference URL (kept as text).
	MaxNVDReferenceURLBytes = 2048
	// MaxNVDReferenceTags caps the tags of one reference.
	MaxNVDReferenceTags = 32
	// maxNVDSourceBytes caps a metric or reference source name.
	maxNVDSourceBytes = 128
)

// CVSS versions the NVD parser keeps.
const (
	NVDCVSS31 = "3.1"
	NVDCVSS40 = "4.0"
)

var (
	nvdCWERe      = regexp.MustCompile(`^CWE-[0-9]{1,6}$`)
	nvdStatusRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z ]{0,31}$`)
	nvdSeverityRe = regexp.MustCompile(`^[A-Z]{1,16}$`)
	nvdTypeRe     = regexp.MustCompile(`^[A-Za-z]{1,16}$`)
	nvdTagRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ./-]{0,63}$`)
	nvdVectorRe   = regexp.MustCompile(`^CVSS:(3\.1|4\.0)/[A-Za-z0-9:./]{1,240}$`)
)

// nvdTimeLayouts are the NVD timestamp forms; zone-less values are UTC.
var nvdTimeLayouts = []string{"2006-01-02T15:04:05.999999999", time.RFC3339Nano}

// NVDCVSS is one CVSS base score of a CVE.
type NVDCVSS struct {
	// Version is NVDCVSS31 or NVDCVSS40.
	Version string
	// Vector is the CVSS vector string.
	Vector string
	// BaseScore is 0.0 to 10.0 with one decimal.
	BaseScore float64
	// BaseSeverity is the upper-case severity name.
	BaseSeverity string
	// Source is the scoring source (e.g. "nvd@nist.gov").
	Source string
	// Type is "Primary" or "Secondary".
	Type string
}

// NVDReference is one reference; URL is text only and never fetched.
type NVDReference struct {
	// URL is the reference location, shown as text.
	URL string
	// Source is the reference source name; may be empty.
	Source string
	// Tags are the NVD reference tags.
	Tags []string
}

// NVDRecord is the matcher's view of one NVD CVE item.
type NVDRecord struct {
	// ID is the CVE ID.
	ID string
	// Published and LastModified come from the item.
	Published, LastModified time.Time
	// Status is the NVD vulnStatus; may be empty.
	Status string
	// Description is the English description; may be empty.
	Description string
	// CVSS are the v3.1 and v4.0 base scores.
	CVSS []NVDCVSS
	// CWEs are the distinct CWE IDs ("CWE-79"); NVD-CWE-* placeholders
	// are left out.
	CWEs []string
	// References are the item's references.
	References []NVDReference
}

// NVDSummary is the result of ParseNVD.
type NVDSummary struct {
	// Timestamp is the feed's own timestamp.
	Timestamp time.Time
	// Records counts the CVE items delivered.
	Records int
	// Newest is the newest item lastModified: the feed's content date
	// (D4). Zero when the feed has no items.
	Newest time.Time
}

type nvdMetricJSON struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string   `json:"version"`
		VectorString string   `json:"vectorString"`
		BaseScore    *float64 `json:"baseScore"`
		BaseSeverity string   `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdLangValueJSON struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdItemJSON struct {
	CVE *struct {
		ID           string             `json:"id"`
		Published    string             `json:"published"`
		LastModified string             `json:"lastModified"`
		VulnStatus   string             `json:"vulnStatus"`
		Descriptions []nvdLangValueJSON `json:"descriptions"`
		Metrics      struct {
			V31 []nvdMetricJSON `json:"cvssMetricV31"`
			V40 []nvdMetricJSON `json:"cvssMetricV40"`
		} `json:"metrics"`
		Weaknesses []struct {
			Description []nvdLangValueJSON `json:"description"`
		} `json:"weaknesses"`
		References []struct {
			URL    string   `json:"url"`
			Source string   `json:"source"`
			Tags   []string `json:"tags"`
		} `json:"references"`
	} `json:"cve"`
}

// ParseNVD streams an NVD CVE JSON 2.0 feed (a decompressed
// nvdcve-2.0-*.json) and calls visit once per CVE item in input order.
// The top level must carry format "NVD_CVE", version "2.0", a timestamp
// and a vulnerabilities array; other top-level fields are skipped within
// MaxNVDHeaderValueBytes. On error the caller must discard what it has
// seen.
func ParseNVD(ctx context.Context, r io.Reader, visit func(NVDRecord) error) (NVDSummary, error) {
	var sum NVDSummary
	br := newBoundedReader(r, MaxNVDFeedBytes)
	dec := json.NewDecoder(br)
	if err := expectDelim(dec, '{'); err != nil {
		return sum, br.fail("nvd feed", err)
	}
	keys := make(map[string]struct{})
	var format, version string
	sawVulns := false
	ids := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return sum, br.fail("nvd feed key", err)
		}
		key, _ := tok.(string)
		if err := checkJSONKey(key); err != nil {
			return sum, fmt.Errorf("nvd feed: %w", err)
		}
		folded := strings.ToLower(key)
		if _, dup := keys[folded]; dup {
			return sum, fmt.Errorf("nvd feed: duplicate top-level key: %w", ErrFeedMalformed)
		}
		keys[folded] = struct{}{}
		if folded == "vulnerabilities" {
			if key != "vulnerabilities" {
				return sum, fmt.Errorf("nvd feed: key spelling: %w", ErrFeedMalformed)
			}
			sawVulns = true
			if err := parseNVDItems(ctx, dec, br, ids, &sum, visit); err != nil {
				return sum, err
			}
			continue
		}
		br.resetWindow(MaxNVDHeaderValueBytes)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return sum, br.fail("nvd feed header", err)
		}
		br.resetWindow(MaxNVDFeedBytes)
		if len(raw) > MaxNVDHeaderValueBytes {
			return sum, fmt.Errorf("nvd feed header: %w", ErrFeedLimit)
		}
		if err := checkJSON(raw, MaxJSONDepth); err != nil {
			return sum, fmt.Errorf("nvd feed header: %w", err)
		}
		var target *string
		switch key {
		case "format":
			target = &format
		case "version":
			target = &version
		case "timestamp":
			var ts string
			if err := json.Unmarshal(raw, &ts); err != nil {
				return sum, fmt.Errorf("nvd feed timestamp: %w", ErrFeedMalformed)
			}
			if sum.Timestamp, err = parseFeedTime(ts, nvdTimeLayouts...); err != nil {
				return sum, fmt.Errorf("nvd feed timestamp: %w", err)
			}
			continue
		default:
			continue // unknown or unused top-level field
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return sum, fmt.Errorf("nvd feed %s: %w", key, ErrFeedMalformed)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return sum, br.fail("nvd feed end", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return sum, br.fail("nvd feed: data after the feed", err)
	}
	if br.exceeded {
		return sum, fmt.Errorf("nvd feed: %w", ErrFeedLimit)
	}
	if format != "NVD_CVE" || version != "2.0" {
		return sum, fmt.Errorf("nvd feed: format or version: %w", ErrFeedMalformed)
	}
	if sum.Timestamp.IsZero() || !sawVulns {
		return sum, fmt.Errorf("nvd feed: missing timestamp or vulnerabilities: %w", ErrFeedMalformed)
	}
	return sum, nil
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

// parseNVDItems streams the vulnerabilities array.
func parseNVDItems(ctx context.Context, dec *json.Decoder, br *boundedReader, ids map[string]struct{}, sum *NVDSummary, visit func(NVDRecord) error) error {
	if err := expectDelim(dec, '['); err != nil {
		return br.fail("nvd vulnerabilities", err)
	}
	for dec.More() {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("nvd feed: %w", err)
		}
		if sum.Records >= MaxNVDRecords {
			return fmt.Errorf("nvd feed: more than %d records: %w", MaxNVDRecords, ErrFeedLimit)
		}
		br.resetWindow(MaxNVDRecordBytes)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return br.fail(fmt.Sprintf("nvd record %d", sum.Records), err)
		}
		br.resetWindow(MaxNVDFeedBytes)
		if len(raw) > MaxNVDRecordBytes {
			return fmt.Errorf("nvd record %d: %w", sum.Records, ErrFeedLimit)
		}
		rec, err := parseNVDItem(raw)
		if err != nil {
			return fmt.Errorf("nvd record %d: %w", sum.Records, err)
		}
		if _, dup := ids[rec.ID]; dup {
			return fmt.Errorf("nvd %s: duplicate: %w", rec.ID, ErrFeedMalformed)
		}
		ids[rec.ID] = struct{}{}
		if err := visit(rec); err != nil {
			return fmt.Errorf("nvd %s: %w", rec.ID, err)
		}
		sum.Records++
		if rec.LastModified.After(sum.Newest) {
			sum.Newest = rec.LastModified
		}
	}
	if err := expectDelim(dec, ']'); err != nil {
		return br.fail("nvd vulnerabilities end", err)
	}
	return nil
}

// parseNVDItem validates one {"cve": {...}} item.
func parseNVDItem(raw []byte) (NVDRecord, error) {
	var j nvdItemJSON
	if err := decodeChecked(raw, &j); err != nil {
		return NVDRecord{}, err
	}
	c := j.CVE
	if c == nil {
		return NVDRecord{}, fmt.Errorf("missing cve: %w", ErrFeedMalformed)
	}
	if !cveIDRe.MatchString(c.ID) {
		return NVDRecord{}, fmt.Errorf("cve id: %w", ErrFeedMalformed)
	}
	rec := NVDRecord{ID: c.ID}
	var err error
	if rec.Published, err = parseFeedTime(c.Published, nvdTimeLayouts...); err != nil {
		return NVDRecord{}, fmt.Errorf("%s published: %w", c.ID, err)
	}
	if rec.LastModified, err = parseFeedTime(c.LastModified, nvdTimeLayouts...); err != nil {
		return NVDRecord{}, fmt.Errorf("%s lastModified: %w", c.ID, err)
	}
	if c.VulnStatus != "" {
		if !nvdStatusRe.MatchString(c.VulnStatus) {
			return NVDRecord{}, fmt.Errorf("%s vulnStatus: %w", c.ID, ErrFeedMalformed)
		}
		rec.Status = c.VulnStatus
	}
	if len(c.Descriptions) > MaxNVDDescriptions {
		return NVDRecord{}, fmt.Errorf("%s: more than %d descriptions: %w", c.ID, MaxNVDDescriptions, ErrFeedLimit)
	}
	for _, d := range c.Descriptions {
		if d.Lang != "en" || rec.Description != "" {
			continue
		}
		if err := checkText(d.Value, MaxNVDDescriptionBytes); err != nil {
			return NVDRecord{}, fmt.Errorf("%s description: %w", c.ID, err)
		}
		rec.Description = d.Value
	}
	for _, m := range []struct {
		version string
		list    []nvdMetricJSON
	}{{NVDCVSS31, c.Metrics.V31}, {NVDCVSS40, c.Metrics.V40}} {
		if len(m.list) > MaxNVDMetrics {
			return NVDRecord{}, fmt.Errorf("%s: more than %d CVSS %s metrics: %w", c.ID, MaxNVDMetrics, m.version, ErrFeedLimit)
		}
		for _, mj := range m.list {
			s, err := nvdCVSS(m.version, mj)
			if err != nil {
				return NVDRecord{}, fmt.Errorf("%s CVSS %s: %w", c.ID, m.version, err)
			}
			rec.CVSS = append(rec.CVSS, s)
		}
	}
	if len(c.Weaknesses) > MaxNVDWeaknesses {
		return NVDRecord{}, fmt.Errorf("%s: more than %d weaknesses: %w", c.ID, MaxNVDWeaknesses, ErrFeedLimit)
	}
	for _, w := range c.Weaknesses {
		if len(w.Description) > MaxNVDWeaknesses {
			return NVDRecord{}, fmt.Errorf("%s: weakness entries: %w", c.ID, ErrFeedLimit)
		}
		for _, d := range w.Description {
			switch {
			case nvdCWERe.MatchString(d.Value):
				if !slices.Contains(rec.CWEs, d.Value) {
					rec.CWEs = append(rec.CWEs, d.Value)
				}
			case strings.HasPrefix(d.Value, "NVD-CWE-") && checkToken(d.Value, 32) == nil:
				// placeholder ("NVD-CWE-Other", "NVD-CWE-noinfo")
			default:
				return NVDRecord{}, fmt.Errorf("%s: CWE value: %w", c.ID, ErrFeedMalformed)
			}
		}
	}
	if len(rec.CWEs) > MaxNVDWeaknesses {
		return NVDRecord{}, fmt.Errorf("%s: more than %d CWEs: %w", c.ID, MaxNVDWeaknesses, ErrFeedLimit)
	}
	if len(c.References) > MaxNVDReferences {
		return NVDRecord{}, fmt.Errorf("%s: more than %d references: %w", c.ID, MaxNVDReferences, ErrFeedLimit)
	}
	for i, rj := range c.References {
		ref, err := nvdReference(rj.URL, rj.Source, rj.Tags)
		if err != nil {
			return NVDRecord{}, fmt.Errorf("%s reference %d: %w", c.ID, i, err)
		}
		rec.References = append(rec.References, ref)
	}
	return rec, nil
}

// nvdCVSS validates one CVSS metric of the given list version.
func nvdCVSS(version string, m nvdMetricJSON) (NVDCVSS, error) {
	d := m.CVSSData
	if d.Version != version {
		return NVDCVSS{}, fmt.Errorf("version: %w", ErrFeedMalformed)
	}
	if !nvdVectorRe.MatchString(d.VectorString) || !strings.HasPrefix(d.VectorString, "CVSS:"+version+"/") {
		return NVDCVSS{}, fmt.Errorf("vector: %w", ErrFeedMalformed)
	}
	if d.BaseScore == nil {
		return NVDCVSS{}, fmt.Errorf("missing baseScore: %w", ErrFeedMalformed)
	}
	score := *d.BaseScore
	if score < 0 || score > 10 || math.Abs(score*10-math.Round(score*10)) > 1e-6 {
		return NVDCVSS{}, fmt.Errorf("baseScore: %w", ErrFeedMalformed)
	}
	if !nvdSeverityRe.MatchString(d.BaseSeverity) {
		return NVDCVSS{}, fmt.Errorf("baseSeverity: %w", ErrFeedMalformed)
	}
	if err := checkToken(m.Source, maxNVDSourceBytes); err != nil {
		return NVDCVSS{}, fmt.Errorf("source: %w", err)
	}
	if !nvdTypeRe.MatchString(m.Type) {
		return NVDCVSS{}, fmt.Errorf("type: %w", ErrFeedMalformed)
	}
	return NVDCVSS{
		Version: version, Vector: d.VectorString, BaseScore: math.Round(score*10) / 10,
		BaseSeverity: d.BaseSeverity, Source: m.Source, Type: m.Type,
	}, nil
}

// nvdReference validates one reference; the URL is checked as text only
// (no whitespace or control characters, bounded), never parsed or fetched.
func nvdReference(url, source string, tags []string) (NVDReference, error) {
	if err := checkToken(url, MaxNVDReferenceURLBytes); err != nil {
		return NVDReference{}, fmt.Errorf("url: %w", err)
	}
	ref := NVDReference{URL: url}
	if source != "" {
		if err := checkToken(source, maxNVDSourceBytes); err != nil {
			return NVDReference{}, fmt.Errorf("source: %w", err)
		}
		ref.Source = source
	}
	if len(tags) > MaxNVDReferenceTags {
		return NVDReference{}, fmt.Errorf("more than %d tags: %w", MaxNVDReferenceTags, ErrFeedLimit)
	}
	for _, t := range tags {
		if !nvdTagRe.MatchString(t) {
			return NVDReference{}, fmt.Errorf("tag: %w", ErrFeedMalformed)
		}
	}
	if len(tags) > 0 {
		ref.Tags = slices.Clone(tags)
	}
	return ref, nil
}
