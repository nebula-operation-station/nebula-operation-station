// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Limits of the CISA KEV catalog JSON (ADR 0011 D4).
const (
	// MaxKEVBytes caps the catalog (about 1.5 MiB in 2024).
	MaxKEVBytes = 32 << 20
	// MaxKEVEntries caps the catalog entries.
	MaxKEVEntries = 100_000
	// MaxKEVEntryBytes caps the JSON of one catalog entry (about 1 KiB
	// in 2024).
	MaxKEVEntryBytes = 64 << 10
	// MaxKEVHeaderValueBytes caps each top-level value besides the
	// vulnerabilities array.
	MaxKEVHeaderValueBytes = 64 << 10
	// MaxKEVNameBytes caps vendor, product and vulnerability name.
	MaxKEVNameBytes = 512
)

// kevVersionRe is the catalogVersion, e.g. "2024.10.21".
var kevVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.-]{0,31}$`)

// KEV ransomware markers.
const (
	kevRansomwareKnown   = "Known"
	kevRansomwareUnknown = "Unknown"
)

// KEVEntry is one known exploited vulnerability.
type KEVEntry struct {
	// CVE is the CVE ID.
	CVE string
	// VendorProject, Product and Name are catalog text (text only).
	VendorProject, Product, Name string
	// DateAdded is the date the CVE entered the catalog.
	DateAdded time.Time
	// DueDate is the federal remediation due date; zero when absent.
	DueDate time.Time
	// KnownRansomware is true when the catalog says "Known".
	KnownRansomware bool
}

// KEVCatalog is a parsed KEV catalog.
type KEVCatalog struct {
	// Version is the catalogVersion.
	Version string
	// Released is the catalog's dateReleased: its content date (D4).
	Released time.Time
	// Entries are the catalog entries in input order.
	Entries []KEVEntry
	// Skipped counts the entries left out because they broke a field
	// rule.
	Skipped int
}

// kevEntryJSON is one catalog entry; descriptions, required actions,
// notes and CWEs are skipped.
type kevEntryJSON struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	DueDate           string `json:"dueDate"`
	Ransomware        string `json:"knownRansomwareCampaignUse"`
}

// KEV top-level keys the parser reads.
const (
	kevKeyVersion  = "catalogVersion"
	kevKeyReleased = "dateReleased"
	kevKeyCount    = "count"
	kevKeyVulns    = "vulnerabilities"
)

// kevDateLayout is the KEV per-entry date form.
const kevDateLayout = "2006-01-02"

// ParseKEV parses the CISA Known Exploited Vulnerabilities catalog. The
// catalog is streamed: entries are decoded one at a time and the entry
// limit is checked before each one. The count field must equal the
// number of entries, skipped ones included, and every CVE may appear
// once. An entry that breaks a field rule is skipped and counted in
// KEVCatalog.Skipped; a size, depth or count limit, a duplicate CVE or a
// bad top level fails the catalog.
func ParseKEV(ctx context.Context, r io.Reader) (KEVCatalog, error) {
	cat, err := parseKEV(ctx, r)
	if err != nil {
		return KEVCatalog{}, fmt.Errorf("kev catalog: %w", err)
	}
	return cat, nil
}

func parseKEV(ctx context.Context, r io.Reader) (KEVCatalog, error) {
	var cat KEVCatalog
	if err := ctx.Err(); err != nil {
		return cat, err
	}
	br := newBoundedReader(r, MaxKEVBytes)
	dec := json.NewDecoder(br)
	if err := expectDelim(dec, '{'); err != nil {
		return cat, br.fail("top level", err)
	}
	keys := make(map[string]struct{})
	var released string
	var count *int
	read := 0
	sawVulns := false
	for more(dec, br) {
		key, err := nextKey(dec, br, "key")
		if err != nil {
			return cat, err
		}
		if err := checkJSONKey(key); err != nil {
			return cat, err
		}
		folded := strings.ToLower(key)
		if _, dup := keys[folded]; dup {
			return cat, fmt.Errorf("duplicate top-level key: %w", ErrFeedMalformed)
		}
		keys[folded] = struct{}{}
		for _, known := range []string{kevKeyVersion, kevKeyReleased, kevKeyCount, kevKeyVulns} {
			if folded == strings.ToLower(known) && key != known {
				return cat, fmt.Errorf("key spelling: %w", ErrFeedMalformed)
			}
		}
		if key == kevKeyVulns {
			sawVulns = true
			if read, err = parseKEVEntries(ctx, dec, br, &cat); err != nil {
				return cat, err
			}
			continue
		}
		raw, err := decodeRecord(dec, br, "header", MaxKEVHeaderValueBytes)
		if err != nil {
			return cat, err
		}
		if err := checkJSON(raw, MaxJSONDepth); err != nil {
			return cat, fmt.Errorf("%s: %w", key, err)
		}
		var target any
		switch key {
		case kevKeyVersion:
			target = &cat.Version
		case kevKeyReleased:
			target = &released
		case kevKeyCount:
			target = &count
		default:
			continue // unknown or unused top-level field
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return cat, fmt.Errorf("%s: %w", key, ErrFeedMalformed)
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return cat, br.fail("end", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return cat, br.fail("data after the catalog", err)
	}
	if br.exceeded {
		return cat, ErrFeedLimit
	}
	if !kevVersionRe.MatchString(cat.Version) {
		return cat, fmt.Errorf("catalogVersion: %w", ErrFeedMalformed)
	}
	var err error
	if cat.Released, err = parseFeedTime(released, time.RFC3339Nano); err != nil {
		return cat, fmt.Errorf("dateReleased: %w", err)
	}
	if !sawVulns || count == nil || *count != read {
		return cat, fmt.Errorf("count does not match entries: %w", ErrFeedMalformed)
	}
	return cat, nil
}

// parseKEVEntries streams the vulnerabilities array into cat and returns
// the number of entries read, skipped ones included.
func parseKEVEntries(ctx context.Context, dec *json.Decoder, br *boundedReader, cat *KEVCatalog) (int, error) {
	if err := expectDelim(dec, '['); err != nil {
		return 0, br.fail("vulnerabilities", err)
	}
	seen := make(map[string]struct{})
	read := 0
	for more(dec, br) {
		if read%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return read, err
			}
		}
		if read >= MaxKEVEntries {
			return read, fmt.Errorf("more than %d entries: %w", MaxKEVEntries, ErrFeedLimit)
		}
		i := read
		read++
		raw, err := decodeRecord(dec, br, "entry", MaxKEVEntryBytes)
		if err != nil {
			return read, fmt.Errorf("entry %d: %w", i, err)
		}
		e, err := parseKEVEntry(raw)
		if err != nil {
			if recordSkippable(err) {
				cat.Skipped++
				continue
			}
			return read, fmt.Errorf("entry %d: %w", i, err)
		}
		if _, dup := seen[e.CVE]; dup {
			return read, fmt.Errorf("%s: duplicate: %w", e.CVE, ErrFeedMalformed)
		}
		seen[e.CVE] = struct{}{}
		cat.Entries = append(cat.Entries, e)
	}
	if err := expectDelim(dec, ']'); err != nil {
		return read, br.fail("vulnerabilities end", err)
	}
	return read, nil
}

// parseKEVEntry validates one catalog entry.
func parseKEVEntry(raw []byte) (KEVEntry, error) {
	var v kevEntryJSON
	if err := decodeChecked(raw, &v); err != nil {
		return KEVEntry{}, err
	}
	if !cveIDRe.MatchString(v.CVEID) {
		return KEVEntry{}, fmt.Errorf("cveID: %w", ErrFeedMalformed)
	}
	where := v.CVEID
	e := KEVEntry{CVE: v.CVEID, VendorProject: v.VendorProject, Product: v.Product, Name: v.VulnerabilityName}
	for _, s := range []string{e.VendorProject, e.Product, e.Name} {
		if err := checkText(s, MaxKEVNameBytes); err != nil {
			return KEVEntry{}, fmt.Errorf("%s: name: %w", where, err)
		}
	}
	var err error
	if e.DateAdded, err = parseFeedTime(v.DateAdded, kevDateLayout); err != nil {
		return KEVEntry{}, fmt.Errorf("%s: dateAdded: %w", where, err)
	}
	if v.DueDate != "" {
		if e.DueDate, err = parseFeedTime(v.DueDate, kevDateLayout); err != nil {
			return KEVEntry{}, fmt.Errorf("%s: dueDate: %w", where, err)
		}
	}
	switch v.Ransomware {
	case kevRansomwareKnown:
		e.KnownRansomware = true
	case kevRansomwareUnknown, "":
	default:
		return KEVEntry{}, fmt.Errorf("%s: knownRansomwareCampaignUse: %w", where, ErrFeedMalformed)
	}
	return e, nil
}
