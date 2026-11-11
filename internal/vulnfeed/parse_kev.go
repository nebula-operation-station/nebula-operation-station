// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"time"
)

// Limits of the CISA KEV catalog JSON (ADR 0011 D4).
const (
	// MaxKEVBytes caps the catalog (about 1.5 MiB in 2024).
	MaxKEVBytes = 32 << 20
	// MaxKEVEntries caps the catalog entries.
	MaxKEVEntries = 100_000
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
}

type kevJSON struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           *int   `json:"count"`
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VendorProject     string `json:"vendorProject"`
		Product           string `json:"product"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		DueDate           string `json:"dueDate"`
		Ransomware        string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// kevDateLayout is the KEV per-entry date form.
const kevDateLayout = "2006-01-02"

// ParseKEV parses the CISA Known Exploited Vulnerabilities catalog. The
// count field must equal the number of entries and every CVE may appear
// once. Descriptions, required actions and notes are skipped.
func ParseKEV(ctx context.Context, r io.Reader) (KEVCatalog, error) {
	data, err := readAllBounded(r, MaxKEVBytes)
	if err != nil {
		return KEVCatalog{}, fmt.Errorf("kev catalog: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return KEVCatalog{}, fmt.Errorf("kev catalog: %w", err)
	}
	var j kevJSON
	if err := decodeChecked(data, &j); err != nil {
		return KEVCatalog{}, fmt.Errorf("kev catalog: %w", err)
	}
	if !kevVersionRe.MatchString(j.CatalogVersion) {
		return KEVCatalog{}, fmt.Errorf("kev catalog: catalogVersion: %w", ErrFeedMalformed)
	}
	cat := KEVCatalog{Version: j.CatalogVersion}
	if cat.Released, err = parseFeedTime(j.DateReleased, time.RFC3339Nano); err != nil {
		return KEVCatalog{}, fmt.Errorf("kev catalog: dateReleased: %w", err)
	}
	if len(j.Vulnerabilities) > MaxKEVEntries {
		return KEVCatalog{}, fmt.Errorf("kev catalog: more than %d entries: %w", MaxKEVEntries, ErrFeedLimit)
	}
	if j.Count == nil || *j.Count != len(j.Vulnerabilities) {
		return KEVCatalog{}, fmt.Errorf("kev catalog: count does not match entries: %w", ErrFeedMalformed)
	}
	seen := make(map[string]struct{}, len(j.Vulnerabilities))
	cat.Entries = make([]KEVEntry, 0, len(j.Vulnerabilities))
	for i, v := range j.Vulnerabilities {
		if !cveIDRe.MatchString(v.CVEID) {
			return KEVCatalog{}, fmt.Errorf("kev entry %d: cveID: %w", i, ErrFeedMalformed)
		}
		where := "kev " + v.CVEID
		if _, dup := seen[v.CVEID]; dup {
			return KEVCatalog{}, fmt.Errorf("%s: duplicate: %w", where, ErrFeedMalformed)
		}
		seen[v.CVEID] = struct{}{}
		e := KEVEntry{CVE: v.CVEID, VendorProject: v.VendorProject, Product: v.Product, Name: v.VulnerabilityName}
		for _, s := range []string{e.VendorProject, e.Product, e.Name} {
			if err := checkText(s, MaxKEVNameBytes); err != nil {
				return KEVCatalog{}, fmt.Errorf("%s: name: %w", where, err)
			}
		}
		if e.DateAdded, err = parseFeedTime(v.DateAdded, kevDateLayout); err != nil {
			return KEVCatalog{}, fmt.Errorf("%s: dateAdded: %w", where, err)
		}
		if v.DueDate != "" {
			if e.DueDate, err = parseFeedTime(v.DueDate, kevDateLayout); err != nil {
				return KEVCatalog{}, fmt.Errorf("%s: dueDate: %w", where, err)
			}
		}
		switch v.Ransomware {
		case kevRansomwareKnown:
			e.KnownRansomware = true
		case kevRansomwareUnknown, "":
		default:
			return KEVCatalog{}, fmt.Errorf("%s: knownRansomwareCampaignUse: %w", where, ErrFeedMalformed)
		}
		cat.Entries = append(cat.Entries, e)
	}
	return cat, nil
}
