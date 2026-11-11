// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulnfeed fetches the vulnerability feeds of the vulnerability
// agent (ADR 0011 D4 and Amendment 1) from a fixed table of allowlisted
// HTTPS origins and keeps them as content-addressed snapshots with
// per-source manifests and high-water marks.
//
// Everything a feed origin returns is untrusted: sizes are capped before a
// body is read, redirects never leave the request's origin, and a snapshot
// whose content date or sequence falls below the newest one ever accepted
// is rejected while the previous snapshot stays in use. The fetch time is
// recorded for audit only and is never a content date.
package vulnfeed

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Size limits per feed (D4): 2 GiB for the NVD mirror, 512 MiB for others.
const (
	// MaxFeedBytesNVD caps an NVD bulk file.
	MaxFeedBytesNVD int64 = 2 << 30
	// MaxFeedBytesDefault caps every other feed file.
	MaxFeedBytesDefault int64 = 512 << 20
)

// DateKind says where a feed's content date comes from (D4).
type DateKind string

// DateKind values.
const (
	// DateKindDated: the content date is inside the data.
	DateKindDated DateKind = "dated"
	// DateKindProxy: the content date is the newest content date of the
	// dated companions fetched in the same sync (reviewed proxy table).
	DateKindProxy DateKind = "proxy"
	// DateKindUndated: no content date; the source always counts as stale.
	DateKindUndated DateKind = "undated"
)

// ChecksumAlg names the companion hash of a checksum-mode feed.
type ChecksumAlg string

// ChecksumAlg values; the companion is the feed URL plus "." and the name.
const (
	ChecksumSHA256 ChecksumAlg = "sha256"
	ChecksumSHA512 ChecksumAlg = "sha512"
)

// Feed is one entry of the fixed feed table.
type Feed struct {
	// Name identifies the feed file locally (snapshot manifest name).
	Name string
	// SourceID is the NOS feed source ID (cmd/nebula-server vulnSources)
	// the feed's data counts towards. Several feeds may share one ID.
	SourceID string
	// URL is the bulk download URL (https only).
	URL string
	// Integrity is the fixed integrity mode; a response can never lower it.
	Integrity vulnfinding.IntegrityMode
	// Checksum is the companion hash for IntegrityChecksum feeds.
	Checksum ChecksumAlg
	// MaxBytes caps the downloaded body.
	MaxBytes int64
	// DateKind says where the content date comes from.
	DateKind DateKind
	// ProxyCompanions names the dated feeds whose newest content date is
	// the proxy date of a DateKindProxy feed.
	ProxyCompanions []string
}

// feedNameRe bounds local feed names (they become file names).
var feedNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// sourceIDRe is the D5 source ID pattern (as in internal/vulnstore).
var sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

// ErrInvalidFeed reports a feed definition that breaks the table rules.
var ErrInvalidFeed = errors.New("vulnfeed: invalid feed definition")

// validate checks one feed definition.
func (f Feed) validate() error {
	if !feedNameRe.MatchString(f.Name) || !sourceIDRe.MatchString(f.SourceID) {
		return fmt.Errorf("feed name or source ID: %w", ErrInvalidFeed)
	}
	u, err := url.Parse(f.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("feed %s: URL must be https without credentials: %w", f.Name, ErrInvalidFeed)
	}
	if f.MaxBytes <= 0 || f.MaxBytes > MaxFeedBytesNVD {
		return fmt.Errorf("feed %s: max bytes: %w", f.Name, ErrInvalidFeed)
	}
	switch f.Integrity {
	case vulnfinding.IntegrityNone, vulnfinding.IntegritySigned:
		if f.Checksum != "" {
			return fmt.Errorf("feed %s: checksum set outside checksum mode: %w", f.Name, ErrInvalidFeed)
		}
	case vulnfinding.IntegrityChecksum:
		if f.Checksum != ChecksumSHA256 && f.Checksum != ChecksumSHA512 {
			return fmt.Errorf("feed %s: checksum algorithm: %w", f.Name, ErrInvalidFeed)
		}
	default:
		return fmt.Errorf("feed %s: integrity mode: %w", f.Name, ErrInvalidFeed)
	}
	switch f.DateKind {
	case DateKindDated, DateKindUndated:
		if len(f.ProxyCompanions) != 0 {
			return fmt.Errorf("feed %s: companions on a non-proxy feed: %w", f.Name, ErrInvalidFeed)
		}
	case DateKindProxy:
		if len(f.ProxyCompanions) == 0 {
			return fmt.Errorf("feed %s: proxy feed without companions: %w", f.Name, ErrInvalidFeed)
		}
	default:
		return fmt.Errorf("feed %s: date kind: %w", f.Name, ErrInvalidFeed)
	}
	return nil
}

// feedTable is the fixed feed table (D4, Q1). Every URL, format and
// licence is *verify* per the ADR; the integrity modes follow D4's
// expectation (signed for CSAF providers, none for the rest).
var feedTable = []Feed{
	{
		// Debian Security Tracker JSON export; undated in itself, proxy-dated
		// by the newest DSA/DLA list date (Q5).
		Name: "debian-tracker", SourceID: "debian-tracker",
		URL:       "https://security-tracker.debian.org/tracker/data/json",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault,
		DateKind: DateKindProxy, ProxyCompanions: []string{"debian-dsa", "debian-dla"},
	},
	{
		Name: "debian-dsa", SourceID: "dsa",
		URL:       "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "debian-dla", SourceID: "dla",
		URL:       "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "osv-debian", SourceID: "osv",
		URL:       "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "osv-ubuntu", SourceID: "osv",
		URL:       "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "osv-alpine", SourceID: "osv",
		URL:       "https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "osv-go", SourceID: "osv",
		URL:       "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		// NVD CVE JSON 2.0 bulk feed (modified file); never the per-CPE API.
		Name: "nvd-modified", SourceID: "nvd",
		URL:       "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesNVD, DateKind: DateKindDated,
	},
	{
		Name: "cisa-kev", SourceID: "kev",
		URL:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "first-epss", SourceID: "epss",
		URL:       "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		Integrity: vulnfinding.IntegrityNone, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		// Public Cisco CSAF provider only; no openVuln API client (Q1).
		Name: "cisco-csaf", SourceID: "cisco-csaf",
		URL:       "https://www.cisco.com/.well-known/csaf/provider-metadata.json",
		Integrity: vulnfinding.IntegritySigned, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
	{
		Name: "paloalto-csaf", SourceID: "paloalto-csaf",
		URL:       "https://security.paloaltonetworks.com/.well-known/csaf/provider-metadata.json",
		Integrity: vulnfinding.IntegritySigned, MaxBytes: MaxFeedBytesDefault, DateKind: DateKindDated,
	},
}

// Feeds returns a copy of the fixed feed table.
func Feeds() []Feed {
	out := make([]Feed, len(feedTable))
	for i, f := range feedTable {
		f.ProxyCompanions = slices.Clone(f.ProxyCompanions)
		out[i] = f
	}
	return out
}

// FeedByName returns a copy of the named feed of the fixed table.
func FeedByName(name string) (Feed, bool) {
	for _, f := range feedTable {
		if f.Name == name {
			f.ProxyCompanions = slices.Clone(f.ProxyCompanions)
			return f, true
		}
	}
	return Feed{}, false
}

// DefaultOrigins returns the origins of the fixed feed table, each once.
func DefaultOrigins() []string {
	var out []string
	for _, f := range feedTable {
		o, err := OriginOf(f.URL)
		if err != nil {
			continue // unreachable: TestFeedTableIsValid checks every URL
		}
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}
