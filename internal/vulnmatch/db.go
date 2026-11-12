// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Feed names of the vulnfeed table the matcher reads.
const (
	FeedDebianTracker = "debian-tracker"
	FeedOSVUbuntu     = "osv-ubuntu"
	FeedOSVAlpine     = "osv-alpine"
	FeedNVD           = "nvd-modified"
	FeedKEV           = "cisa-kev"
	FeedEPSS          = "first-epss"
	FeedCiscoCSAF     = "cisco-csaf"
	FeedPaloAltoCSAF  = "paloalto-csaf"
)

// FeedRef names the snapshot of one feed a match rests on.
type FeedRef struct {
	// SourceID is the NOS feed source ID (the vulnfeed table's SourceID).
	SourceID string
	// SnapshotID is the content-addressed snapshot ID.
	SnapshotID string
	// Integrity is the feed's fixed integrity mode.
	Integrity vulnfinding.IntegrityMode
}

// FeedRefFromManifest returns the FeedRef of an accepted snapshot.
func FeedRefFromManifest(m vulnfeed.Manifest) FeedRef {
	return FeedRef{SourceID: m.SourceID, SnapshotID: m.SnapshotID(), Integrity: m.Integrity}
}

func (r FeedRef) basis() vulnfinding.BasisSource {
	return vulnfinding.BasisSource{SourceID: r.SourceID, SnapshotID: r.SnapshotID, Integrity: r.Integrity}
}

type debKey struct{ pkg, release string }

type debEntry struct {
	issue   string
	state   vulnfinding.TrackerState
	fixed   string
	ordinal int
}

type osvKey struct{ eco, name string }

type osvHit struct {
	rec      int // index into DB.osv
	affected int // index into the record's Affected
}

type osvRec struct {
	feed string
	rec  vulnfeed.OSVRecord
}

type csafDoc struct {
	feed string
	adv  vulnfeed.CSAFAdvisory
}

type epssScore struct {
	probability, percentile float64
	date                    string
}

// DB holds the parsed feed snapshots of one run. Fill it with the Set and
// Add methods (the feed parsers' visit callbacks can call them directly),
// then call Match. A DB is not safe for concurrent use.
type DB struct {
	feeds      map[string]FeedRef
	debian     map[debKey][]debEntry
	debianN    int
	osv        []osvRec
	osvIndex   map[osvKey][]osvHit
	csaf       []csafDoc
	kev        map[string]string
	epss       map[string]epssScore
	nvd        map[string]vulnfinding.CVSS
	nvdCut     int
	sortedDebs bool
	// scoreLimit is MaxScoreEntries; tests lower it.
	scoreLimit int
}

// NewDB returns an empty DB.
func NewDB() *DB {
	return &DB{
		feeds:      map[string]FeedRef{},
		debian:     map[debKey][]debEntry{},
		osvIndex:   map[osvKey][]osvHit{},
		kev:        map[string]string{},
		epss:       map[string]epssScore{},
		nvd:        map[string]vulnfinding.CVSS{},
		scoreLimit: MaxScoreEntries,
	}
}

// SetFeed records the snapshot of the named feed. The name must be in the
// vulnfeed table and ref.SourceID must be that feed's source ID; a source
// ID can therefore only ever come from the fixed table.
func (db *DB) SetFeed(name string, ref FeedRef) error {
	f, ok := vulnfeed.FeedByName(name)
	if !ok || f.SourceID != ref.SourceID {
		return fmt.Errorf("set feed: %w", ErrUnknownFeed)
	}
	if !snapshotIDRe.MatchString(ref.SnapshotID) {
		return fmt.Errorf("set feed %s: snapshot id: %w", name, ErrInvalidFeedRef)
	}
	if ref.Integrity != f.Integrity {
		return fmt.Errorf("set feed %s: integrity mode differs from the feed table: %w", name, ErrInvalidFeedRef)
	}
	db.feeds[name] = ref
	return nil
}

func (db *DB) needFeed(name string) error {
	if _, ok := db.feeds[name]; !ok {
		return fmt.Errorf("feed %s: %w", name, ErrNoFeedSnapshot)
	}
	return nil
}

// AddDebian adds one Debian Security Tracker entry (ParseDebianTracker).
func (db *DB) AddDebian(e vulnfeed.DebianEntry) error {
	if err := db.needFeed(FeedDebianTracker); err != nil {
		return err
	}
	if db.debianN >= MaxDebianEntries {
		return fmt.Errorf("debian entries: %w", ErrLimit)
	}
	k := debKey{e.Package, e.Release}
	db.debian[k] = append(db.debian[k], debEntry{issue: e.IssueID, state: e.State, fixed: e.FixedVersion, ordinal: db.debianN})
	db.debianN++
	db.sortedDebs = false
	return nil
}

// AddOSV adds one OSV record of the named OSV feed (osv-ubuntu,
// osv-alpine). Records of other OSV feeds are accepted and ignored by the
// matcher until it supports their version scheme.
func (db *DB) AddOSV(feed string, r vulnfeed.OSVRecord) error {
	f, ok := vulnfeed.FeedByName(feed)
	if !ok || f.SourceID != "osv" {
		return fmt.Errorf("add osv: %w", ErrUnknownFeed)
	}
	if err := db.needFeed(feed); err != nil {
		return err
	}
	if len(db.osv) >= MaxOSVRecords {
		return fmt.Errorf("osv records: %w", ErrLimit)
	}
	idx := len(db.osv)
	db.osv = append(db.osv, osvRec{feed: feed, rec: r})
	for i, a := range r.Affected {
		k := osvKey{a.Ecosystem, a.Name}
		db.osvIndex[k] = append(db.osvIndex[k], osvHit{rec: idx, affected: i})
	}
	return nil
}

// AddCSAF adds one accepted CSAF advisory of the named signed feed.
func (db *DB) AddCSAF(feed string, a vulnfeed.CSAFAdvisory) error {
	if feed != FeedCiscoCSAF && feed != FeedPaloAltoCSAF {
		return fmt.Errorf("add csaf: %w", ErrUnknownFeed)
	}
	if err := db.needFeed(feed); err != nil {
		return err
	}
	if len(db.csaf) >= MaxCSAFAdvisories {
		return fmt.Errorf("csaf advisories: %w", ErrLimit)
	}
	db.csaf = append(db.csaf, csafDoc{feed: feed, adv: a})
	return nil
}

// AddKEV adds one KEV catalog entry.
func (db *DB) AddKEV(e vulnfeed.KEVEntry) error {
	if err := db.needFeed(FeedKEV); err != nil {
		return err
	}
	if len(db.kev) >= db.scoreLimit {
		return fmt.Errorf("kev entries: %w", ErrLimit)
	}
	if e.DateAdded.IsZero() {
		return nil
	}
	db.kev[strings.ToUpper(e.CVE)] = e.DateAdded.UTC().Format("2006-01-02")
	return nil
}

// SetEPSS adds the scores of one EPSS file. Like AddKEV and AddNVD it
// bounds the total number of entries the DB holds, not just one file's; a
// file that would exceed the bound is rejected whole and leaves the DB
// unchanged.
func (db *DB) SetEPSS(s vulnfeed.EPSSScores) error {
	if err := db.needFeed(FeedEPSS); err != nil {
		return err
	}
	if len(s.Scores) > db.scoreLimit {
		return fmt.Errorf("epss scores: %w", ErrLimit)
	}
	added := map[string]struct{}{}
	for _, sc := range s.Scores {
		k := strings.ToUpper(sc.CVE)
		if _, ok := db.epss[k]; !ok {
			added[k] = struct{}{}
		}
	}
	if len(db.epss)+len(added) > db.scoreLimit {
		return fmt.Errorf("epss scores: %d entries: %w", len(db.epss)+len(added), ErrLimit)
	}
	date := s.Date.UTC().Format("2006-01-02")
	for _, sc := range s.Scores {
		db.epss[strings.ToUpper(sc.CVE)] = epssScore{probability: sc.Probability, percentile: sc.Percentile, date: date}
	}
	return nil
}

// AddNVD adds the CVSS score of one NVD record: the highest valid base
// score, ties broken by CVSS version descending, then vector bytewise.
// Entries with an invalid vector are cut (A1.3).
func (db *DB) AddNVD(r vulnfeed.NVDRecord) error {
	if err := db.needFeed(FeedNVD); err != nil {
		return err
	}
	if len(db.nvd) >= db.scoreLimit {
		return fmt.Errorf("nvd records: %w", ErrLimit)
	}
	var cands []vulnfinding.CVSS
	for _, c := range r.CVSS {
		v := vulnfinding.CVSS{Version: c.Version, Vector: c.Vector, BaseScore: c.BaseScore, Source: vulnfinding.CVSSSourceNVD}
		if !validCVSS(v) {
			db.nvdCut++
			continue
		}
		cands = append(cands, v)
	}
	if len(cands) == 0 {
		return nil
	}
	slices.SortFunc(cands, func(a, b vulnfinding.CVSS) int {
		switch {
		case a.BaseScore != b.BaseScore:
			if a.BaseScore > b.BaseScore {
				return -1
			}
			return 1
		case a.Version != b.Version:
			return -strings.Compare(a.Version, b.Version)
		default:
			return strings.Compare(a.Vector, b.Vector)
		}
	})
	db.nvd[strings.ToUpper(r.ID)] = cands[0]
	return nil
}

// validCVSS mirrors the D2 score rules for the CVSS versions NVD carries.
func validCVSS(c vulnfinding.CVSS) bool {
	if c.Version != "3.1" && c.Version != "4.0" && c.Version != "3.0" {
		return false
	}
	if len(c.Vector) > 255 || !strings.HasPrefix(c.Vector, "CVSS:"+c.Version+"/") {
		return false
	}
	for i := 0; i < len(c.Vector); i++ {
		ch := c.Vector[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == ':' || ch == '.' || ch == '/') {
			return false
		}
	}
	if !(c.BaseScore >= 0 && c.BaseScore <= 10) {
		return false
	}
	x := c.BaseScore * 10
	return x-float64(int64(x+0.5)) < 1e-9 && float64(int64(x+0.5))-x < 1e-9
}

// sortDebian orders each package's entries by issue ID, then input order,
// so Match is independent of the tracker's package order.
func (db *DB) sortDebian() {
	if db.sortedDebs {
		return
	}
	for _, es := range db.debian {
		slices.SortStableFunc(es, func(a, b debEntry) int {
			if c := strings.Compare(a.issue, b.issue); c != 0 {
				return c
			}
			return a.ordinal - b.ordinal
		})
	}
	db.sortedDebs = true
}
