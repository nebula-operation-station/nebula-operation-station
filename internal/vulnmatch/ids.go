// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// canonicalID upper-cases CVE IDs, as vulnfinding does before keying.
func canonicalID(id string) string {
	if cveRe.MatchString(id) {
		return strings.ToUpper(id)
	}
	return id
}

func isCVE(id string) bool { return strings.HasPrefix(id, "CVE-") && cveRe.MatchString(id) }

// chooseIDs applies the A1.3 ID rules to the IDs of one feed record for
// one matched (ecosystem, package or model) pair: at most
// MaxRecordIDEntries IDs are read; invalid IDs are dropped; of the valid,
// deduplicated IDs at most MaxRecordValidIDs are kept (anchors for this
// pair first, then CVE IDs, then others, each bytewise); the primary is
// (1) the anchored ID, (2) the bytewise-smallest CVE ID, (3) the
// bytewise-smallest valid ID; it is removed from the aliases, which are
// cut to the MaxAliases bytewise-smallest. cut counts dropped parts.
func chooseIDs(ids []string, eco, pkg string, anchors map[Anchor]struct{}) (primary string, aliases []string, cut int, ok bool) {
	if len(ids) > MaxRecordIDEntries {
		cut += len(ids) - MaxRecordIDEntries
		ids = ids[:MaxRecordIDEntries]
	}
	seen := make(map[string]struct{}, len(ids))
	var anchored, cves, others []string
	for _, raw := range ids {
		if !vulnIDRe.MatchString(raw) {
			cut++
			continue
		}
		id := canonicalID(raw)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		_, isAnchor := anchors[Anchor{Ecosystem: eco, Package: pkg, VulnID: id}]
		switch {
		case isAnchor:
			anchored = append(anchored, id)
		case isCVE(id):
			cves = append(cves, id)
		default:
			others = append(others, id)
		}
	}
	slices.Sort(anchored)
	slices.Sort(cves)
	slices.Sort(others)
	valid := slices.Concat(anchored, cves, others)
	if len(valid) == 0 {
		return "", nil, cut, false
	}
	if len(valid) > MaxRecordValidIDs {
		cut += len(valid) - MaxRecordValidIDs
		valid = valid[:MaxRecordValidIDs]
	}
	kept := map[string]bool{}
	for _, id := range valid {
		kept[id] = true
	}
	// Rule 1: exactly one anchor decides; several fall to rules 2 and 3
	// among the anchored IDs.
	switch {
	case len(anchored) == 1:
		primary = anchored[0]
	case len(anchored) > 1:
		primary = pickByRules23(anchored)
	default:
		primary = pickByRules23(valid)
	}
	for _, id := range valid {
		if id != primary {
			aliases = append(aliases, id)
		}
	}
	slices.Sort(aliases)
	if len(aliases) > MaxAliases {
		cut += len(aliases) - MaxAliases
		aliases = aliases[:MaxAliases]
	}
	return primary, aliases, cut, true
}

func pickByRules23(ids []string) string {
	best := ""
	for _, id := range ids {
		if isCVE(id) && (best == "" || id < best) {
			best = id
		}
	}
	if best != "" {
		return best
	}
	best = ids[0]
	for _, id := range ids[1:] {
		if id < best {
			best = id
		}
	}
	return best
}

// companionSources returns the source IDs of a feed's proxy companions
// (vulnfeed table), with the companion feed names.
func companionFeeds(feed string) []string {
	f, ok := vulnfeed.FeedByName(feed)
	if !ok {
		return nil
	}
	return f.ProxyCompanions
}

// evidence builds evidence.basis_sources: the match feed and its proxy
// companions first, then the score sources used, each source ID at most
// once; over MaxRecordBasisSources the tail is cut (A1.3 fail-safe).
func (db *DB) evidence(matchFeed string, scoreFeeds []string) (vulnfinding.Evidence, int) {
	var head, tail []vulnfinding.BasisSource
	seen := map[string]bool{}
	add := func(dst *[]vulnfinding.BasisSource, feed string) {
		ref, ok := db.feeds[feed]
		if !ok || seen[ref.SourceID] {
			return
		}
		seen[ref.SourceID] = true
		*dst = append(*dst, ref.basis())
	}
	add(&head, matchFeed)
	for _, c := range companionFeeds(matchFeed) {
		add(&head, c)
	}
	for _, f := range scoreFeeds {
		add(&tail, f)
	}
	slices.SortFunc(tail, func(a, b vulnfinding.BasisSource) int { return strings.Compare(a.SourceID, b.SourceID) })
	all := append(head, tail...)
	cut := 0
	if len(all) > MaxRecordBasisSources {
		cut = len(all) - MaxRecordBasisSources
		all = all[:MaxRecordBasisSources]
	}
	return vulnfinding.Evidence{BasisSources: all, MatcherVersion: MatcherVersion}, cut
}

// scores looks up KEV, EPSS and NVD CVSS for the record's CVE (the primary
// when it is a CVE, else the smallest CVE alias) and returns the feeds
// used.
func (db *DB) scores(primary string, aliases []string) (vulnfinding.Scores, []string) {
	cve := ""
	if isCVE(primary) {
		cve = primary
	} else {
		for _, a := range aliases {
			if isCVE(a) {
				cve = a
				break
			}
		}
	}
	var s vulnfinding.Scores
	var used []string
	if cve == "" {
		return s, nil
	}
	if c, ok := db.nvd[cve]; ok {
		c := c
		s.CVSS = &c
		used = append(used, FeedNVD)
	}
	if d, ok := db.kev[cve]; ok {
		s.KEV = &vulnfinding.KEV{DateAdded: d}
		used = append(used, FeedKEV)
	}
	if e, ok := db.epss[cve]; ok {
		s.EPSS = &vulnfinding.EPSS{Probability: e.probability, Percentile: e.percentile, Date: e.date}
		used = append(used, FeedEPSS)
	}
	return s, used
}
