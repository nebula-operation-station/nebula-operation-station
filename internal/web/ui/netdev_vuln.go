// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnmatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// netdevCoverageUnknown labels a device that no complete Hermes run has
// covered. Its vendor findings are unknown, never a clean result (ADR 0011
// D4, D8).
const netdevCoverageUnknown = "coverage unknown"

// vendorFeedSource reports whether a feed source is a vendor advisory source
// that device findings rest on.
func vendorFeedSource(id string) bool {
	return id == vulnmatch.FeedCiscoCSAF || id == vulnmatch.FeedPaloAltoCSAF
}

// netdevVulnView is the vendor-advisory block of a device page: the device's
// findings with their observer label, the advisory link of each one, and the
// coverage label of the device.
type netdevVulnView struct {
	// Observer names who reported the findings (Hermes).
	Observer string
	// Coverage is the coverage label of the device: the run age, or
	// "coverage unknown" with the reason when no complete run covers it.
	Coverage string
	// CoverageWarn marks an unknown coverage for the warning style.
	CoverageWarn bool
	// Unavailable is set when the findings could not be read.
	Unavailable bool
	// Truncated is set when the store cut the list at its row limit.
	Truncated bool
	// Findings are the device's findings as the store lists them.
	Findings []netdevVulnRow
}

// netdevVulnRow is one finding of a device. Every value from Hermes or the
// advisories is text; the only links are NOS-built.
type netdevVulnRow struct {
	VulnID  string
	VulnURL string
	Tier    string
	State   string
	// Fix is the vendor advisory link; nil when none applies.
	Fix *vulnFixView
}

// deviceVulns builds the vendor-advisory block of device id. It returns nil
// when the vulnerability pages are off.
func (p *NetDevPages) deviceVulns(ctx context.Context, id string) *netdevVulnView {
	if p.h.vuln == nil {
		return nil
	}
	s := vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: id}
	page, err := p.h.vuln.VulnFindings(ctx, VulnQuery{Subject: &s, Limit: MaxVulnRows})
	if err != nil {
		p.h.log.Error("network device page: vulnerabilities", "device", id, "error", err)
		return &netdevVulnView{Observer: hermesObserverLabel, Unavailable: true}
	}
	now := p.h.clockNow()
	page.Feeds = withUnknownFeeds(page.Feeds, page.Rows)
	c := newVulnContext(now, page.Subjects, page.Feeds)
	v := &netdevVulnView{Observer: hermesObserverLabel, Truncated: page.Truncated}
	lbl, stale := subjectLabel(c.subject(s), now)
	// A vendor source that is stale, unlisted or regressed makes the device's
	// vendor findings unknown too, even when its last run is recent (ADR 0011
	// D4, D5): the run covered a source NOS no longer trusts.
	var feedIssues []string
	for _, f := range page.Feeds {
		if !vendorFeedSource(f.SourceID) {
			continue
		}
		for _, l := range feedLabels(f) {
			feedIssues = append(feedIssues, l.Text)
		}
	}
	switch {
	case stale || len(feedIssues) > 0:
		parts := []string{}
		if stale {
			parts = append(parts, lbl.Text)
		}
		parts = append(parts, feedIssues...)
		v.Coverage, v.CoverageWarn = netdevCoverageUnknown+": "+strings.Join(parts, "; "), true
	default:
		v.Coverage = lbl.Text
	}
	fix := p.h.newVulnFixResolver()
	for _, row := range page.Rows {
		if row.Finding.Subject != s {
			continue
		}
		view := c.view(row)
		v.Findings = append(v.Findings, netdevVulnRow{
			VulnID:  view.VulnID,
			VulnURL: view.VulnURL,
			Tier:    view.Tier.Text,
			State:   view.State.Text,
			Fix:     fix.fixWith(ctx, row.Finding),
		})
	}
	return v
}
