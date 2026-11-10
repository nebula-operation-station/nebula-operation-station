// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Hostile values of the browser test's vulnerabilities pages
// (test/browser/vuln.spec.js, ADR 0011 D8, VU-16). Each would run script or
// create a link if any layer turned it into markup; the spec checks that
// window.__pwned stays unset, that they arrive as literal text, and that
// every link on the pages is NOS-built. Several values here could never
// pass the agent API's validation (markup in IDs, package names and
// source IDs, control and bidi characters): the pages must stay safe even
// if a value got past it.
const (
	vulnHostName       = `<img src=x onerror="window.__pwned='subject'">E2E host`
	vulnTwoName        = `</script><script>window.__pwned='two'</script>`
	vulnAssessment     = "<script>window.__pwned='assessment'</script>\nSecond line: <b>bold?</b>\n\t<a href=\"https://evil.example/a\">evil link</a>"
	vulnMarkdownText   = "[click me](javascript:window.__pwned='markdown') and https://evil.example/plain and <a href=\"javascript:window.__pwned='a'\">a</a>"
	vulnControlText    = "<iframe srcdoc=\"<script>parent.__pwned='iframe'</script>\"></iframe> esc\x1b[31m bidi‮evil"
	vulnHostileID      = `<svg onload="window.__pwned='id'">`
	vulnHostilePackage = `openssl<img src=x onerror="window.__pwned='pkg'">`
	vulnHostileAlias   = `<b onmouseover="window.__pwned='alias'">DSA</b>`
	vulnHostileSource  = `evil<script>window.__pwned='feed'</script>`
	vulnHostileRun     = `<b>run</b>"><script>window.__pwned='run'</script>`
	vulnHostileVersion = `3.0.15<img src=x onerror="window.__pwned='version'">`

	vulnImageDigest = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
)

// Finding keys of the harness findings (any 32 bytes; the spec opens the
// finding pages by these).
var (
	vulnKeyCritical = vulnKey("11")
	vulnKeyHostile  = vulnKey("22")
	vulnKeyNotRun   = vulnKey("33")
	vulnKeyStale    = vulnKey("44")
	vulnKeyUnconf   = vulnKey("55")
)

func vulnKey(b string) vulnfinding.Key {
	var k vulnfinding.Key
	raw, err := hex.DecodeString(strings.Repeat(b, len(k)))
	must(err)
	copy(k[:], raw)
	return k
}

// Subjects of the harness: e2e-host is assessed and has open findings,
// e2e-two was never assessed, the image on e2e-host was last assessed 72 h
// ago (stale), e2e-unconf has only a closure Hermes reported and NOS did
// not confirm, and e2e-clean is assessed and has no findings (the only
// subject that may show green, and only where no feed has an issue).
var (
	vulnSubjHost   = vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "e2e-host"}
	vulnSubjTwo    = vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "e2e-two"}
	vulnSubjImage  = vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "e2e-host", ImageDigest: vulnImageDigest}
	vulnSubjUnconf = vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "e2e-unconf"}
	vulnSubjClean  = vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: "e2e-clean"}
)

// harnessVuln is a fixed vulnerabilities backend. It never applies a
// decision: every assertion is refused, so the spec cannot change state.
type harnessVuln struct{}

func vulnRecord(subj vulnstore.Subject, id, pkg, version, text string, basis ...string) vulnfinding.Record {
	r := vulnfinding.Record{SubjectKind: subj.Kind, SubjectRef: vulnfinding.SubjectRef{ID: subj.ID, ImageDigest: subj.ImageDigest},
		Ecosystem: "debian:bookworm", Component: vulnfinding.Component{SourcePackage: pkg, SourceVersion: version},
		Vuln: vulnfinding.Vuln{ID: id}, Fix: vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.16-1~deb12u1"},
		TrackerState: "fixed", MatchBasis: vulnfinding.MatchDistroTracker,
		Evidence:   vulnfinding.Evidence{MatcherVersion: "1.4.0"},
		Assessment: vulnfinding.Assessment{Text: text}}
	for _, b := range basis {
		r.Evidence.BasisSources = append(r.Evidence.BasisSources, vulnfinding.BasisSource{SourceID: b, SnapshotID: "snap-" + b, Integrity: vulnfinding.IntegrityNone})
	}
	return r
}

func (harnessVuln) rows(now time.Time) []ui.VulnRow {
	crit := vulnRecord(vulnSubjHost, "CVE-2026-1111", vulnHostilePackage, "3.0.15-1~deb12u1", vulnAssessment, "debian-tracker", "kev")
	crit.Vuln.Aliases = []string{"DSA-5555-1", vulnHostileAlias}
	crit.Scores = vulnfinding.Scores{KEV: &vulnfinding.KEV{DateAdded: "2026-10-01"},
		CVSS: &vulnfinding.CVSS{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", BaseScore: 9.8, Source: vulnfinding.CVSSSourceNVD}}
	crit.Assessment.ExploitPublic = true
	hostile := vulnRecord(vulnSubjHost, vulnHostileID, "curl", vulnHostileVersion, vulnMarkdownText, "debian-tracker")
	notRun := vulnRecord(vulnSubjTwo, "CVE-2026-2222", "bash", "5.2.15-2", vulnControlText, "debian-tracker")
	stale := vulnRecord(vulnSubjImage, "CVE-2026-1111", "openssl", "3.0.15-1~deb12u1", "image finding", vulnHostileSource)
	unconf := vulnRecord(vulnSubjUnconf, "CVE-2026-3333", "zlib", "1.2.13.dfsg-1", "closed by Hermes", "debian-tracker")
	seen := now.Add(-2 * time.Hour)
	f := func(k vulnfinding.Key, s vulnstore.Subject, r vulnfinding.Record, st vulnstore.State) vulnstore.Finding {
		return vulnstore.Finding{Key: k, Subject: s, Record: r, NOSChecked: true, State: st, FirstSeen: seen, LastSeen: seen, Updated: seen,
			EpisodeFixedVersion: r.Fix.Version}
	}
	fc := f(vulnKeyCritical, vulnSubjHost, crit, vulnstore.StateOpen)
	fc.EpisodeKEVDate = "2026-10-01"
	fu := f(vulnKeyUnconf, vulnSubjUnconf, unconf, vulnstore.StateFixed)
	fu.ClosedBy, fu.ClosedAt = vulnstore.ClosedByHermesUnconfirmed, seen
	return []ui.VulnRow{
		{Finding: fc, Tier: vulnstore.TierCritical},
		{Finding: f(vulnKeyHostile, vulnSubjHost, hostile, vulnstore.StateOpen), Tier: vulnstore.TierUnknown},
		{Finding: f(vulnKeyNotRun, vulnSubjTwo, notRun, vulnstore.StateOpen), Tier: vulnstore.TierMedium},
		{Finding: f(vulnKeyStale, vulnSubjImage, stale, vulnstore.StateOpen), Tier: vulnstore.TierHigh},
		{Finding: fu, Tier: vulnstore.TierMedium},
	}
}

func (harnessVuln) subjects(now time.Time) []ui.VulnSubjectStatus {
	fresh := now.Add(-time.Hour)
	return []ui.VulnSubjectStatus{
		{Subject: vulnSubjHost, Name: vulnHostName, LastComplete: fresh},
		{Subject: vulnSubjTwo, Name: vulnTwoName},
		{Subject: vulnSubjImage, LastComplete: now.Add(-72 * time.Hour)},
		{Subject: vulnSubjUnconf, Name: "unconfirmed host", LastComplete: fresh},
		{Subject: vulnSubjClean, Name: "clean host", LastComplete: fresh},
	}
}

// feeds are the listed sources, all accepted and fresh; the only feed
// issue is the unlisted (hostile) source the stale image finding rests on.
func (harnessVuln) feeds(now time.Time) []ui.VulnFeedStatus {
	var out []ui.VulnFeedStatus
	for _, id := range []string{"debian-tracker", "dsa", "dla", "osv", "nvd", "kev", "epss"} {
		out = append(out, ui.VulnFeedStatus{SourceID: id, Listed: true, SnapshotDate: now.Add(-time.Hour), LastVerdict: vulnstore.SourceAccepted})
	}
	return out
}

func (v harnessVuln) VulnFindings(_ context.Context, q ui.VulnQuery) (ui.VulnPage, error) {
	now := time.Now()
	page := ui.VulnPage{Feeds: v.feeds(now), LastComplete: now.Add(-time.Hour)}
	for _, r := range v.rows(now) {
		if q.VulnID != "" && r.Finding.Record.Vuln.ID != q.VulnID {
			continue
		}
		if q.Subject != nil && r.Finding.Subject != *q.Subject {
			continue
		}
		page.Rows = append(page.Rows, r)
	}
	for _, s := range v.subjects(now) {
		if q.Subject == nil || s.Subject == *q.Subject {
			page.Subjects = append(page.Subjects, s)
		}
	}
	return page, nil
}

func (v harnessVuln) VulnFinding(_ context.Context, key vulnfinding.Key) (ui.VulnFindingDetail, error) {
	now := time.Now()
	for _, r := range v.rows(now) {
		if r.Finding.Key != key {
			continue
		}
		d := ui.VulnFindingDetail{Row: r, Feeds: v.feeds(now), LastComplete: now.Add(-time.Hour), Subject: ui.VulnSubjectStatus{Subject: r.Finding.Subject}}
		for _, s := range v.subjects(now) {
			if s.Subject == r.Finding.Subject {
				d.Subject = s
			}
		}
		if key == vulnKeyCritical {
			d.Holds = []ui.VulnHold{
				{Hold: vulnstore.Hold{RunID: vulnHostileRun, RunSeq: 7, Key: key, Reason: vulnstore.HoldKEVOrCritical, Created: now.Add(-30 * time.Minute)},
					NOSVersion: vulnHostileVersion},
				{Hold: vulnstore.Hold{RunID: "run-contradicted", RunSeq: 8, Key: key, Reason: vulnstore.HoldContradicted, Created: now.Add(-20 * time.Minute)},
					NOSVersion: "3.0.15-1~deb12u1", Contradicted: true},
			}
		}
		return d, nil
	}
	return ui.VulnFindingDetail{}, vulnstore.ErrFindingNotFound
}

func (harnessVuln) VulnMarkResetCandidate(context.Context, string) (vulnstore.MarkResetView, error) {
	return vulnstore.MarkResetView{}, vulnstore.ErrResetRefused
}

// VulnMaintainer: the signed-in user is the maintainer, so the pages show
// the decision forms with hostile values in their fields.
func (harnessVuln) VulnMaintainer(context.Context, string) (bool, error) { return true, nil }

func (harnessVuln) BeginVulnDecision(context.Context, string, ui.VulnDecision) (ui.VulnChallenge, error) {
	return ui.VulnChallenge{}, ui.ErrVulnAssertionRefused
}

func (harnessVuln) CommitVulnDecision(context.Context, string, string, ui.VulnDecision, []byte) error {
	return ui.ErrVulnAssertionRefused
}
