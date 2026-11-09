// SPDX-License-Identifier: AGPL-3.0-or-later

// The P1-30 host-local Trivy observation beside the finding store (ADR
// 0011 D2, plan VU-09).
//
// The image.vulnerabilities result of P1-30 (counts plus the top 25 of a
// host-local Trivy scan, internal/executions/dockerhost) is shown as its
// own, labelled, partial observation with observer "trivy-local". It is
// read from the stored action results only and never written to, compared
// into or derived from the finding store:
//
//   - nothing here calls the vulnerabilities backend (the finding store);
//     the Hermes findings are only shown beside it, by ID, as text;
//   - a Hermes run never opens, updates or closes the observation, and the
//     observation never opens, closes or re-opens a Hermes finding;
//   - an absent, unreadable, foreign or incomplete observation is "not
//     observed" or "unknown", never green; a completed scan is partial by
//     nature and is never green either.
//
// The image badge shows the Hermes status when a fresh complete Hermes run
// covers the image, otherwise the trivy-local observation, always with its
// observer label.
package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Labels of the trivy-local observation.
const (
	// TrivyLocalObserver is the observer name of the P1-30 host-local
	// Trivy observation (ADR 0011 D2). The finding store never holds it.
	TrivyLocalObserver = "trivy-local"
	// trivyLocalLabel is the observer label shown to the user.
	trivyLocalLabel = "host Trivy, partial"
	// hermesObserverLabel is the observer label of the finding store.
	hermesObserverLabel = "Hermes"
	// trivyLocalAction is the P1-30 action whose stored results are read.
	trivyLocalAction = "image.vulnerabilities"
	// trivyLocalChartLabel labels the org-chart CVE line with its observer.
	trivyLocalChartLabel = "CVE (" + trivyLocalLabel + ")"
	// trivyNotObserved is the text of an absent observation.
	trivyNotObserved = "not observed"
	// trivyStaleAfter: an older stored result is stale (as the org chart).
	trivyStaleAfter = indicatorStaleAfter
)

// trivySeverities is the display order of the severity counts.
var trivySeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// trivyLocalCount is one severity count.
type trivyLocalCount struct {
	Severity string
	Count    int
}

// trivyLocalVuln is one top entry with the Hermes state of the same ID
// beside it (never merged into it).
type trivyLocalVuln struct {
	ID       string
	Severity string
	Fixed    string
	// Hermes is the Hermes finding store's view of the same vulnerability
	// ID on this image, as text.
	Hermes vulnLabel
}

// trivyLocalView is the trivy-local observation of one image.
type trivyLocalView struct {
	Observer string
	Label    string
	// Observed: a stored scan of this image exists (any status).
	Observed bool
	// Counted: the scan completed and carries counts.
	Counted bool
	Status  vulnLabel

	Image      string
	Platform   string
	Scanner    string
	DBAge      string
	ObservedAt string
	Cached     bool
	Counts     []trivyLocalCount
	Total      int
	Targets    int
	Top        []trivyLocalVuln
	// Partial explains what the observation does not cover.
	Partial string
}

// vulnImageBadge is the image's badge with its selected source.
type vulnImageBadge struct {
	// Source is "hermes", TrivyLocalObserver or "" (nothing observed).
	Source   string
	Observer string
	Status   vulnLabel
}

// trivyLocalPanel is what the image detail page shows beside the Hermes
// findings.
type trivyLocalPanel struct {
	Badge vulnImageBadge
	Trivy trivyLocalView
	// HermesUnavailable: the finding store could not be read; the
	// observation is shown anyway, without comparison.
	HermesUnavailable bool
}

// imageDigestOf returns the digest of a "repo@sha256:…" reference.
func imageDigestOf(ref string) string {
	_, d, ok := strings.Cut(ref, "@")
	if !ok {
		return ""
	}
	return d
}

// trivyLocalObserve builds the observation of image subject s from its
// host's stored image.vulnerabilities result r. The result is untrusted
// host output, parsed and bounded by dockerhost.ParseImageVulns. Only a
// scan of exactly s's digest counts; anything else is "not observed".
func trivyLocalObserve(r *executions.LastResultRow, s vulnstore.Subject, now time.Time) trivyLocalView {
	v := trivyLocalView{
		Observer: TrivyLocalObserver,
		Label:    trivyLocalLabel,
		Status:   vulnLabel{trivyNotObserved, classUnknown},
		Partial:  "Host-local scan with the host's own vulnerability database: counts plus the top entries only, no packages or ecosystems.",
	}
	if r == nil || len(r.Result) == 0 {
		return v
	}
	p, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil || p.Phase != "done" || p.Image == "" || imageDigestOf(p.Image) != s.ImageDigest {
		return v
	}
	v.Observed = true
	v.Image = p.Image
	v.Platform = p.Platform
	v.Scanner = p.Trivy
	if p.DBAgeH != nil {
		v.DBAge = fmt.Sprintf("%d h", *p.DBAgeH)
	}
	v.Cached = p.Cached
	if !r.FinishedAt.IsZero() {
		v.ObservedAt = vulnTime(r.FinishedAt)
	}
	switch {
	case p.Status == dockerhost.VulnsStale:
		v.Status = vulnLabel{"stale (host database old)", classUnknown}
		return v
	case p.Status != dockerhost.VulnsOK:
		v.Status = vulnLabel{"unknown (" + p.Status + ")", classUnknown}
		return v
	}
	v.Counted = true
	for _, sev := range trivySeverities {
		v.Counts = append(v.Counts, trivyLocalCount{Severity: sev, Count: p.Severity[sev]})
	}
	v.Total, v.Targets = p.Total, p.Targets
	for _, tv := range p.Top {
		v.Top = append(v.Top, trivyLocalVuln{ID: tv.ID, Severity: tv.Severity, Fixed: tv.Fixed, Hermes: vulnLabel{"Hermes findings unavailable", classUnknown}})
	}
	if len(p.Top) < p.Total {
		v.Partial += fmt.Sprintf(" Showing top %d of %d.", len(p.Top), p.Total)
	}
	crit, high := p.Severity["CRITICAL"], p.Severity["HIGH"]
	counts := fmt.Sprintf("%d critical · %d high · %d medium · %d low", crit, high, p.Severity["MEDIUM"], p.Severity["LOW"])
	switch {
	case isStale(r.FinishedAt, now, trivyStaleAfter):
		v.Status = vulnLabel{"stale since " + v.ObservedAt + " · " + counts, classUnknown}
	case crit > 0:
		v.Status = vulnLabel{counts, classCritical}
	case high > 0:
		v.Status = vulnLabel{counts, classWarning}
	default:
		// A partial scan without critical or high entries is not a
		// clean bill of health: never green.
		v.Status = vulnLabel{fmt.Sprintf("%d found, none critical or high (partial)", p.Total), classUnknown}
	}
	return v
}

// trivyBadge selects the badge source: Hermes when hermes is set (a fresh
// complete Hermes run covers the image), otherwise the trivy-local
// observation, otherwise "not observed".
func trivyBadge(hermes *vulnLabel, t trivyLocalView) vulnImageBadge {
	switch {
	case hermes != nil:
		return vulnImageBadge{Source: "hermes", Observer: hermesObserverLabel, Status: *hermes}
	case t.Observed:
		return vulnImageBadge{Source: TrivyLocalObserver, Observer: trivyLocalLabel, Status: t.Status}
	}
	return vulnImageBadge{Status: vulnLabel{trivyNotObserved, classUnknown}}
}

// trivyLocalFor reads the stored P1-30 result of image subject s and
// builds its panel without any Hermes data (store not read yet or
// unavailable). Only the stored action results are read.
func (h *Handler) trivyLocalFor(ctx context.Context, s vulnstore.Subject) *trivyLocalPanel {
	var r *executions.LastResultRow
	if h.operations != nil {
		m, err := h.operations.LastResults(ctx, trivyLocalAction)
		if err != nil {
			h.log.Warn("vulnerabilities: trivy-local results unavailable", "error", err)
		} else if row, ok := m[s.ID]; ok {
			r = &row
		}
	}
	t := trivyLocalObserve(r, s, h.clockNow())
	return &trivyLocalPanel{Trivy: t, Badge: trivyBadge(nil, t), HermesUnavailable: true}
}

// besideHermes puts the Hermes findings of the image (rows, read-only)
// beside the observation and selects the badge source. The observation
// itself is not changed by any Hermes state, and no Hermes state is
// changed by it. A nil panel (not an image subject) is a no-op.
func (p *trivyLocalPanel) besideHermes(rows []VulnRow, st VulnSubjectStatus, group *vulnSubjectGroup, now time.Time) {
	if p == nil {
		return
	}
	p.HermesUnavailable = false
	byID := make(map[string]vulnLabel, len(rows))
	for _, row := range rows {
		if _, ok := byID[row.Finding.Record.Vuln.ID]; !ok {
			byID[row.Finding.Record.Vuln.ID] = vulnStateText(row.Finding)
		}
	}
	for i := range p.Trivy.Top {
		l, ok := byID[p.Trivy.Top[i].ID]
		if !ok {
			p.Trivy.Top[i].Hermes = vulnLabel{"no Hermes finding", classUnknown}
			continue
		}
		p.Trivy.Top[i].Hermes = vulnLabel{"Hermes: " + l.Text, l.Class}
	}
	var hermes *vulnLabel
	if group != nil && !st.LastComplete.IsZero() && now.Sub(st.LastComplete) <= vulnstore.StaleAfter {
		hermes = &group.Status
	}
	p.Badge = trivyBadge(hermes, p.Trivy)
}
