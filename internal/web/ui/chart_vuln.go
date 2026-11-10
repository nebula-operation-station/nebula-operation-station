// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Org-chart vulnerability badges (ADR 0011 D8, plan VU-12). They reuse the
// places of P1-30 and P1-34: the host box extra lines (one "Vulns" line for
// the host subject) and the CVE line of the scanned image, plus the box
// border colour through the line states. The status comes from the same
// per-subject summary as the vulnerabilities list (summarizeSubjects,
// subjectStatus), so the chart and the pages never disagree on what is
// clean. Not assessed, stale, a feed issue, an incomplete read or a failed
// read are labelled and never green; every line names its observer.

const (
	// LineVuln is the Hermes findings line of a host box (and of a PVE
	// guest box linked to a managed host).
	LineVuln = "vuln"
	// maxChartImageLines bounds the Hermes image lines of one host box;
	// the rest are summed up in one "more images" line.
	maxChartImageLines = 4
	// observerHermes and observerTrivy are the observer labels (D2): the
	// finding store holds only Hermes findings; the P1-30 counts are the
	// host-local, partial Trivy observation.
	observerHermes = "Hermes"
	observerTrivy  = "host Trivy, partial"
	// chartListIncomplete marks the image lines of a truncated read.
	chartListIncomplete = "list incomplete"
	// chartImageListURL lists every image subject in every state.
	chartImageListURL = "/vulnerabilities?view=subject&kind=image&state=all"
)

// imageRefDigestRe matches the digest of a digest reference
// ("repo@sha256:<64 lowercase hex>").
var imageRefDigestRe = regexp.MustCompile(`@(sha256:[0-9a-f]{64})$`)

// digestOfImageRef returns the "sha256:<hex>" digest of a digest
// reference, "" when ref is not one.
func digestOfImageRef(ref string) string {
	m := imageRefDigestRe.FindStringSubmatch(ref)
	if m == nil {
		return ""
	}
	return m[1]
}

// chartVulnIndex is the per-page view of the finding store for the org
// chart, read once per page. A nil index means no backend is configured:
// the vuln lines are hidden like any other absent source.
type chartVulnIndex struct {
	// failed: the read failed; every host shows "unknown (read failed)".
	failed        bool
	now           time.Time
	ctx           vulnContext
	sums          map[string]*subjectSummary
	pageFeedIssue bool
	truncated     bool
	// images are the image subjects per host ID, sorted by digest.
	images map[string][]vulnstore.Subject
}

// loadChartVulns reads the findings for the chart. A nil backend yields a
// nil index; a read error an index marked failed (the detail goes to the
// log only).
func (h *Handler) loadChartVulns(ctx context.Context) *chartVulnIndex {
	if h.vuln == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, vulnCallTimeout)
	defer cancel()
	page, err := h.vuln.VulnFindings(ctx, VulnQuery{Limit: MaxVulnRows})
	if err != nil {
		h.log.Warn("org chart: vulnerability findings unavailable", "error", err)
	}
	return newChartVulnIndex(page, err, h.clockNow())
}

// newChartVulnIndex builds the index from a findings page; err marks the
// read as failed.
func newChartVulnIndex(page VulnPage, err error, now time.Time) *chartVulnIndex {
	if err != nil {
		return &chartVulnIndex{failed: true, now: now}
	}
	page.Feeds = withUnknownFeeds(page.Feeds, page.Rows)
	c := newVulnContext(now, page.Subjects, page.Feeds)
	views := make([]vulnFindingView, len(page.Rows))
	for i, row := range page.Rows {
		views[i] = c.view(row)
	}
	sums, order, pageFeedIssue := summarizeSubjects(c, page, views, vulnFilter{State: vulnDefaultState})
	x := &chartVulnIndex{now: now, ctx: c, sums: sums, pageFeedIssue: pageFeedIssue, truncated: page.Truncated, images: map[string][]vulnstore.Subject{}}
	for _, k := range order {
		s := sums[k].subject
		if s.Kind == vulnfinding.SubjectImage {
			x.images[s.ID] = append(x.images[s.ID], s)
		}
	}
	for id := range x.images {
		imgs := x.images[id]
		sort.Slice(imgs, func(i, j int) bool { return imgs[i].ImageDigest < imgs[j].ImageDigest })
	}
	return x
}

// prioTierName names a stored D7 tier with the vulnprio tier names.
func prioTierName(t vulnstore.Tier) vulnprio.Tier {
	switch t {
	case vulnstore.TierCritical:
		return vulnprio.TierCritical
	case vulnstore.TierHigh:
		return vulnprio.TierHigh
	case vulnstore.TierMedium:
		return vulnprio.TierMedium
	case vulnstore.TierLow:
		return vulnprio.TierLow
	}
	return ""
}

// badge returns the status text, line state and hover title of one
// subject. The state is critical for a critical-tier open finding (also
// when the run is stale: a known critical finding is never hidden), stale
// for a stale run, unknown when not assessed or the read was incomplete,
// and ok only where subjectStatus says the subject is clean.
func (x *chartVulnIndex) badge(s vulnstore.Subject) (string, IndicatorState, string) {
	a, ok := x.sums[s.String()]
	if !ok {
		a = &subjectSummary{subject: s, st: x.ctx.subject(s)}
	}
	status := subjectStatus(a.g, a.st, a.feedIssue, x.pageFeedIssue, x.truncated, a.critical, x.now)
	runLabel, stale := subjectLabel(a.st, x.now)
	text := status.Text
	if stale && a.g.Open > 0 {
		// subjectStatus shows only the run age for a stale subject; the
		// badge keeps the open count beside it.
		n := strconv.Itoa(a.g.Open)
		if x.truncated {
			n = "at least " + n
		}
		text += " · " + n + " open"
	}
	if a.g.Open > 0 && a.top != vulnstore.TierUnknown {
		text += " · top " + string(prioTierName(a.top))
	}
	var state IndicatorState
	switch {
	case a.critical:
		state = StateCrit
	case stale && a.st.LastComplete.IsZero():
		state = StateUnknown
	case stale:
		state = StateStale
	case status.Class == classCritical:
		state = StateCrit
	case status.Class == classWarning:
		state = StateWarn
	case status.Class == classOK:
		state = StateOK
	default:
		state = StateUnknown
	}
	title := "observer " + observerHermes + " · " + runLabel.Text + " · priority " + vulnprio.FormulaVersion
	return text, state, title
}

// hostLines returns the Hermes line of a host box: one line for the host
// subject, linked to its vulnerabilities page. A nil index has none.
func (x *chartVulnIndex) hostLines(hostID string) []chartLine {
	if x == nil {
		return nil
	}
	if x.failed {
		return []chartLine{{Kind: LineVuln, Label: "Vulns", Text: observerHermes + " · unknown (read failed)",
			Title: "observer " + observerHermes + " · findings could not be read", State: StateUnknown, URL: "/vulnerabilities"}}
	}
	s := vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: hostID}
	text, state, title := x.badge(s)
	return []chartLine{{Kind: LineVuln, Label: "Vulns", Text: observerHermes + " · " + text, Title: title, State: state, URL: vulnSubjectURL(s)}}
}

// imageLine is the Hermes line of one image subject in the CVE place;
// display names the image. On a truncated read it says the list is
// incomplete.
func (x *chartVulnIndex) imageLine(s vulnstore.Subject, display string) chartLine {
	text, state, title := x.badge(s)
	if x.truncated && !strings.Contains(text, labelIncomplete) {
		// The badge already says "at least" for counts; a stale run's
		// label does not, and either way the read missed findings.
		text += " · " + chartListIncomplete
	}
	return chartLine{Kind: LineCVE, Label: "CVE", Text: observerHermes + " · " + display + " · " + text, Title: title, State: state, URL: vulnSubjectURL(s)}
}

// freshImage returns the host's image subject with the given digest when
// a fresh Hermes run covers it and the findings read is complete (D2 badge
// source selection). A truncated read may miss the image's findings, so it
// never replaces the Trivy counts: a known critical count stays visible.
func (x *chartVulnIndex) freshImage(hostID, digest string) (vulnstore.Subject, bool) {
	if x == nil || x.failed || x.truncated || digest == "" {
		return vulnstore.Subject{}, false
	}
	s := vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: hostID, ImageDigest: digest}
	if _, stale := subjectLabel(x.ctx.subject(s), x.now); stale {
		return vulnstore.Subject{}, false
	}
	return s, true
}

// knownImage returns the host's image subject with the given digest when
// the Hermes read lists it (in any run state: fresh, stale or not
// assessed).
func (x *chartVulnIndex) knownImage(hostID, digest string) (vulnstore.Subject, bool) {
	if x == nil || x.failed || digest == "" {
		return vulnstore.Subject{}, false
	}
	for _, s := range x.images[hostID] {
		if s.ImageDigest == digest {
			return s, true
		}
	}
	return vulnstore.Subject{}, false
}

// imageLines returns the Hermes lines of the host's image subjects other
// than exclude (the image shown in the P1-30 place), at most
// maxChartImageLines plus one line summing up the rest with their worst
// state. On a truncated read the image subjects of the host may be
// incomplete: each line (imageLine) and the summing line say so, and a
// host with any Hermes image line here gets the summing line even with
// nothing hidden.
func (x *chartVulnIndex) imageLines(hostID, exclude string) []chartLine {
	if x == nil || x.failed {
		return nil
	}
	var lines []chartLine
	more, worst := 0, StateOK
	for _, s := range x.images[hostID] {
		if s.ImageDigest == exclude {
			continue
		}
		if len(lines) < maxChartImageLines {
			lines = append(lines, x.imageLine(s, shortDigest(s.ImageDigest)))
			continue
		}
		_, st, _ := x.badge(s)
		worst = worstState(worst, st)
		more++
	}
	text := ""
	switch {
	case x.truncated && more > 0:
		text = "at least " + strconv.Itoa(more) + " more images · " + chartListIncomplete
		worst = worstState(worst, StateUnknown)
	case x.truncated && len(lines) > 0:
		text = "image " + chartListIncomplete
		worst = StateUnknown
	case more > 0:
		text = strconv.Itoa(more) + " more images"
	}
	if text != "" {
		lines = append(lines, chartLine{Kind: LineCVE, Label: "CVE", Text: observerHermes + " · " + text,
			Title: "observer " + observerHermes, State: worst, URL: chartImageListURL})
	}
	return lines
}

// shortDigest shortens "sha256:<hex>" to the first 12 hex digits.
func shortDigest(d string) string {
	if hex, ok := strings.CutPrefix(d, "sha256:"); ok && len(hex) > 12 {
		return "sha256:" + hex[:12]
	}
	return d
}

// cvePlaceLines fills the P1-30 CVE place of a host box (D2): the Hermes
// findings of the scanned image when a fresh Hermes run covers it and the
// findings read is complete (freshImage), otherwise the P1-30 counts
// labelled "host Trivy, partial"; then the host's other Hermes image
// subjects. When Hermes knows the scanned image but its run is stale or
// not assessed, or the read was truncated, the Hermes line of that image
// stays next to the Trivy line, labelled by its badge, and the worst line
// state drives the box border: neither a known critical Hermes finding
// nor a known critical Trivy count is hidden behind the other.
func cvePlaceLines(res chartResults, hostID string, now time.Time) []chartLine {
	trivy, ref := cveLine(rowFor(res.vulns, hostID), now, indicatorStaleAfter)
	digest := digestOfImageRef(ref)
	var lines []chartLine
	switch s, fresh := res.hermes.freshImage(hostID, digest); {
	case len(trivy) > 0 && fresh:
		lines = append(lines, res.hermes.imageLine(s, shortImageRef(ref)))
	case len(trivy) > 0:
		for _, l := range trivy {
			l.Text += " · " + observerTrivy
			lines = append(lines, l)
		}
		if k, ok := res.hermes.knownImage(hostID, digest); ok {
			lines = append(lines, res.hermes.imageLine(k, shortImageRef(ref)))
		}
	default:
		digest = "" // no P1-30 line: every Hermes image shows below
	}
	return append(lines, res.hermes.imageLines(hostID, digest)...)
}
