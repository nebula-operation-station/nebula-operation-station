// SPDX-License-Identifier: AGPL-3.0-or-later

// Vulnerabilities pages (ADR 0011 D6, D8; plan VU-11): the findings list
// by CVE and by subject with filters, the per-CVE page, the per-subject
// page (the subject's "Vulnerabilities" tab), the finding page with its
// held closures, the feed banners and the high-water mark reset page.
//
// Every value from Hermes and the feeds (IDs, versions, package names,
// assessment text, snapshot IDs) is untrusted text: it is rendered by
// html/template as text only, never as HTML, Markdown or a link. The only
// links are NOS-built paths from validated IDs.
//
// Staleness is never shown as green: a subject without a complete run is
// "not assessed", one whose last complete run is older than
// vulnstore.StaleAfter is "stale since …", and a finding resting on a feed
// that is stale, behind its high-water mark, dated in the future, undated,
// unknown or on probation carries that label. "Closed by Hermes, not
// confirmed by NOS" has its own label and filter and keeps the subject off
// green.
//
// The state forms (accept risk, false positive, held-closure confirm and
// discard, mark reset) are rendered for the maintainer (admin) only and
// every submission needs a fresh WebAuthn assertion (Q4, decided
// 2026-11-09); see vuln_decide.go.
package ui

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Limits of the vulnerabilities pages.
const (
	// vulnCallTimeout bounds one backend call while rendering a page.
	vulnCallTimeout = 5 * time.Second
	// MaxVulnRows is the most findings one page asks the backend for; a
	// larger result is shown as truncated, never silently cut.
	MaxVulnRows = 5000
	// maxVulnText bounds any untrusted string the pages show; the record
	// validation already bounds them, this is the renderer's own cap.
	maxVulnText = vulnfinding.MaxAssessmentBytes
)

// ErrVulnAssertionRefused is returned by the backend when the WebAuthn
// assertion of a decision is missing, stale, replayed or does not verify.
var ErrVulnAssertionRefused = errors.New("security key assertion refused")

// VulnRow is one stored finding with its current D7 tier.
type VulnRow struct {
	Finding vulnstore.Finding
	// Tier is the current D7 tier; TierUnknown when not computed.
	Tier vulnstore.Tier
}

// VulnSubjectStatus is the D6 assessment status of one subject.
type VulnSubjectStatus struct {
	Subject vulnstore.Subject
	// Name is NOS's display name of the subject (untrusted host data,
	// rendered as text); empty shows the subject ID.
	Name string
	// LastComplete is the end of the last complete run that covered the
	// subject; zero means no complete run did ("not assessed").
	LastComplete time.Time
}

// VulnFeedStatus is NOS's view of one feed source (D4, D5, D6).
type VulnFeedStatus struct {
	SourceID string
	// Listed: the source is on NOS's fixed source list.
	Listed bool
	// Stale: past its maximum snapshot age, or undated.
	Stale bool
	// SnapshotDate is the content date of the last accepted snapshot;
	// zero when unknown or undated.
	SnapshotDate time.Time
	// LastVerdict is NOS's verdict on the source in the latest run that
	// named it; empty when no run named it.
	LastVerdict vulnstore.SourceStatus
	// Probation after a mark reset, with the pre-reset mark it must pass.
	Probation    bool
	PreResetDate time.Time
	PreResetSeq  *int64
}

// VulnQuery scopes a findings read.
type VulnQuery struct {
	// VulnID limits the read to one vulnerability ID; empty for all.
	VulnID string
	// Subject limits the read to one subject; nil for all.
	Subject *vulnstore.Subject
	// Limit is the most rows to return (MaxVulnRows).
	Limit int
}

// VulnPage is the result of a findings read.
type VulnPage struct {
	Rows []VulnRow
	// Truncated: more rows matched than Limit.
	Truncated bool
	// Subjects are the statuses of every subject in scope, including
	// subjects without findings.
	Subjects []VulnSubjectStatus
	// Feeds are the feed sources on NOS's list plus unknown sources
	// findings rest on.
	Feeds []VulnFeedStatus
	// LastComplete is the end of the last complete run of any subject;
	// zero when Hermes never completed a run.
	LastComplete time.Time
}

// VulnHold is a held closure with NOS's view of the version.
type VulnHold struct {
	Hold vulnstore.Hold
	// NOSVersion is NOS's current basis version of the component; empty
	// when NOS does not know it.
	NOSVersion string
	// Contradicted: NOS's inventory still shows the component below the
	// episode fixed version.
	Contradicted bool
}

// VulnFindingDetail is one finding with everything its page shows.
type VulnFindingDetail struct {
	Row     VulnRow
	Subject VulnSubjectStatus
	Feeds   []VulnFeedStatus
	Holds   []VulnHold
	// LastComplete as in VulnPage.
	LastComplete time.Time
}

// VulnChallenge is the WebAuthn request a decision must be signed with.
type VulnChallenge struct {
	// ID identifies the challenge; it is single use.
	ID string
	// Options is the PublicKeyCredentialRequestOptions JSON.
	Options []byte
}

// VulnFindings is the backend of the vulnerabilities pages. The server
// implements it over vulnstore, the inventory and the executor's WebAuthn
// verification; it re-checks every decision rule the UI checks.
type VulnFindings interface {
	// VulnFindings reads findings in scope.
	VulnFindings(ctx context.Context, q VulnQuery) (VulnPage, error)
	// VulnFinding reads one finding; vulnstore.ErrFindingNotFound if absent.
	VulnFinding(ctx context.Context, key vulnfinding.Key) (VulnFindingDetail, error)
	// VulnMarkResetCandidate returns the mark reset view of a listed
	// source; vulnstore.ErrResetRefused for a source not on the list.
	VulnMarkResetCandidate(ctx context.Context, sourceID string) (vulnstore.MarkResetView, error)
	// VulnMaintainer reports whether user is the maintainer (admin).
	VulnMaintainer(ctx context.Context, user string) (bool, error)
	// BeginVulnDecision returns a fresh WebAuthn challenge bound to the
	// decision's digest and user.
	BeginVulnDecision(ctx context.Context, user string, d VulnDecision) (VulnChallenge, error)
	// CommitVulnDecision verifies the assertion against the challenge,
	// the user and the decision digest, applies the decision and audits it.
	// ErrVulnAssertionRefused when the assertion does not verify.
	CommitVulnDecision(ctx context.Context, user, challengeID string, d VulnDecision, assertion []byte) error
}

// vulnIDRe is the D2 vuln_id pattern.
var vulnIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{1,63}$`)

// vulnSourceIDRe is the D5 source ID pattern.
var vulnSourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

// vulnSubjectIDRe and vulnDigestRe are the subject patterns of vulnstore.
var (
	vulnSubjectIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	vulnDigestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// parseVulnKey decodes a finding key from its hex form.
func parseVulnKey(s string) (vulnfinding.Key, bool) {
	var k vulnfinding.Key
	if len(s) != 2*len(k) {
		return k, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || strings.ToLower(s) != s {
		return k, false
	}
	copy(k[:], b)
	return k, true
}

// vulnText makes an untrusted string safe to show as text: invalid UTF-8
// and non-printable runes (control, bidi and format characters) become
// U+FFFD, except newline and tab when multiline; the result is capped.
func vulnText(s string, multiline bool) string {
	if len(s) > maxVulnText {
		s = s[:maxVulnText]
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteRune(unicode.ReplacementChar)
		case multiline && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case !unicode.IsPrint(r) && r != ' ':
			b.WriteRune(unicode.ReplacementChar)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// vulnLabel is a status label with its badge class.
type vulnLabel struct {
	Text  string
	Class string
}

// Labels, badge classes, layouts and filter values. classOK (green) is
// used in one place only: subjectStatus of a fresh, clean subject.
const (
	labelNotAssessed = "not assessed"
	labelUnconfirmed = "closed by Hermes, not confirmed by NOS"
	labelNotChecked  = "version reported by Hermes, not checked by NOS"
	classUnknown     = "badge--unknown"
	classWarning     = "badge--warning"
	classCritical    = "badge--critical"
	classOK          = "badge--ok"
	vulnTimeLayout   = "2006-01-02 15:04 UTC"
	vulnDateLayout   = "2006-01-02"
	vulnStateAll     = "all"
	vulnStateUnconf  = "unconfirmed"
	vulnViewSubject  = "subject"
	vulnFilterStale  = "stale"
	vulnFilterKEV    = "yes"
	vulnDefaultState = string(vulnstore.StateOpen)
)

func vulnTime(t time.Time) string { return t.UTC().Format(vulnTimeLayout) }

// subjectLabel is the D6 run-age label of a subject; stale reports
// whether it is not assessed or stale.
func subjectLabel(s VulnSubjectStatus, now time.Time) (vulnLabel, bool) {
	if s.LastComplete.IsZero() {
		return vulnLabel{labelNotAssessed, classUnknown}, true
	}
	if now.Sub(s.LastComplete) > vulnstore.StaleAfter {
		return vulnLabel{"stale since " + vulnTime(s.LastComplete), classWarning}, true
	}
	return vulnLabel{"assessed " + vulnTime(s.LastComplete), ""}, false
}

// feedLabels returns the feed labels of one source; empty when the source
// is fine.
func feedLabels(f VulnFeedStatus) []vulnLabel {
	id := vulnText(f.SourceID, false)
	var out []vulnLabel
	if !f.Listed {
		out = append(out, vulnLabel{"feed " + id + " not on NOS's source list", classWarning})
	}
	switch f.LastVerdict {
	case vulnstore.SourceRegressed:
		out = append(out, vulnLabel{"feed " + id + " behind its high-water mark", classWarning})
	case vulnstore.SourceInvalid:
		out = append(out, vulnLabel{"feed " + id + " dated in the future", classWarning})
	case vulnstore.SourceUndated:
		out = append(out, vulnLabel{"feed " + id + " undated", classWarning})
	}
	if f.Stale {
		out = append(out, vulnLabel{"feed " + id + " stale", classWarning})
	}
	if f.Probation {
		out = append(out, vulnLabel{"feed " + id + " on probation after a mark reset", classWarning})
	}
	return out
}

// vulnTierName names a tier.
func vulnTierName(t vulnstore.Tier) (string, string) {
	switch t {
	case vulnstore.TierCritical:
		return "critical", classCritical
	case vulnstore.TierHigh:
		return "high", classCritical
	case vulnstore.TierMedium:
		return "medium", classWarning
	case vulnstore.TierLow:
		return "low", classWarning
	}
	return "unknown", classUnknown
}

// vulnStateText names a D6 state as the pages show it.
func vulnStateText(f vulnstore.Finding) vulnLabel {
	switch f.State {
	case vulnstore.StateOpen:
		return vulnLabel{"open", classCritical}
	case vulnstore.StateAcceptedRisk:
		return vulnLabel{"accepted risk", classWarning}
	case vulnstore.StateFalsePositive:
		return vulnLabel{"false positive", classUnknown}
	case vulnstore.StateFixed:
		switch f.ClosedBy {
		case vulnstore.ClosedByHermesUnconfirmed:
			return vulnLabel{labelUnconfirmed, classWarning}
		case vulnstore.ClosedByNOSInventory:
			return vulnLabel{"fixed (confirmed by NOS inventory)", classUnknown}
		case vulnstore.ClosedBySubjectRemoved:
			return vulnLabel{"fixed (subject removed)", classUnknown}
		case vulnstore.ClosedByAdminConfirmed:
			return vulnLabel{"fixed (confirmed by the maintainer)", classUnknown}
		}
		return vulnLabel{"fixed", classUnknown}
	}
	return vulnLabel{"unknown state", classUnknown}
}

// vulnSubjectURL is the NOS-built path of a subject's page.
func vulnSubjectURL(s vulnstore.Subject) string {
	u := "/vulnerabilities/subject/" + url.PathEscape(string(s.Kind)) + "/" + url.PathEscape(s.ID)
	if s.Kind == vulnfinding.SubjectImage {
		u += "?digest=" + url.QueryEscape(s.ImageDigest)
	}
	return u
}

// vulnCVEURL is the NOS-built path of a vulnerability's page; empty for
// an ID failing the pattern.
func vulnCVEURL(id string) string {
	if !vulnIDRe.MatchString(id) {
		return ""
	}
	return "/vulnerabilities/cve/" + url.PathEscape(id)
}

// vulnFindingView is one finding as the templates show it. Every string
// field holding Hermes or feed data went through vulnText.
type vulnFindingView struct {
	Key         string
	URL         string
	VulnID      string
	VulnURL     string
	Aliases     string
	SubjectKind string
	SubjectID   string
	SubjectName string
	SubjectURL  string
	Ecosystem   string
	Component   string
	Version     string
	Fix         string
	State       vulnLabel
	Tier        vulnLabel
	KEV         string
	CVSS        string
	EPSS        string
	Labels      []vulnLabel
	Hints       []string
	Assessment  string
	Sources     []string
	Matcher     string
	Human       []string
	Open        bool
	Unconfirmed bool
	// Stale: not assessed, stale, or resting on a feed with an issue.
	Stale bool
	// HumanForms: the finding is open or in a human state the maintainer
	// can set again (accept risk, false positive).
	HumanForms bool
}

// vulnContext indexes subjects and feeds for building views.
type vulnContext struct {
	now      time.Time
	subjects map[string]VulnSubjectStatus
	feeds    map[string]VulnFeedStatus
}

func newVulnContext(now time.Time, subjects []VulnSubjectStatus, feeds []VulnFeedStatus) vulnContext {
	c := vulnContext{now: now, subjects: map[string]VulnSubjectStatus{}, feeds: map[string]VulnFeedStatus{}}
	for _, s := range subjects {
		c.subjects[s.Subject.String()] = s
	}
	for _, f := range feeds {
		c.feeds[f.SourceID] = f
	}
	return c
}

func (c vulnContext) subject(s vulnstore.Subject) VulnSubjectStatus {
	if st, ok := c.subjects[s.String()]; ok {
		return st
	}
	// No status known: not assessed (never green).
	return VulnSubjectStatus{Subject: s}
}

func (c vulnContext) view(row VulnRow) vulnFindingView {
	f := row.Finding
	r := f.Record
	v := vulnFindingView{
		Key:         f.Key.String(),
		URL:         "/vulnerabilities/f/" + f.Key.String(),
		VulnID:      vulnText(r.Vuln.ID, false),
		VulnURL:     vulnCVEURL(r.Vuln.ID),
		Aliases:     vulnText(strings.Join(r.Vuln.Aliases, ", "), false),
		SubjectKind: vulnText(string(f.Subject.Kind), false),
		SubjectID:   vulnText(f.Subject.ID, false),
		SubjectURL:  vulnSubjectURL(f.Subject),
		Ecosystem:   vulnText(r.Ecosystem, false),
		State:       vulnStateText(f),
		Assessment:  vulnText(r.Assessment.Text, true),
		Matcher:     vulnText(r.Evidence.MatcherVersion, false),
		Open:        f.State == vulnstore.StateOpen,
		Unconfirmed: f.State == vulnstore.StateFixed && f.ClosedBy == vulnstore.ClosedByHermesUnconfirmed,
	}
	v.HumanForms = f.State != vulnstore.StateFixed
	st := c.subject(f.Subject)
	v.SubjectName = vulnText(st.Name, false)
	if v.SubjectName == "" {
		v.SubjectName = v.SubjectID
	}
	if r.Component.Model != "" {
		v.Component = vulnText(r.Component.Model, false)
		v.Version = vulnText(r.Component.Firmware, false)
	} else {
		v.Component = vulnText(r.Component.SourcePackage, false)
		v.Version = vulnText(r.Component.SourceVersion, false)
	}
	switch r.Fix.State {
	case vulnfinding.FixFixed:
		v.Fix = "fixed in " + vulnText(r.Fix.Version, false)
	case vulnfinding.FixNoFixYet:
		v.Fix = "no fix yet"
	case vulnfinding.FixWontFix:
		v.Fix = "won't fix"
	case vulnfinding.FixNotAffected:
		v.Fix = "not affected"
	default:
		v.Fix = "unknown"
	}
	name, class := vulnTierName(row.Tier)
	v.Tier = vulnLabel{name, class}
	if r.Scores.KEV != nil {
		v.KEV = "KEV since " + vulnText(r.Scores.KEV.DateAdded, false)
	} else if f.EpisodeKEV() {
		v.KEV = "KEV-listed earlier in this episode (" + vulnText(f.EpisodeKEVDate, false) + ")"
	}
	if s := r.Scores.CVSS; s != nil {
		v.CVSS = strconv.FormatFloat(s.BaseScore, 'f', 1, 64) + " (CVSS " + vulnText(s.Version, false) + ", " + vulnText(string(s.Source), false) + ")"
	} else {
		v.CVSS = "unknown"
	}
	if e := r.Scores.EPSS; e != nil {
		v.EPSS = strconv.FormatFloat(e.Probability, 'f', 3, 64) + " (" + vulnText(e.Date, false) + ")"
	}
	if r.Assessment.BackportChecked {
		v.Hints = append(v.Hints, "backport checked")
	}
	if r.Assessment.LikelyFalsePositive {
		v.Hints = append(v.Hints, "likely false positive")
	}
	if r.Assessment.ExploitPublic {
		v.Hints = append(v.Hints, "exploit public")
	}
	for _, b := range r.Evidence.BasisSources {
		v.Sources = append(v.Sources, vulnText(b.SourceID, false)+" "+vulnText(b.SnapshotID, false)+" ("+vulnText(string(b.Integrity), false)+")")
	}
	if h := f.Human; h != nil {
		v.Human = append(v.Human, "by "+vulnText(h.By, false)+" at "+vulnTime(h.At))
		if h.Category != "" {
			v.Human = append(v.Human, "category "+vulnText(h.Category, false))
		}
		if !h.Expires.IsZero() {
			v.Human = append(v.Human, "expires "+vulnTime(h.Expires))
		}
		if h.BasisVersion != "" {
			v.Human = append(v.Human, "bound to version "+vulnText(h.BasisVersion, false))
		}
		v.Human = append(v.Human, "reason: "+vulnText(h.Reason, true))
	}
	if f.State == vulnstore.StateFixed && f.ClosedBy == vulnstore.ClosedByAdminConfirmed {
		v.Human = append(v.Human, "confirmed by "+vulnText(f.ClosedAdmin, false)+": "+vulnText(f.ClosedReason, true))
	}

	// Labels: run age, feeds, closure source, version check.
	sl, stale := subjectLabel(st, c.now)
	if stale {
		v.Labels = append(v.Labels, sl)
		v.Stale = true
	}
	seen := map[string]bool{}
	for _, b := range r.Evidence.BasisSources {
		if seen[b.SourceID] {
			continue
		}
		seen[b.SourceID] = true
		fs, ok := c.feeds[b.SourceID]
		if !ok {
			fs = VulnFeedStatus{SourceID: b.SourceID}
		}
		if ls := feedLabels(fs); len(ls) > 0 {
			v.Labels = append(v.Labels, ls...)
			v.Stale = true
		}
	}
	if v.Unconfirmed {
		v.Labels = append(v.Labels, vulnLabel{labelUnconfirmed, classWarning})
	}
	if !f.NOSChecked {
		v.Labels = append(v.Labels, vulnLabel{labelNotChecked, classUnknown})
	}
	return v
}

// vulnFilter is the list filter (D8: tier, KEV, state, subject kind,
// stale). Unknown values fall back to the default.
type vulnFilter struct {
	View  string
	Tier  string
	KEV   string
	State string
	Kind  string
	Stale string
	// Digest keeps an image subject's digest in the filter form.
	Digest string
}

func parseVulnFilter(q url.Values) vulnFilter {
	f := vulnFilter{State: vulnDefaultState}
	if q.Get("view") == vulnViewSubject {
		f.View = vulnViewSubject
	}
	switch t := q.Get("tier"); t {
	case "critical", "high", "medium", "low", "unknown":
		f.Tier = t
	}
	if q.Get("kev") == vulnFilterKEV {
		f.KEV = vulnFilterKEV
	}
	switch s := q.Get("state"); s {
	case string(vulnstore.StateOpen), string(vulnstore.StateFixed), string(vulnstore.StateAcceptedRisk),
		string(vulnstore.StateFalsePositive), vulnStateUnconf, vulnStateAll:
		f.State = s
	}
	switch k := q.Get("kind"); k {
	case string(vulnfinding.SubjectHost), string(vulnfinding.SubjectImage), string(vulnfinding.SubjectDevice):
		f.Kind = k
	}
	if q.Get("stale") == vulnFilterStale {
		f.Stale = vulnFilterStale
	}
	return f
}

func (fl vulnFilter) match(v vulnFindingView, row VulnRow) bool {
	f := row.Finding
	if fl.Tier != "" && v.Tier.Text != fl.Tier {
		return false
	}
	if fl.KEV == vulnFilterKEV && v.KEV == "" {
		return false
	}
	switch fl.State {
	case vulnStateAll:
	case vulnStateUnconf:
		if !v.Unconfirmed {
			return false
		}
	default:
		if string(f.State) != fl.State {
			return false
		}
	}
	if fl.Kind != "" && string(f.Subject.Kind) != fl.Kind {
		return false
	}
	if fl.Stale == vulnFilterStale && !v.Stale {
		return false
	}
	return true
}

// vulnCVEGroup is one row of the list by CVE.
type vulnCVEGroup struct {
	VulnID   string
	URL      string
	Subjects int
	Tier     vulnLabel
	tier     vulnstore.Tier
	KEV      bool
	Stale    bool
	States   []vulnLabel
}

// vulnSubjectGroup is one row of the list by subject.
type vulnSubjectGroup struct {
	Kind        string
	ID          string
	Name        string
	URL         string
	Status      vulnLabel
	Labels      []vulnLabel
	Open        int
	Unconfirmed int
	Shown       int
}

// vulnBanner is a page-wide notice.
type vulnBanner struct {
	Text string
	// ResetURL links the maintainer to the mark reset page.
	ResetURL string
}

// vulnPageData is the data of every vulnerabilities page.
type vulnPageData struct {
	Filter     vulnFilter
	Banners    []vulnBanner
	Truncated  bool
	Maintainer bool

	// List page.
	CVEs     []vulnCVEGroup
	Subjects []vulnSubjectGroup
	// Findings: the CVE page, the subject page and the finding page.
	Findings []vulnFindingView
	// CVE page.
	CVE string
	// Subject page.
	Subject *vulnSubjectGroup
	// Finding page.
	Finding *vulnFindingView
	Holds   []vulnHoldView
	// DefaultExpiry and MaxExpiry prefill and bound the accept-risk form.
	DefaultExpiry string
	MinExpiry     string
	MaxExpiry     string
	Categories    []string
	// Reset page.
	Reset *vulnResetView
	// Unavailable: the backend failed; the page says so (never "0").
	Unavailable bool
}

// vulnHoldView is a held closure as the finding page shows it.
type vulnHoldView struct {
	RunID        string
	RunSeq       int64
	Reason       string
	Created      string
	NOSVersion   string
	Fixed        string
	Contradicted bool
}

// vulnResetView is the mark reset page.
type vulnResetView struct {
	SourceID     string
	Mark         string
	Reported     string
	RunID        string
	LastAccepted string
	Probation    bool
	PreReset     string
	Possible     bool
}

func vulnMark(d time.Time, seq *int64) string {
	var parts []string
	if !d.IsZero() {
		parts = append(parts, "content date "+vulnTime(d))
	}
	if seq != nil {
		parts = append(parts, "sequence "+strconv.FormatInt(*seq, 10))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// maxUnknownFeedBanners bounds the banners for sources NOS does not list;
// findings name at most vulnfinding.MaxBasisSources each, but many
// findings could name many different unknown IDs.
const maxUnknownFeedBanners = 16

// withUnknownFeeds adds a not-listed status for every basis source of rows
// the backend reported no status for, so a finding never rests on a
// source without a label. At most maxUnknownFeedBanners are added.
func withUnknownFeeds(feeds []VulnFeedStatus, rows []VulnRow) []VulnFeedStatus {
	known := map[string]bool{}
	for _, f := range feeds {
		known[f.SourceID] = true
	}
	out := feeds
	added := 0
	for _, r := range rows {
		for _, b := range r.Finding.Record.Evidence.BasisSources {
			if known[b.SourceID] || added >= maxUnknownFeedBanners {
				continue
			}
			known[b.SourceID] = true
			out = append(out[:len(out):len(out)], VulnFeedStatus{SourceID: b.SourceID})
			added++
		}
	}
	return out
}

// feedBanners builds the page-wide feed and Hermes banners.
func feedBanners(feeds []VulnFeedStatus, lastComplete, now time.Time, maintainer bool) []vulnBanner {
	var out []vulnBanner
	if lastComplete.IsZero() {
		out = append(out, vulnBanner{Text: "No complete Hermes run yet: no subject is assessed."})
	} else if now.Sub(lastComplete) > vulnstore.StaleAfter {
		out = append(out, vulnBanner{Text: "Hermes offline: no complete run since " + vulnTime(lastComplete) + "; every finding is stale."})
	}
	sorted := append([]VulnFeedStatus(nil), feeds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SourceID < sorted[j].SourceID })
	for _, f := range sorted {
		id := vulnText(f.SourceID, false)
		if f.Stale {
			t := "Feed " + id + " stale"
			if !f.SnapshotDate.IsZero() {
				t += ": last accepted snapshot dated " + vulnTime(f.SnapshotDate)
			}
			out = append(out, vulnBanner{Text: t + ". Findings resting on it are not closed by runs."})
		}
		switch f.LastVerdict {
		case vulnstore.SourceRegressed:
			b := vulnBanner{Text: "Feed " + id + " behind its high-water mark in the latest run. Findings resting on it are not closed by that run."}
			if maintainer && f.Listed && vulnSourceIDRe.MatchString(f.SourceID) {
				b.ResetURL = "/vulnerabilities/feeds/" + url.PathEscape(f.SourceID) + "/reset"
			}
			out = append(out, b)
		case vulnstore.SourceInvalid:
			out = append(out, vulnBanner{Text: "Feed " + id + " dated in the future in the latest run. Findings resting on it are not closed by that run."})
		case vulnstore.SourceUndated:
			out = append(out, vulnBanner{Text: "Feed " + id + " undated: treated as stale."})
		}
		if f.Probation {
			out = append(out, vulnBanner{Text: "Feed " + id + " on probation after a mark reset until a run names it above the pre-reset mark (" + vulnMark(f.PreResetDate, f.PreResetSeq) + ")."})
		}
		if !f.Listed {
			out = append(out, vulnBanner{Text: "Feed " + id + " is not on NOS's source list; findings resting on it only raise values."})
		}
	}
	return out
}

// vulnEnabled answers 404 when no backend is configured.
func (h *Handler) vulnEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.vuln == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

// vulnMaintainer reports whether the request's user is the maintainer;
// an error counts as no.
func (h *Handler) vulnMaintainer(ctx context.Context, r *http.Request) bool {
	ok, err := h.vuln.VulnMaintainer(ctx, webUser(r))
	if err != nil {
		h.log.Error("vulnerabilities: maintainer check", "error", err)
		return false
	}
	return ok
}

func (h *Handler) renderVuln(w http.ResponseWriter, r *http.Request, title, content string, d *vulnPageData) {
	scripts := []string{"time.js"}
	if d.Maintainer {
		scripts = []string{"time.js", "webauthn.js", "vuln.js"}
	}
	h.render(w, r, pageData{Title: title, Active: "vulnerabilities", Content: content, Scripts: scripts, Vuln: d})
}

// handleVulnList serves GET /vulnerabilities.
func (h *Handler) handleVulnList(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	d := &vulnPageData{Filter: parseVulnFilter(r.URL.Query()), Maintainer: h.vulnMaintainer(ctx, r)}
	page, err := h.vuln.VulnFindings(ctx, VulnQuery{Limit: MaxVulnRows})
	if err != nil {
		h.log.Error("vulnerabilities: list", "error", err)
		d.Unavailable = true
		h.renderVuln(w, r, "Vulnerabilities", "vuln", d)
		return
	}
	now := h.clockNow()
	page.Feeds = withUnknownFeeds(page.Feeds, page.Rows)
	c := newVulnContext(now, page.Subjects, page.Feeds)
	d.Truncated = page.Truncated
	d.Banners = feedBanners(page.Feeds, page.LastComplete, now, d.Maintainer)
	views := make([]vulnFindingView, len(page.Rows))
	for i, row := range page.Rows {
		views[i] = c.view(row)
	}
	if d.Filter.View == vulnViewSubject {
		d.Subjects = groupBySubject(c, page, views, d.Filter)
	} else {
		d.CVEs = groupByCVE(page.Rows, views, d.Filter)
	}
	h.renderVuln(w, r, "Vulnerabilities", "vuln", d)
}

// groupByCVE builds the list by CVE: highest tier first, then ID.
func groupByCVE(rows []VulnRow, views []vulnFindingView, fl vulnFilter) []vulnCVEGroup {
	idx := map[string]int{}
	var out []vulnCVEGroup
	states := map[string]map[string]bool{}
	for i, row := range rows {
		v := views[i]
		if !fl.match(v, row) {
			continue
		}
		id := row.Finding.Record.Vuln.ID
		j, ok := idx[id]
		if !ok {
			j = len(out)
			idx[id] = j
			out = append(out, vulnCVEGroup{VulnID: v.VulnID, URL: v.VulnURL})
			states[id] = map[string]bool{}
		}
		g := &out[j]
		g.Subjects++
		if row.Tier > g.tier {
			g.tier = row.Tier
		}
		g.KEV = g.KEV || v.KEV != ""
		g.Stale = g.Stale || v.Stale
		if !states[id][v.State.Text] {
			states[id][v.State.Text] = true
			g.States = append(g.States, v.State)
		}
	}
	for i := range out {
		n, c := vulnTierName(out[i].tier)
		out[i].Tier = vulnLabel{n, c}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier > out[j].tier
		}
		return out[i].VulnID < out[j].VulnID
	})
	return out
}

// subjectStatus is the overall status of a subject. Green only when the
// subject is freshly assessed, has no open finding, no closure Hermes
// alone made and no feed issue on its findings.
func subjectStatus(g vulnSubjectGroup, st VulnSubjectStatus, feedIssue bool, critical bool, now time.Time) vulnLabel {
	if l, stale := subjectLabel(st, now); stale {
		return l
	}
	switch {
	case g.Open > 0 && critical:
		return vulnLabel{strconv.Itoa(g.Open) + " open, critical", classCritical}
	case g.Open > 0:
		return vulnLabel{strconv.Itoa(g.Open) + " open", classWarning}
	case g.Unconfirmed > 0:
		return vulnLabel{strconv.Itoa(g.Unconfirmed) + " " + labelUnconfirmed, classWarning}
	case feedIssue:
		return vulnLabel{"feed issue", classWarning}
	}
	return vulnLabel{"no open findings", classOK}
}

// groupBySubject builds the list by subject: every subject in scope, also
// those without findings (they show their run age, never "0 findings").
func groupBySubject(c vulnContext, page VulnPage, views []vulnFindingView, fl vulnFilter) []vulnSubjectGroup {
	type acc struct {
		g         vulnSubjectGroup
		st        VulnSubjectStatus
		feedIssue bool
		critical  bool
	}
	m := map[string]*acc{}
	var order []string
	add := func(s vulnstore.Subject) *acc {
		k := s.String()
		if a, ok := m[k]; ok {
			return a
		}
		st := c.subject(s)
		name := vulnText(st.Name, false)
		if name == "" {
			name = vulnText(s.ID, false)
		}
		a := &acc{st: st, g: vulnSubjectGroup{Kind: vulnText(string(s.Kind), false), ID: vulnText(s.ID, false), Name: name, URL: vulnSubjectURL(s)}}
		m[k] = a
		order = append(order, k)
		return a
	}
	for _, s := range page.Subjects {
		if fl.Kind != "" && string(s.Subject.Kind) != fl.Kind {
			continue
		}
		add(s.Subject)
	}
	for i, row := range page.Rows {
		f := row.Finding
		if fl.Kind != "" && string(f.Subject.Kind) != fl.Kind {
			continue
		}
		a := add(f.Subject)
		v := views[i]
		if v.Open {
			a.g.Open++
			if row.Tier == vulnstore.TierCritical {
				a.critical = true
			}
		}
		if v.Unconfirmed {
			a.g.Unconfirmed++
		}
		if f.State == vulnstore.StateOpen || v.Unconfirmed {
			for _, l := range v.Labels {
				if strings.HasPrefix(l.Text, "feed ") {
					a.feedIssue = true
				}
			}
		}
		if fl.match(v, row) {
			a.g.Shown++
		}
	}
	out := make([]vulnSubjectGroup, 0, len(order))
	for _, k := range order {
		a := m[k]
		a.g.Status = subjectStatus(a.g, a.st, a.feedIssue, a.critical, c.now)
		if l, stale := subjectLabel(a.st, c.now); !stale {
			a.g.Labels = append(a.g.Labels, l)
		}
		if fl.Stale == vulnFilterStale {
			if _, stale := subjectLabel(a.st, c.now); !stale && !a.feedIssue {
				continue
			}
		}
		out = append(out, a.g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// handleVulnCVE serves GET /vulnerabilities/cve/{id}.
func (h *Handler) handleVulnCVE(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	id := r.PathValue("id")
	if !vulnIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	d := &vulnPageData{Filter: vulnFilter{State: vulnStateAll}, CVE: id, Maintainer: h.vulnMaintainer(ctx, r)}
	page, err := h.vuln.VulnFindings(ctx, VulnQuery{VulnID: id, Limit: MaxVulnRows})
	if err != nil {
		h.log.Error("vulnerabilities: cve", "error", err)
		d.Unavailable = true
		h.renderVuln(w, r, id, "vuln_cve", d)
		return
	}
	now := h.clockNow()
	page.Feeds = withUnknownFeeds(page.Feeds, page.Rows)
	c := newVulnContext(now, page.Subjects, page.Feeds)
	d.Truncated = page.Truncated
	d.Banners = feedBanners(page.Feeds, page.LastComplete, now, d.Maintainer)
	for _, row := range page.Rows {
		if row.Finding.Record.Vuln.ID != id {
			continue
		}
		d.Findings = append(d.Findings, c.view(row))
	}
	h.renderVuln(w, r, id, "vuln_cve", d)
}

// handleVulnSubject serves GET /vulnerabilities/subject/{kind}/{id}
// (?digest= for images): the subject's Vulnerabilities tab.
func (h *Handler) handleVulnSubject(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	s := vulnstore.Subject{Kind: vulnfinding.SubjectKind(r.PathValue("kind")), ID: r.PathValue("id")}
	switch s.Kind {
	case vulnfinding.SubjectHost, vulnfinding.SubjectDevice:
	case vulnfinding.SubjectImage:
		s.ImageDigest = r.URL.Query().Get("digest")
		if !vulnDigestRe.MatchString(s.ImageDigest) {
			http.NotFound(w, r)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	if !vulnSubjectIDRe.MatchString(s.ID) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	d := &vulnPageData{Filter: parseVulnFilter(r.URL.Query()), Maintainer: h.vulnMaintainer(ctx, r)}
	if r.URL.Query().Get("state") == "" {
		d.Filter.State = vulnStateAll
	}
	d.Filter.View = ""
	d.Filter.Digest = s.ImageDigest
	title := "Vulnerabilities of " + s.ID
	page, err := h.vuln.VulnFindings(ctx, VulnQuery{Subject: &s, Limit: MaxVulnRows})
	if err != nil {
		h.log.Error("vulnerabilities: subject", "error", err)
		d.Unavailable = true
		h.renderVuln(w, r, title, "vuln_subject", d)
		return
	}
	now := h.clockNow()
	page.Feeds = withUnknownFeeds(page.Feeds, page.Rows)
	c := newVulnContext(now, page.Subjects, page.Feeds)
	d.Truncated = page.Truncated
	d.Banners = feedBanners(page.Feeds, page.LastComplete, now, d.Maintainer)
	var rows []VulnRow
	for _, row := range page.Rows {
		if row.Finding.Subject == s {
			rows = append(rows, row)
		}
	}
	views := make([]vulnFindingView, len(rows))
	for i, row := range rows {
		views[i] = c.view(row)
	}
	groups := groupBySubject(c, VulnPage{Rows: rows, Subjects: []VulnSubjectStatus{c.subject(s)}}, views, vulnFilter{State: vulnStateAll})
	if len(groups) == 1 {
		d.Subject = &groups[0]
	}
	for i, row := range rows {
		if d.Filter.match(views[i], row) {
			d.Findings = append(d.Findings, views[i])
		}
	}
	sort.SliceStable(d.Findings, func(i, j int) bool { return d.Findings[i].VulnID < d.Findings[j].VulnID })
	h.renderVuln(w, r, title, "vuln_subject", d)
}

// handleVulnFinding serves GET /vulnerabilities/f/{key}: the finding with
// its assessment, held closures and, for the maintainer, the state forms.
func (h *Handler) handleVulnFinding(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	key, ok := parseVulnKey(r.PathValue("key"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	det, err := h.vuln.VulnFinding(ctx, key)
	if errors.Is(err, vulnstore.ErrFindingNotFound) {
		http.NotFound(w, r)
		return
	}
	d := &vulnPageData{Maintainer: h.vulnMaintainer(ctx, r)}
	if err != nil {
		h.log.Error("vulnerabilities: finding", "error", err)
		d.Unavailable = true
		h.renderVuln(w, r, "Finding", "vuln_finding", d)
		return
	}
	now := h.clockNow()
	det.Feeds = withUnknownFeeds(det.Feeds, []VulnRow{det.Row})
	c := newVulnContext(now, []VulnSubjectStatus{det.Subject}, det.Feeds)
	d.Banners = feedBanners(det.Feeds, det.LastComplete, now, d.Maintainer)
	v := c.view(det.Row)
	d.Finding = &v
	for _, ho := range det.Holds {
		hv := vulnHoldView{
			RunID:        vulnText(ho.Hold.RunID, false),
			RunSeq:       ho.Hold.RunSeq,
			Reason:       vulnHoldReason(ho.Hold.Reason),
			Created:      vulnTime(ho.Hold.Created),
			NOSVersion:   vulnText(ho.NOSVersion, false),
			Fixed:        vulnText(det.Row.Finding.EpisodeFixedVersion, false),
			Contradicted: ho.Contradicted,
		}
		if hv.NOSVersion == "" {
			hv.NOSVersion = "unknown"
		}
		if hv.Fixed == "" {
			hv.Fixed = "none in this episode"
		}
		d.Holds = append(d.Holds, hv)
	}
	if d.Maintainer {
		d.DefaultExpiry = now.Add(vulnstore.DefaultAcceptExpiry).UTC().Format(vulnDateLayout)
		d.MinExpiry = now.Add(24 * time.Hour).UTC().Format(vulnDateLayout)
		d.MaxExpiry = now.Add(vulnstore.MaxAcceptExpiry).UTC().Format(vulnDateLayout)
		d.Categories = vulnCategories
	}
	h.renderVuln(w, r, "Finding "+v.VulnID, "vuln_finding", d)
}

// vulnHoldReason names a hold reason.
func vulnHoldReason(r vulnstore.HoldReason) string {
	switch r {
	case vulnstore.HoldContradicted:
		return "NOS inventory contradicts the closure"
	case vulnstore.HoldKEVOrCritical:
		return "KEV-listed or critical in this episode"
	case vulnstore.HoldRunGuard:
		return "run closure guard"
	case vulnstore.HoldWindowGuard:
		return "24 h window guard"
	case vulnstore.HoldClassifyFailed:
		return "NOS could not classify the closure"
	case vulnstore.HoldProbation:
		return "a basis feed is on probation"
	}
	return "unknown reason"
}

// handleVulnMarkReset serves GET /vulnerabilities/feeds/{source}/reset,
// for the maintainer only.
func (h *Handler) handleVulnMarkReset(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	id := r.PathValue("source")
	if !vulnSourceIDRe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.vulnMaintainer(ctx, r) {
		http.Error(w, "only the maintainer can reset a feed's high-water mark", http.StatusForbidden)
		return
	}
	d := &vulnPageData{Maintainer: true}
	mv, err := h.vuln.VulnMarkResetCandidate(ctx, id)
	if errors.Is(err, vulnstore.ErrResetRefused) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("vulnerabilities: mark reset candidate", "error", err)
		d.Unavailable = true
		h.renderVuln(w, r, "Reset high-water mark", "vuln_reset", d)
		return
	}
	d.Reset = &vulnResetView{
		SourceID:     id,
		Mark:         vulnMark(mv.MarkDate, mv.MarkSeq),
		Reported:     vulnMark(mv.ReportedDate, mv.ReportedSeq),
		RunID:        vulnText(mv.RunID, false),
		LastAccepted: vulnText(mv.LastAcceptedSnapshot, false),
		Probation:    mv.Probation,
		PreReset:     vulnMark(mv.PreResetDate, mv.PreResetSeq),
		Possible:     mv.RunID != "",
	}
	if d.Reset.LastAccepted == "" {
		d.Reset.LastAccepted = "none"
	}
	h.renderVuln(w, r, "Reset high-water mark of "+id, "vuln_reset", d)
}
