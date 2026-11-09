// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// vulnNow is the fixed clock of the vulnerabilities tests.
var vulnNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// fakeVuln is a fake vulnerabilities backend.
type fakeVuln struct {
	mu         sync.Mutex
	page       VulnPageFixture
	err        error
	detail     ui.VulnFindingDetail
	reset      vulnstore.MarkResetView
	maintainer bool

	begun      []ui.VulnDecision
	committed  []ui.VulnDecision
	assertions []string
	commitErr  error
	challenges int
}

// VulnPageFixture is the page the fake returns.
type VulnPageFixture = ui.VulnPage

func (f *fakeVuln) VulnFindings(_ context.Context, q ui.VulnQuery) (ui.VulnPage, error) {
	if f.err != nil {
		return ui.VulnPage{}, f.err
	}
	p := f.page
	if q.VulnID != "" || q.Subject != nil {
		var rows []ui.VulnRow
		for _, r := range p.Rows {
			if q.VulnID != "" && r.Finding.Record.Vuln.ID != q.VulnID {
				continue
			}
			if q.Subject != nil && r.Finding.Subject != *q.Subject {
				continue
			}
			rows = append(rows, r)
		}
		p.Rows = rows
	}
	return p, nil
}

func (f *fakeVuln) VulnFinding(_ context.Context, key vulnfinding.Key) (ui.VulnFindingDetail, error) {
	if f.err != nil {
		return ui.VulnFindingDetail{}, f.err
	}
	if f.detail.Row.Finding.Key != key {
		return ui.VulnFindingDetail{}, vulnstore.ErrFindingNotFound
	}
	return f.detail, nil
}

func (f *fakeVuln) VulnMarkResetCandidate(_ context.Context, id string) (vulnstore.MarkResetView, error) {
	if id != f.reset.SourceID {
		return vulnstore.MarkResetView{}, vulnstore.ErrResetRefused
	}
	return f.reset, nil
}

func (f *fakeVuln) VulnMaintainer(context.Context, string) (bool, error) { return f.maintainer, nil }

func (f *fakeVuln) BeginVulnDecision(_ context.Context, _ string, d ui.VulnDecision) (ui.VulnChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, d)
	f.challenges++
	id := "challenge-" + strings.Repeat("x", 10) + string(rune('a'+f.challenges))
	return ui.VulnChallenge{ID: id, Options: []byte(`{"publicKey":{"challenge":"AAAA"}}`)}, nil
}

func (f *fakeVuln) CommitVulnDecision(_ context.Context, _ string, _ string, d ui.VulnDecision, assertion []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.commitErr != nil {
		return f.commitErr
	}
	f.committed = append(f.committed, d)
	f.assertions = append(f.assertions, string(assertion))
	return nil
}

func vulnKey(b byte) vulnfinding.Key {
	var k vulnfinding.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func hostSubject(id string) vulnstore.Subject {
	return vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: id}
}

// vulnRow builds a finding on subject s resting on the given sources.
func vulnRow(b byte, s vulnstore.Subject, id string, st vulnstore.State, tier vulnstore.Tier, sources ...string) ui.VulnRow {
	r := vulnfinding.Record{
		SubjectKind: s.Kind,
		SubjectRef:  vulnfinding.SubjectRef{ID: s.ID, ImageDigest: s.ImageDigest},
		Ecosystem:   "debian:bookworm",
		Component:   vulnfinding.Component{SourcePackage: "openssl", SourceVersion: "3.0.11-1"},
		Vuln:        vulnfinding.Vuln{ID: id},
		Fix:         vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.13-1"},
		MatchBasis:  vulnfinding.MatchDistroTracker,
	}
	for _, src := range sources {
		r.Evidence.BasisSources = append(r.Evidence.BasisSources, vulnfinding.BasisSource{SourceID: src, SnapshotID: "snap-1", Integrity: vulnfinding.IntegrityChecksum})
	}
	return ui.VulnRow{Tier: tier, Finding: vulnstore.Finding{Key: vulnKey(b), Subject: s, Record: r, NOSChecked: true, State: st}}
}

func freshSubject(s vulnstore.Subject) ui.VulnSubjectStatus {
	return ui.VulnSubjectStatus{Subject: s, LastComplete: vulnNow.Add(-time.Hour)}
}

func okFeed(id string) ui.VulnFeedStatus {
	return ui.VulnFeedStatus{SourceID: id, Listed: true, LastVerdict: vulnstore.SourceAccepted}
}

func vulnHandler(t *testing.T, f *fakeVuln) http.Handler {
	t.Helper()
	return newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Vuln: f, Now: func() time.Time { return vulnNow }}).Handler()
}

func vulnGet(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func vulnPost(t *testing.T, h http.Handler, path, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestVulnPagesHiddenWithoutBackend(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin}).Handler()
	// The navigation links the page; without a backend it says nothing
	// is assessed, never an empty clean list.
	body := getBody(t, h, "/vulnerabilities")
	if !strings.Contains(body, "not set up on this server: nothing is assessed") || strings.Contains(body, "badge--ok") || strings.Contains(body, "No finding matches") {
		t.Error("page without a backend does not say it is not set up")
	}
	for _, p := range []string{"/vulnerabilities/cve/CVE-2024-0001", "/vulnerabilities/f/" + vulnKey(1).String(), "/vulnerabilities/subject/host/web1", "/vulnerabilities/feeds/kev/reset"} {
		if code, _ := vulnGet(t, h, p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
	for _, p := range []string{"/vulnerabilities/decide/begin", "/vulnerabilities/decide/commit"} {
		if code, _ := vulnPost(t, h, p, `{}`); code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", p, code)
		}
	}
}

func TestVulnNavigationLinksPage(t *testing.T) {
	h := vulnHandler(t, &fakeVuln{})
	if body := getBody(t, h, "/dashboard"); !strings.Contains(body, `href="/vulnerabilities"`) {
		t.Error("navigation has no Vulnerabilities item")
	}
	code, body := vulnGet(t, h, "/vulnerabilities")
	if code != http.StatusOK || !strings.Contains(body, `aria-current="page"`) {
		t.Errorf("GET /vulnerabilities = %d, active nav item missing", code)
	}
}

// hostile strings in every Hermes and feed field.
const (
	hostileScript = `<script>alert(1)</script>`
	hostileImg    = `"><img src=x onerror=alert(2)>`
)

func TestVulnHostileTextRenderedAsText(t *testing.T) {
	s := hostSubject("web1")
	row := vulnRow(1, s, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")
	row.Finding.Record.Assessment.Text = "line1\n" + hostileScript + "\u202egnp.exe"
	row.Finding.Record.Component.SourcePackage = hostileImg
	row.Finding.Record.Component.SourceVersion = hostileScript
	row.Finding.Record.Vuln.Aliases = []string{hostileImg}
	row.Finding.Record.Evidence.BasisSources[0].SnapshotID = hostileScript
	row.Finding.Record.Evidence.MatcherVersion = hostileImg
	row.Finding.Record.Scores.KEV = &vulnfinding.KEV{DateAdded: hostileScript}
	st := freshSubject(s)
	st.Name = hostileImg
	f := &fakeVuln{
		page:   ui.VulnPage{Rows: []ui.VulnRow{row}, Subjects: []ui.VulnSubjectStatus{st}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow},
		detail: ui.VulnFindingDetail{Row: row, Subject: st, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow},
	}
	h := vulnHandler(t, f)
	for _, p := range []string{
		"/vulnerabilities", "/vulnerabilities?view=subject", "/vulnerabilities/cve/CVE-2024-0001",
		"/vulnerabilities/subject/host/web1", "/vulnerabilities/f/" + vulnKey(1).String(),
	} {
		code, body := vulnGet(t, h, p)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d", p, code)
		}
		for _, bad := range []string{"<script>alert", "<img src=x", `"><img`, "\u202e"} {
			if strings.Contains(body, bad) {
				t.Errorf("GET %s renders %q unescaped", p, bad)
			}
		}
	}
	_, body := vulnGet(t, h, "/vulnerabilities/f/"+vulnKey(1).String())
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(2)&gt;", "Hermes assessment (LLM, unverified)", "�gnp.exe", "line1\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding page lacks %q", want)
		}
	}
}

func TestVulnNotAssessedAndStaleNeverGreen(t *testing.T) {
	never := hostSubject("never")
	old := hostSubject("old")
	clean := hostSubject("clean")
	f := &fakeVuln{page: ui.VulnPage{
		Subjects: []ui.VulnSubjectStatus{
			{Subject: never},
			{Subject: old, LastComplete: vulnNow.Add(-vulnstore.StaleAfter - time.Minute)},
			freshSubject(clean),
		},
		LastComplete: vulnNow.Add(-time.Hour),
	}}
	h := vulnHandler(t, f)
	_, body := vulnGet(t, h, "/vulnerabilities?view=subject")
	rows := subjectRows(body)
	if got := rows["never"]; !strings.Contains(got, "not assessed") || strings.Contains(got, "badge--ok") {
		t.Errorf("never-assessed subject row = %q, want not assessed and not green", got)
	}
	if got := rows["old"]; !strings.Contains(got, "stale since") || strings.Contains(got, "badge--ok") {
		t.Errorf("stale subject row = %q, want stale since and not green", got)
	}
	if got := rows["clean"]; !strings.Contains(got, "badge--ok") {
		t.Errorf("fresh clean subject row = %q, want green", got)
	}
	for _, sub := range []string{"never", "old"} {
		if strings.Contains(rows[sub], ">0 findings") || strings.Contains(rows[sub], "no open findings") {
			t.Errorf("%s shown as without findings: %q", sub, rows[sub])
		}
	}

	// A finding of a not-assessed subject carries the label.
	f.page.Rows = []ui.VulnRow{vulnRow(2, never, "CVE-2024-0002", vulnstore.StateOpen, vulnstore.TierLow, "kev")}
	f.page.Feeds = []ui.VulnFeedStatus{okFeed("kev")}
	_, body = vulnGet(t, h, "/vulnerabilities/subject/host/never")
	if !strings.Contains(body, "not assessed") {
		t.Error("subject page of a not-assessed subject lacks the label")
	}
	// A subject unknown to the backend is not assessed, never green.
	_, body = vulnGet(t, h, "/vulnerabilities/subject/host/ghost")
	if !strings.Contains(body, "not assessed") || strings.Contains(body, "vuln-status\">no open findings") || strings.Contains(body, "badge--ok vuln-status") {
		t.Error("unknown subject not shown as not assessed")
	}
}

// subjectRows maps subject ID to its table row in the list by subject.
func subjectRows(body string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(body, `<tr class="vuln-subject">`)[1:] {
		row, _, _ := strings.Cut(part, "</tr>")
		m := regexp.MustCompile(`<span class="hint mono">([^<]*)</span>`).FindStringSubmatch(row)
		if m != nil {
			out[m[1]] = row
		}
	}
	return out
}

func TestVulnUnconfirmedClosureLabelFilterAndNeverGreen(t *testing.T) {
	s := hostSubject("db1")
	row := vulnRow(3, s, "CVE-2024-0003", vulnstore.StateFixed, vulnstore.TierMedium, "debian-tracker")
	row.Finding.ClosedBy = vulnstore.ClosedByHermesUnconfirmed
	other := vulnRow(4, hostSubject("db2"), "CVE-2024-0004", vulnstore.StateFixed, vulnstore.TierMedium, "debian-tracker")
	other.Finding.ClosedBy = vulnstore.ClosedByNOSInventory
	f := &fakeVuln{page: ui.VulnPage{
		Rows:         []ui.VulnRow{row, other},
		Subjects:     []ui.VulnSubjectStatus{freshSubject(s), freshSubject(hostSubject("db2"))},
		Feeds:        []ui.VulnFeedStatus{okFeed("debian-tracker")},
		LastComplete: vulnNow,
	}}
	h := vulnHandler(t, f)
	_, body := vulnGet(t, h, "/vulnerabilities?view=subject")
	rows := subjectRows(body)
	if got := rows["db1"]; strings.Contains(got, "badge--ok") || !strings.Contains(got, "closed by Hermes, not confirmed by NOS") {
		t.Errorf("subject with an unconfirmed closure = %q, want labelled and not green", got)
	}
	if got := rows["db2"]; !strings.Contains(got, "badge--ok") {
		t.Errorf("subject with only NOS-confirmed closures = %q, want green", got)
	}
	_, body = vulnGet(t, h, "/vulnerabilities?state=unconfirmed")
	if !strings.Contains(body, "CVE-2024-0003") || strings.Contains(body, "CVE-2024-0004") {
		t.Error("filter state=unconfirmed does not select exactly the Hermes-only closure")
	}
	if !strings.Contains(body, `value="unconfirmed" selected`) {
		t.Error("unconfirmed filter not offered or not selected")
	}
	_, body = vulnGet(t, h, "/vulnerabilities/subject/host/db1")
	if !strings.Contains(body, "closed by Hermes, not confirmed by NOS") {
		t.Error("subject tab lacks the unconfirmed label")
	}
}

func TestVulnFeedBannersPerSource(t *testing.T) {
	s := hostSubject("web1")
	row := vulnRow(5, s, "CVE-2024-0005", vulnstore.StateOpen, vulnstore.TierHigh, "nvd", "kev", "cisco-csaf", "osv", "mystery")
	seq := int64(41)
	f := &fakeVuln{page: ui.VulnPage{
		Rows:     []ui.VulnRow{row},
		Subjects: []ui.VulnSubjectStatus{freshSubject(s)},
		Feeds: []ui.VulnFeedStatus{
			{SourceID: "nvd", Listed: true, Stale: true, LastVerdict: vulnstore.SourceAccepted, SnapshotDate: vulnNow.Add(-100 * time.Hour)},
			{SourceID: "kev", Listed: true, LastVerdict: vulnstore.SourceRegressed},
			{SourceID: "cisco-csaf", Listed: true, LastVerdict: vulnstore.SourceInvalid},
			{SourceID: "osv", Listed: true, LastVerdict: vulnstore.SourceAccepted, Probation: true, PreResetSeq: &seq},
		},
		LastComplete: vulnNow,
	}}
	h := vulnHandler(t, f)
	_, body := vulnGet(t, h, "/vulnerabilities")
	for _, want := range []string{
		"Feed nvd stale", "Feed kev behind its high-water mark", "Feed cisco-csaf dated in the future",
		"Feed osv on probation", "sequence 41", "Feed mystery is not on NOS",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list page lacks banner %q", want)
		}
	}
	if strings.Contains(body, "/vulnerabilities/feeds/kev/reset") {
		t.Error("non-maintainer sees the mark reset link")
	}
	_, body = vulnGet(t, h, "/vulnerabilities/subject/host/web1")
	for _, want := range []string{"feed nvd stale", "feed kev behind its high-water mark", "feed cisco-csaf dated in the future", "feed osv on probation", "feed mystery not on NOS"} {
		if !strings.Contains(body, want) {
			t.Errorf("finding row lacks label %q", want)
		}
	}
	_, body = vulnGet(t, h, "/vulnerabilities?view=subject")
	if strings.Contains(subjectRows(body)["web1"], "badge--ok") {
		t.Error("subject with feed issues shown green")
	}
	f.maintainer = true
	_, body = vulnGet(t, h, "/vulnerabilities")
	if !strings.Contains(body, `href="/vulnerabilities/feeds/kev/reset"`) {
		t.Error("maintainer lacks the mark reset link on the regressed feed")
	}
}

func TestVulnHermesOfflineBanner(t *testing.T) {
	f := &fakeVuln{}
	h := vulnHandler(t, f)
	if _, body := vulnGet(t, h, "/vulnerabilities"); !strings.Contains(body, "No complete Hermes run yet") {
		t.Error("no banner when Hermes never completed a run")
	}
	f.page.LastComplete = vulnNow.Add(-49 * time.Hour)
	if _, body := vulnGet(t, h, "/vulnerabilities"); !strings.Contains(body, "Hermes offline") {
		t.Error("no banner when Hermes is offline")
	}
	f.err = errors.New("db down")
	_, body := vulnGet(t, h, "/vulnerabilities")
	if !strings.Contains(body, "Vulnerability data unavailable") || strings.Contains(body, "No finding matches") {
		t.Error("backend failure not shown as unavailable")
	}
}

func findingFixture(maintainer bool) *fakeVuln {
	s := hostSubject("web1")
	row := vulnRow(7, s, "CVE-2024-0007", vulnstore.StateOpen, vulnstore.TierCritical, "debian-tracker")
	row.Finding.EpisodeFixedVersion = "3.0.13-1"
	return &fakeVuln{
		maintainer: maintainer,
		detail: ui.VulnFindingDetail{
			Row: row, Subject: freshSubject(s), Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow,
			Holds: []ui.VulnHold{
				{Hold: vulnstore.Hold{RunID: "run-a", RunSeq: 9, Key: vulnKey(7), Reason: vulnstore.HoldContradicted, Created: vulnNow}, NOSVersion: "3.0.11-1", Contradicted: true},
				{Hold: vulnstore.Hold{RunID: "run-b", RunSeq: 10, Key: vulnKey(7), Reason: vulnstore.HoldKEVOrCritical, Created: vulnNow}, NOSVersion: "3.0.13-1"},
			},
		},
		reset: vulnstore.MarkResetView{SourceID: "kev", MarkDate: vulnNow.Add(-time.Hour), RunID: "run-r", ReportedDate: vulnNow.Add(-48 * time.Hour), LastAcceptedSnapshot: "snap-<b>9</b>"},
	}
}

func TestVulnStateFormsMaintainerOnly(t *testing.T) {
	path := "/vulnerabilities/f/" + vulnKey(7).String()
	f := findingFixture(false)
	h := vulnHandler(t, f)
	_, body := vulnGet(t, h, path)
	if strings.Contains(body, "vuln-decision") || strings.Contains(body, "/static/vuln.js") {
		t.Error("non-maintainer sees state forms")
	}
	if !strings.Contains(body, "NOS inventory contradicts") || !strings.Contains(body, "3.0.11-1") {
		t.Error("held-closure view lacks the NOS version contradiction")
	}
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/begin", acceptBody("2027-01-01")); code != http.StatusForbidden {
		t.Errorf("non-maintainer begin = %d, want 403", code)
	}
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"challenge-xxxxxxxxxxb","assertion":{}}`); code != http.StatusForbidden {
		t.Errorf("non-maintainer commit = %d, want 403", code)
	}
	if code, _ := vulnGet(t, h, "/vulnerabilities/feeds/kev/reset"); code != http.StatusForbidden {
		t.Errorf("non-maintainer reset page = %d, want 403", code)
	}
	if len(f.begun) != 0 {
		t.Error("backend asked for a challenge for a non-maintainer")
	}

	f.maintainer = true
	_, body = vulnGet(t, h, path)
	for _, want := range []string{
		`data-kind="accept_risk"`, `data-kind="false_positive"`, `data-kind="discard_hold"`, `data-kind="confirm_hold"`,
		"/static/vuln.js", "/static/webauthn.js", `name="approver"`, `name="expires"`, `max="2027-11-09"`, "backport_fixed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("maintainer finding page lacks %q", want)
		}
	}
	// The contradicted hold offers no confirmation.
	if strings.Count(body, `data-kind="confirm_hold"`) != 1 {
		t.Error("a contradicted hold offers confirmation")
	}
}

func acceptBody(expires string) string {
	return `{"kind":"accept_risk","key":"` + vulnKey(7).String() + `","approver":"garm","reason":"compensating firewall rule","expires":"` + expires + `"}`
}

func TestVulnDecisionInputRules(t *testing.T) {
	key := vulnKey(7).String()
	long := strings.Repeat("a", vulnstore.MaxHumanReason+1)
	tests := []struct {
		name, body, wantMsg string
	}{
		{"approver missing", `{"kind":"accept_risk","key":"` + key + `","reason":"r","expires":"2027-01-01"}`, "approver is required"},
		{"approver malformed", `{"kind":"accept_risk","key":"` + key + `","approver":"<x>","reason":"r","expires":"2027-01-01"}`, "approver must be"},
		{"expiry missing", `{"kind":"accept_risk","key":"` + key + `","approver":"garm","reason":"r"}`, "expiry date is required"},
		{"expiry today", acceptBody("2026-11-09"), "must be in the future"},
		{"expiry past", acceptBody("2025-01-01"), "must be in the future"},
		{"expiry 366 days", acceptBody("2027-11-10"), "more than 365 days"},
		{"expiry not a date", acceptBody("next year"), "must be a date"},
		{"reason missing", `{"kind":"accept_risk","key":"` + key + `","approver":"garm","expires":"2027-01-01"}`, "reason is required"},
		{"reason too long", `{"kind":"false_positive","key":"` + key + `","category":"other","reason":"` + long + `"}`, "longer than 1 KiB"},
		{"reason control char", `{"kind":"false_positive","key":"` + key + `","category":"other","reason":"a\u0000b"}`, "control characters"},
		{"reason invalid utf8", "{\"kind\":\"false_positive\",\"key\":\"" + key + "\",\"category\":\"other\",\"reason\":\"a\xffb\"}", "not valid UTF-8"},
		{"category missing", `{"kind":"false_positive","key":"` + key + `","reason":"r"}`, "category"},
		{"category unknown", `{"kind":"false_positive","key":"` + key + `","category":"trust_me","reason":"r"}`, "category"},
		{"key malformed", `{"kind":"false_positive","key":"zz","category":"other","reason":"r"}`, "finding is missing"},
		{"unknown kind", `{"kind":"close","key":"` + key + `","reason":"r"}`, "unknown decision"},
		{"unknown field", `{"kind":"false_positive","key":"` + key + `","category":"other","reason":"r","basis_version":"9"}`, "not valid JSON"},
		{"hold without run", `{"kind":"confirm_hold","key":"` + key + `","reason":"r"}`, "run is missing"},
		{"reset without run", `{"kind":"mark_reset","source_id":"kev","reason":"r"}`, "no regressed run"},
		{"reset with key", `{"kind":"mark_reset","source_id":"kev","run_id":"run-r","key":"` + key + `","reason":"r"}`, "names no finding"},
		{"reset without reason", `{"kind":"mark_reset","source_id":"kev","run_id":"run-r"}`, "reason is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := findingFixture(true)
			h := vulnHandler(t, f)
			code, out := vulnPost(t, h, "/vulnerabilities/decide/begin", tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status %d (%v), want 400", code, out)
			}
			if msg, _ := out["error"].(string); !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("error %q, want it to contain %q", msg, tc.wantMsg)
			}
			if len(f.begun) != 0 {
				t.Error("a rejected decision reached the backend")
			}
		})
	}
}

func TestVulnAcceptRiskExpiryBoundary(t *testing.T) {
	for _, tc := range []struct {
		date string
		want int
	}{{"2026-11-10", http.StatusOK}, {"2027-11-09", http.StatusOK}, {"2027-11-10", http.StatusBadRequest}} {
		f := findingFixture(true)
		code, _ := vulnPost(t, vulnHandler(t, f), "/vulnerabilities/decide/begin", acceptBody(tc.date))
		if code != tc.want {
			t.Errorf("expiry %s = %d, want %d", tc.date, code, tc.want)
		}
	}
}

func TestVulnDecisionNeedsFreshSingleUseAssertion(t *testing.T) {
	f := findingFixture(true)
	now := vulnNow
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Vuln: f, Now: func() time.Time { return now }}).Handler()

	code, out := vulnPost(t, h, "/vulnerabilities/decide/begin", acceptBody("2027-01-01"))
	if code != http.StatusOK {
		t.Fatalf("begin = %d %v", code, out)
	}
	id, _ := out["id"].(string)
	if _, ok := out["options"].(map[string]any); !ok || id == "" {
		t.Fatalf("begin answer lacks challenge: %v", out)
	}
	if len(f.begun) != 1 || f.begun[0].Approver != "garm" || !f.begun[0].Expires.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) || f.begun[0].Key != vulnKey(7) {
		t.Fatalf("backend got %+v", f.begun)
	}
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"`+id+`"}`); code != http.StatusForbidden {
		t.Errorf("commit without assertion = %d, want 403", code)
	}
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"`+id+`","assertion":{"id":"cred"}}`); code != http.StatusOK {
		t.Fatalf("commit = %d", code)
	}
	if len(f.committed) != 1 || f.committed[0].Digest() != f.begun[0].Digest() || f.assertions[0] != `{"id":"cred"}` {
		t.Fatalf("committed %+v with %v", f.committed, f.assertions)
	}
	// The same challenge is single use.
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"`+id+`","assertion":{"id":"cred"}}`); code != http.StatusNotFound {
		t.Errorf("replayed commit = %d, want 404", code)
	}

	// A challenge older than its lifetime is refused.
	_, out = vulnPost(t, h, "/vulnerabilities/decide/begin", acceptBody("2027-01-01"))
	id, _ = out["id"].(string)
	now = now.Add(6 * time.Minute)
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"`+id+`","assertion":{"id":"cred"}}`); code != http.StatusNotFound {
		t.Errorf("late commit = %d, want 404", code)
	}

	// The backend's assertion refusal is a 403.
	_, out = vulnPost(t, h, "/vulnerabilities/decide/begin", acceptBody("2027-01-01"))
	id, _ = out["id"].(string)
	f.commitErr = ui.ErrVulnAssertionRefused
	if code, _ := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"`+id+`","assertion":{"id":"cred"}}`); code != http.StatusForbidden {
		t.Errorf("refused assertion = %d, want 403", code)
	}
	if len(f.committed) != 1 {
		t.Error("a refused or replayed commit was applied")
	}
}

func TestVulnDecisionStoreErrorsAreFixedMessages(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{
		{vulnstore.ErrContradicted, http.StatusConflict},
		{vulnstore.ErrHoldSuperseded, http.StatusConflict},
		{vulnstore.ErrResetRefused, http.StatusConflict},
		{vulnstore.ErrWrongState, http.StatusConflict},
		{vulnstore.ErrInvalidInput, http.StatusBadRequest},
		{errors.New("secret db path /var/lib/x"), http.StatusBadGateway},
	} {
		f := findingFixture(true)
		h := vulnHandler(t, f)
		_, out := vulnPost(t, h, "/vulnerabilities/decide/begin", `{"kind":"confirm_hold","key":"`+vulnKey(7).String()+`","run_id":"run-b","reason":"fixed by hand"}`)
		f.commitErr = tc.err
		code, out := vulnPost(t, h, "/vulnerabilities/decide/commit", `{"id":"`+out["id"].(string)+`","assertion":{}}`)
		if code != tc.code {
			t.Errorf("%v: %d, want %d", tc.err, code, tc.code)
		}
		if msg, _ := out["error"].(string); strings.Contains(msg, "/var/lib") {
			t.Errorf("%v leaks internal detail: %q", tc.err, msg)
		}
	}
}

func TestVulnMarkResetPage(t *testing.T) {
	f := findingFixture(true)
	seq := int64(7)
	f.reset.Probation = true
	f.reset.PreResetSeq = &seq
	h := vulnHandler(t, f)
	code, body := vulnGet(t, h, "/vulnerabilities/feeds/kev/reset")
	if code != http.StatusOK {
		t.Fatalf("reset page = %d", code)
	}
	for _, want := range []string{
		"Current mark", "content date 2026-11-09 11:00 UTC", "content date 2026-11-07 12:00 UTC", "run-r",
		"snap-&lt;b&gt;9&lt;/b&gt;", "pre-reset mark: sequence 7", `data-kind="mark_reset"`, `name="reason"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("reset page lacks %q", want)
		}
	}
	if code, _ := vulnGet(t, h, "/vulnerabilities/feeds/other/reset"); code != http.StatusNotFound {
		t.Errorf("unlisted source = %d, want 404", code)
	}
	if code, _ := vulnGet(t, h, "/vulnerabilities/feeds/BAD%20ID/reset"); code != http.StatusNotFound {
		t.Errorf("malformed source = %d, want 404", code)
	}
	code, out := vulnPost(t, h, "/vulnerabilities/decide/begin", `{"kind":"mark_reset","source_id":"kev","run_id":"run-r","reason":"provider re-dated the feed"}`)
	if code != http.StatusOK {
		t.Fatalf("reset begin = %d %v", code, out)
	}
	if d := f.begun[0]; d.Kind != ui.VulnMarkReset || d.SourceID != "kev" || d.RunID != "run-r" || d.Reason == "" {
		t.Errorf("reset decision %+v", d)
	}
	// Nothing to reset to: no form.
	f.reset.RunID = ""
	_, body = vulnGet(t, h, "/vulnerabilities/feeds/kev/reset")
	if strings.Contains(body, `data-kind="mark_reset"`) {
		t.Error("reset form shown without a regressed run")
	}
}

// vulnServer serves the UI through the real security middleware.
func vulnServer(t *testing.T, f *fakeVuln) *httptest.Server {
	t.Helper()
	u := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Vuln: f, Now: func() time.Time { return vulnNow }})
	srv, err := u.Server()
	if err != nil {
		t.Fatalf("ui server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestVulnDecisionCSRFThroughMiddleware(t *testing.T) {
	f := findingFixture(true)
	ts := vulnServer(t, f)
	for _, tc := range []struct {
		name, origin, ctype string
		want                int
	}{
		{"no origin", "", "application/json", http.StatusForbidden},
		{"foreign origin", "https://evil.example", "application/json", http.StatusForbidden},
		{"null origin", "null", "application/json", http.StatusForbidden},
		{"form post", leaseOrigin, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"same origin json", leaseOrigin, "application/json", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/vulnerabilities/decide/begin", strings.NewReader(acceptBody("2027-01-01")))
			req.Header.Set("Content-Type", tc.ctype)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if res.StatusCode != tc.want {
				t.Errorf("status %d, want %d", res.StatusCode, tc.want)
			}
		})
	}
	if len(f.begun) != 1 {
		t.Errorf("backend saw %d begins, want 1 (only the same-origin JSON post)", len(f.begun))
	}
}

func TestVulnPagesKeepCSPAndNoInlineScript(t *testing.T) {
	f := findingFixture(true)
	f.page = ui.VulnPage{Rows: []ui.VulnRow{f.detail.Row}, Subjects: []ui.VulnSubjectStatus{f.detail.Subject}, LastComplete: vulnNow}
	ts := vulnServer(t, f)
	for _, p := range []string{"/vulnerabilities", "/vulnerabilities/f/" + vulnKey(7).String(), "/vulnerabilities/feeds/kev/reset"} {
		res, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", p, res.StatusCode)
		}
		if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("GET %s CSP = %q", p, csp)
		}
		if regexp.MustCompile(`<script>|<script [^>]*>[^<]`).Match(b) {
			t.Errorf("GET %s has an inline script", p)
		}
	}
	// The templates themselves carry no inline script, style or handler.
	files, _ := filepath.Glob(filepath.Join(repoRoot, "web", "templates", "vuln*.html"))
	if len(files) < 5 {
		t.Fatalf("vuln templates: %v", files)
	}
	bad := regexp.MustCompile(`(?i)<script>|<style|\sstyle=|\son[a-z]+=|javascript:|safeHTML|template\.HTML`)
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if m := bad.Find(b); m != nil {
			t.Errorf("%s contains %q", filepath.Base(p), m)
		}
	}
}

func TestVulnMalformedPathsAre404(t *testing.T) {
	f := findingFixture(true)
	f.detail.Row.Finding.Key = vulnKey(0xab)
	h := vulnHandler(t, f)
	if code, _ := vulnGet(t, h, "/vulnerabilities/f/"+vulnKey(0xab).String()); code != http.StatusOK {
		t.Fatalf("lower-case key = %d, want 200", code)
	}
	for _, p := range []string{
		"/vulnerabilities/cve/%3Cscript%3E",
		"/vulnerabilities/f/xyz",
		"/vulnerabilities/f/" + strings.ToUpper(vulnKey(0xab).String()),
		"/vulnerabilities/f/" + vulnKey(8).String(),
		"/vulnerabilities/subject/vm/web1",
		"/vulnerabilities/subject/host/Web_1",
		"/vulnerabilities/subject/image/web1?digest=latest",
	} {
		if code, _ := vulnGet(t, h, p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
}
