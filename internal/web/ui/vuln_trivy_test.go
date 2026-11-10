// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// trivyDigest is the platform digest of the image subject under test.
var trivyDigest = "sha256:" + strings.Repeat("0123456789abcdef", 4)

// trivySubject is the image subject (host "box", platform digest).
var trivySubject = vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "box", ImageDigest: trivyDigest}

// trivyPath is the image detail page of trivySubject.
var trivyPath = "/vulnerabilities/subject/image/box?digest=" + trivyDigest

type trivyTop struct{ id, sev, fixed string }

// trivyDoc builds an image.vulnerabilities result for image ref with the
// given status, severity counts and top list.
func trivyDoc(t *testing.T, image, status string, sev map[string]int, top []trivyTop) []byte {
	t.Helper()
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	doc := map[string]any{
		"format": "image-vulns-v1", "phase": "done", "reason": "", "present": true,
		"status": status, "trivy": enc("0.50.1"), "dbver": enc("2"), "dbage": 3,
		"image": image, "platform": enc("linux/amd64"), "cached": false,
	}
	if status == "ok" {
		total := 0
		for _, n := range sev {
			total += n
		}
		var tops []map[string]string
		for _, tv := range top {
			tops = append(tops, map[string]string{"id": tv.id, "severity": tv.sev, "fixed": tv.fixed})
		}
		sum, err := json.Marshal(map[string]any{"severity": sev, "total": total, "targets": 2, "top": tops})
		if err != nil {
			t.Fatalf("marshal summary: %v", err)
		}
		doc["summary"] = enc(string(sum))
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return b
}

// recVuln records every backend call the pages make.
type recVuln struct {
	*fakeVuln
	mu    sync.Mutex
	calls []string
}

func (r *recVuln) rec(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
}

func (r *recVuln) VulnFindings(ctx context.Context, q ui.VulnQuery) (ui.VulnPage, error) {
	r.rec("VulnFindings")
	return r.fakeVuln.VulnFindings(ctx, q)
}

func (r *recVuln) VulnFinding(ctx context.Context, key vulnfinding.Key) (ui.VulnFindingDetail, error) {
	r.rec("VulnFinding")
	return r.fakeVuln.VulnFinding(ctx, key)
}

func (r *recVuln) VulnMarkResetCandidate(ctx context.Context, id string) (vulnstore.MarkResetView, error) {
	r.rec("VulnMarkResetCandidate")
	return r.fakeVuln.VulnMarkResetCandidate(ctx, id)
}

func (r *recVuln) VulnMaintainer(ctx context.Context, user string) (bool, error) {
	r.rec("VulnMaintainer")
	return r.fakeVuln.VulnMaintainer(ctx, user)
}

func (r *recVuln) BeginVulnDecision(ctx context.Context, user string, d ui.VulnDecision) (ui.VulnChallenge, error) {
	r.rec("BeginVulnDecision")
	return r.fakeVuln.BeginVulnDecision(ctx, user, d)
}

func (r *recVuln) CommitVulnDecision(ctx context.Context, user, id string, d ui.VulnDecision, a []byte) error {
	r.rec("CommitVulnDecision")
	return r.fakeVuln.CommitVulnDecision(ctx, user, id, d, a)
}

// trivyHandler builds a handler with the vuln backend v and the stored
// image.vulnerabilities results (nil: none).
func trivyHandler(t *testing.T, v ui.VulnFindings, results map[string]executions.LastResultRow) http.Handler {
	t.Helper()
	ops := &chartOps{fakeOps: &fakeOps{}, extra: map[string]map[string]executions.LastResultRow{}}
	if results != nil {
		ops.extra["image.vulnerabilities"] = results
	}
	return newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, Vuln: v, Operations: ops, Now: func() time.Time { return vulnNow }}).Handler()
}

// trivyRow is a stored result for host "box" finished age before vulnNow.
func trivyRow(doc []byte, age time.Duration) map[string]executions.LastResultRow {
	return map[string]executions.LastResultRow{"box": {Result: doc, FinishedAt: vulnNow.Add(-age)}}
}

// section cuts the first <section> whose opening tag contains marker.
func section(t *testing.T, body, marker string) string {
	t.Helper()
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("page lacks section %q", marker)
	}
	start := strings.LastIndex(body[:i], "<section")
	end := strings.Index(body[i:], "</section>")
	if start < 0 || end < 0 {
		t.Fatalf("section %q not closed", marker)
	}
	return body[start : i+end]
}

const (
	trivyMarker = `data-observer="trivy-local"`
	badgeMarker = `class="panel vuln-image-badge"`
)

func imageRow(b byte, id string, st vulnstore.State) ui.VulnRow {
	return vulnRow(b, trivySubject, id, st, vulnstore.TierHigh, "debian-tracker")
}

func TestTrivyLocalShownBesideHermesLabelledPartial(t *testing.T) {
	f := &fakeVuln{page: ui.VulnPage{
		Rows:     []ui.VulnRow{imageRow(1, "CVE-2024-0001", vulnstore.StateOpen)},
		Subjects: []ui.VulnSubjectStatus{freshSubject(trivySubject)},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow,
	}}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(2, 1, 0, 0), []trivyTop{
		{"CVE-2024-0001", "CRITICAL", "3.0.13-1"}, {"CVE-2024-0002", "CRITICAL", ""}, {"CVE-2024-0003", "HIGH", "1.2"},
	})
	code, body := vulnGet(t, trivyHandler(t, f, trivyRow(doc, time.Hour)), trivyPath)
	if code != http.StatusOK {
		t.Fatalf("GET image page = %d", code)
	}
	sec := section(t, body, trivyMarker)
	for _, want := range []string{
		"trivy-local", "host Trivy, partial", "partial", "2 critical", "1 high",
		"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "no Hermes finding",
		"linux/amd64", "never opens, closes or re-opens a Hermes finding",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("trivy-local section lacks %q", want)
		}
	}
	// The Hermes finding of CVE-2024-0001 is shown beside, not merged.
	if !strings.Contains(sec, "Hermes: open") {
		t.Error("trivy-local section does not show the Hermes state beside the shared CVE")
	}
	// The Hermes findings table still exists next to it.
	if !strings.Contains(body, "/vulnerabilities/f/"+vulnKey(1).String()) {
		t.Error("Hermes findings table missing beside the trivy-local section")
	}
}

func TestTrivyLocalNeverReachesFindingStore(t *testing.T) {
	r := &recVuln{fakeVuln: &fakeVuln{page: ui.VulnPage{
		Rows:     []ui.VulnRow{imageRow(1, "CVE-2024-0001", vulnstore.StateOpen)},
		Subjects: []ui.VulnSubjectStatus{freshSubject(trivySubject)},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow,
	}}}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(1, 1, 0, 0), []trivyTop{
		{"CVE-2024-0009", "CRITICAL", ""}, {"CVE-2024-0010", "HIGH", ""},
	})
	_, body := vulnGet(t, trivyHandler(t, r, trivyRow(doc, time.Hour)), trivyPath)
	r.mu.Lock()
	calls := append([]string(nil), r.calls...)
	r.mu.Unlock()
	findings := 0
	for _, c := range calls {
		switch c {
		case "VulnMaintainer":
		case "VulnFindings":
			findings++
		default:
			t.Errorf("image page made store call %s", c)
		}
	}
	if findings != 1 {
		t.Errorf("image page read the store %d times, want 1 (the Hermes findings only)", findings)
	}
	if len(r.begun) != 0 || len(r.committed) != 0 {
		t.Error("trivy-local observation triggered a store decision")
	}
	// The Hermes table holds the one stored finding only; trivy CVEs are
	// not rendered as findings.
	if n := strings.Count(body, "/vulnerabilities/f/"); n != 1 {
		t.Errorf("findings links = %d, want 1 (trivy-local never becomes a finding)", n)
	}
	if strings.Contains(body, "/vulnerabilities/cve/CVE-2024-0009") {
		t.Error("trivy-local CVE rendered as a finding-store link")
	}
}

// TestTrivyLocalCodeHasNoStoreCall checks the source: the trivy-local code
// never calls the vuln backend (the finding store) nor a vulnstore function.
func TestTrivyLocalCodeHasNoStoreCall(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "vuln_trivy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse vuln_trivy.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "vulnstore" {
			t.Errorf("%s: vuln_trivy.go calls vulnstore.%s", fset.Position(call.Pos()), sel.Sel.Name)
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "vuln" {
			t.Errorf("%s: vuln_trivy.go calls the finding store backend (.vuln.%s)", fset.Position(call.Pos()), sel.Sel.Name)
		}
		return true
	})
}

func TestHermesRunNeverClosesTrivyLocal(t *testing.T) {
	// A fresh complete Hermes run covers the image and closed the CVE.
	closed := imageRow(1, "CVE-2024-0001", vulnstore.StateFixed)
	closed.Finding.ClosedBy = vulnstore.ClosedByHermesUnconfirmed
	f := &fakeVuln{page: ui.VulnPage{
		Rows:     []ui.VulnRow{closed},
		Subjects: []ui.VulnSubjectStatus{freshSubject(trivySubject)},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: vulnNow,
	}}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(1, 0, 0, 0), []trivyTop{{"CVE-2024-0001", "CRITICAL", ""}})
	_, body := vulnGet(t, trivyHandler(t, f, trivyRow(doc, time.Hour)), trivyPath)
	sec := section(t, body, trivyMarker)
	if !strings.Contains(sec, "1 critical") || !strings.Contains(sec, "CVE-2024-0001") || !strings.Contains(sec, "CRITICAL") {
		t.Error("Hermes closure removed or changed the trivy-local observation")
	}
	if !strings.Contains(sec, "badge--critical") {
		t.Error("trivy-local status lost its critical level after a Hermes closure")
	}
	// The difference is shown, never merged: the Hermes state stays the
	// Hermes closure, and the trivy observation does not re-open it.
	if !strings.Contains(sec, "Hermes: closed by Hermes, not confirmed by NOS") {
		t.Error("trivy-local section does not show the differing Hermes state")
	}
	summary := section(t, body, `aria-label="Assessment"`)
	if !strings.Contains(summary, `<dt>Open</dt><dd class="mono">0</dd>`) {
		t.Error("trivy-local observation re-opened the Hermes finding")
	}
	// The badge follows the fresh Hermes run, labelled with its observer.
	badge := section(t, body, badgeMarker)
	if !strings.Contains(badge, "observer: Hermes") || strings.Contains(badge, "observer: host Trivy") {
		t.Errorf("badge with a fresh Hermes run = %q, want observer Hermes", badge)
	}
}

func TestTrivyLocalAbsentShowsNotObservedNotGreen(t *testing.T) {
	other := "sha256:" + strings.Repeat("f", 64)
	malformed := []byte(`{"format":"image-vulns-v1","phase":"done","status":"bogus"}`)
	precheck := []byte(`{"format":"image-vulns-v1","phase":"precheck","reason":"no trivy"}`)
	cases := []struct {
		name    string
		results map[string]executions.LastResultRow
		want    string
	}{
		{"no result", nil, "not observed"},
		{"other host only", map[string]executions.LastResultRow{"web1": {Result: trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(0, 0, 0, 0), nil), FinishedAt: vulnNow}}, "not observed"},
		{"other image digest", trivyRow(trivyDoc(t, "nginx@"+other, "ok", sevCounts(3, 0, 0, 0), nil), time.Hour), "not observed"},
		{"malformed", trivyRow(malformed, time.Hour), "not observed"},
		{"precheck", trivyRow(precheck, time.Hour), "not observed"},
		{"no trivy on host", trivyRow(trivyDoc(t, "nginx@"+trivyDigest, "absent", nil, nil), time.Hour), "unknown (absent)"},
		{"database old", trivyRow(trivyDoc(t, "nginx@"+trivyDigest, "stale", nil, nil), time.Hour), "stale"},
		{"result old", trivyRow(trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(0, 0, 1, 0), nil), 72*time.Hour), "stale"},
		{"clean partial scan", trivyRow(trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(0, 0, 0, 0), nil), time.Hour), "none critical or high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// No Hermes run either: nothing may look green.
			f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{{Subject: trivySubject}}}}
			code, body := vulnGet(t, trivyHandler(t, f, tc.results), trivyPath)
			if code != http.StatusOK {
				t.Fatalf("GET = %d", code)
			}
			sec := section(t, body, trivyMarker)
			if !strings.Contains(sec, tc.want) {
				t.Errorf("trivy-local section lacks %q", tc.want)
			}
			badge := section(t, body, badgeMarker)
			for _, s := range []string{sec, badge} {
				if strings.Contains(s, "badge--ok") || strings.Contains(s, "badge--green") {
					t.Errorf("partial or absent observation rendered green: %q", s)
				}
			}
			if tc.want == "not observed" {
				if !strings.Contains(badge, "not observed") || strings.Contains(sec, "0 critical") {
					t.Errorf("absent observation badge = %q, want not observed and no counts", badge)
				}
			}
		})
	}
}

func TestTrivyLocalBadgeSourceSelection(t *testing.T) {
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(2, 1, 0, 0), []trivyTop{{"CVE-2024-0002", "CRITICAL", ""}})
	cases := []struct {
		name    string
		status  ui.VulnSubjectStatus
		results map[string]executions.LastResultRow
		want    []string
		reject  []string
	}{
		{"no Hermes run", ui.VulnSubjectStatus{Subject: trivySubject}, trivyRow(doc, time.Hour),
			[]string{"observer: host Trivy, partial", "2 critical", "badge--critical"}, []string{"observer: Hermes"}},
		{"stale Hermes run", ui.VulnSubjectStatus{Subject: trivySubject, LastComplete: vulnNow.Add(-vulnstore.StaleAfter - time.Minute)}, trivyRow(doc, time.Hour),
			[]string{"observer: host Trivy, partial", "2 critical"}, []string{"observer: Hermes"}},
		{"fresh Hermes run", freshSubject(trivySubject), trivyRow(doc, time.Hour),
			[]string{"observer: Hermes"}, []string{"observer: host Trivy", "2 critical"}},
		{"neither", ui.VulnSubjectStatus{Subject: trivySubject}, nil,
			[]string{"not observed", "badge--unknown"}, []string{"observer: Hermes", "observer: host Trivy"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{tc.status}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: tc.status.LastComplete}}
			_, body := vulnGet(t, trivyHandler(t, f, tc.results), trivyPath)
			badge := section(t, body, badgeMarker)
			for _, w := range tc.want {
				if !strings.Contains(badge, w) {
					t.Errorf("badge lacks %q: %q", w, badge)
				}
			}
			for _, r := range tc.reject {
				if strings.Contains(badge, r) {
					t.Errorf("badge has %q: %q", r, badge)
				}
			}
		})
	}
}

func TestTrivyLocalShownWhenStoreUnavailable(t *testing.T) {
	f := &fakeVuln{err: errors.New("store down")}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(1, 0, 0, 0), []trivyTop{{"CVE-2024-0002", "CRITICAL", ""}})
	_, body := vulnGet(t, trivyHandler(t, f, trivyRow(doc, time.Hour)), trivyPath)
	sec := section(t, body, trivyMarker)
	if !strings.Contains(sec, "1 critical") || !strings.Contains(sec, "Hermes findings unavailable") {
		t.Error("trivy-local observation not shown independently of the finding store")
	}
	badge := section(t, body, badgeMarker)
	if !strings.Contains(badge, "observer: host Trivy, partial") {
		t.Errorf("badge without the store = %q, want the trivy-local observation", badge)
	}
}

func TestTrivyLocalHostileTextEscaped(t *testing.T) {
	f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{{Subject: trivySubject}}}}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(1, 0, 0, 0), []trivyTop{{"CVE-2024-0002", "CRITICAL", hostileScript + hostileImg}})
	_, body := vulnGet(t, trivyHandler(t, f, trivyRow(doc, time.Hour)), trivyPath)
	sec := section(t, body, trivyMarker)
	for _, bad := range []string{"<script>alert", "<img src=x"} {
		if strings.Contains(sec, bad) {
			t.Errorf("trivy-local section renders %q unescaped", bad)
		}
	}
	if !strings.Contains(sec, "&lt;script&gt;") {
		t.Error("hostile fixed version not rendered as text")
	}
}

func TestTrivyLocalOnlyOnImageSubjects(t *testing.T) {
	s := hostSubject("box")
	f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{freshSubject(s)}}}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(1, 0, 0, 0), nil)
	_, body := vulnGet(t, trivyHandler(t, f, trivyRow(doc, time.Hour)), "/vulnerabilities/subject/host/box")
	if strings.Contains(body, trivyMarker) || strings.Contains(body, badgeMarker) {
		t.Error("host subject page shows the per-image trivy-local observation")
	}
}

func TestTrivyLocalTopListBounded(t *testing.T) {
	var top []trivyTop
	for i := range 25 {
		top = append(top, trivyTop{"CVE-2024-" + strconv.Itoa(1000+i), "HIGH", ""})
	}
	f := &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{{Subject: trivySubject}}}}
	doc := trivyDoc(t, "nginx@"+trivyDigest, "ok", sevCounts(0, 40, 0, 0), top)
	_, body := vulnGet(t, trivyHandler(t, f, trivyRow(doc, time.Hour)), trivyPath)
	sec := section(t, body, trivyMarker)
	if !strings.Contains(sec, "top 25 of 40") {
		t.Error("partial top list not labelled with its bound")
	}
}

func TestChartCVELineLabelledHostTrivyPartial(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(1, 0, 0, 0)), time.Hour)},
	})
	if !strings.Contains(body, "host Trivy, partial") {
		t.Error("org-chart CVE line not labelled with its observer")
	}
}
