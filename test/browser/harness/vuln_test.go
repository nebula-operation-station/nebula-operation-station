// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"text/template"
)

// The pages vuln.spec.js opens, with the hostile values each must show
// (escaped) and the subject status it must show.
var vulnSpecPages = []struct {
	path   string
	shows  []string
	status string // regexp of the subject status badge; empty: none
	green  bool
}{
	{path: "/vulnerabilities?state=all", shows: []string{vulnHostileID, vulnHostileSource}},
	{path: "/vulnerabilities?view=subject", shows: []string{vulnHostName, vulnTwoName}},
	{path: "/vulnerabilities/cve/CVE-2026-1111", shows: []string{vulnHostName, vulnHostilePackage, vulnHostileSource}},
	{path: "/vulnerabilities/subject/host/e2e-host", shows: []string{vulnHostName, vulnHostileID, vulnHostileVersion, vulnHostilePackage}, status: `open, critical$`},
	{path: "/vulnerabilities/subject/host/e2e-two", shows: []string{vulnTwoName}, status: `^not assessed$`},
	{path: "/vulnerabilities/subject/image/e2e-host?digest=" + vulnImageDigest, status: `^stale since `},
	{path: "/vulnerabilities/subject/host/e2e-unconf", status: `closed by Hermes, not confirmed by NOS$`},
	{path: "/vulnerabilities/subject/host/e2e-clean", status: `^no open findings$`, green: true},
	{path: "/vulnerabilities/subject/host/e2e-unknown", status: `^not assessed$`},
	{path: "/vulnerabilities/f/" + vulnKeyCritical.String(), shows: []string{vulnAssessment, vulnHostileAlias, vulnHostileRun, vulnHostileVersion}},
	{path: "/vulnerabilities/f/" + vulnKeyHostile.String(), shows: []string{vulnMarkdownText, vulnHostileID}},
	{path: "/vulnerabilities/f/" + vulnKeyNotRun.String(), shows: []string{"esc�[31m bidi�evil", "not assessed"}},
	{path: "/vulnerabilities/f/" + vulnKeyStale.String(), shows: []string{vulnHostileSource}},
	{path: "/vulnerabilities/f/" + vulnKeyUnconf.String(), shows: []string{"closed by Hermes, not confirmed by NOS"}},
}

var (
	vulnHrefRe   = regexp.MustCompile(`(?:href|action)="([^"]*)"`)
	vulnStatusRe = regexp.MustCompile(`class="badge (badge--[a-z]+) vuln-status">([^<]*)<`)
)

// TestHarnessVulnPagesShowHostileValuesAsText checks, without a browser,
// what vuln.spec.js relies on: every page it opens answers 200 under the
// strict CSP, each hostile value is present only HTML-escaped (never as
// markup), control and bidi characters are replaced, links and form
// targets are NOS paths, and only the clean subject's own page is green.
func TestHarnessVulnPagesShowHostileValuesAsText(t *testing.T) {
	h := newHarness(true, "8080", t.TempDir())
	raw := []string{vulnHostName, vulnTwoName, vulnAssessment, vulnMarkdownText, vulnHostileID, vulnHostilePackage,
		vulnHostileAlias, vulnHostileSource, vulnHostileRun, vulnHostileVersion, "<iframe", "\x1b", "‮"}
	for _, p := range vulnSpecPages {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p.path, nil))
		body := rec.Body.String()
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p.path, rec.Code)
			continue
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("GET %s: CSP %q", p.path, csp)
		}
		for _, r := range raw {
			if strings.Contains(body, r) {
				t.Errorf("GET %s contains the raw hostile value %q", p.path, r)
			}
		}
		for _, s := range p.shows {
			if !strings.Contains(body, template.HTMLEscapeString(s)) {
				t.Errorf("GET %s does not show %q as escaped text", p.path, s)
			}
		}
		for _, m := range vulnHrefRe.FindAllStringSubmatch(body, -1) {
			if u := m[1]; !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") || strings.Contains(strings.ToLower(u), "javascript") || strings.Contains(u, "evil") {
				t.Errorf("GET %s: link or form target %q is not a NOS path", p.path, u)
			}
		}
		if strings.Contains(body, "evil.example") && !strings.Contains(body, template.HTMLEscapeString(vulnAssessment)) &&
			!strings.Contains(body, template.HTMLEscapeString(vulnMarkdownText)) {
			t.Errorf("GET %s shows evil.example outside the assessment text", p.path)
		}
		statuses := vulnStatusRe.FindAllStringSubmatch(body, -1)
		for _, s := range statuses {
			if s[1] == "badge--ok" && !p.green {
				t.Errorf("GET %s: subject status %q is green", p.path, s[2])
			}
		}
		if p.status != "" {
			// The subject summary; image pages also show the host Trivy
			// panel's own status badges before it.
			_, summary, _ := strings.Cut(body, `class="panel vuln-subject-summary"`)
			statuses = vulnStatusRe.FindAllStringSubmatch(summary, 1)
			if len(statuses) != 1 || !regexp.MustCompile(p.status).MatchString(statuses[0][2]) || (statuses[0][1] == "badge--ok") != p.green {
				t.Errorf("GET %s: subject status %v, want %s (green %v)", p.path, statuses, p.status, p.green)
			}
		}
	}
	// The list by subject shows every subject and none of them green (the
	// unlisted feed is a page-wide feed issue).
	_, body := get(t, h, "/vulnerabilities?view=subject")
	st := vulnStatusRe.FindAllStringSubmatch(body, -1)
	if len(st) != 5 {
		t.Fatalf("list by subject: %d statuses, want 5", len(st))
	}
	if !strings.Contains(body, ">feed issue<") {
		t.Error("list by subject: the clean subject does not show the feed issue")
	}
}
