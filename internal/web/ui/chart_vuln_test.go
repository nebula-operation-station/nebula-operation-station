// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// chartVulnBody renders the chart of the single host "box" with the given
// vulnerabilities backend (nil: none configured) and stored results.
func chartVulnBody(t *testing.T, f *fakeVuln, extra map[string]map[string]executions.LastResultRow) string {
	t.Helper()
	o := linesOptions(t, extra)
	if f != nil {
		o.Vuln = f
	}
	return getBody(t, newTestHandler(t, o).Handler(), "/inventory/chart")
}

// vulnLineRe matches the rendered Hermes host line and captures its state.
var vulnLineRe = regexp.MustCompile(`chart__line chart__line--vuln chart__line--([a-z]+)"`)

// vulnLineState returns the state class of the Hermes host line, "" when
// the line is absent.
func vulnLineState(body string) string {
	m := vulnLineRe.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// chartTime is a timestamp relative to the chart clock.
func chartTime(age time.Duration) time.Time { return linesNow.Add(-age) }

func chartFreshHost() ui.VulnSubjectStatus {
	return ui.VulnSubjectStatus{Subject: hostSubject("box"), LastComplete: chartTime(time.Hour)}
}

func TestChartVulnLineHiddenWithoutBackend(t *testing.T) {
	body := chartVulnBody(t, nil, nil)
	if strings.Contains(body, "chart__line--vuln") {
		t.Error("vuln line rendered without a vulnerabilities backend")
	}
}

func TestChartVulnLineStates(t *testing.T) {
	host := hostSubject("box")
	stale := ui.VulnSubjectStatus{Subject: host, LastComplete: chartTime(vulnstore.StaleAfter + time.Hour)}
	cases := []struct {
		name   string
		page   ui.VulnPage
		state  string
		border string
		want   []string
	}{
		{
			name:  "not assessed: subject unknown to Hermes",
			page:  ui.VulnPage{Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}},
			state: "unknown", border: "chart__node--neutral",
			want: []string{"Hermes · not assessed"},
		},
		{
			name:  "not assessed: zero last complete run",
			page:  ui.VulnPage{Subjects: []ui.VulnSubjectStatus{{Subject: host}}},
			state: "unknown", border: "chart__node--neutral",
			want: []string{"Hermes · not assessed"},
		},
		{
			name:  "fresh and clean",
			page:  ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, LastComplete: chartTime(time.Hour)},
			state: "ok", border: "chart__node--neutral",
			want: []string{"Hermes · no open findings"},
		},
		{
			name: "stale run, no findings",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{stale}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}},
			// stale is labelled and grey, never green.
			state: "stale", border: "chart__node--neutral",
			want: []string{"Hermes · stale since "},
		},
		{
			name: "stale run with a medium open finding",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{stale}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")},
				Rows: []ui.VulnRow{vulnRow(1, host, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierMedium, "debian-tracker")}},
			state: "stale", border: "chart__node--neutral",
			want: []string{"stale since ", "1 open"},
		},
		{
			name: "stale run keeps a critical open finding red",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{stale}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")},
				Rows: []ui.VulnRow{vulnRow(1, host, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierCritical, "debian-tracker")}},
			state: "crit", border: "chart__node--critical",
			want: []string{"stale since ", "1 open", "top critical"},
		},
		{
			name: "fresh with a critical open finding",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")},
				Rows: []ui.VulnRow{
					vulnRow(1, host, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierCritical, "debian-tracker"),
					vulnRow(2, host, "CVE-2024-0002", vulnstore.StateOpen, vulnstore.TierLow, "debian-tracker"),
				}},
			state: "crit", border: "chart__node--critical",
			want: []string{"Hermes · 2 open, critical", "top critical"},
		},
		{
			name: "fresh with a high open finding",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")},
				Rows: []ui.VulnRow{vulnRow(1, host, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")}},
			state: "warn", border: "chart__node--warning",
			want: []string{"Hermes · 1 open", "top high"},
		},
		{
			name: "closed by Hermes, not confirmed",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")},
				Rows: []ui.VulnRow{func() ui.VulnRow {
					r := vulnRow(1, host, "CVE-2024-0001", vulnstore.StateFixed, vulnstore.TierLow, "debian-tracker")
					r.Finding.ClosedBy = vulnstore.ClosedByHermesUnconfirmed
					return r
				}()}},
			state: "warn", border: "chart__node--warning",
			want: []string{"closed by Hermes, not confirmed by NOS"},
		},
		{
			name:  "stale feed on the page",
			page:  ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{{SourceID: "debian-tracker", Listed: true, Stale: true}}},
			state: "warn", border: "chart__node--warning",
			want: []string{"Hermes · feed issue"},
		},
		{
			name:  "feed on probation",
			page:  ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{{SourceID: "kev", Listed: true, LastVerdict: vulnstore.SourceAccepted, Probation: true}}},
			state: "warn", border: "chart__node--warning",
			want: []string{"Hermes · feed issue"},
		},
		{
			name:  "unknown feed verdict",
			page:  ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{{SourceID: "kev", Listed: true, LastVerdict: vulnstore.SourceUnknown}}},
			state: "warn", border: "chart__node--warning",
			want: []string{"Hermes · feed issue"},
		},
		{
			name: "finding resting on an unlisted source",
			page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()},
				Rows: []ui.VulnRow{func() ui.VulnRow {
					r := vulnRow(1, host, "CVE-2024-0001", vulnstore.StateFixed, vulnstore.TierLow, "mystery")
					r.Finding.ClosedBy = vulnstore.ClosedByNOSInventory
					return r
				}()}},
			state: "warn", border: "chart__node--warning",
			want: []string{"Hermes · feed issue"},
		},
		{
			name:  "truncated read",
			page:  ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, Truncated: true},
			state: "unknown", border: "chart__node--neutral",
			want: []string{"Hermes · unknown: list incomplete"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := chartVulnBody(t, &fakeVuln{page: tc.page}, nil)
			if got := vulnLineState(body); got != tc.state {
				t.Errorf("vuln line state = %q, want %q", got, tc.state)
			}
			if !hostNodeHas(body, tc.border) {
				t.Errorf("border should be %s", tc.border)
			}
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("chart body missing %q", w)
				}
			}
			if tc.state != "ok" && strings.Contains(body, "no open findings") {
				t.Error("an untrusted subject reads \"no open findings\"")
			}
			if strings.Contains(body, "0 open") {
				t.Error("a count of zero is rendered instead of a status")
			}
		})
	}
}

func TestChartVulnLineReadFailureIsUnknown(t *testing.T) {
	body := chartVulnBody(t, &fakeVuln{err: errors.New("db down: /var/lib/secret")}, nil)
	if got := vulnLineState(body); got != "unknown" {
		t.Errorf("vuln line state = %q, want unknown", got)
	}
	if !strings.Contains(body, "Hermes · unknown (read failed)") {
		t.Error("read failure not labelled")
	}
	if strings.Contains(body, "/var/lib/secret") {
		t.Error("backend error detail leaked into the page")
	}
}

func TestChartVulnLineTitleNamesObserverAndFormula(t *testing.T) {
	page := ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")},
		Rows: []ui.VulnRow{vulnRow(1, hostSubject("box"), "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")}}
	body := chartVulnBody(t, &fakeVuln{page: page}, nil)
	for _, w := range []string{"observer Hermes", "priority vu-prio-v1", "assessed 2026-10-01 11:00 UTC"} {
		if !strings.Contains(body, w) {
			t.Errorf("vuln line title missing %q", w)
		}
	}
}

func TestChartVulnLineEscapesSubjectText(t *testing.T) {
	host := hostSubject("box")
	r := vulnRow(1, host, "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierHigh, "<script>x</script>")
	page := ui.VulnPage{Subjects: []ui.VulnSubjectStatus{{Subject: host, Name: "<b>evil</b>", LastComplete: chartTime(time.Hour)}}, Rows: []ui.VulnRow{r}}
	body := chartVulnBody(t, &fakeVuln{page: page}, nil)
	if strings.Contains(body, "<script>x</script>") || strings.Contains(body, "<b>evil</b>") {
		t.Error("untrusted text rendered as HTML")
	}
}

// imageSubject is the Hermes image subject of the scanned P1-30 image.
func imageSubject(hostID string) vulnstore.Subject {
	return vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: hostID, ImageDigest: "sha256:" + strings.Repeat("0123456789abcdef", 4)}
}

func TestChartCVEPlaceSelectsHermesWhenFresh(t *testing.T) {
	img := imageSubject("box")
	page := ui.VulnPage{
		Subjects: []ui.VulnSubjectStatus{chartFreshHost(), {Subject: img, LastComplete: chartTime(time.Hour)}},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")},
		Rows:     []ui.VulnRow{vulnRow(1, img, "CVE-2024-0009", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")},
	}
	body := chartVulnBody(t, &fakeVuln{page: page}, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(2, 5, 10, 3)), time.Hour)},
	})
	if !strings.Contains(body, "Hermes · nginx@0123456789ab · 1 open") {
		t.Error("fresh Hermes image findings not shown in the CVE place")
	}
	if strings.Contains(body, "2 critical · 5 high") {
		t.Error("P1-30 counts shown although a fresh complete Hermes run covers the image")
	}
	if !strings.Contains(body, `chart__line chart__line--cve chart__line--warn`) {
		t.Error("Hermes CVE line should be warn (high tier)")
	}
}

func TestChartCVEPlaceFallsBackToTrivyLabelled(t *testing.T) {
	img := imageSubject("box")
	cases := map[string]ui.VulnPage{
		"no Hermes image subject": {Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}},
		"stale Hermes image run": {
			Subjects: []ui.VulnSubjectStatus{chartFreshHost(), {Subject: img, LastComplete: chartTime(vulnstore.StaleAfter + time.Hour)}},
			Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")},
		},
		"image not assessed": {Subjects: []ui.VulnSubjectStatus{chartFreshHost(), {Subject: img}}},
	}
	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			body := chartVulnBody(t, &fakeVuln{page: page}, map[string]map[string]executions.LastResultRow{
				"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(2, 5, 10, 3)), time.Hour)},
			})
			if !strings.Contains(body, "nginx@0123456789ab · 2 critical · 5 high · 10 medium · 3 low · host Trivy, partial") {
				t.Error("P1-30 counts not shown with their observer label")
			}
			if strings.Contains(body, "Hermes · nginx@") {
				t.Error("Hermes image line shown without a fresh complete run")
			}
		})
	}
}

func TestChartTrivyLineLabelledWithoutBackend(t *testing.T) {
	body := chartVulnBody(t, nil, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(0, 0, 1, 0)), time.Hour)},
	})
	if !strings.Contains(body, "host Trivy, partial") {
		t.Error("P1-30 line without observer label")
	}
}

func TestChartHermesImageLinesWithoutScan(t *testing.T) {
	img := imageSubject("box")
	other := vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "box", ImageDigest: "sha256:" + strings.Repeat("f", 64)}
	page := ui.VulnPage{
		Subjects: []ui.VulnSubjectStatus{chartFreshHost(), {Subject: img, LastComplete: chartTime(vulnstore.StaleAfter + time.Hour)}, {Subject: other}},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")},
	}
	body := chartVulnBody(t, &fakeVuln{page: page}, nil)
	for _, w := range []string{
		"Hermes · sha256:0123456789ab · stale since ",
		"Hermes · sha256:ffffffffffff · not assessed",
	} {
		if !strings.Contains(body, w) {
			t.Errorf("chart body missing %q", w)
		}
	}
	if strings.Contains(body, "chart__line--cve chart__line--ok") {
		t.Error("stale or unassessed image rendered green")
	}
}
