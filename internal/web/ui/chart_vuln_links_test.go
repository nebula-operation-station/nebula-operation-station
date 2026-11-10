// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// lineLink is the rendered markup of a linked chart line text: the href
// as html/template writes it, followed by the line text.
func lineLink(href, text string) string {
	return `<a class="chart__line-text chart__line-link" href="` + href + `">` + text
}

// chartImage is a Hermes image subject of host "box" whose digest repeats
// the hex digit b.
func chartImage(b string) vulnstore.Subject {
	return vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: "box", ImageDigest: "sha256:" + strings.Repeat(b, 64)}
}

// imageHref is the rendered href of an image subject page.
func imageHref(b string) string {
	return "/vulnerabilities/subject/image/box?digest=sha256%3A" + strings.Repeat(b, 64)
}

// moreImagesHref is the rendered href of the image subject list.
const moreImagesHref = "/vulnerabilities?view=subject&amp;kind=image&amp;state=all"

// sixImagesPage has a fresh host and six fresh Hermes image subjects of
// host "box": four image lines and one "more images" line.
func sixImagesPage(truncated bool) ui.VulnPage {
	p := ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}, Truncated: truncated}
	for _, b := range []string{"1", "2", "3", "4", "5", "6"} {
		p.Subjects = append(p.Subjects, ui.VulnSubjectStatus{Subject: chartImage(b), LastComplete: chartTime(time.Hour)})
	}
	return p
}

func TestChartVulnHostLineRendersSubjectLink(t *testing.T) {
	body := chartVulnBody(t, &fakeVuln{page: ui.VulnPage{Subjects: []ui.VulnSubjectStatus{chartFreshHost()}, Feeds: []ui.VulnFeedStatus{okFeed("debian-tracker")}}}, nil)
	if want := lineLink("/vulnerabilities/subject/host/box", "Hermes · no open findings"); !strings.Contains(body, want) {
		t.Errorf("chart body missing host line link %q", want)
	}
}

func TestChartVulnReadFailureRendersListLink(t *testing.T) {
	body := chartVulnBody(t, &fakeVuln{err: errors.New("db down")}, nil)
	if want := lineLink("/vulnerabilities", "Hermes · unknown (read failed)"); !strings.Contains(body, want) {
		t.Errorf("chart body missing read-failure link %q", want)
	}
}

func TestChartVulnImageLinesRenderSubjectLinks(t *testing.T) {
	body := chartVulnBody(t, &fakeVuln{page: sixImagesPage(false)}, nil)
	for _, b := range []string{"1", "2", "3", "4"} {
		want := lineLink(imageHref(b), "Hermes · sha256:"+strings.Repeat(b, 12)+" · no open findings")
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing image line link %q", want)
		}
	}
	if want := lineLink(moreImagesHref, "Hermes · 2 more images"); !strings.Contains(body, want) {
		t.Errorf("chart body missing more-images link %q", want)
	}
}

func TestChartHermesImageInCVEPlaceRendersLink(t *testing.T) {
	img := imageSubject("box")
	page := ui.VulnPage{
		Subjects: []ui.VulnSubjectStatus{chartFreshHost(), {Subject: img, LastComplete: chartTime(time.Hour)}},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")},
	}
	body := chartVulnBody(t, &fakeVuln{page: page}, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(2, 5, 10, 3)), time.Hour)},
	})
	href := "/vulnerabilities/subject/image/box?digest=sha256%3A" + strings.Repeat("0123456789abcdef", 4)
	if want := lineLink(href, "Hermes · nginx@0123456789ab · no open findings"); !strings.Contains(body, want) {
		t.Errorf("chart body missing CVE place link %q", want)
	}
}

// TestChartVulnGuestBoxRendersHostLink: a PVE guest linked to the managed
// host "box" renders that host's Hermes line with its subject link on
// /inventory/chart (beside the host box's own line); an unlinked guest
// renders none.
func TestChartVulnGuestBoxRendersHostLink(t *testing.T) {
	tree := pveinventory.Tree{Roots: []pveinventory.Box{{
		Kind: pveinventory.KindPVENode, Name: "pve1", RemoteID: "lab",
		State: pveinventory.StateOK, Worst: pveinventory.StateOK,
		Children: []pveinventory.Box{
			{Kind: pveinventory.KindGuest, Name: "linked", VMID: 101, Generation: 1, HostID: "box", State: pveinventory.StateOK, Worst: pveinventory.StateOK},
			{Kind: pveinventory.KindGuest, Name: "plain", VMID: 102, Generation: 1, State: pveinventory.StateOK, Worst: pveinventory.StateOK},
		},
	}}}
	page := ui.VulnPage{
		Subjects: []ui.VulnSubjectStatus{chartFreshHost()},
		Feeds:    []ui.VulnFeedStatus{okFeed("debian-tracker")},
		Rows:     []ui.VulnRow{vulnRow(1, hostSubject("box"), "CVE-2024-0001", vulnstore.StateOpen, vulnstore.TierCritical, "debian-tracker")},
	}
	o := linesOptions(t, nil)
	o.Vuln = &fakeVuln{page: page}
	o.PVEChart = func(context.Context) (pveinventory.Tree, error) { return tree, nil }
	body := getBody(t, newTestHandler(t, o).Handler(), "/inventory/chart")
	want := lineLink("/vulnerabilities/subject/host/box", "Hermes · 1 open, critical")
	if got := strings.Count(body, want); got != 2 {
		t.Errorf("host line links %q = %d, want 2 (host box and linked guest)", want, got)
	}
	if got := strings.Count(body, "chart__line--vuln chart__line--crit"); got != 2 {
		t.Errorf("crit vuln lines = %d, want 2 (unlinked guest has none)", got)
	}
}

// chartLineLinkRe matches every rendered line link and captures its href.
var chartLineLinkRe = regexp.MustCompile(`<a class="chart__line-text chart__line-link" href="([^"]*)">`)

func TestChartLinesWithoutURLRenderNoLink(t *testing.T) {
	// Without a vulnerabilities backend only the P1-30 line exists, which
	// carries no URL: no line link at all.
	body := chartVulnBody(t, nil, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(0, 0, 1, 0)), time.Hour)},
	})
	if m := chartLineLinkRe.FindAllString(body, -1); len(m) != 0 {
		t.Errorf("line links rendered without a URL: %q", m)
	}
	if !strings.Contains(body, `<span class="chart__line-text">nginx@0123456789ab · 0 critical`) {
		t.Error("unlinked line text not rendered as a span")
	}
}

func TestChartLineLinksAreNOSPaths(t *testing.T) {
	body := chartVulnBody(t, &fakeVuln{page: sixImagesPage(false)}, nil)
	links := chartLineLinkRe.FindAllStringSubmatch(body, -1)
	if len(links) != 6 { // host, four images, more images
		t.Fatalf("line links = %d, want 6", len(links))
	}
	for _, l := range links {
		if !strings.HasPrefix(l[1], "/vulnerabilities") {
			t.Errorf("line link %q is not a NOS vulnerabilities path", l[1])
		}
	}
}

func TestChartImageLinesSayIncompleteWhenTruncated(t *testing.T) {
	body := chartVulnBody(t, &fakeVuln{page: sixImagesPage(true)}, nil)
	for _, b := range []string{"1", "2", "3", "4"} {
		want := lineLink(imageHref(b), "Hermes · sha256:"+strings.Repeat(b, 12)+" · unknown: list incomplete")
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing incomplete image line %q", want)
		}
	}
	if want := lineLink(moreImagesHref, "Hermes · at least 2 more images · list incomplete"); !strings.Contains(body, want) {
		t.Errorf("chart body missing incomplete more-images line %q", want)
	}
}

func TestChartImageListMarkedIncompleteWhenTruncatedWithoutMore(t *testing.T) {
	// One image shown, none hidden: the truncated read may still have
	// dropped image subjects, so a line says the list is incomplete.
	page := ui.VulnPage{
		Subjects:  []ui.VulnSubjectStatus{chartFreshHost(), {Subject: chartImage("1"), LastComplete: chartTime(time.Hour)}},
		Feeds:     []ui.VulnFeedStatus{okFeed("debian-tracker")},
		Truncated: true,
	}
	body := chartVulnBody(t, &fakeVuln{page: page}, nil)
	if want := lineLink(moreImagesHref, "Hermes · image list incomplete"); !strings.Contains(body, want) {
		t.Errorf("chart body missing image-list-incomplete line %q", want)
	}
	if strings.Contains(body, "chart__line--cve chart__line--ok") {
		t.Error("image line green on a truncated read")
	}
}

func TestChartStaleImageSaysIncompleteWhenTruncated(t *testing.T) {
	page := ui.VulnPage{
		Subjects:  []ui.VulnSubjectStatus{chartFreshHost(), {Subject: chartImage("1"), LastComplete: chartTime(vulnstore.StaleAfter + time.Hour)}},
		Feeds:     []ui.VulnFeedStatus{okFeed("debian-tracker")},
		Truncated: true,
	}
	body := chartVulnBody(t, &fakeVuln{page: page}, nil)
	re := regexp.MustCompile(`Hermes · sha256:111111111111 · stale since [^<]* · list incomplete<`)
	if !re.MatchString(body) {
		t.Error("stale image line on a truncated read does not say the list is incomplete")
	}
}
