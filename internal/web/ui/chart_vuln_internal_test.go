// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

var chartVulnNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func chartHostSubject(id string) vulnstore.Subject {
	return vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: id}
}

func chartImageSubject(host string, b byte) vulnstore.Subject {
	return vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: host, ImageDigest: "sha256:" + strings.Repeat(string(b), 64)}
}

func TestChartVulnHostLineLinksToSubjectPage(t *testing.T) {
	idx := newChartVulnIndex(VulnPage{Subjects: []VulnSubjectStatus{{Subject: chartHostSubject("box"), LastComplete: chartVulnNow.Add(-time.Hour)}}}, nil, chartVulnNow)
	lines := idx.hostLines("box")
	if len(lines) != 1 {
		t.Fatalf("lines = %d, want 1", len(lines))
	}
	if want := "/vulnerabilities/subject/host/box"; lines[0].URL != want {
		t.Errorf("URL = %q, want %q", lines[0].URL, want)
	}
	if lines[0].Kind != LineVuln || lines[0].Label != "Vulns" {
		t.Errorf("line = %+v", lines[0])
	}
}

func TestChartVulnReadFailureLinksToList(t *testing.T) {
	idx := newChartVulnIndex(VulnPage{}, fmt.Errorf("boom"), chartVulnNow)
	lines := idx.hostLines("box")
	if len(lines) != 1 || lines[0].State != StateUnknown || lines[0].URL != "/vulnerabilities" {
		t.Errorf("lines = %+v", lines)
	}
}

func TestChartVulnNilIndexHasNoLines(t *testing.T) {
	var idx *chartVulnIndex
	if got := idx.hostLines("box"); got != nil {
		t.Errorf("nil index lines = %+v", got)
	}
	if got := idx.imageLines("box", ""); got != nil {
		t.Errorf("nil index image lines = %+v", got)
	}
}

func TestChartVulnGuestLinkedToHostGetsHostLine(t *testing.T) {
	idx := newChartVulnIndex(VulnPage{}, nil, chartVulnNow)
	res := chartResults{hermes: idx}
	linked := guestLines(res, pveGuestView{Name: "g", VMID: 100, HostID: "box"}, chartVulnNow)
	if len(linked) != 1 || linked[0].Kind != LineVuln || linked[0].State != StateUnknown {
		t.Fatalf("linked guest lines = %+v", linked)
	}
	if !strings.Contains(linked[0].Text, labelNotAssessed) {
		t.Errorf("text = %q", linked[0].Text)
	}
	if unlinked := guestLines(res, pveGuestView{Name: "g", VMID: 101}, chartVulnNow); len(unlinked) != 0 {
		t.Errorf("unlinked guest lines = %+v", unlinked)
	}
}

func TestChartVulnImageLinesBounded(t *testing.T) {
	var subjects []VulnSubjectStatus
	for i := 0; i < maxChartImageLines+3; i++ {
		subjects = append(subjects, VulnSubjectStatus{Subject: chartImageSubject("box", "abcdef0123"[i])})
	}
	// An image of another host never shows on this box.
	subjects = append(subjects, VulnSubjectStatus{Subject: chartImageSubject("other", '9')})
	idx := newChartVulnIndex(VulnPage{Subjects: subjects}, nil, chartVulnNow)
	lines := idx.imageLines("box", "")
	if len(lines) != maxChartImageLines+1 {
		t.Fatalf("lines = %d, want %d", len(lines), maxChartImageLines+1)
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last.Text, "3 more images") || last.State != StateUnknown {
		t.Errorf("summary line = %+v", last)
	}
	if last.URL != "/vulnerabilities?view=subject&kind=image&state=all" {
		t.Errorf("summary URL = %q", last.URL)
	}
	for _, l := range lines[:maxChartImageLines] {
		if !strings.HasPrefix(l.URL, "/vulnerabilities/subject/image/box?digest=sha256%3A") {
			t.Errorf("image URL = %q", l.URL)
		}
		if l.Kind != LineCVE {
			t.Errorf("image line kind = %q, want the CVE place", l.Kind)
		}
	}
}

func TestChartVulnImageMoreLineTakesWorstState(t *testing.T) {
	var subjects []VulnSubjectStatus
	var rows []VulnRow
	for i := 0; i < maxChartImageLines+1; i++ {
		s := chartImageSubject("box", "abcde"[i])
		subjects = append(subjects, VulnSubjectStatus{Subject: s, LastComplete: chartVulnNow.Add(-time.Hour)})
		if i == maxChartImageLines {
			rows = append(rows, VulnRow{Tier: vulnstore.TierCritical, Finding: vulnstore.Finding{Subject: s, State: vulnstore.StateOpen, NOSChecked: true}})
		}
	}
	idx := newChartVulnIndex(VulnPage{Subjects: subjects, Rows: rows, Feeds: []VulnFeedStatus{}}, nil, chartVulnNow)
	lines := idx.imageLines("box", "")
	if last := lines[len(lines)-1]; last.State != StateCrit {
		t.Errorf("summary state = %s, want crit", last.State)
	}
}

func TestDigestOfImageRef(t *testing.T) {
	hex := strings.Repeat("0123456789abcdef", 4)
	cases := map[string]string{
		"nginx@sha256:" + hex:                  "sha256:" + hex,
		"nginx:1.25":                           "",
		"nginx@sha256:short":                   "",
		"nginx@sha256:" + hex + "x":            "",
		"nginx@sha256:" + strings.ToUpper(hex): "",
	}
	for in, want := range cases {
		if got := digestOfImageRef(in); got != want {
			t.Errorf("digestOfImageRef(%q) = %q, want %q", in, got, want)
		}
	}
}
