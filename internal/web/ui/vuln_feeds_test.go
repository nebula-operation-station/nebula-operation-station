// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// inDetails reports whether the first occurrence of text in body lies
// inside a <details> element.
func inDetails(body, text string) bool {
	i := strings.Index(body, text)
	if i < 0 {
		return false
	}
	return strings.LastIndex(body[:i], "<details") > strings.LastIndex(body[:i], "</details>")
}

// TestFeedNotConfiguredIsNoteNotStale: a listed feed no run has named
// (the agent omits it on purpose) is a neutral, collapsible note; a seen
// feed that is past its age stays a plain stale warning.
func TestFeedNotConfiguredIsNoteNotStale(t *testing.T) {
	s := hostSubject("web1")
	row := vulnRow(6, s, "CVE-2024-0006", vulnstore.StateOpen, vulnstore.TierHigh, "nvd", "cisco-csaf")
	f := &fakeVuln{page: ui.VulnPage{
		Rows:     []ui.VulnRow{row},
		Subjects: []ui.VulnSubjectStatus{freshSubject(s)},
		Feeds: []ui.VulnFeedStatus{
			okFeed("debian-tracker"),
			{SourceID: "nvd", Listed: true, Stale: true, LastVerdict: vulnstore.SourceAccepted, SnapshotDate: vulnNow.Add(-100 * time.Hour)},
			{SourceID: "cisco-csaf", Listed: true, Stale: true, Unseen: true},
			{SourceID: "paloalto-csaf", Listed: true, Stale: true, Unseen: true},
		},
		LastComplete: vulnNow,
	}}
	h := vulnHandler(t, f)

	_, body := vulnGet(t, h, "/vulnerabilities")
	if !strings.Contains(body, "Feed nvd stale") || inDetails(body, "Feed nvd stale") {
		t.Error("seen stale feed lacks its plain warning banner")
	}
	for _, want := range []string{"Feed cisco-csaf not configured", "Feed paloalto-csaf not configured", "Cisco network devices", "Palo Alto", "not closed by runs"} {
		if !strings.Contains(body, want) {
			t.Errorf("list page lacks note text %q", want)
		}
	}
	for _, name := range []string{"Feed cisco-csaf not configured", "Feed paloalto-csaf not configured"} {
		if !inDetails(body, name) {
			t.Errorf("%q is not in a collapsible note", name)
		}
	}
	for _, bad := range []string{"feed cisco-csaf stale", "feed paloalto-csaf stale", "Feed cisco-csaf stale", "Feed paloalto-csaf stale"} {
		if strings.Contains(body, bad) {
			t.Errorf("list page calls an omitted feed stale: %q", bad)
		}
	}

	// The finding and its subject name the feed as not configured, and the
	// subject is not green: runs do not close findings resting on it.
	_, body = vulnGet(t, h, "/vulnerabilities/subject/host/web1")
	if !strings.Contains(body, "feed cisco-csaf not configured") {
		t.Error("finding row lacks the not-configured label")
	}
	if strings.Contains(body, "feed cisco-csaf stale") {
		t.Error("finding row calls an omitted feed stale")
	}
	_, body = vulnGet(t, h, "/vulnerabilities?view=subject")
	if strings.Contains(subjectRows(body)["web1"], "badge--ok") {
		t.Error("subject resting on an omitted feed shown green")
	}
}

// TestUnseenFeedKeepsClosuresBlocked: an omitted feed keeps a subject
// without findings from being green, as a stale feed does.
func TestUnseenFeedKeepsClosuresBlocked(t *testing.T) {
	s := hostSubject("quiet")
	f := &fakeVuln{page: ui.VulnPage{
		Subjects:     []ui.VulnSubjectStatus{freshSubject(s)},
		Feeds:        []ui.VulnFeedStatus{okFeed("debian-tracker"), {SourceID: "cisco-csaf", Listed: true, Stale: true, Unseen: true}},
		LastComplete: vulnNow,
	}}
	h := vulnHandler(t, f)
	_, body := vulnGet(t, h, "/vulnerabilities?view=subject")
	if got := subjectRows(body)["quiet"]; strings.Contains(got, "badge--ok") || !strings.Contains(got, "feed issue") {
		t.Errorf("subject under an omitted feed = %q, want feed issue and not green", got)
	}
}

// TestOmittedFeedFindingsFollowStaleFilter: a finding that rests only on a
// not-configured (unseen) feed is in the stale filter of the findings page,
// as the subject list keeps its subject under the same feed issue. A
// finding resting on healthy feeds only is not.
func TestOmittedFeedFindingsFollowStaleFilter(t *testing.T) {
	s := hostSubject("web2")
	omitted := vulnRow(7, s, "CVE-2024-0007", vulnstore.StateOpen, vulnstore.TierHigh, "cisco-csaf")
	healthy := vulnRow(8, s, "CVE-2024-0008", vulnstore.StateOpen, vulnstore.TierHigh, "debian-tracker")
	f := &fakeVuln{page: ui.VulnPage{
		Rows:     []ui.VulnRow{omitted, healthy},
		Subjects: []ui.VulnSubjectStatus{freshSubject(s)},
		Feeds: []ui.VulnFeedStatus{
			okFeed("debian-tracker"),
			{SourceID: "cisco-csaf", Listed: true, Unseen: true},
		},
		LastComplete: vulnNow,
	}}
	h := vulnHandler(t, f)

	_, body := vulnGet(t, h, "/vulnerabilities?stale=stale")
	if !strings.Contains(body, "CVE-2024-0007") {
		t.Error("stale filter drops a finding resting on an omitted feed; the subject list still counts it as a feed issue")
	}
	if strings.Contains(body, "CVE-2024-0008") {
		t.Error("stale filter keeps a finding resting on healthy feeds only")
	}
	_, body = vulnGet(t, h, "/vulnerabilities?view=subject&stale=stale")
	if _, ok := subjectRows(body)["web2"]; !ok {
		t.Error("stale filter drops the subject under an omitted feed")
	}
}
