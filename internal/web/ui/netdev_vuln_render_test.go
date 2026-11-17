// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// netdevVulnStub serves one fixed vulnerability page to the device pages.
type netdevVulnStub struct {
	page ui.VulnPage
}

func (s netdevVulnStub) VulnFindings(context.Context, ui.VulnQuery) (ui.VulnPage, error) {
	return s.page, nil
}

func (s netdevVulnStub) VulnFinding(context.Context, vulnfinding.Key) (ui.VulnFindingDetail, error) {
	return ui.VulnFindingDetail{}, errors.New("not used")
}

func (s netdevVulnStub) VulnMarkResetCandidate(context.Context, string) (vulnstore.MarkResetView, error) {
	return vulnstore.MarkResetView{}, errors.New("not used")
}

func (s netdevVulnStub) VulnMaintainer(context.Context, string) (bool, error) { return false, nil }

func (s netdevVulnStub) BeginVulnDecision(context.Context, string, ui.VulnDecision) (ui.VulnChallenge, error) {
	return ui.VulnChallenge{}, errors.New("not used")
}

func (s netdevVulnStub) CommitVulnDecision(context.Context, string, string, ui.VulnDecision, []byte) error {
	return errors.New("not used")
}

// renderFinding is a stored open device finding of switch sw1.
func renderFinding(vulnID string) vulnstore.Finding {
	return vulnstore.Finding{
		Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "sw1"},
		Record: vulnfinding.Record{SubjectKind: vulnfinding.SubjectDevice, SubjectRef: vulnfinding.SubjectRef{ID: "sw1"},
			Ecosystem: "vendor:cisco:cbs", Component: vulnfinding.Component{Model: "CBS350-24P", Firmware: "3.4.0.17"},
			Vuln: vulnfinding.Vuln{ID: vulnID}, Fix: vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.4.1.3"},
			MatchBasis: vulnfinding.MatchVendorAdvisory},
		State: vulnstore.StateOpen,
	}
}

// renderPage is a vulnerability page for switch sw1 last completed at
// lastComplete, with the given rows and feed statuses.
func renderPage(lastComplete time.Time, feeds []ui.VulnFeedStatus, rows ...ui.VulnRow) ui.VulnPage {
	return ui.VulnPage{
		Rows:  rows,
		Feeds: feeds,
		Subjects: []ui.VulnSubjectStatus{{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "sw1"},
			LastComplete: lastComplete}},
	}
}

// newVulnRenderEnv serves the detail page of a CBS switch sw1 whose
// vulnerability page is page, and returns the page body.
func newVulnRenderEnv(t *testing.T, page ui.VulnPage) string {
	t.Helper()
	e := newNetDevEnvVuln(t, nil, io.Discard, netdevVulnStub{page: page})
	e.addCBS("sw1", "Core")
	e.store.facts["sw1"] = netdevcontract.Facts{Model: "CBS350-24P", FirmwareVersion: "3.4.0.17", Serial: "SN1"}
	_, body := e.get("/netdev/sw1")
	return body
}

// TestDeviceVulnBlockRendersFindingsAndLinkOnPage: the device page renders
// the vendor findings with the Hermes observer label, the NOS-built advisory
// link and the coverage line, under the same CSP as every netdev page.
func TestDeviceVulnBlockRendersFindingsAndLinkOnPage(t *testing.T) {
	page := renderPage(netdevNow.Add(-time.Hour), nil, ui.VulnRow{Finding: renderFinding("cisco-sa-cbs-xss-2024")})
	body := newVulnRenderEnv(t, page)
	for _, want := range []string{`id="vendor-advisories"`, "Observed by Hermes", "Coverage: assessed",
		`class="vuln-finding"`, ">cisco-sa-cbs-xss-2024</a>", "vuln-fix-link"} {
		if !strings.Contains(body, want) {
			t.Errorf("device page misses %q", want)
		}
	}
	if strings.Contains(body, "No finding is stored") {
		t.Error("device with a finding shows the empty-findings text")
	}
}

// TestDeviceVulnBlockCoverageUnknownOnPage: a device without a complete run
// shows "coverage unknown" with the warning style and never the clean text.
func TestDeviceVulnBlockCoverageUnknownOnPage(t *testing.T) {
	body := newVulnRenderEnv(t, renderPage(time.Time{}, nil))
	if !strings.Contains(body, `class="status status--warning vuln-coverage"`) ||
		!strings.Contains(body, "Coverage: coverage unknown") {
		t.Fatalf("device page without a run misses the coverage unknown warning")
	}
	if !strings.Contains(body, "No finding is stored for this device.") {
		t.Error("device page misses the no-finding text that does not read as clean")
	}
}

// TestDeviceVulnBlockStaleVendorFeedWarnsOnPage: a recent run does not make
// the coverage assessed while the device's vendor feed is stale (ADR 0011
// D4): the page says coverage unknown and names the feed.
func TestDeviceVulnBlockStaleVendorFeedWarnsOnPage(t *testing.T) {
	feeds := []ui.VulnFeedStatus{{SourceID: "cisco-csaf", Listed: true, Stale: true}}
	body := newVulnRenderEnv(t, renderPage(netdevNow.Add(-time.Hour), feeds))
	if strings.Contains(body, "Coverage: assessed") {
		t.Fatal("device page reads assessed while its vendor feed is stale")
	}
	if !strings.Contains(body, "Coverage: coverage unknown") || !strings.Contains(body, "cisco-csaf") {
		t.Errorf("stale vendor feed not named on the device page")
	}
}

// TestDeviceVulnBlockHostileAdvisoryIDIsEscaped: an advisory ID from the
// feed is shown as escaped text and gets no link.
func TestDeviceVulnBlockHostileAdvisoryIDIsEscaped(t *testing.T) {
	hostile := `<script>alert(1)</script>`
	body := newVulnRenderEnv(t, renderPage(netdevNow.Add(-time.Hour), nil, ui.VulnRow{Finding: renderFinding(hostile)}))
	assertNoHostileMarkup(t, body)
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("hostile advisory ID not shown as escaped text")
	}
}
