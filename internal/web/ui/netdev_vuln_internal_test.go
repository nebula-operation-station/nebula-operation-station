// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// devVulnStub is a VulnFindings backend with one fixed page or error.
type devVulnStub struct {
	page VulnPage
	err  error
}

func (s devVulnStub) VulnFindings(context.Context, VulnQuery) (VulnPage, error) { return s.page, s.err }

func (s devVulnStub) VulnFinding(context.Context, vulnfinding.Key) (VulnFindingDetail, error) {
	return VulnFindingDetail{}, errors.New("not used")
}

func (s devVulnStub) VulnMarkResetCandidate(context.Context, string) (vulnstore.MarkResetView, error) {
	return vulnstore.MarkResetView{}, errors.New("not used")
}

func (s devVulnStub) VulnMaintainer(context.Context, string) (bool, error) { return false, nil }

func (s devVulnStub) BeginVulnDecision(context.Context, string, VulnDecision) (VulnChallenge, error) {
	return VulnChallenge{}, errors.New("not used")
}

func (s devVulnStub) CommitVulnDecision(context.Context, string, string, VulnDecision, []byte) error {
	return errors.New("not used")
}

// devFinding is a stored device finding of device id from a Cisco or Palo
// Alto advisory ID.
func devFinding(id, eco, vulnID string, state vulnstore.State) vulnstore.Finding {
	return vulnstore.Finding{
		Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: id},
		Record: vulnfinding.Record{SubjectKind: vulnfinding.SubjectDevice, SubjectRef: vulnfinding.SubjectRef{ID: id},
			Ecosystem: eco, Component: vulnfinding.Component{Model: "CBS350-24P-4G", Firmware: "3.4.0.17"},
			Vuln: vulnfinding.Vuln{ID: vulnID}, Fix: vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.4.1.3"},
			MatchBasis: vulnfinding.MatchVendorAdvisory},
		State: state,
	}
}

func devPage(rows ...VulnRow) VulnPage {
	return VulnPage{Rows: rows, Subjects: []VulnSubjectStatus{{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "sw01"},
		LastComplete: time.Date(2026, 11, 16, 6, 0, 0, 0, time.UTC)}}}
}

func netdevVulnTestPages(store VulnFindings) *NetDevPages {
	h := &Handler{vuln: store, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now: func() time.Time { return time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC) }}
	return &NetDevPages{h: h}
}

// TestDeviceVulnsShowObservedFindingsWithAdvisoryLink: a device's findings
// carry the Hermes observer label and the NOS-built Cisco advisory link;
// another device's findings are not shown.
func TestDeviceVulnsShowObservedFindingsWithAdvisoryLink(t *testing.T) {
	mine := devFinding("sw01", "vendor:cisco:cbs", "cisco-sa-cbs-xss-2024", vulnstore.StateOpen)
	other := devFinding("sw02", "vendor:cisco:cbs", "cisco-sa-cbs-other", vulnstore.StateOpen)
	page := devPage(VulnRow{Finding: mine}, VulnRow{Finding: other})
	v := netdevVulnTestPages(devVulnStub{page: page}).deviceVulns(context.Background(), "sw01")
	if v == nil || v.Unavailable {
		t.Fatalf("view = %+v", v)
	}
	if v.Observer != hermesObserverLabel {
		t.Fatalf("observer = %q, want %q", v.Observer, hermesObserverLabel)
	}
	if len(v.Findings) != 1 || v.Findings[0].VulnID != "cisco-sa-cbs-xss-2024" {
		t.Fatalf("findings = %+v", v.Findings)
	}
	fix := v.Findings[0].Fix
	if fix == nil || !strings.HasPrefix(fix.URL, ciscoAdvisoryBase) || !strings.HasSuffix(fix.URL, "cisco-sa-cbs-xss-2024") || !fix.External {
		t.Fatalf("advisory link = %+v", fix)
	}
	if v.CoverageWarn || !strings.HasPrefix(v.Coverage, "assessed") {
		t.Fatalf("coverage = %q warn=%v", v.Coverage, v.CoverageWarn)
	}
}

// TestDeviceVulnsCoverageUnknownNeverClean: a device no complete run covered
// shows "coverage unknown", never an empty clean result.
func TestDeviceVulnsCoverageUnknownNeverClean(t *testing.T) {
	page := VulnPage{Subjects: []VulnSubjectStatus{{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "sw01"}}}}
	v := netdevVulnTestPages(devVulnStub{page: page}).deviceVulns(context.Background(), "sw01")
	if v == nil || !v.CoverageWarn || !strings.HasPrefix(v.Coverage, netdevCoverageUnknown) {
		t.Fatalf("view = %+v, want coverage unknown", v)
	}
	if len(v.Findings) != 0 {
		t.Fatalf("findings without a run: %+v", v.Findings)
	}
}

// TestDeviceVulnsHostileTextGetsNoLink: a hostile advisory ID is shown as
// text only; no link is built from it.
func TestDeviceVulnsHostileTextGetsNoLink(t *testing.T) {
	hostile := `<img src=x onerror=alert(1)>`
	page := devPage(VulnRow{Finding: devFinding("sw01", "vendor:cisco:cbs", hostile, vulnstore.StateOpen)})
	v := netdevVulnTestPages(devVulnStub{page: page}).deviceVulns(context.Background(), "sw01")
	if v == nil || len(v.Findings) != 1 {
		t.Fatalf("view = %+v", v)
	}
	if v.Findings[0].VulnID != hostile {
		t.Fatalf("vuln ID = %q, want the text as stored", v.Findings[0].VulnID)
	}
	if fix := v.Findings[0].Fix; fix != nil && fix.URL != "" {
		t.Fatalf("link built from a hostile ID: %q", fix.URL)
	}
}

// TestDeviceVulnsStoreErrorIsUnavailable: a failing store is shown as
// unavailable, not as no findings.
func TestDeviceVulnsStoreErrorIsUnavailable(t *testing.T) {
	v := netdevVulnTestPages(devVulnStub{err: errors.New("db down")}).deviceVulns(context.Background(), "sw01")
	if v == nil || !v.Unavailable || len(v.Findings) != 0 {
		t.Fatalf("view = %+v, want unavailable", v)
	}
}

// TestDeviceVulnsOffWithoutStore: with the vulnerability pages off there is
// no block.
func TestDeviceVulnsOffWithoutStore(t *testing.T) {
	if v := netdevVulnTestPages(nil).deviceVulns(context.Background(), "sw01"); v != nil {
		t.Fatalf("view without a store: %+v", v)
	}
}
