// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// updateLinkChartHandler builds a chart handler with one host "web-01" that
// has a known patch state. When enrolled is true the host has a pinned key
// (enrolled for SSH updates); otherwise it has no pin.
func updateLinkChartHandler(t *testing.T, enrolled bool) http.Handler {
	t.Helper()
	observed := time.Unix(1791960000, 0)
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states:  map[string]executions.OpsState{"web-01": {State: "READY", Reason: "no pending work", ObservedAt: observed}},
		updates: map[string]executions.HostUpdates{
			"web-01": {HostID: "web-01", Total: 3, Security: 1, Kernel: 0, RebootRequired: false, ObservedAt: observed},
		},
		docker:   map[string]executions.LastResultRow{},
		dockerUp: map[string]executions.LastResultRow{},
		registry: map[string]executions.LastResultRow{},
	}
	o := ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", DisplayName: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}}, nil
		},
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	}
	if enrolled {
		o.HostKeys = func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA"}}, nil
		}
	}
	return newTestHandler(t, o).Handler()
}

// hostPageUpdateHandler builds a host-page handler for host "web-01". When
// enrolled is true the host has a pinned key.
func hostPageUpdateHandler(t *testing.T, enrolled bool) http.Handler {
	t.Helper()
	o := ui.Options{
		Operations:   &fakeOps{},
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", DisplayName: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}}, nil
		},
	}
	if enrolled {
		o.HostKeys = func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA"}}, nil
		}
	}
	return newTestHandler(t, o).Handler()
}

// TestChartUpdateLinksEnrolledOnly covers ADR 0006 P2-02 part 1: the chart
// details panel shows the two "Propose ..." links only for hosts enrolled
// for SSH; not-enrolled hosts show the read-only text instead.
func TestChartUpdateLinksEnrolledOnly(t *testing.T) {
	body := getBody(t, updateLinkChartHandler(t, true), "/inventory/chart")
	for _, want := range []string{
		`href="/operations/new?action=package.install_security&amp;host=web-01"`,
		`href="/operations/new?action=package.install_all&amp;host=web-01"`,
		"Propose security updates",
		"Propose all updates",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("enrolled chart details missing %q", want)
		}
	}
	if strings.Contains(body, "read-only: not enrolled for updates") {
		t.Error("enrolled chart shows the read-only text")
	}

	body2 := getBody(t, updateLinkChartHandler(t, false), "/inventory/chart")
	if strings.Contains(body2, "package.install_security") || strings.Contains(body2, "package.install_all") {
		t.Error("not-enrolled chart shows update links")
	}
	if !strings.Contains(body2, "read-only: not enrolled for updates") {
		t.Error("not-enrolled chart missing the read-only text")
	}
}

// TestChartUpdateLinksExactHostID checks that the links carry the exact host
// id and that the URL is HTML-escaped (the ampersand becomes &amp;).
func TestChartUpdateLinksExactHostID(t *testing.T) {
	body := getBody(t, updateLinkChartHandler(t, true), "/inventory/chart")
	for _, want := range []string{
		`action=package.install_security&amp;host=web-01`,
		`action=package.install_all&amp;host=web-01`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("link missing %q", want)
		}
	}
	// A raw (unescaped) ampersand in the href would break the HTML.
	if strings.Contains(body, "action=package.install_security&host=") {
		t.Error("href contains a raw ampersand (not HTML-escaped)")
	}
}

// TestChartUpdateLinksNoReboot checks that the update links never bundle a
// reboot: the link URLs are exactly the two install actions with the host.
func TestChartUpdateLinksNoReboot(t *testing.T) {
	body := getBody(t, updateLinkChartHandler(t, true), "/inventory/chart")
	for _, bad := range []string{"system.reboot", "reboot&host", "reboot&amp;host"} {
		if strings.Contains(body, bad) {
			t.Errorf("update link bundles a reboot or extra param: %q", bad)
		}
	}
}

// TestHostPageUpdateLinksEnrolledOnly covers the host page: the Updates tab
// shows the two "Propose ..." links only for enrolled hosts; not-enrolled
// hosts show the read-only text.
func TestHostPageUpdateLinksEnrolledOnly(t *testing.T) {
	body := getBody(t, hostPageUpdateHandler(t, true), "/hosts/web-01?tab=updates")
	for _, want := range []string{
		`href="/operations/new?action=package.install_security&amp;host=web-01"`,
		`href="/operations/new?action=package.install_all&amp;host=web-01"`,
		"Propose security updates",
		"Propose all updates",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("enrolled host page missing %q", want)
		}
	}
	if strings.Contains(body, "read-only: not enrolled for updates") {
		t.Error("enrolled host page shows the read-only text")
	}

	body2 := getBody(t, hostPageUpdateHandler(t, false), "/hosts/web-01?tab=updates")
	if strings.Contains(body2, `action=package.install_security&amp;host=`) || strings.Contains(body2, `action=package.install_all&amp;host=`) {
		t.Error("not-enrolled host page shows update links")
	}
	if !strings.Contains(body2, "read-only: not enrolled for updates") {
		t.Error("not-enrolled host page missing the read-only text")
	}
}

// TestOperationFormHostPrefill checks the existing operations proposal form:
// a known host in ?host= is preselected, an unknown host is ignored (not
// rendered and nothing is checked).
func TestOperationFormHostPrefill(t *testing.T) {
	h := newTestHandler(t, ui.Options{
		Operations:   &fakeOps{},
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", DisplayName: "web-01"}}, nil
		},
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA"}}, nil
		},
	}).Handler()

	// A known host is preselected.
	known := getBody(t, h, "/operations/new?action=package.install_security&host=web-01")
	if !strings.Contains(known, `value="web-01" checked`) {
		t.Errorf("known host not preselected: %s", known)
	}

	// An unknown host is ignored: it is not rendered and nothing is checked.
	unknown := getBody(t, h, "/operations/new?action=package.install_security&host=does-not-exist")
	if strings.Contains(unknown, "does-not-exist") {
		t.Error("unknown host rendered in the form")
	}
	if strings.Contains(unknown, `value="web-01" checked`) {
		t.Error("unknown host param preselected a real host")
	}
}
