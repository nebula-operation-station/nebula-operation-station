// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Key states of the test host for the update gate.
const (
	keyPinned      = "pinned"
	keyNone        = "none"
	keyBlocked     = "blocked"
	keyUnavailable = "unavailable"
)

// hostKeysFor returns the HostKeys option for the given key state of
// host id: a pinned key, no pin, a blocked pin, or a failing executor
// (pins unavailable).
func hostKeysFor(id, state string) func(context.Context) ([]*pb.HostKeyPin, error) {
	return func(context.Context) ([]*pb.HostKeyPin, error) {
		switch state {
		case keyPinned:
			return []*pb.HostKeyPin{{HostId: id, KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA"}}, nil
		case keyBlocked:
			return []*pb.HostKeyPin{{HostId: id, KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA", Blocked: true}}, nil
		case keyUnavailable:
			return nil, errors.New("executor down")
		default:
			return nil, nil
		}
	}
}

// updateLinkChartHandler builds a chart handler with one host "web-01" that
// has a known patch state with a pending reboot, in the given key state.
func updateLinkChartHandler(t *testing.T, keyState string) http.Handler {
	t.Helper()
	observed := time.Unix(1791960000, 0)
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states:  map[string]executions.OpsState{"web-01": {State: "READY", Reason: "no pending work", ObservedAt: observed}},
		updates: map[string]executions.HostUpdates{
			"web-01": {HostID: "web-01", Total: 3, Security: 1, Kernel: 1, RebootRequired: true, ObservedAt: observed},
		},
		docker:   map[string]executions.LastResultRow{},
		dockerUp: map[string]executions.LastResultRow{},
		registry: map[string]executions.LastResultRow{},
	}
	o := ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", DisplayName: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}}, nil
		},
		HostKeys:     hostKeysFor("web-01", keyState),
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	}
	return newTestHandler(t, o).Handler()
}

// hostPageUpdateHandler builds a host-page handler for host "web-01" in
// the given key state.
func hostPageUpdateHandler(t *testing.T, keyState string) http.Handler {
	t.Helper()
	o := ui.Options{
		Operations:   &fakeOps{},
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", DisplayName: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}}, nil
		},
		HostKeys: hostKeysFor("web-01", keyState),
	}
	return newTestHandler(t, o).Handler()
}

// proposeHrefs returns every href to the operation proposal form.
func proposeHrefs(body string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`href="(/operations/new[^"]*)"`).FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// installHrefs returns the proposal hrefs for the package install
// actions only; the host page carries an unrelated, pre-existing reboot
// proposal link of its own.
func installHrefs(body string) []string {
	var out []string
	for _, href := range proposeHrefs(body) {
		if strings.Contains(href, "action=package.install_") {
			out = append(out, href)
		}
	}
	return out
}

// wantWeb01Hrefs are the exact two (HTML-escaped) proposal links of the
// enrolled host web-01.
var wantWeb01Hrefs = []string{
	"/operations/new?action=package.install_security&amp;host=web-01",
	"/operations/new?action=package.install_all&amp;host=web-01",
}

// equalHrefs reports whether got is exactly want, in order.
func equalHrefs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestChartUpdateLinksEnrolledOnly covers ADR 0006 P2-02 part 1: the chart
// details panel shows the two "Propose ..." links only for hosts enrolled
// for SSH; not-enrolled hosts show the read-only text instead.
func TestChartUpdateLinksEnrolledOnly(t *testing.T) {
	body := getBody(t, updateLinkChartHandler(t, keyPinned), "/inventory/chart")
	for _, want := range []string{"Propose security updates", "Propose all updates"} {
		if !strings.Contains(body, want) {
			t.Errorf("enrolled chart details missing %q", want)
		}
	}
	if got := proposeHrefs(body); !equalHrefs(got, wantWeb01Hrefs) {
		t.Errorf("enrolled chart proposal links = %q, want %q", got, wantWeb01Hrefs)
	}
	if strings.Contains(body, "read-only:") {
		t.Error("enrolled chart shows a read-only text")
	}

	body2 := getBody(t, updateLinkChartHandler(t, keyNone), "/inventory/chart")
	if got := proposeHrefs(body2); len(got) != 0 {
		t.Errorf("not-enrolled chart shows update links %q", got)
	}
	if !strings.Contains(body2, "read-only: not enrolled for updates") {
		t.Error("not-enrolled chart missing the read-only text")
	}
}

// TestChartUpdateLinksExactHostID checks that the links carry the exact host
// id and that the URL is HTML-escaped (the ampersand becomes &amp;).
func TestChartUpdateLinksExactHostID(t *testing.T) {
	body := getBody(t, updateLinkChartHandler(t, keyPinned), "/inventory/chart")
	if got := proposeHrefs(body); !equalHrefs(got, wantWeb01Hrefs) {
		t.Errorf("proposal links = %q, want %q", got, wantWeb01Hrefs)
	}
	// A raw (unescaped) ampersand in the href would break the HTML.
	if strings.Contains(body, "action=package.install_security&host=") {
		t.Error("href contains a raw ampersand (not HTML-escaped)")
	}
}

// TestChartUpdateLinksNoReboot checks that the update links never bundle a
// reboot, even when the host has a reboot pending: the link URLs are
// exactly the two install actions with the host and nothing else.
func TestChartUpdateLinksNoReboot(t *testing.T) {
	body := getBody(t, updateLinkChartHandler(t, keyPinned), "/inventory/chart")
	if !strings.Contains(body, "reboot pending") {
		t.Fatal("fixture: chart does not show the pending reboot")
	}
	got := proposeHrefs(body)
	if !equalHrefs(got, wantWeb01Hrefs) {
		t.Errorf("proposal links = %q, want exactly %q", got, wantWeb01Hrefs)
	}
	for _, href := range got {
		if strings.Contains(href, "reboot") {
			t.Errorf("update link bundles a reboot: %q", href)
		}
	}
}

// TestUpdateLinksKeyStateReason checks the gate and the read-only reason
// for every key state, on the chart details panel and the host page: only
// a pinned key gives links; a blocked pin or unavailable pins never do
// and each shows its own reason.
func TestUpdateLinksKeyStateReason(t *testing.T) {
	for _, tc := range []struct {
		state, reason string
	}{
		{keyNone, "read-only: not enrolled for updates"},
		{keyBlocked, "read-only: host key mismatch (BLOCKED)"},
		{keyUnavailable, "read-only: executor unavailable"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			pages := map[string]string{
				"chart":     getBody(t, updateLinkChartHandler(t, tc.state), "/inventory/chart"),
				"host page": getBody(t, hostPageUpdateHandler(t, tc.state), "/hosts/web-01?tab=updates"),
			}
			for name, body := range pages {
				if got := installHrefs(body); len(got) != 0 {
					t.Errorf("%s: %s host shows update links %q", name, tc.state, got)
				}
				if !strings.Contains(body, tc.reason) {
					t.Errorf("%s: %s host missing reason %q", name, tc.state, tc.reason)
				}
			}
		})
	}
}

// TestHostPageUpdateLinksEnrolledOnly covers the host page: the Updates tab
// shows the two "Propose ..." links only for enrolled hosts; not-enrolled
// hosts show the read-only text.
func TestHostPageUpdateLinksEnrolledOnly(t *testing.T) {
	body := getBody(t, hostPageUpdateHandler(t, keyPinned), "/hosts/web-01?tab=updates")
	for _, want := range []string{"Propose security updates", "Propose all updates"} {
		if !strings.Contains(body, want) {
			t.Errorf("enrolled host page missing %q", want)
		}
	}
	if got := installHrefs(body); !equalHrefs(got, wantWeb01Hrefs) {
		t.Errorf("enrolled host page proposal links = %q, want %q", got, wantWeb01Hrefs)
	}
	if strings.Contains(body, "read-only:") {
		t.Error("enrolled host page shows a read-only text")
	}

	body2 := getBody(t, hostPageUpdateHandler(t, keyNone), "/hosts/web-01?tab=updates")
	if got := installHrefs(body2); len(got) != 0 {
		t.Errorf("not-enrolled host page shows update links %q", got)
	}
	if !strings.Contains(body2, "read-only: not enrolled for updates") {
		t.Error("not-enrolled host page missing the read-only text")
	}
}

// pveUpdateChartHandler builds a chart handler with the managed host
// web-01 (in the given key state) and one PVE node "pve1" with two
// guests: "web-vm" (VMID 100) linked to web-01 and "db-vm" (VMID 101)
// without a link.
func pveUpdateChartHandler(t *testing.T, keyState string) http.Handler {
	t.Helper()
	now := time.Unix(1791960000, 0)
	tree, err := pveinventory.BuildTree(pveinventory.TreeInput{
		Now:   now,
		Hosts: []pveinventory.HostInput{{ID: "web-01", DisplayName: "web-01"}},
		Links: []pveinventory.HostLink{{RemoteID: "pve-lab", VMID: 100, Generation: 1, HostID: "web-01"}},
		Remotes: []pveinventory.RemoteInput{{
			RemoteID: "pve-lab",
			Name:     "PVE lab",
			Nodes:    []pveinventory.NodeInput{{Node: "pve1", Status: "online", ObservedAt: now}},
			Guests: []pveinventory.GuestInput{
				{VMID: 100, Generation: 1, Kind: "qemu", Node: "pve1", Name: "web-vm", Status: "running", ObservedAt: now},
				{VMID: 101, Generation: 1, Kind: "qemu", Node: "pve1", Name: "db-vm", Status: "running", ObservedAt: now},
			},
		}},
	})
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	return newTestHandler(t, ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", DisplayName: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}}, nil
		},
		HostKeys:     hostKeysFor("web-01", keyState),
		PVEChart:     func(context.Context) (pveinventory.Tree, error) { return tree, nil },
		Operations:   &fakeOps{},
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	}).Handler()
}

// guestBox returns the rendered guest box that contains name.
func guestBox(t *testing.T, body, name string) string {
	t.Helper()
	for _, part := range strings.Split(body, `<li class="chart__box chart__box--guest"`)[1:] {
		part, _, _ = strings.Cut(part, "</li>")
		if strings.Contains(part, ">"+name+"<") {
			return part
		}
	}
	t.Fatalf("no guest box %q", name)
	return ""
}

// nodeSection returns the rendered PVE node box up to its guest list.
func nodeSection(t *testing.T, body string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, "chart__box--node")
	if !ok {
		t.Fatal("no PVE node box")
	}
	rest, _, _ = strings.Cut(rest, `<ul class="chart__list">`)
	return rest
}

// TestChartPVEGuestUpdateLinks covers the PVE node and guest boxes: a
// guest linked to an enrolled managed host gets the same two "Propose
// ..." links as the host; an unlinked guest and the node are read-only
// with their reason and never get links.
func TestChartPVEGuestUpdateLinks(t *testing.T) {
	body := getBody(t, pveUpdateChartHandler(t, keyPinned), "/inventory/chart")

	linked := guestBox(t, body, "web-vm")
	if got := proposeHrefs(linked); !equalHrefs(got, wantWeb01Hrefs) {
		t.Errorf("linked enrolled guest links = %q, want %q", got, wantWeb01Hrefs)
	}
	if strings.Contains(linked, "read-only:") {
		t.Error("linked enrolled guest shows a read-only text")
	}

	unlinked := guestBox(t, body, "db-vm")
	if got := proposeHrefs(unlinked); len(got) != 0 {
		t.Errorf("unlinked guest shows update links %q", got)
	}
	if !strings.Contains(unlinked, "read-only: not enrolled as a managed host") {
		t.Errorf("unlinked guest missing the read-only reason: %s", unlinked)
	}

	node := nodeSection(t, body)
	if got := proposeHrefs(node); len(got) != 0 {
		t.Errorf("PVE node shows update links %q", got)
	}
	// html/template escapes the apostrophe in "node's".
	if !strings.Contains(node, "read-only: PVE node — updates via the node&#39;s own enrollment") {
		t.Errorf("PVE node missing the read-only reason: %s", node)
	}
}

// TestChartPVEGuestUpdateLinksNotEnrolled checks that a guest linked to a
// managed host that is not enrolled (no pin, blocked, pins unavailable)
// shows no links and the host's read-only reason.
func TestChartPVEGuestUpdateLinksNotEnrolled(t *testing.T) {
	for _, tc := range []struct {
		state, reason string
	}{
		{keyNone, "read-only: not enrolled for updates"},
		{keyBlocked, "read-only: host key mismatch (BLOCKED)"},
		{keyUnavailable, "read-only: executor unavailable"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			body := getBody(t, pveUpdateChartHandler(t, tc.state), "/inventory/chart")
			linked := guestBox(t, body, "web-vm")
			if got := proposeHrefs(linked); len(got) != 0 {
				t.Errorf("linked %s guest shows update links %q", tc.state, got)
			}
			if !strings.Contains(linked, tc.reason) {
				t.Errorf("linked %s guest missing reason %q: %s", tc.state, tc.reason, linked)
			}
		})
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
