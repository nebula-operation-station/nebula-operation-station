// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// --- Staged OS update from the chart (ADR 0006, P2-02 part 2) ---

// stagedHosts is the host set of the staged update tests: three
// enrolled (pinned) hosts in different environments and one host
// without a pin.
func stagedHosts() []inventory.Host {
	return []inventory.Host{
		{ID: "ci-01", DisplayName: "CI runner", Environment: inventory.EnvDev, Criticality: inventory.CriticalityLow,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.11", Port: 22}}},
		{ID: "db-01", DisplayName: "DB server", Environment: inventory.EnvQA, Criticality: inventory.CriticalityHigh,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.12", Port: 22}}},
		{ID: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.13", Port: 22}}},
		{ID: "plain-01", DisplayName: "Plain", Environment: inventory.EnvProd, Criticality: inventory.CriticalityLow,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.14", Port: 22}}},
	}
}

// stagedPins pins the three enrolled staged update hosts.
func stagedPins() func(context.Context) ([]*pb.HostKeyPin, error) {
	return func(context.Context) ([]*pb.HostKeyPin, error) {
		return []*pb.HostKeyPin{
			{HostId: "ci-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA"},
			{HostId: "db-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:BBBB"},
			{HostId: "web-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:CCCC"},
		}, nil
	}
}

// stagedChartHandler builds a chart handler with the staged update
// hosts and, optionally, the PVE node "pve1" with the guests "web-vm"
// and "db-vm" (the parent and child boxes of the tree).
func stagedChartHandler(t *testing.T, withPVE bool) (*ui.Handler, *fakeOps) {
	t.Helper()
	ops := &fakeOps{}
	opts := ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return stagedHosts(), nil },
		HostKeys:     stagedPins(),
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	}
	if withPVE {
		now := time.Unix(1791960000, 0)
		tree, err := pveinventory.BuildTree(pveinventory.TreeInput{
			Now: now,
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
		opts.PVEChart = func(context.Context) (pveinventory.Tree, error) { return tree, nil }
	}
	return newTestHandler(t, opts), ops
}

// formPost builds a URL-encoded form POST to path.
func formPost(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// hostCheckboxes returns the values of all name="host" checkboxes in
// the given page.
func hostCheckboxes(t *testing.T, body string) []string {
	t.Helper()
	re := regexp.MustCompile(`<input type="checkbox" name="host" value="([^"]*)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func TestChartStagedUpdateCheckboxes(t *testing.T) {
	h, _ := stagedChartHandler(t, true)
	body := getBody(t, h.Handler(), "/inventory/chart")
	got := hostCheckboxes(t, body)
	if len(got) != 3 {
		t.Fatalf("host checkboxes = %v, want exactly ci-01, db-01, web-01", got)
	}
	for _, want := range []string{"ci-01", "db-01", "web-01"} {
		found := false
		for _, id := range got {
			if id == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("checkbox for enrolled host %s missing (got %v)", want, got)
		}
	}
	for _, id := range got {
		switch id {
		case "plain-01", "pve1", "web-vm", "db-vm":
			t.Errorf("checkbox for non-selectable %q", id)
		}
	}
	if !strings.Contains(body, `action="/inventory/chart/staged"`) {
		t.Error("staged update form missing")
	}
	if !strings.Contains(body, "Propose staged update") {
		t.Error("submit button missing")
	}
	for _, action := range []string{"package.install_security", "package.install_all"} {
		if !strings.Contains(body, `value="`+action+`"`) {
			t.Errorf("action option %s missing", action)
		}
	}
}

// TestChartStagedUpdateNoParentCheckboxes: every host checkbox lives in
// the staged update form; the tree boxes (node, host, guest,
// container) carry no checkbox, so selecting or expanding a parent
// never adds descendants.
func TestChartStagedUpdateNoParentCheckboxes(t *testing.T) {
	h, _ := stagedChartHandler(t, true)
	body := getBody(t, h.Handler(), "/inventory/chart")
	before, rest, ok := strings.Cut(body, `<form method="post" action="/inventory/chart/staged"`)
	if !ok {
		t.Fatal("no staged update form")
	}
	form, _, ok := strings.Cut(rest, "</form>")
	if !ok {
		t.Fatal("staged update form not terminated")
	}
	if n := len(hostCheckboxes(t, form)); n != 3 {
		t.Errorf("checkboxes inside the form = %d, want 3", n)
	}
	if n := len(hostCheckboxes(t, before)); n != 0 {
		t.Errorf("host checkboxes outside the form: %d", n)
	}
	// Every input the page submits as "host", of any type and anywhere
	// on the page, is one of the enrolled managed hosts and inside the
	// staged update form: no tree box adds ids to the selection.
	all := regexp.MustCompile(`<input[^>]*name="host"[^>]*>`).FindAllString(body, -1)
	if len(all) != 3 {
		t.Errorf("inputs named host on the page = %d (%v), want 3", len(all), all)
	}
	for _, in := range all {
		if !strings.Contains(form, in) {
			t.Errorf("input %s is outside the staged update form", in)
		}
		m := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(in)
		if m == nil || (m[1] != "ci-01" && m[1] != "db-01" && m[1] != "web-01") {
			t.Errorf("input %s submits a host that is not an enrolled managed host", in)
		}
	}
}

func TestChartStagedUpdateRefusesUnknownHost(t *testing.T) {
	h, ops := stagedChartHandler(t, false)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=ghost-01&action=package.install_security"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown host: status = %d, want 400", rec.Code)
	}
	if len(ops.createdCalls) != 0 {
		t.Error("a proposal was made for an unknown host")
	}
}

func TestChartStagedUpdateRefusesUnenrolledHost(t *testing.T) {
	h, ops := stagedChartHandler(t, false)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=plain-01&action=package.install_security"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unenrolled host: status = %d, want 400", rec.Code)
	}
	if len(ops.createdCalls) != 0 {
		t.Error("a proposal was made for an unenrolled host")
	}
	// A mixed selection is refused as a whole.
	rec = httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=web-01&host=plain-01&action=package.install_security"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mixed selection: status = %d, want 400", rec.Code)
	}
	if len(ops.createdCalls) != 0 {
		t.Error("a proposal was made for a mixed selection")
	}
}

func TestChartStagedUpdateEmptySelection(t *testing.T) {
	h, ops := stagedChartHandler(t, false)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "action=package.install_security"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty selection: status = %d, want 400", rec.Code)
	}
	if len(ops.createdCalls) != 0 {
		t.Error("a proposal was made for an empty selection")
	}
	rec = httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=web-01&action=bogus.action"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: status = %d, want 400", rec.Code)
	}
	if len(ops.createdCalls) != 0 {
		t.Error("a proposal was made for an unknown action")
	}
}

func TestChartStagedUpdateConfirmsThenProposes(t *testing.T) {
	h, ops := stagedChartHandler(t, false)
	// First POST: the confirmation page lists every selected host
	// (web-01 is sent twice and must be deduplicated). Nothing is
	// proposed yet.
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged",
		"host=ci-01&host=db-01&host=web-01&host=web-01&action=package.install_security"))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Confirm staged OS update") {
		t.Error("confirmation heading missing")
	}
	for _, name := range []string{"CI runner", "DB server", "web-01"} {
		if !strings.Contains(body, name) {
			t.Errorf("confirmation page does not list host %q", name)
		}
	}
	if len(ops.createdCalls) != 0 {
		t.Fatal("a proposal was made before confirmation")
	}
	// Confirm: the frozen list reaches the stage proposal unchanged,
	// with the DEV/QA/PROD preset and a manual gate.
	rec = httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged",
		"confirm=1&host=ci-01&host=db-01&host=web-01&action=package.install_security"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/operations/"+opID {
		t.Errorf("Location = %q, want %q", loc, "/operations/"+opID)
	}
	want := []string{"unknown", "package.install_security", "ci-01", "db-01", "web-01"}
	if len(ops.createdCalls) != 1 || !reflect.DeepEqual(ops.createdCalls[0], want) {
		t.Fatalf("CreateStaged calls = %v, want [%v]", ops.createdCalls, want)
	}
	if ops.plan.Preset != executions.PresetEnvironments {
		t.Errorf("plan.Preset = %q, want %q", ops.plan.Preset, executions.PresetEnvironments)
	}
	if ops.plan.Continue != "manual" {
		t.Errorf("plan.Continue = %q, want manual", ops.plan.Continue)
	}
	if ops.plan.MaxFailed != 0 {
		t.Errorf("plan.MaxFailed = %d, want 0", ops.plan.MaxFailed)
	}
}

func TestChartStagedUpdateEscaping(t *testing.T) {
	ops := &fakeOps{}
	h := newTestHandler(t, ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "evil-01", DisplayName: "<script>alert(1)</script>", Environment: inventory.EnvProd,
				Endpoints: []inventory.Endpoint{{Address: "10.0.0.15", Port: 22}}}}, nil
		},
		HostKeys:     hostKeysFor("evil-01", keyPinned),
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	})
	body := getBody(t, h.Handler(), "/inventory/chart")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("host name rendered unescaped in the form")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped host name missing from the form")
	}
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=evil-01&action=package.install_all"))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("host name rendered unescaped on the confirmation page")
	}
}

func TestChartStagedUpdateFormVisibility(t *testing.T) {
	log := func() *slog.Logger { return slog.New(slog.NewTextHandler(&strings.Builder{}, nil)) }
	// No operations: no form, and the endpoint is gone.
	h := newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return stagedHosts(), nil },
		HostKeys:     stagedPins(),
		Log:          log(),
		PublicOrigin: "https://nebula.example",
	})
	body := getBody(t, h.Handler(), "/inventory/chart")
	if strings.Contains(body, "/inventory/chart/staged") {
		t.Error("form rendered without operations")
	}
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=web-01&action=package.install_security"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("endpoint without operations: status = %d, want 404", rec.Code)
	}
	// Pins unavailable: enrollment unknown, no form.
	h = newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return stagedHosts(), nil },
		HostKeys:     hostKeysFor("web-01", keyUnavailable),
		Operations:   &fakeOps{},
		Log:          log(),
		PublicOrigin: "https://nebula.example",
	})
	body = getBody(t, h.Handler(), "/inventory/chart")
	if strings.Contains(body, "/inventory/chart/staged") {
		t.Error("form rendered with unavailable pins")
	}
	// Blocked host: no checkbox for it.
	h = newTestHandler(t, ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01", Environment: inventory.EnvProd}}, nil
		},
		HostKeys:     hostKeysFor("web-01", keyBlocked),
		Operations:   &fakeOps{},
		Log:          log(),
		PublicOrigin: "https://nebula.example",
	})
	body = getBody(t, h.Handler(), "/inventory/chart")
	if strings.Contains(body, `name="host"`) {
		t.Error("checkbox rendered for a blocked host")
	}
}
