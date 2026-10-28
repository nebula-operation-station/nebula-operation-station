// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests for the in-place run endpoints and the per-host pins (job ui5):
// the read-only operation status poll, the privileged session check,
// the pin endpoints (catalog-only actions, validation, audit), and the
// quick-action bar and bulk bar rendered on the host and inventory
// pages. Untrusted names are asserted escaped.

package ui_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// fakePins is a ui.PinStore for tests.
type fakePins struct {
	// pins maps a host ID to its pinned action IDs in position order.
	pins map[string][]string
	// knownHosts lists the inventory host IDs; a pin for any other ID
	// fails with inventory.ErrHostNotFound, like the real store.
	knownHosts []string
	setErr     error
	addErr     error
	// setCalls records every SetPinnedActions call as [host, user, actions...].
	setCalls [][]string
	// addCalls records every AddPinnedAction call as [host, action, user].
	addCalls [][]string
}

func newFakePins(hosts ...string) *fakePins {
	return &fakePins{pins: map[string][]string{}, knownHosts: hosts}
}

func (f *fakePins) known(host string) bool {
	for _, h := range f.knownHosts {
		if h == host {
			return true
		}
	}
	return false
}

func (f *fakePins) ListPinnedActions(_ context.Context, hostID string) ([]inventory.PinnedAction, error) {
	if !f.known(hostID) {
		return nil, fmt.Errorf("list pins: %w", inventory.ErrHostNotFound)
	}
	out := make([]inventory.PinnedAction, 0, len(f.pins[hostID]))
	for i, a := range f.pins[hostID] {
		out = append(out, inventory.PinnedAction{ActionID: a, Position: i})
	}
	return out, nil
}

func (f *fakePins) SetPinnedActions(_ context.Context, hostID string, actionIDs []string, by string) error {
	if f.setErr != nil {
		return f.setErr
	}
	if !f.known(hostID) {
		return fmt.Errorf("set pins: %w", inventory.ErrHostNotFound)
	}
	f.setCalls = append(f.setCalls, append([]string{hostID, by}, actionIDs...))
	f.pins[hostID] = append([]string(nil), actionIDs...)
	return nil
}

func (f *fakePins) AddPinnedAction(_ context.Context, hostID, actionID, by string) error {
	if f.addErr != nil {
		return f.addErr
	}
	if !f.known(hostID) {
		return fmt.Errorf("add pin: %w", inventory.ErrHostNotFound)
	}
	for _, a := range f.pins[hostID] {
		if a == actionID {
			return nil // a pin that already exists is left in place
		}
	}
	f.addCalls = append(f.addCalls, []string{hostID, actionID, by})
	f.pins[hostID] = append(f.pins[hostID], actionID)
	return nil
}

func pinsHandler(t *testing.T, f *fakePins, log *strings.Builder) http.Handler {
	t.Helper()
	o := ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   &fakeOps{},
		Pins:         f,
		Hosts: func(context.Context) ([]inventory.Host, error) {
			var hosts []inventory.Host
			for _, id := range f.knownHosts {
				hosts = append(hosts, inventory.Host{ID: id, DisplayName: "<b>" + id + "</b>"})
			}
			return hosts, nil
		},
	}
	if log != nil {
		o.Log = slog.New(slog.NewTextHandler(log, nil))
	}
	return newTestHandler(t, o).Handler()
}

// TestOperationStatusEndpoint covers the read-only status poll: it
// answers only for existing operations, carries nothing beyond the
// state and the per-host counts, and is GET only.
func TestOperationStatusEndpoint(t *testing.T) {
	f := &fakeOps{exec: executions.Execution{
		ID: opID, ActionID: "core.facts", State: "running",
		Detail: "top-secret detail",
		Hosts: []executions.Host{
			{HostID: "web", State: "finished", Detail: "host detail",
				Result: []byte(`{"x":"<script>"}`), Log: []byte("log <img src=x>")},
			{HostID: "db", State: "running", Detail: "another detail"},
			{HostID: "nas", State: "pending"},
		},
	}}
	h := opsHandler(t, f, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status: status %d, want 200", rec.Code)
	}
	var st struct {
		ID    string `json:"id"`
		State string `json:"state"`
		Hosts struct {
			Total   int            `json:"total"`
			ByState map[string]int `json:"by_state"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("status is not JSON: %v (%s)", err, rec.Body.String())
	}
	if st.ID != opID || st.State != "running" || st.Hosts.Total != 3 {
		t.Errorf("status %q: id=%q state=%q total=%d", rec.Body.String(), st.ID, st.State, st.Hosts.Total)
	}
	for state, want := range map[string]int{"finished": 1, "running": 1, "pending": 1} {
		if st.Hosts.ByState[state] != want {
			t.Errorf("by_state[%q] = %d, want %d", state, st.Hosts.ByState[state], want)
		}
	}
	// Nothing beyond the state and the counts: no host output, no
	// details, no parameters, no fingerprints.
	body := rec.Body.String()
	for _, secret := range []string{"top-secret detail", "host detail", "another detail", "<script>", "log <img", "Result", "Fingerprint"} {
		if strings.Contains(body, secret) {
			t.Errorf("status body leaks %q: %s", secret, body)
		}
	}

	// Unknown operations get a 404 JSON error.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/operations/unknown/status", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET unknown status: status %d, want 404", rec.Code)
	}

	// GET only.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/operations/"+opID+"/status", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status: status %d, want 405", rec.Code)
	}

	// Without the operations service the endpoint is a 404.
	h2 := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/status", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status without operations: status %d, want 404", rec.Code)
	}
}

// TestPrivilegedSessionEndpoint covers the session check: it reports
// the executor status, degrades to "unavailable" on errors, and is GET
// only. It opens nothing.
func TestPrivilegedSessionEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *fakeStatus
		want   string
	}{
		{name: "active session", status: &fakeStatus{resp: &pb.GetStatusResponse{PrivilegedSessionActive: true, PrivilegedSessionExpiryUnix: 1791960000}}, want: `"active":true`},
		{name: "no session", status: &fakeStatus{resp: &pb.GetStatusResponse{}}, want: `"active":false`},
		{name: "executor error", status: &fakeStatus{err: errors.New("down")}, want: `"available":false`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Status: tc.status}).Handler()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/privileged/session", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET session: status %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("body %q missing %q", rec.Body.String(), tc.want)
			}
		})
	}

	// Without a status provider (no executor wired) the check says the
	// session is not active and the executor unavailable.
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/privileged/session", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET session without provider: status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"active":false`) || !strings.Contains(rec.Body.String(), `"available":false`) {
		t.Errorf("body %q", rec.Body.String())
	}

	// GET only.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/privileged/session", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST session: status %d, want 405", rec.Code)
	}
}

// TestHostPinsEndpoint covers the host page pin list: only catalog
// actions, no duplicates, the 12-action limit, valid host IDs, the
// unknown-host 404, POST only, and the audit line.
func TestHostPinsEndpoint(t *testing.T) {
	f := newFakePins("web", "db")
	var logged strings.Builder
	h := pinsHandler(t, f, &logged)

	// A valid list is stored in the given order and audited.
	if code, body := postJSON(t, h, "/hosts/web/pins", `{"actions":["core.facts","system.reboot"]}`); code != http.StatusOK {
		t.Fatalf("set pins: status %d (body %s)", code, body)
	}
	if got := f.pins["web"]; len(got) != 2 || got[0] != "core.facts" || got[1] != "system.reboot" {
		t.Errorf("stored pins %v, want [core.facts system.reboot]", got)
	}
	if len(f.setCalls) != 1 || f.setCalls[0][0] != "web" || f.setCalls[0][1] != "unknown" {
		t.Errorf("set calls %v", f.setCalls)
	}
	if out := logged.String(); !strings.Contains(out, "host_pins_set") || !strings.Contains(out, "host=web") {
		t.Errorf("audit log %q missing the pin line", out)
	}

	// An empty list clears the pins.
	if code, body := postJSON(t, h, "/hosts/web/pins", `{"actions":[]}`); code != http.StatusOK {
		t.Fatalf("clear pins: status %d (body %s)", code, body)
	}
	if got := f.pins["web"]; len(got) != 0 {
		t.Errorf("pins after clear %v, want none", got)
	}

	// Only catalog actions may be pinned.
	if code, body := postJSON(t, h, "/hosts/web/pins", `{"actions":["not.in.catalog"]}`); code != http.StatusBadRequest {
		t.Errorf("non-catalog: status %d (body %s), want 400", code, body)
	}
	// No duplicates.
	if code, body := postJSON(t, h, "/hosts/web/pins", `{"actions":["core.facts","core.facts"]}`); code != http.StatusBadRequest {
		t.Errorf("duplicate: status %d (body %s), want 400", code, body)
	}
	// At most 12.
	ids := make([]string, 0, 13)
	for i := 0; i < 13; i++ {
		ids = append(ids, fmt.Sprintf("service.restart-%d", i))
	}
	body := `{"actions":[` + strings.Join(mapStrings(ids), ",") + `]}`
	if code, _ := postJSON(t, h, "/hosts/web/pins", body); code != http.StatusBadRequest {
		t.Errorf("13 actions: status %d, want 400", code)
	}
	// Invalid host IDs are a 404, like an unknown host.
	if code, _ := postJSON(t, h, "/hosts/bad%20id/pins", `{"actions":["core.facts"]}`); code != http.StatusNotFound {
		t.Errorf("bad host ID: status %d, want 404", code)
	}
	if code, _ := postJSON(t, h, "/hosts/ghost/pins", `{"actions":["core.facts"]}`); code != http.StatusNotFound {
		t.Errorf("unknown host: status %d, want 404", code)
	}
	if len(f.setCalls) != 2 {
		t.Errorf("rejected requests must not reach the store: %v", f.setCalls)
	}

	// POST only.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hosts/web/pins", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET pins: status %d, want 405", rec.Code)
	}

	// Without the pin store the endpoint is a 404.
	h2 := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Operations: &fakeOps{}}).Handler()
	if code, _ := postJSON(t, h2, "/hosts/web/pins", `{"actions":["core.facts"]}`); code != http.StatusNotFound {
		t.Errorf("pins without store: status %d, want 404", code)
	}
}

// TestActionPinEndpoint covers the runbook/module "Pin to hosts…": one
// catalog action to between 1 and 12 known hosts, audited per host.
func TestActionPinEndpoint(t *testing.T) {
	f := newFakePins("web", "db", "nas")
	var logged strings.Builder
	h := pinsHandler(t, f, &logged)

	if code, body := postJSON(t, h, "/actions/pin", `{"action":"core.facts","hosts":["web","db"]}`); code != http.StatusOK {
		t.Fatalf("pin: status %d (body %s)", code, body)
	}
	for _, host := range []string{"web", "db"} {
		if got := f.pins[host]; len(got) != 1 || got[0] != "core.facts" {
			t.Errorf("pins of %s %v, want [core.facts]", host, got)
		}
	}
	if out := logged.String(); !strings.Contains(out, "host_pinned") {
		t.Errorf("audit log %q missing the pin lines", out)
	}

	// A pin that already exists is left in place (no error, no
	// duplicate).
	if code, body := postJSON(t, h, "/actions/pin", `{"action":"core.facts","hosts":["web"]}`); code != http.StatusOK {
		t.Fatalf("re-pin: status %d (body %s)", code, body)
	}
	if got := f.pins["web"]; len(got) != 1 {
		t.Errorf("pins of web after re-pin %v, want one entry", got)
	}

	// Only catalog actions.
	if code, body := postJSON(t, h, "/actions/pin", `{"action":"not.in.catalog","hosts":["web"]}`); code != http.StatusBadRequest {
		t.Errorf("non-catalog: status %d (body %s), want 400", code, body)
	}
	// Unknown and invalid hosts are refused.
	if code, body := postJSON(t, h, "/actions/pin", `{"action":"core.facts","hosts":["ghost"]}`); code != http.StatusBadRequest {
		t.Errorf("unknown host: status %d (body %s), want 400", code, body)
	}
	if code, body := postJSON(t, h, "/actions/pin", `{"action":"core.facts","hosts":["../etc"]}`); code != http.StatusBadRequest {
		t.Errorf("invalid host: status %d (body %s), want 400", code, body)
	}
	// Between 1 and 12 hosts.
	if code, body := postJSON(t, h, "/actions/pin", `{"action":"core.facts","hosts":[]}`); code != http.StatusBadRequest {
		t.Errorf("no hosts: status %d (body %s), want 400", code, body)
	}
	many := make([]string, 0, 13)
	for i := 0; i < 13; i++ {
		many = append(many, fmt.Sprintf("host-%d", i))
	}
	if code, body := postJSON(t, h, "/actions/pin", `{"action":"core.facts","hosts":[`+strings.Join(mapStrings(many), ",")+`]}`); code != http.StatusBadRequest {
		t.Errorf("13 hosts: status %d (body %s), want 400", code, body)
	}

	// POST only.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/actions/pin", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET pin: status %d, want 405", rec.Code)
	}
}

// TestHostPageQuickActions covers the host page quick-action bar: the
// built-ins, the pinned actions (parameter actions as form links), the
// reboot confirm, and the settings-tab pin list; untrusted display
// names are escaped.
func TestHostPageQuickActions(t *testing.T) {
	f := newFakePins("web-01")
	f.pins["web-01"] = []string{"core.facts", "service.restart"} // restart has params
	h := pinsHandler(t, f, nil)

	body := getBody(t, h, "/hosts/web-01")
	for _, want := range []string{
		`id="quick-actions"`,
		`data-action="refresh"`,
		`data-action="package.install_security"`,
		`data-action="system.reboot"`,
		// Pinned without params: a button.
		`data-action="core.facts"`,
		// Pinned with params: a link to the prefilled operation form.
		`href="/operations/new?host=web-01&amp;action=service.restart"`,
		// The inline reboot confirm (no browser dialog).
		`id="quick-reboot-confirm"`,
		"Plan a staged reboot…",
		// The untrusted display name is escaped.
		"&lt;b&gt;web-01&lt;/b&gt;",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if strings.Contains(body, "<b>web-01</b>") {
		t.Error("display name rendered as HTML")
	}

	// The settings tab lists the catalog actions as checkboxes, pinned
	// ones checked.
	settings := getBody(t, h, "/hosts/web-01?tab=settings")
	for _, want := range []string{
		`id="pins-form"`,
		`name="pin" value="core.facts" checked`,
		`name="pin" value="service.restart" checked`,
		`name="pin" value="system.reboot"`,
	} {
		if !strings.Contains(settings, want) {
			t.Errorf("pin settings missing %q", want)
		}
	}

	// Without pins wired there is no pin list and no pinned buttons.
	h2 := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   &fakeOps{},
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01"}}, nil
		},
	}).Handler()
	body2 := getBody(t, h2, "/hosts/web-01")
	if !strings.Contains(body2, `data-action="refresh"`) {
		t.Errorf("built-in quick actions missing without pins")
	}
	if strings.Contains(body2, "pins-form") {
		t.Errorf("pin settings rendered without the pin store")
	}
}

// TestHostPageDoesNotShowExpiredAsInProgress covers issue #71: an expired
// operation on the host page is muted, not the blue in-progress badge, so
// the host does not look busy forever.
func TestHostPageDoesNotShowExpiredAsInProgress(t *testing.T) {
	f := &fakeOps{listHost: []executions.Summary{{ID: opID, ActionID: "core.facts", Risk: "HIGH", State: "expired",
		CreatedBy: "axel", CreatedAt: time.Unix(1791960000, 0), FinishedAt: time.Unix(1791963600, 0), Hosts: 1}}}
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   f,
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01"}}, nil
		},
	}).Handler()

	body := getBody(t, h, "/hosts/web-01?tab=operations")
	if !strings.Contains(body, `badge badge--expired">expired`) {
		t.Fatalf("expired badge missing: %s", body)
	}
	if strings.Contains(body, "badge--pending") {
		t.Error("expired operation shown as in progress")
	}
}

// TestInventoryBulkBar covers the bulk bar on the inventory page: the
// one-click refresh and the inline reboot confirm with the link to the
// operation form.
func TestInventoryBulkBar(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Inventory:    store,
		Operations:   &fakeOps{},
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01"}, {ID: "db-01"}}, nil
		},
	}).Handler()

	body := getBody(t, h, "/inventory")
	for _, want := range []string{
		`id="bulkbar"`,
		`id="bulk-refresh"`,
		`id="bulk-reboot"`,
		`id="bulk-reboot-confirm"`,
		`id="bulk-reboot-go"`,
		`id="bulk-reboot-cancel"`,
		`href="/operations/new"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("inventory missing %q", want)
		}
	}

	// Without the inventory store the bar is not rendered.
	h2 := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   &fakeOps{},
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web-01"}}, nil
		},
	}).Handler()
	if body := getBody(t, h2, "/inventory"); strings.Contains(body, `id="bulkbar"`) {
		t.Error("bulk bar rendered without the inventory store")
	}
}

// mapStrings wraps the strings in quotes for a JSON array body.
func mapStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}
