// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the "Endpoints" section of the host page (job ep01): add an
// alternate endpoint, change the order, remove one; duplicates, the
// 4-endpoint limit and the last endpoint are refused; every change writes
// one audit line with the order before and after; output is escaped and
// the forms go through the Origin-checked POST route.

package ui_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const epOrigin = "https://nebula.example.org"

type epEnv struct {
	h      *ui.Handler
	store  *inventory.Store
	logged *strings.Builder
}

// newEPEnv returns a UI over a real inventory store with two hosts:
// web-01 (one endpoint 10.0.0.11:22) and db-01 (10.0.0.50:22).
func newEPEnv(t *testing.T) *epEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := inventory.New(db)
	for _, h := range []inventory.Host{
		{ID: "web-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.11", Port: 22}}},
		{ID: "db-01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityHigh,
			Endpoints: []inventory.Endpoint{{Address: "10.0.0.50", Port: 22}}},
	} {
		if _, err := store.Create(context.Background(), h, inventory.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	logged := &strings.Builder{}
	h := newTestHandler(t, ui.Options{
		PublicOrigin: epOrigin,
		Inventory:    store,
		Hosts:        store.List,
		Log:          slog.New(slog.NewTextHandler(logged, nil)),
	})
	return &epEnv{h: h, store: store, logged: logged}
}

// post sends an endpoint form for web-01 and returns the status and the
// redirect target.
func (e *epEnv) post(t *testing.T, form url.Values) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/hosts/web-01/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.h.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Header().Get("Location")
}

func (e *epEnv) endpoints(t *testing.T) []inventory.Endpoint {
	t.Helper()
	h, err := e.store.Get(context.Background(), "web-01")
	if err != nil {
		t.Fatal(err)
	}
	return h.Endpoints
}

func addForm(addr, port string) url.Values {
	return url.Values{"endpoint_op": {"add"}, "address": {addr}, "port": {port}}
}

func endpointForm(op, addr, port, to string) url.Values {
	v := url.Values{"endpoint_op": {op}, "address": {addr}, "port": {port}}
	if to != "" {
		v.Set("to", to)
	}
	return v
}

const settingsTab = "/hosts/web-01?tab=settings"

func mustOK(t *testing.T, code int, loc string) {
	t.Helper()
	if code != http.StatusSeeOther || loc != settingsTab {
		t.Fatalf("status %d location %q, want 303 %q", code, loc, settingsTab)
	}
}

func mustWarn(t *testing.T, code int, loc, want string) {
	t.Helper()
	if code != http.StatusSeeOther || !strings.HasPrefix(loc, settingsTab+"&warn=") {
		t.Fatalf("status %d location %q, want 303 with a warning", code, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("warn"); !strings.Contains(got, want) {
		t.Fatalf("warning %q does not contain %q", got, want)
	}
}

func TestHostEndpointAddAppendsAlternateAndAudits(t *testing.T) {
	e := newEPEnv(t)
	code, loc := e.post(t, addForm("VPN.example.org", "2222"))
	mustOK(t, code, loc)
	code, loc = e.post(t, addForm("2001:DB8::1", ""))
	mustOK(t, code, loc)
	want := []inventory.Endpoint{{Address: "10.0.0.11", Port: 22}, {Address: "vpn.example.org", Port: 2222}, {Address: "2001:db8::1", Port: 22}}
	if got := e.endpoints(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints = %v, want %v", got, want)
	}
	out := e.logged.String()
	for _, w := range []string{"kind=host_endpoint_added", "host=web-01", "user=unknown", "endpoint=vpn.example.org:2222",
		`before=10.0.0.11:22`, `after="10.0.0.11:22 vpn.example.org:2222"`, "endpoint=[2001:db8::1]:22"} {
		if !strings.Contains(out, w) {
			t.Errorf("audit log missing %q:\n%s", w, out)
		}
	}
}

func TestHostEndpointReorderAndAudit(t *testing.T) {
	e := newEPEnv(t)
	for _, a := range []string{"10.0.0.12", "10.0.0.13"} {
		code, loc := e.post(t, addForm(a, "22"))
		mustOK(t, code, loc)
	}
	e.logged.Reset()
	code, loc := e.post(t, endpointForm("move", "10.0.0.13", "22", "0"))
	mustOK(t, code, loc)
	want := []inventory.Endpoint{{Address: "10.0.0.13", Port: 22}, {Address: "10.0.0.11", Port: 22}, {Address: "10.0.0.12", Port: 22}}
	if got := e.endpoints(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("endpoints = %v, want %v", got, want)
	}
	out := e.logged.String()
	for _, w := range []string{"kind=host_endpoint_moved", "endpoint=10.0.0.13:22",
		`before="10.0.0.11:22 10.0.0.12:22 10.0.0.13:22"`, `after="10.0.0.13:22 10.0.0.11:22 10.0.0.12:22"`} {
		if !strings.Contains(out, w) {
			t.Errorf("audit log missing %q:\n%s", w, out)
		}
	}
	// Moving down one step.
	code, loc = e.post(t, endpointForm("move", "10.0.0.13", "22", "1"))
	mustOK(t, code, loc)
	if got := e.endpoints(t)[0].Address; got != "10.0.0.11" {
		t.Fatalf("primary = %s, want 10.0.0.11", got)
	}
}

func TestHostEndpointRemoveAndAudit(t *testing.T) {
	e := newEPEnv(t)
	code, loc := e.post(t, addForm("10.0.0.12", "22"))
	mustOK(t, code, loc)
	e.logged.Reset()
	code, loc = e.post(t, endpointForm("remove", "10.0.0.11", "22", ""))
	mustOK(t, code, loc)
	if got := e.endpoints(t); !reflect.DeepEqual(got, []inventory.Endpoint{{Address: "10.0.0.12", Port: 22}}) {
		t.Fatalf("endpoints = %v", got)
	}
	out := e.logged.String()
	for _, w := range []string{"kind=host_endpoint_removed", "endpoint=10.0.0.11:22", `before="10.0.0.11:22 10.0.0.12:22"`, "after=10.0.0.12:22"} {
		if !strings.Contains(out, w) {
			t.Errorf("audit log missing %q:\n%s", w, out)
		}
	}
}

func TestHostEndpointRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup []url.Values
		form  url.Values
		warn  string
	}{
		{"duplicate", nil, addForm("10.0.0.11", "22"), "already"},
		{"duplicate default port", nil, addForm("10.0.0.11", ""), "already"},
		{"used by other host", nil, addForm("10.0.0.50", "22"), "db-01"},
		{"last endpoint", nil, endpointForm("remove", "10.0.0.11", "22", ""), "last endpoint"},
		{"fifth endpoint", []url.Values{addForm("10.0.0.12", ""), addForm("10.0.0.13", ""), addForm("10.0.0.14", "")},
			addForm("10.0.0.15", ""), "at most 4"},
		{"bad port text", nil, addForm("10.0.0.12", "22a"), "port"},
		{"port zero", nil, addForm("10.0.0.12", "0"), "port"},
		{"port too big", nil, addForm("10.0.0.12", "65536"), "port"},
		{"bad address", nil, addForm("not an address", "22"), "neither"},
		{"empty address", nil, addForm("", "22"), "address"},
		{"zone", nil, addForm("fe80::1%eth0", "22"), "zone"},
		{"unknown endpoint", nil, endpointForm("remove", "10.0.0.99", "22", ""), "not found"},
		{"bad position", nil, endpointForm("move", "10.0.0.11", "22", "x"), "position"},
		{"position out of range", nil, endpointForm("move", "10.0.0.11", "22", "3"), "position"},
		{"unknown op", nil, endpointForm("swap", "10.0.0.11", "22", ""), "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEPEnv(t)
			for _, s := range c.setup {
				code, loc := e.post(t, s)
				mustOK(t, code, loc)
			}
			before := e.endpoints(t)
			e.logged.Reset()
			code, loc := e.post(t, c.form)
			mustWarn(t, code, loc, c.warn)
			if got := e.endpoints(t); !reflect.DeepEqual(got, before) {
				t.Errorf("endpoints changed on refusal: %v -> %v", before, got)
			}
			if strings.Contains(e.logged.String(), "kind=host_endpoint") {
				t.Errorf("refusal wrote an audit line:\n%s", e.logged.String())
			}
		})
	}
}

func TestHostEndpointsSectionRenders(t *testing.T) {
	e := newEPEnv(t)
	body := getBody(t, e.h.Handler(), settingsTab)
	for _, w := range []string{`aria-label="Endpoints"`, "Primary", "10.0.0.11", `name="endpoint_op" value="add"`,
		`action="/hosts/web-01/settings"`, "data-fetch", "same host key"} {
		if !strings.Contains(body, w) {
			t.Errorf("settings tab missing %q", w)
		}
	}
	// One endpoint: nothing to remove or move.
	for _, w := range []string{`name="endpoint_op" value="remove"`, `name="endpoint_op" value="move"`} {
		if strings.Contains(body, w) {
			t.Errorf("single endpoint offers %q", w)
		}
	}
	code, loc := e.post(t, addForm("10.0.0.12", "2222"))
	mustOK(t, code, loc)
	body = getBody(t, e.h.Handler(), settingsTab)
	for _, w := range []string{"Alternate 1", "10.0.0.12", `name="endpoint_op" value="remove"`, `name="endpoint_op" value="move"`} {
		if !strings.Contains(body, w) {
			t.Errorf("settings tab missing %q", w)
		}
	}
}

func TestHostEndpointsSectionHidesAddAtLimit(t *testing.T) {
	e := newEPEnv(t)
	for _, a := range []string{"10.0.0.12", "10.0.0.13", "10.0.0.14"} {
		code, loc := e.post(t, addForm(a, ""))
		mustOK(t, code, loc)
	}
	body := getBody(t, e.h.Handler(), settingsTab)
	if strings.Contains(body, `name="endpoint_op" value="add"`) {
		t.Error("add form shown with 4 endpoints")
	}
	if !strings.Contains(body, "at most 4") {
		t.Error("limit hint missing")
	}
}

func TestHostEndpointWarningIsEscaped(t *testing.T) {
	e := newEPEnv(t)
	code, loc := e.post(t, addForm(`<img src=x onerror=alert(1)>`, "22"))
	if code != http.StatusSeeOther || !strings.Contains(loc, "warn=") {
		t.Fatalf("status %d location %q", code, loc)
	}
	body := getBody(t, e.h.Handler(), loc)
	if strings.Contains(body, "<img src=x") {
		t.Fatal("warning rendered unescaped")
	}
	if !strings.Contains(body, "&lt;img src=x") {
		t.Fatal("escaped warning missing")
	}
}

func TestHostEndpointEditNeedsOrigin(t *testing.T) {
	for _, tc := range []struct {
		origin string
		want   int
	}{
		{"", http.StatusForbidden},
		{"null", http.StatusForbidden},
		{"https://evil.example.org", http.StatusForbidden},
		{epOrigin, http.StatusSeeOther},
	} {
		e := newEPEnv(t)
		srv, err := e.h.Server()
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(srv.Handler)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/hosts/web-01/settings", strings.NewReader(addForm("10.0.0.12", "22").Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		ts.Close()
		if res.StatusCode != tc.want {
			t.Errorf("Origin %q = %d, want %d", tc.origin, res.StatusCode, tc.want)
		}
		if n := len(e.endpoints(t)); (tc.want == http.StatusForbidden) != (n == 1) {
			t.Errorf("Origin %q: %d endpoints after the request", tc.origin, n)
		}
	}
}

// TestHostSettingsFormEndpointChangeAudited covers the existing settings
// textarea: a change of the endpoint list writes the order before and
// after, so no endpoint change is silent.
func TestHostSettingsFormEndpointChangeAudited(t *testing.T) {
	e := newEPEnv(t)
	form := url.Values{"id": {"web-01"}, "environment": {"PROD"}, "criticality": {"MEDIUM"},
		"endpoints": {"10.0.0.12\n10.0.0.11"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/hosts/web-01/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != settingsTab {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	out := e.logged.String()
	for _, w := range []string{"kind=host_endpoints_changed", "before=10.0.0.11:22", `after="10.0.0.12:22 10.0.0.11:22"`} {
		if !strings.Contains(out, w) {
			t.Errorf("audit log missing %q:\n%s", w, out)
		}
	}
	// More than 4 endpoints are refused in the UI.
	form.Set("endpoints", "10.0.0.11\n10.0.0.12\n10.0.0.13\n10.0.0.14\n10.0.0.15")
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/hosts/web-01/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	e.h.Handler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("Location"), "warn=") {
		t.Fatalf("5 endpoints accepted: location %q", rec.Header().Get("Location"))
	}
	if n := len(e.endpoints(t)); n != 2 {
		t.Fatalf("endpoints = %d, want 2", n)
	}
}

// updateRoute sends a full host update for web-01 through the settings
// form (textarea, one endpoint per line) or the JSON route and reports
// whether it was accepted.
type updateRoute struct {
	name string
	send func(t *testing.T, h http.Handler, criticality string, endpoints []string) bool
}

var updateRoutes = []updateRoute{
	{"form", func(t *testing.T, h http.Handler, crit string, eps []string) bool {
		t.Helper()
		form := url.Values{"id": {"web-01"}, "environment": {"PROD"}, "criticality": {crit},
			"endpoints": {strings.Join(eps, "\n")}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/hosts/web-01/settings", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("form update: status %d", rec.Code)
		}
		return rec.Header().Get("Location") == settingsTab
	}},
	{"json", func(t *testing.T, h http.Handler, crit string, eps []string) bool {
		t.Helper()
		q := make([]string, len(eps))
		for i, s := range eps {
			q[i] = strconv.Quote(s)
		}
		body := `{"id":"web-01","environment":"PROD","criticality":"` + crit + `","endpoints":[` + strings.Join(q, ",") + `]}`
		code, resp := postJSON(t, h, "/inventory/hosts/update", body)
		if code != http.StatusOK && code != http.StatusBadRequest {
			t.Fatalf("json update: status %d (%s)", code, resp)
		}
		return code == http.StatusOK
	}},
}

// TestHostUpdateRefusesDuplicateSpellings: both update routes use the
// normalized duplicate rule, so two spellings of one IPv6 endpoint are
// refused and nothing is stored or audited.
func TestHostUpdateRefusesDuplicateSpellings(t *testing.T) {
	for _, rt := range updateRoutes {
		for _, eps := range [][]string{
			{"[fd00::9]:22", "[fd00:0::9]:22"},
			{"fd00::9", "[FD00:0::9]:22"},
			{"10.0.0.11", "10.0.0.11:22"},
		} {
			t.Run(rt.name+"/"+strings.Join(eps, ","), func(t *testing.T) {
				e := newEPEnv(t)
				before := e.endpoints(t)
				e.logged.Reset()
				if rt.send(t, e.h.Handler(), "MEDIUM", eps) {
					t.Fatalf("duplicate spellings %v accepted", eps)
				}
				if got := e.endpoints(t); !reflect.DeepEqual(got, before) {
					t.Errorf("endpoints changed: %v -> %v", before, got)
				}
				if strings.Contains(e.logged.String(), "kind=host_") {
					t.Errorf("refusal wrote an audit line:\n%s", e.logged.String())
				}
			})
		}
	}
}

// TestHostUpdateAuditsEndpointChangeOnBothRoutes: the JSON route writes
// the same before/after endpoint audit line as the settings form, and an
// update that leaves the endpoints alone writes none.
func TestHostUpdateAuditsEndpointChangeOnBothRoutes(t *testing.T) {
	for _, rt := range updateRoutes {
		t.Run(rt.name, func(t *testing.T) {
			e := newEPEnv(t)
			if !rt.send(t, e.h.Handler(), "MEDIUM", []string{"10.0.0.12", "10.0.0.11"}) {
				t.Fatal("reorder refused")
			}
			out := e.logged.String()
			for _, w := range []string{"kind=host_updated", "kind=host_endpoints_changed", "before=10.0.0.11:22",
				`after="10.0.0.12:22 10.0.0.11:22"`} {
				if !strings.Contains(out, w) {
					t.Errorf("audit log missing %q:\n%s", w, out)
				}
			}
			// Swap primary and alternate: also audited.
			e.logged.Reset()
			if !rt.send(t, e.h.Handler(), "MEDIUM", []string{"10.0.0.11", "10.0.0.12"}) {
				t.Fatal("swap refused")
			}
			if w := `before="10.0.0.12:22 10.0.0.11:22" after="10.0.0.11:22 10.0.0.12:22"`; !strings.Contains(e.logged.String(), w) {
				t.Errorf("audit log missing %q:\n%s", w, e.logged.String())
			}
			// Criticality only: host_updated, no endpoint line.
			e.logged.Reset()
			if !rt.send(t, e.h.Handler(), "HIGH", []string{"10.0.0.11", "10.0.0.12"}) {
				t.Fatal("criticality change refused")
			}
			out = e.logged.String()
			if !strings.Contains(out, "kind=host_updated") || strings.Contains(out, "kind=host_endpoints_changed") {
				t.Errorf("unexpected audit for an unchanged endpoint list:\n%s", out)
			}
		})
	}
}

// TestHostUpdateKeepsStoredEndpointsAboveUILimit: a host stored with more
// than MaxEditableEndpoints endpoints (the inventory allows more) can
// still be updated on both routes, but its list cannot grow.
func TestHostUpdateKeepsStoredEndpointsAboveUILimit(t *testing.T) {
	six := []string{"10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15", "10.0.0.16"}
	for _, rt := range updateRoutes {
		t.Run(rt.name, func(t *testing.T) {
			e := newEPEnv(t)
			h, err := e.store.Get(context.Background(), "web-01")
			if err != nil {
				t.Fatal(err)
			}
			h.Endpoints = nil
			for _, a := range six {
				h.Endpoints = append(h.Endpoints, inventory.Endpoint{Address: a, Port: 22})
			}
			if _, err := e.store.Update(context.Background(), h); err != nil {
				t.Fatal(err)
			}
			if !rt.send(t, e.h.Handler(), "HIGH", six) {
				t.Fatal("update of a host with 6 stored endpoints refused")
			}
			got, err := e.store.Get(context.Background(), "web-01")
			if err != nil {
				t.Fatal(err)
			}
			if got.Criticality != inventory.CriticalityHigh || len(got.Endpoints) != 6 {
				t.Fatalf("host = %s with %d endpoints, want HIGH with 6", got.Criticality, len(got.Endpoints))
			}
			if rt.send(t, e.h.Handler(), "HIGH", append(append([]string(nil), six...), "10.0.0.17")) {
				t.Fatal("7th endpoint accepted")
			}
			if got := e.endpoints(t); len(got) != 6 {
				t.Fatalf("endpoints = %d, want 6", len(got))
			}
		})
	}
	// A new host is capped at MaxEditableEndpoints.
	e := newEPEnv(t)
	body := `{"id":"web-09","environment":"PROD","criticality":"LOW","endpoints":["10.1.0.1","10.1.0.2","10.1.0.3","10.1.0.4","10.1.0.5"]}`
	if code, resp := postJSON(t, e.h.Handler(), "/inventory/hosts", body); code != http.StatusBadRequest {
		t.Fatalf("create with 5 endpoints: status %d (%s)", code, resp)
	}
}

// getFailInventory is an inventory without UpdateWithEndpointChange whose
// Get fails, so the endpoint list before an update cannot be read.
type getFailInventory struct{ *fakeInventory }

func (g getFailInventory) Get(context.Context, string) (inventory.Host, error) {
	return inventory.Host{}, errors.New("read failed")
}

// TestHostUpdateAuditsWhenBeforeUnknown: with a store that cannot return
// the change atomically and a failing read of the previous state, the
// update is still audited (before=unknown) and the read error is logged.
func TestHostUpdateAuditsWhenBeforeUnknown(t *testing.T) {
	fake := newFakeInventory()
	fake.hosts["web-01"] = inventory.Host{ID: "web-01", Environment: inventory.EnvProd,
		Criticality: inventory.CriticalityMedium, Endpoints: []inventory.Endpoint{{Address: "10.0.0.11", Port: 22}}}
	logged := &strings.Builder{}
	h := newTestHandler(t, ui.Options{PublicOrigin: epOrigin, Inventory: getFailInventory{fake},
		Log: slog.New(slog.NewTextHandler(logged, nil))})
	body := `{"id":"web-01","environment":"PROD","criticality":"MEDIUM","endpoints":["10.0.0.12","10.0.0.11"]}`
	if code, resp := postJSON(t, h.Handler(), "/inventory/hosts/update", body); code != http.StatusOK {
		t.Fatalf("status %d (%s)", code, resp)
	}
	out := logged.String()
	for _, w := range []string{"read host before update", "kind=host_updated", "kind=host_endpoints_changed",
		"before=unknown", `after="10.0.0.12:22 10.0.0.11:22"`} {
		if !strings.Contains(out, w) {
			t.Errorf("log missing %q:\n%s", w, out)
		}
	}
}
