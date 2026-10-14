// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// fakeInventory is a ui.InventoryStore for tests.
type fakeInventory struct {
	hosts     map[string]inventory.Host
	createErr error
	updateErr error
	deleteErr error
	created   []inventory.Host
	updated   []inventory.Host
	deleted   []string
}

func newFakeInventory() *fakeInventory {
	return &fakeInventory{hosts: map[string]inventory.Host{}}
}

func (f *fakeInventory) Create(ctx context.Context, h inventory.Host, opts inventory.CreateOptions) (inventory.Host, error) {
	if f.createErr != nil {
		return inventory.Host{}, f.createErr
	}
	if _, ok := f.hosts[h.ID]; ok {
		return inventory.Host{}, fmt.Errorf("create: %w", inventory.ErrHostExists)
	}
	f.hosts[h.ID] = h
	f.created = append(f.created, h)
	return h, nil
}

func (f *fakeInventory) Get(ctx context.Context, id string) (inventory.Host, error) {
	h, ok := f.hosts[id]
	if !ok {
		return inventory.Host{}, fmt.Errorf("get: %w", inventory.ErrHostNotFound)
	}
	return h, nil
}

func (f *fakeInventory) Update(ctx context.Context, h inventory.Host) (inventory.Host, error) {
	if f.updateErr != nil {
		return inventory.Host{}, f.updateErr
	}
	if _, ok := f.hosts[h.ID]; !ok {
		return inventory.Host{}, fmt.Errorf("update: %w", inventory.ErrHostNotFound)
	}
	f.hosts[h.ID] = h
	f.updated = append(f.updated, h)
	return h, nil
}

func (f *fakeInventory) Delete(ctx context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.hosts[id]; !ok {
		return fmt.Errorf("delete: %w", inventory.ErrHostNotFound)
	}
	delete(f.hosts, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func postJSON(t *testing.T, h http.Handler, path, body string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

const validHostBody = `{
  "id": "web-02",
  "display_name": "Web server 2",
  "environment": "PROD",
  "criticality": "HIGH",
  "endpoints": ["10.0.0.5", "10.8.0.5:2222", "[fd00::9]:2222"],
  "tags": {"rack": "a1"}
}`

func TestInventoryCreateHost(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	code, body := postJSON(t, h.Handler(), "/inventory/hosts", validHostBody)
	if code != http.StatusOK {
		t.Fatalf("POST /inventory/hosts: status %d, want 200 (body %s)", code, body)
	}
	if !strings.Contains(body, `"ok":true`) {
		t.Errorf("response %q, want {\"ok\":true}", body)
	}
	if len(store.created) != 1 {
		t.Fatalf("store created %d hosts, want 1", len(store.created))
	}
	got := store.created[0]
	if got.ID != "web-02" || got.DisplayName != "Web server 2" {
		t.Errorf("host = %+v, want id web-02", got)
	}
	if got.Environment != inventory.EnvProd || got.Criticality != inventory.CriticalityHigh {
		t.Errorf("environment/criticality = %s/%s, want PROD/HIGH", got.Environment, got.Criticality)
	}
	wantEndpoints := []inventory.Endpoint{
		{Address: "10.0.0.5", Port: 22},   // bare host: default port
		{Address: "10.8.0.5", Port: 2222}, // explicit port
		{Address: "fd00::9", Port: 2222},  // bracketed IPv6
	}
	if len(got.Endpoints) != len(wantEndpoints) {
		t.Fatalf("endpoints = %+v, want %+v", got.Endpoints, wantEndpoints)
	}
	for i, e := range wantEndpoints {
		if got.Endpoints[i] != e {
			t.Errorf("endpoint %d = %+v, want %+v", i, got.Endpoints[i], e)
		}
	}
	if got.Tags["rack"] != "a1" {
		t.Errorf("tags = %v, want rack=a1", got.Tags)
	}
}

func TestInventoryUpdateHost(t *testing.T) {
	store := newFakeInventory()
	store.hosts["web-01"] = inventory.Host{
		ID:          "web-01",
		DisplayName: "Web server 1",
		Environment: inventory.EnvProd,
		Criticality: inventory.CriticalityHigh,
		Endpoints:   []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}},
	}
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	code, body := postJSON(t, h.Handler(), "/inventory/hosts/update", strings.Replace(validHostBody, "web-02", "web-01", 1))
	if code != http.StatusOK {
		t.Fatalf("POST /inventory/hosts/update: status %d, want 200 (body %s)", code, body)
	}
	if !strings.Contains(body, `"ok":true`) {
		t.Errorf("response %q, want {\"ok\":true}", body)
	}
	if len(store.updated) != 1 || store.updated[0].ID != "web-01" {
		t.Fatalf("store updated %+v, want one update of web-01", store.updated)
	}
	if store.updated[0].DisplayName != "Web server 2" {
		t.Errorf("display name = %q, want the updated value", store.updated[0].DisplayName)
	}
}

func TestInventoryDeleteHost(t *testing.T) {
	store := newFakeInventory()
	store.hosts["web-01"] = inventory.Host{ID: "web-01"}
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	code, body := postJSON(t, h.Handler(), "/inventory/hosts/delete", `{"id":"web-01"}`)
	if code != http.StatusOK {
		t.Fatalf("POST /inventory/hosts/delete: status %d, want 200 (body %s)", code, body)
	}
	if !strings.Contains(body, `"ok":true`) {
		t.Errorf("response %q, want {\"ok\":true}", body)
	}
	if len(store.deleted) != 1 || store.deleted[0] != "web-01" {
		t.Fatalf("store deleted %v, want [web-01]", store.deleted)
	}
	if _, ok := store.hosts["web-01"]; ok {
		t.Error("host still in the store after delete")
	}
}

func TestInventoryValidationReturns400WithProblemText(t *testing.T) {
	store := newFakeInventory()
	store.createErr = &inventory.ValidationError{Problems: []string{
		`id "Bad_ID" must match ^[a-z0-9][a-z0-9._-]{0,62}$`,
		`environment "STAGE" must be DEV, QA or PROD`,
	}}
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	code, body := postJSON(t, h.Handler(), "/inventory/hosts", validHostBody)
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (body %s)", code, body)
	}
	for _, want := range []string{`"error"`, "invalid host:", "must be DEV, QA or PROD"} {
		if !strings.Contains(body, want) {
			t.Errorf("response %q missing %q", body, want)
		}
	}
	if len(store.created) != 0 {
		t.Error("store created a host despite the validation error")
	}
}

func TestInventoryBadEndpointReturns400(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	body := `{"id":"web-02","display_name":"x","environment":"DEV","criticality":"LOW","endpoints":["10.0.0.1:notaport"]}`
	code, resp := postJSON(t, h.Handler(), "/inventory/hosts", body)
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (body %s)", code, resp)
	}
	if !strings.Contains(resp, "port") {
		t.Errorf("response %q does not describe the bad endpoint", resp)
	}
}

func TestInventoryUnknownFieldRejected(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	for _, path := range []string{"/inventory/hosts", "/inventory/hosts/update", "/inventory/hosts/delete"} {
		body := `{"id":"web-01","bogus":1}`
		code, resp := postJSON(t, h.Handler(), path, body)
		if code != http.StatusBadRequest {
			t.Errorf("POST %s with unknown field: status %d, want 400 (body %s)", path, code, resp)
		}
	}
}

func TestInventoryBadJSONRejected(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	code, resp := postJSON(t, h.Handler(), "/inventory/hosts", `{"id":`)
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (body %s)", code, resp)
	}
}

func TestInventoryBodyOverLimitRejected(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	// Push the body just over 64 KiB with a long display name.
	body := `{"id":"web-02","display_name":"` + strings.Repeat("a", 64<<10) + `","environment":"DEV","criticality":"LOW","endpoints":["10.0.0.1"]}`
	code, resp := postJSON(t, h.Handler(), "/inventory/hosts", body)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413 (body %s)", code, resp)
	}
	if !strings.Contains(resp, "too large") {
		t.Errorf("response %q, want a too-large error", resp)
	}
}

func TestInventoryEndpointsRejectNonPost(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	for _, path := range []string{"/inventory/hosts", "/inventory/hosts/update", "/inventory/hosts/delete"} {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: status %d, want 405", path, rec.Code)
		}
	}
}

func TestInventoryNotFoundReturns404(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{name: "update unknown host", path: "/inventory/hosts/update", body: validHostBody},
		{name: "delete unknown host", path: "/inventory/hosts/delete", body: `{"id":"ghost"}`},
		{name: "delete empty id", path: "/inventory/hosts/delete", body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := postJSON(t, h.Handler(), tc.path, tc.body)
			if code != http.StatusNotFound {
				t.Fatalf("status %d, want 404 (body %s)", code, resp)
			}
			if !strings.Contains(resp, `"error":"host not found"`) {
				t.Errorf("response %q, want {\"error\":\"host not found\"}", resp)
			}
		})
	}
}

func TestInventoryStoreErrorHidesDetail(t *testing.T) {
	const detail = "disk on fire at /run/nebula/server.db: i/o timeout"
	for _, tc := range []struct {
		name string
		path string
		body string
		kind string
	}{
		{name: "create", path: "/inventory/hosts", body: validHostBody, kind: "createErr"},
		{name: "update", path: "/inventory/hosts/update", body: validHostBody, kind: "updateErr"},
		{name: "delete", path: "/inventory/hosts/delete", body: `{"id":"web-01"}`, kind: "deleteErr"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logged strings.Builder
			store := newFakeInventory()
			switch tc.kind {
			case "createErr":
				store.createErr = errors.New(detail)
			case "updateErr":
				store.updateErr = errors.New(detail)
			case "deleteErr":
				store.deleteErr = errors.New(detail)
			}
			h := newTestHandler(t, ui.Options{
				PublicOrigin: "https://nebula.example.org",
				Inventory:    store,
				Log:          slog.New(slog.NewTextHandler(&logged, nil)),
			})
			code, resp := postJSON(t, h.Handler(), tc.path, tc.body)
			if code != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500 (body %s)", code, resp)
			}
			if !strings.Contains(resp, `"error":"inventory unavailable"`) {
				t.Errorf("response %q, want {\"error\":\"inventory unavailable\"}", resp)
			}
			if strings.Contains(resp, "disk on fire") || strings.Contains(resp, "server.db") {
				t.Errorf("response %q leaks the error detail", resp)
			}
			if !strings.Contains(logged.String(), detail) {
				t.Errorf("log %q missing the error detail", logged.String())
			}
		})
	}
}

func TestInventoryEndpointsWithoutStoreAre404(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"})
	for _, tc := range []struct {
		path string
		body string
	}{
		{path: "/inventory/hosts", body: validHostBody},
		{path: "/inventory/hosts/update", body: validHostBody},
		{path: "/inventory/hosts/delete", body: `{"id":"web-01"}`},
	} {
		code, resp := postJSON(t, h.Handler(), tc.path, tc.body)
		if code != http.StatusNotFound {
			t.Errorf("POST %s without store: status %d, want 404 (body %s)", tc.path, code, resp)
		}
	}
}

func TestInventoryPageWithoutStoreHasNoButtons(t *testing.T) {
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Hosts:        func(ctx context.Context) ([]inventory.Host, error) { return inventoryHosts(), nil },
	})
	body := getBody(t, h.Handler(), "/inventory")
	for _, forbidden := range []string{"Add host", "inventory__edit", "inventory__delete", "inventory.js"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("read-only inventory page contains %q", forbidden)
		}
	}
}

func TestInventoryPageWithStoreHasFormAndButtons(t *testing.T) {
	store := newFakeInventory()
	store.hosts["web-01"] = inventory.Host{
		ID:          "web-01",
		DisplayName: "Web server 1",
		Environment: inventory.EnvProd,
		Criticality: inventory.CriticalityHigh,
		Endpoints:   []inventory.Endpoint{{Address: "10.0.0.5", Port: 22}},
		Tags:        map[string]string{"rack": "a1"},
	}
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Hosts:        func(ctx context.Context) ([]inventory.Host, error) { return inventoryHosts(), nil },
		Inventory:    store,
	})
	body := getBody(t, h.Handler(), "/inventory")
	for _, want := range []string{
		"Add host",
		`id="host-form"`,
		`class="button inventory__edit"`,
		`class="button inventory__delete"`,
		`class="inventory__delete-confirm"`,
		`src="/static/webauthn.js"`,
		`src="/static/inventory.js"`,
		// The row carries the data the edit form is prefilled from
		// (html/template escapes the JSON quotes in the attribute).
		`data-id="web-01"`,
		`data-endpoints="[&#34;10.0.0.5:22&#34;,&#34;10.0.0.5:2222&#34;]"`,
		`data-tags="{}"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("inventory page missing %q", want)
		}
	}
}

func TestInventoryAuditLogged(t *testing.T) {
	var logged strings.Builder
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Inventory:    store,
		Log:          slog.New(slog.NewTextHandler(&logged, nil)),
	})
	if code, body := postJSON(t, h.Handler(), "/inventory/hosts", validHostBody); code != http.StatusOK {
		t.Fatalf("create: status %d (body %s)", code, body)
	}
	out := logged.String()
	for _, want := range []string{"host_created", "web-02", "user=unknown"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log %q missing %q", out, want)
		}
	}
	logged.Reset()
	if code, body := postJSON(t, h.Handler(), "/inventory/hosts/delete", `{"id":"web-02"}`); code != http.StatusOK {
		t.Fatalf("delete: status %d (body %s)", code, body)
	}
	out = logged.String()
	if !strings.Contains(out, "host_deleted") || !strings.Contains(out, "web-02") {
		t.Errorf("audit log %q missing the delete line", out)
	}
}

func TestInventoryNeedsJSONContentTypeAndRejectsDuplicates(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store})
	for _, ct := range []string{"", "application/x-www-form-urlencoded", "text/plain", "multipart/form-data; boundary=x"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/inventory/hosts", strings.NewReader(validHostBody))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		h.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType || len(store.created) != 0 {
			t.Fatalf("content type %q: status %d, created %d", ct, rec.Code, len(store.created))
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/inventory/hosts", strings.NewReader(validHostBody))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("charset parameter: %d %s", rec.Code, rec.Body.String())
	}
	code, body := postJSON(t, h.Handler(), "/inventory/hosts", validHostBody)
	if code != http.StatusConflict || !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate: %d %s", code, body)
	}
}

// Every script a page references is embedded: a missing one would turn
// the host form into a plain GET form and break the page silently.
func TestPagesOnlyReferenceEmbeddedScripts(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: newFakeInventory(),
		Hosts: func(context.Context) ([]inventory.Host, error) { return nil, nil }})
	src := regexp.MustCompile(`<script src="(/static/[^"]+)"`)
	for _, page := range []string{"/inventory", "/dashboard", "/login", "/setup"} {
		body := getBody(t, h.Handler(), page)
		matches := src.FindAllStringSubmatch(body, -1)
		if len(matches) == 0 {
			t.Fatalf("%s references no scripts", page)
		}
		for _, m := range matches {
			rec := httptest.NewRecorder()
			h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, m[1], nil))
			if rec.Code != http.StatusOK {
				t.Errorf("%s: %s answers %d", page, m[1], rec.Code)
			}
		}
	}
}
