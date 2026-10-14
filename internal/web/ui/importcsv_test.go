// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const importCSV = "server_name,ip,vpn_ip,env\nweb-01,10.0.0.1,10.8.0.1,PROD\nweb-02,10.0.0.2,,DEV\nbad,not an ip,,DEV\nweb-01,10.0.0.9,,DEV\n"

func importBody(t *testing.T, csv string, mapping map[string]string, rows []int) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"csv": csv, "mapping": mapping, "rows": rows, "default_criticality": "MEDIUM"})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var importMapping = map[string]string{"id": "server_name", "endpoint1": "ip", "endpoint2": "vpn_ip", "environment": "env"}

func TestImportPreviewAndCommit(t *testing.T) {
	store := newFakeInventory()
	store.hosts["web-02"] = inventory.Host{ID: "web-02"}
	var logged strings.Builder
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store,
		Log: slog.New(slog.NewTextHandler(&logged, nil))}).Handler()

	code, body := postJSON(t, h, "/inventory/import/preview", importBody(t, importCSV, nil, nil))
	if code != http.StatusOK || !strings.Contains(body, `"columns":["server_name","ip","vpn_ip","env"]`) {
		t.Fatalf("columns: %d %s", code, body)
	}
	code, body = postJSON(t, h, "/inventory/import/preview", importBody(t, importCSV, importMapping, nil))
	var p struct {
		Rows []struct {
			Number    int
			ID        string
			Endpoints []string
			Errors    []string
			Exists    bool
		}
	}
	if err := json.Unmarshal([]byte(body), &p); err != nil || code != http.StatusOK || len(p.Rows) != 4 {
		t.Fatalf("preview: %d %s", code, body)
	}
	if strings.Join(p.Rows[0].Endpoints, ",") != "10.0.0.1:22,10.8.0.1:22" || !p.Rows[1].Exists || len(p.Rows[2].Errors) == 0 || len(p.Rows[3].Errors) == 0 {
		t.Fatalf("rows: %+v", p.Rows)
	}
	// Rows with errors, existing hosts and numbers that are not in the file
	// are skipped, whatever the browser selects.
	code, body = postJSON(t, h, "/inventory/import/commit", importBody(t, importCSV, importMapping, []int{1, 2, 3, 4, 99}))
	if code != http.StatusOK || len(store.created) != 1 || store.created[0].ID != "web-01" {
		t.Fatalf("commit: %d %s %v", code, body, store.created)
	}
	for _, want := range []string{`"status":"created"`, `"reason":"already exists"`, `"reason":"not in the file"`} {
		if !strings.Contains(body, want) {
			t.Errorf("commit result misses %s: %s", want, body)
		}
	}
	if !strings.Contains(logged.String(), "host_imported") || !strings.Contains(logged.String(), "kind=host_import") {
		t.Fatalf("audit: %s", logged.String())
	}
}

func TestImportRejections(t *testing.T) {
	store := newFakeInventory()
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store}).Handler()
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"unknown field":  {importBody(t, importCSV, map[string]string{"password": "ip"}, nil), http.StatusBadRequest},
		"unknown column": {importBody(t, importCSV, map[string]string{"id": "nope"}, nil), http.StatusBadRequest},
		"too large":      {importBody(t, strings.Repeat("a", ui.MaxImportBytes+1), nil, nil), http.StatusRequestEntityTooLarge},
		"extra json":     {`{"csv":"a\n","x":1}`, http.StatusBadRequest},
		"too many rows":  {importBody(t, importCSV, importMapping, make([]int, 10001)), http.StatusBadRequest},
	} {
		code, body := postJSON(t, h, "/inventory/import/preview", tc.body)
		if code != tc.code {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if len(store.created) != 0 {
		t.Fatal("created something")
	}
	// Without the inventory store everything is 404.
	h = newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	if code, _ := postJSON(t, h, "/inventory/import/preview", importBody(t, importCSV, nil, nil)); code != http.StatusNotFound {
		t.Fatalf("no store: %d", code)
	}
}

func TestImportStorageErrorsStayInTheLog(t *testing.T) {
	store := newFakeInventory()
	store.createErr = errors.New("disk I/O at /var/lib/nebula/server/server.db")
	var logged strings.Builder
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Inventory: store,
		Log: slog.New(slog.NewTextHandler(&logged, nil))}).Handler()
	_, body := postJSON(t, h, "/inventory/import/commit", importBody(t, importCSV, importMapping, []int{1}))
	if !strings.Contains(body, `"status":"failed"`) || strings.Contains(body, "server.db") || !strings.Contains(logged.String(), "server.db") {
		t.Fatalf("%s / %s", body, logged.String())
	}
}
