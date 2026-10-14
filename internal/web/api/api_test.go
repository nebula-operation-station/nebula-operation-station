// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

const opID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"

type fakeOps struct{}

func (fakeOps) Get(_ context.Context, id string) (executions.Execution, error) {
	if id != opID {
		return executions.Execution{}, executions.ErrNotFound
	}
	return executions.Execution{ID: opID, ActionID: "core.facts", ModuleVersion: "1.0.0", Risk: "HIGH", State: "finished",
		CreatedBy: "axel", CreatedAt: time.Unix(1791960000, 0), Params: `{"unit":"nginx.service"}`, Detail: "failed: op-detail",
		Hosts: []executions.Host{{HostID: "web", State: "finished", Class: "script_failed", ExitCode: 3, Detail: "exit 3",
			Result: []byte(`{"secret-ish":"<b>"}`), Log: []byte("host log line\xff")}}}, nil
}
func (fakeOps) List(_ context.Context, limit int) ([]executions.Summary, error) {
	return []executions.Summary{{ID: opID, ActionID: "core.facts", State: "finished", Hosts: 1, Failed: 1}}, nil
}
func (fakeOps) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	return map[string]executions.HostUpdates{"web": {Total: 9, Security: 2, RebootRequired: true, ObservedAt: time.Unix(1791960000, 0)}}, nil
}
func (fakeOps) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	return map[string]executions.OpsState{"web": {State: executions.StateWarning, Reason: "2 security updates"}}, nil
}

const (
	invTok = "nos_inventory-token"
	opsTok = "nos_operations-token"
	logTok = "nos_logs-token"
)

func handler(t *testing.T) http.Handler {
	t.Helper()
	h, err := api.New(api.Options{
		Tokens: []serverconfig.APIToken{
			{Name: "ha", SHA256: api.HashToken(invTok), Scopes: []string{serverconfig.ScopeInventoryRead}},
			{Name: "ops", SHA256: api.HashToken(opsTok), Scopes: []string{serverconfig.ScopeOperationsRead}},
			{Name: "logs", SHA256: api.HashToken(logTok), Scopes: []string{serverconfig.ScopeOperationsRead, serverconfig.ScopeExecutionLogsRead}},
		},
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web", DisplayName: "Web", Environment: inventory.EnvProd, Criticality: inventory.CriticalityHigh}, {ID: "new"}}, nil
		},
		Operations: fakeOps{},
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(t *testing.T, h http.Handler, method, path, tok string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestAPINeedsATokenWithTheScope(t *testing.T) {
	h := handler(t)
	for name, tc := range map[string]struct {
		method, path, tok string
		code              int
	}{
		"no token":         {"GET", "/api/v1/hosts", "", http.StatusUnauthorized},
		"wrong token":      {"GET", "/api/v1/hosts", "nos_wrong", http.StatusUnauthorized},
		"basic auth":       {"GET", "/api/v1/hosts", "", http.StatusUnauthorized},
		"missing scope":    {"GET", "/api/v1/operations", invTok, http.StatusForbidden},
		"other scope":      {"GET", "/api/v1/hosts", opsTok, http.StatusForbidden},
		"write":            {"POST", "/api/v1/hosts", invTok, http.StatusMethodNotAllowed},
		"delete":           {"DELETE", "/api/v1/hosts/web", invTok, http.StatusMethodNotAllowed},
		"unknown endpoint": {"GET", "/api/v1/vault", logTok, http.StatusNotFound},
		"hosts":            {"GET", "/api/v1/hosts", invTok, http.StatusOK},
		"head":             {"HEAD", "/api/v1/hosts", invTok, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			if code, body := get(t, h, tc.method, tc.path, tc.tok); code != tc.code {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	req.SetBasicAuth("x", invTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("basic auth: %d", rec.Code)
	}
}

func TestAPIHostsShowOpsStateAndUpdates(t *testing.T) {
	h := handler(t)
	code, body := get(t, h, "GET", "/api/v1/hosts/web", invTok)
	var v map[string]any
	if code != 200 || json.Unmarshal([]byte(body), &v) != nil || v["ops_state"] != "WARNING" || v["environment"] != "PROD" {
		t.Fatalf("%d %s", code, body)
	}
	if u := v["updates"].(map[string]any); u["security"] != 2.0 || u["reboot_required"] != true {
		t.Fatalf("updates %v", u)
	}
	if code, body := get(t, h, "GET", "/api/v1/hosts", invTok); code != 200 || !strings.Contains(body, `"id":"new","display_name":"","environment":"","criticality":"","ops_state":"UNKNOWN"`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := get(t, h, "GET", "/api/v1/hosts/ghost", invTok); code != http.StatusNotFound {
		t.Fatalf("%d", code)
	}
}

// Host output is sensitive: it needs execution_logs.read.
func TestAPIOperationsShowHostOutputOnlyWithTheLogsScope(t *testing.T) {
	h := handler(t)
	code, body := get(t, h, "GET", "/api/v1/operations/"+opID, opsTok)
	if code != 200 || strings.Contains(body, "host log line") || strings.Contains(body, "secret-ish") || strings.Contains(body, "exit 3") ||
		strings.Contains(body, "nginx.service") || strings.Contains(body, "op-detail") ||
		!strings.Contains(body, `"class":"script_failed"`) || !strings.Contains(body, `"failed":1`) {
		t.Fatalf("%d %s", code, body)
	}
	code, body = get(t, h, "GET", "/api/v1/operations/"+opID, logTok)
	if code != 200 || !strings.Contains(body, "host log line�") || !strings.Contains(body, `secret-ish`) ||
		!strings.Contains(body, "nginx.service") || !strings.Contains(body, "op-detail") {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := get(t, h, "GET", "/api/v1/operations?limit=500", opsTok); code != http.StatusBadRequest {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := get(t, h, "GET", "/api/v1/operations?limit=5", opsTok); code != 200 || !strings.Contains(body, opID) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := get(t, h, "GET", "/api/v1/operations/nope", opsTok); code != http.StatusNotFound {
		t.Fatalf("%d", code)
	}
}
