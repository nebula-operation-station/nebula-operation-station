// SPDX-License-Identifier: AGPL-3.0-or-later

// Round trip of the read-only API token through runServer (docs/admin/guide.md
// 10.2): nebula-server -api-token NAME:SCOPE prints an entry, the entry is put
// into server.json unchanged, the server is started, and a client with the
// token reads hosts and operations. The requests here carry no Origin header
// and are not sent by vrServer.do, so the chain that a real agent meets runs.
// The data is written to the real server.db before the start, and the
// responses are read back through the stores the server uses.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	arrHost   = "web-01"
	arrOp     = "00000001-0000-4000-8000-000000000001"
	arrAction = "updates.check"
	// arrMarker precedes the printed JSON entry in the -api-token output.
	arrMarker = "restart nebula-server:\n\n"
)

// arrIssued is one token printed by newAPIToken and the entry it printed.
type arrIssued struct {
	token string
	entry string
}

// arrPrint runs newAPIToken for spec and takes the token and the JSON entry
// out of the printed output, the way an operator would copy them.
func arrPrint(t *testing.T, spec string) arrIssued {
	t.Helper()
	var out bytes.Buffer
	if err := newAPIToken(spec, &out); err != nil {
		t.Fatalf("newAPIToken(%q): %v", spec, err)
	}
	var tok string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "  nos_") {
			tok = strings.TrimSpace(line)
			break
		}
	}
	if tok == "" {
		t.Fatalf("no token line in output:\n%s", out.String())
	}
	i := strings.Index(out.String(), arrMarker)
	if i < 0 {
		t.Fatalf("no entry marker in output:\n%s", out.String())
	}
	entry := strings.TrimSpace(out.String()[i+len(arrMarker):])
	return arrIssued{token: tok, entry: entry}
}

// arrAPISection builds the "api" section of server.json from printed entries,
// inserting each entry's text as printed. The loader must accept it as it is.
func arrAPISection(t *testing.T, issued ...arrIssued) json.RawMessage {
	t.Helper()
	parts := make([]string, 0, len(issued))
	for _, x := range issued {
		parts = append(parts, x.entry)
	}
	return json.RawMessage(`{"enabled": true, "tokens": [` + strings.Join(parts, ", ") + `]}`)
}

// arrSeed writes one inventory host, one finished operation with a result
// and log, and a stored Ops State into dir's server.db, through the same
// stores the server reads from.
func arrSeed(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := inventory.Host{ID: arrHost, DisplayName: "Web 01", Environment: "DEV", Criticality: "LOW", CredentialRef: "lab",
		Endpoints: []inventory.Endpoint{{Address: "10.0.0.5"}}}
	if _, err := inventory.New(db).Create(ctx, h, inventory.CreateOptions{}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	finished := int64(1_800_000_000)
	if _, err := db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state,
		durable, timeout_s, created_by, created_at, finished_at) VALUES (?, ?, '1.0.0', ?, 'read', 'finished', 0, 60, 'alice', ?, ?)`,
		arrOp, arrAction, strings.Repeat("a", 64), finished-1, finished); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints,
		state, class, exit_code, result, log, started_at, finished_at) VALUES (?, ?, 'fp', 'lab', '[]',
		'finished', 'success', 0, ?, ?, ?, ?)`,
		arrOp, arrHost, []byte("3 updates"), []byte("apt: ok\n"), finished-1, finished); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO host_ops_state (host_id, state, reason, source, observed_at, changed_at)
		VALUES (?, 'READY', '', 'test', ?, ?)`, arrHost, finished, finished); err != nil {
		t.Fatal(err)
	}
}

// arrReq sends one request with no Origin header. bearer, when not empty, is
// the Authorization token and cookie, when not empty, a session cookie.
func arrReq(t *testing.T, base, method, path, bearer, cookie string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// TestPrintedAPITokenEntryLoadsUnchanged checks that the entry printed by
// -api-token holds the hash and not the token, and that the server loads it
// as it was printed: a request with the token gets 200 from the server.
func TestPrintedAPITokenEntryLoadsUnchanged(t *testing.T) {
	ha := arrPrint(t, "homeassistant:inventory.read")
	var entry serverconfig.APIToken
	if err := json.Unmarshal([]byte(ha.entry), &entry); err != nil {
		t.Fatalf("printed entry is not JSON: %v\n%s", err, ha.entry)
	}
	if strings.Contains(ha.entry, ha.token) {
		t.Fatal("printed entry contains the token itself, it must hold only the hash")
	}
	if entry.Name != "homeassistant" || entry.SHA256 != api.HashToken(ha.token) ||
		len(entry.Scopes) != 1 || entry.Scopes[0] != serverconfig.ScopeInventoryRead {
		t.Fatalf("printed entry = %+v, does not match the token %q", entry, ha.token)
	}
	if len(entry.SourceAddresses) != 0 {
		t.Fatalf("printed entry carries source_addresses %v, want none", entry.SourceAddresses)
	}

	dir := t.TempDir()
	sock := serveVTExecutor(t)
	arrSeed(t, dir)
	cfg := vrConfig(t, dir, sock, arrAPISection(t, ha))
	s := startVR(t, dir, cfg)
	code, body := arrReq(t, s.base, http.MethodGet, "/api/v1/hosts", ha.token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/hosts with the printed token = %d %s", code, body)
	}
}

// TestReadOnlyAPIAnswersFromRealStores runs the printed entries through
// runServer and reads hosts and operations with them, without an Origin
// header. The answers carry the seeded host and operation, and the fields
// of docs/admin/guide.md 10.2; only a token with execution_logs.read gets
// the host output.
func TestReadOnlyAPIAnswersFromRealStores(t *testing.T) {
	hosts := arrPrint(t, "ha:inventory.read")
	ops := arrPrint(t, "status:operations.read")
	logs := arrPrint(t, "logs:operations.read,execution_logs.read")
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	arrSeed(t, dir)
	s := startVR(t, dir, vrConfig(t, dir, sock, arrAPISection(t, hosts, ops, logs)))

	// Hosts: exactly the seeded host, with its Ops State from the store.
	code, body := arrReq(t, s.base, http.MethodGet, "/api/v1/hosts", hosts.token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/hosts = %d %s", code, body)
	}
	var list struct {
		Hosts []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("hosts body %s: %v", body, err)
	}
	if len(list.Hosts) != 1 || list.Hosts[0]["id"] != arrHost || list.Hosts[0]["ops_state"] != "READY" ||
		list.Hosts[0]["display_name"] != "Web 01" || list.Hosts[0]["environment"] != "DEV" || list.Hosts[0]["criticality"] != "LOW" {
		t.Fatalf("hosts = %s, want the seeded host READY", body)
	}
	if _, ok := list.Hosts[0]["updates"]; ok {
		t.Fatalf("host without an update check carries updates: %s", body)
	}
	code, body = arrReq(t, s.base, http.MethodGet, "/api/v1/hosts/"+arrHost, hosts.token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/hosts/%s = %d %s", arrHost, code, body)
	}
	var one map[string]any
	if err := json.Unmarshal(body, &one); err != nil || one["id"] != arrHost || one["ops_state"] != "READY" {
		t.Fatalf("host %s: %v", body, err)
	}
	if code, _ = arrReq(t, s.base, http.MethodGet, "/api/v1/hosts/no-such-host", hosts.token, ""); code != http.StatusNotFound {
		t.Fatalf("unknown host = %d, want 404", code)
	}

	// Operations: the list and the one operation, without host output.
	code, body = arrReq(t, s.base, http.MethodGet, "/api/v1/operations", ops.token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/operations = %d %s", code, body)
	}
	var listed struct {
		Operations []map[string]any `json:"operations"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("operations body %s: %v", body, err)
	}
	if len(listed.Operations) != 1 || listed.Operations[0]["id"] != arrOp || listed.Operations[0]["action"] != arrAction ||
		listed.Operations[0]["state"] != "finished" || listed.Operations[0]["created_by"] != "alice" {
		t.Fatalf("operations = %s, want the seeded operation", body)
	}
	code, body = arrReq(t, s.base, http.MethodGet, "/api/v1/operations/"+arrOp, ops.token, "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/operations/{id} = %d %s", code, body)
	}
	var op struct {
		ID        string           `json:"id"`
		State     string           `json:"state"`
		HostsList []map[string]any `json:"host_runs"`
	}
	if err := json.Unmarshal(body, &op); err != nil {
		t.Fatalf("operation body %s: %v", body, err)
	}
	if op.ID != arrOp || op.State != "finished" || len(op.HostsList) != 1 || op.HostsList[0]["host"] != arrHost ||
		op.HostsList[0]["class"] != "success" {
		t.Fatalf("operation = %s, want the seeded run of %s", body, arrHost)
	}
	for _, k := range []string{"result", "log", "detail", "params"} {
		if strings.Contains(string(body), `"`+k+`"`) {
			t.Fatalf("operation without execution_logs.read carries %q: %s", k, body)
		}
	}

	// With execution_logs.read the host output comes as text.
	code, body = arrReq(t, s.base, http.MethodGet, "/api/v1/operations/"+arrOp, logs.token, "")
	if code != http.StatusOK {
		t.Fatalf("GET operation with logs scope = %d %s", code, body)
	}
	if !strings.Contains(string(body), `"result":"3 updates"`) || !strings.Contains(string(body), `"log":"apt: ok\n"`) {
		t.Fatalf("operation with execution_logs.read lacks the output: %s", body)
	}

	// No answer may hold a token or a token hash.
	for _, x := range []arrIssued{hosts, ops, logs} {
		if strings.Contains(string(body), x.token) || strings.Contains(string(body), api.HashToken(x.token)) {
			t.Fatal("an answer contains a token or a token hash")
		}
	}
}

// TestReadOnlyAPIRefusalsOnTheRunChain sends the refusals through the same
// chain: no or wrong token, a scope that does not cover the path, methods
// other than GET, and the session rules when a session cookie comes along.
func TestReadOnlyAPIRefusalsOnTheRunChain(t *testing.T) {
	hosts := arrPrint(t, "ha:inventory.read")
	ops := arrPrint(t, "status:operations.read")
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	arrSeed(t, dir)
	alice, _ := vrSessions(t, dir)
	s := startVR(t, dir, vrConfig(t, dir, sock, arrAPISection(t, hosts, ops)))
	opPath := "/api/v1/operations/" + arrOp

	// Authentication.
	for _, p := range []string{"/api/v1/hosts", opPath} {
		if code, _ := arrReq(t, s.base, http.MethodGet, p, "", ""); code != http.StatusUnauthorized {
			t.Fatalf("GET %s without token = %d, want 401", p, code)
		}
	}
	if code, _ := arrReq(t, s.base, http.MethodGet, "/api/v1/hosts", "nos_wrong-token", ""); code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", code)
	}

	// Scopes: a token reads only the paths of its scopes.
	if code, _ := arrReq(t, s.base, http.MethodGet, opPath, hosts.token, ""); code != http.StatusForbidden {
		t.Fatalf("hosts-only token on an operation = %d, want 403", code)
	}
	if code, _ := arrReq(t, s.base, http.MethodGet, "/api/v1/hosts", ops.token, ""); code != http.StatusForbidden {
		t.Fatalf("operations-only token on hosts = %d, want 403", code)
	}

	// Methods: the API is read-only, every other method is 405 with the token.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		for _, p := range []string{"/api/v1/hosts", "/api/v1/hosts/" + arrHost, "/api/v1/operations", opPath} {
			if code, body := arrReq(t, s.base, m, p, hosts.token, ""); code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s with token = %d %s, want 405", m, p, code, body)
			}
		}
	}

	// Session rules: a GET with the token and a session cookie is still
	// answered by the token API (the cookie is not used there). A state-changing
	// request with a cookie keeps the origin check, so it is refused before
	// the API sees it: the token exemption needs no cookie.
	if code, body := arrReq(t, s.base, http.MethodGet, "/api/v1/hosts", hosts.token, alice); code != http.StatusOK {
		t.Fatalf("GET with token and session cookie = %d %s, want 200", code, body)
	}
	if code, body := arrReq(t, s.base, http.MethodPost, "/api/v1/hosts", hosts.token, alice); code != http.StatusForbidden {
		t.Fatalf("POST with token and session cookie without Origin = %d %s, want 403", code, body)
	}
}

// TestRunRefusesReadTokenWithSourceAddresses checks the source address rule
// for the read-only token. The configuration allows source_addresses only on
// the vulnerability token and the ops token (serverconfig, Problems), and the
// read-only API does not check them. So a read-only entry that carries them
// must stop the start, and the server must not serve with it.
func TestRunRefusesReadTokenWithSourceAddresses(t *testing.T) {
	hosts := arrPrint(t, "ha:inventory.read")
	entry := strings.TrimSuffix(hosts.entry, "}") + `, "source_addresses": ["127.0.0.1"]}`
	var m map[string]any
	if err := json.Unmarshal([]byte(entry), &m); err != nil {
		t.Fatalf("constructed entry is not JSON: %v", err)
	}
	dir := t.TempDir()
	sock := serveVTExecutor(t)
	arrSeed(t, dir)
	cfg := vrConfig(t, dir, sock, json.RawMessage(`{"enabled": true, "tokens": [`+entry+`]}`))
	cfg["listen"] = freeListenAddr(t)
	path := writeConfig(t, dir, cfg)
	var stderr bytes.Buffer
	err := runServer(context.Background(), []string{"-config", path}, &stderr, vulnHooks{sink: newVTSink()})
	if err == nil {
		t.Fatal("runServer started with source_addresses on a read-only token")
	}
	if !strings.Contains(err.Error(), "source_addresses") {
		t.Fatalf("runServer error = %v, want the source_addresses problem", err)
	}
}
