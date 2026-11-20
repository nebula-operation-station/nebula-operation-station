// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// E2E02: end-to-end acceptance of the ops agent over real HTTP (ADR 0016).
//
// The agent side is always internal/opsagent/nosclient with a token file
// and, against the binary, the pinned CA and no Origin header.
//
// Two compositions are needed, because nebula-server does not connect a
// finding source to the ops projection yet (opsNoFindings in
// cmd/nebula-server/ops.go): the binary never offers a fix work item.
//
//   - TestE2E02OpsAgentOverRealHTTP runs against the nebula-server binary
//     itself, built and started with the e2e01 helpers behind the e2e01 TLS
//     front, with the ops token "ops-agent" (scopes ops.read and
//     ops.notes.write, source 127.0.0.1) and the agent settings enabled.
//     One full agent cycle (agent-config, work, a note for the due item,
//     status) is answered 2xx by the whole runServer composition, the ops
//     token is refused every proposal, approval and authorisation path, and
//     after shutdown server.db holds no execution and no proposal audit
//     while notes.db holds the note.
//   - TestE2E02FixSuggestionIsOnlyAPrefilledForm uses the ag24 composition
//     (real executor, executions service with the suggestion index, real
//     ops API with a finding double) served over HTTP, plus the real UI
//     handler for the operation form. The agent reads the fix work item and
//     posts a fix suggestion with nosclient; nothing is planned and the
//     executor gets no call. A person opens the suggestion, gets the
//     prefilled form only, and submits it through POST /operations/create:
//     the proposal is at least MEDIUM, pending, and needs the security key
//     although a privileged session is open (ADR 0016 D8, D9).

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const (
	// e2e02Token is the ops agent's bearer token (test only).
	e2e02Token = "nos_e2e02-acceptance-ops-agent-token"
	// e2e02Origin is the binary's public_origin.
	e2e02Origin = "https://nos.e2e02.test"
	// e2e02Summary is the text of the agent's summary note.
	e2e02Summary = "E2E02 fleet summary: nothing open."
	// e2e02FixAction is the step the agent suggests (a catalog action on
	// the suggestion allowlist, offered as a candidate for the group).
	e2e02FixAction = "package.install_security"
)

// --- the real binary ---

// e2e02Env is a running nebula-server with the ops token.
type e2e02Env struct {
	*e2e01Env
}

// e2e02Server is e2e01Server with the ops token instead of the vuln token
// and the agent settings stored (enabled, class lab) before the start, as an
// admin did earlier through the settings page.
func e2e02Server(t *testing.T) *e2e02Env {
	t.Helper()
	dir := privateDir(t)
	bin := e2e01Build(t, dir)
	certPEM, keyPEM, err := e2e01Cert()
	if err != nil {
		t.Fatal(err)
	}
	listen, err := e2e01FreeAddr()
	if err != nil {
		t.Fatal(err)
	}
	e, err := e2e01Files(dir, listen, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.t = t
	// Replace the token file and server.json of e2e01Files.
	if err := os.WriteFile(e.tokenFile, []byte(e2e02Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"listen":          listen,
		"public_origin":   e2e02Origin,
		"data_dir":        e.dataDir,
		"discovery_dir":   filepath.Join(dir, "discovery"),
		"pve_spool_dir":   filepath.Join(dir, "pve"),
		"executor_socket": filepath.Join(dir, "executor.sock"),
		"executor_user":   "nebula-executor",
		"api": map[string]any{"enabled": true, "tokens": []map[string]any{{
			"name":             serverconfig.DefaultOpsTokenName,
			"sha256":           api.HashToken(e2e02Token),
			"scopes":           []string{serverconfig.ScopeOpsRead, serverconfig.ScopeOpsNotesWrite},
			"source_addresses": []string{"127.0.0.1"},
		}}},
	}
	if err := os.WriteFile(filepath.Join(dir, "server.json"), mustMarshal(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	e2e02StoreSettings(t, filepath.Join(e.dataDir, "server.db"))
	e.srv, err = e2e01Start(bin, filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() {
		if err := e.srv.stop(); err != nil {
			t.Errorf("stop the server: %v", err)
		}
	})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.base = "https://" + e2e01TLSFront(t, listen, cert)
	return &e2e02Env{e}
}

// e2e02StoreSettings writes enabled lab settings into the server.db at path.
func e2e02StoreSettings(t *testing.T, path string) {
	t.Helper()
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := opsconfig.NewStore(db, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	row, err := st.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Save(ctx, "admin", ag24Settings(opsconfig.DataClassLab), row.Version, auditlog.New(db, false)); err != nil {
		t.Fatal(err)
	}
}

// opsClient is the agent's NOS client on the binary (pinned CA).
func (e *e2e02Env) opsClient() *nosclient.Client {
	e.t.Helper()
	c, err := nosclient.New(nosclient.Config{BaseURL: e.base, TokenFile: e.tokenFile, CAFile: e.caFile})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *e2e02Env) with(t *testing.T) *e2e02Env {
	return &e2e02Env{e.e2e01Env.with(t)}
}

// TestE2E02OpsAgentOverRealHTTP starts the binary once, runs one agent
// cycle and the refusals, stops it and reads back what was stored.
func TestE2E02OpsAgentOverRealHTTP(t *testing.T) {
	e := e2e02Server(t)
	ran := t.Run("AgentCyclePassesTheRealHTTPChain", func(t *testing.T) { e2e02AgentCycle(t, e.with(t)) })
	t.Run("OpsTokenCannotProposeApproveOrAuthorize", func(t *testing.T) { e2e02Refusals(t, e.with(t)) })
	if err := e.srv.stop(); err != nil {
		t.Fatalf("stop the server: %v", err)
	}
	if !ran {
		t.Fatal("the agent cycle failed; nothing to read back")
	}
	t.Run("StoredNoteOnlyNoExecution", func(t *testing.T) { e2e02ReadBack(t, e.with(t)) })
}

// One agent cycle through the binary's whole HTTP chain, bearer token and no
// Origin header: settings, work list, a note for the due item, the status.
// Every call is answered 2xx (nosclient returns an error otherwise), and the
// answered item is no longer due.
func e2e02AgentCycle(t *testing.T, e *e2e02Env) {
	ctx := e.ctx()
	c := e.opsClient()
	cfg, err := c.AgentConfig(ctx)
	if err != nil {
		t.Fatalf("GET agent-config: %v", err)
	}
	if !cfg.Enabled || cfg.DataClass != opsconfig.DataClassLab {
		t.Fatalf("agent-config %+v, want the stored enabled lab settings", cfg)
	}
	items, err := c.Work(ctx)
	if err != nil {
		t.Fatalf("GET work: %v", err)
	}
	var due *nosclient.WorkItem
	for i := range items {
		if items[i].Kind == string(opsnotes.KindSummary) {
			due = &items[i]
		}
		if items[i].Kind == string(opsnotes.KindFix) {
			t.Errorf("work item %+v: the binary has no finding source, no fix item may be due", items[i])
		}
	}
	if due == nil {
		t.Fatalf("work list %+v has no summary item", items)
	}
	if err := c.PostNote(ctx, nosclient.Draft{Kind: due.Kind, Ref: due.Ref, Digest: due.Digest, Text: e2e02Summary}); err != nil {
		t.Fatalf("POST notes (bearer, no Origin): %v", err)
	}
	if err := c.PostStatus(ctx, nosclient.Status{RunAt: time.Now().UTC().Format(time.RFC3339), ItemsSeen: len(items),
		LLMCalls: 1, NotesWritten: 1, Refusals: []string{}}); err != nil {
		t.Fatalf("POST status (bearer, no Origin): %v", err)
	}
	again, err := c.Work(ctx)
	if err != nil {
		t.Fatalf("GET work again: %v", err)
	}
	for _, it := range again {
		if it.Kind == due.Kind && it.Ref == due.Ref && it.Digest == due.Digest {
			t.Fatalf("the answered item %+v is still due", it)
		}
	}
}

// The ops token reaches nothing that proposes, approves or authorises: the
// operation endpoints of the UI (with and without the public Origin, so
// both the origin check and the session gate are passed through), the
// read API's operations (scope), and every other method on the ops paths.
func e2e02Refusals(t *testing.T, e *e2e02Env) {
	bearer := "Bearer " + e2e02Token
	jsonHdr := func(origin bool) map[string]string {
		h := map[string]string{"Authorization": bearer, "Content-Type": "application/json"}
		if origin {
			h["Origin"] = e2e02Origin
		}
		return h
	}
	propose := `{"action":"` + e2e02FixAction + `","hosts":["web01"],"suggestion":"1.1"}`
	for _, rq := range []struct {
		name, method, path, body string
		origin                   bool
	}{
		{"propose", http.MethodPost, "/operations/create", propose, false},
		{"propose with origin", http.MethodPost, "/operations/create", propose, true},
		{"approve", http.MethodPost, "/operations/approve", `{"id":"x","assertion":{}}`, false},
		{"approve with origin", http.MethodPost, "/operations/approve", `{"id":"x","assertion":{}}`, true},
		{"gate (authorise a stage)", http.MethodPost, "/operations/gate", `{"id":"x"}`, true},
		{"gate commit", http.MethodPost, "/operations/gate/commit", `{"id":"x"}`, true},
		{"retry", http.MethodPost, "/operations/retry", `{"id":"x","host":"web01"}`, true},
		{"open the suggestion form", http.MethodGet, "/operations/new?suggestion=1.1", "", false},
		{"read API operations", http.MethodGet, api.Prefix + "operations", "", false},
		{"read API propose", http.MethodPost, api.Prefix + "operations", propose, false},
		{"ops notes path is not a proposal path", http.MethodPut, api.OpsNotesPath, propose, false},
	} {
		t.Run(rq.name, func(t *testing.T) {
			code, body := e.with(t).raw(rq.method, rq.path, "", jsonHdr(rq.origin), rq.body)
			t.Logf("%s %s: %d %.80q", rq.method, rq.path, code, body)
			if rq.method == http.MethodGet && code == http.StatusOK {
				// The session gate answers a page GET without a session
				// with the login page; the form is never served.
				if !strings.Contains(body, "<title>Log in") || strings.Contains(body, `name="suggestion"`) {
					t.Fatalf("GET %s with the ops token served a page other than the login page: %.200q", rq.path, body)
				}
				return
			}
			if code != http.StatusUnauthorized && code != http.StatusForbidden && code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s with the ops token: %d %q, want 401, 403 or 405", rq.method, rq.path, code, body)
			}
		})
	}
}

// After shutdown: notes.db holds the agent's note, server.db holds no
// execution and no proposal, permit, lease or schedule audit entry.
func e2e02ReadBack(t *testing.T, e *e2e02Env) {
	db, err := serverdb.Open(filepath.Join(e.dataDir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM executions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d executions stored, want none", n)
	}
	e2e02NoProposalAudit(t, db)

	notes, err := opsnotes.Open(filepath.Join(e.dataDir, "opsnotes", "notes.db"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer notes.Close()
	ns, err := notes.List(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 || ns[0].Kind != opsnotes.KindSummary || ns[0].Body.Text != e2e02Summary {
		t.Fatalf("stored notes %+v, want the one summary note", ns)
	}
}

// e2e02ProposalWords mark the audit kinds of anything that plans, approves
// or authorises work on a host (execution_proposed, batch_approved,
// read_grant_proposed, schedule_approved, ...).
var e2e02ProposalWords = []string{"propos", "approv", "permit", "lease", "grant", "schedule", "authoriz"}

// e2e02ProposalAudit returns the audit kinds in db that mark a proposal,
// approval, permit, lease, grant or schedule.
func e2e02ProposalAudit(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT kind FROM audit_log ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		for _, w := range e2e02ProposalWords {
			if strings.Contains(k, w) {
				out = append(out, k)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// e2e02NoProposalAudit fails on any proposal-like audit entry in db.
func e2e02NoProposalAudit(t *testing.T, db *sql.DB) {
	t.Helper()
	if ks := e2e02ProposalAudit(t, db); len(ks) != 0 {
		t.Fatalf("audit entries %v, want no proposal, approval, permit, lease, grant or schedule", ks)
	}
}

// --- the fix suggestion: stored only, a person proposes ---

// e2e02FixEnv is the ag24 composition with the real UI handler for the
// operation form beside it.
type e2e02FixEnv struct {
	*ag24Env
	ui *httptest.Server
}

// newE2E02FixEnv starts the ag24 composition (settings enabled, class lab;
// the store unlocked and a privileged session open, so anything that does
// not need presence would be approved at once) and the UI handler over the
// same executions service and notes store, as cmd/nebula-server wires it.
func newE2E02FixEnv(t *testing.T) *e2e02FixEnv {
	t.Helper()
	e := newAG24Env(t, ag24HostWeb)
	e.enable(opsconfig.DataClassLab)
	e.h.unlock()
	e.h.openSession()
	h, err := ui.New(ui.Options{
		PublicOrigin: ag24NOSBase,
		Operations:   e.ops,
		Log:          e.logger,
		Hosts:        e.inv.List,
		HostKeys: func(ctx context.Context) ([]*pb.HostKeyPin, error) {
			r, err := e.client.ListHostKeys(ctx, &pb.ListHostKeysRequest{})
			if err != nil {
				return nil, err
			}
			return r.GetHosts(), nil
		},
		OperationSuggestions: &ui.OperationSuggestions{Store: e.notes,
			IsAdmin: func(context.Context, string) (bool, error) { return true, nil }},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	return &e2e02FixEnv{ag24Env: e, ui: srv}
}

// person sends one request to the UI as the admin's browser does after the
// session gate (the gate itself is covered against the binary).
func (e *e2e02FixEnv) person(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(e.ctx(), method, e.ui.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.ui.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, e2e01MaxAnswer))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// e2e02Created is the answer of POST /operations/create.
type e2e02Created struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Risk        string          `json:"risk"`
	Requirement string          `json:"requirement"`
	Options     json.RawMessage `json:"options"`
}

// create submits the operation form as the browser's script does.
func (e *e2e02FixEnv) create(t *testing.T, action, host, suggestion string) e2e02Created {
	t.Helper()
	body := mustMarshal(t, map[string]any{"action": action, "hosts": []string{host}, "suggestion": suggestion})
	code, out := e.person(t, http.MethodPost, "/operations/create", string(body))
	if code < 200 || code > 299 {
		t.Fatalf("POST /operations/create %s on %s (suggestion %q): %d %s", action, host, suggestion, code, out)
	}
	var c e2e02Created
	if err := json.Unmarshal(out, &c); err != nil || c.ID == "" {
		t.Fatalf("create answer %s: %v", out, err)
	}
	return c
}

// e2e02AtLeastMedium reports whether risk is MEDIUM or above.
func e2e02AtLeastMedium(risk string) bool {
	return risk == "MEDIUM" || risk == "HIGH" || risk == "CRITICAL"
}

// TestE2E02FixSuggestionIsOnlyAPrefilledForm: the agent's fix suggestion,
// posted with nosclient over HTTP, is stored as a note only; opening it gives
// a prefilled form and plans nothing; the proposal a person submits from it
// is at least MEDIUM and needs the security key despite the open privileged
// session.
func TestE2E02FixSuggestionIsOnlyAPrefilledForm(t *testing.T) {
	e := newE2E02FixEnv(t)
	tokFile := filepath.Join(privateDir(t), "ops.token")
	if err := os.WriteFile(tokFile, []byte(ag24OpsToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := nosclient.New(nosclient.Config{BaseURL: e.srv.URL, TokenFile: tokFile})
	if err != nil {
		t.Fatal(err)
	}
	rpcs := e.rpcs.Load()

	// 1. The agent's cycle: settings, the fix item, the suggestion, status.
	ctx := e.ctx()
	if cfg, err := agent.AgentConfig(ctx); err != nil || !cfg.Enabled {
		t.Fatalf("GET agent-config: %+v, %v", cfg, err)
	}
	items, err := agent.Work(ctx)
	if err != nil {
		t.Fatalf("GET work: %v", err)
	}
	var fix *nosclient.WorkItem
	for i := range items {
		if items[i].Kind == string(opsnotes.KindFix) && items[i].Ref == ag24GroupWeb {
			fix = &items[i]
		}
	}
	if fix == nil || fix.Group == nil || len(fix.Group.Findings) == 0 {
		t.Fatalf("work list %+v has no fix item for %s with findings", items, ag24GroupWeb)
	}
	offered := false
	for _, c := range fix.Group.Candidates {
		offered = offered || (c.Action == e2e02FixAction && c.HostID == ag24HostWeb)
	}
	if !offered {
		t.Fatalf("fix item candidates %+v do not offer %s on %s", fix.Group.Candidates, e2e02FixAction, ag24HostWeb)
	}
	if err := agent.PostNote(ctx, nosclient.Draft{Kind: fix.Kind, Ref: fix.Ref, Digest: fix.Digest,
		Summary: "Install the security updates for openssl.", Urgency: "today",
		Steps: []nosclient.Step{{ActionID: e2e02FixAction, HostID: ag24HostWeb, Why: "fixes " + fix.Group.Findings[0].VulnID}}}); err != nil {
		t.Fatalf("POST fix note: %v", err)
	}
	if err := agent.PostStatus(ctx, nosclient.Status{RunAt: time.Now().UTC().Format(time.RFC3339), ItemsSeen: len(items),
		LLMCalls: 1, NotesWritten: 1, Refusals: []string{}}); err != nil {
		t.Fatalf("POST status: %v", err)
	}

	// 2. Stored as a suggestion only: one note, no execution, no executor
	// call, no proposal audit.
	ns, err := e.notes.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 || ns[0].Kind != opsnotes.KindFix || len(ns[0].Body.Steps) != 1 {
		t.Fatalf("notes %+v, want the one fix note with one step", ns)
	}
	ref := strconv.FormatInt(ns[0].ID, 10) + ".1"
	if n := e.executionRows(); n != 0 {
		t.Fatalf("%d executions after the agent's cycle, want none", n)
	}
	if got := e.rpcs.Load(); got != rpcs {
		t.Fatalf("the agent's cycle made %d executor calls, want none", got-rpcs)
	}
	e2e02NoProposalAudit(t, e.db)

	// 3. The ops token reaches no operation path of the API on this mux
	// either (the read API needs operations.read).
	for _, rq := range []struct{ method, path string }{
		{http.MethodGet, api.Prefix + "operations"},
		{http.MethodPost, api.Prefix + "operations"},
	} {
		if code, body := e.do(ag24OpsToken, rq.method, rq.path, []byte(`{}`)); code < 400 {
			t.Fatalf("%s %s with the ops token: %d %s, want a refusal", rq.method, rq.path, code, body)
		}
	}

	// 4. A person opens the suggestion: the prefilled form, nothing planned.
	code, page := e.person(t, http.MethodGet, "/operations/new?suggestion="+ref, "")
	if code != http.StatusOK {
		t.Fatalf("GET suggestion form: %d %s", code, page)
	}
	for _, want := range []string{`name="suggestion" value="` + ref + `"`, `value="` + e2e02FixAction + `" checked`,
		`value="` + ag24HostWeb + `" checked`, "This execution needs a security-key touch."} {
		if !bytes.Contains(page, []byte(want)) {
			t.Errorf("suggestion form lacks %q", want)
		}
	}
	if n := e.executionRows(); n != 0 {
		t.Fatalf("opening the suggestion planned %d executions", n)
	}
	e2e02NoProposalAudit(t, e.db)

	// 5. The person submits the form: at least MEDIUM, pending, presence;
	// the executor runs nothing without the assertion.
	c := e.create(t, e2e02FixAction, ag24HostWeb, ref)
	if !e2e02AtLeastMedium(c.Risk) || c.Requirement != "assertion_presence" || c.State != "pending" {
		t.Fatalf("proposal from the suggestion %+v, want >= MEDIUM, assertion_presence, pending", c)
	}
	e.wantNoRunWithoutAssertion(t, executions.Created{ID: c.ID, Options: c.Options}, ag24HostWeb)

	// The person changed the action to a natively LOW one: still raised to
	// MEDIUM by the reference (ADR 0016 D9 floor).
	wantNativelyLowRefresh(t)
	low := e.create(t, "package.refresh", ag24HostWeb, ref)
	if low.Risk != "MEDIUM" || low.Requirement != "assertion_presence" || low.State != "pending" {
		t.Fatalf("LOW action from the suggestion %+v, want MEDIUM, assertion_presence, pending", low)
	}
	e.wantNoRunWithoutAssertion(t, executions.Created{ID: low.ID, Options: low.Options}, ag24HostWeb)

	// Control: the same LOW action on a host without a note, without a
	// reference, is approved by the open session; the floor made the
	// difference above.
	plain := e.create(t, "package.refresh", ag24HostDB, "")
	if plain.Risk != "LOW" || plain.State != "approved" {
		t.Fatalf("unmarked LOW action %+v, want LOW approved by the privileged session", plain)
	}

	// The proposals carry their origin into the audit log; the agent made
	// none of them.
	marked := 0
	for _, b := range e.auditBodies() {
		if strings.HasPrefix(b, "execution_proposed ") && strings.Contains(b, "suggestion:"+ref) {
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("%d execution_proposed audit entries carry origin suggestion:%s, want 2", marked, ref)
	}

	// 6. An invented reference opens nothing and plans nothing.
	rows := e.executionRows()
	if code, _ := e.person(t, http.MethodGet, "/operations/new?suggestion="+strconv.FormatInt(ns[0].ID+99, 10)+".1", ""); code != http.StatusNotFound {
		t.Fatalf("invented suggestion form: %d, want 404", code)
	}
	body := mustMarshal(t, map[string]any{"action": e2e02FixAction, "hosts": []string{ag24HostDB}, "suggestion": strconv.FormatInt(ns[0].ID+99, 10) + ".1"})
	if code, out := e.person(t, http.MethodPost, "/operations/create", string(body)); code < 400 {
		t.Fatalf("create with an invented suggestion: %d %s, want a refusal", code, out)
	}
	if e.executionRows() != rows {
		t.Fatal("an invented suggestion planned an execution")
	}
}

// wantNativelyLowRefresh fails unless package.refresh is declared LOW, so the
// floor check above stays meaningful.
func wantNativelyLowRefresh(t *testing.T) {
	t.Helper()
	a, ok := actions.Lookup("package.refresh")
	if !ok || a.Risk != pb.RiskClass_RISK_CLASS_LOW {
		t.Fatalf("package.refresh is not a declared LOW action (%v, %v)", ok, a.Risk)
	}
}
