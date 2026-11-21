// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// UG05: end-to-end acceptance of a write operation, from the HTTP request
// of the operations form to the script on the host.
//
// Until now no Go test carried a writing action from an HTTP request to the
// script: the acceptance tests call the executor directly (newHarness with
// a raw gRPC client), executions.Service runs against hosts that cannot be
// reached, every runServer test has no executor or a fake one, and the
// browser harness calls executions.Service without gRPC. The seam between
// them (form parameters -> ParametersJSON -> canonical form in the permit
// -> script; answers through executorclient) was untested.
//
// Nothing between the browser request and the script is a fake here:
//
//   - the server is the nebula-server binary (e2e01Build), with its real
//     middleware (origin check), session gate, executions.Service and
//     executorclient;
//   - the executor is the harness's in-process executor (newHarness), served
//     over its Unix socket with peercred and the real method-role table; the
//     server reaches it through executorclient's peercred.DialVerified;
//   - the run goes through hostrun to the in-process SSH server
//     (hostruntest), which executes the built-in service.restart script with
//     /bin/sh on this machine.
//
// Only the host's tools are fakes: sudo, systemctl and journalctl in a
// directory put first on the test process's PATH (the SSH server's shells
// inherit it). They log every call to a file the test reads.
//
// The login, the privileged session, the proposal and the approval are the
// browser's requests with the harness's virtual authenticator (the
// executor verifies the assertions); the host is added through the
// inventory route of the UI.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	// ug05Host is the host ID, pinned in the executor and in the server's
	// inventory.
	ug05Host = "runhost"
	// ug05Unit is the unit the operation restarts.
	ug05Unit = "nginx.service"
	// ug05Budget bounds the test after the build (server start, executor
	// connection, every operation).
	ug05Budget = 90 * time.Second
	// ug05ConnectTimeout bounds the wait for the server's executor
	// connection (it retries every 5 seconds, cmd/nebula-server/executor.go).
	ug05ConnectTimeout = 20 * time.Second
	// ug05RunTimeout bounds the wait for one operation to finish.
	ug05RunTimeout = 30 * time.Second
	// ug05Poll is the interval of the bounded waits.
	ug05Poll = 100 * time.Millisecond
	// ug05Description is the unit description the fake systemctl reports:
	// markup that the detail page must show as text.
	ug05Description = "E2E <b>nginx</b> unit"
)

// ug05FakeSudo logs its call and runs the command (sudo -n).
const ug05FakeSudo = `#!/bin/sh
printf 'sudo %s\n' "$*" >> '@LOG@'
[ "$1" = "-n" ] && shift
exec "$@"
`

// ug05FakeSystemctl logs its call. In mode "ok" a restart succeeds and the
// unit is active; in mode "fail" the restart fails as systemctl reports a
// unit that does not come up (exit 1) and the unit is failed.
const ug05FakeSystemctl = `#!/bin/sh
printf 'systemctl %s\n' "$*" >> '@LOG@'
mode=$(cat '@MODE@')
case "$1" in
restart)
	if [ "$mode" = fail ]; then
		echo "Job for $3 failed because the control process exited with error code." >&2
		exit 1
	fi
	echo "E2E-FAKE restarted $3"
	exit 0 ;;
show)
	state=active; sub=running
	if [ "$mode" = fail ]; then state=failed; sub=failed; fi
	printf 'Id=%s\nDescription=@DESC@\nLoadState=loaded\nActiveState=%s\nSubState=%s\nUnitFileState=enabled\nMainPID=4242\n' "$4" "$state" "$sub"
	exit 0 ;;
esac
exit 0
`

// ug05FakeJournalctl logs its call and prints one journal line.
const ug05FakeJournalctl = `#!/bin/sh
printf 'journalctl %s\n' "$*" >> '@LOG@'
echo "2026-11-21T10:00:00+0000 runhost nginx[4242]: E2E-FAKE journal line"
`

// ug05Fakes are the host's fake tools.
type ug05Fakes struct {
	log, mode string
}

// ug05InstallFakes writes the fake tools into a private directory and puts
// it first on PATH for the rest of the test (hostruntest runs the script
// with /bin/sh, which inherits this process's environment).
func ug05InstallFakes(t *testing.T) *ug05Fakes {
	t.Helper()
	dir := privateDir(t)
	f := &ug05Fakes{log: filepath.Join(dir, "calls.log"), mode: filepath.Join(dir, "mode")}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	r := strings.NewReplacer("@LOG@", f.log, "@MODE@", f.mode, "@DESC@", ug05Description)
	for name, body := range map[string]string{"sudo": ug05FakeSudo, "systemctl": ug05FakeSystemctl, "journalctl": ug05FakeJournalctl} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(r.Replace(body)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.setMode(t, "ok")
	f.reset(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return f
}

func (f *ug05Fakes) setMode(t *testing.T, mode string) {
	t.Helper()
	if err := os.WriteFile(f.mode, []byte(mode+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// reset empties the call log.
func (f *ug05Fakes) reset(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.log, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// calls returns the logged calls, one per line.
func (f *ug05Fakes) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// count returns how many logged calls are exactly call.
func (f *ug05Fakes) count(t *testing.T, call string) int {
	t.Helper()
	n := 0
	for _, c := range f.calls(t) {
		if c == call {
			n++
		}
	}
	return n
}

// ug05Env is the running chain: executor harness, pinned host, server.
type ug05Env struct {
	t      *testing.T
	h      *harness
	host   runHost
	fakes  *ug05Fakes
	srv    *e2e01Process
	base   string // http://127.0.0.1:port
	cookie string // the web session cookie value
	hc     *http.Client
}

func (e *ug05Env) with(t *testing.T) *ug05Env {
	c := *e
	c.t = t
	return &c
}

// ug05StartServer writes server.json into dir and starts bin. The
// configured executor socket does not exist yet: the server logs that the
// executor is unreachable and retries in the background. The test then
// links that path to the harness's socket and waits, with a deadline, for
// the server's "executor connected" log line. (A server that reaches the
// executor on its first try logs nothing; the link is the same socket, and
// executorclient still checks the peer UID with SO_PEERCRED.)
func ug05StartServer(t *testing.T, dir, bin, executorSocket string) (*e2e01Process, string) {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	listen, err := e2e01FreeAddr()
	if err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "data")
	for _, d := range []string{dataDir, filepath.Join(dir, "discovery"), filepath.Join(dir, "pve")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "executor.sock")
	cfg, err := json.Marshal(map[string]any{
		"listen":          listen,
		"public_origin":   origin,
		"data_dir":        dataDir,
		"discovery_dir":   filepath.Join(dir, "discovery"),
		"pve_spool_dir":   filepath.Join(dir, "pve"),
		"executor_socket": link,
		"executor_user":   me.Username,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "server.json")
	if err := os.WriteFile(cfgFile, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := e2e01Start(bin, cfgFile)
	if err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.stop(); err != nil {
			t.Errorf("stop the server: %v", err)
		}
	})
	ug05WaitLog(t, srv, "executor unreachable; retrying in the background")
	if err := os.Symlink(executorSocket, link); err != nil {
		t.Fatal(err)
	}
	ug05WaitLog(t, srv, "executor connected")
	return srv, "http://" + listen
}

// ug05WaitLog waits until the server logged a record with msg, or fails
// after ug05ConnectTimeout.
func ug05WaitLog(t *testing.T, srv *e2e01Process, msg string) {
	t.Helper()
	want, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	needle := `"msg":` + string(want)
	deadline := time.Now().Add(ug05ConnectTimeout)
	for !strings.Contains(srv.log.String(), needle) {
		if time.Now().After(deadline) {
			t.Fatalf("the server did not log %q within %s:\n%s", msg, ug05ConnectTimeout, srv.log.String())
		}
		time.Sleep(ug05Poll)
	}
}

// do sends one request as the browser would: with the session cookie (when
// the test has one) and, when withOrigin, the Origin header of the public
// origin. It returns the status and the body.
func (e *ug05Env) do(method, path string, body any, withOrigin bool) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(e.t.Context(), e2e01CallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, e.base+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withOrigin {
		req.Header.Set("Origin", origin)
	}
	if e.cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.cookie})
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, e2e01MaxAnswer))
	if err != nil {
		e.t.Fatal(err)
	}
	if method == http.MethodPost && path == "/login/finish" {
		for _, c := range resp.Cookies() {
			if c.Name == auth.CookieName && c.Value != "" {
				e.cookie = c.Value
			}
		}
	}
	return resp.StatusCode, b
}

// postJSON posts body with Origin and decodes a 200 answer into out.
func (e *ug05Env) postJSON(path string, body, out any) {
	e.t.Helper()
	code, b := e.do(http.MethodPost, path, body, true)
	if code != http.StatusOK {
		e.t.Fatalf("POST %s: %d %s", path, code, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("POST %s: answer %q: %v", path, b, err)
		}
	}
}

// assertion signs the challenge of the WebAuthn request options the server
// delivered, with the harness's authenticator.
func (e *ug05Env) assertion(options json.RawMessage) json.RawMessage {
	e.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(options))
	if err != nil {
		e.t.Fatalf("request options %q: %v", options, err)
	}
	return json.RawMessage(e.h.sign(opts.Challenge))
}

// login runs the browser's login ceremony (POST /login/begin, the
// authenticator's assertion, POST /login/finish) and opens the privileged
// session the same way; the executor verifies both assertions.
func (e *ug05Env) login() {
	e.t.Helper()
	var begin struct {
		LoginID string          `json:"login_id"`
		Options json.RawMessage `json:"options"`
	}
	e.postJSON("/login/begin", map[string]any{}, &begin)
	e.postJSON("/login/finish", map[string]any{"login_id": begin.LoginID, "assertion": e.assertion(begin.Options)}, nil)
	if e.cookie == "" {
		e.t.Fatal("login set no session cookie")
	}
	var priv struct {
		Options json.RawMessage `json:"options"`
	}
	e.postJSON("/privileged/begin", map[string]any{}, &priv)
	e.postJSON("/privileged/finish", map[string]any{"assertion": e.assertion(priv.Options)}, nil)
}

// ug05Created is the answer of POST /operations/create.
type ug05Created struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Risk        string          `json:"risk"`
	Requirement string          `json:"requirement"`
	Options     json.RawMessage `json:"options"`
}

// create proposes service.restart of unit on the host through the
// operations form's request.
func (e *ug05Env) create(unit string) (int, []byte) {
	e.t.Helper()
	return e.do(http.MethodPost, "/operations/create", map[string]any{
		"action": "service.restart", "hosts": []string{ug05Host}, "params": map[string]string{"unit": unit},
	}, true)
}

func (e *ug05Env) createOK(unit string) ug05Created {
	e.t.Helper()
	code, b := e.create(unit)
	if code != http.StatusOK {
		e.t.Fatalf("POST /operations/create: %d %s", code, b)
	}
	var c ug05Created
	if err := json.Unmarshal(b, &c); err != nil {
		e.t.Fatal(err)
	}
	if c.ID == "" || c.State != "pending" || len(c.Options) == 0 {
		e.t.Fatalf("created %+v, want a pending operation with request options", c)
	}
	return c
}

// approve approves c with the authenticator's assertion over the challenge
// the server delivered.
func (e *ug05Env) approve(c ug05Created) {
	e.t.Helper()
	body := map[string]any{"id": c.ID, "assertion": e.assertion(c.Options)}
	if c.Requirement == "assertion_verified_typed_count" {
		body["typed_count"] = 1
	}
	e.postJSON("/operations/approve", body, nil)
}

// state returns the operation's state from GET /operations/{id}/status.
func (e *ug05Env) state(id string) string {
	e.t.Helper()
	code, b := e.do(http.MethodGet, "/operations/"+id+"/status", nil, false)
	if code != http.StatusOK {
		e.t.Fatalf("GET status of %s: %d %s", id, code, b)
	}
	var st struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		e.t.Fatal(err)
	}
	return st.State
}

// waitFinished waits until the operation is no longer approved or running.
func (e *ug05Env) waitFinished(id string) string {
	e.t.Helper()
	deadline := time.Now().Add(ug05RunTimeout)
	for {
		s := e.state(id)
		if s != "approved" && s != "running" {
			return s
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("operation %s still %s after %s; server log:\n%s", id, s, ug05RunTimeout, e.srv.log.String())
		}
		time.Sleep(ug05Poll)
	}
}

// page returns the operation's detail page.
func (e *ug05Env) page(id string) string {
	e.t.Helper()
	code, b := e.do(http.MethodGet, "/operations/"+id, nil, false)
	if code != http.StatusOK {
		e.t.Fatalf("GET /operations/%s: %d %s", id, code, b)
	}
	return string(b)
}

// auditCount counts the executor's audit lines of a permit event kind.
func (e *ug05Env) auditCount(kind string) int {
	return strings.Count(e.h.logs.String(), `"kind":"`+kind+`"`)
}

// TestUG05WriteOperationFromHTTPFormToHostScript builds and starts the
// server once and runs the write operation and its refusals through it.
func TestUG05WriteOperationFromHTTPFormToHostScript(t *testing.T) {
	dir := privateDir(t)
	bin := e2e01Build(t, dir)
	began := time.Now()

	// Executor: unlocked vault, the in-process SSH host pinned, the built-in
	// service.restart script trusted at its declared risk (as trustDefaults
	// trusts the test script).
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost(ug05Host)
	restart, ok := actions.Lookup("service.restart")
	if !ok {
		t.Fatal("service.restart is not registered")
	}
	if err := h.db.TrustArtifact(executordb.TrustedArtifact{
		SHA256: hexSum(restart.Script), ActionID: restart.ID, ModuleVersion: restart.Version,
		Risk: canonical.RiskMedium, TrustedBy: "test-harness",
	}); err != nil {
		t.Fatal(err)
	}

	srv, base := ug05StartServer(t, dir, bin, h.socket)
	e := &ug05Env{t: t, h: h, host: host, srv: srv, base: base,
		hc: &http.Client{Timeout: e2e01CallTimeout, Transport: &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	t.Cleanup(e.hc.CloseIdleConnections)
	e.fakes = ug05InstallFakes(t)

	e.login()
	// The host goes into the server's inventory through the UI's route.
	e.postJSON("/inventory/hosts", map[string]any{"id": ug05Host, "endpoints": []string{host.endpoint}}, nil)

	steps := []struct {
		name string
		fn   func(*testing.T, *ug05Env)
	}{
		{"PostWithoutOriginIsForbidden", ug05NoOrigin},
		{"NothingRunsWithoutApproval", ug05NoApproval},
		{"OptionLikeUnitIsRefusedByTheForm", ug05OptionUnit},
		{"ApprovedRestartRunsTheScriptOnce", ug05Restart},
		{"FailedUnitIsNotSuccess", ug05FailedUnit},
	}
	for _, s := range steps {
		if !t.Run(s.name, func(t *testing.T) { s.fn(t, e.with(t)) }) {
			break
		}
	}
	if err := srv.stop(); err != nil {
		t.Fatalf("stop the server: %v", err)
	}
	if d := time.Since(began); d > ug05Budget {
		t.Fatalf("the chain took %s after the build, want under %s", d.Round(time.Second), ug05Budget)
	}
}

// The origin check stays for the session: the same POST without Origin is
// refused by the middleware with 403 and proposes nothing.
func ug05NoOrigin(t *testing.T, e *ug05Env) {
	proposed := e.auditCount("proposed")
	code, b := e.do(http.MethodPost, "/operations/create", map[string]any{
		"action": "service.restart", "hosts": []string{ug05Host}, "params": map[string]string{"unit": ug05Unit},
	}, false)
	if code != http.StatusForbidden || !strings.Contains(string(b), e2e01OriginRefusal) {
		t.Fatalf("POST /operations/create without Origin: %d %q, want the origin check's 403", code, b)
	}
	if n := e.auditCount("proposed"); n != proposed {
		t.Fatalf("a refused request reached the executor: %d new proposals", n-proposed)
	}
}

// A proposal without approval runs nothing: the operation stays pending,
// the executor authorizes no run and the host sees no command.
func ug05NoApproval(t *testing.T, e *ug05Env) {
	e.fakes.reset(t)
	proposed, authorized := e.auditCount("proposed"), e.auditCount("authorized")
	hostCmds := len(e.host.srv.Commands())
	c := e.createOK(ug05Unit)
	if n := e.auditCount("proposed"); n != proposed+1 {
		t.Fatalf("%d proposals in the executor, want 1", n-proposed)
	}
	// Long enough for a dispatcher to have picked it up if it would.
	time.Sleep(time.Second)
	if s := e.state(c.ID); s != "pending" {
		t.Fatalf("unapproved operation is %s, want pending", s)
	}
	if calls := e.fakes.calls(t); len(calls) != 0 {
		t.Fatalf("host tools called without approval: %q", calls)
	}
	if n := e.auditCount("authorized"); n != authorized {
		t.Fatal("the executor authorized a run without approval")
	}
	if n := len(e.host.srv.Commands()); n != hostCmds {
		t.Fatalf("%d commands reached the host without approval", n-hostCmds)
	}
}

// unit=-x looks like an option to systemctl: the form's request is refused
// by the action's parameter pattern before any executor call, so the
// executor holds no new permit and the host sees nothing.
func ug05OptionUnit(t *testing.T, e *ug05Env) {
	e.fakes.reset(t)
	proposed := e.auditCount("proposed")
	hostCmds := len(e.host.srv.Commands())
	code, b := e.create("-x")
	if code != http.StatusBadRequest || !strings.Contains(string(b), "unit") {
		t.Fatalf("POST /operations/create with unit=-x: %d %q, want 400 naming the parameter", code, b)
	}
	if n := e.auditCount("proposed"); n != proposed {
		t.Fatalf("unit=-x reached the executor: %d new proposals", n-proposed)
	}
	if calls := e.fakes.calls(t); len(calls) != 0 || len(e.host.srv.Commands()) != hostCmds {
		t.Fatalf("unit=-x reached the host: %q", calls)
	}
}

// The approved restart runs the built-in script once on the pinned host
// with the parameters of the form: the fake systemctl was asked for exactly
// one restart of nginx.service, the operation ends with class success, and
// the detail page shows the result as text.
func ug05Restart(t *testing.T, e *ug05Env) {
	e.fakes.reset(t)
	e.fakes.setMode(t, "ok")
	hostCmds := len(e.host.srv.Commands())
	c := e.createOK(ug05Unit)
	e.approve(c)
	if s := e.waitFinished(c.ID); s != "finished" {
		t.Fatalf("operation ended %s, want finished; page:\n%s", s, e.page(c.ID))
	}
	if n := len(e.host.srv.Commands()); n != hostCmds+1 {
		t.Fatalf("%d commands on the host, want 1", n-hostCmds)
	}
	restart := "systemctl restart -- " + ug05Unit
	if n := e.fakes.count(t, restart); n != 1 {
		t.Fatalf("%d calls %q, want exactly 1; calls: %q", n, restart, e.fakes.calls(t))
	}
	if os.Getuid() != 0 {
		// Not root on the host: the script restarts through sudo -n.
		if n := e.fakes.count(t, "sudo -n "+restart); n != 1 {
			t.Fatalf("%d sudo restarts, want 1; calls: %q", n, e.fakes.calls(t))
		}
	}
	for _, c := range e.fakes.calls(t) {
		if strings.Contains(c, "restart") && !strings.HasSuffix(c, restart) {
			t.Fatalf("unexpected restart call %q", c)
		}
	}
	e.h.requireAudit("run_finished", ug05Host, "success")
	t.Logf("risk %s, requirement %s, host tool calls %q", c.Risk, c.Requirement, e.fakes.calls(t))

	p := e.page(c.ID)
	for _, want := range []string{
		"<td>" + ug05Host + "</td>",
		"<td>success</td>",
		"systemctl restart: exit status 0",
		"<th>ActiveState</th><td>active</td>",
		"E2E-FAKE restarted " + ug05Unit,
		// Host output is text, never markup.
		"E2E &lt;b&gt;nginx&lt;/b&gt; unit",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("detail page lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "<b>nginx</b>") {
		t.Error("the detail page renders host output as markup")
	}
}

// A unit that does not come up: systemctl restart exits 1 and the unit is
// failed. The script exits with systemctl's status, which hostrun classifies
// as script_failed (classify in internal/hostrun/durable.go: a non-zero exit
// other than 10, 11 and the signal codes). The page shows that class and
// the failed state, not success.
func ug05FailedUnit(t *testing.T, e *ug05Env) {
	e.fakes.reset(t)
	e.fakes.setMode(t, "fail")
	defer e.fakes.setMode(t, "ok")
	c := e.createOK(ug05Unit)
	e.approve(c)
	if s := e.waitFinished(c.ID); s != "finished" {
		t.Fatalf("operation ended %s, want finished; page:\n%s", s, e.page(c.ID))
	}
	restart := "systemctl restart -- " + ug05Unit
	if n := e.fakes.count(t, restart); n != 1 {
		t.Fatalf("%d calls %q, want exactly 1 (service.restart is never retried); calls: %q", n, restart, e.fakes.calls(t))
	}
	p := e.page(c.ID)
	for _, want := range []string{
		`<span class="status--error">script_failed</span>`,
		"systemctl restart: exit status 1",
		"<th>ActiveState</th><td>failed</td>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("detail page lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "<td>success</td>") {
		t.Errorf("a failed unit is shown as success:\n%s", p)
	}
	if t.Failed() {
		t.Logf("executor log:\n%s", e.h.logs.String())
	}
}
