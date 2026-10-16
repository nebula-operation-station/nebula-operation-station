// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const opID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"

type fakeOps struct {
	createErr  error
	approveErr error
	created    []string
	plan       executions.Plan
	approved   string
	exec       executions.Execution
	rollout    *pb.Rollout
	gateRes    executions.GateResult
	gateErr    error
	gates      []string
}

func (f *fakeOps) CreateStaged(_ context.Context, user, action string, hosts []string, _ map[string]string, plan executions.Plan) (executions.Created, error) {
	if f.createErr != nil {
		return executions.Created{}, f.createErr
	}
	f.plan = plan
	f.created = append([]string{user, action}, hosts...)
	return executions.Created{ID: opID, State: "pending", Risk: "HIGH"}, nil
}

func (f *fakeOps) Rollout(context.Context, string) (*pb.Rollout, error) {
	if f.rollout == nil {
		return nil, status.Error(codes.Unavailable, "down")
	}
	return f.rollout, nil
}

func (f *fakeOps) BeginGate(_ context.Context, _, id string, g executions.Gate) (executions.GateResult, error) {
	f.gates = append(f.gates, fmt.Sprintf("begin %s %s %d %s", id, g.Kind, g.Stage, g.Host))
	return f.gateRes, f.gateErr
}

func (f *fakeOps) CommitGate(_ context.Context, _, id string, g executions.Gate, assertion []byte) error {
	f.gates = append(f.gates, fmt.Sprintf("commit %s %s %d %s %s", id, g.Kind, g.Stage, g.Host, assertion))
	return f.gateErr
}

func (f *fakeOps) Abort(_ context.Context, _, id string) error {
	f.gates = append(f.gates, "abort "+id)
	return f.gateErr
}

func (f *fakeOps) RetryHost(_ context.Context, _, id, host string) error {
	f.gates = append(f.gates, "retry "+id+" "+host)
	return f.gateErr
}

func (f *fakeOps) Approve(_ context.Context, _ string, id string, assertion []byte, _ uint32) error {
	f.approved = id + ":" + string(assertion)
	return f.approveErr
}

func (f *fakeOps) Get(_ context.Context, id string) (executions.Execution, error) {
	if id != opID {
		return executions.Execution{}, executions.ErrNotFound
	}
	return f.exec, nil
}

func (f *fakeOps) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	return map[string]executions.HostUpdates{"web": {HostID: "web", Total: 3, Security: 1, RebootRequired: true, ObservedAt: time.Unix(1791960000, 0)}}, nil
}

func (f *fakeOps) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	return map[string]executions.OpsState{"web": {State: "WARNING", Reason: "1 security updates", ObservedAt: time.Unix(1791960000, 0)}}, nil
}

func (f *fakeOps) List(context.Context, int) ([]executions.Summary, error) {
	return []executions.Summary{{ID: opID, ActionID: "core.facts", Risk: "HIGH", State: "finished", CreatedBy: "axel", CreatedAt: time.Unix(1791960000, 0), Hosts: 1}}, nil
}

func opsHandler(t *testing.T, ops ui.Operations, log *strings.Builder) http.Handler {
	t.Helper()
	o := ui.Options{
		PublicOrigin: "https://nebula.example.org",
		Operations:   ops,
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web", DisplayName: "<b>Web</b>"}, {ID: "new"}}, nil
		},
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:x"}}, nil
		},
	}
	if log != nil {
		o.Log = slog.New(slog.NewTextHandler(log, nil))
	}
	return newTestHandler(t, o).Handler()
}

func TestOperationsPages(t *testing.T) {
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "core.facts", ModuleVersion: "1.0.0", Risk: "HIGH", State: "pending",
		Requirement: "assertion_verified", Digest: strings.Repeat("d", 64), Options: []byte(`{"publicKey":{"challenge":"a\"b<"}}`),
		CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{{HostID: "web", State: "finished", Class: "script_failed", Detail: "exit status 3",
			Result: []byte(`{"x":"<script>"}`), Log: []byte("<img src=x onerror=alert(1)>")}}}}
	h := opsHandler(t, f, nil)

	list := getBody(t, h, "/operations")
	if !strings.Contains(list, `href="/operations/`+opID+`"`) || !strings.Contains(list, "core.facts") {
		t.Fatalf("list: %s", list)
	}
	form := getBody(t, h, "/operations/new")
	if !strings.Contains(form, `value="core.facts"`) || !strings.Contains(form, "&lt;b&gt;Web&lt;/b&gt;") ||
		!strings.Contains(form, `name="host" value="new" disabled`) || !strings.Contains(form, "operations.js") {
		t.Fatalf("new: %s", form)
	}
	page := getBody(t, h, "/operations/"+opID)
	for _, want := range []string{"Approve with security key", "&lt;img src=x", "&lt;script&gt;", "data-options=", "exit status 3"} {
		if !strings.Contains(page, want) {
			t.Errorf("detail page misses %q", want)
		}
	}
	if strings.Contains(page, "<img src=x") || strings.Contains(page, `"x": "<script>"`) {
		t.Error("host output rendered as HTML")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/operations/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", rec.Code)
	}
}

func TestOperationsWithoutServiceAreEmptyOr404(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	if body := getBody(t, h, "/operations"); !strings.Contains(body, "Operations") {
		t.Fatalf("empty page: %s", body)
	}
	for _, p := range []string{"/operations/new", "/operations/" + opID} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if code, _ := postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web"]}`); code != http.StatusNotFound {
		t.Errorf("create: %d", code)
	}
}

func TestOperationCreateAndApprove(t *testing.T) {
	f := &fakeOps{}
	h := opsHandler(t, f, nil)
	code, body := postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web"]}`)
	if code != http.StatusOK || !strings.Contains(body, opID) || strings.Join(f.created, ",") != "unknown,core.facts,web" {
		t.Fatalf("create: %d %s %v", code, body, f.created)
	}
	if code, _ := postJSON(t, h, "/operations/create", `{"action":"x","hosts":[],"extra":1}`); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", code)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/operations/create", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form post: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/operations/create", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("GET on create")
	}
	code, body = postJSON(t, h, "/operations/approve", `{"id":"`+opID+`","assertion":{"id":"cred"}}`)
	if code != http.StatusOK || f.approved != opID+`:{"id":"cred"}` {
		t.Fatalf("approve: %d %s %s", code, body, f.approved)
	}
}

func TestOperationErrorsAreSafeForTheBrowser(t *testing.T) {
	for name, tc := range map[string]struct {
		create, approve error
		path, body      string
		code            int
		want, notWant   string
	}{
		"host error": {create: &executions.HostError{Host: "new", Reason: "not enrolled (no pinned host key)"}, path: "/operations/create",
			code: http.StatusBadRequest, want: "host new: not enrolled"},
		"executor refusal": {create: status.Error(codes.FailedPrecondition, "privileged_session_required: LOW risk needs an active privileged session"),
			path: "/operations/create", code: http.StatusConflict, want: "privileged session"},
		"executor down": {create: status.Error(codes.Unavailable, "dial unix /run/nebula/executor.sock: no such file"), path: "/operations/create",
			code: http.StatusBadGateway, want: "executor unavailable", notWant: "executor.sock"},
		"storage": {create: errors.New("sqlite: disk I/O error at /var/lib/nebula/server/server.db"), path: "/operations/create",
			code: http.StatusInternalServerError, want: "operations unavailable", notWant: "server.db"},
		"bad key": {approve: status.Error(codes.PermissionDenied, "assertion_invalid: signature does not verify"), path: "/operations/approve",
			code: http.StatusForbidden, want: "security key not accepted", notWant: "signature"},
		"bad parameter": {create: &executions.ParamError{Reason: "unit: not a valid value"}, path: "/operations/create",
			code: http.StatusBadRequest, want: "unit: not a valid value"},
		"not pending": {approve: executions.ErrNotPending, path: "/operations/approve", code: http.StatusConflict, want: "not waiting"},
	} {
		t.Run(name, func(t *testing.T) {
			var log strings.Builder
			h := opsHandler(t, &fakeOps{createErr: tc.create, approveErr: tc.approve}, &log)
			body := `{"action":"core.facts","hosts":["new"]}`
			if tc.path == "/operations/approve" {
				body = `{"id":"` + opID + `","assertion":{}}`
			}
			code, resp := postJSON(t, h, tc.path, body)
			if code != tc.code || !strings.Contains(resp, tc.want) || (tc.notWant != "" && strings.Contains(resp, tc.notWant)) {
				t.Fatalf("%d %s", code, resp)
			}
		})
	}
}

func TestUpdatesAreShownAsText(t *testing.T) {
	sim := base64.StdEncoding.EncodeToString([]byte("Inst open<b>ssl [1] (2 Debian-Security:12/stable-security [amd64])\nInst openssl [3.0.1] (3.0.2 Debian-Security:12/stable-security [amd64])\n"))
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "package.list_updates", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{{HostID: "web", State: "finished", Class: "success",
			Result: []byte(`{"format":"apt-simulate-v1","mode":"upgrade","simulate":"` + sim + `","reboot_required":true,"reboot_pkgs":"","lists_mtime":0,"proxmox":false}`)}}}}
	h := opsHandler(t, f, nil)
	page := getBody(t, h, "/operations/"+opID)
	if !strings.Contains(page, "1 updates, 1 security") || !strings.Contains(page, "<td>openssl</td><td>3.0.1</td><td>3.0.2</td>") || strings.Contains(page, "open<b>") {
		t.Fatalf("page: %s", page)
	}
	o := ui.Options{PublicOrigin: "https://nebula.example.org", Operations: f,
		Hosts: func(context.Context) ([]inventory.Host, error) { return []inventory.Host{{ID: "web"}}, nil }}
	inv := getBody(t, newTestHandler(t, o).Handler(), "/inventory")
	if !strings.Contains(inv, "1 security / 3 total, reboot required, checked 2026-10-14") || !strings.Contains(inv, ">WARNING</span>") ||
		!strings.Contains(inv, "· 1 security updates") {
		t.Fatalf("inventory: %s", inv)
	}
}

func TestInstallResultsAreShown(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	res := `{"format":"apt-install-v1","phase":"done","mode":"install_security","apt_exit":0,"packages":"` + enc([]byte("openssl\n")) +
		`","dpkg_audit_clean":true,"reboot_required":true,"new_failed_units":"` + enc([]byte("nginx<b>.service\n")) + `","docker":""}`
	pre := `{"format":"apt-install-v1","phase":"precheck","reason":"less than 500 MB free on /var"}`
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "package.install_security", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{
			{HostID: "a", State: "finished", Class: "success", Result: []byte(res)},
			{HostID: "b", State: "finished", Class: "precheck_failed", Result: []byte(pre)},
		}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{"1 packages", "reboot required", "WARNING: units failed since the update: nginx&lt;b&gt;.service",
		"Precheck failed: less than 500 MB free on /var. Nothing was installed."} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
}

func TestServiceResultsAreShown(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	list := `{"format":"systemd-units-v1","units":"` + enc("nginx.service loaded failed failed Web <b>server</b>\n") + `"}`
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "service.list", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: []byte(list)}}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{"<td>nginx.service</td>", `<span class="status--error">failed</span>`, "Web &lt;b&gt;server&lt;/b&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("list page misses %q", want)
		}
	}
	st := `{"format":"systemd-status-v1","phase":"done","verb":"restart","exit":0,"show":"` + enc("ActiveState=active\n") +
		`","journal":"` + enc("started <script>\n") + `"}`
	f.exec = executions.Execution{ID: opID, ActionID: "service.restart", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Params: `{"unit":"nginx.service"}`,
		Hosts:  []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: []byte(st)}}}
	page = getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{"systemctl restart: exit status 0", "<th>ActiveState</th><td>active</td>", "started &lt;script&gt;",
		"nginx.service"} {
		if !strings.Contains(page, want) {
			t.Errorf("status page misses %q", want)
		}
	}
}

func TestDockerResultsAreShown(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	id := strings.Repeat("ab", 32)
	list := `{"format":"docker-ps-v1","phase":"done","present":true,"version":"` + enc("27.3.1") + `","containers":"` +
		enc(id+"\tweb\tnginx:<b>1</b>\trunning\tUp 2 hours (unhealthy)\t0.0.0.0:80->80/tcp\tsite\tweb\t/srv/site\n"+
			id+"\tdb\tpostgres:16\texited\tExited (0) 1 hour ago\t\t\t\t\n") + `"}`
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "docker.list", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{
			{HostID: "a", State: "finished", Class: "success", Result: []byte(list)},
			{HostID: "b", State: "finished", Class: "success", Result: []byte(`{"format":"docker-ps-v1","phase":"done","present":false}`)},
			{HostID: "c", State: "finished", Class: "precheck_failed", Result: []byte(`{"format":"docker-ps-v1","phase":"precheck","reason":"docker ps failed"}`)},
		}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{"Docker 27.3.1: 2 containers, 1 running, 1 stopped", `<span class="status--error">1 unhealthy</span>`,
		"Compose projects: site", `<span title="/srv/site">site / web</span>`, "nginx:&lt;b&gt;1&lt;/b&gt;", "0.0.0.0:80-&gt;80/tcp",
		"Docker is not installed on this host.", "Precheck failed: docker ps failed"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
}

func TestDockerLogsAreShown(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	res := `{"format":"docker-logs-v1","phase":"done","container":"web","state":"` + enc("exited") + `","logs":"` +
		enc("2026-10-14T10:00:00Z <script>alert(1)</script>\n") + `"}`
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "docker.logs", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Params: `{"container":"web"}`,
		Hosts:  []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: []byte(res)}}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{`Container web: <span class="status--error">exited</span>; 1 log lines`,
		"2026-10-14T10:00:00Z &lt;script&gt;alert(1)&lt;/script&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
}

func TestDockerInspectIsShown(t *testing.T) {
	b, err := os.ReadFile("../../executions/dockerhost/testdata/docker29-inspect.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "docker.inspect", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Params: `{"container":"full"}`,
		Hosts: []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: b},
			{HostID: "b", State: "finished", Class: "precheck_failed", Result: []byte(`{"format":"docker-inspect-v1","phase":"precheck","reason":"no such container"}`)}}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{"<td>full <span class=\"hint\">b46feb47000b</span></td>", "nos-test/sleeper@sha256:1c39e3d3",
		`<span class="status--error">unhealthy</span>`, "unless-stopped; 0 restarts", "bridge (172.17.0.2)",
		"<td>90/tcp</td><td>127.0.0.1:9090</td>", "<td>/data</td><td>bind</td><td>/tmp</td><td>read-only</td>",
		"<td>volume nosvol</td>", "Precheck failed: no such container"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(page, "hunter2") {
		t.Fatal("secret on the page")
	}
}

func stagedExecution() executions.Execution {
	return executions.Execution{ID: opID, ActionID: "core.facts", State: "running", CreatedAt: time.Unix(1791960000, 0), Digest: strings.Repeat("d", 64),
		StagePlan: `{"plan":"stages-v1","stages":[{"name":"canary","hosts":["web"],"max_failed":0,"max_unreachable":0,"continue":"manual","timeout_s":600},` +
			`{"name":"rest","hosts":["db","app"],"max_failed":1,"max_unreachable":1,"continue":"manual","timeout_s":600}]}`,
		Waiting: "stage 1 (canary) passed; waiting for you to continue to stage 2",
		Hosts: []executions.Host{
			{HostID: "web", State: "finished", Class: "success", Stage: 1},
			{HostID: "db", State: "waiting", Stage: 2},
			{HostID: "app", State: "waiting", Stage: 2},
		}}
}

func TestStagedOperationShowsStagesAndGate(t *testing.T) {
	f := &fakeOps{exec: stagedExecution(), rollout: &pb.Rollout{OpenStage: 1,
		GateRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED,
		Stages:          []*pb.StageStatus{{Open: true, Passed: true, Outcomes: []*pb.HostOutcome{{HostId: "web", Outcome: "succeeded"}}}, {}}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{"<td>1. canary</td>", "<td>db, app</td>", "<td>1 / 1</td>", "waiting for you to continue to stage 2",
		`data-kind="open" data-stage="2"`, "Continue to stage 2 with security key", `id="rollout-abort"`, "<td>passed</td>", "<td>closed</td>"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	// Stage-2 hosts are not open yet: no skip.
	if strings.Contains(page, `data-kind="skip"`) {
		t.Error("skip offered for a closed stage")
	}

	// Hardened mode: the CLI command instead of a button; an unreachable
	// host of the open stage can be retried or skipped.
	f.rollout = &pb.Rollout{OpenStage: 2, GateRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY,
		Stages: []*pb.StageStatus{{Open: true, Passed: true}, {Open: true, Outcomes: []*pb.HostOutcome{{HostId: "db", Outcome: "unreachable"}}}}}
	f.exec.Hosts[1] = executions.Host{HostID: "db", State: "finished", Class: "network_unreachable", Stage: 2}
	page = getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	for _, want := range []string{`class="button button--small retry-button" data-host="db"`, `data-kind="skip" data-host="db"`, `data-kind="skip" data-host="app"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(page, `data-kind="open"`) {
		t.Error("gate offered although the open stage has not passed")
	}

	// The executor's view is unavailable: stages from the plan, no buttons.
	f.rollout = nil
	page = getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	if !strings.Contains(page, "<td>2. rest</td>") || strings.Contains(page, "gate-button") || strings.Contains(page, "rollout-abort") {
		t.Error("buttons without the executor's view")
	}
}

func TestGateEndpoints(t *testing.T) {
	f := &fakeOps{exec: stagedExecution(), gateRes: executions.GateResult{Done: true}}
	h := opsHandler(t, f, nil)
	if code, body := postJSON(t, h, "/operations/gate", `{"id":"`+opID+`","kind":"open","stage":2}`); code != http.StatusOK || !strings.Contains(body, `"done":true`) {
		t.Fatalf("%d %s", code, body)
	}
	f.gateRes = executions.GateResult{Options: []byte(`{"publicKey":{"challenge":"x"}}`)}
	if code, body := postJSON(t, h, "/operations/gate", `{"id":"`+opID+`","kind":"open","stage":2}`); code != http.StatusOK || !strings.Contains(body, `"options":{"publicKey"`) {
		t.Fatalf("%d %s", code, body)
	}
	f.gateRes = executions.GateResult{CLI: true}
	if code, body := postJSON(t, h, "/operations/gate", `{"id":"`+opID+`","kind":"skip","host":"db"}`); code != http.StatusConflict || !strings.Contains(body, "nebula approve --skip db") {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := postJSON(t, h, "/operations/gate/commit", `{"id":"`+opID+`","kind":"open","stage":2,"assertion":{"id":"cred"}}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, _ := postJSON(t, h, "/operations/abort", `{"id":"`+opID+`"}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, _ := postJSON(t, h, "/operations/retry", `{"id":"`+opID+`","host":"db"}`); code != http.StatusOK {
		t.Fatal(code)
	}
	want := []string{"begin " + opID + " open 2 ", "begin " + opID + " open 2 ", "begin " + opID + " skip 0 db",
		"commit " + opID + ` open 2  {"id":"cred"}`, "abort " + opID, "retry " + opID + " db"}
	if strings.Join(f.gates, "|") != strings.Join(want, "|") {
		t.Fatalf("%q", f.gates)
	}
	for err, code := range map[error]int{
		executions.ErrNotFound:                                   http.StatusNotFound,
		executions.ErrNotRunning:                                 http.StatusConflict,
		executions.ErrNoRetry:                                    http.StatusConflict,
		&executions.PlanError{Reason: "x"}:                       http.StatusBadRequest,
		status.Error(codes.PermissionDenied, "assertion"):        http.StatusConflict,
		status.Error(codes.Unavailable, "dial /run/x.sock"):      http.StatusBadGateway,
		status.Error(codes.FailedPrecondition, "stage_not_done"): http.StatusConflict,
	} {
		f.gateErr = err
		for _, path := range []string{"/operations/gate", "/operations/gate/commit", "/operations/abort", "/operations/retry"} {
			if c, body := postJSON(t, h, path, `{"id":"`+opID+`"}`); c != code || strings.Contains(body, "/run/") {
				t.Errorf("%v %s: %d %s", err, path, c, body)
			}
		}
	}
	if code, _ := postJSON(t, h, "/operations/gate", `{"id":"`+opID+`","extra":1}`); code != http.StatusBadRequest {
		t.Fatal(code)
	}
}

func TestCreatePassesThePlan(t *testing.T) {
	f := &fakeOps{}
	h := opsHandler(t, f, nil)
	code, _ := postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web","db"],"plan":{"preset":"canary","size":1,"continue":"manual","max_failed":1}}`)
	if code != http.StatusOK || f.plan != (executions.Plan{Preset: "canary", Size: 1, Continue: "manual", MaxFailed: 1}) {
		t.Fatalf("%d %+v", code, f.plan)
	}
	f.createErr = &executions.PlanError{Reason: "the canary must be 1 to 1 hosts"}
	if code, body := postJSON(t, h, "/operations/create", `{"action":"core.facts","hosts":["web"],"plan":{"preset":"canary"}}`); code != http.StatusBadRequest || !strings.Contains(body, "canary") {
		t.Fatalf("%d %s", code, body)
	}
}

func TestDockerControlIsShown(t *testing.T) {
	b, err := os.ReadFile("../../executions/dockerhost/testdata/docker29-start.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "docker.start", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Params: `{"container":"plain"}`, Hosts: []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: b}}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	if !strings.Contains(page, "docker start plain: exit status 0;") || !strings.Contains(page, "state exited → running") {
		t.Fatal(page)
	}
}

func TestDockerUpdatesAreShown(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	b := "sha256:" + strings.Repeat("b", 64)
	res := `{"format":"docker-updates-v1","phase":"done","images":1,"lines":"` + enc("nginx:1.27\tupdate\t"+b+"\tlocal none\n"+"bad<b>:1\tcurrent\t"+b+"\t\n") + `"}`
	f := &fakeOps{exec: executions.Execution{ID: opID, ActionID: "docker.check_updates", State: "finished", CreatedAt: time.Unix(1791960000, 0),
		Hosts: []executions.Host{{HostID: "a", State: "finished", Class: "success", Result: []byte(res)}}}}
	page := getBody(t, opsHandler(t, f, nil), "/operations/"+opID)
	if !strings.Contains(page, "1 images checked") || !strings.Contains(page, "1 with an update available") || !strings.Contains(page, "<td>nginx:1.27</td>") || strings.Contains(page, "bad<b>") {
		t.Fatal(page)
	}
}
