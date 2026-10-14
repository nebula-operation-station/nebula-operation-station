// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	approved   string
	exec       executions.Execution
}

func (f *fakeOps) Create(_ context.Context, user, action string, hosts []string) (executions.Created, error) {
	if f.createErr != nil {
		return executions.Created{}, f.createErr
	}
	f.created = append([]string{user, action}, hosts...)
	return executions.Created{ID: opID, State: "pending", Risk: "HIGH"}, nil
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
