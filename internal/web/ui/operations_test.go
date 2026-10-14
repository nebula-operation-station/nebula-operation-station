// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
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
