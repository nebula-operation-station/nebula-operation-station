// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const tasksPath = "/api2/json/nodes/pve1/tasks"

func TestNodeTasksPVE9(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve9.json")}})
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if got.Truncated {
		t.Error("Truncated = true, want false")
	}
	if len(got.Tasks) != 4 {
		t.Fatalf("len(Tasks) = %d, want 4", len(got.Tasks))
	}
	first := got.Tasks[0]
	if first.Node != "pve1" || first.Type != "qmstart" || first.ID != "100" || first.User != "root@pam" {
		t.Errorf("first = %+v, want node pve1 type qmstart id 100 user root@pam", first)
	}
	wantStart := time.Unix(1761580000, 0).UTC()
	if !first.Start.Equal(wantStart) {
		t.Errorf("first.Start = %v, want %v", first.Start, wantStart)
	}
	if first.Status != "RUNNING" {
		t.Errorf("first.Status = %q, want RUNNING", first.Status)
	}
	if !first.End.IsZero() {
		t.Errorf("first.End = %v, want zero for active task", first.End)
	}
	last := got.Tasks[3]
	if last.Type != "aptupdate" || last.ID != "" {
		t.Errorf("last = %+v, want aptupdate/empty target", last)
	}
	// The typed read endpoint is /nodes/{node}/tasks; nothing else is
	// touched (no /tasks/{upid} status or log endpoint).
	if f.hits[tasksPath] != 1 {
		t.Errorf("tasklist hits = %d, want 1", f.hits[tasksPath])
	}
	if len(f.hits) != 1 {
		t.Errorf("unexpected endpoints hit: %v", f.hits)
	}
}

func TestNodeTasksPVE8(t *testing.T) {
	// Task status comes from object metadata, never from a UPID suffix.
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve8.json")}})
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if len(got.Tasks) != 4 {
		t.Fatalf("len(Tasks) = %d, want 4", len(got.Tasks))
	}
	for i, want := range []string{"", "OK", "WARNINGS: 1", "job failed"} {
		if got.Tasks[i].Status != want {
			t.Errorf("task %d: Status = %q, want %q", i, got.Tasks[i].Status, want)
		}
	}
	if !got.Tasks[1].End.Equal(time.Unix(1761579030, 0).UTC()) {
		t.Errorf("second task end = %v, want metadata end time", got.Tasks[1].End)
	}
	if got.Tasks[1].Type != "vzdump" || got.Tasks[1].ID != "200" || got.Tasks[1].User != "admin@pve" {
		t.Errorf("second = %+v, want vzdump/200/admin@pve", got.Tasks[1])
	}
}

func TestNodeTasksSince(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve9.json")}})
	c := newTestClient(t, f)

	since := time.Unix(1761578500, 0).UTC()
	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Since: since})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if len(got.Tasks) != 2 {
		t.Fatalf("len(Tasks) = %d, want 2 (start >= since)", len(got.Tasks))
	}
	for _, task := range got.Tasks {
		if task.Start.Before(since) {
			t.Errorf("task %q started %v before since %v", task.UPID, task.Start, since)
		}
	}
}

func TestNodeTasksLimit(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve9.json")}})
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Limit: 2})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if len(got.Tasks) != 2 {
		t.Fatalf("len(Tasks) = %d, want 2", len(got.Tasks))
	}
	if !got.Truncated {
		t.Error("Truncated = false, want true (more tasks matched)")
	}
}

func TestNodeTasksLimitExact(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve9.json")}})
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Limit: 4})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if len(got.Tasks) != 4 || got.Truncated {
		t.Fatalf("len(Tasks)=%d Truncated=%v, want 4/false", len(got.Tasks), got.Truncated)
	}
}

func TestNodeTasksLimitRejected(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve9.json")}})
	c := newTestClient(t, f)

	if _, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Limit: MaxTaskLimit + 1}); err == nil {
		t.Fatal("want error for limit above the maximum")
	}
}

func TestNodeTasksEmpty(t *testing.T) {
	// A node with no task history is a valid empty result, distinct from
	// unavailable.
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: `{"data":[]}`}})
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if !got.Available {
		t.Fatalf("want available, reason %q", got.Reason)
	}
	if len(got.Tasks) != 0 || got.Truncated {
		t.Errorf("Tasks/Truncated = %d/%v, want 0/false", len(got.Tasks), got.Truncated)
	}
}

func TestNodeTasksUnknownNode(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{})
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	wantUnavailable(t, got.Available, got.Reason, "unknown node")
	if !strings.Contains(got.Reason, "unknown node") {
		t.Errorf("Reason = %q, want unknown node explanation", got.Reason)
	}
}

func TestNodeTasksUnavailable(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{})
	f.srv.Close()
	c := newTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	wantUnavailable(t, got.Available, got.Reason, "closed server")
}

func TestNodeTasksTimeout(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: `{"data":[]}`, delay: 300 * time.Millisecond}})
	c := newTestClient(t, f)
	c.Timeout = 50 * time.Millisecond

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	wantUnavailable(t, got.Available, got.Reason, "timeout")
	if !strings.Contains(got.Reason, "timed out") {
		t.Errorf("Reason = %q, want timeout explanation", got.Reason)
	}
}

func TestNodeTasksMalformedUPID(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"garbage", `{"data":[{"upid":"UPID:bad"}]}`},
		{"missing fields", `{"data":[{"upid":"UPID:pve1:00001234:00000001:68FF97E0:qmstart:100:"}]}`},
		{"bad start time", `{"data":[{"upid":"UPID:pve1:00001234:00000001:FFFFFFFF:qmstart:100:root@pam:"}]}`},
		{"nonhex pid", `{"data":[{"upid":"UPID:pve1:0000123Z:00000001:68FF97E0:qmstart:100:root@pam:"}]}`},
		{"colon in user", `{"data":[{"upid":"UPID:pve1:00001234:00000001:68FF97E0:qmstart:100:root:extra@pam:"}]}`},
		{"invalid trailing status", `{"data":[{"upid":"UPID:pve1:00001234:00000001:68FF97E0:qmstart:100:root@pam:started"}]}`},
		{"slash in target", `{"data":[{"upid":"UPID:pve1:00001234:00000001:68FF97E0:qmstart:a/b:root@pam:"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: tt.body}})
			c := newTestClient(t, f)
			if _, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestNodeTasksInvalidNode(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: `{"data":[]}`}})
	c := newTestClient(t, f)

	for _, node := range []string{"", "a b", "a/b", "../etc", strings.Repeat("a", 65)} {
		if _, err := c.NodeTasks(context.Background(), node, TaskFilter{}); err == nil {
			t.Errorf("node %q: want error", node)
		}
	}
}

func TestNodeTasksOversize(t *testing.T) {
	body := `{"data":[{"upid":"UPID:` + strings.Repeat("x", 300) + `"}]}`
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: body}})
	c := newTestClient(t, f)
	c.MaxBody = 100

	if _, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestNodeTasksErrorDoesNotLeakBody(t *testing.T) {
	body := `{"data":[{"upid":"marker-xyz"}]}`
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: body}})
	c := newTestClient(t, f)

	_, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{})
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if strings.Contains(err.Error(), "marker-xyz") {
		t.Error("error message leaks response body")
	}
}

func TestNodeTasksNoMutationEndpoints(t *testing.T) {
	// The client must only ever GET task metadata; the per-task status and
	// log endpoints under /nodes/{node}/tasks/{upid} are out of scope.
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve9.json")}})
	c := newTestClient(t, f)

	if _, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{}); err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	for path := range f.hits {
		if strings.Contains(path, "/tasks/") {
			t.Errorf("client hit task detail endpoint %q", path)
		}
	}
}

func TestUPIDGrammar(t *testing.T) {
	for _, target := range []string{"", "100", "storage-backup"} {
		raw := "UPID:pve-1:0000ABCD:1ABCDEF01:68FF97E0:vzdump:" + target + ":root@pam:"
		got, err := parseUPID(raw)
		if err != nil {
			t.Fatalf("target %q: %v", target, err)
		}
		if got.ID != target || !got.Start.Equal(time.Unix(0x68FF97E0, 0).UTC()) || got.Status != "" {
			t.Fatalf("parsed task = %+v", got)
		}
	}
}

func TestNodeTasksPagination(t *testing.T) {
	for _, tt := range []struct {
		name                               string
		total, limit, wantCount, wantCalls int
		truncated                          bool
	}{
		{"multiple pages", 150, 200, 150, 2, false},
		{"truncated", 250, 150, 150, 2, true},
		{"exact full pages", 200, 200, 200, 3, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.URL.Path != tasksPath {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				start, err := strconv.Atoi(r.URL.Query().Get("start"))
				if err != nil || start != (calls-1)*100 {
					t.Errorf("invalid pagination start %q", r.URL.Query().Get("start"))
				}
				limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
				if err != nil || limit != 100 {
					t.Errorf("invalid pagination limit %q", r.URL.Query().Get("limit"))
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				page := []map[string]any{}
				for i := start; i < min(start+limit, tt.total); i++ {
					when := int64(1761580000 - i)
					page = append(page, map[string]any{"upid": fmt.Sprintf("UPID:pve1:0000ABCD:1ABCDEF01:%08X:aptupdate::root@pam:", when), "node": "pve1", "pid": 0xABCD, "pstart": 0x1ABCDEF01, "starttime": when, "type": "aptupdate", "id": "", "user": "root@pam", "endtime": when + 1, "status": "OK"})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": page})
			}))
			defer srv.Close()
			c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/api2/json", Token: func(context.Context) (string, error) { return "test-token", nil }}
			got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Limit: tt.limit})
			if err != nil {
				t.Fatal(err)
			}
			if !got.Available || len(got.Tasks) != tt.wantCount || got.Truncated != tt.truncated || calls != tt.wantCalls {
				t.Fatalf("available/count/truncated/calls = %v/%d/%v/%d, want true/%d/%v/%d", got.Available, len(got.Tasks), got.Truncated, calls, tt.wantCount, tt.truncated, tt.wantCalls)
			}
			for i, task := range got.Tasks {
				if task.Start.Unix() != int64(1761580000-i) || task.End.Unix() != task.Start.Unix()+1 || task.Status != "OK" {
					t.Fatalf("task %d lost metadata: %+v", i, task)
				}
			}
		})
	}
}

func TestNodeTasksScanIsBounded(t *testing.T) {
	calls := 0
	var page struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(fixture(t, "tasklist_pve9.json")), &page); err != nil {
		t.Fatal(err)
	}
	// An untrusted server ignores Since and keeps returning full pages.
	entries := make([]map[string]any, 100)
	for i := range entries {
		entries[i] = page.Data[0]
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != tasksPath || r.URL.Query().Get("start") != strconv.Itoa((calls-1)*100) || r.URL.Query().Get("limit") != "100" || r.URL.Query().Get("since") != "1761580001" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": entries})
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL + "/api2/json", Token: func(context.Context) (string, error) { return "test-token", nil }}
	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Since: time.Unix(1761580001, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Available || len(got.Tasks) != 0 || !got.Truncated || calls != 10 {
		t.Fatalf("available/count/truncated/calls = %v/%d/%v/%d, want true/0/true/10", got.Available, len(got.Tasks), got.Truncated, calls)
	}
}

func TestNodeTasksRejectsMalformedMetadata(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"end before start", func(task map[string]any) { task["endtime"] = 1 }},
		{"end outside range", func(task map[string]any) { task["endtime"] = maxStartUnix + 1 }},
		{"oversize status", func(task map[string]any) { task["status"] = strings.Repeat("x", maxTextLen+1) }},
		{"oversize user", func(task map[string]any) { task["user"] = strings.Repeat("x", maxTextLen+1) }},
		{"wrong node", func(task map[string]any) { task["upid"] = strings.Replace(task["upid"].(string), "pve1", "pve2", 1) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var page struct {
				Data []map[string]any `json:"data"`
			}
			if err := json.Unmarshal([]byte(fixture(t, "tasklist_pve9.json")), &page); err != nil {
				t.Fatal(err)
			}
			tt.change(page.Data[0])
			body, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: string(body)}})
			if _, err := newTestClient(t, f).NodeTasks(context.Background(), "pve1", TaskFilter{}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}
