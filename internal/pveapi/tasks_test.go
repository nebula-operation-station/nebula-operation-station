// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const tasksPath = "/api2/json/nodes/pve1/tasklist"

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
	if first.Status != "started" {
		t.Errorf("first.Status = %q, want started", first.Status)
	}
	if !first.End.IsZero() {
		t.Errorf("first.End = %v, want zero (tasklist carries no end time)", first.End)
	}
	last := got.Tasks[3]
	if last.Type != "update" || last.ID != "0" {
		t.Errorf("last = %+v, want update/0", last)
	}
	// The typed read endpoint is /nodes/{node}/tasklist; nothing else is
	// touched (no /tasks/{upid} status or log endpoint).
	if f.hits[tasksPath] != 1 {
		t.Errorf("tasklist hits = %d, want 1", f.hits[tasksPath])
	}
	if len(f.hits) != 1 {
		t.Errorf("unexpected endpoints hit: %v", f.hits)
	}
}

func TestNodeTasksPVE8(t *testing.T) {
	// PVE 8 tasklist UPIDs carry no trailing status field.
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
	for _, task := range got.Tasks {
		if task.Status != "" {
			t.Errorf("UPID %q: Status = %q, want empty (PVE 8 has no status field)", task.UPID, task.Status)
		}
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
		{"garbage", `{"data":["UPID:bad"]}`},
		{"missing fields", `{"data":["UPID:pve1:00001234:00000001:1761580000:qmstart:100"]}`},
		{"bad start time", `{"data":["UPID:pve1:00001234:00000001:99999999999:qmstart:100:root@pam"]}`},
		{"vmid out of range", `{"data":["UPID:pve1:00001234:00000001:1761580000:qmstart:9999999999:root@pam"]}`},
		{"colon in user", `{"data":["UPID:pve1:00001234:00000001:1761580000:qmstart:100:root:extra@pam"]}`},
		{"invalid status", `{"data":["UPID:pve1:00001234:00000001:1761580000:qmstart:100:root@pam:weird"]}`},
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
	body := `{"data":["UPID:` + strings.Repeat("x", 300) + `"]}`
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: body}})
	c := newTestClient(t, f)
	c.MaxBody = 100

	if _, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestNodeTasksErrorDoesNotLeakBody(t *testing.T) {
	body := `{"data":["marker-xyz"]}`
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
	// The client must only ever GET the tasklist; the per-task status and
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
