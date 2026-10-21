// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// seedExecution inserts one finished execution with one host row directly,
// bypassing the approval flow (the batch reads are plain SELECTs).
func seedExecution(t *testing.T, db *sql.DB, id, action, host, class string, result []byte, created, finished int64) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at, finished_at)
		VALUES (?, ?, '1.0.0', ?, 'LOW', 'finished', 0, 60, 'axel', ?, ?)`, id, action, strings.Repeat("a", 64), created, finished); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, result, started_at, finished_at)
		VALUES (?, ?, 'SHA256:x', 'nebula-default', '[]', 'finished', ?, ?, ?, ?)`, id, host, class, result, finished, finished); err != nil {
		t.Fatal(err)
	}
}

func TestLastResultsLatestSuccessPerHost(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	ctx := context.Background()
	seedExecution(t, db, strings.Repeat("1", 36), "core.facts", "web", "success", []byte(`{"old":1}`), 100, 100)
	seedExecution(t, db, strings.Repeat("2", 36), "core.facts", "web", "success", []byte(`{"new":2}`), 200, 200)
	seedExecution(t, db, strings.Repeat("3", 36), "core.facts", "web", "failed", []byte(`{"late":3}`), 300, 300)
	seedExecution(t, db, strings.Repeat("4", 36), "core.facts", "db", "success", []byte(`{"db":4}`), 150, 150)
	seedExecution(t, db, strings.Repeat("5", 36), "docker.list", "web", "success", []byte(`[]`), 250, 250)

	m, err := s.LastResults(ctx, "core.facts")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("got %d hosts, want 2: %v", len(m), m)
	}
	web, ok := m["web"]
	if !ok || string(web.Result) != `{"new":2}` || !web.FinishedAt.Equal(time.Unix(200, 0)) {
		t.Errorf("web: %+v", web)
	}
	dbh, ok := m["db"]
	if !ok || string(dbh.Result) != `{"db":4}` {
		t.Errorf("db: %+v", dbh)
	}
	if _, err := s.LastResults(ctx, "nope"); err != nil {
		t.Fatal(err)
	}
}

func TestLastResultsTieKeepsNewestExecutionID(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	ctx := context.Background()
	// Same finished_at: the higher execution id wins (ORDER BY e.id DESC).
	seedExecution(t, db, strings.Repeat("1", 36), "core.facts", "web", "success", []byte(`{"a":1}`), 100, 100)
	seedExecution(t, db, strings.Repeat("9", 36), "core.facts", "web", "success", []byte(`{"b":2}`), 100, 100)
	m, err := s.LastResults(ctx, "core.facts")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(m["web"].Result); got != `{"b":2}` {
		t.Errorf("tie: got %s, want the newer execution id's result", got)
	}
}

func TestLastSeen(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	ctx := context.Background()
	seedExecution(t, db, strings.Repeat("1", 36), "core.facts", "web", "failed", nil, 100, 100)
	seedExecution(t, db, strings.Repeat("2", 36), "docker.list", "web", "success", nil, 200, 200)
	seedExecution(t, db, strings.Repeat("3", 36), "core.facts", "db", "success", nil, 300, 300)

	all, err := s.LastSeenAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || !all["web"].Equal(time.Unix(200, 0)) || !all["db"].Equal(time.Unix(300, 0)) {
		t.Errorf("all: %v", all)
	}
	at, ok, err := s.LastSeen(ctx, "web")
	if err != nil || !ok || !at.Equal(time.Unix(200, 0)) {
		t.Errorf("web: %v %v %v", at, ok, err)
	}
	if _, ok, err := s.LastSeen(ctx, "new"); err != nil || ok {
		t.Errorf("new: %v %v %v", time.Time{}, ok, err)
	}
}

func TestListHost(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	ctx := context.Background()
	seedExecution(t, db, strings.Repeat("1", 36), "core.facts", "web", "success", nil, 100, 100)
	seedExecution(t, db, strings.Repeat("2", 36), "package.list_updates", "web", "success", nil, 200, 200)
	seedExecution(t, db, strings.Repeat("3", 36), "core.facts", "db", "success", nil, 300, 300)

	list, err := s.ListHost(ctx, "web", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ActionID != "package.list_updates" || list[1].ActionID != "core.facts" {
		t.Fatalf("order/content: %+v", list)
	}
	if list[0].Hosts != 1 || list[0].Failed != 0 || !list[0].FinishedAt.Equal(time.Unix(200, 0)) {
		t.Errorf("summary: %+v", list[0])
	}
	one, err := s.ListHost(ctx, "web", 1)
	if err != nil || len(one) != 1 || one[0].ActionID != "package.list_updates" {
		t.Errorf("limit: %+v %v", one, err)
	}
	if list, err := s.ListHost(ctx, "new", 50); err != nil || len(list) != 0 {
		t.Errorf("unknown host: %+v %v", list, err)
	}
}

func TestListFinishedAt(t *testing.T) {
	s, db := setup(t, &fakeExec{})
	ctx := context.Background()
	seedExecution(t, db, strings.Repeat("1", 36), "core.facts", "web", "success", nil, 100, 100)
	list, err := s.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !list[0].FinishedAt.Equal(time.Unix(100, 0)) {
		t.Errorf("list: %+v", list)
	}
}
