// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// execColumns are every executions column that exists before
// 0050_execution_rejected.sql, in a fixed order.
const execColumns = `id, digest, action_id, module_version, artifact_sha256, risk, requirement, state, detail, durable,
	timeout_s, options, approval_expiry, created_by, created_at, finished_at, params, stage_plan, waiting, schedule_id, origin`

// hostColumns are every execution_hosts column before 0050.
const hostColumns = `execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, detail, exit_code,
	result, log, log_truncated, started_at, finished_at, stage`

// readRows returns every row of query as a slice of column values, so rows
// read before and after a migration compare with reflect.DeepEqual.
func readRows(t *testing.T, db *sql.DB, query string) [][]any {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, vals)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestExecutionRejectedMigrationKeepsRowsAndIndexes is the check asked for in
// the review of PR #687: the table rebuild of 0050_execution_rejected.sql
// (written as 0048 at the time) keeps every executions and execution_hosts
// row unchanged, including origin, schedule, stage plan and the host results
// (exit code, result, log), and keeps the three executions indexes and every
// other index of both tables with their definitions. The foreign key of
// execution_hosts still points at executions and holds for every row.
func TestExecutionRejectedMigrationKeepsRowsAndIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := OpenAt(path, 49)
	if err != nil {
		t.Fatalf("open at 0049: %v", err)
	}
	art := strings.Repeat("a", 64)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO executions (` + execColumns + `) VALUES
			('00000000-0000-4000-8000-000000000001', 'd1', 'package.upgrade', '1.2.3', ?, 'high', 'webauthn', 'finished', 'done', 1,
			 600, x'0102ff', 1700000100, 'axel', 1700000000, 1700000200, '{"package":"nginx"}', '{"stages":[1]}', '', 'sched-1', 'ops-agent:finding-7'),
			('00000000-0000-4000-8000-000000000002', 'd2', 'core.facts', '1.0.0', ?, 'low', '', 'pending', '', 0,
			 60, NULL, 1700000500, 'bea', 1700000400, NULL, '{}', '', 'approval', '', ''),
			('00000000-0000-4000-8000-000000000003', 'd3', 'core.facts', '1.0.0', ?, 'low', '', 'expired', 'expired; nothing was run', 0,
			 60, NULL, 1700000600, 'bea', 1700000550, 1700000700, '{}', '', '', '', 'vuln-agent')`,
			[]any{art, art, art}},
		{`INSERT INTO execution_hosts (` + hostColumns + `) VALUES
			('00000000-0000-4000-8000-000000000001', 'web-01', 'SHA256:AAAA', 'admin-key', '["10.0.0.1:22"]', 'finished', 'ok', 'exit 0', 0,
			 x'7b226f6b223a747275657d', x'6c6f67206c696e650a', 0, 1700000110, 1700000150, 1),
			('00000000-0000-4000-8000-000000000001', 'web-02', 'SHA256:BBBB', 'admin-key', '["10.0.0.2:22"]', 'finished', 'failed', 'exit 3', 3,
			 NULL, x'6572726f720a', 1, 1700000120, 1700000190, 2),
			('00000000-0000-4000-8000-000000000002', 'db-01', 'SHA256:CCCC', 'admin-key', '["10.0.0.3:22"]', 'waiting', '', '', -1,
			 NULL, NULL, 0, NULL, NULL, 1),
			('00000000-0000-4000-8000-000000000003', 'db-02', 'SHA256:DDDD', 'admin-key', '["10.0.0.4:22"]', 'finished', 'not_executed', 'expired; nothing was run', -1,
			 NULL, NULL, 0, NULL, 1700000700, 1)`, nil},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("seed at 0049: %v", err)
		}
	}
	execQuery := `SELECT ` + execColumns + ` FROM executions ORDER BY id`
	hostQuery := `SELECT ` + hostColumns + ` FROM execution_hosts ORDER BY execution_id, host_id`
	indexQuery := `SELECT tbl_name, name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name IN ('executions', 'execution_hosts') ORDER BY name`
	beforeExec := readRows(t, db, execQuery)
	beforeHosts := readRows(t, db, hostQuery)
	beforeIndexes := readRows(t, db, indexQuery)
	if len(beforeExec) != 3 || len(beforeHosts) != 4 {
		t.Fatalf("seeded %d executions and %d host rows, want 3 and 4", len(beforeExec), len(beforeHosts))
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("upgrade from 0049: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if got := readRows(t, db, execQuery); !reflect.DeepEqual(got, beforeExec) {
		t.Errorf("executions rows changed by the upgrade:\nbefore %v\nafter  %v", beforeExec, got)
	}
	if got := readRows(t, db, hostQuery); !reflect.DeepEqual(got, beforeHosts) {
		t.Errorf("execution_hosts rows changed by the upgrade:\nbefore %v\nafter  %v", beforeHosts, got)
	}
	afterIndexes := readRows(t, db, indexQuery)
	if !reflect.DeepEqual(afterIndexes, beforeIndexes) {
		t.Errorf("indexes changed by the upgrade:\nbefore %v\nafter  %v", beforeIndexes, afterIndexes)
	}
	names := map[string]bool{}
	for _, r := range afterIndexes {
		names[r[1].(string)] = true
	}
	for _, want := range []string{"executions_created", "executions_schedule", "idx_executions_action_id"} {
		if !names[want] {
			t.Errorf("index %s missing after the upgrade (have %v)", want, names)
		}
	}

	// The child table's foreign key points at the renamed executions table
	// and holds for every row.
	fks := readRows(t, db, `SELECT "table", "from", "to" FROM pragma_foreign_key_list('execution_hosts')`)
	if len(fks) != 1 || fks[0][0] != "executions" || fks[0][1] != "execution_id" || fks[0][2] != "id" {
		t.Errorf("execution_hosts foreign keys = %v, want execution_id -> executions(id)", fks)
	}
	if bad := readRows(t, db, `SELECT * FROM pragma_foreign_key_check`); len(bad) != 0 {
		t.Errorf("foreign key violations after the upgrade: %v", bad)
	}
	// No temporary table of the rebuild is left behind.
	if left := readRows(t, db, `SELECT name FROM sqlite_master WHERE name LIKE '%\_new' ESCAPE '\'`); len(left) != 0 {
		t.Errorf("rebuild tables left behind: %v", left)
	}
	// The CHECK takes the new state.
	if _, err := db.Exec(`UPDATE executions SET state = 'rejected' WHERE id = '00000000-0000-4000-8000-000000000002'`); err != nil {
		t.Errorf("state rejected refused after the upgrade: %v", err)
	}
}
