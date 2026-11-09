// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"database/sql"
	"strings"
	"testing"
)

func TestVulnTablesExistAfterMigration(t *testing.T) {
	db := openTemp(t)
	for _, name := range []string{
		"vuln_store_state", "vuln_runs", "vuln_run_sources", "vuln_source_marks",
		"vuln_run_batches", "vuln_run_subjects", "vuln_run_reported", "vuln_run_rejected",
		"vuln_findings", "vuln_subject_watermarks", "vuln_held_closures",
	} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
	var next int
	if err := db.QueryRow(`SELECT next_run_seq FROM vuln_store_state WHERE id = 1`).Scan(&next); err != nil || next != 1 {
		t.Fatalf("next_run_seq = %d, %v; want 1", next, err)
	}
}

func insertVulnRun(db *sql.DB, id string, seq int) error {
	_, err := db.Exec(`INSERT INTO vuln_runs (id, run_seq, token_id, inventory_generation, matcher_version, state, started_at)
		VALUES (?, ?, 'tok', 1, 'm1', 'running', 1)`, id, seq)
	return err
}

func insertVulnFinding(db *sql.DB, key []byte, state, closedBy string, closedAt any) error {
	_, err := db.Exec(`INSERT INTO vuln_findings (finding_key, subject, subject_kind, record, nos_checked, state,
		closed_by, closed_at, state_run_seq, episode_opened_at, episode_opened_run_seq, episode_peak_tier,
		first_seen_at, last_seen_at, updated_at)
		VALUES (?, 'host/web', 'host', '{}', 1, ?, NULLIF(?, ''), ?, 1, 1, 1, 0, 1, 1, 1)`,
		key, state, closedBy, closedAt)
	return err
}

func TestVulnRunsRejectDuplicateSeqAndUnknownState(t *testing.T) {
	db := openTemp(t)
	if err := insertVulnRun(db, "r1", 1); err != nil {
		t.Fatal(err)
	}
	if err := insertVulnRun(db, "r2", 1); err == nil {
		t.Error("duplicate run_seq accepted")
	}
	if err := insertVulnRun(db, "r3", 0); err == nil {
		t.Error("run_seq 0 accepted")
	}
	if _, err := db.Exec(`UPDATE vuln_runs SET state = 'done', ended_at = 2 WHERE id = 'r1'`); err == nil {
		t.Error("unknown run state accepted")
	}
	if _, err := db.Exec(`UPDATE vuln_runs SET state = 'completed' WHERE id = 'r1'`); err == nil {
		t.Error("completed run without ended_at accepted")
	}
	if _, err := db.Exec(`INSERT INTO vuln_run_sources (run_id, source_id, snapshot_id, integrity, date_kind, status, stale)
		VALUES ('r1', 'kev', 's1', 'signed', 'data', 'trusted', 0)`); err == nil {
		t.Error("unknown source status accepted")
	}
}

func TestVulnFindingsEnforceStateInvariants(t *testing.T) {
	db := openTemp(t)
	key := func(b byte) []byte { return []byte(strings.Repeat(string(rune('a'+b)), 32)) }
	if err := insertVulnFinding(db, key(0), "open", "", nil); err != nil {
		t.Fatalf("open finding refused: %v", err)
	}
	if err := insertVulnFinding(db, key(1), "fixed", "hermes_unconfirmed", 5); err != nil {
		t.Fatalf("fixed finding refused: %v", err)
	}
	cases := map[string]struct {
		key      []byte
		state    string
		closedBy string
		closedAt any
	}{
		"short key":               {[]byte("short"), "open", "", nil},
		"unknown state":           {key(2), "closed", "", nil},
		"fixed without closed_by": {key(3), "fixed", "", 5},
		"open with closed_by":     {key(4), "open", "nos_inventory", 5},
		"unknown closed_by":       {key(5), "fixed", "hermes", 5},
		"accepted without human":  {key(6), "accepted_risk", "", nil},
		"duplicate key":           {key(0), "open", "", nil},
	}
	for name, c := range cases {
		if err := insertVulnFinding(db, c.key, c.state, c.closedBy, c.closedAt); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := db.Exec(`UPDATE vuln_findings SET assessment = ? WHERE finding_key = ?`, strings.Repeat("x", 4097), key(0)); err == nil {
		t.Error("assessment over 4 KiB accepted")
	}
	if _, err := db.Exec(`UPDATE vuln_findings SET state = 'false_positive', human_by = 'admin', human_category = 'guess'
		WHERE finding_key = ?`, key(0)); err == nil {
		t.Error("unknown false_positive category accepted")
	}
}

func TestVulnHeldClosuresNeedRunAndFinding(t *testing.T) {
	db := openTemp(t)
	k := []byte(strings.Repeat("k", 32))
	if _, err := db.Exec(`INSERT INTO vuln_held_closures (run_id, finding_key, run_seq, subject, reason, finding_rev, created_at)
		VALUES ('nope', ?, 1, 'host/web', 'contradicted', 1, 1)`, k); err == nil {
		t.Fatal("hold without run and finding accepted")
	}
	if err := insertVulnRun(db, "r1", 1); err != nil {
		t.Fatal(err)
	}
	if err := insertVulnFinding(db, k, "open", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_held_closures (run_id, finding_key, run_seq, subject, reason, finding_rev, created_at)
		VALUES ('r1', ?, 1, 'host/web', 'contradicted', 1, 1)`, k); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM vuln_runs WHERE id = 'r1'`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_held_closures`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("holds after run delete = %d, %v; want cascade to 0", n, err)
	}
}
