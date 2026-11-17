// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"database/sql"
	"strings"
	"testing"
)

func TestIntegrityTablesExistAfterMigration(t *testing.T) {
	db := openTemp(t)
	for _, name := range []string{"integrity_store_state", "integrity_runs", "integrity_findings"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
}

// runID is a 32-character run ID as the store writes them.
const runID = "0123456789abcdef0123456789abcdef"

func insertIntegrityFinding(db *sql.DB, subject, state string, path []byte, closedRun any) error {
	_, err := db.Exec(`INSERT INTO integrity_findings (subject, class, severity, path, path_display, state,
		first_seen_at, last_seen_at, opened_run_id, last_run_id, closed_run_id, closed_at, state_at)
		VALUES (?, 'etc-changed', 'high', ?, 'p', ?, 1, 1, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE 2 END, 1)`,
		subject, path, state, runID, runID, closedRun, closedRun)
	return err
}

func TestIntegrityFindingsEnforceStateAndSubjectInvariants(t *testing.T) {
	db := openTemp(t)
	if err := insertIntegrityFinding(db, "nos", "open", []byte("/etc/x"), nil); err != nil {
		t.Fatalf("open finding refused: %v", err)
	}
	if err := insertIntegrityFinding(db, "host/web-1", "resolved", []byte("/etc/y"), runID); err != nil {
		t.Fatalf("resolved finding refused: %v", err)
	}
	if err := insertIntegrityFinding(db, "host/web-1", "open", []byte("/etc/z"), runID); err == nil {
		t.Error("open finding with closed_run_id accepted")
	}
	if err := insertIntegrityFinding(db, "web-1", "open", []byte("/etc/z"), nil); err == nil {
		t.Error("subject without host/ or nos prefix accepted")
	}
	if err := insertIntegrityFinding(db, "nos", "fixed", []byte("/etc/z"), nil); err == nil {
		t.Error("unknown state accepted")
	}
	if err := insertIntegrityFinding(db, "nos", "open", nil, nil); err == nil {
		t.Error("empty raw path accepted")
	}
	if err := insertIntegrityFinding(db, "nos", "open", []byte(strings.Repeat("a", 4097)), nil); err == nil {
		t.Error("path over 4096 bytes accepted")
	}
	// Same key twice is one finding (subject, class, path is the key).
	if err := insertIntegrityFinding(db, "nos", "open", []byte("/etc/x"), nil); err == nil {
		t.Error("duplicate (subject, class, path) accepted")
	}
}

func TestIntegrityFindingsKeepRawPathBytes(t *testing.T) {
	db := openTemp(t)
	raw := []byte{'/', 'e', 't', 'c', '/', 0xff, 0xfe}
	if err := insertIntegrityFinding(db, "nos", "open", raw, nil); err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err := db.QueryRow(`SELECT path FROM integrity_findings WHERE subject = 'nos'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("raw path changed: %x, want %x", got, raw)
	}
}
