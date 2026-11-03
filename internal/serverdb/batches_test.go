// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"database/sql"
	"strings"
	"testing"
)

func insertBatch(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO batches (id, digest, state, risk, member_count, stage_count, canonical, expiry, created_by, created_at)
		VALUES (?, ?, 'pending', 'MEDIUM', 2, 1, x'7b7d', 100, 'axel', 1)`, id, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
}

func insertBatchMember(db *sql.DB, batch string, idx int, member, exec, outcome string) error {
	_, err := db.Exec(`INSERT INTO batch_members (batch_id, idx, member_id, execution_id, stage, action_id, module_version, artifact_sha256,
		parameters_hash, risk, host_id, fingerprint, credential_ref, outcome, updated_at)
		VALUES (?, ?, ?, ?, 1, 'package.install_all', '1.0.0', ?, ?, 'MEDIUM', 'web', 'SHA256:x', 'nebula-default', ?, 1)`,
		batch, idx, member, exec, strings.Repeat("a", 64), strings.Repeat("b", 64), outcome)
	return err
}

func TestBatchTablesExistAfterMigration(t *testing.T) {
	db := openTemp(t)
	for _, name := range []string{"batches", "batch_stages", "batch_members"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
}

func TestBatchMembersRejectUnknownOutcomeAndDuplicates(t *testing.T) {
	db := openTemp(t)
	batch := strings.Repeat("1", 36)
	insertBatch(t, db, batch)
	if err := insertBatchMember(db, batch, 0, "m-001", strings.Repeat("2", 36), "planned"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		idx             int
		member, exec, o string
	}{
		"retrying outcome":    {1, "m-002", strings.Repeat("3", 36), "retrying"},
		"rolled back outcome": {1, "m-002", strings.Repeat("3", 36), "rolled_back"},
		"duplicate member":    {1, "m-001", strings.Repeat("3", 36), "planned"},
		"duplicate execution": {1, "m-002", strings.Repeat("2", 36), "planned"},
		"index beyond 100":    {100, "m-101", strings.Repeat("3", 36), "planned"},
	}
	for name, c := range cases {
		if err := insertBatchMember(db, batch, c.idx, c.member, c.exec, c.o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, o := range []string{"dispatched", "success", "failed", "skipped", "not_executed", "unknown"} {
		if _, err := db.Exec(`UPDATE batch_members SET outcome = ? WHERE batch_id = ? AND idx = 0`, o, batch); err != nil {
			t.Errorf("outcome %s refused: %v", o, err)
		}
	}
}

func TestBatchMembersNeedTheirBatch(t *testing.T) {
	db := openTemp(t)
	if err := insertBatchMember(db, strings.Repeat("9", 36), 0, "m-001", strings.Repeat("2", 36), "planned"); err == nil {
		t.Fatal("member without a batch accepted")
	}
}

func TestBatchRejectsCriticalRiskAndOversizeCounts(t *testing.T) {
	db := openTemp(t)
	for name, q := range map[string]string{
		"critical":    `INSERT INTO batches (id, digest, state, risk, member_count, stage_count, canonical, expiry, created_by, created_at) VALUES (?, ?, 'pending', 'CRITICAL', 1, 1, x'7b7d', 1, 'a', 1)`,
		"101 members": `INSERT INTO batches (id, digest, state, risk, member_count, stage_count, canonical, expiry, created_by, created_at) VALUES (?, ?, 'pending', 'LOW', 101, 1, x'7b7d', 1, 'a', 1)`,
		"21 stages":   `INSERT INTO batches (id, digest, state, risk, member_count, stage_count, canonical, expiry, created_by, created_at) VALUES (?, ?, 'pending', 'LOW', 1, 21, x'7b7d', 1, 'a', 1)`,
	} {
		if _, err := db.Exec(q, strings.Repeat("1", 36), strings.Repeat("d", 64)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
