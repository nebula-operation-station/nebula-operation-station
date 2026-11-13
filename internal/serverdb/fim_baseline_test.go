// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"bytes"
	"database/sql"
	"testing"
)

// fimHost inserts a host and returns its ID.
func fimHost(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO hosts(name, created_at, updated_at) VALUES (?, '2026-11-13T00:00:00Z', '2026-11-13T00:00:00Z')`, name)
	if err != nil {
		t.Fatalf("insert host %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func fimDigest(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// insertFimBaseline inserts an approved baseline row for host.
func insertFimBaseline(db *sql.DB, host int64, version int, digest []byte, entries int) error {
	_, err := db.Exec(`INSERT INTO fim_baselines (host_id, version, digest, profile_id, entry_count, approved_at)
		VALUES (?, ?, ?, 'fim-v1', ?, 1)`, host, version, digest, entries)
	return err
}

// insertFimProposal inserts a proposal row for host; base 0 means none.
func insertFimProposal(db *sql.DB, host int64, baseVersion int, baseDigest any, digest []byte, entries int) error {
	_, err := db.Exec(`INSERT INTO fim_baseline_proposals (host_id, base_version, base_digest, digest, profile_id, entry_count, proposed_at)
		VALUES (?, ?, ?, ?, 'fim-v1', ?, 1)`, host, baseVersion, baseDigest, digest, entries)
	return err
}

// insertFimEntry inserts one entry into the given table (approved or proposal).
func insertFimEntry(db *sql.DB, table string, host int64, path []byte, typ int, link, sum any, kind int) error {
	_, err := db.Exec(`INSERT INTO `+table+` (host_id, path, type, size, mode, uid, gid, inode, mtime, ctime,
		hash_kind, hash_secret, hash_sum, link)
		VALUES (?, ?, ?, 0, 420, 0, 0, 1, 1, 1, ?, 0, ?, ?)`, host, path, typ, kind, sum, link)
	return err
}

func TestFimBaselineTablesExistAfterMigration(t *testing.T) {
	db := openTemp(t)
	for _, name := range []string{"fim_store_state", "fim_baselines", "fim_baseline_entries",
		"fim_baseline_proposals", "fim_baseline_proposal_entries"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
}

func TestFimBaselineRefusesUnknownHostAndBadDigest(t *testing.T) {
	db := openTemp(t)
	if err := insertFimBaseline(db, 999, 1, fimDigest(1), 0); err == nil {
		t.Error("baseline for unknown host accepted")
	}
	host := fimHost(t, db, "web-1")
	if err := insertFimBaseline(db, host, 1, fimDigest(1)[:31], 0); err == nil {
		t.Error("31-byte digest accepted")
	}
	if err := insertFimBaseline(db, host, 0, fimDigest(1), 0); err == nil {
		t.Error("version 0 approved baseline accepted")
	}
	if err := insertFimBaseline(db, host, 1, fimDigest(1), 300001); err == nil {
		t.Error("entry count above 300,000 accepted")
	}
	if err := insertFimBaseline(db, host, 1, fimDigest(1), 300000); err != nil {
		t.Errorf("entry count at the limit refused: %v", err)
	}
}

func TestFimBaselineAllowsOneRowPerHost(t *testing.T) {
	db := openTemp(t)
	host := fimHost(t, db, "web-1")
	if err := insertFimBaseline(db, host, 1, fimDigest(1), 0); err != nil {
		t.Fatal(err)
	}
	if err := insertFimBaseline(db, host, 2, fimDigest(2), 0); err == nil {
		t.Error("second approved baseline for one host accepted")
	}
}

func TestFimProposalAtMostOnePerHost(t *testing.T) {
	db := openTemp(t)
	host := fimHost(t, db, "web-1")
	other := fimHost(t, db, "web-2")
	if err := insertFimProposal(db, host, 0, nil, fimDigest(1), 0); err != nil {
		t.Fatalf("first proposal refused: %v", err)
	}
	if err := insertFimProposal(db, host, 0, nil, fimDigest(2), 0); err == nil {
		t.Error("second open proposal for one host accepted")
	}
	if err := insertFimProposal(db, other, 0, nil, fimDigest(2), 0); err != nil {
		t.Errorf("proposal for a second host refused: %v", err)
	}
}

func TestFimProposalBaseMustMatchVersion(t *testing.T) {
	db := openTemp(t)
	host := fimHost(t, db, "web-1")
	// Trust on first scan: no approved baseline, so no base digest.
	if err := insertFimProposal(db, host, 0, fimDigest(9), fimDigest(1), 0); err == nil {
		t.Error("proposal with base digest but no base version accepted")
	}
	if err := insertFimProposal(db, host, 1, nil, fimDigest(1), 0); err == nil {
		t.Error("proposal on an approved baseline without its digest accepted")
	}
	if err := insertFimProposal(db, host, 1, fimDigest(9), fimDigest(1), 0); err != nil {
		t.Errorf("valid proposal on an approved baseline refused: %v", err)
	}
}

func TestFimEntriesEnforceShapeAndRawPaths(t *testing.T) {
	db := openTemp(t)
	host := fimHost(t, db, "web-1")
	if err := insertFimBaseline(db, host, 1, fimDigest(1), 0); err != nil {
		t.Fatal(err)
	}
	raw := []byte{'/', 'e', 't', 'c', '/', 0xff, 0xfe}
	if err := insertFimEntry(db, "fim_baseline_entries", host, raw, 1, nil, fimDigest(3), 1); err != nil {
		t.Fatalf("file entry refused: %v", err)
	}
	var got []byte
	if err := db.QueryRow(`SELECT path FROM fim_baseline_entries WHERE host_id = ?`, host).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("raw path changed: %x, want %x", got, raw)
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, raw, 1, nil, fimDigest(3), 1); err == nil {
		t.Error("duplicate path for one host accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, nil, 1, nil, fimDigest(3), 1); err == nil {
		t.Error("empty raw path accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, []byte(string(make([]byte, 4097))), 1, nil, fimDigest(3), 1); err == nil {
		t.Error("path over 4096 bytes accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, []byte("/etc/a"), 1, nil, nil, 1); err == nil {
		t.Error("hashed file without hash sum accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, []byte("/etc/b"), 1, nil, fimDigest(3), 0); err == nil {
		t.Error("hash sum on an unhashed entry accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, []byte("/etc/c"), 3, nil, nil, 0); err == nil {
		t.Error("symlink without target accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, []byte("/etc/d"), 1, []byte("x"), nil, 0); err == nil {
		t.Error("target on a regular file accepted")
	}
	if err := insertFimEntry(db, "fim_baseline_entries", host, []byte("/etc/e"), 3, []byte("/x"), nil, 0); err != nil {
		t.Errorf("valid symlink refused: %v", err)
	}
}

func TestFimProposalEntriesAreRemovedWithTheProposal(t *testing.T) {
	db := openTemp(t)
	host := fimHost(t, db, "web-1")
	if err := insertFimProposal(db, host, 0, nil, fimDigest(1), 1); err != nil {
		t.Fatal(err)
	}
	if err := insertFimEntry(db, "fim_baseline_proposal_entries", host, []byte("/etc/a"), 1, nil, fimDigest(3), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM fim_baseline_proposals WHERE host_id = ?`, host); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fim_baseline_proposal_entries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d proposal entries survived their proposal", n)
	}
}

func TestFimHostDeletionRemovesBaselineAndProposal(t *testing.T) {
	db := openTemp(t)
	host := fimHost(t, db, "web-1")
	if err := insertFimBaseline(db, host, 1, fimDigest(1), 0); err != nil {
		t.Fatal(err)
	}
	if err := insertFimProposal(db, host, 1, fimDigest(1), fimDigest(2), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM hosts WHERE id = ?`, host); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"fim_baselines", "fim_baseline_proposals"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s kept %d rows after host deletion", table, n)
		}
	}
}
