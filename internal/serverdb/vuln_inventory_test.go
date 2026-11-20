// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"path/filepath"
	"testing"
)

func TestVulnInventoryTablesExistAfterMigration(t *testing.T) {
	db := openTemp(t)
	for _, name := range []string{"vuln_inventory_reads", "vuln_inventory_snapshots", "vuln_inventory_snapshot_reads"} {
		if !tableExists(t, db, name) {
			t.Errorf("table %s missing", name)
		}
	}
}

func TestVulnInventoryReadRejectsInvalidColumns(t *testing.T) {
	db := openTemp(t)
	const valid = `INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason, dropped,
		ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
		VALUES ('h1', 'e1', 1, ?, '', ?, 'debian:12', '', '', '', '', ?, ?, x'5b5d')`
	cases := []struct {
		name                      string
		complete, dropped, binary any
		sources                   any
		wantErr                   bool
	}{
		{"complete 1 and zero counts", 1, 0, 0, 0, false},
		{"complete 0 with drops", 0, 3, 10, 2, false},
		{"complete 2 rejected", 2, 0, 0, 0, true},
		{"negative dropped rejected", 1, -1, 0, 0, true},
		{"negative binaries rejected", 1, 0, -1, 0, true},
		{"negative sources rejected", 1, 0, 0, -1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := db.Exec(valid, c.complete, c.dropped, c.binary, c.sources)
			if (err != nil) != c.wantErr {
				t.Fatalf("insert err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestVulnInventorySnapshotLinksEnforced(t *testing.T) {
	db := openTemp(t)
	if _, err := db.Exec(`INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason, dropped,
		ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
		VALUES ('h1', 'e1', 1, 1, '', 0, '', '', '', '', '', 0, 0, x'5b5d')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshots (id, generation, taken_at) VALUES ('s1', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshots (id, generation, taken_at) VALUES ('s2', 1, 1)`); err == nil {
		t.Error("duplicate snapshot generation accepted")
	}
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES ('s1', 1)`); err != nil {
		t.Fatalf("link to existing read and snapshot refused: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES ('s1', 1)`); err == nil {
		t.Error("duplicate snapshot link accepted")
	}
	if _, err := db.Exec(`INSERT INTO vuln_inventory_snapshot_reads (snapshot_id, read_id) VALUES ('s1', 99)`); err == nil {
		t.Error("link to missing read accepted")
	}
	if _, err := db.Exec(`DELETE FROM vuln_inventory_reads WHERE id = 1`); err == nil {
		t.Error("read referenced by a snapshot was deleted")
	}
}

// TestVulnInventoryMigrationFromRevision51 applies the migrations up to 0051
// to a database that holds rows, then runs the full migration engine twice.
// The rows must survive, the new tables must exist after the first run, and
// the second run must succeed and change nothing.
func TestVulnInventoryMigrationFromRevision51(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nebula.db")
	db, err := OpenAt(path, 51)
	if err != nil {
		t.Fatalf("open at 0051: %v", err)
	}
	if tableExists(t, db, "vuln_inventory_reads") {
		t.Fatal("vuln_inventory_reads exists before 0052")
	}
	if err := insertVulnRun(db, "r1", 1); err != nil {
		t.Fatal(err)
	}
	before := readRows(t, db, `SELECT id, run_seq, token_id, state FROM vuln_runs ORDER BY id`)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	for pass := 1; pass <= 2; pass++ {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("pass %d: open: %v", pass, err)
		}
		for _, name := range []string{"vuln_inventory_reads", "vuln_inventory_snapshots", "vuln_inventory_snapshot_reads"} {
			if !tableExists(t, db, name) {
				t.Errorf("pass %d: table %s missing", pass, name)
			}
		}
		after := readRows(t, db, `SELECT id, run_seq, token_id, state FROM vuln_runs ORDER BY id`)
		if len(after) != len(before) || len(after) != 1 || after[0][0] != before[0][0] || after[0][1] != before[0][1] {
			t.Errorf("pass %d: vuln_runs changed: before %v after %v", pass, before, after)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
