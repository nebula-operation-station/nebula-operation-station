// SPDX-License-Identifier: AGPL-3.0-or-later

package serverdb

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestVulnImageReadOnceMigrationKeepsNewestCopy checks 0054_vuln_image_read_once.sql
// on a server.db that already holds copies of one execution's image read (the
// state 0053 left behind): the upgrade keeps only the newest row of each
// (host_id, execution_id), leaves every other row unchanged, and adds the
// unique key that refuses a new copy.
func TestVulnImageReadOnceMigrationKeepsNewestCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	db, err := OpenAt(path, 53)
	if err != nil {
		t.Fatalf("open at 0053: %v", err)
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	// id, host, execution, read_at. Rows 1-3 are copies of one execution.
	for _, r := range []struct {
		host, exec string
		readAt     int64
	}{
		{"host-1", "exec-a", 100},
		{"host-1", "exec-a", 100},
		{"host-1", "exec-a", 100},
		{"host-1", "exec-b", 200},
		{"host-2", "exec-a", 100},
	} {
		if _, err := db.Exec(`INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id, read_at,
			complete, reason, os_family, os_name, packages, body)
			VALUES ('registry.example/app/web', ?, ?, ?, ?, 1, '', 'debian', '12', 0, x'5b5d')`,
			digest, r.host, r.exec, r.readAt); err != nil {
			t.Fatalf("seed read: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("upgrade from 0053: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ids := readRows(t, db, `SELECT id, host_id, execution_id FROM vuln_image_reads ORDER BY id`)
	want := [][]any{{int64(3), "host-1", "exec-a"}, {int64(4), "host-1", "exec-b"}, {int64(5), "host-2", "exec-a"}}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("reads after upgrade = %v, want %v", ids, want)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'vuln_image_reads_host_execution'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("unique index vuln_image_reads_host_execution missing after upgrade")
	}
	if _, err := db.Exec(`INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id, read_at,
		complete, reason, os_family, os_name, packages, body)
		VALUES ('registry.example/app/web', ?, 'host-1', 'exec-b', 300, 1, '', 'debian', '12', 0, x'5b5d')`, digest); err == nil {
		t.Fatal("a second read of host-1 exec-b was stored")
	}
}

// TestExecutionHostsInspectIndexExists checks that 0054 adds the index the
// docker.inspect lookup of ObserveImage plans with.
func TestExecutionHostsInspectIndexExists(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rows := readRows(t, db, `SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'execution_hosts' AND name = 'execution_hosts_inspect'`)
	if len(rows) != 1 {
		t.Fatalf("execution_hosts_inspect index: %d rows, want 1", len(rows))
	}
}
