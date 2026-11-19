// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// TestRejectIntentMigrationUpFromMain0049 checks the migrations that follow
// main's 0049: an installation at 0049 gets the rejected state (0050) and the
// rejection intent columns (0051) without losing its rows, and the
// intent reason is limited to 200 characters.
func TestRejectIntentMigrationUpFromMain0049(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	db, err := serverdb.OpenAt(path, 49)
	if err != nil {
		t.Fatalf("open at 0049: %v", err)
	}
	var v int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil || v != 49 {
		t.Fatalf("version before the upgrade = %d (%v), want 49", v, err)
	}
	if _, err := db.Exec(`INSERT INTO executions (id, action_id, module_version, artifact_sha256, risk, state, durable, timeout_s, created_by, created_at)
		VALUES ('00000000-0000-0000-0000-000000000001', 'core.facts', '1.0.0', ?, 'low', 'pending', 0, 60, 'axel', 1)`,
		strings.Repeat("a", 64)); err != nil {
		t.Fatalf("insert pending row at 0049: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = serverdb.Open(path)
	if err != nil {
		t.Fatalf("upgrade from 0049: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// The migrations are recorded in order, with no 0048 (its number is
	// taken by the rebased 0050).
	for _, want := range []int{50, 51} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, want).Scan(&n); err != nil || n != 1 {
			t.Fatalf("migration %d recorded %d times (%v), want once", want, n, err)
		}
	}
	var n48 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 48`).Scan(&n48); err != nil || n48 != 0 {
		t.Fatalf("migration 48 recorded %d times (%v), want none", n48, err)
	}

	// The pending row survived, with no rejection intent.
	var state string
	var user, reason *string
	if err := db.QueryRow(`SELECT state, reject_user, reject_reason FROM executions WHERE id = '00000000-0000-0000-0000-000000000001'`).Scan(&state, &user, &reason); err != nil {
		t.Fatalf("read row after upgrade: %v", err)
	}
	if state != "pending" || user != nil || reason != nil {
		t.Fatalf("row = state %q user %v reason %v, want pending with no intent", state, user, reason)
	}

	// The rejected state is accepted by the CHECK (0050).
	if _, err := db.Exec(`UPDATE executions SET state = 'rejected' WHERE id = '00000000-0000-0000-0000-000000000001'`); err != nil {
		t.Fatalf("set rejected: %v", err)
	}

	// The intent reason takes up to 200 characters and no more (0051).
	id := `'00000000-0000-0000-0000-000000000001'`
	if _, err := db.Exec(`UPDATE executions SET reject_reason = ? WHERE id = ` + id, strings.Repeat("ä", 200)); err != nil {
		t.Fatalf("200-character reason refused: %v", err)
	}
	if _, err := db.Exec(`UPDATE executions SET reject_reason = ? WHERE id = `+id, strings.Repeat("a", 201)); err == nil {
		t.Fatal("201-character reason accepted, want the CHECK to refuse it")
	}
	if _, err := db.Exec(`UPDATE executions SET reject_user = ?, reject_at = 5 WHERE id = `+id, "axel"); err != nil {
		t.Fatalf("set intent user and time: %v", err)
	}
}
