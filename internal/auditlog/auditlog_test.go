// SPDX-License-Identifier: AGPL-3.0-or-later

package auditlog

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func TestAuditLog(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	plain := New(db, false)
	var out bytes.Buffer
	log := slog.New(NewHandler(slog.NewJSONHandler(&out, nil), plain))
	log.Info("started")
	log.Info("audit", "kind", "host_created", "host", "web", "user", "axel")
	chained := New(db, true)
	clog := slog.New(NewHandler(slog.NewJSONHandler(&out, nil), chained)).With("component", "ui")
	for i := 0; i < 3; i++ {
		clog.Info("audit", "kind", "asset_saved", "asset", "nas", "user", "axel", "at", time.Unix(0, 0))
	}
	log.Info("audit", "kind", "network_saved", "user", "bob")
	clog.Info("audit", "kind", "asset_deleted", "user", strings.Repeat("u", 100))
	list, err := plain.List(ctx, 0, 10, "")
	if err != nil || len(list) != 6 || list[0].Kind != "asset_deleted" || len(list[0].User) != 64 || list[5].Attrs["host"] != "web" {
		t.Fatalf("%+v %v", list, err)
	}
	if only, _ := plain.List(ctx, 0, 10, "asset_saved"); len(only) != 3 || !only[0].Chained || only[0].Attrs["component"] != "ui" || only[0].Attrs["at"] != "1970-01-01T00:00:00Z" {
		t.Fatalf("%+v", only)
	}
	if page, _ := plain.List(ctx, list[2].Seq, 10, ""); len(page) != 3 {
		t.Fatalf("%d", len(page))
	}
	n, err := chained.Verify(ctx)
	if err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if _, err := db.Exec(`UPDATE audit_log SET body = '{}' WHERE seq = 3`); err == nil {
		t.Fatal("audit line updated")
	}
	if _, err := db.Exec(`DELETE FROM audit_log WHERE seq = 1`); err == nil {
		t.Fatal("audit line deleted")
	}
	// Deleting the first chained lines offline (trigger dropped) breaks
	// the chain too: the new first line does not start from zeros.
	if _, err := db.Exec(`DROP TRIGGER audit_log_no_delete`); err != nil {
		t.Fatal(err)
	}
	first, _, _ := chained.VerifyHead(ctx)
	if _, err := db.Exec(`DELETE FROM audit_log WHERE seq = (SELECT min(seq) FROM audit_log WHERE hash IS NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if n, _, err := chained.VerifyHead(ctx); !errors.Is(err, ErrChainBroken) {
		t.Fatal("prefix deletion not detected", first, n, err)
	}
	// An offline edit (trigger dropped) breaks the chain.
	if _, err := db.Exec(`DROP TRIGGER audit_log_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE audit_log SET user_name = 'mallory' WHERE seq = 4`); err != nil {
		t.Fatal(err)
	}
	if _, err := chained.Verify(ctx); !errors.Is(err, ErrChainBroken) {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 7 {
		t.Fatal(out.String())
	}
}

// The server audit log's copy of attrKey keeps crafted keys distinct like
// the events copy (review fx3, note 2).
func TestAttrKeySuffixCollision(t *testing.T) {
	long := strings.Repeat("k", MaxKind)
	first := attrKey(long+"a", map[string]string{clip(long+"a", MaxKind): "x"})
	taken := map[string]string{clip(long+"a", MaxKind): "1", first: "2"}
	if got := attrKey(long+"a", taken); got == first || len(got) > MaxKind {
		t.Fatalf("%q reused or too long", got)
	}
	if got := attrKey("_truncated", map[string]string{}); got == "_truncated" {
		t.Fatal("the reserved key was handed out")
	}
}
