// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

const injectedFailure = "injected-store-failure"

// newRetryImporter is newTestImporter with access to the database and the
// log, so a test can make the store fail and read what was logged.
func newRetryImporter(t *testing.T) (*Importer, *Spool, *pveinventory.Store, *sql.DB, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	expectTempDirOwnership(t, root)
	spool, err := NewSpool(root)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	t.Cleanup(func() { spool.Close() })
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "inv.db"))
	if err != nil {
		t.Fatalf("serverdb.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := pveinventory.New(db)
	logs := &bytes.Buffer{}
	im, err := NewImporter(spool, store, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatalf("NewImporter: %v", err)
	}
	return im, spool, store, db, logs
}

// failStore makes every insert into table fail for rows matching when, until
// the returned function restores the store.
func failStore(t *testing.T, db *sql.DB, table, when string) (restore func()) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER fail_store BEFORE INSERT ON `+table+
		` WHEN `+when+` BEGIN SELECT RAISE(ABORT, '`+injectedFailure+`'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	return func() {
		t.Helper()
		if _, err := db.ExecContext(ctx, `DROP TRIGGER fail_store`); err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
	}
}

// A store failure says nothing about the observation: the file must survive
// it and apply completely once the store works again, whether one dataset or
// the whole ingest failed.
func TestImporterKeepsObservationTheStoreFailed(t *testing.T) {
	cases := []struct {
		name, table, when string
	}{
		{"one dataset", "pve_dataset_status", "NEW.dataset = 'tasks'"},
		{"remote row", "pve_remotes", "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			im, spool, store, db, logs := newRetryImporter(t)
			ctx := context.Background()
			collectInto(t, spool, &fakeReader{
				remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
				readFn:  defaultReadFn,
			})
			restore := failStore(t, db, tc.table, tc.when)

			rep, err := im.ImportOnce(ctx)
			if err != nil {
				t.Fatalf("ImportOnce: %v", err)
			}
			if rep.Partial != 1 || rep.Imported != 0 || rep.Rejected != 0 || len(rep.Errors) != 1 {
				t.Fatalf("report = %+v, want 1 partial", rep)
			}
			if names, _ := spool.List(ctx); len(names) != 1 {
				t.Fatalf("spool = %v, want the observation kept", names)
			}
			if got := logs.String(); !strings.Contains(got, `"reason":"store_failed"`) ||
				strings.Contains(got, injectedFailure) {
				t.Fatalf("log must carry the fixed code only:\n%s", got)
			}

			restore()
			rep, err = im.ImportOnce(ctx)
			if err != nil {
				t.Fatalf("ImportOnce: %v", err)
			}
			if rep.Imported != 1 || rep.Partial != 0 {
				t.Fatalf("retry report = %+v, want 1 imported", rep)
			}
			if names, _ := spool.List(ctx); len(names) != 0 {
				t.Fatalf("spool = %v, want empty after the retry", names)
			}
			if _, err := store.GetRemote(ctx, "remote-a"); err != nil {
				t.Fatalf("GetRemote: %v", err)
			}
			statuses, err := store.ListDatasetStatus(ctx, "remote-a")
			if err != nil {
				t.Fatalf("ListDatasetStatus: %v", err)
			}
			if len(statuses) != 5 {
				t.Fatalf("dataset statuses = %+v, want all 5", statuses)
			}
		})
	}
}

// A kept file must not outlive a newer collection of its remote: the next
// generation supersedes it, so a dataset that keeps failing holds back at
// most the newest file.
func TestImporterDropsKeptObservationOnceSuperseded(t *testing.T) {
	im, spool, store, db, _ := newRetryImporter(t)
	ctx := context.Background()
	collectInto(t, spool, &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  defaultReadFn,
	})
	names, err := spool.List(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("List = %v, %v", names, err)
	}
	obs, err := spool.ReadFile(ctx, names[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	restore := failStore(t, db, "pve_dataset_status", "NEW.dataset = 'tasks'")
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Partial != 1 {
		t.Fatalf("ImportOnce = %+v, %v", rep, err)
	}
	restore()

	obs.CollectionGeneration++
	if _, err := store.IngestObservation(ctx, obs); err != nil {
		t.Fatalf("IngestObservation: %v", err)
	}
	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Replayed != 1 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want 1 replayed", rep)
	}
	if names, _ := spool.List(ctx); len(names) != 0 {
		t.Fatalf("spool = %v, want empty", names)
	}
}
