// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func TestDriftAcceptPreservesConcurrentHostEdits(t *testing.T) {
	ctx := context.Background()
	host := mkManagedHost("web1", "10.77.10.101")
	host.CredentialRef = "lab-key"
	host.Criticality = inventory.CriticalityHigh
	host.Tags = map[string]string{TagPVERAM: "8 GiB", "role": "web"}
	s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil || len(hints) != 1 {
		t.Fatalf("sweep = %+v, %v", hints, err)
	}
	// Inject an edit at the timestamp boundary, between reading a hint and
	// writing its acceptance. Rewriting a previously loaded host loses it.
	edited := host
	edited.Groups = []string{}
	edited.CredentialRef = "replacement-key"
	edited.Criticality = inventory.CriticalityCritical
	edited.Endpoints = []inventory.Endpoint{{Address: "10.77.10.102", Port: 2222}}
	edited.DisplayName = "edited web host"
	edited.Tags = map[string]string{TagPVERAM: "8 GiB", "role": "database"}
	editedOnce := false
	s.now = func() time.Time {
		if editedOnce {
			return testBase
		}
		editedOnce = true
		if _, err := inventory.NewWithNow(s.db, func() time.Time { return testBase }).Update(ctx, edited); err != nil {
			t.Fatalf("concurrent edit: %v", err)
		}
		return testBase
	}
	if _, err := s.ResolveDriftHint(ctx, hints[0].ID, DriftAccepted, "alice"); err != nil {
		t.Fatal(err)
	}
	got, err := s.hostStore().Get(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	edited.Tags[TagPVERAM] = "4 GiB"
	if !reflect.DeepEqual(got, edited) {
		t.Fatalf("accept lost host edits: got %+v, want %+v", got, edited)
	}
}

func TestStagingClonedMACsWithoutAssets(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatal(err)
	}
	var guests []pvecontract.GuestObservation
	for _, id := range []uint64{100, 200} {
		guests = append(guests, mkGuestWithIfaces(id, 1, fmt.Sprintf("vm%d", id), []pvecontract.GuestInterface{
			{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", IPs: []string{fmt.Sprintf("10.77.10.%d/24", id)}, Source: pvecontract.SourceQEMUAgent},
		}))
	}
	mustIngestGuest(t, s, newObsA().guests(guests...).build())
	rows, err := s.SweepStaging(ctx, "remote-a")
	if err != nil || len(rows) != 2 {
		t.Fatalf("sweep = %+v, %v", rows, err)
	}
	for _, row := range rows {
		if row.Status != StagingConflict || len(row.Candidates) != 0 {
			t.Fatalf("clone = %+v", row)
		}
		if _, err := s.ImportStaged(ctx, row.RemoteID, row.VMID, row.Generation, "", "alice"); !errors.Is(err, ErrStagingConflict) {
			t.Fatalf("clone import = %v", err)
		}
	}
}

func TestStagingIPOnlyCandidateIsPossibleMatch(t *testing.T) {
	for _, source := range []string{pvecontract.SourceQEMUAgent, pvecontract.SourceLXCAPI} {
		t.Run(source, func(t *testing.T) {
			s, _, _ := newTestStore(t)
			ctx := context.Background()
			if err := s.UpsertRemote(ctx, remoteA()); err != nil {
				t.Fatal(err)
			}
			host := mkManagedHost("web1", "10.77.10.101")
			host.Endpoints = append(host.Endpoints, inventory.Endpoint{Address: "10.77.10.101", Port: 2222})
			mustCreateHost(t, s.db, host)
			mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "vm1", []pvecontract.GuestInterface{
				{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", IPs: []string{"10.77.10.101/24"}, Source: source},
			})).build())
			rows, err := s.SweepStaging(ctx, "remote-a")
			if err != nil || len(rows) != 1 {
				t.Fatalf("sweep = %+v, %v", rows, err)
			}
			if rows[0].Status != StagingPossible || len(rows[0].Candidates) != 1 {
				t.Fatalf("IP-only match = %+v", rows[0])
			}
		})
	}
}

func stagedImportStore(t *testing.T) *Store {
	t.Helper()
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatal(err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithIfaces(100, 1, "vm1", []pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:01", IPs: []string{"10.77.10.101/24"}, Source: pvecontract.SourceQEMUAgent},
	})).build())
	if _, err := s.SweepStaging(ctx, "remote-a"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestImportStaleIncarnationCreatesNoHost(t *testing.T) {
	s := stagedImportStore(t)
	ctx := context.Background()
	mustIngestGuest(t, s, newObsA().guests(mkGuest(100, 2, "replacement")).build())
	if _, err := s.ImportStaged(ctx, "remote-a", 100, 1, "", "alice"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("stale import = %v", err)
	}
	hosts, err := s.hostStore().List(ctx)
	if err != nil || len(hosts) != 0 {
		t.Fatalf("orphan hosts = %+v, %v", hosts, err)
	}
	if _, err := s.GetLink(ctx, "remote-a", 100, 1); !errors.Is(err, ErrLinkNotFound) {
		t.Fatalf("stale link: %v", err)
	}
}

func TestImportRollsBackHostLinkAndMarking(t *testing.T) {
	for _, failure := range []string{"link", "mark"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", failure, existing), func(t *testing.T) {
				s := stagedImportStore(t)
				ctx := context.Background()
				hostID := ""
				if existing {
					hostID = "existing"
					mustCreateHost(t, s.db, mkManagedHost(hostID, "10.77.10.102"))
				}
				trigger := `CREATE TRIGGER fail_import BEFORE INSERT ON pve_host_links BEGIN SELECT RAISE(ABORT, 'import failure'); END`
				if failure == "mark" {
					trigger = `CREATE TRIGGER fail_import BEFORE UPDATE OF imported_at ON pve_staging BEGIN SELECT RAISE(ABORT, 'import failure'); END`
				}
				if _, err := s.db.ExecContext(ctx, trigger); err != nil {
					t.Fatal(err)
				}
				if _, err := s.ImportStaged(ctx, "remote-a", 100, 1, hostID, "alice"); err == nil {
					t.Fatal("import must fail")
				}
				hosts, err := s.hostStore().List(ctx)
				want := 0
				if existing {
					want = 1
				}
				if err != nil || len(hosts) != want {
					t.Fatalf("hosts after rollback = %+v, %v", hosts, err)
				}
				if _, err := s.GetLink(ctx, "remote-a", 100, 1); !errors.Is(err, ErrLinkNotFound) {
					t.Fatalf("link after rollback: %v", err)
				}
				entry, err := s.getStaging(ctx, "remote-a", 100, 1)
				if err != nil || !entry.ImportedAt.IsZero() || entry.ImportedAsset != "" {
					t.Fatalf("mark after rollback = %+v, %v", entry, err)
				}
			})
		}
	}
}

func TestDriftVersionsRejectOldConfirmationsAndKeepDecisions(t *testing.T) {
	ctx := context.Background()
	host := mkManagedHost("web1", "10.77.10.101")
	host.Tags = map[string]string{TagPVERAM: "8 GiB"}
	s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
	sweep := func() DriftHint {
		t.Helper()
		hints, err := s.SweepDrift(ctx, "remote-a")
		if err != nil || len(hints) != 1 {
			t.Fatalf("sweep = %+v, %v", hints, err)
		}
		return hints[0]
	}
	old := sweep()
	if same := sweep(); same.ID != old.ID {
		t.Fatal("unchanged hint received a new confirmation ID")
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithConfig(100, 1, "vm1", 2<<30, nil)).build())
	current := sweep()
	if current.ID == old.ID {
		t.Fatal("changed values reused a confirmation ID")
	}
	if _, err := s.ResolveDriftHint(ctx, old.ID, DriftAccepted, "alice"); err == nil {
		t.Fatal("stale confirmation accepted")
	}
	resolved, err := s.ResolveDriftHint(ctx, current.ID, DriftIgnored, "bob")
	if err != nil {
		t.Fatal(err)
	}
	reopened := sweep()
	if reopened.ID == current.ID || !reopened.ResolvedAt.IsZero() {
		t.Fatalf("redetection must create a new open version: %+v", reopened)
	}
	preserved, err := s.getDriftHint(ctx, current.ID)
	if err != nil || !reflect.DeepEqual(preserved, resolved) {
		t.Fatalf("decision lost: %+v, %v", preserved, err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithConfig(100, 1, "vm1", 1<<30, nil)).build())
	newest := sweep()
	if newest.ID == current.ID {
		t.Fatal("new observation reused a resolved hint")
	}
	history, err := s.ListDriftHints(ctx, "remote-a", 0)
	if err != nil || len(history) != 4 {
		t.Fatalf("history = %+v, %v", history, err)
	}
	if _, err := s.ResolveDriftHint(ctx, current.ID, DriftAccepted, "alice"); !errors.Is(err, ErrDriftResolved) {
		t.Fatalf("resolved confirmation = %v", err)
	}
}

func TestDriftPersistenceErrorsReachSweep(t *testing.T) {
	for _, trigger := range []string{
		`CREATE TRIGGER fail_hint BEFORE INSERT ON pve_drift_hints BEGIN SELECT RAISE(ABORT, 'hint persistence failure'); END`,
		`CREATE TRIGGER fail_hint AFTER INSERT ON pve_drift_hints BEGIN DELETE FROM pve_drift_hints WHERE id = NEW.id; END`,
	} {
		t.Run(trigger, func(t *testing.T) {
			ctx := context.Background()
			host := mkManagedHost("web1", "10.77.10.101")
			host.Tags = map[string]string{TagPVERAM: "8 GiB"}
			s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
			if _, err := s.db.ExecContext(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			hints, err := s.SweepDrift(ctx, "remote-a")
			if err == nil || len(hints) != 0 {
				t.Fatalf("failed persistence reported success: %+v, %v", hints, err)
			}
		})
	}
}

func TestDriftUnavailableConfigStillComparesOtherFieldsAndGuests(t *testing.T) {
	ctx := context.Background()
	for _, missing := range []bool{true, false} {
		t.Run(fmt.Sprintf("missing=%t", missing), func(t *testing.T) {
			host := mkManagedHost("web1", "10.77.10.101")
			host.Tags = map[string]string{TagPVERAM: "8 GiB", TagPVENode: "old-node", TagPVEState: "stopped"}
			s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
			later := mkGuestWithConfig(200, 1, "vm2", 2<<30, nil)
			unavailable := mkGuest(100, 1, "vm1")
			mustIngestGuest(t, s, newObsA().guests(unavailable, later).build())
			if missing {
				if _, err := s.db.ExecContext(ctx, `DELETE FROM pve_guest_configs WHERE vmid = 100`); err != nil {
					t.Fatal(err)
				}
			}
			host2 := mkManagedHost("web2", "10.77.10.102")
			host2.Tags = map[string]string{TagPVERAM: "8 GiB"}
			mustCreateHost(t, s.db, host2)
			if _, err := s.CreateLink(ctx, "remote-a", 200, 1, "web2", "alice"); err != nil {
				t.Fatal(err)
			}
			hints, err := s.SweepDrift(ctx, "remote-a")
			if err != nil || len(hints) != 3 {
				t.Fatalf("independent comparisons = %+v, %v", hints, err)
			}
			for _, hint := range hints {
				if hint.VMID == 100 && hint.Field == DriftFieldRAM {
					t.Fatal("unavailable RAM compared using old data")
				}
			}
		})
	}
}

func TestStagingSweepsBeyondFirstThousandGuests(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatal(err)
	}
	guests := make([]pvecontract.GuestObservation, MaxGuestsQuery+1)
	for i := range guests {
		guests[i] = mkGuest(uint64(i+100), 1, fmt.Sprintf("vm%d", i))
	}
	mustIngestGuest(t, s, newObsA().guests(guests[:MaxGuestsQuery]...).incomplete().build())
	mustIngestGuest(t, s, newObsA().guests(guests[MaxGuestsQuery:]...).incomplete().build())
	rows, err := s.SweepStaging(ctx, "remote-a")
	if err != nil || len(rows) != len(guests) {
		t.Fatalf("swept %d of %d guests: %v", len(rows), len(guests), err)
	}
	seen := map[uint64]bool{}
	for _, row := range rows {
		if seen[row.VMID] {
			t.Fatalf("duplicate guest %d", row.VMID)
		}
		seen[row.VMID] = true
	}
	if _, err := s.getStaging(ctx, "remote-a", guests[len(guests)-1].VMID, 1); err != nil {
		t.Fatalf("last guest missing: %v", err)
	}
}

func TestDriftAcceptanceRollsBackTagOnResolutionFailure(t *testing.T) {
	ctx := context.Background()
	host := mkManagedHost("web1", "10.77.10.101")
	host.Tags = map[string]string{TagPVERAM: "8 GiB"}
	s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil || len(hints) != 1 {
		t.Fatalf("sweep = %+v, %v", hints, err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_resolve BEFORE UPDATE OF resolved_at ON pve_drift_hints BEGIN SELECT RAISE(ABORT, 'resolution failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveDriftHint(ctx, hints[0].ID, DriftAccepted, "alice"); err == nil || !strings.Contains(err.Error(), "resolution failure") {
		t.Fatalf("resolve = %v", err)
	}
	got, err := s.hostStore().Get(ctx, host.ID)
	if err != nil || got.Tags[TagPVERAM] != "8 GiB" {
		t.Fatalf("tag escaped rollback: %+v, %v", got, err)
	}
}

func TestDriftVersionUpdateFailureRetainsPreviousHint(t *testing.T) {
	ctx := context.Background()
	host := mkManagedHost("web1", "10.77.10.101")
	host.Tags = map[string]string{TagPVERAM: "8 GiB"}
	s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil || len(hints) != 1 {
		t.Fatalf("sweep = %+v, %v", hints, err)
	}
	before := hints[0]
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithConfig(100, 1, "vm1", 2<<30, nil)).build())
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_version BEFORE UPDATE OF superseded_at ON pve_drift_hints BEGIN SELECT RAISE(ABORT, 'version failure'); END`); err != nil {
		t.Fatal(err)
	}
	if hints, err := s.SweepDrift(ctx, "remote-a"); err == nil || len(hints) != 0 || !strings.Contains(err.Error(), "version failure") {
		t.Fatalf("sweep failure = %+v, %v", hints, err)
	}
	after, err := s.getDriftHint(ctx, before.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("failed version changed previous hint: %+v, %v", after, err)
	}
}

func TestDriftDisappearedDifferenceInvalidatesConfirmation(t *testing.T) {
	ctx := context.Background()
	host := mkManagedHost("web1", "10.77.10.101")
	host.Tags = map[string]string{TagPVERAM: "8 GiB"}
	s := setupLinkedGuest(t, mkGuestWithConfig(100, 1, "vm1", 4<<30, nil), host)
	hints, err := s.SweepDrift(ctx, "remote-a")
	if err != nil || len(hints) != 1 {
		t.Fatalf("sweep = %+v, %v", hints, err)
	}
	mustIngestGuest(t, s, newObsA().guests(mkGuestWithConfig(100, 1, "vm1", 8<<30, nil)).build())
	if hints, err := s.SweepDrift(ctx, "remote-a"); err != nil || len(hints) != 0 {
		t.Fatalf("matched sweep = %+v, %v", hints, err)
	}
	if _, err := s.ResolveDriftHint(ctx, hints[0].ID, DriftAccepted, "alice"); !errors.Is(err, ErrDriftStale) {
		t.Fatalf("obsolete confirmation = %v", err)
	}
}

func TestDriftVersionMigrationPreservesExistingDecisions(t *testing.T) {
	ctx := context.Background()
	_, db, _ := newTestStore(t)
	// Rebuild the pre-versioning drift table with both an open hint and an
	// audited decision, then reopen through the normal migration path.
	if _, err := db.ExecContext(ctx, `
  DROP TABLE pve_drift_hints;
  CREATE TABLE pve_drift_hints (
   id INTEGER PRIMARY KEY, remote_id TEXT NOT NULL, vmid INTEGER NOT NULL,
   generation INTEGER NOT NULL, host_id TEXT NOT NULL, field TEXT NOT NULL,
   inventory_value TEXT NOT NULL, pve_value TEXT NOT NULL, created_at TEXT NOT NULL,
   resolved_at TEXT NOT NULL DEFAULT '', resolution TEXT NOT NULL DEFAULT '',
   resolved_by TEXT NOT NULL DEFAULT '', UNIQUE(host_id, field));
  INSERT INTO pve_drift_hints VALUES
   (41, 'remote-a', 100, 1, 'web1', 'ram', '8 GiB', '4 GiB', '2026-10-29T12:00:00Z', '2026-10-29T12:00:00Z', 'ignored', 'alice'),
   (42, 'remote-a', 100, 1, 'web1', 'state', 'stopped', 'running', '2026-10-29T12:00:00Z', '', '', '');
  DROP INDEX idx_pve_backup_task_freshness;
  DROP INDEX idx_pve_backup_catalog_freshness;
  DROP TABLE pve_metric_buckets;
  DROP TABLE pve_metric_current;
  DELETE FROM schema_migrations WHERE version >= 22;`); err != nil {
		t.Fatal(err)
	}
	var path string
	var seq int
	var name string
	if err := db.QueryRowContext(ctx, `PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	before, err := scanLegacyDriftDecision(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	s := New(migrated)
	after, err := s.getDriftHint(ctx, 41)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("migration changed decision: %+v, %v", after, err)
	}
	open, err := s.getDriftHint(ctx, 42)
	if err != nil || !open.ResolvedAt.IsZero() || !open.SupersededAt.IsZero() {
		t.Fatalf("migration changed open hint: %+v, %v", open, err)
	}
	next, err := s.recordDrift(ctx, Link{RemoteID: "remote-a", VMID: 100, Generation: 1}, "web1", DriftFieldRAM, "8 GiB", "2 GiB")
	if err != nil || next.ID <= 42 {
		t.Fatalf("migration reused confirmation IDs: %+v, %v", next, err)
	}
}

func scanLegacyDriftDecision(ctx context.Context, db *sql.DB) (DriftHint, error) {
	return scanDriftRow(db.QueryRowContext(ctx, `SELECT id, remote_id, vmid, generation, host_id, field,
  inventory_value, pve_value, created_at, resolved_at, resolution, resolved_by, '' FROM pve_drift_hints WHERE id = 41`))
}

func ingestOK(t *testing.T, s *Store, obs pvecontract.Observation) IngestReport {
	t.Helper()
	rep, err := s.IngestObservation(context.Background(), obs)
	if err != nil {
		t.Fatalf("ingest: %v (%+v)", err, rep)
	}
	return rep
}

func TestStaleCollectionCannotMutateInventory(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  uint64
		at   time.Time
	}{
		{"older collection", 1, testBase.Add(time.Hour)},
		{"older observation", 2, testBase.Add(-time.Nanosecond)},
		{"older subsecond observation", 2, testBase.Add(3 * time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			ctx := context.Background()
			current := newObsA().nodes(mkNode("p1")).guests(mkGuest(100, 2, "current"), mkGuest(200, 1, "keep")).build()
			current.CollectionGeneration = 2
			current.ObservedAt = testBase.Add(5 * time.Nanosecond)
			ingestOK(t, s, current)
			beforeRemote, _ := s.GetRemote(ctx, "remote-a")
			beforeGuest, _ := s.GetGuest(ctx, "remote-a", 100)
			beforeStatus, _ := s.GetDatasetStatus(ctx, "remote-a", DatasetGuests)
			stale := newObsA().nodes(mkNode("old")).guests(mkGuest(100, 3, "stale")).build()
			stale.CollectionGeneration, stale.ObservedAt = tc.gen, tc.at
			if _, err := s.IngestObservation(ctx, stale); !errors.Is(err, ErrStaleObservation) {
				t.Fatalf("want stale rejection, got %v", err)
			}
			afterRemote, _ := s.GetRemote(ctx, "remote-a")
			afterGuest, _ := s.GetGuest(ctx, "remote-a", 100)
			afterStatus, _ := s.GetDatasetStatus(ctx, "remote-a", DatasetGuests)
			if beforeRemote != afterRemote || beforeGuest != afterGuest || beforeStatus != afterStatus {
				t.Fatal("stale observation changed rows or status")
			}
			if n := countRows(t, db, "pve_guests", "tombstoned = 1"); n != 0 {
				t.Fatalf("stale observation tombstoned %d guests", n)
			}
			if n := countRows(t, db, "pve_nodes"); n != 1 {
				t.Fatalf("stale observation wrote nodes: %d", n)
			}
		})
	}
}

func TestCollectionPagesReconcileTogether(t *testing.T) {
	s, db, _ := newTestStore(t)
	ingestOK(t, s, newObsA().guests(mkGuest(300, 1, "removed")).build())
	first := newObsA().incomplete().guests(mkGuest(100, 1, "first")).build()
	first.CollectionGeneration = 2
	ingestOK(t, s, first)
	// Collection membership must survive constructing another store over the DB.
	s = NewWithNow(db, func() time.Time { return testBase })
	final := newObsA().guests(mkGuest(200, 1, "last")).build()
	final.CollectionGeneration = 2
	rep := ingestOK(t, s, final)
	if rep.GuestsTombstoned != 1 {
		t.Fatalf("want only absent guest tombstoned: %+v", rep)
	}
	// Replaying the final page also keeps the preceding page's identities.
	if replay := ingestOK(t, s, final); replay.GuestsTombstoned != 0 {
		t.Fatalf("final page replay lost collection membership: %+v", replay)
	}
	final.Nodes = pvecontract.AvailableDataset([]pvecontract.NodeObservation{mkNode("p1")})
	if replay := ingestOK(t, s, final); replay.GuestsTombstoned != 0 {
		t.Fatalf("updating another dataset lost collection membership: %+v", replay)
	}
	for _, id := range []uint64{100, 200} {
		if _, err := s.GetGuest(context.Background(), "remote-a", id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerationHighWaterSurvivesTombstonePruning(t *testing.T) {
	for _, prune := range []bool{false, true} {
		t.Run(fmt.Sprint(prune), func(t *testing.T) {
			s, db, now := newTestStore(t)
			ctx := context.Background()
			ingestOK(t, s, newObsA().guests(mkGuest(100, 5, "latest")).build())
			ingestOK(t, s, newObsA().guests().build())
			if prune {
				*now = testBase.Add(TombstoneRetention + time.Hour)
				if _, err := s.Prune(ctx); err != nil {
					t.Fatal(err)
				}
				if countRows(t, db, "pve_guests") != 0 {
					t.Fatal("tombstone was not pruned")
				}
				s = NewWithNow(db, func() time.Time { return *now })
			}
			for _, gen := range []uint64{4, 5} {
				rep := ingestOK(t, s, newObsA().guests(mkGuest(100, gen, "obsolete")).build())
				if rep.GuestsStarted != 0 {
					t.Fatalf("generation %d resurrected: %+v", gen, rep)
				}
				if _, err := s.GetGuest(ctx, "remote-a", 100); !errors.Is(err, ErrGuestNotFound) {
					t.Fatalf("obsolete guest active: %v", err)
				}
			}
			ingestOK(t, s, newObsA().guests(mkGuest(100, 6, "new")).build())
			got, err := s.GetGuest(ctx, "remote-a", 100)
			if err != nil || got.Generation != 6 {
				t.Fatalf("new generation: %+v %v", got, err)
			}
		})
	}
}

func TestMutableEvidenceUpdatesOnNewObservation(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	b := pvecontract.BackupEvidence{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask, Name: "backup", Status: "running", StartedUnix: testBase.Unix(), Verified: pvecontract.Unknown}
	task := pvecontract.TaskObservation{Node: "p1", Actor: "root", Type: "backup", Target: "qemu/100", StartedUnix: testBase.Unix(), ExitStatus: ""}
	g := mkGuest(100, 1, "vm")
	g.Backups = pvecontract.AvailableDataset([]pvecontract.BackupEvidence{b})
	ingestOK(t, s, newObsA().guests(g).tasks(task).build())
	b.Status, b.FinishedUnix, b.Verified = "success", testBase.Add(time.Minute).Unix(), pvecontract.Yes
	task.ExitStatus = "success"
	g.Backups.Value[0] = b
	obs := newObsA().guests(g).tasks(task).build()
	obs.CollectionGeneration = 2
	obs.ObservedAt = testBase.Add(time.Minute)
	ingestOK(t, s, obs)
	backups, err := s.ListBackups(ctx, "remote-a", 100, 1, 0)
	if err != nil || len(backups) != 1 || backups[0].Status != "success" || backups[0].FinishedUnix != b.FinishedUnix || backups[0].Verified != pvecontract.Yes || backups[0].CollectionGeneration != 2 || !backups[0].ObservedAt.Equal(obs.ObservedAt) {
		t.Fatalf("backup update lost: %+v %v", backups, err)
	}
	tasks, err := s.ListTasks(ctx, "remote-a", 0)
	if err != nil || len(tasks) != 1 || tasks[0].ExitStatus != "success" || tasks[0].CollectionGeneration != 2 || !tasks[0].ObservedAt.Equal(obs.ObservedAt) {
		t.Fatalf("task update lost: %+v %v", tasks, err)
	}
	older := obs
	older.ObservedAt = testBase
	older.Guests.Value[0].Backups.Value[0].Status = "running"
	older.Tasks.Value[0].ExitStatus = ""
	if _, err := s.IngestObservation(ctx, older); !errors.Is(err, ErrStaleObservation) {
		t.Fatalf("older evidence accepted: %v", err)
	}
	retained, err := s.ListBackups(ctx, "remote-a", 100, 1, 0)
	if err != nil || !reflect.DeepEqual(retained, backups) {
		t.Fatalf("older backup clobbered completion: %+v %v", retained, err)
	}
	retainedTasks, err := s.ListTasks(ctx, "remote-a", 0)
	if err != nil || !reflect.DeepEqual(retainedTasks, tasks) {
		t.Fatalf("older task clobbered completion: %+v %v", retainedTasks, err)
	}
}

func TestBackupsNewestFirstWithBoundedPagination(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	for page := 0; page < 2; page++ {
		g := mkGuest(100, 1, "vm")
		var backups []pvecontract.BackupEvidence
		for i := 0; i < MaxBackupsQuery; i++ {
			backups = append(backups, pvecontract.BackupEvidence{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask, Name: fmt.Sprintf("b-%03d", page*MaxBackupsQuery+i), StartedUnix: testBase.Unix() + int64(page*MaxBackupsQuery+i), Status: "success", Verified: pvecontract.Unknown})
		}
		g.Backups = pvecontract.AvailableDataset(backups)
		ingestOK(t, s, newObsA().guests(g).build())
	}
	first, err := s.ListBackups(ctx, "remote-a", 100, 1, 0)
	if err != nil || len(first) != MaxBackupsQuery || first[0].Name != "b-127" || first[63].Name != "b-064" {
		t.Fatalf("newest backups missing: %+v %v", first, err)
	}
	second, err := s.ListBackupsPage(ctx, "remote-a", 100, 1, 0, &first[len(first)-1])
	if err != nil || len(second) != MaxBackupsQuery || second[0].Name != "b-063" || second[63].Name != "b-000" {
		t.Fatalf("backup page: %+v %v", second, err)
	}
	if _, err := s.ListBackupsPage(ctx, "remote-a", 100, 1, MaxBackupsQuery+1, nil); err == nil {
		t.Fatal("oversize page accepted")
	}
	if _, err := s.ListBackupsPage(ctx, "remote-b", 100, 1, 1, &first[0]); err == nil {
		t.Fatal("cursor from another remote accepted")
	}
	// Ties use the complete evidence identity, so no records disappear.
	g := mkGuest(200, 1, "ties")
	g.Backups = pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
		{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask, Name: "a", Status: "success", StartedUnix: testBase.Unix(), Verified: pvecontract.Unknown},
		{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask, Name: "b", Status: "success", StartedUnix: testBase.Unix(), Verified: pvecontract.Unknown},
	})
	ingestOK(t, s, newObsA().incomplete().guests(g).build())
	one, err := s.ListBackupsPage(ctx, "remote-a", 200, 1, 1, nil)
	if err != nil || len(one) != 1 {
		t.Fatalf("first tied page: %v", err)
	}
	two, err := s.ListBackupsPage(ctx, "remote-a", 200, 1, 1, &one[0])
	if err != nil || len(two) != 1 || reflect.DeepEqual(one, two) {
		t.Fatalf("tied page: %+v %v", two, err)
	}
}

func TestPartialPagesEnforceRemoteGuestLimitAtomically(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	for page := 0; page < pvecontract.MaxGuestsPerRemote/pvecontract.MaxObjectsPerPage; page++ {
		var guests []pvecontract.GuestObservation
		for i := 0; i < pvecontract.MaxObjectsPerPage; i++ {
			guests = append(guests, mkGuest(uint64(100+page*pvecontract.MaxObjectsPerPage+i), 1, "vm"))
		}
		ingestOK(t, s, newObsA().incomplete().guests(guests...).build())
	}
	before, _ := s.GetDatasetStatus(ctx, "remote-a", DatasetGuests)
	// First update a real row, then cross the remote-wide bound.
	obs := newObsA().incomplete().guests(mkGuest(100, 1, "must-roll-back"), mkGuest(20000, 1, "overflow")).build()
	rep, err := s.IngestObservation(ctx, obs)
	if err == nil || rep.Errors["guests"] == nil {
		t.Fatalf("remote guest overflow accepted: %+v %v", rep, err)
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 0"); n != pvecontract.MaxGuestsPerRemote {
		t.Fatalf("active guests=%d", n)
	}
	got, _ := s.GetGuest(ctx, "remote-a", 100)
	if got.Name != "vm" {
		t.Fatal("earlier mutation did not roll back")
	}
	after, _ := s.GetDatasetStatus(ctx, "remote-a", DatasetGuests)
	if before != after {
		t.Fatal("status changed on overflow")
	}
	// Reconciliation spans multiple bounded batches and retains all prior pages.
	rep = ingestOK(t, s, newObsA().guests().build())
	if rep.GuestsTombstoned != 0 {
		t.Fatalf("paged collection lost guests: %+v", rep)
	}
	// A fresh collection has few seen identities but still cannot grow the
	// remote's active set past the bound.
	obs.CollectionGeneration = 2
	rep, err = s.IngestObservation(ctx, obs)
	if err == nil || rep.Errors["guests"] == nil {
		t.Fatalf("active guest overflow accepted: %+v %v", rep, err)
	}
	got, _ = s.GetGuest(ctx, "remote-a", 100)
	if got.Name != "vm" || countRows(t, db, "pve_guests", "tombstoned = 0") != pvecontract.MaxGuestsPerRemote {
		t.Fatal("active-set overflow failed to roll back")
	}
	final := newObsA().guests().build()
	final.CollectionGeneration = 2
	rep = ingestOK(t, s, final)
	if rep.GuestsTombstoned != pvecontract.MaxGuestsPerRemote {
		t.Fatalf("reconciliation skipped a batch: %+v", rep)
	}
}

func TestUnavailableNodeDetailsPreserveAgeAndReason(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	node := mkNode("p1")
	node.Details = pvecontract.AvailableDataset(pvecontract.NodeDetails{PVEVersion: "9.0.1", KernelVersion: "6.8.0"})
	ingestOK(t, s, newObsA().nodes(node).build())
	node.Details = pvecontract.UnavailableDataset[pvecontract.NodeDetails]("detail endpoint unavailable")
	obs := newObsA().nodes(node).build()
	obs.CollectionGeneration = 2
	obs.ObservedAt = testBase.Add(time.Hour)
	ingestOK(t, s, obs)
	got, err := s.GetNode(ctx, "remote-a", "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.DetailsAvailable || got.PVEVersion != "9.0.1" || got.KernelVersion != "6.8.0" || !got.DetailsObservedAt.Equal(testBase) || got.DetailsReason != node.Details.Reason || !got.DetailsCheckedAt.Equal(obs.ObservedAt) || got.DetailsSource != obs.Source || !got.ObservedAt.Equal(obs.ObservedAt) {
		t.Fatalf("detail metadata lost: %+v", got)
	}
	nodes, err := s.ListNodes(ctx, "remote-a", 0)
	if err != nil || len(nodes) != 1 || !reflect.DeepEqual(nodes[0], got) {
		t.Fatalf("list detail metadata differs: %+v %v", nodes, err)
	}
}
