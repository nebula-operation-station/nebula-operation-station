// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

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
