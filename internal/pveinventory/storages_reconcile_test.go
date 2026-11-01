// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for storage reconciliation: a complete, available storage read
// is authoritative and drops the remote's pve_storages rows it no longer
// reports (a storage deleted in PVE, a node that stopped reporting).
// Partial, incomplete and unavailable observations never delete. A shared
// storage reported by several nodes stays stored per node but appears
// once in the org chart.

package pveinventory

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// storageRowPairs lists the stored (node, name) pairs of one remote.
func storageRowPairs(t *testing.T, db *sql.DB, remoteID string) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT node, name FROM pve_storages WHERE remote_id = ? ORDER BY node, name`, remoteID)
	if err != nil {
		t.Fatalf("query storages: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var node, name string
		if err := rows.Scan(&node, &name); err != nil {
			t.Fatalf("scan storage row: %v", err)
		}
		out[node+"\x00"+name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate storage rows: %v", err)
	}
	return out
}

// datasetStateOf returns the stored state of one top-level dataset.
func datasetStateOf(t *testing.T, db *sql.DB, remoteID, dataset string) string {
	t.Helper()
	var state string
	if err := db.QueryRow(`SELECT state FROM pve_dataset_status WHERE remote_id = ? AND dataset = ?`, remoteID, dataset).Scan(&state); err != nil {
		t.Fatalf("dataset status %s/%s: %v", remoteID, dataset, err)
	}
	return state
}

// countBoxesByID counts boxes with the given ID anywhere in the tree.
func countBoxesByID(roots []Box, id string) int {
	n := 0
	var walk func(b []Box)
	walk = func(b []Box) {
		for _, x := range b {
			if x.ID == id {
				n++
			}
			walk(x.Children)
		}
	}
	walk(roots)
	return n
}

// seedStorageCluster ingests one complete observation with p1 and p2,
// their node-local storages and a shared storage reported by both.
func seedStorageCluster(t *testing.T, s *Store, ctx context.Context) {
	t.Helper()
	obs := newObsA().
		nodes(mkNode("p1"), mkNode("p2")).
		storages(
			onNode(mkStorage("local", "dir", 1<<30, 512<<20), "p1", false),
			onNode(mkStorage("local2", "dir", 1<<30, 512<<20), "p2", false),
			onNode(mkStorage("nfs-shared", "nfs", 10<<30, 5<<30), "p1", true),
			onNode(mkStorage("nfs-shared", "nfs", 10<<30, 5<<30), "p2", true),
		).
		build()
	rep, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("seed ingest: %v", err)
	}
	if rep.StoragesUpserted != 4 || rep.StoragesDeleted != 0 {
		t.Fatalf("seed report: %+v", rep)
	}
}

func TestIngestStoragesCompleteReadDropsRemovedStorage(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	seedStorageCluster(t, s, ctx)
	if n := countRows(t, db, "pve_storages"); n != 4 {
		t.Fatalf("expected 4 storage rows, got %d", n)
	}

	// A newer complete read: p2 was removed from the cluster and
	// nfs-shared was deleted in PVE. Only p1's local storage remains.
	obs := newObsA().
		nodes(mkNode("p1")).
		storages(onNode(mkStorage("local", "dir", 1<<30, 512<<20), "p1", false)).
		build()
	obs.CollectionGeneration = 2
	obs.ObservedAt = testBase.Add(time.Minute)
	rep, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.StoragesUpserted != 1 || rep.StoragesDeleted != 3 {
		t.Fatalf("report 2: %+v", rep)
	}
	got := storageRowPairs(t, db, "remote-a")
	if len(got) != 1 || !got["p1\x00local"] {
		t.Fatalf("remaining rows: %v", got)
	}
}

func TestIngestStoragesCompleteEmptyReadDropsAllRows(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	seedStorageCluster(t, s, ctx)

	// A complete read that found no storages is a complete enumeration
	// that found nothing: every row disappears.
	obs := newObsA().
		nodes(mkNode("p1"), mkNode("p2")).
		storages().
		build()
	obs.CollectionGeneration = 2
	obs.ObservedAt = testBase.Add(time.Minute)
	rep, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.StoragesUpserted != 0 || rep.StoragesDeleted != 4 {
		t.Fatalf("report 2: %+v", rep)
	}
	if n := countRows(t, db, "pve_storages"); n != 0 {
		t.Fatalf("expected 0 storage rows, got %d", n)
	}
}

func TestIngestStoragesPartialObservationKeepsRows(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	seedStorageCluster(t, s, ctx)

	// Node p2 is offline: the observation is incomplete and its storage
	// read covers only p1. p2's rows must survive.
	obs := newObsA().
		nodes(mkNode("p1")).
		storages(onNode(mkStorage("local", "dir", 1<<30, 512<<20), "p1", false)).
		incomplete().
		build()
	obs.CollectionGeneration = 2
	obs.ObservedAt = testBase.Add(time.Minute)
	rep, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.StoragesDeleted != 0 {
		t.Fatalf("partial observation deleted rows: %+v", rep)
	}
	got := storageRowPairs(t, db, "remote-a")
	if len(got) != 4 || !got["p2\x00local2"] || !got["p2\x00nfs-shared"] {
		t.Fatalf("rows after partial read: %v", got)
	}
	if st := datasetStateOf(t, db, "remote-a", DatasetStorages); st != string(StatePartial) {
		t.Fatalf("dataset state = %q, want partial", st)
	}
}

func TestIngestStoragesUnavailableKeepsRows(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	seedStorageCluster(t, s, ctx)

	// The storage read failed: dataset unavailable, nothing deleted.
	obs := newObsA().
		nodes(mkNode("p1"), mkNode("p2")).
		build() // storages stays unavailable
	obs.CollectionGeneration = 2
	obs.ObservedAt = testBase.Add(time.Minute)
	rep, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.StoragesUpserted != 0 || rep.StoragesDeleted != 0 {
		t.Fatalf("report 2: %+v", rep)
	}
	if n := countRows(t, db, "pve_storages"); n != 4 {
		t.Fatalf("expected 4 storage rows, got %d", n)
	}
	if st := datasetStateOf(t, db, "remote-a", DatasetStorages); st != string(StateUnavailable) {
		t.Fatalf("dataset state = %q, want unavailable", st)
	}
}

func TestIngestStoragesSharedStorageOnceInTree(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	seedStorageCluster(t, s, ctx)

	// Both per-node rows stay stored...
	if n := countRows(t, s.db, "pve_storages"); n != 4 {
		t.Fatalf("expected 4 storage rows, got %d", n)
	}
	// ...but the shared storage appears exactly once in the org chart.
	tree, err := s.ChartTree(ctx, testBase.Add(time.Minute))
	if err != nil {
		t.Fatalf("ChartTree: %v", err)
	}
	if n := countBoxesByID(tree.Roots, "storage/remote-a/nfs-shared"); n != 1 {
		t.Fatalf("shared storage boxes = %d, want 1", n)
	}
	if n := countBoxesByID(tree.Roots, "storage/remote-a/local"); n != 1 {
		t.Fatalf("local storage boxes = %d, want 1", n)
	}
	if n := countBoxesByID(tree.Roots, "storage/remote-a/local2"); n != 1 {
		t.Fatalf("local2 storage boxes = %d, want 1", n)
	}
}
