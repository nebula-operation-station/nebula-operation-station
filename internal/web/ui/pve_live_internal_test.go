// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func liveGuestObs(vmid, gen uint64, kind pvecontract.GuestKind, node string) pvecontract.GuestObservation {
	return pvecontract.GuestObservation{VMID: vmid, Kind: kind, Node: node, Name: "g", Status: pvecontract.GuestRunning, Generation: gen,
		Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
		Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
		Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read")}
}

func liveObs(gen uint64, guests ...pvecontract.GuestObservation) pvecontract.Observation {
	return pvecontract.Observation{RemoteID: "remote-a", ObservedAt: time.Unix(1_800_000_000+int64(gen)*60, 0).UTC(), Source: "test",
		CollectionGeneration: gen, Complete: true,
		Nodes: pvecontract.AvailableDataset([]pvecontract.NodeObservation{{Node: "p1", Status: pvecontract.NodeOnline, CPUCount: 1,
			RAMTotalBytes: 1 << 30, Details: pvecontract.UnavailableDataset[pvecontract.NodeDetails]("not read")}}),
		Guests:   pvecontract.AvailableDataset(guests),
		Storages: pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:  pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:    pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read")}
}

// TestPVETelemetryInventoryReadsStoredInventory pins the adapter the live
// proposal resolves targets through: stored remotes and nodes only, active
// incarnations only (a removed guest is gone, a recreated one has its new
// generation).
func TestPVETelemetryInventoryReadsStoredInventory(t *testing.T) {
	ctx := context.Background()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := pveinventory.New(db)
	if err := store.UpsertRemote(ctx, pvecontract.Remote{RemoteID: "remote-a", Name: "a", Kind: pvecontract.KindStandalone,
		Endpoints: []pvecontract.Endpoint{{Host: "a.lab", Port: 8006}}, TrustPin: strings.Repeat("a", 64), TrustGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.IngestObservation(ctx, liveObs(1, liveGuestObs(101, 1, pvecontract.GuestQEMU, "p1"), liveGuestObs(102, 1, pvecontract.GuestLXC, "p1"))); err != nil {
		t.Fatal(err)
	}
	inv := pveTelemetryInventory{store}
	if ok, err := inv.HasRemote(ctx, "remote-a"); !ok || err != nil {
		t.Fatalf("HasRemote(remote-a) = %v, %v", ok, err)
	}
	if ok, err := inv.HasRemote(ctx, "remote-z"); ok || err != nil {
		t.Fatalf("HasRemote(remote-z) = %v, %v", ok, err)
	}
	if ok, _ := inv.HasNode(ctx, "remote-a", "p1"); !ok {
		t.Fatal("stored node not found")
	}
	if ok, _ := inv.HasNode(ctx, "remote-a", "p9"); ok {
		t.Fatal("unknown node found")
	}
	// Next pass: 101 recreated (generation 2), 102 removed.
	if _, err := store.IngestObservation(ctx, liveObs(2, liveGuestObs(101, 2, pvecontract.GuestQEMU, "p1"))); err != nil {
		t.Fatal(err)
	}
	gs, err := inv.ActiveGuests(ctx, "remote-a", 101, 2)
	if err != nil || !slices.Equal(gs, []executions.TelemetryGuest{{VMID: 101, Generation: 2, Kind: "qemu", Node: "p1"}}) {
		t.Fatalf("ActiveGuests(101) = %+v, %v", gs, err)
	}
	if gs, err := inv.ActiveGuests(ctx, "remote-a", 102, 2); err != nil || len(gs) != 0 {
		t.Fatalf("ActiveGuests(102) = %+v, %v (removed guest)", gs, err)
	}
	if gs, err := inv.ActiveGuests(ctx, "remote-a", 0, 2); err != nil || len(gs) != 0 {
		t.Fatalf("ActiveGuests(0) = %+v, %v", gs, err)
	}
}
