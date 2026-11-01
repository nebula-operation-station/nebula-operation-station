// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the pveinventory store and ingest. They cover the P1-11
// acceptance criteria: cross-remote VMID isolation, atomic per-dataset
// ingest, partial and stale handling, incarnation reset, retention
// pruning with an injected clock, and bounded queries.

package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

var testBase = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func newTestStore(t *testing.T) (*Store, *sql.DB, *time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	now := testBase
	s := NewWithNow(db, func() time.Time { return now })
	t.Cleanup(func() { db.Close() })
	return s, db, &now
}

func remoteA() pvecontract.Remote {
	return pvecontract.Remote{
		RemoteID:        "remote-a",
		Name:            "Lab A",
		Kind:            pvecontract.KindStandalone,
		Endpoints:       []pvecontract.Endpoint{{Host: "192.168.0.10", Port: 8006}},
		TrustPin:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TrustGeneration: 3,
	}
}

func remoteB() pvecontract.Remote {
	return pvecontract.Remote{
		RemoteID:        "remote-b",
		Name:            "Lab B",
		Kind:            pvecontract.KindStandalone,
		Endpoints:       []pvecontract.Endpoint{{Host: "192.168.0.11", Port: 8006}},
		TrustPin:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		TrustGeneration: 1,
	}
}

func mkNode(name string) pvecontract.NodeObservation {
	return pvecontract.NodeObservation{
		Node:          name,
		Status:        pvecontract.NodeOnline,
		UptimeSeconds: 3600,
		CPUCount:      8,
		RAMTotalBytes: 32 << 30,
		RAMUsedBytes:  8 << 30,
		Details:       pvecontract.UnavailableDataset[pvecontract.NodeDetails]("not read"),
	}
}

func mkGuest(vmid uint64, gen uint64, name string) pvecontract.GuestObservation {
	return pvecontract.GuestObservation{
		VMID:       vmid,
		Kind:       pvecontract.GuestQEMU,
		Node:       "p1",
		Name:       name,
		Status:     pvecontract.GuestRunning,
		Generation: gen,
		Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
		Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
		Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
		Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
		Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read"),
	}
}

func mkStorage(name, typ string, sizeBytes, freeBytes uint64) pvecontract.StorageObservation {
	return pvecontract.StorageObservation{
		Name:      name,
		Type:      typ,
		Content:   []string{"images"},
		Active:    true,
		SizeBytes: sizeBytes,
		FreeBytes: freeBytes,
	}
}

// onNode sets the reporting node and PVE's shared flag on a storage.
func onNode(st pvecontract.StorageObservation, node string, shared bool) pvecontract.StorageObservation {
	st.Node = node
	st.Shared = shared
	return st
}

func newObsA() *obsBuilder {
	return &obsBuilder{obs: pvecontract.Observation{
		RemoteID:             "remote-a",
		ObservedAt:           testBase,
		Source:               "test-collector",
		CollectionGeneration: 1,
		Complete:             true,
		Nodes:                pvecontract.UnavailableDataset[[]pvecontract.NodeObservation]("not read"),
		Guests:               pvecontract.UnavailableDataset[[]pvecontract.GuestObservation]("not read"),
		Storages:             pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:              pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:                pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read"),
	}}
}

func newObsB() *obsBuilder {
	return &obsBuilder{obs: pvecontract.Observation{
		RemoteID:             "remote-b",
		ObservedAt:           testBase,
		Source:               "test-collector",
		CollectionGeneration: 1,
		Complete:             true,
		Nodes:                pvecontract.UnavailableDataset[[]pvecontract.NodeObservation]("not read"),
		Guests:               pvecontract.UnavailableDataset[[]pvecontract.GuestObservation]("not read"),
		Storages:             pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:              pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:                pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read"),
	}}
}

// obsBuilder assembles a valid pvecontract.Observation for tests.
type obsBuilder struct {
	obs pvecontract.Observation
}

func (b *obsBuilder) nodes(nodes ...pvecontract.NodeObservation) *obsBuilder {
	b.obs.Nodes = pvecontract.AvailableDataset(nodes)
	return b
}

func (b *obsBuilder) guests(guests ...pvecontract.GuestObservation) *obsBuilder {
	b.obs.Guests = pvecontract.AvailableDataset(guests)
	return b
}

func (b *obsBuilder) storages(storages ...pvecontract.StorageObservation) *obsBuilder {
	b.obs.Storages = pvecontract.AvailableDataset(storages)
	return b
}

func (b *obsBuilder) cluster(c pvecontract.ClusterObservation) *obsBuilder {
	b.obs.Cluster = pvecontract.AvailableDataset(c)
	return b
}

func (b *obsBuilder) tasks(tasks ...pvecontract.TaskObservation) *obsBuilder {
	b.obs.Tasks = pvecontract.AvailableDataset(tasks)
	return b
}

func (b *obsBuilder) incomplete() *obsBuilder {
	b.obs.Complete = false
	b.obs.Reason = "enumeration incomplete"
	return b
}

func (b *obsBuilder) build() pvecontract.Observation { return b.obs }

func countRows(t *testing.T, db *sql.DB, table string, where ...string) int {
	t.Helper()
	q := "SELECT COUNT(*) FROM " + table
	if len(where) > 0 {
		q += " WHERE " + where[0]
	}
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestCrossRemoteVMIDCollision(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote A: %v", err)
	}
	if err := s.UpsertRemote(ctx, remoteB()); err != nil {
		t.Fatalf("UpsertRemote B: %v", err)
	}

	// Both remotes host VMID 100.
	if _, err := s.IngestObservation(ctx, newObsA().guests(mkGuest(100, 1, "vm-a")).build()); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsB().guests(mkGuest(100, 1, "vm-b")).build()); err != nil {
		t.Fatalf("ingest B: %v", err)
	}

	ga, err := s.GetGuest(ctx, "remote-a", 100)
	if err != nil {
		t.Fatalf("GetGuest A: %v", err)
	}
	gb, err := s.GetGuest(ctx, "remote-b", 100)
	if err != nil {
		t.Fatalf("GetGuest B: %v", err)
	}
	if ga.Name != "vm-a" || gb.Name != "vm-b" {
		t.Fatalf("wrong names: A=%q B=%q", ga.Name, gb.Name)
	}
	if ga.RemoteID != "remote-a" || gb.RemoteID != "remote-b" {
		t.Fatalf("wrong remote ids: %q / %q", ga.RemoteID, gb.RemoteID)
	}

	listA, err := s.ListGuests(ctx, "remote-a", GuestFilter{}, 0)
	if err != nil {
		t.Fatalf("ListGuests A: %v", err)
	}
	listB, err := s.ListGuests(ctx, "remote-b", GuestFilter{}, 0)
	if err != nil {
		t.Fatalf("ListGuests B: %v", err)
	}
	if len(listA) != 1 || len(listB) != 1 {
		t.Fatalf("expected 1 guest per remote, got A=%d B=%d", len(listA), len(listB))
	}
}

func TestIngestIdempotentAndDatasetIndependent(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	obs := newObsA().
		nodes(mkNode("p1")).
		guests(mkGuest(100, 1, "vm1")).
		storages(pvecontract.StorageObservation{Name: "local", Type: "dir", Format: "raw", Active: true, SizeBytes: 1000, FreeBytes: 500}).
		build()

	rep1, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	if rep1.NodesUpserted != 1 || rep1.GuestsUpserted != 1 || rep1.GuestsStarted != 1 || rep1.StoragesUpserted != 1 {
		t.Fatalf("unexpected report: %+v", rep1)
	}

	// Re-ingest the same observation: nothing new, no tombstones, no new starts.
	rep2, err := s.IngestObservation(ctx, obs)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep2.GuestsUpserted != 1 || rep2.GuestsStarted != 0 || rep2.GuestsTombstoned != 0 {
		t.Fatalf("re-ingest not idempotent: %+v", rep2)
	}
	if n := countRows(t, db, "pve_guests"); n != 1 {
		t.Fatalf("expected 1 guest row, got %d", n)
	}
	if n := countRows(t, db, "pve_nodes"); n != 1 {
		t.Fatalf("expected 1 node row, got %d", n)
	}
	if n := countRows(t, db, "pve_storages"); n != 1 {
		t.Fatalf("expected 1 storage row, got %d", n)
	}

	// A second observation where nodes are available but guests are
	// unavailable: the node dataset commits, the guest dataset is left
	// untouched, and both dataset statuses are recorded.
	obs2 := newObsA().nodes(mkNode("p1")).build()
	if _, err := s.IngestObservation(ctx, obs2); err != nil {
		t.Fatalf("ingest 3: %v", err)
	}
	st, err := s.GetDatasetStatus(ctx, "remote-a", "nodes")
	if err != nil {
		t.Fatalf("GetDatasetStatus nodes: %v", err)
	}
	if st.State != "available" {
		t.Fatalf("nodes state = %q, want available", st.State)
	}
	st, err = s.GetDatasetStatus(ctx, "remote-a", "guests")
	if err != nil {
		t.Fatalf("GetDatasetStatus guests: %v", err)
	}
	if st.State != "unavailable" {
		t.Fatalf("guests state = %q, want unavailable", st.State)
	}
	if n := countRows(t, db, "pve_guests"); n != 1 {
		t.Fatalf("guest row count changed by unavailable dataset: %d", n)
	}
}

func TestDatasetFailureIsAtomicAndIsolated(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	// 1) Guest 100/1 becomes active, then 2) a complete empty enumeration
	// tombstones it.
	if _, err := s.IngestObservation(ctx, newObsA().nodes(mkNode("p1")).guests(mkGuest(100, 1, "vm1")).build()); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsA().nodes(mkNode("p1")).guests().build()); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 1"); n != 1 {
		t.Fatalf("expected 1 tombstoned guest, got %d", n)
	}

	// Mutate one guest and its dataset status successfully before a later
	// guest fails. Both mutations must roll back, while nodes still commit.
	before, err := s.GetDatasetStatus(ctx, "remote-a", DatasetGuests)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER mutate_guest_status AFTER INSERT ON pve_guests
		WHEN NEW.vmid = 200 BEGIN
		UPDATE pve_dataset_status SET reason = 'must roll back' WHERE dataset = 'guests';
		END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_second_guest BEFORE INSERT ON pve_guests
		WHEN NEW.vmid = 300 BEGIN SELECT RAISE(ABORT, 'forced guest failure'); END`); err != nil {
		t.Fatal(err)
	}
	obs3 := newObsA().nodes(mkNode("p2")).guests(mkGuest(200, 1, "first-write"), mkGuest(300, 1, "failure")).build()
	rep, err := s.IngestObservation(ctx, obs3)
	if err == nil {
		t.Fatalf("expected an error for the failed guests dataset")
	}
	if rep.Errors["guests"] == nil {
		t.Fatalf("expected Errors[guests], got %+v", rep.Errors)
	}
	if rep.NodesUpserted != 1 {
		t.Fatalf("node dataset must commit despite guest failure, report: %+v", rep)
	}
	if n := countRows(t, db, "pve_guests"); n != 1 {
		t.Fatalf("guest dataset must roll back atomically, rows=%d", n)
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 1"); n != 1 {
		t.Fatalf("tombstone state must survive the rollback, rows=%d", n)
	}
	if n := countRows(t, db, "pve_nodes"); n != 2 {
		t.Fatalf("expected 2 node rows (p1, p2), got %d", n)
	}
	after, err := s.GetDatasetStatus(ctx, "remote-a", DatasetGuests)
	if err != nil || after != before {
		t.Fatalf("guest status must roll back: before=%+v after=%+v err=%v", before, after, err)
	}
	// Guest details must not be written for a rolled-back guests dataset.
	if n := countRows(t, db, "pve_guest_configs"); n != 0 {
		t.Fatalf("no guest detail rows expected after guest dataset failure, got %d", n)
	}
}

func TestPartialPollKeepsUnseenGuests(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	// Full enumeration sees both guests.
	obs1 := newObsA().guests(mkGuest(100, 1, "vm1"), mkGuest(200, 1, "vm2")).build()
	if _, err := s.IngestObservation(ctx, obs1); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}

	// Partial enumeration sees only guest 100.
	obs2 := newObsA().incomplete().guests(mkGuest(100, 1, "vm1")).build()
	rep, err := s.IngestObservation(ctx, obs2)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.GuestsTombstoned != 0 {
		t.Fatalf("partial poll must not tombstone: %+v", rep)
	}

	list, err := s.ListGuests(ctx, "remote-a", GuestFilter{}, 0)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 live guests, got %d", len(list))
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 1"); n != 0 {
		t.Fatalf("partial poll must not create tombstones, got %d", n)
	}

	st, err := s.GetDatasetStatus(ctx, "remote-a", "guests")
	if err != nil {
		t.Fatalf("GetDatasetStatus: %v", err)
	}
	if st.State != "partial" {
		t.Fatalf("guests state = %q, want partial", st.State)
	}
}

func TestCompleteEmptyEnumerationTombstonesAll(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	obs1 := newObsA().guests(mkGuest(100, 1, "vm1"), mkGuest(200, 1, "vm2")).build()
	if _, err := s.IngestObservation(ctx, obs1); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}

	obs2 := newObsA().guests().build()
	rep, err := s.IngestObservation(ctx, obs2)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.GuestsTombstoned != 2 {
		t.Fatalf("expected 2 tombstones, got %+v", rep)
	}

	if _, err := s.GetGuest(ctx, "remote-a", 100); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("GetGuest after tombstone = %v, want ErrGuestNotFound", err)
	}
	list, err := s.ListGuests(ctx, "remote-a", GuestFilter{}, 0)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected no live guests, got %d", len(list))
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 1"); n != 2 {
		t.Fatalf("expected 2 tombstone rows, got %d", n)
	}
}

func TestIncarnationResetOnVMIDReuse(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	// Generation 1: "old-vm".
	obs1 := newObsA().guests(mkGuest(100, 1, "old-vm")).build()
	if _, err := s.IngestObservation(ctx, obs1); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}

	// Generation 2: VMID reused for a different machine.
	g2 := mkGuest(100, 2, "new-vm")
	g2.Status = pvecontract.GuestStopped
	obs2 := newObsA().guests(g2).build()
	rep, err := s.IngestObservation(ctx, obs2)
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if rep.GuestsTombstoned != 1 || rep.GuestsStarted != 1 {
		t.Fatalf("expected incarnation reset (tombstone 1, start 1), got %+v", rep)
	}

	g, err := s.GetGuest(ctx, "remote-a", 100)
	if err != nil {
		t.Fatalf("GetGuest: %v", err)
	}
	if g.Generation != 2 || g.Name != "new-vm" || g.Status != string(pvecontract.GuestStopped) {
		t.Fatalf("wrong active incarnation: %+v", g)
	}
	if g.TombstonedAt != (time.Time{}) {
		t.Fatalf("active incarnation must not be tombstoned: %+v", g)
	}

	// The old incarnation is kept as a tombstone.
	list, err := s.ListGuests(ctx, "remote-a", GuestFilter{IncludeTombstoned: true}, 0)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 incarnations (1 tombstoned), got %d", len(list))
	}
	var old *Guest
	for i := range list {
		if list[i].Generation == 1 {
			old = &list[i]
		}
	}
	if old == nil {
		t.Fatalf("old incarnation missing from list: %+v", list)
	}
	if old.Name != "old-vm" || old.TombstonedAt.IsZero() {
		t.Fatalf("old incarnation not tombstoned correctly: %+v", old)
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 1 AND generation = 1"); n != 1 {
		t.Fatalf("expected 1 tombstoned generation-1 row, got %d", n)
	}
}

func TestStaleGenerationDoesNotClobberNewer(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	if _, err := s.IngestObservation(ctx, newObsA().guests(mkGuest(100, 1, "gen1")).build()); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsA().guests(mkGuest(100, 2, "gen2")).build()); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}

	// A stale collector still reports generation 1.
	rep, err := s.IngestObservation(ctx, newObsA().guests(mkGuest(100, 1, "stale")).build())
	if err != nil {
		t.Fatalf("ingest 3: %v", err)
	}
	if rep.GuestsTombstoned != 0 || rep.GuestsStarted != 0 {
		t.Fatalf("stale generation must be ignored: %+v", rep)
	}

	g, err := s.GetGuest(ctx, "remote-a", 100)
	if err != nil {
		t.Fatalf("GetGuest: %v", err)
	}
	if g.Generation != 2 || g.Name != "gen2" {
		t.Fatalf("stale observation clobbered the newer incarnation: %+v", g)
	}
}

func TestStaleDataKeptWithAge(t *testing.T) {
	s, _, now := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	if _, err := s.IngestObservation(ctx, newObsA().guests(mkGuest(100, 1, "vm1")).build()); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// Age the observation far beyond the tombstone retention window. The
	// data must still be queryable, with its age exposed.
	*now = testBase.Add(40 * 24 * time.Hour)

	g, err := s.GetGuest(ctx, "remote-a", 100)
	if err != nil {
		t.Fatalf("stale data must remain queryable: %v", err)
	}
	if g.Age != 40*24*time.Hour {
		t.Fatalf("age = %v, want 40h*24", g.Age)
	}
	if g.ObservedAt != testBase {
		t.Fatalf("observed_at = %v, want %v", g.ObservedAt, testBase)
	}
}

func TestRetentionPrunesOldTombstone(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	// Guest with a config sub-dataset row, so pruning must cascade.
	g := mkGuest(100, 1, "vm1")
	g.Config = pvecontract.AvailableDataset(pvecontract.GuestConfig{
		CPUCount: 4,
		RAMBytes: 8 << 30,
		Disks:    []pvecontract.Disk{{Storage: "local", Volume: "local:100", Format: "qcow2"}},
		BootOrder: []string{
			"scsi0",
		},
		HostPCI:     []pvecontract.HostPCI{},
		CloudInitIP: nil,
		Tags:        []string{"prod"},
		Pool:        "default",
		Capabilities: pvecontract.GuestCapabilities{
			Snapshots:     pvecontract.Yes,
			LiveMigration: pvecontract.No,
			RAMSnapshots:  pvecontract.Unknown,
		},
	})
	if _, err := s.IngestObservation(ctx, newObsA().guests(g).build()); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	if n := countRows(t, db, "pve_guest_configs"); n != 1 {
		t.Fatalf("expected 1 config row, got %d", n)
	}

	// Tombstone it 40 days later.
	*now = testBase.Add(40 * 24 * time.Hour)
	if _, err := s.IngestObservation(ctx, newObsA().guests().build()); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}

	// Prune at 71 days: the tombstone is 31 days old (> 30).
	*now = testBase.Add(71 * 24 * time.Hour)
	rep, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if rep.TombstonesRemoved != 1 {
		t.Fatalf("expected 1 tombstone removed, got %+v", rep)
	}
	if n := countRows(t, db, "pve_guests"); n != 0 {
		t.Fatalf("tombstone row must be deleted, got %d", n)
	}
	if n := countRows(t, db, "pve_guest_configs"); n != 0 {
		t.Fatalf("sub-dataset rows must be deleted with the tombstone, got %d", n)
	}
}

func TestRetentionKeepsRecentTombstone(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	if _, err := s.IngestObservation(ctx, newObsA().guests(mkGuest(100, 1, "vm1")).build()); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	*now = testBase.Add(10 * 24 * time.Hour)
	if _, err := s.IngestObservation(ctx, newObsA().guests().build()); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}

	// Prune at 20 days: the tombstone is only 10 days old.
	*now = testBase.Add(20 * 24 * time.Hour)
	rep, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if rep.TombstonesRemoved != 0 {
		t.Fatalf("recent tombstone must be kept, got %+v", rep)
	}
	if n := countRows(t, db, "pve_guests", "tombstoned = 1"); n != 1 {
		t.Fatalf("expected 1 tombstone row to remain, got %d", n)
	}
}

func TestTaskRetention(t *testing.T) {
	s, db, now := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	// At day 40 a task from the base time is 40 days old.
	*now = testBase.Add(40 * 24 * time.Hour)
	if _, err := s.IngestObservation(ctx, newObsA().tasks(
		pvecontract.TaskObservation{Node: "p1", Actor: "root", Type: "status", Target: "qemu/100", StartedUnix: testBase.Unix(), ExitStatus: "success"},
	).build()); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}

	// At day 71 a fresh task is 10 days old; the first one is 71 days old.
	*now = testBase.Add(71 * 24 * time.Hour)
	if _, err := s.IngestObservation(ctx, newObsA().tasks(
		pvecontract.TaskObservation{Node: "p1", Actor: "root", Type: "status", Target: "qemu/200", StartedUnix: testBase.Add(61 * 24 * time.Hour).Unix(), ExitStatus: "success"},
	).build()); err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if n := countRows(t, db, "pve_tasks"); n != 2 {
		t.Fatalf("expected 2 task rows, got %d", n)
	}
	rep, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if rep.TasksRemoved != 1 {
		t.Fatalf("expected 1 task removed, got %+v", rep)
	}
	if n := countRows(t, db, "pve_tasks"); n != 1 {
		t.Fatalf("expected 1 task row to remain, got %d", n)
	}
}

func TestBoundedQueries(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	guests := make([]pvecontract.GuestObservation, 0, 5)
	for i := uint64(100); i < 105; i++ {
		guests = append(guests, mkGuest(i, 1, "vm"))
	}
	if _, err := s.IngestObservation(ctx, newObsA().guests(guests...).build()); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// A limit above the named maximum is rejected, not clamped.
	if _, err := s.ListGuests(ctx, "remote-a", GuestFilter{}, MaxGuestsQuery+1); err == nil {
		t.Fatalf("limit above max must be rejected")
	}

	// limit 0 uses the default (max) and returns all 5 rows.
	out, err := s.ListGuests(ctx, "remote-a", GuestFilter{}, 0)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(out) != 5 {
		t.Fatalf("expected 5 rows, got %d", len(out))
	}

	// An explicit small limit is honoured.
	out, err = s.ListGuests(ctx, "remote-a", GuestFilter{}, 3)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(out))
	}

	// VMID filter.
	out, err = s.ListGuests(ctx, "remote-a", GuestFilter{VMID: 102}, 0)
	if err != nil {
		t.Fatalf("ListGuests: %v", err)
	}
	if len(out) != 1 || out[0].VMID != 102 {
		t.Fatalf("VMID filter broken: %+v", out)
	}
}

func TestRemoteUpsertTrustGeneration(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}
	r, err := s.GetRemote(ctx, "remote-a")
	if err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
	if r.TrustGeneration != 3 {
		t.Fatalf("trust generation = %d, want 3", r.TrustGeneration)
	}

	// A lower generation must never lower the recorded one.
	lower := remoteA()
	lower.TrustGeneration = 2
	if err := s.UpsertRemote(ctx, lower); err != nil {
		t.Fatalf("UpsertRemote (lower gen): %v", err)
	}
	r, err = s.GetRemote(ctx, "remote-a")
	if err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
	if r.TrustGeneration != 3 {
		t.Fatalf("trust generation lowered to %d, want 3", r.TrustGeneration)
	}

	// A higher generation is accepted.
	higher := remoteA()
	higher.TrustGeneration = 5
	if err := s.UpsertRemote(ctx, higher); err != nil {
		t.Fatalf("UpsertRemote (higher gen): %v", err)
	}
	r, err = s.GetRemote(ctx, "remote-a")
	if err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
	if r.TrustGeneration != 5 {
		t.Fatalf("trust generation = %d, want 5", r.TrustGeneration)
	}
}

func TestGuestDetailsRoundTrip(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	g := mkGuest(100, 1, "vm1")
	g.Config = pvecontract.AvailableDataset(pvecontract.GuestConfig{
		CPUCount:  4,
		RAMBytes:  8 << 30,
		Disks:     []pvecontract.Disk{{Storage: "local", Volume: "local:100", Format: "qcow2"}},
		BootOrder: []string{"scsi0", "ide2"},
		HostPCI:   []pvecontract.HostPCI{{ID: "hostpci0", Device: "PCI-8086:1234:11:00.1", Target: "11:00.1"}},
		CloudInitIP: &pvecontract.CloudInitIP{
			IP:      "10.0.0.5/24",
			Gateway: "10.0.0.1",
		},
		Tags: []string{"prod", "web"},
		Pool: "default",
		Capabilities: pvecontract.GuestCapabilities{
			Snapshots:     pvecontract.Yes,
			LiveMigration: pvecontract.No,
			RAMSnapshots:  pvecontract.Unknown,
		},
	})
	g.Interfaces = pvecontract.AvailableDataset([]pvecontract.GuestInterface{
		{Name: "net0", MAC: "aa:bb:cc:dd:ee:ff", Bridge: "vmbr0", VLAN: 0, IPs: []string{"10.0.0.5/24"}, Source: pvecontract.SourceQEMUAgent},
	})
	g.Snapshots = pvecontract.AvailableDataset([]pvecontract.Snapshot{
		{Name: "snap1", TimeUnix: 1700000000, Parent: "", HasRAM: true},
		{Name: "snap2", TimeUnix: 1700000100, Parent: "snap1", HasRAM: false},
	})
	g.Backups = pvecontract.AvailableDataset([]pvecontract.BackupEvidence{
		{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask, Name: "backup-100", Status: "success", StartedUnix: 1700000000, FinishedUnix: 1700000600, Verified: pvecontract.Yes},
	})
	if _, err := s.IngestObservation(ctx, newObsA().guests(g).build()); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	cfg, err := s.GetGuestConfig(ctx, "remote-a", 100, 1)
	if err != nil {
		t.Fatalf("GetGuestConfig: %v", err)
	}
	if cfg.CPUCount != 4 || cfg.RAMBytes != 8<<30 || len(cfg.Disks) != 1 || cfg.Disks[0].Volume != "local:100" {
		t.Fatalf("config round-trip mismatch: %+v", cfg)
	}
	if cfg.CapSnapshots != pvecontract.Yes || cfg.CapLiveMigration != pvecontract.No || cfg.CapRAMSnapshots != pvecontract.Unknown {
		t.Fatalf("capabilities round-trip mismatch: %v/%v/%v", cfg.CapSnapshots, cfg.CapLiveMigration, cfg.CapRAMSnapshots)
	}
	if len(cfg.BootOrder) != 2 || cfg.BootOrder[0] != "scsi0" {
		t.Fatalf("boot order round-trip mismatch: %+v", cfg.BootOrder)
	}
	if len(cfg.Tags) != 2 || cfg.Tags[1] != "web" {
		t.Fatalf("tags round-trip mismatch: %+v", cfg.Tags)
	}
	if len(cfg.HostPCI) != 1 || cfg.HostPCI[0].Device != "PCI-8086:1234:11:00.1" {
		t.Fatalf("host pci round-trip mismatch: %+v", cfg.HostPCI)
	}

	itfs, err := s.ListInterfaces(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("ListInterfaces: %v", err)
	}
	if len(itfs) != 1 || itfs[0].Name != "net0" || itfs[0].MAC != "aa:bb:cc:dd:ee:ff" || itfs[0].Bridge != "vmbr0" || len(itfs[0].IPs) != 1 {
		t.Fatalf("interface round-trip mismatch: %+v", itfs)
	}

	snaps, err := s.ListSnapshots(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 2 || snaps[0].Name != "snap1" || !snaps[0].HasRAM || snaps[1].Parent != "snap1" {
		t.Fatalf("snapshot round-trip mismatch: %+v", snaps)
	}

	bks, err := s.ListBackups(ctx, "remote-a", 100, 1, 0)
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(bks) != 1 || bks[0].Name != "backup-100" || bks[0].Verified != pvecontract.Yes || bks[0].Status != "success" || bks[0].Kind != pvecontract.BackupKindTask {
		t.Fatalf("backup round-trip mismatch: %+v", bks)
	}
}

func TestClusterRoundTrip(t *testing.T) {
	s, _, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	cluster := pvecontract.ClusterObservation{
		Quorum: "quorate",
		Nodes: []pvecontract.ClusterNode{
			{Node: "p1", Status: pvecontract.NodeOnline, Vote: true},
			{Node: "p2", Status: pvecontract.NodeOffline, Vote: false},
		},
		HAResources: []pvecontract.HAResource{
			{ID: "100", Kind: pvecontract.GuestQEMU, VMID: 100, Desired: "started", Observed: "started", Node: "p1"},
		},
	}
	if _, err := s.IngestObservation(ctx, newObsA().cluster(cluster).build()); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	got, err := s.GetCluster(ctx, "remote-a")
	if err != nil {
		t.Fatalf("GetCluster: %v", err)
	}
	if got.Quorum != "quorate" || len(got.Nodes) != 2 || len(got.HAResources) != 1 {
		t.Fatalf("cluster round-trip mismatch: %+v", got)
	}
	if got.Nodes[0].Node != "p1" || !got.Nodes[0].Vote || got.Nodes[1].Status != pvecontract.NodeOffline {
		t.Fatalf("cluster nodes round-trip mismatch: %+v", got.Nodes)
	}
	if got.HAResources[0].VMID != 100 || got.HAResources[0].Desired != "started" {
		t.Fatalf("HA resource round-trip mismatch: %+v", got.HAResources)
	}

	st, err := s.GetDatasetStatus(ctx, "remote-a", "cluster")
	if err != nil {
		t.Fatalf("GetDatasetStatus: %v", err)
	}
	if st.State != "available" {
		t.Fatalf("cluster state = %q, want available", st.State)
	}
}

func TestUnavailableDatasetStored(t *testing.T) {
	s, db, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertRemote(ctx, remoteA()); err != nil {
		t.Fatalf("UpsertRemote: %v", err)
	}

	// All datasets unavailable except remote metadata.
	obs := pvecontract.Observation{
		RemoteID:             "remote-a",
		ObservedAt:           testBase,
		Source:               "test-collector",
		CollectionGeneration: 1,
		Complete:             true,
		Nodes:                pvecontract.UnavailableDataset[[]pvecontract.NodeObservation]("endpoint error"),
		Guests:               pvecontract.UnavailableDataset[[]pvecontract.GuestObservation]("endpoint error"),
		Storages:             pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("endpoint error"),
		Cluster:              pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("endpoint error"),
		Tasks:                pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("endpoint error"),
	}
	if _, err := s.IngestObservation(ctx, obs); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	for _, ds := range []string{"nodes", "guests", "storages", "cluster", "tasks"} {
		st, err := s.GetDatasetStatus(ctx, "remote-a", ds)
		if err != nil {
			t.Fatalf("GetDatasetStatus %s: %v", ds, err)
		}
		if st.State != "unavailable" || st.Reason != "endpoint error" {
			t.Fatalf("dataset %s = %+v, want unavailable with reason", ds, st)
		}
	}
	if n := countRows(t, db, "pve_nodes"); n != 0 {
		t.Fatalf("no node rows expected, got %d", n)
	}
	if n := countRows(t, db, "pve_guests"); n != 0 {
		t.Fatalf("no guest rows expected, got %d", n)
	}
}
