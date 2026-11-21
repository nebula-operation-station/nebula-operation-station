// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// inventoryFactsAction is the action whose latest result gives a host's
// release (os-release values, ADR 0011 D3).
const inventoryFactsAction = "core.facts"

// factsSource is the part of executions.Service the inventory reads from.
type factsSource interface {
	LastResult(ctx context.Context, actionID, host string) ([]byte, time.Time, bool, error)
}

// vulnInventoryService stores each successful package.list_installed result
// as a vulninventory read (ADR 0011 D3). It implements
// executions.InstalledObserver. It never fails a run: errors are logged by
// class only, never with package names or result text.
type vulnInventoryService struct {
	store *vulninventory.Store
	facts factsSource
	log   *slog.Logger
	// closer closes findings by a complete read (D5 paths 1 and 2). It is
	// set once the findings store exists (setCloser); until then a complete
	// read closes nothing, and the next complete read does.
	closer atomic.Pointer[vulnstore.Store]
}

// setCloser sets the findings store that complete reads close findings in.
func (v *vulnInventoryService) setCloser(st *vulnstore.Store) {
	v.closer.Store(st)
}

// newVulnInventoryService returns the service on db (server.db) that reads
// the release of each host from facts.
func newVulnInventoryService(db *sql.DB, facts factsSource, log *slog.Logger) (*vulnInventoryService, error) {
	st, err := vulninventory.New(db)
	if err != nil {
		return nil, fmt.Errorf("vulnerability inventory store: %w", err)
	}
	return &vulnInventoryService{store: st, facts: facts, log: log}, nil
}

// observeTimeout bounds the database work of one ObserveInstalled call (the
// release lookup and the store write). The parse is bounded by the input
// limits of osdebian.
const observeTimeout = 30 * time.Second

// markTimeout bounds the write of a partial marker. The marker is written
// on a context that is not cancelled by the observe deadline, so that a
// lookup or write that timed out can still leave a marker behind.
const markTimeout = 5 * time.Second

// ObserveInstalled parses result (untrusted host output) with
// osdebian.ParseInstalledResult and stores the read of host from execution
// execID at time at. The distribution comes only from the host's newest
// successful core.facts result, and only when that result is at least as
// recent as the list (finished at or after at); otherwise the read is stored
// partial with vulninventory.ReasonFactsOlder. Without a facts result the
// read is stored incomplete.
//
// Fail closed: when the release lookup fails, the facts are older than the
// list, or the store fails to write the read, a partial marker is stored
// instead. The host's older complete read then stops being its latest
// inventory. A refusal of the store (a field over its limit caused by host
// content) gives ReasonRefused; any other store failure gives
// ReasonStoreUnavailable. If the marker cannot be stored either, the failure
// is only logged.
//
// On shutdown (parent is cancelled) nothing is written, because the server
// is stopping and a cancelled write is not a refusal of the list.
func (v *vulnInventoryService) ObserveInstalled(parent context.Context, hostID, execID string, at time.Time, result []byte) {
	ctx, cancel := context.WithTimeout(parent, observeTimeout)
	defer cancel()
	facts, factsAt, ok, err := v.facts.LastResult(ctx, inventoryFactsAction, hostID)
	if err != nil {
		if v.shutdown(parent, hostID, execID) {
			return
		}
		v.log.Error("vulnerability inventory: release lookup", "host", hostID, "execution", execID, "error_class", "lookup")
		v.markFailed(parent, hostID, execID, at, vulninventory.ReasonLookupFailed)
		return
	}
	var eco string
	var distro vulnver.Distro
	if ok {
		if factsAt.Unix() < at.Unix() {
			v.markFailed(parent, hostID, execID, at, vulninventory.ReasonFactsOlder)
			return
		}
		if id, ver, code, readable := executions.OSRelease(facts); readable {
			eco, distro = vulninventory.Ecosystem(id, ver, code)
		}
	}
	inv := osdebian.ParseInstalledResult(result, osdebian.ReadStatus{ExitCode: 0}, distro)
	read := vulninventory.FromInstalled(hostID, execID, at, eco, inv)
	if _, err := v.store.Put(ctx, read); err != nil {
		if v.shutdown(parent, hostID, execID) {
			return
		}
		class := inventoryErrorClass(err)
		reason := vulninventory.ReasonStoreUnavailable
		if class == "limit" || class == "invalid_read" {
			reason = vulninventory.ReasonRefused
		}
		v.log.Error("vulnerability inventory: store read", "host", hostID, "execution", execID, "error_class", class)
		v.markFailed(parent, hostID, execID, at, reason)
		return
	}
	if read.Complete {
		v.closeByInventory(ctx, parent, hostID, execID, read)
	}
	binaries := 0
	for _, c := range read.Components {
		binaries += len(c.Binaries)
	}
	v.log.Info("audit", "kind", "vuln_inventory_read_stored", "host", hostID, "execution", execID,
		"complete", read.Complete, "binaries", binaries, "sources", len(read.Components))
}

// closeByInventory closes the open findings of host that the complete read
// settles (D5 paths 1 and 2) and writes the count as an audit line. A failure
// is logged by class and does not fail the run; the findings stay open.
func (v *vulnInventoryService) closeByInventory(ctx context.Context, parent context.Context, hostID, execID string, read vulninventory.Read) {
	st := v.closer.Load()
	if st == nil {
		return
	}
	if read.Ecosystem == "" {
		// A host read names its ecosystem (the release is mapped); without one
		// NOS cannot tell which findings it covers, so it closes nothing.
		v.log.Error("vulnerability inventory: close by inventory", "host", hostID, "execution", execID, "error_class", "ecosystem")
		return
	}
	versions := make(map[string]string, len(read.Components))
	for _, c := range read.Components {
		versions[c.Source] = c.SourceVersion
	}
	closed, err := st.CloseByInventory(ctx, vulnstore.InventoryRead{
		Subject:  vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: hostID},
		Complete: read.Complete,
		// The list was taken no earlier than the read's listing lag before
		// it finished (vulnListLag); a finding written after that may not be
		// in the list, so it stays open.
		ReadAt:         read.ReadAt.Add(-vulnListLag),
		Ecosystem:      read.Ecosystem,
		SourceVersions: versions,
	})
	if err != nil {
		if v.shutdown(parent, hostID, execID) {
			return
		}
		v.log.Error("vulnerability inventory: close by inventory", "host", hostID, "execution", execID, "error_class", "close")
		return
	}
	v.log.Info("audit", "kind", "vuln_closed_by_inventory", "host", hostID, "execution", execID, "closed", len(closed))
}

// shutdown reports whether parent is cancelled (the server is stopping). If
// so it logs the skip by class and the caller writes nothing.
func (v *vulnInventoryService) shutdown(parent context.Context, hostID, execID string) bool {
	if parent.Err() == nil {
		return false
	}
	v.log.Info("vulnerability inventory: skipped on shutdown", "host", hostID, "execution", execID, "error_class", "canceled")
	return true
}

// markFailed stores the partial marker of a list that could not be read or
// stored, so that the host's previous read is no longer its latest one. The
// marker is written on a fresh context bounded by markTimeout. A failure to
// store the marker is logged by class and does not fail the run.
func (v *vulnInventoryService) markFailed(parent context.Context, hostID, execID string, at time.Time, reason string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), markTimeout)
	defer cancel()
	if _, err := v.store.Put(ctx, vulninventory.Failed(hostID, execID, at, reason)); err != nil {
		v.log.Error("vulnerability inventory: store failure marker", "host", hostID, "execution", execID, "error_class", inventoryErrorClass(err))
		return
	}
	v.log.Info("audit", "kind", "vuln_inventory_read_failed", "host", hostID, "execution", execID, "reason", reason)
}

// vulnHostLister lists the inventory hosts; inventory.Store is one.
type vulnHostLister interface {
	List(ctx context.Context) ([]inventory.Host, error)
}

// vulnSnapshotIDMaxBytes is the longest snapshot ID the store can hold
// (the vuln_inventory_snapshots.id column). A longer ID is Gone.
const vulnSnapshotIDMaxBytes = 64

// vulnInventory serves the D3 inventory export from the stored package
// inventory: each snapshot pins the newest read of every host, read through
// vulninventory.Store. It never triggers a read; it only reuses the reads
// that the executions stored. A snapshot is immutable for its ID, its
// generation rises above the hour value of the old snapshot IDs and above
// every generation a run has seen, and it is Gone once it is older than
// vulnstore.MaxInventoryAge.
type vulnInventory struct {
	reads inventoryReads
	db    *sql.DB
	hosts vulnHostLister
	now   func() time.Time
	cache *snapshotCache
}

// inventoryReads is the part of vulninventory.Store the export uses.
// Snapshot is the only call that decodes the pinned read bodies, so tests
// count its calls.
type inventoryReads interface {
	Current(ctx context.Context, hosts []string, maxReuse time.Duration, floor int64) (vulninventory.Snapshot, error)
	Snapshot(ctx context.Context, id string) (vulninventory.Snapshot, error)
}

// snapshotCache holds the decoded snapshot that was served last. A snapshot
// is immutable for its ID, so the decoded copy is valid for that ID for as
// long as the snapshot is fresh (see vulnInventory.fresh). One entry is
// enough: Hermes pages one snapshot at a time, and a run start names the
// snapshot of its export.
type snapshotCache struct {
	mu   sync.Mutex
	snap api.VulnSnapshot
	set  bool
}

// get returns the cached snapshot when it has ID.
func (c *snapshotCache) get(id string) (api.VulnSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.set && c.snap.ID == id {
		return c.snap, true
	}
	return api.VulnSnapshot{}, false
}

// put replaces the cached snapshot with s.
func (c *snapshotCache) put(s api.VulnSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snap, c.set = s, true
}

// newVulnInventory returns the export's inventory on db (server.db), with the
// hosts from hosts and the clock now (nil means time.Now).
func newVulnInventory(db *sql.DB, hosts vulnHostLister, now func() time.Time) (vulnInventory, error) {
	if hosts == nil {
		return vulnInventory{}, errors.New("vulnerability inventory: no host list")
	}
	if now == nil {
		now = time.Now
	}
	st, err := vulninventory.New(db)
	if err != nil {
		return vulnInventory{}, fmt.Errorf("vulnerability inventory: %w", err)
	}
	return newVulnInventoryOn(st, db, hosts, now), nil
}

// newVulnInventoryOn returns the export's inventory over reads, which is the
// store on db in production. now must not be nil.
func newVulnInventoryOn(reads inventoryReads, db *sql.DB, hosts vulnHostLister, now func() time.Time) vulnInventory {
	return vulnInventory{reads: reads, db: db, hosts: hosts, now: now, cache: &snapshotCache{}}
}

// fresh reports whether a snapshot taken at takenAt may still be served: it
// is at most vulnstore.MaxInventoryAge old. A TakenAt after the clock (the
// wall clock stepped back) is not fresh, as the store's reuse rule counts a
// negative age as expired.
func (v vulnInventory) fresh(takenAt time.Time) bool {
	age := v.now().UTC().Sub(takenAt)
	return age >= 0 && age <= vulnstore.MaxInventoryAge
}

// VulnSnapshot returns the current snapshot when id is empty: the newest read
// of every host in the inventory, as a new or reused snapshot. Otherwise it
// returns the snapshot with that ID. A host list that cannot be read is an
// error, never an empty snapshot.
func (v vulnInventory) VulnSnapshot(ctx context.Context, id string) (api.VulnSnapshot, error) {
	if id != "" {
		return v.byID(ctx, id)
	}
	hosts, err := v.hosts.List(ctx)
	if err != nil {
		return api.VulnSnapshot{}, fmt.Errorf("vuln inventory: list hosts: %w", err)
	}
	ids := make([]string, 0, len(hosts))
	for _, h := range hosts {
		ids = append(ids, h.ID)
	}
	cur, err := v.current(ctx, ids)
	if err != nil {
		return api.VulnSnapshot{}, err
	}
	// Current leaves the bodies out. The snapshot is immutable for its ID,
	// so a decoded copy of the same ID is the same snapshot: decode only
	// when it is not cached.
	if s, ok := v.cache.get(cur.ID); ok {
		return s, nil
	}
	return v.load(ctx, cur.ID)
}

// maxCurrentAttempts bounds the Current calls of one export. A run start that
// records a generation after the floor was read makes the snapshot just
// returned unusable for a run, and the next call builds a higher one.
const maxCurrentAttempts = 3

// current returns the current snapshot of ids with a generation above every
// run floor the export can see. The floor is read before and after Current:
// when a run start recorded the returned generation in between (Current may
// have reused that snapshot), the snapshot is not handed out, because the
// next run start with it would be refused with 409. The two reads are not in
// one transaction with Current (that needs a change in vulninventory), so a
// run that records a generation after the second read is still possible; it
// is seen by the next export call.
func (v vulnInventory) current(ctx context.Context, ids []string) (vulninventory.Snapshot, error) {
	// Generations of the old hourly IDs (time in hours) stay below the new ones.
	hour := v.now().UTC().Truncate(vulnInventoryBucket).Unix() / int64(vulnInventoryBucket/time.Second)
	for range maxCurrentAttempts {
		floor, err := maxInventoryGeneration(ctx, v.db)
		if err != nil {
			return vulninventory.Snapshot{}, err
		}
		cur, err := v.reads.Current(ctx, ids, vulnInventoryBucket, max(floor, hour))
		if err != nil {
			return vulninventory.Snapshot{}, fmt.Errorf("vuln inventory: current: %w", err)
		}
		recorded, err := maxInventoryGeneration(ctx, v.db)
		if err != nil {
			return vulninventory.Snapshot{}, err
		}
		if recorded < cur.Generation {
			return cur, nil
		}
	}
	return vulninventory.Snapshot{}, fmt.Errorf("vuln inventory: current: run starts recorded the snapshot generation on %d attempts", maxCurrentAttempts)
}

// byID returns the snapshot with id, or api.ErrVulnSnapshotGone when the
// store does not hold it (unknown, pruned, an ID of the old form, or an ID
// the store cannot hold) or when it is not fresh (see fresh).
func (v vulnInventory) byID(ctx context.Context, id string) (api.VulnSnapshot, error) {
	if len(id) > vulnSnapshotIDMaxBytes {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	if s, ok := v.cache.get(id); ok {
		if !v.fresh(s.TakenAt) {
			return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
		}
		return s, nil
	}
	return v.load(ctx, id)
}

// load decodes the snapshot with id from the store, caches it and returns it.
// The store's refusals of an unknown or unusable ID are Gone; a snapshot that
// is not fresh is Gone too and is not cached.
func (v vulnInventory) load(ctx context.Context, id string) (api.VulnSnapshot, error) {
	s, err := v.reads.Snapshot(ctx, id)
	if errors.Is(err, vulninventory.ErrSnapshotGone) || errors.Is(err, vulninventory.ErrInvalidRead) {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	if err != nil {
		return api.VulnSnapshot{}, fmt.Errorf("vuln inventory: snapshot %s: %w", id, err)
	}
	out := toVulnSnapshot(s)
	if !v.fresh(out.TakenAt) {
		return api.VulnSnapshot{}, api.ErrVulnSnapshotGone
	}
	v.cache.put(out)
	return out, nil
}

// toVulnSnapshot maps a stored snapshot to the export's snapshot type.
func toVulnSnapshot(s vulninventory.Snapshot) api.VulnSnapshot {
	out := api.VulnSnapshot{ID: s.ID, Generation: s.Generation, TakenAt: s.TakenAt,
		Subjects: make([]api.VulnSubject, 0, len(s.Reads))}
	for _, r := range s.Reads {
		out.Subjects = append(out.Subjects, hostSubject(r))
	}
	return out
}

// hostSubject maps the read of one host to an export subject. Only what the
// api types hold is copied: the host ID as the subject reference, the
// ecosystem, the completeness, the kernel (its source only when it is mapped)
// and the components with their binaries. Nothing else of the read is
// exported, and no host name or address.
func hostSubject(r vulninventory.Read) api.VulnSubject {
	sub := api.VulnSubject{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: r.HostID},
		Ecosystem: r.Ecosystem, Complete: r.Complete}
	if r.Kernel.Release != "" {
		k := &api.VulnKernel{Release: r.Kernel.Release}
		if r.Kernel.State == string(osdebian.KernelMapped) {
			k.Source, k.SourceVersion = r.Kernel.Source, r.Kernel.Version
		}
		sub.Kernel = k
	}
	for _, c := range r.Components {
		vc := api.VulnComponent{Source: c.Source, SourceVersion: c.SourceVersion,
			Binaries: make([]api.VulnBinary, 0, len(c.Binaries))}
		for _, b := range c.Binaries {
			vc.Binaries = append(vc.Binaries, api.VulnBinary{Name: b.Name, Version: b.Version, Arch: b.Arch})
		}
		sub.Components = append(sub.Components, vc)
	}
	return sub
}

// maxInventoryGeneration is the highest inventory generation a run has
// started with (vuln_store_state.max_inventory_generation); 0 before the
// first run. The export's generations must stay above it (ADR 0011 D5).
func maxInventoryGeneration(ctx context.Context, db *sql.DB) (int64, error) {
	var g int64
	err := db.QueryRowContext(ctx, `SELECT max_inventory_generation FROM vuln_store_state WHERE id = 1`).Scan(&g)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("vulnerability store state: %w", err)
	}
	return g, nil
}

// sweepSnapshots prunes the inventory snapshots older than
// vulnstore.MaxInventoryAge. The newest snapshot is always kept.
func (v *vulnService) sweepSnapshots(ctx context.Context) error {
	if err := v.inventory.PruneSnapshots(ctx, vulnstore.MaxInventoryAge); err != nil {
		return fmt.Errorf("vulnerability inventory: prune snapshots: %w", err)
	}
	return nil
}

// inventoryErrorClass names the class of an error without its text: a store
// refusal (limit or format), a context end (canceled or timeout), or any
// other store failure ("store", for example a busy or closed database).
func inventoryErrorClass(err error) string {
	switch {
	case errors.Is(err, vulninventory.ErrLimit):
		return "limit"
	case errors.Is(err, vulninventory.ErrInvalidRead):
		return "invalid_read"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "store"
	}
}
