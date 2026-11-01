// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveinventory persists normalized Proxmox VE observations
// (internal/pvecontract) in the server database (ADR 0006, ticket P1-11).
//
// These tables are presentation copies only: the executor owns
// authoritative remote identity, guest generations and links. Identity
// rules:
//
//   - every remote child is keyed with its remote_id;
//   - nodes by (remote_id, node);
//   - guests by (remote_id, vmid, generation) -- never vmid alone. A VMID
//     reused after deletion is a new generation (incarnation); the old one
//     is tombstoned, not deleted.
//
// Every dataset carries source, observed_at and a state
// (available | unavailable | partial). Stale data is kept with its age and
// is only removed by explicit retention: tombstoned incarnations and task
// metadata are pruned after TombstoneRetention (30 days). A partial
// enumeration never tombstones unseen guests; only a complete one can.
//
// No credential material, raw API responses, task logs or command output
// are stored here.
package pveinventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// DatasetState is the availability state of one stored dataset.
type DatasetState string

// Dataset states.
const (
	// StateAvailable means the dataset was read; the value may be empty,
	// which is a complete enumeration that found nothing.
	StateAvailable DatasetState = "available"
	// StateUnavailable means the dataset could not be read; Reason is set.
	StateUnavailable DatasetState = "unavailable"
	// StatePartial means the enumeration was incomplete; unseen objects
	// must not be treated as deleted.
	StatePartial DatasetState = "partial"
)

// Top-level dataset names of one observation.
const (
	DatasetNodes    = "nodes"
	DatasetGuests   = "guests"
	DatasetStorages = "storages"
	DatasetCluster  = "cluster"
	DatasetTasks    = "tasks"
)

// Per-guest sub-dataset names.
const (
	DatasetConfig     = "config"
	DatasetInterfaces = "interfaces"
	DatasetSnapshots  = "snapshots"
	DatasetBackups    = "backups"
)

// Retention bounds (named constants).
const (
	// TombstoneRetention is how long tombstoned guest incarnations are kept
	// before explicit pruning.
	TombstoneRetention = 30 * 24 * time.Hour
	// TaskRetention is how long task metadata is kept before explicit
	// pruning.
	TaskRetention = 30 * 24 * time.Hour
)

// Bounded query limits (named constants). Every list query clamps its
// result to one of these.
const (
	// MaxGuestsQuery bounds ListGuests.
	MaxGuestsQuery = 1000
	// MaxNodesQuery bounds ListNodes.
	MaxNodesQuery = 1000
	// MaxStoragesQuery bounds ListStorages (per-node reports; vorher 64
	// distinct storages).
	MaxStoragesQuery = pvecontract.MaxStorageReportsPerRemote
	// MaxTasksQuery bounds ListTasks.
	MaxTasksQuery = 1000
	// MaxSnapshotsQuery bounds ListSnapshots.
	MaxSnapshotsQuery = 256
	// MaxBackupsQuery bounds ListBackups.
	MaxBackupsQuery = 64
	// MaxInterfacesQuery bounds ListInterfaces.
	MaxInterfacesQuery = 128
	// MaxRemotesQuery bounds ListRemotes.
	MaxRemotesQuery = 1000
)

// Sentinel errors callers branch on.
var (
	// ErrStaleObservation is returned when a collection predates the stored observation.
	ErrStaleObservation = errors.New("pveinventory: stale observation")
	// ErrRemoteNotFound is returned for an unknown remote_id.
	ErrRemoteNotFound = errors.New("pveinventory: remote not found")
	// ErrNodeNotFound is returned for an unknown (remote_id, node).
	ErrNodeNotFound = errors.New("pveinventory: node not found")
	// ErrGuestNotFound is returned for an unknown (remote_id, vmid).
	ErrGuestNotFound = errors.New("pveinventory: guest not found")
	// ErrClusterNotFound is returned when no cluster status is stored.
	ErrClusterNotFound = errors.New("pveinventory: cluster status not found")
	// ErrDatasetNotFound is returned for an unknown dataset status row.
	ErrDatasetNotFound = errors.New("pveinventory: dataset status not found")
)

// Store persists PVE inventory in the server database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a Store for db using time.Now for timestamps and ages.
func New(db *sql.DB) *Store { return NewWithNow(db, time.Now) }

// NewWithNow returns a Store for db that uses now for timestamps and ages.
// A nil now means time.Now.
func NewWithNow(db *sql.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}
}

// Open opens (and migrates) the server database at path and returns a Store
// over it using time.Now. The caller closes the returned database.
func Open(path string) (*Store, *sql.DB, error) {
	db, err := serverdb.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return New(db), db, nil
}

// Remote is the stored presentation copy of one PVE remote.
type Remote struct {
	RemoteID                 string
	Name                     string
	Kind                     string
	TrustGeneration          uint64
	FirstObservedAt          time.Time
	LastObservedAt           time.Time
	LastSource               string
	LastCollectionGeneration uint64
}

// Node is one stored PVE node.
type Node struct {
	RemoteID      string
	Node          string
	Status        string
	UptimeSeconds uint64
	CPUCount      uint32
	RAMTotalBytes uint64
	RAMUsedBytes  uint64
	PVEVersion    string
	KernelVersion string
	// DetailsObservedAt timestamps the retained version values, even when unavailable.
	DetailsObservedAt time.Time
	// DetailsCheckedAt timestamps the most recent detail availability observation.
	DetailsCheckedAt time.Time
	// DetailsSource identifies the collector of the most recent detail check.
	DetailsSource string
	// DetailsReason explains why the most recent detail check was unavailable.
	DetailsReason        string
	DetailsAvailable     bool
	ObservedAt           time.Time
	Source               string
	State                DatasetState
	Reason               string
	CollectionGeneration uint64
	// Age is now - ObservedAt, computed at query time.
	Age time.Duration
}

// Guest is one stored guest incarnation.
type Guest struct {
	RemoteID             string
	VMID                 uint64
	Generation           uint64
	Kind                 string
	Node                 string
	Name                 string
	Status               string
	UUID                 string
	ObservedAt           time.Time
	Source               string
	State                DatasetState
	Reason               string
	CollectionGeneration uint64
	Tombstoned           bool
	TombstonedAt         time.Time
	// Age is now - ObservedAt, computed at query time.
	Age time.Duration
}

// GuestConfig is one stored guest configuration summary.
type GuestConfig struct {
	RemoteID             string
	VMID                 uint64
	Generation           uint64
	CPUCount             uint32
	RAMBytes             uint64
	Disks                []pvecontract.Disk
	BootOrder            []string
	HostPCI              []pvecontract.HostPCI
	CloudInitIP          *pvecontract.CloudInitIP
	Tags                 []string
	Pool                 string
	CapSnapshots         pvecontract.TriState
	CapLiveMigration     pvecontract.TriState
	CapRAMSnapshots      pvecontract.TriState
	ObservedAt           time.Time
	Source               string
	State                DatasetState
	Reason               string
	CollectionGeneration uint64
}

// GuestInterface is one stored guest interface.
type GuestInterface struct {
	RemoteID             string
	VMID                 uint64
	Generation           uint64
	Name                 string
	MAC                  string
	Bridge               string
	VLAN                 uint16
	IPs                  []string
	Source               string
	ObservedAt           time.Time
	CollectionGeneration uint64
}

// Snapshot is one stored guest snapshot.
type Snapshot struct {
	RemoteID             string
	VMID                 uint64
	Generation           uint64
	Name                 string
	TimeUnix             int64
	Parent               string
	HasRAM               bool
	ObservedAt           time.Time
	Source               string
	State                DatasetState
	Reason               string
	CollectionGeneration uint64
}

// BackupObservation is one stored backup evidence record.
type BackupObservation struct {
	RemoteID             string
	VMID                 uint64
	Generation           uint64
	Source               string
	Kind                 string
	Name                 string
	Status               string
	StartedUnix          int64
	FinishedUnix         int64
	Verified             pvecontract.TriState
	ObservedAt           time.Time
	CollectionGeneration uint64
}

// Storage is one stored PVE storage as reported by one node.
type Storage struct {
	RemoteID string
	// Node is the node that reported the storage and its usage; empty
	// for reports from sources without per-node storage.
	Node    string
	Name    string
	Type    string
	Format  string
	Content []string
	Active  bool
	// Shared is PVE's authoritative shared flag (counted once per remote).
	Shared               bool
	SizeBytes            uint64
	FreeBytes            uint64
	ObservedAt           time.Time
	Source               string
	State                DatasetState
	Reason               string
	CollectionGeneration uint64
}

// Cluster is one stored cluster and HA summary.
type Cluster struct {
	RemoteID             string
	Quorum               string
	Nodes                []pvecontract.ClusterNode
	HAResources          []pvecontract.HAResource
	ObservedAt           time.Time
	Source               string
	State                DatasetState
	Reason               string
	CollectionGeneration uint64
}

// Task is one stored task metadata record.
type Task struct {
	RemoteID             string
	Node                 string
	Actor                string
	Type                 string
	Target               string
	StartedUnix          int64
	ExitStatus           string
	ObservedAt           time.Time
	Source               string
	CollectionGeneration uint64
}

// DatasetStatus is the current state of one top-level dataset for a remote.
type DatasetStatus struct {
	RemoteID             string
	Dataset              string
	State                DatasetState
	ObservedAt           time.Time
	Source               string
	Reason               string
	CollectionGeneration uint64
}

// GuestDatasetStatus is the current state of one per-guest sub-dataset for
// one incarnation.
type GuestDatasetStatus struct {
	RemoteID             string
	VMID                 uint64
	Generation           uint64
	Dataset              string
	State                DatasetState
	ObservedAt           time.Time
	Source               string
	Reason               string
	CollectionGeneration uint64
}

// PruneReport summarizes what Prune removed.
type PruneReport struct {
	// TombstonesRemoved is the number of tombstoned guest incarnations
	// (and their sub-dataset rows) removed.
	TombstonesRemoved int
	// TasksRemoved is the number of task metadata rows removed.
	TasksRemoved int
}

// formatTime renders a time as RFC 3339 UTC for storage.
func (s *Store) formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// age returns now - t, floored at zero.
func (s *Store) age(t time.Time) time.Duration {
	d := s.now().Sub(t)
	if d < 0 {
		return 0
	}
	return d
}

// checkLimit resolves a query limit: a non-positive limit uses max, and a
// limit above max is an error (bounds are explicit, not silently clamped).
func checkLimit(limit, max int) (int, error) {
	if limit <= 0 {
		return max, nil
	}
	if limit > max {
		return 0, fmt.Errorf("pveinventory: limit %d exceeds max %d", limit, max)
	}
	return limit, nil
}

// --- Remotes ---

// UpsertRemote stores the executor-owned identity of a remote as a
// presentation copy. It is idempotent and never lowers an already recorded
// trust generation.
func (s *Store) UpsertRemote(ctx context.Context, r pvecontract.Remote) error {
	v, err := pvecontract.ValidateRemote(r)
	if err != nil {
		return fmt.Errorf("pveinventory: upsert remote: %w", err)
	}
	now := s.now()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO pve_remotes (remote_id, name, kind, trust_generation,
		                          first_observed_at, last_observed_at,
		                          last_source, last_collection_generation)
		VALUES (?, ?, ?, ?, ?, ?, '', 0)
		ON CONFLICT (remote_id) DO UPDATE SET
			name             = excluded.name,
			kind             = excluded.kind,
			trust_generation = MAX(pve_remotes.trust_generation, excluded.trust_generation),
			last_observed_at = excluded.last_observed_at`,
		v.RemoteID, v.Name, string(v.Kind), v.TrustGeneration,
		s.formatTime(now), s.formatTime(now)); err != nil {
		return fmt.Errorf("pveinventory: upsert remote %s: %w", v.RemoteID, err)
	}
	return nil
}

// GetRemote returns the stored remote with remoteID.
func (s *Store) GetRemote(ctx context.Context, remoteID string) (Remote, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, name, kind, trust_generation,
		       first_observed_at, last_observed_at, last_source,
		       last_collection_generation
		FROM pve_remotes WHERE remote_id = ?`, remoteID)
	var r Remote
	var first, last string
	if err := row.Scan(&r.RemoteID, &r.Name, &r.Kind, &r.TrustGeneration,
		&first, &last, &r.LastSource, &r.LastCollectionGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Remote{}, fmt.Errorf("pveinventory: get remote %s: %w", remoteID, ErrRemoteNotFound)
		}
		return Remote{}, fmt.Errorf("pveinventory: get remote %s: %w", remoteID, err)
	}
	r.FirstObservedAt, _ = time.Parse(time.RFC3339, first)
	r.LastObservedAt, _ = time.Parse(time.RFC3339, last)
	return r, nil
}

// ListRemotes returns up to limit remotes, ordered by remote_id. A
// non-positive limit uses MaxRemotesQuery.
func (s *Store) ListRemotes(ctx context.Context, limit int) ([]Remote, error) {
	limit, err := checkLimit(limit, MaxRemotesQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, name, kind, trust_generation,
		       first_observed_at, last_observed_at, last_source,
		       last_collection_generation
		FROM pve_remotes ORDER BY remote_id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list remotes: %w", err)
	}
	defer rows.Close()
	var out []Remote
	for rows.Next() {
		var r Remote
		var first, last string
		if err := rows.Scan(&r.RemoteID, &r.Name, &r.Kind, &r.TrustGeneration,
			&first, &last, &r.LastSource, &r.LastCollectionGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: list remotes: %w", err)
		}
		r.FirstObservedAt, _ = time.Parse(time.RFC3339, first)
		r.LastObservedAt, _ = time.Parse(time.RFC3339, last)
		out = append(out, r)
	}
	return out, rows.Err()
}

// touchRemote records that a remote was observed (bookkeeping only; it does
// not change the executor-owned identity fields).
func (s *Store) touchRemote(ctx context.Context, tx *sql.Tx, remoteID string, observedAt time.Time, source string, gen uint64) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pve_remotes (remote_id, first_observed_at, last_observed_at,
		                          last_source, last_collection_generation)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (remote_id) DO UPDATE SET
			last_observed_at             = excluded.last_observed_at,
			last_source                  = excluded.last_source,
			last_collection_generation   = MAX(pve_remotes.last_collection_generation, excluded.last_collection_generation)`,
		remoteID, observedAt.UTC().Format(time.RFC3339Nano), observedAt.UTC().Format(time.RFC3339Nano), source, gen); err != nil {
		return fmt.Errorf("pveinventory: touch remote %s: %w", remoteID, err)
	}
	return nil
}

// --- Nodes ---

// GetNode returns the stored node (remoteID, node).
func (s *Store) GetNode(ctx context.Context, remoteID, node string) (Node, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, node, status, uptime_seconds, cpu_count,
		       ram_total_bytes, ram_used_bytes, pve_version, kernel_version,
		       details_available, observed_at, source, state, reason,
		       collection_generation, details_observed_at, details_checked_at, details_source, details_reason
		FROM pve_nodes WHERE remote_id = ? AND node = ?`, remoteID, node)
	var n Node
	var details int
	var observed, state, detailsObserved, detailsChecked string
	if err := row.Scan(&n.RemoteID, &n.Node, &n.Status, &n.UptimeSeconds,
		&n.CPUCount, &n.RAMTotalBytes, &n.RAMUsedBytes, &n.PVEVersion,
		&n.KernelVersion, &details, &observed, &n.Source, &state, &n.Reason,
		&n.CollectionGeneration, &detailsObserved, &detailsChecked, &n.DetailsSource, &n.DetailsReason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Node{}, fmt.Errorf("pveinventory: get node %s/%s: %w", remoteID, node, ErrNodeNotFound)
		}
		return Node{}, fmt.Errorf("pveinventory: get node %s/%s: %w", remoteID, node, err)
	}
	n.DetailsObservedAt, _ = time.Parse(time.RFC3339, detailsObserved)
	n.DetailsCheckedAt, _ = time.Parse(time.RFC3339, detailsChecked)
	n.DetailsAvailable = details != 0
	n.State = DatasetState(state)
	n.ObservedAt, _ = time.Parse(time.RFC3339, observed)
	n.Age = s.age(n.ObservedAt)
	return n, nil
}

// ListNodes returns up to limit nodes of one remote, ordered by node name.
// A non-positive limit uses MaxNodesQuery.
func (s *Store) ListNodes(ctx context.Context, remoteID string, limit int) ([]Node, error) {
	limit, err := checkLimit(limit, MaxNodesQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, node, status, uptime_seconds, cpu_count,
		       ram_total_bytes, ram_used_bytes, pve_version, kernel_version,
		       details_available, observed_at, source, state, reason,
		       collection_generation, details_observed_at, details_checked_at, details_source, details_reason
		FROM pve_nodes WHERE remote_id = ? ORDER BY node LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list nodes %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var details int
		var observed, state, detailsObserved, detailsChecked string
		if err := rows.Scan(&n.RemoteID, &n.Node, &n.Status, &n.UptimeSeconds,
			&n.CPUCount, &n.RAMTotalBytes, &n.RAMUsedBytes, &n.PVEVersion,
			&n.KernelVersion, &details, &observed, &n.Source, &state, &n.Reason,
			&n.CollectionGeneration, &detailsObserved, &detailsChecked, &n.DetailsSource, &n.DetailsReason); err != nil {
			return nil, fmt.Errorf("pveinventory: list nodes %s: %w", remoteID, err)
		}
		n.DetailsObservedAt, _ = time.Parse(time.RFC3339, detailsObserved)
		n.DetailsCheckedAt, _ = time.Parse(time.RFC3339, detailsChecked)
		n.DetailsAvailable = details != 0
		n.State = DatasetState(state)
		n.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		n.Age = s.age(n.ObservedAt)
		out = append(out, n)
	}
	return out, rows.Err()
}

// --- Guests ---

// GuestFilter selects which guests ListGuests returns.
type GuestFilter struct {
	// IncludeTombstoned also returns tombstoned incarnations. By default
	// only active incarnations are returned.
	IncludeTombstoned bool
	// VMID restricts to one VMID (0 = all).
	VMID uint64
}

// GetGuest returns the latest active incarnation of (remoteID, vmid).
func (s *Store) GetGuest(ctx context.Context, remoteID string, vmid uint64) (Guest, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, kind, node, name, status, uuid,
		       observed_at, source, state, reason, collection_generation,
		       tombstoned, tombstoned_at
		FROM pve_guests
		WHERE remote_id = ? AND vmid = ? AND tombstoned = 0
		ORDER BY generation DESC LIMIT 1`, remoteID, vmid)
	return scanGuestRow(row, s, fmt.Sprintf("get guest %s/%d", remoteID, vmid))
}

// ListGuests returns up to limit guests of one remote. Active incarnations
// are returned by default; set GuestFilter.IncludeTombstoned to include
// tombstones. A non-positive limit uses MaxGuestsQuery.
func (s *Store) ListGuests(ctx context.Context, remoteID string, f GuestFilter, limit int) ([]Guest, error) {
	limit, err := checkLimit(limit, MaxGuestsQuery)
	if err != nil {
		return nil, err
	}
	query := `
		SELECT remote_id, vmid, generation, kind, node, name, status, uuid,
		       observed_at, source, state, reason, collection_generation,
		       tombstoned, tombstoned_at
		FROM pve_guests WHERE remote_id = ?`
	args := []any{remoteID}
	if !f.IncludeTombstoned {
		query += ` AND tombstoned = 0`
	}
	if f.VMID != 0 {
		query += ` AND vmid = ?`
		args = append(args, f.VMID)
	}
	query += ` ORDER BY vmid, generation DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list guests %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []Guest
	for rows.Next() {
		g, err := scanGuestRow(rows, s, fmt.Sprintf("list guests %s", remoteID))
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// guestScanner is implemented by *sql.Row and *sql.Rows.
type guestScanner interface {
	Scan(dest ...any) error
}

func scanGuestRow(sc guestScanner, s *Store, where string) (Guest, error) {
	var g Guest
	var tomb int
	var observed, state, tombAt string
	if err := sc.Scan(&g.RemoteID, &g.VMID, &g.Generation, &g.Kind, &g.Node,
		&g.Name, &g.Status, &g.UUID, &observed, &g.Source, &state, &g.Reason,
		&g.CollectionGeneration, &tomb, &tombAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Guest{}, fmt.Errorf("pveinventory: %s: %w", where, ErrGuestNotFound)
		}
		return Guest{}, fmt.Errorf("pveinventory: %s: %w", where, err)
	}
	g.Tombstoned = tomb != 0
	g.State = DatasetState(state)
	g.ObservedAt, _ = time.Parse(time.RFC3339, observed)
	if tombAt != "" {
		g.TombstonedAt, _ = time.Parse(time.RFC3339, tombAt)
	}
	g.Age = s.age(g.ObservedAt)
	return g, nil
}

// --- Guest configs ---

// GetGuestConfig returns the stored config summary of one incarnation.
func (s *Store) GetGuestConfig(ctx context.Context, remoteID string, vmid, generation uint64) (GuestConfig, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, cpu_count, ram_bytes, disks_json,
		       boot_order_json, hostpci_json, cloud_init_ip_json, tags_json,
		       pool, cap_snapshots, cap_live_migration, cap_ram_snapshots,
		       observed_at, source, state, reason, collection_generation
		FROM pve_guest_configs WHERE remote_id = ? AND vmid = ? AND generation = ?`,
		remoteID, vmid, generation)
	return scanGuestConfigRow(row, s, fmt.Sprintf("get guest config %s/%d/%d", remoteID, vmid, generation))
}

func scanGuestConfigRow(sc guestScanner, s *Store, where string) (GuestConfig, error) {
	var c GuestConfig
	var disks, boot, hostpci, cloudinit, tags, observed, state string
	if err := sc.Scan(&c.RemoteID, &c.VMID, &c.Generation, &c.CPUCount, &c.RAMBytes,
		&disks, &boot, &hostpci, &cloudinit, &tags, &c.Pool,
		&c.CapSnapshots, &c.CapLiveMigration, &c.CapRAMSnapshots,
		&observed, &c.Source, &state, &c.Reason, &c.CollectionGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GuestConfig{}, fmt.Errorf("pveinventory: %s: %w", where, ErrGuestNotFound)
		}
		return GuestConfig{}, fmt.Errorf("pveinventory: %s: %w", where, err)
	}
	if err := json.Unmarshal([]byte(disks), &c.Disks); err != nil {
		return GuestConfig{}, fmt.Errorf("pveinventory: %s: disks: %w", where, err)
	}
	if err := json.Unmarshal([]byte(boot), &c.BootOrder); err != nil {
		return GuestConfig{}, fmt.Errorf("pveinventory: %s: boot_order: %w", where, err)
	}
	if err := json.Unmarshal([]byte(hostpci), &c.HostPCI); err != nil {
		return GuestConfig{}, fmt.Errorf("pveinventory: %s: hostpci: %w", where, err)
	}
	if cloudinit != "" {
		var ci pvecontract.CloudInitIP
		if err := json.Unmarshal([]byte(cloudinit), &ci); err != nil {
			return GuestConfig{}, fmt.Errorf("pveinventory: %s: cloud_init_ip: %w", where, err)
		}
		c.CloudInitIP = &ci
	}
	if err := json.Unmarshal([]byte(tags), &c.Tags); err != nil {
		return GuestConfig{}, fmt.Errorf("pveinventory: %s: tags: %w", where, err)
	}
	c.State = DatasetState(state)
	c.ObservedAt, _ = time.Parse(time.RFC3339, observed)
	return c, nil
}

// --- Interfaces ---

// ListInterfaces returns up to limit interfaces of one incarnation, ordered
// by name. A non-positive limit uses MaxInterfacesQuery.
func (s *Store) ListInterfaces(ctx context.Context, remoteID string, vmid, generation uint64, limit int) ([]GuestInterface, error) {
	limit, err := checkLimit(limit, MaxInterfacesQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, name, mac, bridge, vlan, ips_json,
		       source, observed_at, collection_generation
		FROM pve_interfaces
		WHERE remote_id = ? AND vmid = ? AND generation = ?
		ORDER BY name LIMIT ?`, remoteID, vmid, generation, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list interfaces %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	defer rows.Close()
	var out []GuestInterface
	for rows.Next() {
		var itf GuestInterface
		var ips, observed string
		if err := rows.Scan(&itf.RemoteID, &itf.VMID, &itf.Generation, &itf.Name,
			&itf.MAC, &itf.Bridge, &itf.VLAN, &ips, &itf.Source, &observed,
			&itf.CollectionGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: list interfaces %s/%d/%d: %w", remoteID, vmid, generation, err)
		}
		if err := json.Unmarshal([]byte(ips), &itf.IPs); err != nil {
			return nil, fmt.Errorf("pveinventory: list interfaces %s/%d/%d: ips: %w", remoteID, vmid, generation, err)
		}
		itf.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		out = append(out, itf)
	}
	return out, rows.Err()
}

// --- Snapshots ---

// ListSnapshots returns up to limit snapshots of one incarnation, ordered by
// name. A non-positive limit uses MaxSnapshotsQuery.
func (s *Store) ListSnapshots(ctx context.Context, remoteID string, vmid, generation uint64, limit int) ([]Snapshot, error) {
	limit, err := checkLimit(limit, MaxSnapshotsQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, name, time_unix, parent, has_ram,
		       observed_at, source, state, reason, collection_generation
		FROM pve_snapshots
		WHERE remote_id = ? AND vmid = ? AND generation = ?
		ORDER BY name LIMIT ?`, remoteID, vmid, generation, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list snapshots %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var hasRAM int
		var observed, state string
		if err := rows.Scan(&sn.RemoteID, &sn.VMID, &sn.Generation, &sn.Name,
			&sn.TimeUnix, &sn.Parent, &hasRAM, &observed, &sn.Source, &state,
			&sn.Reason, &sn.CollectionGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: list snapshots %s/%d/%d: %w", remoteID, vmid, generation, err)
		}
		sn.HasRAM = hasRAM != 0
		sn.State = DatasetState(state)
		sn.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		out = append(out, sn)
	}
	return out, rows.Err()
}

// --- Backups ---

// ListBackups returns up to limit backup records, newest start first.
// A non-positive limit uses MaxBackupsQuery.
func (s *Store) ListBackups(ctx context.Context, remoteID string, vmid, generation uint64, limit int) ([]BackupObservation, error) {
	return s.ListBackupsPage(ctx, remoteID, vmid, generation, limit, nil)
}

// ListBackupsPage returns a bounded page ordered by start time and evidence
// identity descending. Pass the previous page's last record as before, or nil
// for the newest page. A non-positive limit uses MaxBackupsQuery.
func (s *Store) ListBackupsPage(ctx context.Context, remoteID string, vmid, generation uint64, limit int, before *BackupObservation) ([]BackupObservation, error) {
	limit, err := checkLimit(limit, MaxBackupsQuery)
	if err != nil {
		return nil, err
	}
	query := `
		SELECT remote_id, vmid, generation, source, kind, name, status,
		       started_unix, finished_unix, verified, observed_at,
		       collection_generation
		FROM pve_backup_observations
		WHERE remote_id = ? AND vmid = ? AND generation = ?`
	args := []any{remoteID, vmid, generation}
	if before != nil {
		if before.RemoteID != remoteID || before.VMID != vmid || before.Generation != generation {
			return nil, errors.New("pveinventory: backup cursor belongs to another incarnation")
		}
		query += ` AND (started_unix, source, kind, name) < (?, ?, ?, ?)`
		args = append(args, before.StartedUnix, before.Source, before.Kind, before.Name)
	}
	query += ` ORDER BY started_unix DESC, source DESC, kind DESC, name DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list backups %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	defer rows.Close()
	var out []BackupObservation
	for rows.Next() {
		var b BackupObservation
		var observed string
		if err := rows.Scan(&b.RemoteID, &b.VMID, &b.Generation, &b.Source,
			&b.Kind, &b.Name, &b.Status, &b.StartedUnix, &b.FinishedUnix,
			&b.Verified, &observed, &b.CollectionGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: list backups %s/%d/%d: %w", remoteID, vmid, generation, err)
		}
		b.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		out = append(out, b)
	}
	return out, rows.Err()
}

// --- Storages ---

// ListStorages returns up to limit per-node storage reports of one remote,
// ordered by name, then node.
// A non-positive limit uses MaxStoragesQuery.
func (s *Store) ListStorages(ctx context.Context, remoteID string, limit int) ([]Storage, error) {
	limit, err := checkLimit(limit, MaxStoragesQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, node, name, type, format, content_json, active, shared,
		       size_bytes, free_bytes, observed_at, source, state, reason,
		       collection_generation
		FROM pve_storages WHERE remote_id = ? ORDER BY name, node LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list storages %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []Storage
	for rows.Next() {
		var st Storage
		var content string
		var active, shared int
		var observed, state string
		if err := rows.Scan(&st.RemoteID, &st.Node, &st.Name, &st.Type, &st.Format,
			&content, &active, &shared, &st.SizeBytes, &st.FreeBytes, &observed,
			&st.Source, &state, &st.Reason, &st.CollectionGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: list storages %s: %w", remoteID, err)
		}
		if err := json.Unmarshal([]byte(content), &st.Content); err != nil {
			return nil, fmt.Errorf("pveinventory: list storages %s: content: %w", remoteID, err)
		}
		st.Active = active != 0
		st.Shared = shared != 0
		st.State = DatasetState(state)
		st.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		out = append(out, st)
	}
	return out, rows.Err()
}

// --- Cluster ---

// GetCluster returns the stored cluster and HA summary of one remote.
func (s *Store) GetCluster(ctx context.Context, remoteID string) (Cluster, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, quorum, nodes_json, ha_resources_json, observed_at,
		       source, state, reason, collection_generation
		FROM pve_cluster_status WHERE remote_id = ?`, remoteID)
	var c Cluster
	var nodes, ha, observed, state string
	if err := row.Scan(&c.RemoteID, &c.Quorum, &nodes, &ha, &observed,
		&c.Source, &state, &c.Reason, &c.CollectionGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Cluster{}, fmt.Errorf("pveinventory: get cluster %s: %w", remoteID, ErrClusterNotFound)
		}
		return Cluster{}, fmt.Errorf("pveinventory: get cluster %s: %w", remoteID, err)
	}
	if err := json.Unmarshal([]byte(nodes), &c.Nodes); err != nil {
		return Cluster{}, fmt.Errorf("pveinventory: get cluster %s: nodes: %w", remoteID, err)
	}
	if err := json.Unmarshal([]byte(ha), &c.HAResources); err != nil {
		return Cluster{}, fmt.Errorf("pveinventory: get cluster %s: ha: %w", remoteID, err)
	}
	c.State = DatasetState(state)
	c.ObservedAt, _ = time.Parse(time.RFC3339, observed)
	return c, nil
}

// --- Tasks ---

// ListTasks returns up to limit task metadata records of one remote, newest
// first. A non-positive limit uses MaxTasksQuery.
func (s *Store) ListTasks(ctx context.Context, remoteID string, limit int) ([]Task, error) {
	limit, err := checkLimit(limit, MaxTasksQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, node, actor, type, target, started_unix, exit_status,
		       observed_at, source, collection_generation
		FROM pve_tasks WHERE remote_id = ?
		ORDER BY started_unix DESC, node, actor LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list tasks %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []Task
	for rows.Next() {
		var t Task
		var observed string
		if err := rows.Scan(&t.RemoteID, &t.Node, &t.Actor, &t.Type, &t.Target,
			&t.StartedUnix, &t.ExitStatus, &observed, &t.Source,
			&t.CollectionGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: list tasks %s: %w", remoteID, err)
		}
		t.ObservedAt, _ = time.Parse(time.RFC3339, observed)
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- Dataset status ---

// GetDatasetStatus returns the current state of one top-level dataset for a
// remote.
func (s *Store) GetDatasetStatus(ctx context.Context, remoteID, dataset string) (DatasetStatus, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, dataset, state, observed_at, source, reason,
		       collection_generation
		FROM pve_dataset_status WHERE remote_id = ? AND dataset = ?`, remoteID, dataset)
	return scanDatasetStatusRow(row, s, fmt.Sprintf("get dataset status %s/%s", remoteID, dataset))
}

// ListDatasetStatus returns the current state of every top-level dataset
// recorded for a remote.
func (s *Store) ListDatasetStatus(ctx context.Context, remoteID string) ([]DatasetStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, dataset, state, observed_at, source, reason,
		       collection_generation
		FROM pve_dataset_status WHERE remote_id = ? ORDER BY dataset`, remoteID)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list dataset status %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []DatasetStatus
	for rows.Next() {
		d, err := scanDatasetStatusRow(rows, s, fmt.Sprintf("list dataset status %s", remoteID))
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func scanDatasetStatusRow(sc guestScanner, s *Store, where string) (DatasetStatus, error) {
	var d DatasetStatus
	var observed, state string
	if err := sc.Scan(&d.RemoteID, &d.Dataset, &state, &observed, &d.Source,
		&d.Reason, &d.CollectionGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DatasetStatus{}, fmt.Errorf("pveinventory: %s: %w", where, ErrDatasetNotFound)
		}
		return DatasetStatus{}, fmt.Errorf("pveinventory: %s: %w", where, err)
	}
	d.State = DatasetState(state)
	d.ObservedAt, _ = time.Parse(time.RFC3339, observed)
	return d, nil
}

// GetGuestDatasetStatus returns the current state of one per-guest
// sub-dataset for one incarnation.
func (s *Store) GetGuestDatasetStatus(ctx context.Context, remoteID string, vmid, generation uint64, dataset string) (GuestDatasetStatus, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, dataset, state, observed_at, source,
		       reason, collection_generation
		FROM pve_guest_dataset_status
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND dataset = ?`,
		remoteID, vmid, generation, dataset)
	var d GuestDatasetStatus
	var observed, state string
	if err := row.Scan(&d.RemoteID, &d.VMID, &d.Generation, &d.Dataset, &state,
		&observed, &d.Source, &d.Reason, &d.CollectionGeneration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GuestDatasetStatus{}, fmt.Errorf("pveinventory: get guest dataset status %s/%d/%d/%s: %w", remoteID, vmid, generation, dataset, ErrDatasetNotFound)
		}
		return GuestDatasetStatus{}, fmt.Errorf("pveinventory: get guest dataset status %s/%d/%d/%s: %w", remoteID, vmid, generation, dataset, err)
	}
	d.State = DatasetState(state)
	d.ObservedAt, _ = time.Parse(time.RFC3339, observed)
	return d, nil
}

// --- Retention ---

// Prune removes tombstoned guest incarnations older than
// TombstoneRetention (and their sub-dataset rows) and task metadata older
// than TaskRetention, using the store's clock. It is the only code path that
// deletes stored observations; nothing is ever deleted implicitly.
func (s *Store) Prune(ctx context.Context) (PruneReport, error) {
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PruneReport{}, fmt.Errorf("pveinventory: prune: begin: %w", err)
	}
	defer tx.Rollback()

	tombCutoff := s.formatTime(now.Add(-TombstoneRetention))
	subq := `SELECT remote_id, vmid, generation FROM pve_guests
	          WHERE tombstoned = 1 AND tombstoned_at != '' AND tombstoned_at < ?`

	// Remove the sub-dataset rows of the pruned incarnations first, while
	// the tombstone rows still exist for the subquery.
	for _, table := range []string{
		"pve_guest_configs", "pve_interfaces", "pve_snapshots",
		"pve_backup_observations", "pve_guest_dataset_status",
	} {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE (remote_id, vmid, generation) IN (%s)`, table, subq),
			tombCutoff); err != nil {
			return PruneReport{}, fmt.Errorf("pveinventory: prune %s: %w", table, err)
		}
	}

	// Retired guest metric series share the tombstone lifecycle. Keep node
	// series and other incarnations/remotes intact.
	for _, table := range []string{"pve_metric_buckets", "pve_metric_current"} {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE target_kind = ? AND (remote_id, vmid, generation) IN (%s)`, table, subq),
			string(MetricTargetGuest), tombCutoff); err != nil {
			return PruneReport{}, fmt.Errorf("pveinventory: prune %s: %w", table, err)
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM pve_guests
		WHERE tombstoned = 1 AND tombstoned_at != '' AND tombstoned_at < ?`, tombCutoff)
	if err != nil {
		return PruneReport{}, fmt.Errorf("pveinventory: prune guests: %w", err)
	}
	tombstones, _ := res.RowsAffected()

	taskCutoff := now.Add(-TaskRetention).Unix()
	res, err = tx.ExecContext(ctx, `DELETE FROM pve_tasks WHERE started_unix < ?`, taskCutoff)
	if err != nil {
		return PruneReport{}, fmt.Errorf("pveinventory: prune tasks: %w", err)
	}
	tasks, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return PruneReport{}, fmt.Errorf("pveinventory: prune: commit: %w", err)
	}
	return PruneReport{TombstonesRemoved: int(tombstones), TasksRemoved: int(tasks)}, nil
}
