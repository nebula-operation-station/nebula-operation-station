// SPDX-License-Identifier: AGPL-3.0-or-later

// Ingestion of validated Proxmox VE observations into the PVE inventory
// store (ADR 0006, ticket P1-11).
//
// Each top-level dataset (nodes, guests, storages, cluster, tasks) and the
// per-guest detail group are committed atomically in their own transaction:
// a dataset either fully applies or is fully rolled back, and a failure in
// one dataset does not roll back the others.
//
// Incarnation detection: guests are keyed by (remote_id, vmid, generation).
// A VMID whose observed generation differs from the stored active
// generation is a reused VMID -- the old incarnation is tombstoned and the
// new one inserted. A complete enumeration tombstones active incarnations
// it does not see; a partial one never does. Stale data is kept with its
// age and is only removed by explicit retention (Prune).
package pveinventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// IngestReport summarizes what IngestObservation stored.
type IngestReport struct {
	// RemoteID is the remote the observation was for.
	RemoteID string
	// NodesUpserted is the number of node rows upserted.
	NodesUpserted int
	// GuestsUpserted is the number of guest incarnations inserted or
	// updated.
	GuestsUpserted int
	// GuestsTombstoned is the number of guest incarnations tombstoned
	// (incarnation resets plus unseen-guest tombstones).
	GuestsTombstoned int
	// GuestsStarted is the number of new incarnations started.
	GuestsStarted int
	// StoragesUpserted is the number of storage rows upserted.
	StoragesUpserted int
	// TasksInserted is the number of task rows inserted.
	TasksInserted int
	// ClusterUpserted reports whether the cluster status was written.
	ClusterUpserted bool
	// GuestConfigsUpserted is the number of guest config rows upserted.
	GuestConfigsUpserted int
	// InterfacesStored is the number of interface rows stored.
	InterfacesStored int
	// SnapshotsStored is the number of snapshot rows stored.
	SnapshotsStored int
	// BackupsStored is the number of backup evidence rows inserted.
	BackupsStored int
	// Errors maps a dataset name to the error that failed it. An empty map
	// means every dataset applied.
	Errors map[string]error
}

// boolToInt renders a bool as 0/1 for storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// storedState maps a pvecontract dataset plus the observation's completeness
// to a stored dataset state and its reason.
//
//   - an unavailable dataset is stored unavailable with its own reason;
//   - an available value of a whole-remote enumeration (isEnumeration) is
//     stored partial when the observation is incomplete, because unseen
//     objects may exist;
//   - everything else that was read is stored available with no reason.
func storedState(state pvecontract.Availability, datasetReason string, complete bool, obsReason string, isEnumeration bool) (DatasetState, string) {
	switch {
	case state == pvecontract.Unavailable:
		return StateUnavailable, datasetReason
	case isEnumeration && !complete:
		return StatePartial, obsReason
	default:
		return StateAvailable, ""
	}
}

// withTx runs fn in a single transaction, committing on success and rolling
// back on any error.
func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("pveinventory: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("pveinventory: commit: %w", err)
	}
	return nil
}

// withObservationTx rejects obsolete collections inside the same transaction
// as the writes, including when another ingest has advanced the remote.
func (s *Store) withObservationTx(ctx context.Context, obs pvecontract.Observation, fn func(*sql.Tx) error) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var generation uint64
		var observed string
		err := tx.QueryRowContext(ctx, `SELECT last_collection_generation, last_observed_at
			FROM pve_remotes WHERE remote_id = ?`, obs.RemoteID).Scan(&generation, &observed)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("pveinventory: check collection freshness: %w", err)
		}
		if err == nil {
			at, err := time.Parse(time.RFC3339, observed)
			if err != nil {
				return fmt.Errorf("pveinventory: parse collection timestamp: %w", err)
			}
			if obs.CollectionGeneration < generation || (obs.CollectionGeneration == generation && obs.ObservedAt.Before(at)) {
				return ErrStaleObservation
			}
		}
		return fn(tx)
	})
}

// setDatasetStatus records the current state of one top-level dataset.
func (s *Store) setDatasetStatus(ctx context.Context, tx *sql.Tx, remoteID, dataset string, state DatasetState, obs pvecontract.Observation, reason string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pve_dataset_status (remote_id, dataset, state, observed_at, source, reason, collection_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (remote_id, dataset) DO UPDATE SET
			state                 = excluded.state,
			observed_at           = excluded.observed_at,
			source                = excluded.source,
			reason                = excluded.reason,
			collection_generation = MAX(pve_dataset_status.collection_generation, excluded.collection_generation)`,
		remoteID, dataset, string(state), s.formatTime(obs.ObservedAt), obs.Source, reason,
		obs.CollectionGeneration); err != nil {
		return fmt.Errorf("pveinventory: set dataset status %s/%s: %w", remoteID, dataset, err)
	}
	return nil
}

// setGuestDatasetStatus records the current state of one per-guest
// sub-dataset for one incarnation.
func (s *Store) setGuestDatasetStatus(ctx context.Context, tx *sql.Tx, remoteID string, vmid, generation uint64, dataset string, state DatasetState, obs pvecontract.Observation, reason string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pve_guest_dataset_status (remote_id, vmid, generation, dataset, state, observed_at, source, reason, collection_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (remote_id, vmid, generation, dataset) DO UPDATE SET
			state                 = excluded.state,
			observed_at           = excluded.observed_at,
			source                = excluded.source,
			reason                = excluded.reason,
			collection_generation = MAX(pve_guest_dataset_status.collection_generation, excluded.collection_generation)`,
		remoteID, vmid, generation, dataset, string(state), s.formatTime(obs.ObservedAt), obs.Source, reason,
		obs.CollectionGeneration); err != nil {
		return fmt.Errorf("pveinventory: set guest dataset status %s/%d/%d/%s: %w", remoteID, vmid, generation, dataset, err)
	}
	return nil
}

// IngestObservation validates and persists one observation page. Each
// dataset is committed atomically in its own transaction; a failure in one
// dataset is recorded in IngestReport.Errors and does not roll back the
// others. The returned report is always populated for the datasets that
// applied.
func (s *Store) IngestObservation(ctx context.Context, obs pvecontract.Observation) (IngestReport, error) {
	v, err := pvecontract.ValidateObservation(obs)
	if err != nil {
		return IngestReport{}, fmt.Errorf("pveinventory: ingest: %w", err)
	}
	rep := IngestReport{RemoteID: v.RemoteID, Errors: map[string]error{}}

	// Remote bookkeeping (presentation copy; identity is executor-owned).
	if err := s.withObservationTx(ctx, v, func(tx *sql.Tx) error {
		return s.touchRemote(ctx, tx, v.RemoteID, v.ObservedAt, v.Source, v.CollectionGeneration)
	}); err != nil {
		rep.Errors["remote"] = err
		if errors.Is(err, ErrStaleObservation) {
			return rep, err
		}
	}

	if n, err := s.ingestNodes(ctx, v); err != nil {
		rep.Errors["nodes"] = err
	} else {
		rep.NodesUpserted = n
	}
	guestsOK := true
	if g, err := s.ingestGuests(ctx, v); err != nil {
		rep.Errors["guests"] = err
		guestsOK = false
	} else {
		rep.GuestsUpserted = g.Upserted
		rep.GuestsTombstoned = g.Tombstoned
		rep.GuestsStarted = g.Started
	}
	// Guest details belong to incarnations; if the guests dataset failed
	// and rolled back, do not write sub-dataset rows for incarnations that
	// may not exist.
	if guestsOK {
		if d, err := s.ingestGuestDetails(ctx, v); err != nil {
			rep.Errors["guest_details"] = err
		} else {
			rep.GuestConfigsUpserted = d.Configs
			rep.InterfacesStored = d.Interfaces
			rep.SnapshotsStored = d.Snapshots
			rep.BackupsStored = d.Backups
		}
	}
	if n, err := s.ingestStorages(ctx, v); err != nil {
		rep.Errors["storages"] = err
	} else {
		rep.StoragesUpserted = n
	}
	if done, err := s.ingestCluster(ctx, v); err != nil {
		rep.Errors["cluster"] = err
	} else {
		rep.ClusterUpserted = done
	}
	if n, err := s.ingestTasks(ctx, v); err != nil {
		rep.Errors["tasks"] = err
	} else {
		rep.TasksInserted = n
	}

	if len(rep.Errors) > 0 {
		names := make([]string, 0, len(rep.Errors))
		for name := range rep.Errors {
			names = append(names, name)
		}
		sort.Strings(names)
		var msgs []string
		for _, name := range names {
			msgs = append(msgs, fmt.Sprintf("%s: %v", name, rep.Errors[name]))
		}
		return rep, errors.New("pveinventory: ingest: " + strings.Join(msgs, "; "))
	}
	return rep, nil
}

// ingestNodes upserts the node dataset and records its status.
func (s *Store) ingestNodes(ctx context.Context, obs pvecontract.Observation) (int, error) {
	state, reason := storedState(obs.Nodes.State, obs.Nodes.Reason, obs.Complete, obs.Reason, true)
	var n int
	err := s.withObservationTx(ctx, obs, func(tx *sql.Tx) error {
		if obs.Nodes.State == pvecontract.Available {
			for _, nd := range obs.Nodes.Value {
				detailsAvail := 0
				pveVer, kernelVer := "", ""
				if nd.Details.State == pvecontract.Available {
					detailsAvail = 1
					pveVer = nd.Details.Value.PVEVersion
					kernelVer = nd.Details.Value.KernelVersion
				}
				detailsObserved := ""
				if detailsAvail == 1 {
					detailsObserved = s.formatTime(obs.ObservedAt)
				}
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO pve_nodes (remote_id, node, status, uptime_seconds, cpu_count,
					                      ram_total_bytes, ram_used_bytes, pve_version, kernel_version,
					                      details_available, observed_at, source, state, reason,
					                      collection_generation, details_observed_at, details_checked_at,
					                      details_source, details_reason)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT (remote_id, node) DO UPDATE SET
						status                = excluded.status,
						uptime_seconds        = excluded.uptime_seconds,
						cpu_count             = excluded.cpu_count,
						ram_total_bytes       = excluded.ram_total_bytes,
						ram_used_bytes        = excluded.ram_used_bytes,
						pve_version           = CASE WHEN excluded.details_available = 1 THEN excluded.pve_version ELSE pve_nodes.pve_version END,
						kernel_version        = CASE WHEN excluded.details_available = 1 THEN excluded.kernel_version ELSE pve_nodes.kernel_version END,
						details_observed_at   = CASE WHEN excluded.details_available = 1 THEN excluded.details_observed_at ELSE pve_nodes.details_observed_at END,
						details_checked_at    = excluded.details_checked_at,
						details_source        = excluded.details_source,
						details_reason        = excluded.details_reason,
						details_available     = excluded.details_available,
						observed_at           = excluded.observed_at,
						source                = excluded.source,
						state                 = excluded.state,
						reason                = excluded.reason,
						collection_generation = MAX(pve_nodes.collection_generation, excluded.collection_generation)`,
					obs.RemoteID, nd.Node, string(nd.Status), nd.UptimeSeconds, nd.CPUCount,
					nd.RAMTotalBytes, nd.RAMUsedBytes, pveVer, kernelVer, detailsAvail,
					s.formatTime(obs.ObservedAt), obs.Source, string(state), reason,
					obs.CollectionGeneration, detailsObserved, s.formatTime(obs.ObservedAt), obs.Source, nd.Details.Reason); err != nil {
					return fmt.Errorf("pveinventory: ingest node %s: %w", nd.Node, err)
				}
				n++
			}
		}
		return s.setDatasetStatus(ctx, tx, obs.RemoteID, DatasetNodes, state, obs, reason)
	})
	return n, err
}

// guestsIngest is the per-observation guest ingest summary.
type guestsIngest struct {
	Upserted   int
	Tombstoned int
	Started    int
}

// ingestGuests applies incarnation detection and records the guests dataset
// status.
func (s *Store) ingestGuests(ctx context.Context, obs pvecontract.Observation) (guestsIngest, error) {
	var rep guestsIngest
	state, reason := storedState(obs.Guests.State, obs.Guests.Reason, obs.Complete, obs.Reason, true)
	err := s.withObservationTx(ctx, obs, func(tx *sql.Tx) error {
		if obs.Guests.State != pvecontract.Available {
			return s.setDatasetStatus(ctx, tx, obs.RemoteID, DatasetGuests, state, obs, reason)
		}
		now := s.formatTime(s.now())
		if err := s.prepareGuestCollection(ctx, tx, obs); err != nil {
			return err
		}
		for _, g := range obs.Guests.Value {
			if _, err := tx.ExecContext(ctx, `INSERT INTO pve_guest_collection_seen (remote_id, vmid)
				VALUES (?, ?) ON CONFLICT DO NOTHING`, obs.RemoteID, g.VMID); err != nil {
				return fmt.Errorf("pveinventory: record collection guest: %w", err)
			}
			var activeGen uint64
			var hasActive bool
			row := tx.QueryRowContext(ctx, `
				SELECT generation FROM pve_guests
				WHERE remote_id = ? AND vmid = ? AND tombstoned = 0
				ORDER BY generation DESC LIMIT 1`, obs.RemoteID, g.VMID)
			if err := row.Scan(&activeGen); err == nil {
				hasActive = true
			} else if !errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("pveinventory: ingest guest %d: %w", g.VMID, err)
			}
			switch {
			case !hasActive:
				var highWater uint64
				if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation), 0)
					FROM pve_guest_generations WHERE remote_id = ? AND vmid = ?`, obs.RemoteID, g.VMID).Scan(&highWater); err != nil {
					return fmt.Errorf("pveinventory: read guest generation: %w", err)
				}
				if g.Generation <= highWater {
					continue
				}
				if err := s.insertGuest(ctx, tx, obs, g, state, reason); err != nil {
					return err
				}
				rep.Upserted++
				rep.Started++
			case g.Generation == activeGen:
				if err := s.updateGuest(ctx, tx, obs, g, state, reason); err != nil {
					return err
				}
				rep.Upserted++
			case g.Generation > activeGen:
				if err := s.tombstoneGuest(ctx, tx, obs.RemoteID, g.VMID, activeGen, now); err != nil {
					return err
				}
				if err := s.insertGuest(ctx, tx, obs, g, state, reason); err != nil {
					return err
				}
				rep.Upserted++
				rep.Started++
				rep.Tombstoned++
			default:
				// g.Generation < activeGen: a stale observation; keep the
				// newer incarnation and do not clobber it.
			}
		}
		var seenCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pve_guest_collection_seen WHERE remote_id = ?`, obs.RemoteID).Scan(&seenCount); err != nil {
			return fmt.Errorf("pveinventory: count collection guests: %w", err)
		}
		if seenCount > pvecontract.MaxGuestsPerRemote {
			return fmt.Errorf("pveinventory: collection exceeds guest limit %d", pvecontract.MaxGuestsPerRemote)
		}
		// Only the final page reconciles the whole collection, in bounded batches.
		if obs.Complete {
			for {
				active, err := s.unseenGuests(ctx, tx, obs.RemoteID)
				if err != nil {
					return err
				}
				if len(active) == 0 {
					break
				}
				for _, inc := range active {
					if err := s.tombstoneGuest(ctx, tx, obs.RemoteID, inc.vmid, inc.gen, now); err != nil {
						return err
					}
					rep.Tombstoned++
				}
			}
		}
		var activeCount int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pve_guests WHERE remote_id = ? AND tombstoned = 0`, obs.RemoteID).Scan(&activeCount); err != nil {
			return fmt.Errorf("pveinventory: count active guests: %w", err)
		}
		if activeCount > pvecontract.MaxGuestsPerRemote {
			return fmt.Errorf("pveinventory: remote exceeds guest limit %d", pvecontract.MaxGuestsPerRemote)
		}
		return s.setDatasetStatus(ctx, tx, obs.RemoteID, DatasetGuests, state, obs, reason)
	})
	return rep, err
}

// prepareGuestCollection starts a collection or resumes its persisted membership.
// A paged collection keeps its membership until the collection generation
// advances. A standalone complete observation reconciles its own enumeration.
func (s *Store) prepareGuestCollection(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation) error {
	var generation uint64
	var paged bool
	err := tx.QueryRowContext(ctx, `SELECT collection_generation, paged
		FROM pve_guest_collections WHERE remote_id = ?`, obs.RemoteID).Scan(&generation, &paged)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("pveinventory: read collection: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) || generation != obs.CollectionGeneration || !paged {
		if _, err := tx.ExecContext(ctx, `DELETE FROM pve_guest_collection_seen WHERE remote_id = ?`, obs.RemoteID); err != nil {
			return fmt.Errorf("pveinventory: reset collection: %w", err)
		}
		paged = false
	}
	paged = paged || !obs.Complete
	if _, err := tx.ExecContext(ctx, `INSERT INTO pve_guest_collections
		(remote_id, collection_generation, paged) VALUES (?, ?, ?)
		ON CONFLICT (remote_id) DO UPDATE SET collection_generation = excluded.collection_generation,
		paged = excluded.paged`, obs.RemoteID, obs.CollectionGeneration, paged); err != nil {
		return fmt.Errorf("pveinventory: record collection: %w", err)
	}
	return nil
}

// activeIncarnation is a (vmid, generation) pair of an active guest.
type activeIncarnation struct {
	vmid uint64
	gen  uint64
}

// reconcileBatchSize bounds memory used while reconciling a collection.
const reconcileBatchSize = 256

// unseenGuests lists one bounded batch of active incarnations absent from the collection.
func (s *Store) unseenGuests(ctx context.Context, tx *sql.Tx, remoteID string) ([]activeIncarnation, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT vmid, generation FROM pve_guests AS g
		WHERE remote_id = ? AND tombstoned = 0 AND NOT EXISTS (
			SELECT 1 FROM pve_guest_collection_seen AS seen
			WHERE seen.remote_id = g.remote_id AND seen.vmid = g.vmid)
		ORDER BY vmid, generation LIMIT ?`, remoteID, reconcileBatchSize)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list active guests %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []activeIncarnation
	for rows.Next() {
		var i activeIncarnation
		if err := rows.Scan(&i.vmid, &i.gen); err != nil {
			return nil, fmt.Errorf("pveinventory: list active guests %s: %w", remoteID, err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// insertGuest inserts a new guest incarnation.
func (s *Store) insertGuest(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation, g pvecontract.GuestObservation, state DatasetState, reason string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pve_guests (remote_id, vmid, generation, kind, node, name, status, uuid,
		                        observed_at, source, state, reason, collection_generation,
		                        tombstoned, tombstoned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')`,
		obs.RemoteID, g.VMID, g.Generation, string(g.Kind), g.Node, g.Name, string(g.Status),
		g.UUID, s.formatTime(obs.ObservedAt), obs.Source, string(state), reason,
		obs.CollectionGeneration); err != nil {
		return fmt.Errorf("pveinventory: insert guest %s/%d: %w", obs.RemoteID, g.VMID, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pve_guest_generations (remote_id, vmid, generation)
		VALUES (?, ?, ?) ON CONFLICT (remote_id, vmid) DO UPDATE SET
		generation = MAX(pve_guest_generations.generation, excluded.generation)`, obs.RemoteID, g.VMID, g.Generation); err != nil {
		return fmt.Errorf("pveinventory: retain guest generation: %w", err)
	}
	return nil
}

// updateGuest updates an existing active guest incarnation in place.
func (s *Store) updateGuest(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation, g pvecontract.GuestObservation, state DatasetState, reason string) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE pve_guests SET
			kind                  = ?,
			node                  = ?,
			name                  = ?,
			status                = ?,
			uuid                  = ?,
			observed_at           = ?,
			source                = ?,
			state                 = ?,
			reason                = ?,
			collection_generation = MAX(collection_generation, ?)
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`,
		string(g.Kind), g.Node, g.Name, string(g.Status), g.UUID,
		s.formatTime(obs.ObservedAt), obs.Source, string(state), reason,
		obs.CollectionGeneration, obs.RemoteID, g.VMID, g.Generation)
	if err != nil {
		return fmt.Errorf("pveinventory: update guest %s/%d: %w", obs.RemoteID, g.VMID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("pveinventory: update guest %s/%d: incarnation not found", obs.RemoteID, g.VMID)
	}
	return nil
}

// tombstoneGuest marks one incarnation tombstoned at now.
func (s *Store) tombstoneGuest(ctx context.Context, tx *sql.Tx, remoteID string, vmid, gen uint64, now string) error {
	if _, err := tx.ExecContext(ctx, `
		UPDATE pve_guests SET tombstoned = 1, tombstoned_at = ?
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`,
		now, remoteID, vmid, gen); err != nil {
		return fmt.Errorf("pveinventory: tombstone guest %s/%d: %w", remoteID, vmid, err)
	}
	return nil
}

// guestDetailsIngest is the per-observation guest-detail ingest summary.
type guestDetailsIngest struct {
	Configs    int
	Interfaces int
	Snapshots  int
	Backups    int
}

// ingestGuestDetails applies the per-guest sub-datasets (config,
// interfaces, snapshots, backups) and records their statuses.
func (s *Store) ingestGuestDetails(ctx context.Context, obs pvecontract.Observation) (guestDetailsIngest, error) {
	var rep guestDetailsIngest
	if obs.Guests.State != pvecontract.Available {
		return rep, nil
	}
	err := s.withObservationTx(ctx, obs, func(tx *sql.Tx) error {
		for _, g := range obs.Guests.Value {
			var active bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pve_guests
				WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0)`, obs.RemoteID, g.VMID, g.Generation).Scan(&active); err != nil {
				return fmt.Errorf("pveinventory: check guest detail incarnation: %w", err)
			}
			if !active {
				continue
			}
			if err := s.ingestGuestConfig(ctx, tx, obs, g, &rep); err != nil {
				return err
			}
			if err := s.ingestGuestInterfaces(ctx, tx, obs, g, &rep); err != nil {
				return err
			}
			if err := s.ingestGuestSnapshots(ctx, tx, obs, g, &rep); err != nil {
				return err
			}
			if err := s.ingestGuestBackups(ctx, tx, obs, g, &rep); err != nil {
				return err
			}
		}
		return nil
	})
	return rep, err
}

// ingestGuestConfig upserts one guest's config summary and records its
// status.
func (s *Store) ingestGuestConfig(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation, g pvecontract.GuestObservation, rep *guestDetailsIngest) error {
	state, reason := storedState(g.Config.State, g.Config.Reason, obs.Complete, obs.Reason, false)
	if g.Config.State == pvecontract.Available {
		c := g.Config.Value
		disksJSON, err := json.Marshal(c.Disks)
		if err != nil {
			return fmt.Errorf("pveinventory: guest %d config disks: %w", g.VMID, err)
		}
		bootJSON, err := json.Marshal(c.BootOrder)
		if err != nil {
			return fmt.Errorf("pveinventory: guest %d config boot_order: %w", g.VMID, err)
		}
		hostpciJSON, err := json.Marshal(c.HostPCI)
		if err != nil {
			return fmt.Errorf("pveinventory: guest %d config hostpci: %w", g.VMID, err)
		}
		tagsJSON, err := json.Marshal(c.Tags)
		if err != nil {
			return fmt.Errorf("pveinventory: guest %d config tags: %w", g.VMID, err)
		}
		cloudinitJSON := ""
		if c.CloudInitIP != nil {
			b, err := json.Marshal(c.CloudInitIP)
			if err != nil {
				return fmt.Errorf("pveinventory: guest %d config cloud_init_ip: %w", g.VMID, err)
			}
			cloudinitJSON = string(b)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pve_guest_configs (remote_id, vmid, generation, cpu_count, ram_bytes,
			                              disks_json, boot_order_json, hostpci_json,
			                              cloud_init_ip_json, tags_json, pool, cap_snapshots,
			                              cap_live_migration, cap_ram_snapshots, observed_at,
			                              source, state, reason, collection_generation)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (remote_id, vmid, generation) DO UPDATE SET
				cpu_count             = excluded.cpu_count,
				ram_bytes             = excluded.ram_bytes,
				disks_json            = excluded.disks_json,
				boot_order_json       = excluded.boot_order_json,
				hostpci_json          = excluded.hostpci_json,
				cloud_init_ip_json    = excluded.cloud_init_ip_json,
				tags_json             = excluded.tags_json,
				pool                  = excluded.pool,
				cap_snapshots         = excluded.cap_snapshots,
				cap_live_migration    = excluded.cap_live_migration,
				cap_ram_snapshots     = excluded.cap_ram_snapshots,
				observed_at           = excluded.observed_at,
				source                = excluded.source,
				state                 = excluded.state,
				reason                = excluded.reason,
				collection_generation = MAX(pve_guest_configs.collection_generation, excluded.collection_generation)`,
			obs.RemoteID, g.VMID, g.Generation, c.CPUCount, c.RAMBytes, string(disksJSON),
			string(bootJSON), string(hostpciJSON), cloudinitJSON, string(tagsJSON), c.Pool,
			string(c.Capabilities.Snapshots), string(c.Capabilities.LiveMigration),
			string(c.Capabilities.RAMSnapshots), s.formatTime(obs.ObservedAt), obs.Source,
			string(state), reason, obs.CollectionGeneration); err != nil {
			return fmt.Errorf("pveinventory: ingest guest %d config: %w", g.VMID, err)
		}
		rep.Configs++
	}
	return s.setGuestDatasetStatus(ctx, tx, obs.RemoteID, g.VMID, g.Generation, DatasetConfig, state, obs, reason)
}

// ingestGuestInterfaces replaces one guest's interfaces and records its
// status.
func (s *Store) ingestGuestInterfaces(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation, g pvecontract.GuestObservation, rep *guestDetailsIngest) error {
	state, reason := storedState(g.Interfaces.State, g.Interfaces.Reason, obs.Complete, obs.Reason, false)
	if g.Interfaces.State == pvecontract.Available {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM pve_interfaces
			WHERE remote_id = ? AND vmid = ? AND generation = ?`,
			obs.RemoteID, g.VMID, g.Generation); err != nil {
			return fmt.Errorf("pveinventory: ingest guest %d interfaces: %w", g.VMID, err)
		}
		for _, itf := range g.Interfaces.Value {
			ipsJSON, err := json.Marshal(itf.IPs)
			if err != nil {
				return fmt.Errorf("pveinventory: guest %d interface %s ips: %w", g.VMID, itf.Name, err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO pve_interfaces (remote_id, vmid, generation, name, mac, bridge,
				                           vlan, ips_json, source, observed_at,
				                           collection_generation)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				obs.RemoteID, g.VMID, g.Generation, itf.Name, itf.MAC, itf.Bridge,
				itf.VLAN, string(ipsJSON), itf.Source, s.formatTime(obs.ObservedAt),
				obs.CollectionGeneration); err != nil {
				return fmt.Errorf("pveinventory: ingest guest %d interface %s: %w", g.VMID, itf.Name, err)
			}
			rep.Interfaces++
		}
	}
	return s.setGuestDatasetStatus(ctx, tx, obs.RemoteID, g.VMID, g.Generation, DatasetInterfaces, state, obs, reason)
}

// ingestGuestSnapshots replaces one guest's snapshots and records its
// status.
func (s *Store) ingestGuestSnapshots(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation, g pvecontract.GuestObservation, rep *guestDetailsIngest) error {
	state, reason := storedState(g.Snapshots.State, g.Snapshots.Reason, obs.Complete, obs.Reason, false)
	if g.Snapshots.State == pvecontract.Available {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM pve_snapshots
			WHERE remote_id = ? AND vmid = ? AND generation = ?`,
			obs.RemoteID, g.VMID, g.Generation); err != nil {
			return fmt.Errorf("pveinventory: ingest guest %d snapshots: %w", g.VMID, err)
		}
		for _, sn := range g.Snapshots.Value {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO pve_snapshots (remote_id, vmid, generation, name, time_unix, parent,
				                          has_ram, observed_at, source, state, reason,
				                          collection_generation)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				obs.RemoteID, g.VMID, g.Generation, sn.Name, sn.TimeUnix, sn.Parent,
				boolToInt(sn.HasRAM), s.formatTime(obs.ObservedAt), obs.Source, string(state),
				reason, obs.CollectionGeneration); err != nil {
				return fmt.Errorf("pveinventory: ingest guest %d snapshot %s: %w", g.VMID, sn.Name, err)
			}
			rep.Snapshots++
		}
	}
	return s.setGuestDatasetStatus(ctx, tx, obs.RemoteID, g.VMID, g.Generation, DatasetSnapshots, state, obs, reason)
}

// ingestGuestBackups inserts one guest's backup evidence records and records
// its status. Evidence is accumulated and updated, never deleted.
func (s *Store) ingestGuestBackups(ctx context.Context, tx *sql.Tx, obs pvecontract.Observation, g pvecontract.GuestObservation, rep *guestDetailsIngest) error {
	state, reason := storedState(g.Backups.State, g.Backups.Reason, obs.Complete, obs.Reason, false)
	if g.Backups.State == pvecontract.Available {
		for _, b := range g.Backups.Value {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO pve_backup_observations (remote_id, vmid, generation, source, kind,
				                                     name, status, started_unix, finished_unix,
				                                     verified, observed_at, collection_generation)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (remote_id, vmid, generation, source, kind, name, started_unix) DO UPDATE SET
					status = excluded.status,
					finished_unix = excluded.finished_unix,
					verified = excluded.verified,
					observed_at = excluded.observed_at,
					collection_generation = excluded.collection_generation`,
				obs.RemoteID, g.VMID, g.Generation, b.Source, b.Kind, b.Name, b.Status,
				b.StartedUnix, b.FinishedUnix, string(b.Verified), s.formatTime(obs.ObservedAt),
				obs.CollectionGeneration); err != nil {
				return fmt.Errorf("pveinventory: ingest guest %d backup %s: %w", g.VMID, b.Name, err)
			}
			rep.Backups++
		}
	}
	return s.setGuestDatasetStatus(ctx, tx, obs.RemoteID, g.VMID, g.Generation, DatasetBackups, state, obs, reason)
}

// ingestStorages upserts the storage dataset and records its status.
func (s *Store) ingestStorages(ctx context.Context, obs pvecontract.Observation) (int, error) {
	state, reason := storedState(obs.Storages.State, obs.Storages.Reason, obs.Complete, obs.Reason, true)
	var n int
	err := s.withObservationTx(ctx, obs, func(tx *sql.Tx) error {
		if obs.Storages.State == pvecontract.Available {
			for _, st := range obs.Storages.Value {
				contentJSON, err := json.Marshal(st.Content)
				if err != nil {
					return fmt.Errorf("pveinventory: storage %s content: %w", st.Name, err)
				}
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO pve_storages (remote_id, node, name, type, format, content_json, active,
					                         shared, size_bytes, free_bytes, observed_at, source, state,
					                         reason, collection_generation)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT (remote_id, node, name) DO UPDATE SET
						type                  = excluded.type,
						format                = excluded.format,
						content_json          = excluded.content_json,
						active                = excluded.active,
						shared                = excluded.shared,
						size_bytes            = excluded.size_bytes,
						free_bytes            = excluded.free_bytes,
						observed_at           = excluded.observed_at,
						source                = excluded.source,
						state                 = excluded.state,
						reason                = excluded.reason,
						collection_generation = MAX(pve_storages.collection_generation, excluded.collection_generation)`,
					obs.RemoteID, st.Node, st.Name, st.Type, st.Format, string(contentJSON),
					boolToInt(st.Active), boolToInt(st.Shared), st.SizeBytes, st.FreeBytes,
					s.formatTime(obs.ObservedAt), obs.Source, string(state), reason,
					obs.CollectionGeneration); err != nil {
					return fmt.Errorf("pveinventory: ingest storage %s: %w", st.Name, err)
				}
				n++
			}
		}
		return s.setDatasetStatus(ctx, tx, obs.RemoteID, DatasetStorages, state, obs, reason)
	})
	return n, err
}

// ingestCluster upserts the cluster/HA summary and records its status.
func (s *Store) ingestCluster(ctx context.Context, obs pvecontract.Observation) (bool, error) {
	state, reason := storedState(obs.Cluster.State, obs.Cluster.Reason, obs.Complete, obs.Reason, false)
	var done bool
	err := s.withObservationTx(ctx, obs, func(tx *sql.Tx) error {
		if obs.Cluster.State == pvecontract.Available {
			nodesJSON, err := json.Marshal(obs.Cluster.Value.Nodes)
			if err != nil {
				return fmt.Errorf("pveinventory: cluster nodes: %w", err)
			}
			haJSON, err := json.Marshal(obs.Cluster.Value.HAResources)
			if err != nil {
				return fmt.Errorf("pveinventory: cluster ha: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO pve_cluster_status (remote_id, quorum, nodes_json, ha_resources_json,
				                               observed_at, source, state, reason,
				                               collection_generation)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (remote_id) DO UPDATE SET
					quorum                = excluded.quorum,
					nodes_json            = excluded.nodes_json,
					ha_resources_json     = excluded.ha_resources_json,
					observed_at           = excluded.observed_at,
					source                = excluded.source,
					state                 = excluded.state,
					reason                = excluded.reason,
					collection_generation = MAX(pve_cluster_status.collection_generation, excluded.collection_generation)`,
				obs.RemoteID, obs.Cluster.Value.Quorum, string(nodesJSON), string(haJSON),
				s.formatTime(obs.ObservedAt), obs.Source, string(state), reason,
				obs.CollectionGeneration); err != nil {
				return fmt.Errorf("pveinventory: ingest cluster: %w", err)
			}
			done = true
		}
		return s.setDatasetStatus(ctx, tx, obs.RemoteID, DatasetCluster, state, obs, reason)
	})
	return done, err
}

// ingestTasks inserts the task metadata and records its status. Task rows
// are historical: they are accumulated and updated, never deleted
// except by explicit retention.
func (s *Store) ingestTasks(ctx context.Context, obs pvecontract.Observation) (int, error) {
	state, reason := storedState(obs.Tasks.State, obs.Tasks.Reason, obs.Complete, obs.Reason, true)
	var n int
	err := s.withObservationTx(ctx, obs, func(tx *sql.Tx) error {
		if obs.Tasks.State == pvecontract.Available {
			for _, t := range obs.Tasks.Value {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO pve_tasks (remote_id, node, actor, type, target, started_unix,
					                      exit_status, observed_at, source, collection_generation)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT (remote_id, node, started_unix, actor, type, target) DO UPDATE SET
						exit_status = excluded.exit_status,
						observed_at = excluded.observed_at,
						source = excluded.source,
						collection_generation = excluded.collection_generation`,
					obs.RemoteID, t.Node, t.Actor, t.Type, t.Target, t.StartedUnix,
					t.ExitStatus, s.formatTime(obs.ObservedAt), obs.Source,
					obs.CollectionGeneration); err != nil {
					return fmt.Errorf("pveinventory: ingest task %s: %w", t.Target, err)
				}
				n++
			}
		}
		return s.setDatasetStatus(ctx, tx, obs.RemoteID, DatasetTasks, state, obs, reason)
	})
	return n, err
}
