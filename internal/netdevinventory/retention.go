// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Retention of ADR 0010 Q11 (decided 2026-11-09 as proposed).
const (
	// MACLLDPRetention is how long MAC table and LLDP history is kept.
	MACLLDPRetention = 21 * 24 * time.Hour
	// HitCountRetention is how long hit-count samples are kept.
	HitCountRetention = 90 * 24 * time.Hour
	// ConfigVersionRetention is how long config versions are kept.
	ConfigVersionRetention = 400 * 24 * time.Hour
	// MaxConfigVersionsPerDevice bounds the config versions of one device.
	MaxConfigVersionsPerDevice = 1000
	// SnapshotRetention is how long superseded facts, port, VLAN and
	// firewall policy datasets are kept. Q11 names no window for them; they
	// are stored only when they change, so they follow the config version
	// window (assumption of ND-16, see the report).
	SnapshotRetention = ConfigVersionRetention
	// MaxSnapshotsPerRead bounds the superseded datasets of one (device,
	// read) kept under SnapshotRetention, like MaxConfigVersionsPerDevice.
	MaxSnapshotsPerRead = MaxConfigVersionsPerDevice
)

// HistoryRetention returns how long superseded datasets of read, and rows
// carried over as absent within a dataset, are kept.
func HistoryRetention(r Read) time.Duration {
	switch r {
	case ReadMACTable, ReadLLDPNeighbors:
		return MACLLDPRetention
	case ReadHitCounts:
		return HitCountRetention
	}
	return SnapshotRetention
}

// countCapped reports whether the superseded datasets of read are also
// bounded by MaxSnapshotsPerRead. MAC, LLDP and hit-count history is
// bounded by its time window and MinHistorySpacing instead.
func countCapped(r Read) bool { return HistoryRetention(r) == SnapshotRetention }

// MinHistorySpacing returns the minimum distance in observed_at between two
// superseded datasets of read that ReplaceDataset keeps, or 0 for reads
// bounded by MaxSnapshotsPerRead. It is half the poll interval, so normal
// polling keeps every dataset, while a replaying or misbehaving writer
// cannot grow MAC, LLDP or hit-count history beyond
// HistoryRetention/MinHistorySpacing + 1 superseded datasets per (device,
// read), whatever its rate.
func MinHistorySpacing(r Read) time.Duration {
	if countCapped(r) || PollInterval(r) == 0 {
		return 0
	}
	return PollInterval(r) / 2
}

// PruneReport counts what Prune removed.
type PruneReport struct {
	// Datasets is the number of superseded datasets removed (with their
	// rows).
	Datasets int64
	// CarriedRows is the number of carried rows removed from datasets that
	// were kept.
	CarriedRows int64
	// ConfigVersions is the number of config versions removed.
	ConfigVersions int64
}

// Prune applies the Q11 retention in one transaction. It never removes
// the current (newest) dataset of a (device, read), a device, the newest
// config version of a (device, config), the approved baseline or a
// version bound to a change in the last ConfigVersionRetention.
func (s *Store) Prune(ctx context.Context) (PruneReport, error) {
	now := s.now()
	var rep PruneReport
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		for _, rd := range Reads {
			cutoff := micros(now.Add(-HistoryRetention(rd)))
			n, err := exec(ctx, tx, `DELETE FROM netdev_datasets
				WHERE read = ? AND current = 0 AND observed_at < ?`, string(rd), cutoff)
			if err != nil {
				return fmt.Errorf("netdevinventory: prune %s datasets: %w", rd, err)
			}
			rep.Datasets += n
			if countCapped(rd) {
				n, err := exec(ctx, tx, `DELETE FROM netdev_datasets WHERE current = 0 AND id IN (
					SELECT id FROM (
						SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY observed_at DESC, id DESC) AS rn
						FROM netdev_datasets WHERE read = ? AND current = 0)
					WHERE rn > ?)`, string(rd), MaxSnapshotsPerRead)
				if err != nil {
					return fmt.Errorf("netdevinventory: cap %s datasets: %w", rd, err)
				}
				rep.Datasets += n
			}
			for _, t := range readTables(rd) {
				n, err := exec(ctx, tx, `DELETE FROM `+t.name+` WHERE seen_at IS NOT NULL AND seen_at < ?
					AND dataset_id IN (SELECT id FROM netdev_datasets WHERE read = ?)`, cutoff, string(rd))
				if err != nil {
					return fmt.Errorf("netdevinventory: prune carried %s rows: %w", t.name, err)
				}
				rep.CarriedRows += n
			}
		}
		n, err := pruneConfigVersions(ctx, tx, now)
		if err != nil {
			return err
		}
		rep.ConfigVersions = n
		return nil
	})
	if err != nil {
		return PruneReport{}, err
	}
	return rep, nil
}

// configProtected is the SQL condition (over netdev_config_versions v) of a
// version retention must keep: the baseline, a version bound to a change
// at or after ?1, and the newest version of its (device, config).
const configProtected = `(v.baseline = 1
	OR (v.change_bound_at IS NOT NULL AND v.change_bound_at >= ?)
	OR v.id = (SELECT n.id FROM netdev_config_versions n
		WHERE n.device_id = v.device_id AND n.config = v.config
		ORDER BY n.last_seen DESC, n.id DESC LIMIT 1))`

func pruneConfigVersions(ctx context.Context, tx *sql.Tx, now time.Time) (int64, error) {
	cutoff := micros(now.Add(-ConfigVersionRetention))
	aged, err := exec(ctx, tx, `DELETE FROM netdev_config_versions WHERE id IN (
		SELECT v.id FROM netdev_config_versions v WHERE v.last_seen < ? AND NOT `+configProtected+`)`,
		cutoff, cutoff)
	if err != nil {
		return 0, fmt.Errorf("netdevinventory: prune config versions: %w", err)
	}
	// Over the count limit, the oldest unprotected versions go first.
	// Protected versions count against the limit but are never removed, so
	// a device keeps at most the limit unless its protected versions alone
	// exceed it.
	capped, err := exec(ctx, tx, `WITH
		p AS (SELECT v.id, v.device_id, v.last_seen, `+configProtected+` AS prot FROM netdev_config_versions v),
		u AS (SELECT id, device_id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY last_seen DESC, id DESC) AS rn
			FROM p WHERE prot = 0),
		c AS (SELECT device_id, SUM(prot) AS np FROM p GROUP BY device_id)
		DELETE FROM netdev_config_versions WHERE id IN (
			SELECT u.id FROM u JOIN c ON c.device_id = u.device_id WHERE u.rn > ? - c.np)`,
		cutoff, MaxConfigVersionsPerDevice)
	if err != nil {
		return 0, fmt.Errorf("netdevinventory: cap config versions: %w", err)
	}
	return aged + capped, nil
}

func exec(ctx context.Context, tx *sql.Tx, q string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
