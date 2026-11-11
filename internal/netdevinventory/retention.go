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

// countCapped reports whether the superseded datasets of read are capped
// at MaxSnapshotsPerRead (facts, ports, VLANs, firewall policy). MAC, LLDP
// and hit-count history is spaced by MinHistorySpacing instead, and its
// cap follows from that spacing (see MaxHistoryPerRead).
func countCapped(r Read) bool { return HistoryRetention(r) == SnapshotRetention }

// MinHistorySpacing returns the minimum distance in observed_at between two
// superseded datasets of read that ReplaceDataset keeps, or 0 for reads
// capped at MaxSnapshotsPerRead. It is half the poll interval, so normal
// polling keeps every dataset while denser writes collapse.
func MinHistorySpacing(r Read) time.Duration {
	if countCapped(r) || PollInterval(r) == 0 {
		return 0
	}
	return PollInterval(r) / 2
}

// MaxHistoryPerRead returns the most superseded datasets one (device,
// read) keeps: MaxSnapshotsPerRead for count-capped reads, and
// HistoryRetention/MinHistorySpacing + 1 for MAC, LLDP and hit counts
// (more than normal polling produces over the window, so the cap only
// bites on a replaying or misbehaving writer).
func MaxHistoryPerRead(r Read) int {
	if sp := MinHistorySpacing(r); sp > 0 {
		return int(HistoryRetention(r)/sp) + 1
	}
	return MaxSnapshotsPerRead
}

// boundHistory enforces the history limits of read inside tx: superseded
// datasets observed before now minus HistoryRetention are removed, and
// the remaining superseded datasets are trimmed to MaxHistoryPerRead per
// device, oldest first. Current datasets are never removed. With
// deviceID empty it applies to every device (Prune); ReplaceDataset calls
// it for the written (device, read) in its own transaction, so the bound
// holds after every write whether or not Prune runs. Rows of removed
// datasets go with them (ON DELETE CASCADE).
func boundHistory(ctx context.Context, tx *sql.Tx, read Read, deviceID string, now time.Time) (int64, error) {
	aged, err := dropAgedHistory(ctx, tx, read, deviceID, now)
	if err != nil {
		return 0, err
	}
	devFilter := ""
	if deviceID != "" {
		devFilter = " AND device_id = ?"
	}
	args := []any{string(read)}
	if deviceID != "" {
		args = append(args, deviceID)
	}
	args = append(args, MaxHistoryPerRead(read))
	capped, err := exec(ctx, tx, `DELETE FROM netdev_datasets WHERE current = 0 AND id IN (
		SELECT id FROM (
			SELECT id, ROW_NUMBER() OVER (PARTITION BY device_id ORDER BY observed_at DESC, id DESC) AS rn
			FROM netdev_datasets WHERE read = ? AND current = 0`+devFilter+`)
		WHERE rn > ?)`, args...)
	if err != nil {
		return 0, fmt.Errorf("netdevinventory: cap %s history: %w", read, err)
	}
	return aged + capped, nil
}

// dropAgedHistory removes the superseded datasets of read observed before
// now minus HistoryRetention, for deviceID or (empty) every device. For
// one device it is a range delete on idx_netdev_datasets_history.
func dropAgedHistory(ctx context.Context, tx *sql.Tx, read Read, deviceID string, now time.Time) (int64, error) {
	devFilter := ""
	args := []any{string(read), micros(now.Add(-HistoryRetention(read)))}
	if deviceID != "" {
		devFilter = " AND device_id = ?"
		args = append(args, deviceID)
	}
	n, err := exec(ctx, tx, `DELETE FROM netdev_datasets
		WHERE read = ? AND current = 0 AND observed_at < ?`+devFilter, args...)
	if err != nil {
		return 0, fmt.Errorf("netdevinventory: drop aged %s history: %w", read, err)
	}
	return n, nil
}

// boundUnchanged enforces the retention window of (deviceID, read) on a
// write that keeps the current dataset (identical payload or redelivery):
// superseded datasets that left the window are removed, and so are rows
// carried over with a seen_at before it, in every kept dataset of the
// (device, read). The current dataset itself is not rewritten. Such a
// write adds no history, so the count cap cannot be newly exceeded and is
// not rechecked.
func boundUnchanged(ctx context.Context, tx *sql.Tx, read Read, deviceID string, now time.Time) error {
	if _, err := dropAgedHistory(ctx, tx, read, deviceID, now); err != nil {
		return err
	}
	_, err := dropExpiredCarried(ctx, tx, read, deviceID, now)
	return err
}

// dropExpiredCarried removes rows carried over with a seen_at before now
// minus HistoryRetention from every dataset of read, current or
// superseded, for deviceID or (empty) every device. For one device it is
// one DELETE per row table: the datasets come from
// idx_netdev_datasets_history (at most MaxHistoryPerRead + 1 after the
// bound) and their rows from the (dataset_id, row_key) primary key.
func dropExpiredCarried(ctx context.Context, tx *sql.Tx, read Read, deviceID string, now time.Time) (int64, error) {
	devFilter := ""
	args := []any{micros(now.Add(-HistoryRetention(read))), string(read)}
	if deviceID != "" {
		devFilter = " AND device_id = ?"
		args = append(args, deviceID)
	}
	var total int64
	for _, t := range readTables(read) {
		n, err := exec(ctx, tx, `DELETE FROM `+t.name+` WHERE seen_at IS NOT NULL AND seen_at < ?
			AND dataset_id IN (SELECT id FROM netdev_datasets WHERE read = ?`+devFilter+`)`, args...)
		if err != nil {
			return 0, fmt.Errorf("netdevinventory: drop expired carried %s rows: %w", t.name, err)
		}
		total += n
	}
	return total, nil
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

// Prune applies the Q11 retention in one transaction: the bulk, periodic
// form of the history bound ReplaceDataset already enforces per write
// (boundHistory over all devices), plus removal of expired carried rows
// and of config versions. Superseded datasets age out of their window
// even for a device that is no longer written. It never removes the
// current (newest) dataset of a (device, read), a device, the newest
// config version of a (device, config), the approved baseline or a
// version bound to a change in the last ConfigVersionRetention.
func (s *Store) Prune(ctx context.Context) (PruneReport, error) {
	now := s.now()
	var rep PruneReport
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		for _, rd := range Reads {
			n, err := boundHistory(ctx, tx, rd, "", now)
			if err != nil {
				return err
			}
			rep.Datasets += n
			n, err = dropExpiredCarried(ctx, tx, rd, "", now)
			if err != nil {
				return err
			}
			rep.CarriedRows += n
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
