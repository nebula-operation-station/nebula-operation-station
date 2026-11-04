// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

// Provider-reported guest NICs (ADR 0009 D1 tier 2, TM14).
//
// The pve-collector reports, per remote, every guest netN device with its
// bridge, VLAN tag and MAC. These are the provider's claims about guest
// configuration, not observations of traffic, so they are kept in their
// own tables (migration 0034) under the fixed source SourceProvider and
// never enter the observed tiers: they create no endpoint, carry no
// address and change no reporter claim. A provider NIC is related to an
// observed endpoint only by MAC, at read time, on the server
// (EndpointGuestLinks), the same way server-side matching sets the
// IPAM/host links (SetEndpointLinks).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// SourceProvider is the source label of every guest NIC link. It is not
// an observed tier: UpsertEndpoint and UpsertBucket refuse it.
const SourceProvider = "provider"

// Guest NIC bounds, next to the code that enforces them.
const (
	// MaxGuestNICRemotes bounds the remotes with a stored snapshot.
	MaxGuestNICRemotes = 256
	// MaxGuestNICsPerRemote bounds the NICs in one remote's snapshot; it
	// matches the collector's record bound (pvecollect.MaxGuestNetNICs).
	MaxGuestNICsPerRemote = 16_384
	// MaxGuestNICs bounds the stored NICs across all remotes.
	MaxGuestNICs = 100_000
	// MaxGuestNICIndex is one past the highest netN index Proxmox
	// accepts (net0 … net31).
	MaxGuestNICIndex = 32
	// maxGuestLinks bounds the links one MAC or endpoint query returns.
	maxGuestLinks = 64
)

// countGuestNICs is the traffic_counts name of the guest NIC total
// (migration 0034).
const countGuestNICs = "guest_nics"

var (
	// ErrInvalidGuestNIC marks a malformed guest NIC snapshot.
	ErrInvalidGuestNIC = errors.New("trafficstore: invalid guest nic snapshot")
	// ErrStaleSnapshot marks a guest NIC snapshot older than the stored
	// snapshot of its remote; it is refused so a replay cannot roll the
	// remote back.
	ErrStaleSnapshot = errors.New("trafficstore: guest nic snapshot older than the stored one")
)

// GuestNIC is one provider-reported guest netN device.
type GuestNIC struct {
	// VMID is the guest's Proxmox VMID.
	VMID uint64
	// Kind is the guest kind (qemu or lxc).
	Kind pvecontract.GuestKind
	// Index is N of netN.
	Index int
	// Bridge is the Linux bridge or SDN vnet, "" when the NIC has none.
	Bridge string
	// VLAN is the 802.1Q tag, 0 when untagged.
	VLAN int
	// MAC is the lowercase unicast aa:bb:cc:dd:ee:ff MAC.
	MAC string
}

// GuestNICSnapshot is one remote's complete guest NIC set at one time.
type GuestNICSnapshot struct {
	// Remote is the Proxmox remote ID the collector read.
	Remote string
	// ObservedAt is when the collector read the configuration.
	ObservedAt time.Time
	// NICs is the complete set; (VMID, Index) is unique.
	NICs []GuestNIC
}

// GuestLink is a stored provider guest NIC as returned by the queries.
type GuestLink struct {
	// Source is always SourceProvider.
	Source string
	// Remote is the reporting Proxmox remote.
	Remote string
	// VMID, Kind and Index identify the guest NIC on the remote.
	VMID  uint64
	Kind  pvecontract.GuestKind
	Index int
	// Bridge and VLAN are the provider's configuration claims.
	Bridge string
	VLAN   int
	// MAC is the NIC's MAC, the only key matched against endpoints.
	MAC string
	// ObservedAt is the observation time of the remote's snapshot.
	ObservedAt time.Time
}

// validGuestMAC reports whether mac is a lowercase, non-zero unicast MAC.
func validGuestMAC(mac string) bool {
	if !macRE.MatchString(mac) || mac == "00:00:00:00:00:00" {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && b&1 == 0
}

// validateGuestSnapshot checks snap against the store's clock and
// retention and returns its NICs in (VMID, Index) order. Error texts
// never quote the untrusted values.
func (s *Store) validateGuestSnapshot(snap GuestNICSnapshot) ([]GuestNIC, error) {
	if !pvecontract.ValidRemoteID(snap.Remote) {
		return nil, fmt.Errorf("%w: malformed remote", ErrInvalidGuestNIC)
	}
	if snap.ObservedAt.Unix() <= 0 {
		return nil, fmt.Errorf("%w: remote %s: observation time not positive", ErrInvalidGuestNIC, snap.Remote)
	}
	now := s.now()
	if snap.ObservedAt.After(now.Add(maxClockSkew)) {
		return nil, fmt.Errorf("%w: remote %s: observation time in the future", ErrInvalidGuestNIC, snap.Remote)
	}
	if snap.ObservedAt.Before(now.Add(-s.retention)) {
		return nil, fmt.Errorf("trafficstore: guest nic snapshot of remote %s: %w", snap.Remote, ErrOutOfRange)
	}
	if len(snap.NICs) > MaxGuestNICsPerRemote {
		return nil, fmt.Errorf("trafficstore: remote %s: %d guest nics exceed %d: %w", snap.Remote, len(snap.NICs), MaxGuestNICsPerRemote, ErrLimit)
	}
	nics := slices.Clone(snap.NICs)
	slices.SortFunc(nics, func(a, b GuestNIC) int {
		if a.VMID != b.VMID {
			if a.VMID < b.VMID {
				return -1
			}
			return 1
		}
		return a.Index - b.Index
	})
	for i, n := range nics {
		if n.VMID < pvecontract.MinVMID || n.VMID > pvecontract.MaxVMID {
			return nil, fmt.Errorf("%w: remote %s: vmid out of range", ErrInvalidGuestNIC, snap.Remote)
		}
		where := fmt.Sprintf("remote %s vmid %d", snap.Remote, n.VMID)
		switch {
		case n.Kind != pvecontract.GuestQEMU && n.Kind != pvecontract.GuestLXC:
			return nil, fmt.Errorf("%w: %s: unknown kind", ErrInvalidGuestNIC, where)
		case n.Index < 0 || n.Index >= MaxGuestNICIndex:
			return nil, fmt.Errorf("%w: %s: nic index out of range", ErrInvalidGuestNIC, where)
		case n.Bridge != "" && !pvecontract.ValidBridgeName(n.Bridge):
			return nil, fmt.Errorf("%w: %s net%d: malformed bridge", ErrInvalidGuestNIC, where, n.Index)
		case n.VLAN < 0 || n.VLAN > pvecontract.MaxVLAN:
			return nil, fmt.Errorf("%w: %s net%d: vlan out of range", ErrInvalidGuestNIC, where, n.Index)
		case !validGuestMAC(n.MAC):
			return nil, fmt.Errorf("%w: %s net%d: mac is not a lowercase unicast mac", ErrInvalidGuestNIC, where, n.Index)
		case i > 0 && nics[i-1].VMID == n.VMID && nics[i-1].Index == n.Index:
			return nil, fmt.Errorf("%w: %s net%d: duplicated", ErrInvalidGuestNIC, where, n.Index)
		}
	}
	return nics, nil
}

// SQL of the guest NIC store; package-level so the tests can check the
// query plans.
const (
	guestSnapshotSQL       = `SELECT observed_at FROM net_guest_nic_snapshots WHERE remote = ?`
	countGuestRemotesSQL   = `SELECT COUNT(*) FROM net_guest_nic_snapshots`
	countRemoteGuestNICSQL = `SELECT COUNT(*) FROM net_guest_nics WHERE remote = ?`
	upsertGuestSnapshotSQL = `
		INSERT INTO net_guest_nic_snapshots (remote, observed_at, imported_at) VALUES (?, ?, ?)
		ON CONFLICT (remote) DO UPDATE SET observed_at = excluded.observed_at, imported_at = excluded.imported_at`
	deleteGuestNICsSQL = `DELETE FROM net_guest_nics WHERE remote = ?`
	insertGuestNICSQL  = `
		INSERT INTO net_guest_nics (remote, vmid, nic_index, kind, bridge, vlan, mac)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	pruneGuestSnapshotsSQL = `DELETE FROM net_guest_nic_snapshots WHERE observed_at < ?`

	guestLinkColumns = `g.remote, g.vmid, g.nic_index, g.kind, g.bridge, g.vlan, g.mac, s.observed_at
		FROM net_guest_nics g JOIN net_guest_nic_snapshots s ON s.remote = g.remote`
	guestNICsByRemoteSQL = `SELECT ` + guestLinkColumns + `
		WHERE g.remote = ? ORDER BY g.vmid, g.nic_index LIMIT ?`
	guestNICsByMACSQL = `SELECT ` + guestLinkColumns + `
		WHERE g.mac = ? ORDER BY g.remote, g.vmid, g.nic_index LIMIT ?`
	endpointMACSQL = `SELECT mac FROM net_endpoints WHERE id = ?`
)

// ReplaceGuestNICs stores snap as the remote's current provider guest NIC
// set, replacing the remote's previous set as a whole. A snapshot older
// than the stored one is refused with ErrStaleSnapshot (the same one
// again is an idempotent retry); one older than the retention with
// ErrOutOfRange; a malformed one with ErrInvalidGuestNIC; one that would
// exceed the remote, per-remote or total bound with ErrLimit. Nothing is
// written into the observed endpoint tables.
func (s *Store) ReplaceGuestNICs(ctx context.Context, snap GuestNICSnapshot) error {
	nics, err := s.validateGuestSnapshot(snap)
	if err != nil {
		return err
	}
	if len(nics) > s.guestNICCapRemote {
		return fmt.Errorf("trafficstore: remote %s: %d guest nics exceed %d: %w", snap.Remote, len(nics), s.guestNICCapRemote, ErrLimit)
	}
	s.autoPrune(ctx)
	observed := snap.ObservedAt.Unix()
	return s.writeTx(ctx, "replace guest nics", func(tx *sql.Tx) error {
		var stored int64
		err := tx.QueryRowContext(ctx, guestSnapshotSQL, snap.Remote).Scan(&stored)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			var remotes int
			if err := tx.QueryRowContext(ctx, countGuestRemotesSQL).Scan(&remotes); err != nil {
				return fmt.Errorf("trafficstore: count guest nic remotes: %w", err)
			}
			if remotes >= s.guestRemoteCap {
				return fmt.Errorf("trafficstore: guest nic remotes at %d: %w", s.guestRemoteCap, ErrLimit)
			}
		case err != nil:
			return fmt.Errorf("trafficstore: read guest nic snapshot of %s: %w", snap.Remote, err)
		case observed < stored:
			return fmt.Errorf("trafficstore: remote %s: %w", snap.Remote, ErrStaleSnapshot)
		}
		total, err := readCount(ctx, tx, countGuestNICs, countTotal)
		if err != nil {
			return err
		}
		var own int
		if err := tx.QueryRowContext(ctx, countRemoteGuestNICSQL, snap.Remote).Scan(&own); err != nil {
			return fmt.Errorf("trafficstore: count guest nics of %s: %w", snap.Remote, err)
		}
		if total-own+len(nics) > s.guestNICCap {
			return fmt.Errorf("trafficstore: guest nics at %d: %w", s.guestNICCap, ErrLimit)
		}
		if _, err := tx.ExecContext(ctx, upsertGuestSnapshotSQL, snap.Remote, observed, s.now().Unix()); err != nil {
			return fmt.Errorf("trafficstore: store guest nic snapshot of %s: %w", snap.Remote, err)
		}
		if _, err := tx.ExecContext(ctx, deleteGuestNICsSQL, snap.Remote); err != nil {
			return fmt.Errorf("trafficstore: clear guest nics of %s: %w", snap.Remote, err)
		}
		stmt, err := tx.PrepareContext(ctx, insertGuestNICSQL)
		if err != nil {
			return fmt.Errorf("trafficstore: prepare guest nic insert: %w", err)
		}
		defer stmt.Close()
		for _, n := range nics {
			if _, err := stmt.ExecContext(ctx, snap.Remote, int64(n.VMID), n.Index, string(n.Kind), n.Bridge, n.VLAN, n.MAC); err != nil {
				return fmt.Errorf("trafficstore: store guest nic of %s vmid %d: %w", snap.Remote, n.VMID, err)
			}
		}
		return nil
	})
}

// GuestNICs returns the remote's stored provider guest NICs in (VMID,
// Index) order; none when the remote has no snapshot.
func (s *Store) GuestNICs(ctx context.Context, remote string) ([]GuestLink, error) {
	if !pvecontract.ValidRemoteID(remote) {
		return nil, fmt.Errorf("%w: malformed remote", ErrInvalidQuery)
	}
	return s.guestLinks(ctx, guestNICsByRemoteSQL, remote, MaxGuestNICsPerRemote)
}

// GuestLinksByMAC returns the provider guest NICs with the given MAC,
// ordered by remote, VMID and index, at most maxGuestLinks of them.
// Several remotes may report the same MAC (cloned guests); every claim is
// returned under its own remote and none is preferred.
func (s *Store) GuestLinksByMAC(ctx context.Context, mac string) ([]GuestLink, error) {
	if !validGuestMAC(mac) {
		return nil, fmt.Errorf("%w: malformed mac", ErrInvalidQuery)
	}
	return s.guestLinks(ctx, guestNICsByMACSQL, mac, maxGuestLinks)
}

// EndpointGuestLinks returns the provider guest NICs whose MAC equals the
// observed endpoint's MAC (server-side matching by MAC only; an endpoint
// without a MAC has none). It returns ErrNotFound when there is no such
// endpoint. The endpoint itself is not changed.
func (s *Store) EndpointGuestLinks(ctx context.Context, id string) ([]GuestLink, error) {
	var mac string
	err := s.db.QueryRowContext(ctx, endpointMACSQL, id).Scan(&mac)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("trafficstore: endpoint %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("trafficstore: read endpoint %s: %w", id, err)
	}
	if mac == "" {
		return nil, nil
	}
	return s.guestLinks(ctx, guestNICsByMACSQL, mac, maxGuestLinks)
}

// guestLinks runs one of the guest link queries with key and limit.
func (s *Store) guestLinks(ctx context.Context, query, key string, limit int) ([]GuestLink, error) {
	rows, err := s.db.QueryContext(ctx, query, key, limit)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: query guest nics: %w", err)
	}
	defer rows.Close()
	var out []GuestLink
	for rows.Next() {
		var (
			l        GuestLink
			vmid     int64
			kind     string
			observed int64
		)
		if err := rows.Scan(&l.Remote, &vmid, &l.Index, &kind, &l.Bridge, &l.VLAN, &l.MAC, &observed); err != nil {
			return nil, fmt.Errorf("trafficstore: scan guest nic: %w", err)
		}
		l.Source = SourceProvider
		l.VMID = uint64(vmid)
		l.Kind = pvecontract.GuestKind(kind)
		l.ObservedAt = time.Unix(observed, 0).UTC()
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("trafficstore: query guest nics: %w", err)
	}
	return out, nil
}

// CountGuestNICs returns the number of stored provider guest NICs.
func (s *Store) CountGuestNICs(ctx context.Context) (int, error) {
	return readCount(ctx, s.db, countGuestNICs, countTotal)
}
