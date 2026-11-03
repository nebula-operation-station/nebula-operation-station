// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Join of a provisioned guest (ADR 0008 section 4, PV-06): the guest a
// pve.guest.provision run created becomes a managed inventory host linked
// to its incarnation (remote, node, VMID, generation), so the org chart
// shows it as enrolled. Host creation and link are one transaction; the
// host-key pin is the executor's (enrollment approval).

// maxJoinGuestNameLen bounds the expected guest name (a DNS name).
const maxJoinGuestNameLen = 253

// ErrJoinGuestMismatch is returned when the stored incarnation is not the
// provisioned guest (another node, name or kind).
var ErrJoinGuestMismatch = errors.New("pveinventory: guest does not match the provisioned guest")

// GuestJoin names a provisioned guest and the inventory host it becomes.
type GuestJoin struct {
	RemoteID   string
	Node       string
	VMID       uint64
	Generation uint64
	// GuestName is the name the provisioning gave the guest; the stored
	// incarnation must carry it.
	GuestName string
	// Host is created new; an existing host ID is refused. An unset
	// criticality is stored as HIGH (unknown counts as HIGH, spec 11) until
	// the operator records it.
	Host  inventory.Host
	Actor string
}

// GuestJoinResult is the created host and link.
type GuestJoinResult struct {
	Host inventory.Host
	Link Link
	// Node is the node the incarnation was observed on.
	Node string
}

func (j GuestJoin) validate() error {
	if err := validActor(j.Actor); err != nil {
		return err
	}
	switch {
	case !pvecontract.ValidRemoteID(j.RemoteID):
		return fmt.Errorf("pveinventory: join: invalid remote %q", j.RemoteID)
	case !pvecontract.ValidNodeName(j.Node):
		return fmt.Errorf("pveinventory: join: invalid node %q", j.Node)
	case j.VMID < pvecontract.MinVMID || j.VMID > pvecontract.MaxVMID:
		return fmt.Errorf("pveinventory: join: vmid %d out of range", j.VMID)
	case j.Generation < 1:
		return errors.New("pveinventory: join: generation must be at least 1")
	case j.GuestName == "" || len(j.GuestName) > maxJoinGuestNameLen || !utf8.ValidString(j.GuestName):
		return fmt.Errorf("pveinventory: join: guest name must be valid UTF-8 of 1..%d bytes", maxJoinGuestNameLen)
	}
	return nil
}

// JoinProvisionedGuest creates the managed host for a provisioned guest and
// links it to the guest incarnation in one transaction. The incarnation
// must be active and be the provisioned guest (QEMU, node and name); the
// host ID must be new. Nothing is left behind on error.
func (s *Store) JoinProvisionedGuest(ctx context.Context, j GuestJoin) (GuestJoinResult, error) {
	if err := j.validate(); err != nil {
		return GuestJoinResult{}, err
	}
	h := j.Host
	if h.Criticality == "" {
		h.Criticality = inventory.CriticalityHigh
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GuestJoinResult{}, fmt.Errorf("pveinventory: begin join: %w", err)
	}
	defer tx.Rollback()

	var kind, node, name string
	err = tx.QueryRowContext(ctx, `SELECT kind, node, name FROM pve_guests
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`,
		j.RemoteID, j.VMID, j.Generation).Scan(&kind, &node, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return GuestJoinResult{}, fmt.Errorf("%w: %s/%d/%d", ErrGuestNotFound, j.RemoteID, j.VMID, j.Generation)
	}
	if err != nil {
		return GuestJoinResult{}, fmt.Errorf("pveinventory: join: load guest %s/%d/%d: %w", j.RemoteID, j.VMID, j.Generation, err)
	}
	if kind != string(pvecontract.GuestQEMU) || node != j.Node || name != j.GuestName {
		return GuestJoinResult{}, fmt.Errorf("%w: %s/%d/%d", ErrJoinGuestMismatch, j.RemoteID, j.VMID, j.Generation)
	}

	h, err = s.hostStore().CreateTx(ctx, tx, h, inventory.CreateOptions{})
	if err != nil {
		return GuestJoinResult{}, err
	}
	now := s.formatTime(s.now())
	if err := s.createLinkTx(ctx, tx, j.RemoteID, j.VMID, j.Generation, h.ID, j.Actor, now); err != nil {
		return GuestJoinResult{}, err
	}
	// A staged (unmanaged) entry of the same incarnation is now imported.
	if _, err := tx.ExecContext(ctx, `
		UPDATE pve_staging SET imported_at = ?, imported_by = ?, imported_asset = ?
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND imported_at = ''`,
		now, j.Actor, h.ID, j.RemoteID, j.VMID, j.Generation); err != nil {
		return GuestJoinResult{}, fmt.Errorf("pveinventory: join: mark staging %s/%d/%d: %w", j.RemoteID, j.VMID, j.Generation, err)
	}
	if err := tx.Commit(); err != nil {
		return GuestJoinResult{}, fmt.Errorf("pveinventory: commit join: %w", err)
	}
	createdAt, _ := time.Parse(time.RFC3339, now)
	return GuestJoinResult{
		Host: h,
		Link: Link{RemoteID: j.RemoteID, VMID: j.VMID, Generation: j.Generation, HostID: h.ID, CreatedBy: j.Actor, CreatedAt: createdAt},
		Node: node,
	}, nil
}
