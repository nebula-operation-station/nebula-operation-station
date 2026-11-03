// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Join of a provisioned guest (ADR 0008 section 4, PV-06): the guest a
// pve.guest.provision run created becomes a managed inventory host linked
// to its incarnation (remote, node, VMID, generation), so the org chart
// shows it as enrolled. Host creation and link are one transaction; the
// host-key pin is the executor's (enrollment approval). The join takes the
// executor's committed enrollment (CommitGuestJoin) and refuses anything
// that is not exactly what was approved and pinned: no host is created
// before the key is pinned, and never for another host ID, endpoint or
// guest than the approved one.

// maxJoinGuestNameLen bounds the expected guest name (a DNS name).
const maxJoinGuestNameLen = 253

// ErrJoinGuestMismatch is returned when the stored incarnation is not the
// provisioned guest (another node, name or kind).
var ErrJoinGuestMismatch = errors.New("pveinventory: guest does not match the provisioned guest")

// ErrJoinNotApproved is returned when the join is not backed by a
// committed enrollment of exactly this host and guest.
var ErrJoinNotApproved = errors.New("pveinventory: join does not match the committed enrollment")

// Join methods of a committed enrollment (the executor's values).
const (
	JoinMethodAgent  = "agent"
	JoinMethodReview = "review"
)

// CommittedEnrollment is the executor's committed guest join
// (CommitGuestJoinResponse): the approved binding and the pin outcome.
type CommittedEnrollment struct {
	// Digest is the execution digest of the approved enrollment.
	Digest string
	HostID string
	// Endpoint is the approved SSH endpoint in the executor's canonical
	// host:port form.
	Endpoint      string
	CredentialRef string
	Fingerprint   string
	RemoteID      string
	Node          string
	VMID          uint64
	Generation    uint64
	GuestName     string
	// JoinMethod is JoinMethodAgent or JoinMethodReview.
	JoinMethod string
	// Pinned is set when the executor pinned the approved key.
	Pinned bool
}

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
	// Enrollment is the committed enrollment the join is backed by; it
	// must name exactly this host, its only endpoint and this guest.
	Enrollment CommittedEnrollment
}

// GuestJoinResult is the created host and link.
type GuestJoinResult struct {
	Host inventory.Host
	Link Link
	// Node is the node the incarnation was observed on.
	Node string
	// Fingerprint and JoinMethod are the committed pin and how its key was
	// established.
	Fingerprint string
	JoinMethod  string
}

// canonicalEndpoint is the executor's form of one inventory endpoint.
func canonicalEndpoint(ep inventory.Endpoint) (string, error) {
	addr := ep.Address
	if ep.Port != 0 {
		addr = net.JoinHostPort(ep.Address, strconv.Itoa(ep.Port))
	}
	e, err := sshtransport.ParseEndpoint(addr)
	if err != nil {
		return "", err
	}
	return e.String(), nil
}

// checkEnrollment ties the join to the committed enrollment.
func (j GuestJoin) checkEnrollment() error {
	c := j.Enrollment
	switch {
	case !c.Pinned:
		return fmt.Errorf("%w: the host key is not pinned", ErrJoinNotApproved)
	case !canonical.ValidSHA256Hex(c.Digest):
		return fmt.Errorf("%w: digest", ErrJoinNotApproved)
	case !canonical.ValidHostKeyFingerprint(c.Fingerprint):
		return fmt.Errorf("%w: fingerprint", ErrJoinNotApproved)
	case c.JoinMethod != JoinMethodAgent && c.JoinMethod != JoinMethodReview:
		return fmt.Errorf("%w: join method", ErrJoinNotApproved)
	case c.HostID != j.Host.ID:
		return fmt.Errorf("%w: host %q is not the approved host", ErrJoinNotApproved, j.Host.ID)
	case c.RemoteID != j.RemoteID || c.Node != j.Node || c.VMID != j.VMID || c.Generation != j.Generation ||
		c.GuestName != j.GuestName:
		return fmt.Errorf("%w: guest %s/%d/%d is not the approved guest", ErrJoinNotApproved, j.RemoteID, j.VMID, j.Generation)
	case j.Host.CredentialRef != "" && j.Host.CredentialRef != c.CredentialRef:
		return fmt.Errorf("%w: credential", ErrJoinNotApproved)
	case len(j.Host.Endpoints) != 1:
		return fmt.Errorf("%w: the host must have exactly the approved endpoint", ErrJoinNotApproved)
	}
	approved, err := sshtransport.ParseEndpoint(c.Endpoint)
	if err != nil {
		return fmt.Errorf("%w: endpoint", ErrJoinNotApproved)
	}
	if got, err := canonicalEndpoint(j.Host.Endpoints[0]); err != nil || got != approved.String() {
		return fmt.Errorf("%w: endpoint is not the approved endpoint", ErrJoinNotApproved)
	}
	return nil
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
	return j.checkEnrollment()
}

// JoinProvisionedGuest creates the managed host for a provisioned guest and
// links it to the guest incarnation in one transaction. j.Enrollment must
// be the executor's committed, pinned enrollment of exactly this host (ID,
// only endpoint, credential) and guest (remote, node, VMID, generation,
// name). The incarnation must be active and be the provisioned guest
// (QEMU, node and name); the host ID must be new. Nothing is left behind
// on error. GuestJoinFlow.Commit is the caller that obtains j.Enrollment.
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
		Node: node, Fingerprint: j.Enrollment.Fingerprint, JoinMethod: j.Enrollment.JoinMethod,
	}, nil
}
