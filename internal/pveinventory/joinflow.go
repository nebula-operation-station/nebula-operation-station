// SPDX-License-Identifier: AGPL-3.0-or-later

package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Server side of the join of a provisioned guest (ADR 0008 section 4,
// PV-06): propose the enrollment on the executor, and after the approval
// commit it there and create the inventory host and guest link from the
// executor's committed binding only.
//
// TODO(PV-08): the deployment run page ("enrolling" state, fingerprint
// review on the deployment page) calls GuestJoinFlow; it is constructed
// there with the server's executor client. Until then no server route
// reaches it.

// ErrJoinNotPinned is returned when the executor did not pin the approved
// key; no host is created.
var ErrJoinNotPinned = errors.New("pveinventory: the executor did not pin the approved host key")

// GuestJoinExecutor is the part of the executor client the join uses
// (server role).
type GuestJoinExecutor interface {
	ProposeGuestJoin(ctx context.Context, in *pb.ProposeGuestJoinRequest, opts ...grpc.CallOption) (*pb.ProposeGuestJoinResponse, error)
	CommitGuestJoin(ctx context.Context, in *pb.CommitGuestJoinRequest, opts ...grpc.CallOption) (*pb.CommitGuestJoinResponse, error)
}

// GuestJoinFlow joins provisioned guests.
type GuestJoinFlow struct {
	Store    *Store
	Executor GuestJoinExecutor
}

// GuestJoinProposal names the provisioned guest and the host it becomes.
type GuestJoinProposal struct {
	RemoteID   string
	Node       string
	VMID       uint64
	Generation uint64
	GuestName  string
	HostID     string
	// Endpoint is the guest's SSH endpoint.
	Endpoint      string
	SSHUser       string
	CredentialRef string
}

// Propose checks that the guest incarnation is the provisioned guest and
// the host ID is free, then asks the executor to propose the enrollment.
// The response carries the join method and fingerprint to show for
// approval; Commit takes it back unchanged.
func (f *GuestJoinFlow) Propose(ctx context.Context, p GuestJoinProposal) (*pb.ProposeGuestJoinResponse, error) {
	if f.Store == nil || f.Executor == nil {
		return nil, errors.New("pveinventory: guest join flow: Store and Executor are required")
	}
	if err := f.Store.checkJoinable(ctx, p.RemoteID, p.Node, p.VMID, p.Generation, p.GuestName, p.HostID); err != nil {
		return nil, err
	}
	return f.Executor.ProposeGuestJoin(ctx, &pb.ProposeGuestJoinRequest{
		Guest: &pb.GuestJoinTarget{RemoteId: p.RemoteID, Node: p.Node, Vmid: p.VMID, Generation: p.Generation, GuestName: p.GuestName},
		Host:  &pb.EnrollHost{HostId: p.HostID, Endpoint: p.Endpoint, SshUser: p.SSHUser, CredentialRef: p.CredentialRef},
	})
}

// Commit commits the approved join on the executor and, once the executor
// pinned the key, creates the inventory host and its guest link. host
// carries the inventory attributes (display name, environment, groups,
// tags, criticality); its ID, endpoint and credential must be the approved
// ones, the guest comes from the executor's committed binding.
func (f *GuestJoinFlow) Commit(ctx context.Context, proposal *pb.ProposeGuestJoinResponse, host inventory.Host, actor string) (GuestJoinResult, error) {
	if f.Store == nil || f.Executor == nil {
		return GuestJoinResult{}, errors.New("pveinventory: guest join flow: Store and Executor are required")
	}
	c, err := f.Executor.CommitGuestJoin(ctx, &pb.CommitGuestJoinRequest{
		ExecutionDigest: proposal.GetPermit().GetExecutionDigest(), Guest: proposal.GetGuest(),
		Host: proposal.GetHost(), JoinMethod: proposal.GetJoinMethod(),
	})
	if err != nil {
		return GuestJoinResult{}, fmt.Errorf("pveinventory: commit guest join: %w", err)
	}
	if !c.GetResult().GetPinned() {
		return GuestJoinResult{}, ErrJoinNotPinned
	}
	g, h := c.GetGuest(), c.GetHost()
	return f.Store.JoinProvisionedGuest(ctx, GuestJoin{
		RemoteID: g.GetRemoteId(), Node: g.GetNode(), VMID: g.GetVmid(), Generation: g.GetGeneration(),
		GuestName: g.GetGuestName(), Host: host, Actor: actor,
		Enrollment: CommittedEnrollment{
			Digest: c.GetExecutionDigest(), HostID: h.GetHostId(), Endpoint: h.GetEndpoint(),
			CredentialRef: h.GetCredentialRef(), Fingerprint: c.GetResult().GetFingerprint(),
			RemoteID: g.GetRemoteId(), Node: g.GetNode(), VMID: g.GetVmid(), Generation: g.GetGeneration(),
			GuestName: g.GetGuestName(), JoinMethod: c.GetJoinMethod(), Pinned: true,
		},
	})
}

// checkJoinable is the read-only precheck of a join: the incarnation is
// the active provisioned guest and the host ID is new.
func (s *Store) checkJoinable(ctx context.Context, remoteID, node string, vmid, generation uint64, name, hostID string) error {
	var kind, gotNode, gotName string
	err := s.db.QueryRowContext(ctx, `SELECT kind, node, name FROM pve_guests
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`,
		remoteID, vmid, generation).Scan(&kind, &gotNode, &gotName)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s/%d/%d", ErrGuestNotFound, remoteID, vmid, generation)
	}
	if err != nil {
		return fmt.Errorf("pveinventory: join: load guest %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	if kind != string(pvecontract.GuestQEMU) || gotNode != node || gotName != name {
		return fmt.Errorf("%w: %s/%d/%d", ErrJoinGuestMismatch, remoteID, vmid, generation)
	}
	if _, err := s.hostStore().Get(ctx, hostID); err == nil {
		return fmt.Errorf("pveinventory: join: %w: %s", inventory.ErrHostExists, hostID)
	} else if !errors.Is(err, inventory.ErrHostNotFound) {
		return fmt.Errorf("pveinventory: join: load host %s: %w", hostID, err)
	}
	return nil
}
