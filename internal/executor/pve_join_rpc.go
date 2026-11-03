// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Guest join approval binding, commit and RPC surface (ADR 0008 section 4,
// PV-06). The server proposes with ProposeGuestJoin, relays the approval
// and commits with CommitGuestJoin; from the committed binding it creates
// the inventory host and the guest link (pveinventory.GuestJoinFlow).

// ErrPveJoinNotApproved is returned by Commit when the request does not
// match an approved guest join; nothing is read or pinned.
var ErrPveJoinNotApproved = errors.New("executor: guest join does not match an approved join")

// pveGuestBinding is the guest part of a guest join approval.
type pveGuestBinding struct {
	RemoteID   string `json:"remote"`
	Node       string `json:"node"`
	VMID       uint64 `json:"vmid"`
	Generation uint64 `json:"generation"`
	Name       string `json:"name"`
	// JoinMethod is PveJoinMethodAgent or PveJoinMethodReview; the
	// approver sees whether the key was agent-verified.
	JoinMethod string `json:"join_method"`
}

func (b pveGuestBinding) proto() *pb.GuestJoinTarget {
	return &pb.GuestJoinTarget{RemoteId: b.RemoteID, Node: b.Node, Vmid: b.VMID, Generation: b.Generation, GuestName: b.Name}
}

// guestJoinParams is the canonical parameter document of a guest join: the
// enrollment document of the one host plus the guest binding. It never
// equals a bulk enrollment's document, so neither commit path can use the
// other's approval.
func guestJoinParams(e enrollEntry, b pveGuestBinding) ([]byte, error) {
	return json.Marshal(map[string]any{"hosts": []enrollEntry{e}, "criticality": "none (counts as HIGH)", "guest": b})
}

func guestJoinRequest(e enrollEntry, b pveGuestBinding, now time.Time) (canonical.Request, []byte, error) {
	params, err := guestJoinParams(e, b)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	return enrollRequestWith([]enrollEntry{e}, params, now)
}

// PveGuestJoinCommit is the committed guest join.
type PveGuestJoinCommit struct {
	Result *pb.EnrollResult
	// Host and Guest are the approved binding (normalized).
	Host       *pb.EnrollHost
	Guest      *pb.GuestJoinTarget
	JoinMethod string
}

// Commit pins the host key of an approved guest join. host, guest and
// method must be exactly the proposal's: they rebuild the approved
// parameters, so another host ID, endpoint, guest, generation or join
// method is not authorized. The endpoint must still present the approved
// key. It returns an error only when nothing could be authorized or the
// host key store failed; a refused pin is reported in Result.
func (j *PveGuestJoin) Commit(ctx context.Context, d canonical.Digest, host *pb.EnrollHost, guest *pb.GuestJoinTarget, method string) (PveGuestJoinCommit, error) {
	s := j.Service
	if s == nil {
		return PveGuestJoinCommit{}, errors.New("executor: pve guest join: Service is required")
	}
	req := PveGuestJoinRequest{RemoteID: guest.GetRemoteId(), Node: guest.GetNode(), VMID: guest.GetVmid(),
		Generation: guest.GetGeneration(), GuestName: guest.GetGuestName(), HostID: host.GetHostId(),
		Endpoint: host.GetEndpoint(), SSHUser: host.GetSshUser(), CredentialRef: host.GetCredentialRef()}
	e, err := req.validate()
	if err != nil {
		return PveGuestJoinCommit{}, err
	}
	if method != PveJoinMethodAgent && method != PveJoinMethodReview {
		return PveGuestJoinCommit{}, fmt.Errorf("%w: join method", ErrPveJoinInvalid)
	}
	if !canonical.ValidHostKeyFingerprint(host.GetFingerprint()) {
		return PveGuestJoinCommit{}, fmt.Errorf("%w: fingerprint", ErrPveJoinInvalid)
	}
	e.Fingerprint = host.GetFingerprint()
	b := pveGuestBinding{RemoteID: req.RemoteID, Node: req.Node, VMID: req.VMID, Generation: req.Generation,
		Name: req.GuestName, JoinMethod: method}
	params, err := guestJoinParams(e, b)
	if err != nil {
		return PveGuestJoinCommit{}, fmt.Errorf("join %s: parameters: %w", e.HostID, err)
	}
	if _, err := s.auth.AuthorizeGrant(d, permit.Run{
		HostID: e.HostID, HostKeyFingerprint: e.Fingerprint, ActionID: enrollAction, ModuleVersion: enrollVersion,
		Artifact: enrollArtifact, ParametersJSON: params, CredentialRef: e.Credential,
	}); err != nil {
		return PveGuestJoinCommit{}, fmt.Errorf("%w: %w", ErrPveJoinNotApproved, err)
	}
	res := &pb.EnrollResult{HostId: e.HostID}
	if err := s.enrollOne(ctx, d, "guest-join:"+d.String()[:16], e, res); err != nil {
		return PveGuestJoinCommit{}, fmt.Errorf("join %s: host key store: %w", e.HostID, err)
	}
	s.log.Warn("audit", "kind", "guest_join_committed", "digest", d.String(), "remote", b.RemoteID, "node", b.Node,
		"vmid", b.VMID, "generation", b.Generation, "host", e.HostID, "fingerprint", e.Fingerprint,
		"method", method, "pinned", res.Pinned)
	return PveGuestJoinCommit{
		Result: res,
		Host: &pb.EnrollHost{HostId: e.HostID, Endpoint: e.Endpoint, SshUser: e.User, CredentialRef: e.Credential,
			Fingerprint: e.Fingerprint, KeyType: host.GetKeyType()},
		Guest:      b.proto(),
		JoinMethod: method,
	}, nil
}

// pveGuestJoin is the guest join of this executor: the agent read uses the
// remote registry, the vault and the pinned PVE read channel.
func (s *Service) pveGuestJoin() *PveGuestJoin {
	return &PveGuestJoin{Service: s, Mutations: s.pveMutations(), Agent: pveGuestAgentAPI{s: s}}
}

// pveJoinStatus maps a guest join error to a gRPC status without
// untrusted text.
func pveJoinStatus(err error) error {
	switch {
	case errors.Is(err, ErrPveJoinInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrPveJoinRefused), errors.Is(err, ErrPveJoinKeyMismatch):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrPveJoinUnreachable):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrPveJoinNotApproved):
		return toStatus(err)
	case permit.CodeOf(err) != "":
		return toStatus(err)
	default:
		return status.Error(codes.Internal, "guest join failed")
	}
}

// ProposeGuestJoin proposes the enrollment of a provisioned guest (server
// role).
func (s *Service) ProposeGuestJoin(ctx context.Context, in *pb.ProposeGuestJoinRequest) (*pb.ProposeGuestJoinResponse, error) {
	g, h := in.GetGuest(), in.GetHost()
	p, err := s.pveGuestJoin().Propose(ctx, PveGuestJoinRequest{RemoteID: g.GetRemoteId(), Node: g.GetNode(),
		VMID: g.GetVmid(), Generation: g.GetGeneration(), GuestName: g.GetGuestName(), HostID: h.GetHostId(),
		Endpoint: h.GetEndpoint(), SSHUser: h.GetSshUser(), CredentialRef: h.GetCredentialRef()})
	if err != nil {
		return nil, pveJoinStatus(err)
	}
	return &pb.ProposeGuestJoinResponse{JoinMethod: p.Method, AgentDetail: p.AgentDetail, Host: p.Host,
		Guest: p.Guest, Permit: p.Permit}, nil
}

// CommitGuestJoin pins the host key of an approved guest join (server
// role).
func (s *Service) CommitGuestJoin(ctx context.Context, in *pb.CommitGuestJoinRequest) (*pb.CommitGuestJoinResponse, error) {
	d, err := canonical.ParseDigest(in.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	c, err := s.pveGuestJoin().Commit(ctx, d, in.GetHost(), in.GetGuest(), in.GetJoinMethod())
	if err != nil {
		return nil, pveJoinStatus(err)
	}
	return &pb.CommitGuestJoinResponse{Result: c.Result, ExecutionDigest: d.String(), Guest: c.Guest, Host: c.Host,
		JoinMethod: c.JoinMethod}, nil
}

// pveGuestAgentAPI is the production PveGuestAgentReader: typed pveapi
// reads over the remote's pinned TLS channel (the same trust and transport
// as ReadPVE), with the read token. A trust failure blocks the remote as
// for every other read.
type pveGuestAgentAPI struct {
	s *Service
}

// client builds the pinned API client of rm and returns it with its trust
// watch and the release of the remote's request slot.
func (a pveGuestAgentAPI) client(ctx context.Context, rm executordb.PveRemote, read pveapi.TokenSupplier) (*pveapi.Client, *pveTrustWatch, func(), error) {
	if read == nil {
		return nil, nil, nil, errors.New("executor: guest agent read: no read token")
	}
	release, err := a.s.pveRead.acquire(ctx, rm.RemoteID)
	if err != nil {
		return nil, nil, nil, err
	}
	trust, err := a.s.pveReadTrust(ctx, rm)
	if errors.Is(err, errPveReadTrust) {
		release()
		return nil, nil, nil, a.s.blockPveRead(rm.RemoteID)
	}
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	hc, watch, base, err := pveReadHTTP(rm, trust, a.s.clock)
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	c, err := pveapi.New(base, hc, read, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	return c, watch, release, nil
}

// checkTrust blocks the remote when a request of the read failed trust
// verification.
func (a pveGuestAgentAPI) checkTrust(rm executordb.PveRemote, watch *pveTrustWatch) error {
	if watch.failed.Load() {
		return a.s.blockPveRead(rm.RemoteID)
	}
	return nil
}

// LiveGuestName implements PveGuestAgentReader.
func (a pveGuestAgentAPI) LiveGuestName(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, read pveapi.TokenSupplier) (string, error) {
	c, watch, release, err := a.client(ctx, rm, read)
	if err != nil {
		return "", err
	}
	defer release()
	cfg, err := c.GetQemuConfig(ctx, node, int(vmid))
	if terr := a.checkTrust(rm, watch); terr != nil {
		return "", terr
	}
	if err != nil {
		return "", err
	}
	return cfg.Name, nil
}

// AgentFileRead implements PveGuestAgentReader.
func (a pveGuestAgentAPI) AgentFileRead(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, path string, maxBytes int, read pveapi.TokenSupplier) ([]byte, error) {
	c, watch, release, err := a.client(ctx, rm, read)
	if err != nil {
		return nil, err
	}
	defer release()
	raw, err := c.AgentFileRead(ctx, node, int(vmid), path, maxBytes)
	if terr := a.checkTrust(rm, watch); terr != nil {
		return nil, terr
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}
