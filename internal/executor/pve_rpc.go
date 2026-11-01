// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const pveRepinAction = "nebula.pve.repin"

var pveRepinArtifact = []byte("nebula.pve.repin 1.0.0\nReplace the approved remote trust fingerprint and invalidate dependent authority.\n")

func (s *Service) pveAdmin() *PveAdmin {
	return &PveAdmin{DB: s.db, Vault: s.vault, Now: s.clock, Log: s.log, AuthorizeRepin: s.authorizePVERepin,
		RevokeGrants: func(remoteID, reason string) error {
			_, err := s.auth.RevokeProviderGrants(remoteID, reason)
			return err
		}}
}

func pveAdminProto(r executordb.PveRemote) *pb.PVEAdminRemote {
	out := &pb.PVEAdminRemote{RemoteId: r.RemoteID, Name: r.Name, Kind: string(r.Kind), TrustPin: r.TrustPin, TrustGeneration: r.TrustGeneration, State: string(r.State), ReadRef: r.Credentials.ReadRef, ReadVersion: r.Credentials.ReadVersion, ActionRef: r.Credentials.ActionRef, ActionVersion: r.Credentials.ActionVersion, UpdatedAtUnix: r.UpdatedAt.Unix()}
	for _, ep := range r.Endpoints {
		out.Endpoints = append(out.Endpoints, &pb.PVEEndpoint{Host: ep.Host, Port: uint32(ep.Port)})
	}
	return out
}

func pveEndpointsFromProto(in []*pb.PVEEndpoint) ([]pvecontract.Endpoint, error) {
	if len(in) == 0 || len(in) > pvecontract.MaxEndpointsPerRemote {
		return nil, status.Error(codes.InvalidArgument, "invalid pve endpoint count")
	}
	out := make([]pvecontract.Endpoint, 0, len(in))
	for _, ep := range in {
		if ep.GetPort() == 0 || ep.GetPort() > 65535 {
			return nil, status.Error(codes.InvalidArgument, "invalid pve endpoint port")
		}
		out = append(out, pvecontract.Endpoint{Host: ep.GetHost(), Port: uint16(ep.GetPort())})
	}
	return out, nil
}

func pveRPCError(err error) error {
	switch {
	case errors.Is(err, vault.ErrLocked), errors.Is(err, ErrPveApprovalRequired), errors.Is(err, executordb.ErrRemoteState):
		return status.Error(codes.FailedPrecondition, "pve operation requires an unlocked vault and valid remote state or approval")
	case errors.Is(err, executordb.ErrRemoteNotFound):
		return status.Error(codes.NotFound, "pve remote not found")
	case errors.Is(err, executordb.ErrSecretVersion), errors.Is(err, vault.ErrConcurrentChange):
		return status.Error(codes.Aborted, "pve remote changed; retry")
	case errors.Is(err, ErrPveTokenFormat), errors.Is(err, ErrPveTokenRejected), errors.Is(err, ErrPveTokenInvalid), errors.Is(err, ErrPvePurpose), errors.Is(err, ErrPvePinMismatch), errors.Is(err, pvecontract.ErrInvalid), errors.Is(err, executordb.ErrInvalid):
		return status.Error(codes.InvalidArgument, "pve token, profile, trust confirmation or remote is invalid")
	default:
		return status.Error(codes.Internal, "pve operation failed")
	}
}

// ProbePVERemote probes validated endpoints inside the unlocked executor.
func (s *Service) ProbePVERemote(ctx context.Context, in *pb.ProbePVERemoteRequest) (*pb.ProbePVERemoteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	a := s.pveAdmin()
	if err := a.checkDeps(); err != nil {
		return nil, pveRPCError(err)
	}
	eps, err := pveEndpointsFromProto(in.GetEndpoints())
	if err != nil {
		return nil, err
	}
	// Apply the same kind, host, duplicate and endpoint limits as AddRemote.
	r, err := pvecontract.ValidateRemote(pvecontract.Remote{RemoteID: "probe", Kind: pvecontract.Kind(in.GetKind()), Endpoints: eps, TrustPin: strings.Repeat("0", 64), TrustGeneration: 1})
	if err != nil {
		return nil, pveRPCError(err)
	}
	res, err := a.probeFn()(ctx, r.Endpoints)
	if err != nil {
		return nil, pveRPCError(err)
	}
	pin, _, err := res.TrustIdentity(r.Kind)
	if err != nil {
		return nil, pveRPCError(err)
	}
	out := &pb.ProbePVERemoteResponse{TrustPin: pin}
	for _, ep := range res.Endpoints {
		out.Endpoints = append(out.Endpoints, &pb.PVEProbeEndpoint{Host: ep.Host, Port: uint32(ep.Port), LeafFingerprint: ep.LeafFingerprint, CaFingerprint: ep.CAFingerprint})
	}
	return out, nil
}

// AddPVERemote stores tokens only in the executor and records the peer UID.
func (s *Service) AddPVERemote(ctx context.Context, in *pb.AddPVERemoteRequest) (*pb.AddPVERemoteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	defer clear(in.GetReadToken())
	defer clear(in.GetActionToken())
	eps, err := pveEndpointsFromProto(in.GetEndpoints())
	if err != nil {
		return nil, err
	}
	r, err := s.pveAdmin().AddRemote(ctx, PveAddRemote{RemoteID: in.GetRemoteId(), Name: in.GetName(), Kind: pvecontract.Kind(in.GetKind()), Endpoints: eps, ConfirmedPin: in.GetConfirmedPin(), ReadToken: in.GetReadToken(), ActionToken: in.GetActionToken(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.AddPVERemoteResponse{Remote: pveAdminProto(r)}, nil
}

// RotatePVEToken atomically replaces a purpose's encrypted credential.
func (s *Service) RotatePVEToken(ctx context.Context, in *pb.RotatePVETokenRequest) (*pb.RotatePVETokenResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	defer clear(in.GetToken())
	r, err := s.pveAdmin().RotateToken(ctx, PveRotateToken{RemoteID: in.GetRemoteId(), Purpose: in.GetPurpose(), Token: in.GetToken(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.RotatePVETokenResponse{Remote: pveAdminProto(r)}, nil
}

// RemovePVERemote disables and tombstones a remote after removing custody.
func (s *Service) RemovePVERemote(ctx context.Context, in *pb.RemovePVERemoteRequest) (*pb.RemovePVERemoteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	r, err := s.pveAdmin().RemoveRemote(ctx, PveRemove{RemoteID: in.GetRemoteId(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.RemovePVERemoteResponse{Remote: pveAdminProto(r)}, nil
}

// ListPVEAdminRemotes lists credential references, never their values.
func (s *Service) ListPVEAdminRemotes(ctx context.Context, _ *pb.ListPVEAdminRemotesRequest) (*pb.ListPVEAdminRemotesResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	rows, err := s.pveAdmin().ListRemotes(ctx)
	if err != nil {
		return nil, pveRPCError(err)
	}
	out := &pb.ListPVEAdminRemotesResponse{}
	for _, r := range rows {
		out.Remotes = append(out.Remotes, pveAdminProto(r))
	}
	return out, nil
}

func pveRepinBinding(r executordb.PveRemote, newPin string) ([]byte, canonical.Target, error) {
	params, err := json.Marshal(struct {
		Remote executordb.PveRemote `json:"remote"`
		NewPin string               `json:"new_pin"`
	}{r, newPin})
	// The permit target uses the same 32-byte fingerprint encoding as the
	// existing authority; the parameters retain its PVE identity and kind.
	fp, decodeErr := hex.DecodeString(r.TrustPin)
	if err != nil || decodeErr != nil {
		return nil, canonical.Target{}, ErrPveApprovalRequired
	}
	target := canonical.Target{HostID: PveVaultID(r.RemoteID, "trust"), HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fp)}
	return params, target, nil
}

// ProposePVERepin creates an exact HIGH approval; probing sends no token.
func (s *Service) ProposePVERepin(ctx context.Context, in *pb.ProposePVERepinRequest) (*pb.ProposePVERepinResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	a := s.pveAdmin()
	if err := a.checkDeps(); err != nil {
		return nil, pveRPCError(err)
	}
	r, ok, err := s.db.GetRemote(in.GetRemoteId())
	if err != nil {
		return nil, pveRPCError(err)
	}
	if !ok || r.State == executordb.StateRemoved {
		return nil, pveRPCError(executordb.ErrRemoteNotFound)
	}
	if r.TrustPin != in.GetOldPin() || !pvecontract.ValidTrustPin(in.GetConfirmedNewPin()) || r.TrustPin == in.GetConfirmedNewPin() {
		return nil, pveRPCError(ErrPvePinMismatch)
	}
	probe, err := a.probeFn()(ctx, r.Endpoints)
	if err != nil {
		return nil, pveRPCError(err)
	}
	pin, _, err := probe.TrustIdentity(r.Kind)
	if err != nil || pin != in.GetConfirmedNewPin() {
		return nil, pveRPCError(ErrPvePinMismatch)
	}
	params, target, err := pveRepinBinding(r, pin)
	if err != nil {
		return nil, pveRPCError(err)
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return nil, pveRPCError(err)
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, pveRPCError(err)
	}
	rq := canonical.Request{ExecutionID: id, ActionID: pveRepinAction, ModuleVersion: repinVersion, ArtifactSHA256: sha256Hex(pveRepinArtifact), ParametersHash: ph, CredentialRefs: []string{r.Credentials.ReadRef}, RiskClass: canonical.RiskHigh, StagePlanHash: stagePlanRepin, ExpiryUnix: s.clock().Add(repinLifetime).Unix(), ResolvedTargets: []canonical.Target{target}}
	res, err := s.auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return nil, toStatus(err)
	}
	out, err := s.permitResponse(res.Permit)
	if err != nil {
		return nil, err
	}
	return &pb.ProposePVERepinResponse{Permit: out}, nil
}

func (s *Service) authorizePVERepin(_ context.Context, r executordb.PveRemote, in PveRepin) error {
	d, err := canonical.ParseDigest(in.ApprovalDigest)
	if err != nil {
		return ErrPveApprovalRequired
	}
	params, target, err := pveRepinBinding(r, in.ConfirmedNewPin)
	if err != nil {
		return err
	}
	_, err = s.auth.AuthorizeGrant(d, permit.Run{HostID: target.HostID, HostKeyFingerprint: target.HostKeyFingerprint, ActionID: pveRepinAction, ModuleVersion: repinVersion, Artifact: pveRepinArtifact, ParametersJSON: params, CredentialRef: r.Credentials.ReadRef})
	if err != nil {
		return ErrPveApprovalRequired
	}
	return nil
}

// CommitPVERepin consumes the approved binding before changing trust.
func (s *Service) CommitPVERepin(ctx context.Context, in *pb.CommitPVERepinRequest) (*pb.CommitPVERepinResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	r, err := s.pveAdmin().Repin(ctx, PveRepin{RemoteID: in.GetRemoteId(), OldPin: in.GetOldPin(), ConfirmedNewPin: in.GetConfirmedNewPin(), ApprovalDigest: in.GetExecutionDigest(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.CommitPVERepinResponse{Remote: pveAdminProto(r)}, nil
}
