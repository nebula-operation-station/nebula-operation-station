// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executor implements the nebula-executor gRPC service. It is a thin
// layer: authorization decisions live in internal/permit, key handling in
// internal/keyring, caller identity in internal/peercred.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// MaxMessageSize is the largest gRPC message the executor accepts. It must
// exceed permit.MaxArtifactSize plus framing.
const MaxMessageSize = permit.MaxArtifactSize + 1<<20

// MaxResponseSize bounds responses. ListPending with the maximum number of
// pending permits and targets must fit, or a flood of proposals could make
// the CLI approval path unusable.
const MaxResponseSize = 64 << 20

// MaxConcurrentStreams bounds parallel calls per connection.
const MaxConcurrentStreams = 16

// Service implements pb.ExecutorServiceServer.
type Service struct {
	pb.UnimplementedExecutorServiceServer

	auth *permit.Authority
	keys *keyring.Keyring
	log  *slog.Logger
}

// NewService wires the service.
func NewService(auth *permit.Authority, keys *keyring.Keyring, log *slog.Logger) *Service {
	return &Service{auth: auth, keys: keys, log: log}
}

// AuditLogger returns a permit audit hook that writes structured log lines.
func AuditLogger(log *slog.Logger) func(permit.Event) {
	return func(e permit.Event) {
		log.Info("audit",
			"kind", e.Kind, "digest", e.Digest, "host", e.Host,
			"code", string(e.Code), "detail", e.Detail, "time", e.Time.UTC())
	}
}

// NewGRPCServer returns a gRPC server enforcing policy on every call.
func NewGRPCServer(svc *Service, policy *peercred.Policy, log *slog.Logger) *grpc.Server {
	denied := func(uid uint32, pid int32, method string) {
		log.Warn("audit", "kind", "rpc_denied", "uid", uid, "pid", pid, "method", method)
	}
	s := grpc.NewServer(
		// Unknown UIDs are dropped during the handshake, before any request
		// is read; the interceptors then enforce the per-method table.
		grpc.Creds(peercred.Credentials{Policy: policy, OnReject: func(uid uint32, pid int32) {
			log.Warn("audit", "kind", "connection_rejected", "uid", uid, "pid", pid)
		}}),
		grpc.MaxConcurrentStreams(MaxConcurrentStreams),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(denied)),
		grpc.StreamInterceptor(policy.StreamInterceptor(denied)),
		grpc.MaxRecvMsgSize(MaxMessageSize),
		grpc.MaxSendMsgSize(MaxResponseSize),
	)
	pb.RegisterExecutorServiceServer(s, svc)
	return s
}

// LoadWebAuthnCredentials reads the executor's credential file. A missing
// file yields no credentials (browser approval impossible, CLI still works).
func LoadWebAuthnCredentials(dataDir string) ([]webauthnverify.Credential, error) {
	path := filepath.Join(dataDir, "webauthn-credentials.json")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var creds []webauthnverify.Credential
	if err := json.Unmarshal(b, &creds); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return creds, nil
}

func (s *Service) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	active, till := s.auth.Session()
	pending, approved := s.auth.Counts()
	resp := &pb.GetStatusResponse{
		Unlocked:                s.keys.Unlocked(),
		PrivilegedSessionActive: active,
		HardenedMode:            s.auth.Mode() == permit.ModeHardened,
		PendingPermits:          uint32(pending),
		ApprovedPermits:         uint32(approved),
		LoadedCredentialRefs:    s.keys.Refs(),
	}
	if active {
		resp.PrivilegedSessionExpiryUnix = till.Unix()
	}
	return resp, nil
}

func (s *Service) ProposeExecution(_ context.Context, req *pb.ProposeExecutionRequest) (*pb.ProposeExecutionResponse, error) {
	if req.GetRequest() == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	r, err := fromProto(req.GetRequest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	res, err := s.auth.Propose(r, req.GetParametersJson())
	if err != nil {
		return nil, toStatus(err)
	}
	p := res.Permit
	out := &pb.ProposeExecutionResponse{
		ExecutionDigest:     p.Digest.String(),
		CanonicalRequest:    p.Canonical,
		ApprovalRequirement: requirementToProto(p.Requirement),
		State:               stateToProto(p.State),
	}
	if p.State == permit.StatePending && p.Requirement != permit.RequireCLI {
		out.Challenge = p.Challenge
		out.ChallengeExpiryUnix = p.ApprovalExpiry.Unix()
	}
	return out, nil
}

func (s *Service) SubmitAssertion(_ context.Context, req *pb.SubmitAssertionRequest) (*pb.SubmitAssertionResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p, err := s.auth.SubmitAssertion(d, req.GetAssertionJson(), int(req.GetTypedTargetCount()))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.SubmitAssertionResponse{State: stateToProto(p.State)}, nil
}

func (s *Service) BeginPrivilegedSession(_ context.Context, _ *pb.BeginPrivilegedSessionRequest) (*pb.BeginPrivilegedSessionResponse, error) {
	ch, exp, err := s.auth.BeginSession()
	if err != nil {
		return nil, status.Error(codes.Internal, "cannot create challenge")
	}
	return &pb.BeginPrivilegedSessionResponse{Challenge: ch, ChallengeExpiryUnix: exp.Unix()}, nil
}

func (s *Service) CompletePrivilegedSession(_ context.Context, req *pb.CompletePrivilegedSessionRequest) (*pb.CompletePrivilegedSessionResponse, error) {
	till, err := s.auth.CompleteSession(req.GetAssertionJson())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.CompletePrivilegedSessionResponse{SessionExpiryUnix: till.Unix()}, nil
}

func (s *Service) AuthorizeRun(_ context.Context, req *pb.AuthorizeRunRequest) (*pb.AuthorizeRunResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Credentials first: a host must not be marked as used if the run could
	// not start anyway.
	if !s.keys.Unlocked() {
		return nil, status.Error(codes.FailedPrecondition, "vault_locked: run `nebula unlock` on the executor host")
	}
	if _, err := s.keys.Signer(req.GetCredentialRef()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "credential_unavailable: %s", req.GetCredentialRef())
	}
	err = s.auth.Authorize(d, permit.Run{
		HostID:             req.GetHostId(),
		HostKeyFingerprint: req.GetHostKeyFingerprint(),
		ActionID:           req.GetActionId(),
		ModuleVersion:      req.GetModuleVersion(),
		Artifact:           req.GetArtifact(),
		ParametersJSON:     req.GetParametersJson(),
		CredentialRef:      req.GetCredentialRef(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.AuthorizeRunResponse{Authorized: true}, nil
}

func (s *Service) Unlock(ctx context.Context, req *pb.UnlockRequest) (*pb.UnlockResponse, error) {
	refs, err := s.keys.Unlock(req.GetPassphrase())
	who := callerName(ctx)
	if err != nil {
		s.log.Warn("audit", "kind", "unlock_failed", "by", who, "detail", err.Error())
		if errors.Is(err, keyring.ErrWrongPassword) {
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	s.log.Info("audit", "kind", "unlocked", "by", who, "credentials", refs)
	return &pb.UnlockResponse{LoadedCredentialRefs: refs}, nil
}

func (s *Service) Lock(ctx context.Context, _ *pb.LockRequest) (*pb.LockResponse, error) {
	who := callerName(ctx)
	// Revoke permits before wiping keys so that no AuthorizeRun can succeed
	// in between.
	s.auth.Lock(who)
	s.keys.Lock()
	return &pb.LockResponse{}, nil
}

func (s *Service) ListPending(_ context.Context, _ *pb.ListPendingRequest) (*pb.ListPendingResponse, error) {
	out := &pb.ListPendingResponse{}
	for _, p := range s.auth.Pending() {
		out.Permits = append(out.Permits, &pb.PendingPermit{
			ExecutionDigest:     p.Digest.String(),
			Request:             toProto(p.Request),
			ApprovalRequirement: requirementToProto(p.Requirement),
			ApprovalExpiryUnix:  p.ApprovalExpiry.Unix(),
			CanonicalParameters: p.Parameters,
		})
	}
	return out, nil
}

func (s *Service) ApproveCLI(ctx context.Context, req *pb.ApproveCLIRequest) (*pb.ApproveCLIResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p, err := s.auth.ApproveCLI(d, int(req.GetTypedTargetCount()), callerName(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ApproveCLIResponse{State: stateToProto(p.State)}, nil
}

func callerName(ctx context.Context) string {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return "unknown"
	}
	return string(c.Role) + ":uid" + strconv.FormatUint(uint64(c.UID), 10)
}

func toStatus(err error) error {
	code := permit.CodeOf(err)
	var c codes.Code
	switch code {
	case permit.CodeInvalidRequest:
		c = codes.InvalidArgument
	case permit.CodeNotFound:
		c = codes.NotFound
	case permit.CodeExecutionIDReused:
		c = codes.AlreadyExists
	case permit.CodeLimit:
		c = codes.ResourceExhausted
	case permit.CodeWrongState, permit.CodeSessionRequired, permit.CodeCLIRequired, permit.CodeNoChallenge, permit.CodeExpired:
		c = codes.FailedPrecondition
	case permit.CodeAssertionRejected, permit.CodeTypedCountMismatch,
		permit.CodeTargetNotPermitted, permit.CodeHostAlreadyRun, permit.CodeArtifactMismatch,
		permit.CodeParametersMismatch, permit.CodeActionMismatch, permit.CodeCredentialMismatch:
		c = codes.PermissionDenied
	default:
		c = codes.Internal
	}
	return status.Error(c, err.Error())
}
