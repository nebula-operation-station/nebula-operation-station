// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executor implements the nebula-executor gRPC service. It is a thin
// layer: authorization decisions live in internal/permit, key handling in
// internal/keyring, caller identity in internal/peercred.
package executor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
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
	db   *executordb.DB
	reg  *webauthnreg.Registrar
	log  *slog.Logger
	// transport is the SSH client configuration (spec 08 defaults).
	transport sshtransport.Config
	// recovery limits wrong TOTP recovery codes.
	recovery recoveryLimiter
	// vault holds the secrets that are not SSH keys (spec 06).
	vault *vault.Vault
	// vaultParams are the Argon2id parameters for InitVault.
	vaultParams vault.Params
	// jobs describes how durable jobs start on hosts.
	jobs hostrun.JobConfig
	// reconcileMu serializes reconciliation passes.
	reconcileMu sync.Mutex
	// dispatching holds runs whose dispatch is in flight in this process;
	// reconciliation leaves them alone (after a restart the set is empty).
	dispatchMu  sync.Mutex
	dispatching map[string]bool
	// eventKey verifies the signed event chain (M10-1).
	eventKey ed25519.PublicKey
	// Now is the clock for request expiries the executor sets itself
	// (re-pin, enrollment); nil means time.Now. Tests set it.
	Now func() time.Time
}

func (s *Service) clock() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// NewService wires the service. db holds the executor's risk data and
// credentials, which the admin RPCs change; reg runs WebAuthn
// registrations. All arguments are required.
func NewService(auth *permit.Authority, keys *keyring.Keyring, db *executordb.DB, reg *webauthnreg.Registrar, log *slog.Logger) *Service {
	if auth == nil || keys == nil || db == nil || reg == nil || log == nil {
		panic("executor: NewService needs authority, keyring, database, registrar and logger")
	}
	return &Service{auth: auth, keys: keys, db: db, reg: reg, log: log, vault: vault.New(db), vaultParams: vault.DefaultParams,
		jobs: hostrun.DefaultJobConfig}
}

// SetJobConfig changes how durable jobs start on hosts (tests run them
// without sudo and systemd).
func (s *Service) SetJobConfig(c hostrun.JobConfig) { s.jobs = c }

// SetVaultParams changes the Argon2id parameters InitVault uses. Tests use
// it to avoid 256 MiB per derivation; production keeps the defaults.
func (s *Service) SetVaultParams(p vault.Params) {
	s.vaultParams = p
	s.vault.SetMinParams(p)
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
	if _, pending, err := s.db.RecoveryPending(); err == nil && pending {
		resp.RecoveryPending = true
	}
	resp.VaultState = s.vaultState()
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
	// Executor-internal actions (re-pin) have their own RPCs that build the
	// request from the executor's records.
	if strings.HasPrefix(r.ActionID, reservedActionPrefix) {
		return nil, status.Errorf(codes.InvalidArgument, "action_id %q is reserved for the executor", r.ActionID)
	}
	// The Safety Scanner sees the bytes before the risk is decided.
	if art := req.GetArtifact(); len(art) > 0 {
		sum, err := s.auth.ObserveArtifact(art)
		if err != nil {
			return nil, toStatus(err)
		}
		if sum != r.ArtifactSHA256 {
			return nil, status.Error(codes.InvalidArgument, "artifact_mismatch: the artifact does not hash to artifact_sha256")
		}
	}
	var res permit.ProposeResult
	if len(req.GetStagePlanJson()) > 0 {
		res, err = s.auth.ProposeStaged(r, req.GetParametersJson(), req.GetStagePlanJson(), req.GetRaiseToMinimum())
	} else {
		// Without a plan the request is one stage of all targets, and its
		// stage_plan_hash must say so.
		if r.StagePlanHash != stageplan.SingleStageHash {
			return nil, status.Error(codes.InvalidArgument, "stage_plan_invalid: a request without stage_plan_json must carry the single-stage plan hash")
		}
		propose := s.auth.Propose
		if req.GetRaiseToMinimum() {
			propose = s.auth.ProposeAtLeastMinimum
		}
		res, err = propose(r, req.GetParametersJson())
	}
	if err != nil {
		return nil, toStatus(err)
	}
	p := res.Permit
	out := &pb.ProposeExecutionResponse{
		ExecutionDigest:     p.Digest.String(),
		CanonicalRequest:    p.Canonical,
		ApprovalRequirement: requirementToProto(p.Requirement),
		State:               stateToProto(p.State),
		RiskClass:           riskToProto(p.Request.RiskClass),
	}
	if p.State == permit.StatePending && p.Requirement != permit.RequireCLI {
		out.Challenge = p.Challenge
		out.ChallengeExpiryUnix = p.ApprovalExpiry.Unix()
		opts, err := s.reg.RequestOptions(p.Challenge, time.Until(p.ApprovalExpiry))
		if err != nil {
			return nil, status.Error(codes.Internal, "request options")
		}
		out.RequestOptionsJson = opts
	}
	return out, nil
}

func (s *Service) SubmitAssertion(_ context.Context, req *pb.SubmitAssertionRequest) (*pb.SubmitAssertionResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.checkNotRecovering(); err != nil {
		return nil, err
	}
	p, err := s.auth.SubmitAssertion(d, req.GetAssertionJson(), int(req.GetTypedTargetCount()))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.SubmitAssertionResponse{State: stateToProto(p.State)}, nil
}

func (s *Service) BeginPrivilegedSession(_ context.Context, _ *pb.BeginPrivilegedSessionRequest) (*pb.BeginPrivilegedSessionResponse, error) {
	if err := s.checkNotRecovering(); err != nil {
		return nil, err
	}
	ch, exp, err := s.auth.BeginSession()
	if err != nil {
		return nil, status.Error(codes.Internal, "cannot create challenge")
	}
	opts, err := s.reg.RequestOptions(ch, time.Until(exp))
	if err != nil {
		return nil, status.Error(codes.Internal, "cannot build request options")
	}
	return &pb.BeginPrivilegedSessionResponse{Challenge: ch, ChallengeExpiryUnix: exp.Unix(), RequestOptionsJson: opts}, nil
}

func (s *Service) CompletePrivilegedSession(_ context.Context, req *pb.CompletePrivilegedSessionRequest) (*pb.CompletePrivilegedSessionResponse, error) {
	if err := s.checkNotRecovering(); err != nil {
		return nil, err
	}
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

// Unlock tries the passphrase on the SSH keys and, once initialized, on
// the vault (spec 06: one unlock). It fails only if nothing it tried was
// unlocked; the response tells the CLI which part needs another passphrase.
func (s *Service) Unlock(ctx context.Context, req *pb.UnlockRequest) (*pb.UnlockResponse, error) {
	who := callerName(ctx)
	scope := req.GetScope()
	resp := &pb.UnlockResponse{}
	var keysErr, vaultErr error
	tryKeys := scope != pb.UnlockScope_UNLOCK_SCOPE_VAULT
	tryVault := scope != pb.UnlockScope_UNLOCK_SCOPE_KEYS
	if tryVault {
		st := s.vaultState()
		if st == pb.VaultState_VAULT_STATE_NOT_INITIALIZED {
			tryVault = false
			if scope == pb.UnlockScope_UNLOCK_SCOPE_VAULT {
				return nil, status.Error(codes.FailedPrecondition, vault.ErrNotInitialized.Error())
			}
		}
	}
	// keyring.Unlock wipes the passphrase it gets; the vault needs its own copy.
	vaultPass := append([]byte(nil), req.GetPassphrase()...)
	defer clear(vaultPass)
	if tryKeys {
		refs, err := s.keys.Unlock(req.GetPassphrase())
		if err != nil {
			keysErr = err
			resp.KeysError = err.Error()
			resp.KeysWrongPassphrase = errors.Is(err, keyring.ErrWrongPassword)
			s.log.Warn("audit", "kind", "unlock_failed", "by", who, "detail", err.Error())
		} else {
			resp.KeysUnlocked, resp.LoadedCredentialRefs = true, refs
			s.log.Info("audit", "kind", "unlocked", "by", who, "credentials", refs)
		}
	}
	if tryVault {
		if err := s.vault.Unlock(vaultPass); err != nil {
			vaultErr = err
			resp.VaultWrongPassphrase = errors.Is(err, vault.ErrWrongPassphrase)
			s.log.Warn("audit", "kind", "vault_unlock_failed", "by", who, "detail", err.Error())
		} else {
			s.log.Info("audit", "kind", "vault_unlocked", "by", who)
		}
	}
	resp.VaultState = s.vaultState()
	if resp.KeysUnlocked || (tryVault && vaultErr == nil) {
		return resp, nil
	}
	if errors.Is(keysErr, keyring.ErrWrongPassword) || resp.VaultWrongPassphrase {
		return nil, status.Error(codes.Unauthenticated, "the passphrase does not unlock anything")
	}
	if keysErr != nil {
		return nil, status.Error(codes.FailedPrecondition, keysErr.Error())
	}
	return nil, status.Error(codes.FailedPrecondition, "vault: "+vaultErr.Error())
}

func (s *Service) Lock(ctx context.Context, _ *pb.LockRequest) (*pb.LockResponse, error) {
	who := callerName(ctx)
	// Revoke permits before wiping keys so that no AuthorizeRun can succeed
	// in between.
	s.auth.Lock(who)
	s.keys.Lock()
	s.vault.Lock()
	s.reg.Reset("executor locked")
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
			StagePlan:           planToProto(p.Plan),
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
	case permit.CodeInvalidRequest, permit.CodeStagePlan, permit.CodeGateInvalid, permit.CodeGrantInvalid:
		c = codes.InvalidArgument
	case permit.CodeScheduleUnavailable:
		c = codes.Unimplemented
	case permit.CodeTooSoon:
		c = codes.ResourceExhausted
	case permit.CodeNotFound:
		c = codes.NotFound
	case permit.CodeExecutionIDReused:
		c = codes.AlreadyExists
	case permit.CodeLimit:
		c = codes.ResourceExhausted
	case permit.CodeStorage:
		c = codes.Unavailable
	case permit.CodeWrongState, permit.CodeSessionRequired, permit.CodeCLIRequired, permit.CodeNoChallenge, permit.CodeExpired,
		permit.CodeStageNotDone:
		c = codes.FailedPrecondition
	case permit.CodeAssertionRejected, permit.CodeTypedCountMismatch, permit.CodeRiskAboveApproval,
		permit.CodeTargetNotPermitted, permit.CodeHostAlreadyRun, permit.CodeArtifactMismatch,
		permit.CodeParametersMismatch, permit.CodeActionMismatch, permit.CodeCredentialMismatch,
		permit.CodeStageNotOpen, permit.CodeRolloutStopped, permit.CodeRolloutAborted,
		permit.CodeGrantInactive, permit.CodeGrantNotCovered:
		c = codes.PermissionDenied
	default:
		c = codes.Internal
	}
	return status.Error(c, err.Error())
}
