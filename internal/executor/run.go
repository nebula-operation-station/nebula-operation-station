// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Connection classes in RunAttached responses (spec 07 error classes).
const (
	classNetworkUnreachable    = "network_unreachable"
	classAuthenticationFailed  = "authentication_failed"
	classHostKeyMismatch       = "host_key_mismatch"
	classCredentialUnavailable = "credential_unavailable"
	classUnknown               = "unknown"
)

// prepareRun checks everything about a run that needs no permit, so that a
// refused run does not use up the permit's host.
func (s *Service) prepareRun(r *pb.AuthorizeRunRequest, endpoints []string) (canonical.Digest, []sshtransport.Endpoint, error) {
	if r == nil {
		return canonical.Digest{}, nil, status.Error(codes.InvalidArgument, "run is required")
	}
	d, err := canonical.ParseDigest(r.GetExecutionDigest())
	if err != nil {
		return canonical.Digest{}, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	eps, err := parseEndpoints(endpoints)
	if err != nil {
		return canonical.Digest{}, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if !s.keys.Unlocked() {
		return canonical.Digest{}, nil, status.Error(codes.FailedPrecondition, "vault_locked: run `nebula unlock` on the executor host")
	}
	hk, ok, err := s.db.HostKey(r.GetHostId())
	if err != nil {
		return canonical.Digest{}, nil, s.adminStoreError("run", err)
	}
	if !ok {
		return canonical.Digest{}, nil, status.Error(codes.FailedPrecondition, ErrHostNotPinned.Error())
	}
	if hk.Blocked != nil {
		return canonical.Digest{}, nil, status.Error(codes.FailedPrecondition, "host_key_mismatch: "+ErrHostBlocked.Error())
	}
	// The connection uses the pin's credential, so it must be the one the
	// permit allows for this run.
	if hk.CredentialRef != r.GetCredentialRef() {
		return canonical.Digest{}, nil, status.Error(codes.PermissionDenied, "credential_mismatch: the host's pinned credential is not the run's")
	}
	if _, err := s.keys.Signer(hk.CredentialRef); err != nil {
		return canonical.Digest{}, nil, status.Errorf(codes.FailedPrecondition, "credential_unavailable: %s", hk.CredentialRef)
	}
	return d, eps, nil
}

func authorizeRequest(r *pb.AuthorizeRunRequest) permit.Run {
	return permit.Run{
		HostID:             r.GetHostId(),
		HostKeyFingerprint: r.GetHostKeyFingerprint(),
		ActionID:           r.GetActionId(),
		ModuleVersion:      r.GetModuleVersion(),
		Artifact:           r.GetArtifact(),
		ParametersJSON:     r.GetParametersJson(),
		CredentialRef:      r.GetCredentialRef(),
	}
}

// RunAttached authorizes one host run and runs it attached (spec 07).
// Everything that can be checked without using up the permit's host is
// checked first; after AuthorizeGrant every outcome is a response class.
func (s *Service) RunAttached(ctx context.Context, req *pb.RunAttachedRequest) (*pb.RunAttachedResponse, error) {
	r := req.GetRun()
	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout > hostrun.MaxTimeout {
		return nil, status.Errorf(codes.InvalidArgument, "timeout above %s; long work is a durable job", hostrun.MaxTimeout)
	}
	d, eps, err := s.prepareRun(r, req.GetEndpoints())
	if err != nil {
		return nil, err
	}

	grant, err := s.auth.AuthorizeGrant(d, authorizeRequest(r))
	if err != nil {
		return nil, toStatus(err)
	}

	start := time.Now()
	resp := &pb.RunAttachedResponse{ExitCode: -1}
	c, err := s.Connect(ctx, r.GetHostId(), r.GetHostKeyFingerprint(), eps)
	if err != nil {
		resp.Class, resp.Detail = connectClass(err)
		resp.DurationMs = time.Since(start).Milliseconds()
		s.auditRun(d, r.GetHostId(), resp)
		return resp, nil
	}
	defer c.Close()
	resp.Endpoint = c.Endpoint.String()
	res, err := hostrun.Attached(ctx, c.Client, grant.ExecutionID, grant.Parameters, r.GetArtifact(), timeout)
	if err != nil {
		resp.Class, resp.Detail = classUnknown, err.Error()
	} else {
		resp.Class, resp.Detail, resp.ExitCode = res.Class, res.Detail, int32(res.ExitCode)
		resp.Result, resp.Log, resp.LogTruncated = res.Result, res.Log, res.LogTruncated
	}
	resp.DurationMs = time.Since(start).Milliseconds()
	s.auditRun(d, r.GetHostId(), resp)
	return resp, nil
}

func connectClass(err error) (string, string) {
	var te *sshtransport.Error
	switch {
	case errors.Is(err, ErrHostBlocked):
		return classHostKeyMismatch, err.Error()
	case errors.Is(err, ErrTargetFingerprint):
		return classHostKeyMismatch, err.Error()
	case errors.Is(err, keyring.ErrLocked):
		return "vault_locked", "the keyring was locked during the run"
	case errors.Is(err, keyring.ErrUnknownRef):
		return classCredentialUnavailable, "the host's credential is not loaded"
	case errors.As(err, &te):
		switch te.Class {
		case sshtransport.ClassUnreachable:
			return classNetworkUnreachable, te.Detail
		case sshtransport.ClassHostKeyMismatch:
			return classHostKeyMismatch, "the host presented another key; it is blocked until re-pinned"
		case sshtransport.ClassAuth:
			return classAuthenticationFailed, te.Detail
		}
		return classUnknown, te.Detail
	}
	return classUnknown, "connection failed"
}

func (s *Service) auditRun(d canonical.Digest, host string, r *pb.RunAttachedResponse) {
	s.log.Info("audit", "kind", "run_finished", "digest", d.String(), "host", host, "class", r.GetClass(),
		"exit", r.GetExitCode(), "endpoint", r.GetEndpoint(), "result_bytes", len(r.GetResult()),
		"log_bytes", len(r.GetLog()), "log_truncated", r.GetLogTruncated(), "duration_ms", r.GetDurationMs())
}
