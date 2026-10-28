// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// reconnectInterval is how often the server retries the executor
// connection while it has none.
const reconnectInterval = 5 * time.Second

// errNotConnected is returned while the server has no executor connection.
var errNotConnected = status.Error(codes.Unavailable, "executor not connected")

// lazyExecutor holds the executor client once it could be created. The
// server starts without one when the executor is not up yet (start order,
// executor restart) and connects in the background, so it never needs a
// restart of its own. It implements the parts of the client the UI and the
// login use.
type lazyExecutor struct {
	c atomic.Pointer[executorclient.Client]
}

// connect tries to create the client until it succeeds or ctx ends.
func (l *lazyExecutor) connect(ctx context.Context, o executorclient.Options, log *slog.Logger) {
	warned := false
	for {
		c, err := executorclient.New(ctx, o)
		if err == nil {
			l.c.Store(c)
			if warned {
				log.Info("executor connected")
			}
			return
		}
		if !warned {
			log.Warn("executor unreachable; retrying in the background", "error", err)
			warned = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectInterval):
		}
	}
}

func (l *lazyExecutor) close() {
	if c := l.c.Load(); c != nil {
		c.Close()
	}
}

func (l *lazyExecutor) GetStatus(ctx context.Context, in *pb.GetStatusRequest, opts ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.GetStatus(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) BeginLogin(ctx context.Context, in *pb.BeginLoginRequest, opts ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.BeginLogin(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) FinishLogin(ctx context.Context, in *pb.FinishLoginRequest, opts ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.FinishLogin(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) BeginRegistration(ctx context.Context, in *pb.BeginRegistrationRequest, opts ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.BeginRegistration(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) FinishRegistration(ctx context.Context, in *pb.FinishRegistrationRequest, opts ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.FinishRegistration(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) BeginPrivilegedSession(ctx context.Context, in *pb.BeginPrivilegedSessionRequest, opts ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.BeginPrivilegedSession(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CompletePrivilegedSession(ctx context.Context, in *pb.CompletePrivilegedSessionRequest, opts ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CompletePrivilegedSession(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ProposeRepin(ctx context.Context, in *pb.ProposeRepinRequest, opts ...grpc.CallOption) (*pb.ProposeRepinResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ProposeRepin(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CommitRepin(ctx context.Context, in *pb.CommitRepinRequest, opts ...grpc.CallOption) (*pb.CommitRepinResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CommitRepin(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ProposeEnroll(ctx context.Context, in *pb.ProposeEnrollRequest, opts ...grpc.CallOption) (*pb.ProposeEnrollResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ProposeEnroll(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CommitEnroll(ctx context.Context, in *pb.CommitEnrollRequest, opts ...grpc.CallOption) (*pb.CommitEnrollResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CommitEnroll(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ListHostKeys(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ListWebAuthnCredentials(ctx context.Context, in *pb.ListWebAuthnCredentialsRequest, opts ...grpc.CallOption) (*pb.ListWebAuthnCredentialsResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ListWebAuthnCredentials(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) GetTOTPStatus(ctx context.Context, in *pb.GetTOTPStatusRequest, opts ...grpc.CallOption) (*pb.GetTOTPStatusResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.GetTOTPStatus(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) Lock(ctx context.Context, in *pb.LockRequest, opts ...grpc.CallOption) (*pb.LockResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.Lock(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CheckCredential(ctx context.Context, in *pb.CheckCredentialRequest, opts ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CheckCredential(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) RecoveryLogin(ctx context.Context, in *pb.RecoveryLoginRequest, opts ...grpc.CallOption) (*pb.RecoveryLoginResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.RecoveryLogin(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ProposeExecution(ctx context.Context, in *pb.ProposeExecutionRequest, opts ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ProposeExecution(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.SubmitAssertion(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) GetPermitState(ctx context.Context, in *pb.GetPermitStateRequest, opts ...grpc.CallOption) (*pb.GetPermitStateResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.GetPermitState(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) RunAttached(ctx context.Context, in *pb.RunAttachedRequest, opts ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.RunAttached(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) StartDurable(ctx context.Context, in *pb.StartDurableRequest, opts ...grpc.CallOption) (*pb.StartDurableResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.StartDurable(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) GetRun(ctx context.Context, in *pb.GetRunRequest, opts ...grpc.CallOption) (*pb.GetRunResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.GetRun(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) BeginGate(ctx context.Context, in *pb.BeginGateRequest, opts ...grpc.CallOption) (*pb.BeginGateResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.BeginGate(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CommitGate(ctx context.Context, in *pb.CommitGateRequest, opts ...grpc.CallOption) (*pb.CommitGateResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CommitGate(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) AbortRollout(ctx context.Context, in *pb.AbortRolloutRequest, opts ...grpc.CallOption) (*pb.AbortRolloutResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.AbortRollout(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) GetRollout(ctx context.Context, in *pb.GetRolloutRequest, opts ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.GetRollout(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ProposeScheduleGrant(ctx context.Context, in *pb.ProposeScheduleGrantRequest, opts ...grpc.CallOption) (*pb.ProposeScheduleGrantResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ProposeScheduleGrant(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CommitScheduleGrant(ctx context.Context, in *pb.CommitScheduleGrantRequest, opts ...grpc.CallOption) (*pb.CommitScheduleGrantResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CommitScheduleGrant(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) RevokeScheduleGrant(ctx context.Context, in *pb.RevokeScheduleGrantRequest, opts ...grpc.CallOption) (*pb.RevokeScheduleGrantResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.RevokeScheduleGrant(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) RunScheduled(ctx context.Context, in *pb.RunScheduledRequest, opts ...grpc.CallOption) (*pb.RunScheduledResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.RunScheduled(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ListScheduleGrants(ctx context.Context, in *pb.ListScheduleGrantsRequest, opts ...grpc.CallOption) (*pb.ListScheduleGrantsResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ListScheduleGrants(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) BeginTrustArtifact(ctx context.Context, in *pb.BeginTrustArtifactRequest, opts ...grpc.CallOption) (*pb.BeginTrustArtifactResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.BeginTrustArtifact(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) CommitTrustArtifact(ctx context.Context, in *pb.CommitTrustArtifactRequest, opts ...grpc.CallOption) (*pb.CommitTrustArtifactResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CommitTrustArtifact(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) GetArtifactTrust(ctx context.Context, in *pb.GetArtifactTrustRequest, opts ...grpc.CallOption) (*pb.GetArtifactTrustResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.GetArtifactTrust(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) RegisterModule(ctx context.Context, in *pb.RegisterModuleRequest, opts ...grpc.CallOption) (*pb.RegisterModuleResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.RegisterModule(ctx, in, opts...)
	}
	return nil, errNotConnected
}

func (l *lazyExecutor) ListEvents(ctx context.Context, in *pb.ListEventsRequest, opts ...grpc.CallOption) (*pb.ListEventsResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ListEvents(ctx, in, opts...)
	}
	return nil, errNotConnected
}
