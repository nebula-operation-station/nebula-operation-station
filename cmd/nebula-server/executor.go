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

func (l *lazyExecutor) ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ListHostKeys(ctx, in, opts...)
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
