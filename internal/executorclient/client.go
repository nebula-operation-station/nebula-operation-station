// SPDX-License-Identifier: AGPL-3.0-or-later

// Package executorclient is the typed gRPC client nebula-server uses to
// talk to nebula-executor over the SO_PEERCRED Unix socket.
//
// The client dials only through peercred.DialVerified, so a socket planted
// by another user is never talked to. Every call has a per-call timeout,
// and every failure is returned as a typed *Error that callers branch on
// with errors.Is.
package executorclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Per-call timeouts.
const (
	// DefaultCallTimeout bounds every call except AuthorizeRun.
	DefaultCallTimeout = 10 * time.Second
	// AuthorizeRunCallTimeout bounds AuthorizeRun, which hashes artifacts of
	// up to permit.MaxArtifactSize.
	AuthorizeRunCallTimeout = 60 * time.Second
)

// Options configure a Client.
type Options struct {
	// SocketPath is the executor's Unix domain socket (absolute path).
	SocketPath string
	// ExecutorUser is the OS user the executor runs as. The socket must be
	// served by this user's UID; any other UID is refused.
	ExecutorUser string
	// DefaultTimeout bounds every call except AuthorizeRun. Zero means
	// DefaultCallTimeout.
	DefaultTimeout time.Duration
	// AuthorizeRunTimeout bounds AuthorizeRun. Zero means
	// AuthorizeRunCallTimeout.
	AuthorizeRunTimeout time.Duration
}

// Client is a typed executor client. It implements pb.ExecutorServiceClient
// and is safe for concurrent use.
type Client struct {
	cc  *grpc.ClientConn
	rpc pb.ExecutorServiceClient

	defaultTimeout   time.Duration
	authorizeTimeout time.Duration
}

// New creates a Client and verifies the connection: the socket must exist,
// be served by the configured executor user, and answer GetStatus.
func New(ctx context.Context, o Options) (*Client, error) {
	if o.SocketPath == "" {
		return nil, errors.New("executorclient: SocketPath is required")
	}
	if !filepath.IsAbs(o.SocketPath) {
		return nil, fmt.Errorf("executorclient: SocketPath %q must be an absolute path", o.SocketPath)
	}
	if o.ExecutorUser == "" {
		return nil, errors.New("executorclient: ExecutorUser is required")
	}
	wantUID, err := peercred.LookupUID(o.ExecutorUser)
	if err != nil {
		return nil, fmt.Errorf("executorclient: resolve executor user %q: %w", o.ExecutorUser, err)
	}
	if o.DefaultTimeout <= 0 {
		o.DefaultTimeout = DefaultCallTimeout
	}
	if o.AuthorizeRunTimeout <= 0 {
		o.AuthorizeRunTimeout = AuthorizeRunCallTimeout
	}

	// The dialer is the only place that touches the socket: it dials the
	// configured path and refuses a socket served by another UID. The
	// address argument is the resolver endpoint, not the socket path, so it
	// is ignored here (same pattern as cmd/nebula-server).
	conn, err := grpc.NewClient("passthrough:///executor",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, o.SocketPath, wantUID)
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(executor.MaxMessageSize),
			grpc.MaxCallRecvMsgSize(executor.MaxResponseSize)))
	if err != nil {
		return nil, fmt.Errorf("executorclient: %w", err)
	}
	c := &Client{
		cc:               conn,
		rpc:              pb.NewExecutorServiceClient(conn),
		defaultTimeout:   o.DefaultTimeout,
		authorizeTimeout: o.AuthorizeRunTimeout,
	}
	if _, err := c.GetStatus(ctx, &pb.GetStatusRequest{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("executorclient: verify executor at %s: %w", o.SocketPath, err)
	}
	return c, nil
}

// Close closes the connection to the executor.
func (c *Client) Close() error { return c.cc.Close() }

// The methods below implement pb.ExecutorServiceClient. Each call gets a
// per-call timeout (DefaultTimeout, or AuthorizeRunTimeout for AuthorizeRun)
// and its failure is converted to a typed *Error.

// GetStatus returns the executor's state.
func (c *Client) GetStatus(ctx context.Context, in *pb.GetStatusRequest, opts ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetStatus(ctx, in, opts...)
	return resp, mapError(err)
}

// Unlock decrypts the vault with the given passphrase.
func (c *Client) Unlock(ctx context.Context, in *pb.UnlockRequest, opts ...grpc.CallOption) (*pb.UnlockResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.Unlock(ctx, in, opts...)
	return resp, mapError(err)
}

// BeginPrivilegedSession starts a privileged session and returns the
// WebAuthn challenge.
func (c *Client) BeginPrivilegedSession(ctx context.Context, in *pb.BeginPrivilegedSessionRequest, opts ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BeginPrivilegedSession(ctx, in, opts...)
	return resp, mapError(err)
}

// CompletePrivilegedSession verifies the WebAuthn assertion and opens the
// session.
func (c *Client) CompletePrivilegedSession(ctx context.Context, in *pb.CompletePrivilegedSessionRequest, opts ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CompletePrivilegedSession(ctx, in, opts...)
	return resp, mapError(err)
}

// ProposeExecution stores an execution request and returns the permit
// digest and, for medium and high risk, the approval challenge.
func (c *Client) ProposeExecution(ctx context.Context, in *pb.ProposeExecutionRequest, opts ...grpc.CallOption) (*pb.ProposeExecutionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposeExecution(ctx, in, opts...)
	return resp, mapError(err)
}

// SubmitAssertion approves a proposed execution with a WebAuthn assertion.
func (c *Client) SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.SubmitAssertion(ctx, in, opts...)
	return resp, mapError(err)
}

// AuthorizeRun verifies a single run against its permit. It uses the
// AuthorizeRun timeout because it hashes the full artifact.
func (c *Client) AuthorizeRun(ctx context.Context, in *pb.AuthorizeRunRequest, opts ...grpc.CallOption) (*pb.AuthorizeRunResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.authorizeTimeout)
	defer cancel()
	resp, err := c.rpc.AuthorizeRun(ctx, in, opts...)
	return resp, mapError(err)
}

// Lock re-encrypts and drops the vault keys.
func (c *Client) Lock(ctx context.Context, in *pb.LockRequest, opts ...grpc.CallOption) (*pb.LockResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.Lock(ctx, in, opts...)
	return resp, mapError(err)
}

// ListPending lists executions that still need an approval.
func (c *Client) ListPending(ctx context.Context, in *pb.ListPendingRequest, opts ...grpc.CallOption) (*pb.ListPendingResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPending(ctx, in, opts...)
	return resp, mapError(err)
}

// ApproveCLI approves a pending execution from the CLI (hardened mode).
func (c *Client) ApproveCLI(ctx context.Context, in *pb.ApproveCLIRequest, opts ...grpc.CallOption) (*pb.ApproveCLIResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ApproveCLI(ctx, in, opts...)
	return resp, mapError(err)
}

// The risk-data methods below are admin-only on the executor (H01); the
// server's UID is denied. They exist so that Client implements the full
// generated interface.

// TrustArtifact trusts an artifact at a declared risk (admin role only).
func (c *Client) TrustArtifact(ctx context.Context, in *pb.TrustArtifactRequest, opts ...grpc.CallOption) (*pb.TrustArtifactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.authorizeTimeout)
	defer cancel()
	resp, err := c.rpc.TrustArtifact(ctx, in, opts...)
	return resp, mapError(err)
}

// UntrustArtifact withdraws trust (admin role only).
func (c *Client) UntrustArtifact(ctx context.Context, in *pb.UntrustArtifactRequest, opts ...grpc.CallOption) (*pb.UntrustArtifactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.UntrustArtifact(ctx, in, opts...)
	return resp, mapError(err)
}

// ListTrustedArtifacts lists trusted artifacts (admin role only).
func (c *Client) ListTrustedArtifacts(ctx context.Context, in *pb.ListTrustedArtifactsRequest, opts ...grpc.CallOption) (*pb.ListTrustedArtifactsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListTrustedArtifacts(ctx, in, opts...)
	return resp, mapError(err)
}

// SetHostCriticality sets or clears a host's criticality (admin role only).
func (c *Client) SetHostCriticality(ctx context.Context, in *pb.SetHostCriticalityRequest, opts ...grpc.CallOption) (*pb.SetHostCriticalityResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.SetHostCriticality(ctx, in, opts...)
	return resp, mapError(err)
}

// ListHostCriticality lists host criticality records (admin role only).
func (c *Client) ListHostCriticality(ctx context.Context, in *pb.ListHostCriticalityRequest, opts ...grpc.CallOption) (*pb.ListHostCriticalityResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListHostCriticality(ctx, in, opts...)
	return resp, mapError(err)
}

// Compile-time check: the client must implement the generated interface so
// that a generated-code change breaks the build here.
var _ pb.ExecutorServiceClient = (*Client)(nil)
