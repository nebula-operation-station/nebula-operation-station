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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

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
	return newClient(ctx, o, false)
}

// NewPVECollector creates a Client for a collector-only UID. It verifies the
// executor's peer UID and probes ListPVERemotes instead of GetStatus. An
// Unimplemented response is accepted while the PVE handlers await wiring.
func NewPVECollector(ctx context.Context, o Options) (*Client, error) {
	return newClient(ctx, o, true)
}

func newClient(ctx context.Context, o Options, collector bool) (*Client, error) {
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
	if collector {
		_, err = c.ListPVERemotes(ctx, &pb.ListPVERemotesRequest{})
		if status.Code(err) == codes.Unimplemented {
			err = nil
		}
	} else {
		_, err = c.GetStatus(ctx, &pb.GetStatusRequest{})
	}
	if err != nil {
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

// GetPermitState returns the state of the live permit for the execution
// digest (read-only; UNSPECIFIED when there is no live permit).
func (c *Client) GetPermitState(ctx context.Context, in *pb.GetPermitStateRequest, opts ...grpc.CallOption) (*pb.GetPermitStateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetPermitState(ctx, in, opts...)
	return resp, mapError(err)
}

// ListPVERemotes lists the registered PVE remotes with their nonsecret
// metadata (ADR 0006). Role: server, admin, pve-collector.
func (c *Client) ListPVERemotes(ctx context.Context, in *pb.ListPVERemotesRequest, opts ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPVERemotes(ctx, in, opts...)
	return resp, mapError(err)
}

// ReadPVE performs one typed PVE read against one remote and returns a
// pvecontract-shaped observation page (ADR 0006). Role: admin,
// pve-collector. The server never calls this: the server writes poll
// requests to the spool and the pve-collector schedules the reads.
func (c *Client) ReadPVE(ctx context.Context, in *pb.ReadPVERequest, opts ...grpc.CallOption) (*pb.ReadPVEResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ReadPVE(ctx, in, opts...)
	return resp, mapError(err)
}

// ProbePVERemote probes PVE endpoints without credentials (admin role).
func (c *Client) ProbePVERemote(ctx context.Context, in *pb.ProbePVERemoteRequest, opts ...grpc.CallOption) (*pb.ProbePVERemoteResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProbePVERemote(ctx, in, opts...)
	return resp, mapError(err)
}

// AddPVERemote registers a PVE remote (admin role).
func (c *Client) AddPVERemote(ctx context.Context, in *pb.AddPVERemoteRequest, opts ...grpc.CallOption) (*pb.AddPVERemoteResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.AddPVERemote(ctx, in, opts...)
	return resp, mapError(err)
}

// RotatePVEToken replaces a PVE remote token (admin role).
func (c *Client) RotatePVEToken(ctx context.Context, in *pb.RotatePVETokenRequest, opts ...grpc.CallOption) (*pb.RotatePVETokenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RotatePVEToken(ctx, in, opts...)
	return resp, mapError(err)
}

// RemovePVERemote removes a PVE remote (admin role).
func (c *Client) RemovePVERemote(ctx context.Context, in *pb.RemovePVERemoteRequest, opts ...grpc.CallOption) (*pb.RemovePVERemoteResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemovePVERemote(ctx, in, opts...)
	return resp, mapError(err)
}

// ListPVEAdminRemotes lists PVE remote administration metadata (admin role).
func (c *Client) ListPVEAdminRemotes(ctx context.Context, in *pb.ListPVEAdminRemotesRequest, opts ...grpc.CallOption) (*pb.ListPVEAdminRemotesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPVEAdminRemotes(ctx, in, opts...)
	return resp, mapError(err)
}

// ProposePVERepin proposes a PVE remote trust change (admin role).
func (c *Client) ProposePVERepin(ctx context.Context, in *pb.ProposePVERepinRequest, opts ...grpc.CallOption) (*pb.ProposePVERepinResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposePVERepin(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitPVERepin commits an approved PVE remote trust change (admin role).
func (c *Client) CommitPVERepin(ctx context.Context, in *pb.CommitPVERepinRequest, opts ...grpc.CallOption) (*pb.CommitPVERepinResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitPVERepin(ctx, in, opts...)
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

// CreateRegistrationCode: Creates a one-time registration code (admin role only).
func (c *Client) CreateRegistrationCode(ctx context.Context, in *pb.CreateRegistrationCodeRequest, opts ...grpc.CallOption) (*pb.CreateRegistrationCodeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CreateRegistrationCode(ctx, in, opts...)
	return resp, mapError(err)
}

// BeginRegistration: Starts a WebAuthn registration.
func (c *Client) BeginRegistration(ctx context.Context, in *pb.BeginRegistrationRequest, opts ...grpc.CallOption) (*pb.BeginRegistrationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BeginRegistration(ctx, in, opts...)
	return resp, mapError(err)
}

// FinishRegistration: Completes a WebAuthn registration.
func (c *Client) FinishRegistration(ctx context.Context, in *pb.FinishRegistrationRequest, opts ...grpc.CallOption) (*pb.FinishRegistrationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.FinishRegistration(ctx, in, opts...)
	return resp, mapError(err)
}

// ListWebAuthnCredentials: Lists registered credentials (admin role only).
func (c *Client) ListWebAuthnCredentials(ctx context.Context, in *pb.ListWebAuthnCredentialsRequest, opts ...grpc.CallOption) (*pb.ListWebAuthnCredentialsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListWebAuthnCredentials(ctx, in, opts...)
	return resp, mapError(err)
}

// RemoveWebAuthnCredential: Removes a credential and locks the executor (admin role only).
func (c *Client) RemoveWebAuthnCredential(ctx context.Context, in *pb.RemoveWebAuthnCredentialRequest, opts ...grpc.CallOption) (*pb.RemoveWebAuthnCredentialResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemoveWebAuthnCredential(ctx, in, opts...)
	return resp, mapError(err)
}

// ProbeHostKey: Reads a host key for enrollment (admin role only).
func (c *Client) ProbeHostKey(ctx context.Context, in *pb.ProbeHostKeyRequest, opts ...grpc.CallOption) (*pb.ProbeHostKeyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProbeHostKey(ctx, in, opts...)
	return resp, mapError(err)
}

// PinHostKey: Pins a host key (admin role only).
func (c *Client) PinHostKey(ctx context.Context, in *pb.PinHostKeyRequest, opts ...grpc.CallOption) (*pb.PinHostKeyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.PinHostKey(ctx, in, opts...)
	return resp, mapError(err)
}

// UnpinHostKey: Removes a host key pin (admin role only).
func (c *Client) UnpinHostKey(ctx context.Context, in *pb.UnpinHostKeyRequest, opts ...grpc.CallOption) (*pb.UnpinHostKeyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.UnpinHostKey(ctx, in, opts...)
	return resp, mapError(err)
}

// ListHostKeys: Lists the pinned host keys.
func (c *Client) ListHostKeys(ctx context.Context, in *pb.ListHostKeysRequest, opts ...grpc.CallOption) (*pb.ListHostKeysResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListHostKeys(ctx, in, opts...)
	return resp, mapError(err)
}

// ProposeRepin: Proposes re-pinning a blocked host (server role only).
func (c *Client) ProposeRepin(ctx context.Context, in *pb.ProposeRepinRequest, opts ...grpc.CallOption) (*pb.ProposeRepinResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposeRepin(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitRepin: Carries out an approved re-pin (server role only). It
// probes the host, so it gets a longer timeout.
func (c *Client) CommitRepin(ctx context.Context, in *pb.CommitRepinRequest, opts ...grpc.CallOption) (*pb.CommitRepinResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+30*time.Second)
	defer cancel()
	resp, err := c.rpc.CommitRepin(ctx, in, opts...)
	return resp, mapError(err)
}

// ProposeEnroll: Reads host keys and proposes a bulk enrollment (server
// role only). It probes up to 50 hosts, so it gets a longer timeout.
func (c *Client) ProposeEnroll(ctx context.Context, in *pb.ProposeEnrollRequest, opts ...grpc.CallOption) (*pb.ProposeEnrollResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+2*time.Minute)
	defer cancel()
	resp, err := c.rpc.ProposeEnroll(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitEnroll: Pins the hosts of an approved enrollment (server role only).
func (c *Client) CommitEnroll(ctx context.Context, in *pb.CommitEnrollRequest, opts ...grpc.CallOption) (*pb.CommitEnrollResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+5*time.Minute)
	defer cancel()
	resp, err := c.rpc.CommitEnroll(ctx, in, opts...)
	return resp, mapError(err)
}

// TestConnection: Tests the SSH connection to a pinned host (admin role only).
func (c *Client) TestConnection(ctx context.Context, in *pb.TestConnectionRequest, opts ...grpc.CallOption) (*pb.TestConnectionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.TestConnection(ctx, in, opts...)
	return resp, mapError(err)
}

// BeginLogin: Starts a web login (server role).
func (c *Client) BeginLogin(ctx context.Context, in *pb.BeginLoginRequest, opts ...grpc.CallOption) (*pb.BeginLoginResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BeginLogin(ctx, in, opts...)
	return resp, mapError(err)
}

// FinishLogin: Completes a web login (server role).
func (c *Client) FinishLogin(ctx context.Context, in *pb.FinishLoginRequest, opts ...grpc.CallOption) (*pb.FinishLoginResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.FinishLogin(ctx, in, opts...)
	return resp, mapError(err)
}

// CheckCredential: Reports whether a credential is still registered (server role).
func (c *Client) CheckCredential(ctx context.Context, in *pb.CheckCredentialRequest, opts ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CheckCredential(ctx, in, opts...)
	return resp, mapError(err)
}

// BeginTOTPSetup: Creates a new TOTP recovery secret (admin role only).
func (c *Client) BeginTOTPSetup(ctx context.Context, in *pb.BeginTOTPSetupRequest, opts ...grpc.CallOption) (*pb.BeginTOTPSetupResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BeginTOTPSetup(ctx, in, opts...)
	return resp, mapError(err)
}

// ConfirmTOTPSetup: Activates the TOTP secret (admin role only).
func (c *Client) ConfirmTOTPSetup(ctx context.Context, in *pb.ConfirmTOTPSetupRequest, opts ...grpc.CallOption) (*pb.ConfirmTOTPSetupResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ConfirmTOTPSetup(ctx, in, opts...)
	return resp, mapError(err)
}

// RemoveTOTP: Removes the TOTP secret (admin role only).
func (c *Client) RemoveTOTP(ctx context.Context, in *pb.RemoveTOTPRequest, opts ...grpc.CallOption) (*pb.RemoveTOTPResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemoveTOTP(ctx, in, opts...)
	return resp, mapError(err)
}

// GetTOTPStatus: Reports the TOTP and recovery state (admin role only).
func (c *Client) GetTOTPStatus(ctx context.Context, in *pb.GetTOTPStatusRequest, opts ...grpc.CallOption) (*pb.GetTOTPStatusResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetTOTPStatus(ctx, in, opts...)
	return resp, mapError(err)
}

// RecoveryLogin: Verifies a TOTP recovery code (server role).
func (c *Client) RecoveryLogin(ctx context.Context, in *pb.RecoveryLoginRequest, opts ...grpc.CallOption) (*pb.RecoveryLoginResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RecoveryLogin(ctx, in, opts...)
	return resp, mapError(err)
}

// FinishRecovery: Ends a pending recovery (admin role only).
func (c *Client) FinishRecovery(ctx context.Context, in *pb.FinishRecoveryRequest, opts ...grpc.CallOption) (*pb.FinishRecoveryResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.FinishRecovery(ctx, in, opts...)
	return resp, mapError(err)
}

// GetSSHPublicKey: Returns a loaded SSH public key (admin role only).
func (c *Client) GetSSHPublicKey(ctx context.Context, in *pb.GetSSHPublicKeyRequest, opts ...grpc.CallOption) (*pb.GetSSHPublicKeyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetSSHPublicKey(ctx, in, opts...)
	return resp, mapError(err)
}

// InitVault: Creates the vault (admin role only).
func (c *Client) InitVault(ctx context.Context, in *pb.InitVaultRequest, opts ...grpc.CallOption) (*pb.InitVaultResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.InitVault(ctx, in, opts...)
	return resp, mapError(err)
}

// SetSecret: Stores a vault secret (admin role only).
func (c *Client) SetSecret(ctx context.Context, in *pb.SetSecretRequest, opts ...grpc.CallOption) (*pb.SetSecretResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.SetSecret(ctx, in, opts...)
	return resp, mapError(err)
}

// ListSecrets: Lists vault secret IDs (admin role only).
func (c *Client) ListSecrets(ctx context.Context, in *pb.ListSecretsRequest, opts ...grpc.CallOption) (*pb.ListSecretsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListSecrets(ctx, in, opts...)
	return resp, mapError(err)
}

// DeleteSecret: Deletes a vault secret (admin role only).
func (c *Client) DeleteSecret(ctx context.Context, in *pb.DeleteSecretRequest, opts ...grpc.CallOption) (*pb.DeleteSecretResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.DeleteSecret(ctx, in, opts...)
	return resp, mapError(err)
}

// RunAttached: Runs one authorized host run attached (server role). The
// call may take the run's timeout plus connection time.
func (c *Client) RunAttached(ctx context.Context, in *pb.RunAttachedRequest, opts ...grpc.CallOption) (*pb.RunAttachedResponse, error) {
	t := time.Duration(in.GetTimeoutSeconds()) * time.Second
	if t <= 0 || t > 10*time.Minute {
		t = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, t+time.Minute)
	defer cancel()
	resp, err := c.rpc.RunAttached(ctx, in, opts...)
	return resp, mapError(err)
}

// StartDurable: Starts one authorized host run as a durable job (server role).
func (c *Client) StartDurable(ctx context.Context, in *pb.StartDurableRequest, opts ...grpc.CallOption) (*pb.StartDurableResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	resp, err := c.rpc.StartDurable(ctx, in, opts...)
	return resp, mapError(err)
}

// GetRun: The state of a durable run (server role).
func (c *Client) GetRun(ctx context.Context, in *pb.GetRunRequest, opts ...grpc.CallOption) (*pb.GetRunResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetRun(ctx, in, opts...)
	return resp, mapError(err)
}

// BeginGate: Checks a gate and returns what it needs (server role).
func (c *Client) BeginGate(ctx context.Context, in *pb.BeginGateRequest, opts ...grpc.CallOption) (*pb.BeginGateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BeginGate(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitGate: Applies a gate (server role).
func (c *Client) CommitGate(ctx context.Context, in *pb.CommitGateRequest, opts ...grpc.CallOption) (*pb.CommitGateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitGate(ctx, in, opts...)
	return resp, mapError(err)
}

// AbortRollout: Stops a rollout (server role).
func (c *Client) AbortRollout(ctx context.Context, in *pb.AbortRolloutRequest, opts ...grpc.CallOption) (*pb.AbortRolloutResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.AbortRollout(ctx, in, opts...)
	return resp, mapError(err)
}

// GetRollout: The executor's view of a rollout (server and admin roles).
func (c *Client) GetRollout(ctx context.Context, in *pb.GetRolloutRequest, opts ...grpc.CallOption) (*pb.GetRolloutResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetRollout(ctx, in, opts...)
	return resp, mapError(err)
}

// ApproveGateCLI: Hardened gate path (admin role).
func (c *Client) ApproveGateCLI(ctx context.Context, in *pb.ApproveGateCLIRequest, opts ...grpc.CallOption) (*pb.ApproveGateCLIResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ApproveGateCLI(ctx, in, opts...)
	return resp, mapError(err)
}

// ProposeScheduleGrant: Checks a schedule grant document (server role).
func (c *Client) ProposeScheduleGrant(ctx context.Context, in *pb.ProposeScheduleGrantRequest, opts ...grpc.CallOption) (*pb.ProposeScheduleGrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ProposeScheduleGrant(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitScheduleGrant: Approves a schedule grant (server role).
func (c *Client) CommitScheduleGrant(ctx context.Context, in *pb.CommitScheduleGrantRequest, opts ...grpc.CallOption) (*pb.CommitScheduleGrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitScheduleGrant(ctx, in, opts...)
	return resp, mapError(err)
}

// ListPendingScheduleGrants: Proposed schedule grants (admin role).
func (c *Client) ListPendingScheduleGrants(ctx context.Context, in *pb.ListPendingScheduleGrantsRequest, opts ...grpc.CallOption) (*pb.ListPendingScheduleGrantsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListPendingScheduleGrants(ctx, in, opts...)
	return resp, mapError(err)
}

// ApproveScheduleGrantCLI: Hardened grant approval (admin role).
func (c *Client) ApproveScheduleGrantCLI(ctx context.Context, in *pb.ApproveScheduleGrantCLIRequest, opts ...grpc.CallOption) (*pb.ApproveScheduleGrantCLIResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ApproveScheduleGrantCLI(ctx, in, opts...)
	return resp, mapError(err)
}

// ListScheduleGrants: Stored schedule grants (server and admin roles).
func (c *Client) ListScheduleGrants(ctx context.Context, in *pb.ListScheduleGrantsRequest, opts ...grpc.CallOption) (*pb.ListScheduleGrantsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListScheduleGrants(ctx, in, opts...)
	return resp, mapError(err)
}

// RevokeScheduleGrant: Revokes a schedule grant (server and admin roles).
func (c *Client) RevokeScheduleGrant(ctx context.Context, in *pb.RevokeScheduleGrantRequest, opts ...grpc.CallOption) (*pb.RevokeScheduleGrantResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RevokeScheduleGrant(ctx, in, opts...)
	return resp, mapError(err)
}

// RunScheduled: Runs one host run under a schedule grant (server role).
// It runs on the host, so it gets the run timeout like RunAttached.
func (c *Client) RunScheduled(ctx context.Context, in *pb.RunScheduledRequest, opts ...grpc.CallOption) (*pb.RunScheduledResponse, error) {
	t := time.Duration(in.GetTimeoutSeconds()) * time.Second
	if t <= 0 || t > 10*time.Minute {
		t = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout+t)
	defer cancel()
	resp, err := c.rpc.RunScheduled(ctx, in, opts...)
	return resp, mapError(err)
}

// BeginTrustArtifact: Starts trusting an artifact from the browser (server role).
func (c *Client) BeginTrustArtifact(ctx context.Context, in *pb.BeginTrustArtifactRequest, opts ...grpc.CallOption) (*pb.BeginTrustArtifactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BeginTrustArtifact(ctx, in, opts...)
	return resp, mapError(err)
}

// CommitTrustArtifact: Trusts the artifact with the security key's assertion (server role).
func (c *Client) CommitTrustArtifact(ctx context.Context, in *pb.CommitTrustArtifactRequest, opts ...grpc.CallOption) (*pb.CommitTrustArtifactResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.CommitTrustArtifact(ctx, in, opts...)
	return resp, mapError(err)
}

// GetArtifactTrust: Whether the executor trusts an artifact (server and admin roles).
func (c *Client) GetArtifactTrust(ctx context.Context, in *pb.GetArtifactTrustRequest, opts ...grpc.CallOption) (*pb.GetArtifactTrustResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.GetArtifactTrust(ctx, in, opts...)
	return resp, mapError(err)
}

// RegisterModule: Verifies and registers a signed module (server role).
func (c *Client) RegisterModule(ctx context.Context, in *pb.RegisterModuleRequest, opts ...grpc.CallOption) (*pb.RegisterModuleResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RegisterModule(ctx, in, opts...)
	return resp, mapError(err)
}

// AddSigner: Trusts a module signer (admin role).
func (c *Client) AddSigner(ctx context.Context, in *pb.AddSignerRequest, opts ...grpc.CallOption) (*pb.AddSignerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.AddSigner(ctx, in, opts...)
	return resp, mapError(err)
}

// RemoveSigner: Removes a module signer (admin role).
func (c *Client) RemoveSigner(ctx context.Context, in *pb.RemoveSignerRequest, opts ...grpc.CallOption) (*pb.RemoveSignerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.RemoveSigner(ctx, in, opts...)
	return resp, mapError(err)
}

// ConfirmModuleSigner: Accepts a module's new signer (admin role).
func (c *Client) ConfirmModuleSigner(ctx context.Context, in *pb.ConfirmModuleSignerRequest, opts ...grpc.CallOption) (*pb.ConfirmModuleSignerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ConfirmModuleSigner(ctx, in, opts...)
	return resp, mapError(err)
}

// ListSigners: Lists module signers (server and admin roles).
func (c *Client) ListSigners(ctx context.Context, in *pb.ListSignersRequest, opts ...grpc.CallOption) (*pb.ListSignersResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListSigners(ctx, in, opts...)
	return resp, mapError(err)
}

// ListEvents reads the executor's signed event chain (M10-1).
func (c *Client) ListEvents(ctx context.Context, in *pb.ListEventsRequest, opts ...grpc.CallOption) (*pb.ListEventsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.ListEvents(ctx, in, opts...)
	return resp, mapError(err)
}

// BackupExecutor is admin-only on the executor; the server's calls are
// refused there.
func (c *Client) BackupExecutor(ctx context.Context, in *pb.BackupExecutorRequest, opts ...grpc.CallOption) (*pb.BackupExecutorResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.defaultTimeout)
	defer cancel()
	resp, err := c.rpc.BackupExecutor(ctx, in, opts...)
	return resp, mapError(err)
}

// Compile-time check: the client must implement the generated interface so
// that a generated-code change breaks the build here.
var _ pb.ExecutorServiceClient = (*Client)(nil)
