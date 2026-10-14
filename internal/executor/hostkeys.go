// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// SSH host keys and connections (H05, spec 08).

// Connection refusals before any network traffic.
var (
	ErrHostNotPinned     = errors.New("host has no pinned key; enroll it first")
	ErrHostBlocked       = errors.New("host is blocked after a host key mismatch; re-pin it on the executor host")
	ErrTargetFingerprint = errors.New("the target's host key fingerprint differs from the pinned key")
)

// Connect opens an SSH connection to a pinned host over endpoints, in
// order, with the host's own credential only. fingerprint, if not empty, is
// the key the caller expects (a permit's target) and must equal the pin.
// A host key mismatch blocks the host; it stays blocked until re-pinned.
func (s *Service) Connect(ctx context.Context, hostID, fingerprint string, endpoints []sshtransport.Endpoint) (*sshtransport.Client, error) {
	hk, ok, err := s.db.HostKey(hostID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrHostNotPinned
	}
	if hk.Blocked != nil {
		return nil, ErrHostBlocked
	}
	if fingerprint != "" && fingerprint != hk.Fingerprint {
		return nil, ErrTargetFingerprint
	}
	pin, err := ssh.ParsePublicKey(hk.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("stored host key of %s: %w", hostID, err)
	}
	signer, err := s.keys.Signer(hk.CredentialRef)
	if err != nil {
		return nil, err
	}
	c, err := s.transport.Dial(ctx, sshtransport.Target{HostID: hostID, Endpoints: endpoints, User: hk.User, HostKey: pin}, signer)
	if err == nil {
		return c, nil
	}
	var te *sshtransport.Error
	if errors.As(err, &te) {
		switch te.Class {
		case sshtransport.ClassHostKeyMismatch:
			presented, endpoint := "", ""
			if te.Presented != nil {
				presented = sshtransport.Fingerprint(te.Presented)
			}
			if n := len(te.Attempts); n > 0 {
				endpoint = te.Attempts[n-1].Endpoint.String()
			}
			set, berr := s.db.BlockHost(hostID, presented, endpoint)
			if berr != nil {
				s.log.Error("audit", "kind", "store_error", "op", "block_host", "host", hostID, "detail", berr.Error())
			}
			s.log.Error("audit", "kind", "host_key_mismatch", "host", hostID, "endpoint", endpoint,
				"pinned", hk.Fingerprint, "presented", presented, "newly_blocked", set)
		case sshtransport.ClassAuth:
			s.log.Warn("audit", "kind", "ssh_auth_failed", "host", hostID, "user", hk.User,
				"credential", hk.CredentialRef, "detail", te.Detail)
		}
	}
	return nil, err
}

func parseEndpoints(in []string) ([]sshtransport.Endpoint, error) {
	if len(in) == 0 || len(in) > sshtransport.MaxEndpoints {
		return nil, fmt.Errorf("need 1..%d endpoints", sshtransport.MaxEndpoints)
	}
	out := make([]sshtransport.Endpoint, len(in))
	for i, s := range in {
		ep, err := sshtransport.ParseEndpoint(s)
		if err != nil {
			return nil, err
		}
		out[i] = ep
	}
	return out, nil
}

func (s *Service) ProbeHostKey(ctx context.Context, req *pb.ProbeHostKeyRequest) (*pb.ProbeHostKeyResponse, error) {
	ep, err := sshtransport.ParseEndpoint(req.GetEndpoint())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	k, err := s.transport.Probe(ctx, ep)
	if err != nil {
		if sshtransport.ClassOf(err) == sshtransport.ClassInvalid {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &pb.ProbeHostKeyResponse{
		Endpoint: ep.String(), KeyType: k.Type(), Fingerprint: sshtransport.Fingerprint(k),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))),
	}, nil
}

func sourceFromProto(s pb.HostKeySource) (string, error) {
	switch s {
	case pb.HostKeySource_HOST_KEY_SOURCE_PROBE:
		return executordb.SourceProbe, nil
	case pb.HostKeySource_HOST_KEY_SOURCE_KNOWN_HOSTS:
		return executordb.SourceKnownHosts, nil
	default:
		return "", errors.New("source is required")
	}
}

func sourceToProto(s string) pb.HostKeySource {
	switch s {
	case executordb.SourceProbe:
		return pb.HostKeySource_HOST_KEY_SOURCE_PROBE
	case executordb.SourceKnownHosts:
		return pb.HostKeySource_HOST_KEY_SOURCE_KNOWN_HOSTS
	default:
		return pb.HostKeySource_HOST_KEY_SOURCE_UNSPECIFIED
	}
}

func pinToProto(k executordb.HostKey) *pb.HostKeyPin {
	out := &pb.HostKeyPin{
		HostId: k.HostID, Fingerprint: k.Fingerprint, SshUser: k.User, CredentialRef: k.CredentialRef,
		Source: sourceToProto(k.Source), PinnedAtUnix: k.PinnedAt.Unix(), PinnedBy: k.PinnedBy,
	}
	if pk, err := ssh.ParsePublicKey(k.PublicKey); err == nil {
		out.KeyType = pk.Type()
	}
	if k.Blocked != nil {
		out.Blocked = true
		out.BlockedAtUnix = k.Blocked.At.Unix()
		out.BlockedFingerprint = k.Blocked.Fingerprint
		out.BlockedEndpoint = k.Blocked.Endpoint
	}
	return out
}

func (s *Service) PinHostKey(ctx context.Context, req *pb.PinHostKeyRequest) (*pb.PinHostKeyResponse, error) {
	if !canonical.ValidHostID(req.GetHostId()) {
		return nil, status.Errorf(codes.InvalidArgument, "host_id %q is malformed", req.GetHostId())
	}
	src, err := sourceFromProto(req.GetSource())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(req.GetAuthorizedKey()) > 4096 || strings.ContainsAny(req.GetAuthorizedKey(), "\r\n") {
		return nil, status.Error(codes.InvalidArgument, "authorized_key must be one line")
	}
	k, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(req.GetAuthorizedKey()))
	if err != nil || len(options) != 0 || len(rest) != 0 {
		return nil, status.Error(codes.InvalidArgument, "authorized_key must be one plain \"type base64\" key")
	}
	if err := sshtransport.CheckHostKey(k); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	fp := sshtransport.Fingerprint(k)
	if req.GetExpectedFingerprint() != fp {
		return nil, status.Errorf(codes.InvalidArgument, "the key's fingerprint is %s, not the confirmed %q", fp, req.GetExpectedFingerprint())
	}
	if _, err := s.keys.Signer(req.GetCredentialRef()); errors.Is(err, keyring.ErrUnknownRef) {
		return nil, status.Errorf(codes.InvalidArgument, "credential reference %q is not loaded in the keyring", req.GetCredentialRef())
	}
	who := callerName(ctx)
	pinned, err := s.db.PinHostKey(executordb.HostKey{
		HostID: req.GetHostId(), PublicKey: k.Marshal(), User: req.GetSshUser(),
		CredentialRef: req.GetCredentialRef(), Source: src, PinnedBy: who,
	})
	if errors.Is(err, executordb.ErrHostPinned) {
		return nil, status.Errorf(codes.AlreadyExists, "host %s is already pinned; unpin it first", req.GetHostId())
	}
	if err != nil {
		return nil, s.adminStoreError("pin_host_key", err)
	}
	s.log.Info("audit", "kind", "host_key_pinned", "by", who, "host", pinned.HostID, "fingerprint", pinned.Fingerprint,
		"user", pinned.User, "credential", pinned.CredentialRef, "source", pinned.Source)
	return &pb.PinHostKeyResponse{Pin: pinToProto(pinned)}, nil
}

func (s *Service) UnpinHostKey(ctx context.Context, req *pb.UnpinHostKeyRequest) (*pb.UnpinHostKeyResponse, error) {
	old, removed, err := s.db.UnpinHostKey(req.GetHostId(), req.GetExpectedFingerprint())
	if err != nil {
		return nil, s.adminStoreError("unpin_host_key", err)
	}
	if removed {
		blocked := old.Blocked != nil
		s.log.Warn("audit", "kind", "host_key_unpinned", "by", callerName(ctx), "host", old.HostID,
			"fingerprint", old.Fingerprint, "was_blocked", blocked)
	}
	return &pb.UnpinHostKeyResponse{Removed: removed}, nil
}

func (s *Service) ListHostKeys(_ context.Context, _ *pb.ListHostKeysRequest) (*pb.ListHostKeysResponse, error) {
	list, err := s.db.ListHostKeys()
	if err != nil {
		return nil, s.adminStoreError("list_host_keys", err)
	}
	out := &pb.ListHostKeysResponse{}
	for _, k := range list {
		out.Hosts = append(out.Hosts, pinToProto(k))
	}
	return out, nil
}

func (s *Service) TestConnection(ctx context.Context, req *pb.TestConnectionRequest) (*pb.TestConnectionResponse, error) {
	eps, err := parseEndpoints(req.GetEndpoints())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	c, err := s.Connect(ctx, req.GetHostId(), "", eps)
	switch {
	case err == nil:
		defer c.Close()
		resp := &pb.TestConnectionResponse{Ok: true, Endpoint: c.Endpoint.String()}
		resp.Attempts = attemptsToProto(c.Attempts)
		return resp, nil
	case errors.Is(err, ErrHostNotPinned):
		return nil, status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrHostBlocked):
		return &pb.TestConnectionResponse{FailureClass: "blocked", Detail: err.Error()}, nil
	case errors.Is(err, keyring.ErrLocked):
		return nil, status.Error(codes.FailedPrecondition, "keyring is locked; run `nebula unlock`")
	case errors.Is(err, keyring.ErrUnknownRef):
		return nil, status.Error(codes.FailedPrecondition, "the host's credential reference is not loaded in the keyring")
	}
	var te *sshtransport.Error
	if errors.As(err, &te) {
		return &pb.TestConnectionResponse{FailureClass: string(te.Class), Detail: te.Detail, Attempts: attemptsToProto(te.Attempts)}, nil
	}
	return nil, s.adminStoreError("test_connection", err)
}

func attemptsToProto(in []sshtransport.Attempt) []*pb.ConnectionAttempt {
	out := make([]*pb.ConnectionAttempt, len(in))
	for i, a := range in {
		msg := ""
		if a.Err != nil {
			msg = a.Err.Error()
		}
		out[i] = &pb.ConnectionAttempt{Endpoint: a.Endpoint.String(), Stage: a.Stage, Error: msg}
	}
	return out
}

// GetSSHPublicKey returns the public half of a loaded key for the
// enrollment script (`nebula host enroll-script`).
func (s *Service) GetSSHPublicKey(_ context.Context, req *pb.GetSSHPublicKeyRequest) (*pb.GetSSHPublicKeyResponse, error) {
	signer, err := s.keys.Signer(req.GetCredentialRef())
	switch {
	case errors.Is(err, keyring.ErrLocked):
		return nil, status.Error(codes.FailedPrecondition, "keyring is locked; run `nebula unlock`")
	case errors.Is(err, keyring.ErrUnknownRef):
		return nil, status.Errorf(codes.NotFound, "credential reference %q is not loaded", req.GetCredentialRef())
	case err != nil:
		return nil, status.Error(codes.Internal, "keyring error")
	}
	pub := signer.PublicKey()
	return &pb.GetSSHPublicKeyResponse{
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint:   sshtransport.Fingerprint(pub),
	}, nil
}
