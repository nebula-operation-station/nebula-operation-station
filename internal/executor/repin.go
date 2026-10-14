// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Re-pinning a blocked host from the web UI (spec 08: "Re-pinning a
// changed key is a HIGH action with user verification"). The executor
// builds the request from its own block record, so the server names only
// the host; the approved request binds host, pinned and presented key,
// endpoint and block time. Commit rebuilds the request from the current
// record: anything that changed since the approval no longer matches it.

const (
	// repinAction is reserved: ProposeExecution refuses the nebula.
	// namespace, so only ProposeRepin can create such a permit.
	repinAction  = "nebula.host_key.repin"
	repinVersion = "1.0.0"
	// repinLifetime bounds approval and commit.
	repinLifetime = 15 * time.Minute
	// reservedActionPrefix is the namespace of executor-internal actions.
	reservedActionPrefix = "nebula."
)

// repinArtifact is the fixed "script" of a re-pin. Nothing runs on the
// host; the bytes name the operation so that its hash is part of the
// approval like any artifact.
var repinArtifact = []byte("nebula.host_key.repin 1.0.0\nReplace the pinned SSH host key of the host with the key it presented\n(see the parameters); the host's criticality record moves with it.\n")

// stagePlanRepin is the stage plan hash of a re-pin (one step, no stages).
var stagePlanRepin = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"repin-v1"}`))
	return s
}()

// repinParams are the parameters of a re-pin, from the executor's record.
func repinParams(hk executordb.HostKey) ([]byte, error) {
	if hk.Blocked == nil {
		return nil, errors.New("not blocked")
	}
	return json.Marshal(map[string]any{
		"host":             hk.HostID,
		"pinned":           hk.Fingerprint,
		"presented":        hk.Blocked.Fingerprint,
		"endpoint":         hk.Blocked.Endpoint,
		"blocked_at_unix":  hk.Blocked.At.Unix(),
		"credential":       hk.CredentialRef,
		"ssh_user":         hk.User,
		"criticality_kept": true,
	})
}

// repinnable checks that a host can be re-pinned from the UI.
func repinnable(hk executordb.HostKey, ok bool) error {
	switch {
	case !ok:
		return status.Error(codes.NotFound, ErrHostNotPinned.Error())
	case hk.Blocked == nil:
		return status.Error(codes.FailedPrecondition, "host_not_blocked: the host is not blocked by a host key mismatch")
	case !canonical.ValidHostKeyFingerprint(hk.Blocked.Fingerprint):
		return status.Error(codes.FailedPrecondition,
			"no_presented_key: the host offered no key of the pinned type; re-pin it with `nebula host unpin` and `nebula host pin`")
	}
	if _, err := sshtransport.ParseEndpoint(hk.Blocked.Endpoint); err != nil {
		return status.Error(codes.FailedPrecondition, "the recorded endpoint is unusable; re-pin it on the executor host")
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newExecutionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ProposeRepin proposes re-pinning a blocked host (server role).
func (s *Service) ProposeRepin(_ context.Context, req *pb.ProposeRepinRequest) (*pb.ProposeRepinResponse, error) {
	if !canonical.ValidHostID(req.GetHostId()) {
		return nil, status.Errorf(codes.InvalidArgument, "host_id %q is malformed", req.GetHostId())
	}
	hk, ok, err := s.db.HostKey(req.GetHostId())
	if err != nil {
		return nil, s.adminStoreError("repin", err)
	}
	if err := repinnable(hk, ok); err != nil {
		return nil, err
	}
	params, err := repinParams(hk)
	if err != nil {
		return nil, status.Error(codes.Internal, "repin parameters")
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return nil, status.Error(codes.Internal, "repin parameters")
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "random")
	}
	r := canonical.Request{
		ExecutionID: id, ActionID: repinAction, ModuleVersion: repinVersion,
		ArtifactSHA256: sha256Hex(repinArtifact), ParametersHash: ph,
		CredentialRefs: []string{hk.CredentialRef},
		// At least HIGH (user verification); a CRITICAL host stays CRITICAL.
		RiskClass:       canonical.RiskHigh,
		StagePlanHash:   stagePlanRepin,
		ExpiryUnix:      s.clock().Add(repinLifetime).Unix(),
		ResolvedTargets: []canonical.Target{{HostID: hk.HostID, HostKeyFingerprint: hk.Fingerprint}},
	}
	res, err := s.auth.ProposeAtLeastMinimum(r, params)
	if err != nil {
		return nil, toStatus(err)
	}
	p := res.Permit
	out, err := s.permitResponse(p)
	if err != nil {
		return nil, err
	}
	s.log.Warn("audit", "kind", "repin_proposed", "host", hk.HostID, "digest", p.Digest.String(),
		"pinned", hk.Fingerprint, "presented", hk.Blocked.Fingerprint, "endpoint", hk.Blocked.Endpoint, "risk", string(p.Request.RiskClass))
	return &pb.ProposeRepinResponse{Permit: out, Pin: pinToProto(hk)}, nil
}

// CommitRepin carries out an approved re-pin (server role).
func (s *Service) CommitRepin(ctx context.Context, req *pb.CommitRepinRequest) (*pb.CommitRepinResponse, error) {
	d, err := canonical.ParseDigest(req.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	hk, ok, err := s.db.HostKey(req.GetHostId())
	if err != nil {
		return nil, s.adminStoreError("repin", err)
	}
	if err := repinnable(hk, ok); err != nil {
		return nil, err
	}
	params, err := repinParams(hk)
	if err != nil {
		return nil, status.Error(codes.Internal, "repin parameters")
	}
	// The run is rebuilt from the current record: a different block, pin,
	// endpoint or credential no longer hashes to the approval.
	if _, err := s.auth.AuthorizeGrant(d, permit.Run{
		HostID: hk.HostID, HostKeyFingerprint: hk.Fingerprint, ActionID: repinAction, ModuleVersion: repinVersion,
		Artifact: repinArtifact, ParametersJSON: params, CredentialRef: hk.CredentialRef,
	}); err != nil {
		return nil, toStatus(err)
	}
	// From here the approval is used up whatever happens.
	ep, _ := sshtransport.ParseEndpoint(hk.Blocked.Endpoint)
	pinned, err := ssh.ParsePublicKey(hk.PublicKey)
	if err != nil {
		return nil, s.adminStoreError("repin", fmt.Errorf("stored host key of %s: %w", hk.HostID, err))
	}
	// The block recorded the key of the pinned type; read that type again.
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	key, err := s.transport.ProbeAs(pctx, ep, pinned)
	cancel()
	if err != nil {
		s.log.Warn("audit", "kind", "repin_failed", "host", hk.HostID, "digest", d.String(), "detail", "probe: "+err.Error())
		return nil, status.Error(codes.Unavailable, "repin_probe_failed: the endpoint could not be reached; nothing changed (approve a new re-pin)")
	}
	if got := sshtransport.Fingerprint(key); got != hk.Blocked.Fingerprint {
		s.log.Error("audit", "kind", "repin_failed", "host", hk.HostID, "digest", d.String(),
			"detail", "the endpoint now presents "+got+", not the approved "+hk.Blocked.Fingerprint)
		return nil, status.Errorf(codes.FailedPrecondition,
			"repin_key_changed: the endpoint now presents %s, not the approved %s; nothing changed", got, hk.Blocked.Fingerprint)
	}
	by := "repin:" + d.String()[:16]
	repinned, err := s.db.RepinHostKey(hk.HostID, hk.Fingerprint, hk.Blocked.At, key.Marshal(), by)
	if errors.Is(err, executordb.ErrRepinStale) {
		return nil, status.Error(codes.Aborted, "repin_stale: the host changed meanwhile; nothing changed")
	}
	if errors.Is(err, executordb.ErrInvalid) {
		return nil, status.Error(codes.FailedPrecondition, strings.TrimPrefix(err.Error(), "executordb: "))
	}
	if err != nil {
		return nil, s.adminStoreError("repin", err)
	}
	s.log.Warn("audit", "kind", "host_key_repinned", "host", repinned.HostID, "digest", d.String(),
		"old", hk.Fingerprint, "new", repinned.Fingerprint, "endpoint", hk.Blocked.Endpoint)
	return &pb.CommitRepinResponse{Pin: pinToProto(repinned)}, nil
}

// permitResponse describes a proposed permit like ProposeExecution does.
func (s *Service) permitResponse(p permit.Permit) (*pb.ProposeExecutionResponse, error) {
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
