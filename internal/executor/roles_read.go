// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	maxReadEndpointBytes  = 1024
	maxReadGrantListBytes = MaxResponseSize
)

var (
	readGrantIDRe       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	readRunCredentialRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

func validateReadMessage(m proto.Message) error {
	if !m.ProtoReflect().IsValid() || proto.Size(m) > MaxMessageSize {
		return status.Error(codes.InvalidArgument, "read grant: missing or oversize request")
	}
	return nil
}

func readGrantStatus(err error) error {
	code := permit.CodeOf(err)
	message := err.Error()
	if code == "" {
		// RunRead uses the schedule compatibility mapper. Normalize its
		// known grant codes for the new API; preserve unrelated statuses.
		st := status.Convert(err)
		name, _, _ := strings.Cut(st.Message(), ":")
		code, message = permit.Code(name), st.Message()
	}

	originalCode := code
	switch code {
	case permit.CodeScheduleUnavailable:
		code = permit.CodeLeaseUnavailable
	case permit.CodeGrantInactive:
		code = permit.CodeLeaseInactive
	case permit.CodeGrantNotCovered:
		code = permit.CodeLeaseNotCovered
	case permit.CodeTooSoon:
		code = permit.CodeLeaseBudget
	}
	if code != originalCode {
		_, detail, _ := strings.Cut(message, ":")
		message = (&permit.Error{Code: code, Detail: strings.TrimSpace(detail)}).Error()
	}

	switch code {
	case permit.CodeLeaseInvalid:
		return status.Error(codes.InvalidArgument, message)
	case permit.CodeLeaseUnavailable:
		return status.Error(codes.Unimplemented, message)
	case permit.CodeLeaseInactive, permit.CodeLeaseNotCovered:
		return status.Error(codes.PermissionDenied, message)
	case permit.CodeLeaseBudget:
		return status.Error(codes.ResourceExhausted, message)
	default:
		if permit.CodeOf(err) == "" {
			return err
		}
		return toStatus(err)
	}
}

func readGrantToProto(g permit.StoredReadGrant) *pb.ReadGrant {
	out := &pb.ReadGrant{GrantId: g.ID, GrantDigest: g.Digest, CanonicalGrant: g.Doc, ApprovedBy: g.ApprovedBy, CreatedUnix: g.CreatedAt.Unix(), ExpiryUnix: g.ExpiresAt.Unix()}
	if !g.RevokedAt.IsZero() {
		out.RevokedUnix = g.RevokedAt.Unix()
	}
	return out
}

// ProposeReadGrant validates the complete frozen read scope before recording
// a proposal. The authority alone chooses and binds its approval requirement.
func (s *Service) ProposeReadGrant(_ context.Context, req *pb.ProposeReadGrantRequest) (*pb.ProposeReadGrantResponse, error) {
	if err := validateReadMessage(req); err != nil {
		return nil, err
	}
	doc, _, _, err := permit.ParseReadGrant(req.GetGrantJson(), s.clock())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "read grant: invalid document")
	}
	for _, target := range doc.Targets {
		pin, ok, err := s.db.HostKey(target.HostID)
		if err != nil {
			return nil, s.adminStoreError("read grant", err)
		}
		if !ok || pin.Fingerprint != target.HostKeyFingerprint || pin.Blocked != nil {
			return nil, status.Error(codes.InvalidArgument, "read grant: target is not pinned with the approved key or is blocked")
		}
	}
	for _, target := range doc.ProviderTargets {
		rm, ok, err := s.db.GetRemote(target.RemoteID)
		if err != nil {
			return nil, s.adminStoreError("read grant", err)
		}
		if !ok || rm.State != executordb.StateActive || rm.TrustPin != target.TrustPin || rm.TrustGeneration != target.TrustGeneration ||
			rm.Credentials.ReadVersion != target.CredentialVersion {
			return nil, status.Error(codes.InvalidArgument, "read grant: remote is not active with the approved trust and credential version")
		}
	}
	pg, err := s.auth.ProposeReadGrant(req.GetGrantJson())
	if err != nil {
		return nil, readGrantStatus(err)
	}
	out := &pb.ProposeReadGrantResponse{GrantDigest: pg.Digest, CanonicalGrant: pg.Canonical, ApprovalRequirement: requirementToProto(pg.Requirement)}
	if len(pg.Challenge) > 0 {
		out.Challenge, out.ChallengeExpiryUnix = pg.Challenge, pg.Expiry.Unix()
		opts, err := s.reg.RequestOptions(pg.Challenge, pg.Expiry.Sub(s.clock()))
		if err != nil {
			return nil, status.Error(codes.Internal, "read grant: request options unavailable")
		}
		out.RequestOptionsJson = opts
	}
	return out, nil
}

// CommitReadGrant relays a bounded assertion to executor verification. No
// server-supplied identity, approval flag or session substitutes for user UV.
func (s *Service) CommitReadGrant(_ context.Context, req *pb.CommitReadGrantRequest) (*pb.CommitReadGrantResponse, error) {
	if err := validateReadMessage(req); err != nil {
		return nil, err
	}
	raw := req.GetAssertionJson()
	if !canonical.ValidSHA256Hex(req.GetGrantDigest()) || len(raw) == 0 || len(raw) > webauthnverify.MaxAssertionSize || !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, status.Error(codes.InvalidArgument, "read grant: invalid digest or assertion")
	}
	g, err := s.auth.CommitReadGrant(req.GetGrantDigest(), raw)
	if err != nil {
		return nil, readGrantStatus(err)
	}
	return &pb.CommitReadGrantResponse{Grant: readGrantToProto(g)}, nil
}

// ListPendingReadGrants provides complete frozen documents for admin review.
func (s *Service) ListPendingReadGrants(_ context.Context, req *pb.ListPendingReadGrantsRequest) (*pb.ListPendingReadGrantsResponse, error) {
	if err := validateReadMessage(req); err != nil {
		return nil, err
	}
	out := &pb.ListPendingReadGrantsResponse{}
	size := 0
	for _, g := range s.auth.PendingReadGrants() {
		row := &pb.PendingReadGrant{GrantDigest: g.Digest, CanonicalGrant: g.Canonical, ApprovalExpiryUnix: g.Expiry.Unix()}
		size += protowire.SizeTag(1) + protowire.SizeBytes(proto.Size(row))
		if size > maxReadGrantListBytes {
			return nil, status.Error(codes.ResourceExhausted, "read grant: pending list exceeds response limit")
		}
		out.Grants = append(out.Grants, row)
	}
	return out, nil
}

// ApproveReadGrantCLI approves a locally reviewed digest. The peercred table
// restricts this assertion-free approval path to the executor-local admin.
func (s *Service) ApproveReadGrantCLI(ctx context.Context, req *pb.ApproveReadGrantCLIRequest) (*pb.ApproveReadGrantCLIResponse, error) {
	if err := validateReadMessage(req); err != nil {
		return nil, err
	}
	if !canonical.ValidSHA256Hex(req.GetGrantDigest()) {
		return nil, status.Error(codes.InvalidArgument, "read grant: invalid digest")
	}
	g, err := s.auth.ApproveReadGrantCLI(req.GetGrantDigest(), callerName(ctx))
	if err != nil {
		return nil, readGrantStatus(err)
	}
	return &pb.ApproveReadGrantCLIResponse{Grant: readGrantToProto(g)}, nil
}

// ListReadGrants returns the complete approved read-grant registry, bounded
// by the transport response ceiling. It never truncates approved scope.
func (s *Service) ListReadGrants(_ context.Context, req *pb.ListReadGrantsRequest) (*pb.ListReadGrantsResponse, error) {
	if err := validateReadMessage(req); err != nil {
		return nil, err
	}
	gs, err := s.auth.ReadGrants()
	if err != nil {
		return nil, readGrantStatus(err)
	}
	out := &pb.ListReadGrantsResponse{}
	size := 0
	for _, g := range gs {
		row := readGrantToProto(g)
		size += protowire.SizeTag(1) + protowire.SizeBytes(proto.Size(row))
		if size > maxReadGrantListBytes {
			return nil, status.Error(codes.ResourceExhausted, "read grant: list exceeds response limit")
		}
		out.Grants = append(out.Grants, row)
	}
	return out, nil
}

// RevokeReadGrant reduces authority without a session or assertion.
func (s *Service) RevokeReadGrant(ctx context.Context, req *pb.RevokeReadGrantRequest) (*pb.RevokeReadGrantResponse, error) {
	if err := validateReadMessage(req); err != nil {
		return nil, err
	}
	if !readGrantIDRe.MatchString(req.GetGrantId()) {
		return nil, status.Error(codes.InvalidArgument, "read grant: invalid grant ID")
	}
	if err := s.auth.RevokeReadGrant(req.GetGrantId(), callerName(ctx)); err != nil {
		return nil, readGrantStatus(err)
	}
	return &pb.RevokeReadGrantResponse{}, nil
}

func validateRunReadGrant(req *pb.RunReadGrantRequest) error {
	if err := validateReadMessage(req); err != nil {
		return err
	}
	r := req.GetRun()
	if !readGrantIDRe.MatchString(req.GetGrantId()) || r == nil || r.GetExecutionDigest() != "" {
		return status.Error(codes.InvalidArgument, "read grant: invalid grant ID or run")
	}
	switch req.GetTrigger() {
	case pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED, pb.ReadGrantTrigger_READ_GRANT_TRIGGER_ON_DEMAND:
	default:
		return status.Error(codes.InvalidArgument, "read grant: invalid trigger")
	}
	if !canonical.ValidHostID(r.GetHostId()) || !canonical.ValidHostKeyFingerprint(r.GetHostKeyFingerprint()) || !canonical.ValidActionID(r.GetActionId()) || !canonical.ValidModuleVersion(r.GetModuleVersion()) || !readRunCredentialRe.MatchString(r.GetCredentialRef()) {
		return status.Error(codes.InvalidArgument, "read grant: malformed run binding")
	}
	if len(r.GetArtifact()) == 0 || len(r.GetArtifact()) > permit.MaxArtifactSize {
		return status.Error(codes.InvalidArgument, "read grant: invalid artifact size")
	}
	if _, err := canonical.HashParameters(r.GetParametersJson()); err != nil {
		return status.Error(codes.InvalidArgument, "read grant: invalid parameters")
	}
	for _, ep := range req.GetEndpoints() {
		if len(ep) > maxReadEndpointBytes || !utf8.ValidString(ep) {
			return status.Error(codes.InvalidArgument, "read grant: invalid endpoint")
		}
	}
	if _, err := parseEndpoints(req.GetEndpoints()); err != nil {
		return status.Error(codes.InvalidArgument, "read grant: invalid endpoints")
	}
	if time.Duration(req.GetTimeoutSeconds())*time.Second > hostrun.MaxTimeout {
		return status.Error(codes.InvalidArgument, "read grant: invalid timeout")
	}
	return nil
}

// RunReadGrant routes both approved triggers through the existing shared read
// authorization and dispatch path. A trigger never widens a grant's scope.
func (s *Service) RunReadGrant(ctx context.Context, req *pb.RunReadGrantRequest) (*pb.RunReadGrantResponse, error) {
	if err := validateRunReadGrant(req); err != nil {
		return nil, err
	}
	trigger := permit.TriggerOnDemand
	if req.GetTrigger() == pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED {
		trigger = permit.TriggerScheduled
	}
	result, err := s.RunRead(ctx, trigger, &pb.RunScheduledRequest{GrantId: req.GetGrantId(), Run: req.GetRun(), Endpoints: req.GetEndpoints(), TimeoutSeconds: req.GetTimeoutSeconds()})
	if err != nil {
		return nil, readGrantStatus(err)
	}
	return &pb.RunReadGrantResponse{ExecutionId: result.GetExecutionId(), Result: result.GetResult()}, nil
}
