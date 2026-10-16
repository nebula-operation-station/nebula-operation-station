// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Schedule grants (docs/implementation/schedule-grants.md). The rules are
// in internal/permit; this file converts and runs.

func grantToProto(g permit.StoredGrant) *pb.ScheduleGrant {
	out := &pb.ScheduleGrant{GrantId: g.ID, GrantDigest: g.Digest, CanonicalGrant: g.Doc, ApprovedBy: g.ApprovedBy,
		CreatedUnix: g.CreatedAt.Unix(), ExpiryUnix: g.ExpiresAt.Unix()}
	if !g.RevokedAt.IsZero() {
		out.RevokedUnix = g.RevokedAt.Unix()
	}
	return out
}

// ProposeScheduleGrant checks a grant document (server role).
func (s *Service) ProposeScheduleGrant(_ context.Context, req *pb.ProposeScheduleGrantRequest) (*pb.ProposeScheduleGrantResponse, error) {
	// Every target must be pinned with exactly the granted key, checked
	// before the authority records the proposal, so a refused one never
	// takes a pending slot. A document that does not parse is refused by
	// the authority below with its reason.
	if doc, _, _, err := schedgrant.Parse(req.GetGrantJson(), time.Now()); err == nil {
		for _, t := range doc.Targets {
			hk, ok, err := s.db.HostKey(t.HostID)
			if err != nil {
				return nil, s.adminStoreError("schedule grant", err)
			}
			if !ok || hk.Fingerprint != t.HostKeyFingerprint || hk.Blocked != nil {
				return nil, status.Errorf(codes.InvalidArgument, "schedule_grant_invalid: host %s is not pinned with that key (or is blocked)", t.HostID)
			}
		}
	}
	pg, err := s.auth.ProposeScheduleGrant(req.GetGrantJson())
	if err != nil {
		return nil, toStatus(err)
	}
	out := &pb.ProposeScheduleGrantResponse{GrantDigest: pg.Digest, CanonicalGrant: pg.Canonical,
		ApprovalRequirement: requirementToProto(pg.Requirement)}
	if len(pg.Challenge) > 0 {
		out.Challenge, out.ChallengeExpiryUnix = pg.Challenge, pg.Expiry.Unix()
		opts, err := s.reg.RequestOptions(pg.Challenge, time.Until(pg.Expiry))
		if err != nil {
			return nil, status.Error(codes.Internal, "request options")
		}
		out.RequestOptionsJson = opts
	}
	return out, nil
}

// CommitScheduleGrant approves a proposed grant (server role).
func (s *Service) CommitScheduleGrant(_ context.Context, req *pb.CommitScheduleGrantRequest) (*pb.CommitScheduleGrantResponse, error) {
	g, err := s.auth.CommitScheduleGrant(req.GetGrantDigest(), req.GetAssertionJson())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.CommitScheduleGrantResponse{Grant: grantToProto(g)}, nil
}

// ListPendingScheduleGrants lists proposed grants (admin).
func (s *Service) ListPendingScheduleGrants(_ context.Context, _ *pb.ListPendingScheduleGrantsRequest) (*pb.ListPendingScheduleGrantsResponse, error) {
	out := &pb.ListPendingScheduleGrantsResponse{}
	for _, g := range s.auth.PendingScheduleGrants() {
		out.Grants = append(out.Grants, &pb.PendingScheduleGrant{GrantDigest: g.Digest, CanonicalGrant: g.Canonical, ApprovalExpiryUnix: g.Expiry.Unix()})
	}
	return out, nil
}

// ApproveScheduleGrantCLI approves a proposed grant (admin).
func (s *Service) ApproveScheduleGrantCLI(ctx context.Context, req *pb.ApproveScheduleGrantCLIRequest) (*pb.ApproveScheduleGrantCLIResponse, error) {
	g, err := s.auth.ApproveScheduleGrantCLI(req.GetGrantDigest(), callerName(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ApproveScheduleGrantCLIResponse{Grant: grantToProto(g)}, nil
}

// ListScheduleGrants lists stored grants (server, admin).
func (s *Service) ListScheduleGrants(_ context.Context, _ *pb.ListScheduleGrantsRequest) (*pb.ListScheduleGrantsResponse, error) {
	gs, err := s.auth.ScheduleGrants()
	if err != nil {
		return nil, toStatus(err)
	}
	out := &pb.ListScheduleGrantsResponse{}
	for _, g := range gs {
		out.Grants = append(out.Grants, grantToProto(g))
	}
	return out, nil
}

// RevokeScheduleGrant revokes a grant (server, admin).
func (s *Service) RevokeScheduleGrant(ctx context.Context, req *pb.RevokeScheduleGrantRequest) (*pb.RevokeScheduleGrantResponse, error) {
	if err := s.auth.RevokeScheduleGrant(req.GetGrantId(), callerName(ctx)); err != nil {
		return nil, toStatus(err)
	}
	return &pb.RevokeScheduleGrantResponse{}, nil
}

// RunScheduled runs one host run under a grant (server role). Checks that
// need no grant come first; after AuthorizeScheduled the interval has
// started whatever happens.
func (s *Service) RunScheduled(ctx context.Context, req *pb.RunScheduledRequest) (*pb.RunScheduledResponse, error) {
	r := req.GetRun()
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "run is required")
	}
	if r.GetExecutionDigest() != "" {
		return nil, status.Error(codes.InvalidArgument, "a scheduled run has no permit digest")
	}
	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout > hostrun.MaxTimeout {
		return nil, status.Errorf(codes.InvalidArgument, "timeout above %s", hostrun.MaxTimeout)
	}
	// prepareRun wants a digest; a scheduled run is named by the grant.
	probe := &pb.AuthorizeRunRequest{ExecutionDigest: zeroDigest, HostId: r.GetHostId(), CredentialRef: r.GetCredentialRef()}
	_, eps, err := s.prepareRun(probe, req.GetEndpoints())
	if err != nil {
		return nil, err
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "random")
	}
	grant, err := s.auth.AuthorizeScheduled(req.GetGrantId(), id, authorizeRequest(r))
	if err != nil {
		return nil, toStatus(err)
	}
	start := time.Now()
	resp := &pb.RunAttachedResponse{ExitCode: -1}
	label := "grant:" + req.GetGrantId()
	c, err := s.Connect(ctx, r.GetHostId(), r.GetHostKeyFingerprint(), eps)
	if err != nil {
		resp.Class, resp.Detail = connectClass(err)
		resp.DurationMs = time.Since(start).Milliseconds()
		s.auditScheduled(label, id, r.GetHostId(), resp)
		return &pb.RunScheduledResponse{ExecutionId: id, Result: resp}, nil
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
	s.auditScheduled(label, id, r.GetHostId(), resp)
	return &pb.RunScheduledResponse{ExecutionId: id, Result: resp}, nil
}

// zeroDigest satisfies prepareRun's digest check for scheduled runs.
const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

func (s *Service) auditScheduled(label, id, host string, r *pb.RunAttachedResponse) {
	s.log.Info("audit", "kind", "run_finished", "digest", label, "execution", id, "host", host, "class", r.GetClass(),
		"exit", r.GetExitCode(), "endpoint", r.GetEndpoint(), "result_bytes", len(r.GetResult()), "log_bytes", len(r.GetLog()),
		"log_truncated", r.GetLogTruncated(), "duration_ms", r.GetDurationMs())
}
