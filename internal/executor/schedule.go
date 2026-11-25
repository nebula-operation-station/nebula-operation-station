// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
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
	return s.RunRead(ctx, permit.TriggerScheduled, req)
}

// RunRead dispatches an exact scheduled or on-demand read through the same
// grant, budget and lifecycle checks. RPC adapters choose the trigger; this
// entry point grants no authority beyond the approved document.
func (s *Service) RunRead(ctx context.Context, trigger string, req *pb.RunScheduledRequest) (*pb.RunScheduledResponse, error) {
	r := req.GetRun()
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "run is required")
	}
	if r.GetExecutionDigest() != "" {
		return nil, status.Error(codes.InvalidArgument, "a scheduled run has no permit digest")
	}
	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if limit := readTimeoutLimit(r.GetActionId()); timeout > limit {
		return nil, status.Errorf(codes.InvalidArgument, "timeout above %s", limit)
	}
	if err := checkReadAction(r.GetActionId()); err != nil {
		return nil, err
	}
	release, err := s.admitRead()
	if err != nil {
		return nil, err
	}
	defer release()
	dispatch := s.auth.ReadDispatchGuard()
	// prepareRun wants a digest; a scheduled run is named by the grant.
	probe := &pb.AuthorizeRunRequest{ExecutionDigest: zeroDigest, HostId: r.GetHostId(), CredentialRef: r.GetCredentialRef()}
	_, eps, err := s.prepareRun(probe, req.GetEndpoints())
	if err != nil {
		return nil, err
	}
	signer, err := s.keys.Signer(r.GetCredentialRef())
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "credential unavailable for read")
	}
	run := authorizeRequest(r)
	run.CredentialVersion = ssh.FingerprintSHA256(signer.PublicKey())
	id, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "random")
	}
	var grant permit.Grant
	if trigger == permit.TriggerScheduled {
		grant, err = s.auth.AuthorizeScheduled(req.GetGrantId(), id, run)
	} else {
		grant, err = s.auth.AuthorizeReadRun(req.GetGrantId(), id, trigger, run)
	}
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
	resp.Endpoint = c.Endpoint.String()
	// The handshake can block while a lease is revoked or the executor is
	// locked. Recheck authority and local pin/credential state immediately
	// before dispatch, serialized with lifecycle changes, without claiming
	// another budget unit.
	recheck := func(dispatchCtx context.Context) error {
		if err := dispatchCtx.Err(); err != nil {
			return status.Error(codes.Canceled, "read canceled before dispatch")
		}
		if _, _, err := s.prepareRun(probe, req.GetEndpoints()); err != nil {
			return err
		}
		hk, ok, err := s.db.HostKey(r.GetHostId())
		if err != nil {
			return s.adminStoreError("read dispatch", err)
		}
		if !ok || hk.Fingerprint != r.GetHostKeyFingerprint() || hk.Blocked != nil {
			return status.Error(codes.PermissionDenied, "read target pin changed before dispatch")
		}
		current, err := s.keys.Signer(r.GetCredentialRef())
		if err != nil || ssh.FingerprintSHA256(current.PublicKey()) != run.CredentialVersion {
			return status.Error(codes.PermissionDenied, "read credential version changed before dispatch")
		}
		return nil
	}
	if durableReadAction(r.GetActionId()) {
		return s.dispatchDurableRead(ctx, dispatch, grant, req, c, recheck, resp, start, label, timeout)
	}
	// Attached's own timer starts after NewSession. A hostile peer can
	// otherwise stall channel creation forever while holding the lifecycle
	// guard. Bound the entire dispatch and close the connection on expiry.
	dispatchTimeout := timeout
	if dispatchTimeout <= 0 {
		dispatchTimeout = hostrun.DefaultTimeout
	}
	dispatchCtx, cancel := context.WithTimeout(ctx, dispatchTimeout)
	defer cancel()
	defer closeReadConnectionOnCancel(dispatchCtx, c)()
	err = dispatch(grant, func() error {
		if err := recheck(dispatchCtx); err != nil {
			return err
		}
		res, err := hostrun.Attached(dispatchCtx, c.Client, grant.ExecutionID, grant.Parameters, r.GetArtifact(), timeout)
		if err != nil {
			resp.Class, resp.Detail = classUnknown, err.Error()
		} else {
			resp.Class, resp.Detail, resp.ExitCode = res.Class, res.Detail, int32(res.ExitCode)
			resp.Result, resp.Log, resp.LogTruncated = res.Result, res.Log, res.LogTruncated
		}
		return nil
	})
	if err != nil {
		resp.Class, resp.Detail = "read_denied", "read authority changed before dispatch"
		resp.DurationMs = time.Since(start).Milliseconds()
		s.auditScheduled(label, id, r.GetHostId(), resp)
		if permit.CodeOf(err) != "" {
			return nil, toStatus(err)
		}
		return nil, err
	}
	resp.DurationMs = time.Since(start).Milliseconds()
	s.auditScheduled(label, id, r.GetHostId(), resp)
	return &pb.RunScheduledResponse{ExecutionId: id, Result: resp}, nil
}

// Durable reads (decisions (b)/(g) option 2,
// docs/implementation/integrity-wiring-decisions.md). Only fim.scan runs as
// a durable job from a read lease: its 40 minute timeout and its result of
// up to 128 MiB do not fit an attached run, which would hold the read
// guard, and with it Lock and every revocation, for the whole run.
const (
	// fimScanReadTimeout is the longest timeout a fim.scan read may ask
	// for, and its default: the action's own limit (ADR 0015 D6), never
	// above the durable maximum.
	fimScanReadTimeout = min(fimscan.ActionTimeout, hostrun.MaxDurableTimeout)
	// durableReadDispatchTimeout bounds storing and starting a durable read
	// job on the host (not the job). The dispatch holds the read guard, so
	// Lock and a revocation wait at most this long for it.
	durableReadDispatchTimeout = 30 * time.Second
)

// durableReadAction reports whether a read of actionID runs as a durable
// job. Only fim.scan does.
func durableReadAction(actionID string) bool {
	return actionID == permit.FimScanActionID
}

// readTimeoutLimit is the longest timeout a read of actionID may ask for:
// fim.scan's own limit, the attached maximum for every other action.
func readTimeoutLimit(actionID string) time.Duration {
	if durableReadAction(actionID) {
		return fimScanReadTimeout
	}
	return hostrun.MaxTimeout
}

// checkReadAction refuses a durable built-in action other than fim.scan
// before anything is reserved: the read path would run it attached, which
// its contract does not allow, and only fim.scan has a durable read branch.
func checkReadAction(actionID string) error {
	if durableReadAction(actionID) {
		return nil
	}
	if a, ok := actions.Lookup(actionID); ok && a.Durable {
		return status.Error(codes.InvalidArgument, "read: a durable action other than fim.scan cannot run from a read lease")
	}
	return nil
}

// dispatchDurableRead stores and starts an authorized fim.scan read as a
// durable job. Recording and starting the job are serialized with Lock and
// both revocations like an attached dispatch (the claim is rechecked and
// spent under the read guard), so once Lock or a revocation has returned
// no job of a claim made before it starts. The job itself runs after the
// guard is released: lifecycle calls never wait for it. Like every durable
// job (spec 07) it is not cancelled by a later Lock or revocation; the
// reconciler collects its outcome (once the keyring is unlocked).
//
// The response carries the run's class and state only, never the result
// document: the reconciler reads that with the fim.scan limit.
func (s *Service) dispatchDurableRead(ctx context.Context, dispatch func(permit.Grant, func() error) error, grant permit.Grant,
	req *pb.RunScheduledRequest, c *sshtransport.Client, recheck func(context.Context) error, resp *pb.RunAttachedResponse,
	start time.Time, label string, timeout time.Duration) (*pb.RunScheduledResponse, error) {
	r := req.GetRun()
	if timeout <= 0 {
		timeout = fimScanReadTimeout
	}
	id, host := grant.ExecutionID, r.GetHostId()
	key := id + "/" + host
	s.setDispatching(key, true)
	defer s.setDispatching(key, false)
	dispatchCtx, cancel := context.WithTimeout(ctx, durableReadDispatchTimeout)
	defer cancel()
	defer closeReadConnectionOnCancel(dispatchCtx, c)()
	var finish *executordb.Run
	err := dispatch(grant, func() error {
		if err := recheck(dispatchCtx); err != nil {
			return err
		}
		// Recorded before anything goes to the host: a crash from here on
		// is reconciled, never dispatched again.
		if err := s.db.CreateRun(executordb.Run{ExecutionID: id, HostID: host, Digest: label, Endpoints: req.GetEndpoints(),
			Fingerprint: r.GetHostKeyFingerprint(), Timeout: timeout, ActionID: permit.FimScanActionID}); err != nil {
			s.log.Error("audit", "kind", "store_error", "op", "create_run", "digest", label, "host", host, "detail", err.Error())
			return status.Error(codes.Unavailable, "storage_error: the read was authorized but could not be recorded; it was not started")
		}
		s.log.Info("audit", "kind", "run_dispatching", "digest", label, "host", host, "execution", id)
		// finishRun reports to the authority, which this callback must not
		// reenter: a run that ends at dispatch is closed after the guard.
		finish = s.dispatchDurableJob(dispatchCtx, c, id, host, label, grant.Parameters, r.GetArtifact(), timeout)
		return nil
	})
	if finish != nil {
		s.finishRun(*finish)
	}
	if err != nil {
		resp.Class, resp.Detail = "read_denied", "read authority changed before dispatch"
		if permit.CodeOf(err) == "" && status.Code(err) == codes.Unavailable {
			resp.Class, resp.Detail = classNotExecuted, "the read could not be recorded"
		}
		resp.DurationMs = time.Since(start).Milliseconds()
		s.auditScheduled(label, id, host, resp)
		if permit.CodeOf(err) != "" {
			return nil, toStatus(err)
		}
		return nil, err
	}
	st, err := s.runStatus(id, host, false)
	if err != nil {
		return nil, err
	}
	resp.Class, resp.ExitCode, resp.Detail = st.GetClass(), st.GetExitCode(), "durable job "+st.GetState()
	if st.GetDetail() != "" {
		resp.Detail += ": " + st.GetDetail()
	}
	resp.DurationMs = time.Since(start).Milliseconds()
	return &pb.RunScheduledResponse{ExecutionId: id, Result: resp}, nil
}

// maxConcurrentReads is an executor-wide ceiling, never multiplied by grants
// or callers. Excess requests are denied before reserving or opening SSH.
const maxConcurrentReads = 4

func (s *Service) admitRead() (func(), error) {
	s.readSlotsOnce.Do(func() { s.readSlots = make(chan struct{}, maxConcurrentReads) })
	select {
	case s.readSlots <- struct{}{}:
		return func() { <-s.readSlots }, nil
	default:
		return nil, status.Error(codes.ResourceExhausted, "read concurrency limit reached")
	}
}

func closeReadConnectionOnCancel(ctx context.Context, c io.Closer) func() {
	// Stopping AfterFunc does not wait for an in-flight callback. Share
	// the guard with cleanup because the transport's Close is not atomic.
	var once sync.Once
	closeConnection := func() { once.Do(func() { _ = c.Close() }) }
	stopClose := context.AfterFunc(ctx, closeConnection)
	return func() {
		stopClose()
		closeConnection()
	}
}

// zeroDigest satisfies prepareRun's digest check for scheduled runs.
const zeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"

func (s *Service) auditScheduled(label, id, host string, r *pb.RunAttachedResponse) {
	s.log.Info("audit", "kind", "run_finished", "digest", label, "execution", id, "host", host, "class", r.GetClass(),
		"exit", r.GetExitCode(), "endpoint", r.GetEndpoint(), "result_bytes", len(r.GetResult()), "log_bytes", len(r.GetLog()),
		"log_truncated", r.GetLogTruncated(), "duration_ms", r.GetDurationMs())
}
