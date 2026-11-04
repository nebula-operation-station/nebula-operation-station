// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Production batch member dispatch (ADR 0007 E11). The server names an
// approved batch and one member; the executor takes everything that runs
// from the frozen plan, claims the member's single-use permit, records the
// intent in the durable run table and runs the member attached through
// dispatch.Dispatcher, which re-checks trust, risk, Lock, expiry and the
// bound credential versions immediately before the target.

// maxBatchMemberTimeout bounds one member run: members run attached, so the
// attached-run limit applies. It is also the default.
const maxBatchMemberTimeout = hostrun.MaxTimeout

// Run classes of batch members besides hostrun's and the connection classes.
const (
	// classBatchNotExecuted: the member was claimed, but nothing reached
	// the target.
	classBatchNotExecuted = "not_executed"
)

// errBatchExecutionUnconfigured is returned while no dispatcher is wired.
var errBatchExecutionUnconfigured = status.Error(codes.Unimplemented, "batch: execution not configured")

// attachedRunner runs one script attached (hostrun.Attached; tests replace
// it because the attached bootstrap needs sudo on the target).
type attachedRunner func(ctx context.Context, client *ssh.Client, executionID string, params, script []byte, timeout time.Duration, secrets ...hostrun.Secret) (hostrun.Result, error)

// batchMemberCall is the per-call state of one claimed member run, keyed by
// its single-use execution ID. It holds only what the request supplied and
// the executor verified (endpoints, the hash-checked artifact, the opened
// secrets) and collects the run's response; nothing in it chooses what runs.
type batchMemberCall struct {
	hostID      string
	fingerprint string
	endpoints   []string
	eps         []sshtransport.Endpoint
	artifact    []byte
	secrets     []hostrun.Secret
	timeout     time.Duration
	resp        *pb.RunBatchMemberResponse
}

// batchExec is the executor's production batch execution state.
type batchExec struct {
	disp     *dispatch.Dispatcher
	attached attachedRunner

	mu sync.Mutex
	// calls are the claimed member runs in flight, by execution ID.
	calls map[string]*batchMemberCall
	// hosts are the targets a batch member runs on right now (host ID to
	// execution ID): at most one batch member per target at a time, across
	// every batch, in addition to the per-batch same-host ordering.
	hosts map[string]string
}

// EnableBatchExecution wires the production batch dispatcher and only then
// advertises batch execution (GetBatchCredentialVersions
// batch_execution_available). It needs the batch authority
// (SetBatchAuthority) and must be called before the server starts serving.
func (s *Service) EnableBatchExecution() error {
	if s.batchAuth == nil {
		return errors.New("executor: batch execution needs the batch authority")
	}
	x := &batchExec{attached: hostrun.Attached, calls: map[string]*batchMemberCall{}, hosts: map[string]string{}}
	d, err := dispatch.New(dispatch.Options{
		Permits:  s.batchAuth,
		Recorder: batchRunRecorder{s: s, x: x},
		Transport: func(ctx context.Context, run dispatch.Run) (dispatch.Outcome, error) {
			return s.batchTransport(ctx, x, run)
		},
		Now:         s.clock,
		Log:         s.log,
		Audit:       s.auditBatchDispatch,
		Credentials: s.CredentialVersion,
	})
	if err != nil {
		return fmt.Errorf("executor: batch dispatcher: %w", err)
	}
	x.disp = d
	s.batchRun = x
	s.batchExecution = true
	return nil
}

// auditBatchDispatch logs one dispatcher decision; events carry IDs,
// outcomes and secret-free details only.
func (s *Service) auditBatchDispatch(ev dispatch.Event) {
	s.log.Info("audit", "kind", "batch_member_"+ev.Kind, "execution", ev.ExecutionID, "outcome", string(ev.Outcome), "detail", ev.Detail)
}

// validateRunBatchMember checks the request shape before any authority
// work.
func validateRunBatchMember(req *pb.RunBatchMemberRequest) (canonical.Digest, []sshtransport.Endpoint, time.Duration, error) {
	if err := validateBatchMessage(req); err != nil {
		return canonical.Digest{}, nil, 0, err
	}
	d, err := parseBatchDigest(req.GetBatchDigest())
	if err != nil {
		return canonical.Digest{}, nil, 0, err
	}
	id := req.GetMemberId()
	if id == "" || len(id) > maxBatchMemberIDBytes || !utf8.ValidString(id) {
		return canonical.Digest{}, nil, 0, status.Error(codes.InvalidArgument, "batch: invalid member ID")
	}
	if n := len(req.GetArtifact()); n == 0 || n > permit.MaxArtifactSize {
		return canonical.Digest{}, nil, 0, status.Error(codes.InvalidArgument, "batch: member artifact missing or oversize")
	}
	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout > maxBatchMemberTimeout {
		return canonical.Digest{}, nil, 0, status.Errorf(codes.InvalidArgument, "batch: timeout above %s", maxBatchMemberTimeout)
	}
	if timeout == 0 {
		timeout = maxBatchMemberTimeout
	}
	eps, err := parseEndpoints(req.GetEndpoints())
	if err != nil {
		return canonical.Digest{}, nil, 0, status.Error(codes.InvalidArgument, "batch: "+err.Error())
	}
	return d, eps, timeout, nil
}

// memberCredentialRef returns the credential the target's pin connects
// with, after checking that the member binds exactly that credential and a
// version of it, so the dispatcher's rotation check covers the key that is
// actually used.
func (s *Service) memberCredentialRef(m canonical.BatchMember, hk executordb.HostKey) error {
	if len(m.Request.CredentialRefs) != 1 || m.Request.CredentialRefs[0] != hk.CredentialRef {
		return status.Error(codes.FailedPrecondition, "credential_mismatch: the host's pinned credential is not the member's")
	}
	if !slices.ContainsFunc(m.CredentialVersions, func(v canonical.CredentialVersion) bool { return v.Reference == hk.CredentialRef }) {
		return status.Error(codes.FailedPrecondition, "credential_mismatch: the member binds no version of the host's credential")
	}
	return nil
}

// checkMemberTarget checks the member's single SSH target against the pin
// before anything is claimed: pinned, not blocked, the frozen fingerprint
// and the member's credential.
func (s *Service) checkMemberTarget(m canonical.BatchMember) (canonical.Target, error) {
	if m.ProviderTarget != nil || len(m.Request.ResolvedTargets) != 1 {
		return canonical.Target{}, status.Error(codes.FailedPrecondition, "batch: only single-host SSH members are executed")
	}
	t := m.Request.ResolvedTargets[0]
	hk, ok, err := s.db.HostKey(t.HostID)
	if err != nil {
		return canonical.Target{}, s.adminStoreError("batch_member", err)
	}
	switch {
	case !ok:
		return canonical.Target{}, status.Error(codes.FailedPrecondition, ErrHostNotPinned.Error())
	case hk.Blocked != nil:
		return canonical.Target{}, status.Error(codes.FailedPrecondition, "host_key_mismatch: "+ErrHostBlocked.Error())
	case hk.Fingerprint != t.HostKeyFingerprint:
		return canonical.Target{}, status.Error(codes.FailedPrecondition, "host_key_mismatch: "+ErrTargetFingerprint.Error())
	}
	if err := s.memberCredentialRef(m, hk); err != nil {
		return canonical.Target{}, err
	}
	return t, nil
}

// reserveHost marks hostID as running a batch member; false when another
// batch member runs there now.
func (x *batchExec) reserveHost(hostID, executionID string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, busy := x.hosts[hostID]; busy {
		return false
	}
	x.hosts[hostID] = executionID
	return true
}

func (x *batchExec) releaseHost(hostID string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.hosts, hostID)
}

func (x *batchExec) call(executionID string) (*batchMemberCall, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	c, ok := x.calls[executionID]
	return c, ok
}

func (x *batchExec) setCall(executionID string, c *batchMemberCall) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if c == nil {
		delete(x.calls, executionID)
		return
	}
	x.calls[executionID] = c
}

// RunBatchMember runs one member of an approved batch exactly once (server
// role, ADR 0007 E11). Refusals before the claim (malformed request, no
// batch execution, locked keyring, unknown or unapproved batch, unknown
// member, artifact not matching the frozen hash, unpinned or blocked host,
// another batch member running on the target, stage/dependency/same-host
// gates, an already claimed member) are error statuses and nothing ran.
// After the claim every outcome is a response; the member is never run
// again, whatever the outcome.
func (s *Service) RunBatchMember(ctx context.Context, req *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
	d, eps, timeout, err := validateRunBatchMember(req)
	if err != nil {
		return nil, err
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	x := s.batchRun
	if x == nil {
		return nil, errBatchExecutionUnconfigured
	}
	if !s.keys.Unlocked() {
		return nil, status.Error(codes.FailedPrecondition, "vault_locked: run `nebula unlock` on the executor host")
	}
	ap, err := s.batchAuth.Check(ctx, d)
	if err != nil {
		return nil, batchStatus(err)
	}
	index := slices.IndexFunc(ap.Plan.Members, func(m canonical.BatchMember) bool { return m.MemberID == req.GetMemberId() })
	if index < 0 || index >= len(ap.Parameters) {
		return nil, status.Error(codes.NotFound, "batch: no such member in the approved plan")
	}
	member := ap.Plan.Members[index]
	if sum := sha256.Sum256(req.GetArtifact()); canonical.Digest(sum).String() != member.Request.ArtifactSHA256 {
		return nil, status.Error(codes.InvalidArgument, "batch: artifact differs from the approved plan")
	}
	target, err := s.checkMemberTarget(member)
	if err != nil {
		return nil, err
	}
	secrets, err := s.runSecrets(ap.Parameters[index])
	if err != nil {
		return nil, err
	}
	execID := member.Request.ExecutionID
	if !x.reserveHost(target.HostID, execID) {
		s.log.Warn("audit", "kind", "batch_member_refused", "batch", d.String(), "member", member.MemberID, "host", target.HostID,
			"detail", "another batch member runs on the target")
		return nil, status.Error(codes.FailedPrecondition, "batch_host_busy: another batch member runs on the target")
	}
	defer x.releaseHost(target.HostID)
	if _, err := s.batchAuth.ClaimMember(ctx, d, index, member); err != nil {
		return nil, batchStatus(err)
	}
	// From here the member is spent: every outcome is a response.
	resp := &pb.RunBatchMemberResponse{ExecutionId: execID, ExitCode: -1}
	x.setCall(execID, &batchMemberCall{hostID: target.HostID, fingerprint: target.HostKeyFingerprint, endpoints: slices.Clone(req.GetEndpoints()),
		eps: eps, artifact: req.GetArtifact(), secrets: secrets, timeout: timeout, resp: resp})
	defer x.setCall(execID, nil)
	// The reconciler leaves the run alone while it is in flight here.
	key := execID + "/" + target.HostID
	s.setDispatching(key, true)
	defer s.setDispatching(key, false)

	outcome, derr := x.disp.Dispatch(ctx, d, member.MemberID)
	switch outcome {
	case dispatch.OutcomeSuccess:
		resp.Outcome = pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS
	case dispatch.OutcomeFailure:
		resp.Outcome = pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE
		if resp.GetClass() == classBatchNotExecuted {
			// Refused by the transport's last checks: nothing reached
			// the host.
			resp.Outcome = pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED
		}
	case dispatch.OutcomeNotExecuted:
		resp.Outcome = pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED
		resp.Class = classBatchNotExecuted
	default:
		resp.Outcome = pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN
		resp.Class = classUnknown
	}
	if derr != nil && (outcome == dispatch.OutcomeNotExecuted || outcome == dispatch.OutcomeUnknown) {
		resp.Detail = derr.Error()
	}
	// The rollout decides on the executor's own outcome: it frees the
	// target for the batch's next member and applies the stop policy. An
	// unknown or not executed member counts as failed, so it stops the
	// rollout under the default zero threshold; it is never claimable
	// again.
	s.batchAuth.RecordOutcome(execID, member.MemberID, batchRolloutOutcome(outcome, resp))
	s.log.Info("audit", "kind", "batch_member_finished", "batch", d.String(), "member", member.MemberID, "execution", execID,
		"host", target.HostID, "outcome", resp.GetOutcome().String(), "class", resp.GetClass(), "exit", resp.GetExitCode(),
		"result_bytes", len(resp.GetResult()), "log_bytes", len(resp.GetLog()), "duration_ms", resp.GetDurationMs())
	return resp, nil
}

// batchRolloutOutcome maps a dispatch outcome to the rollout's.
func batchRolloutOutcome(o dispatch.Outcome, resp *pb.RunBatchMemberResponse) permit.Outcome {
	switch {
	case o == dispatch.OutcomeSuccess:
		return permit.OutcomeSucceeded
	case o == dispatch.OutcomeFailure && resp.GetUnreachable():
		return permit.OutcomeUnreachable
	}
	return permit.OutcomeFailed
}

// batchTransport runs one claimed member on its exact frozen target. It is
// called by the dispatcher after the intent is durable and every
// revalidation passed. Nothing reaching the host (connection failure,
// refused start) is a definitive failure; once the script was handed to the
// host the run class decides; the run is marked running in the durable
// table first, so a crash from then on is reconciled as unknown, never
// rerun.
func (s *Service) batchTransport(ctx context.Context, x *batchExec, run dispatch.Run) (dispatch.Outcome, error) {
	call, ok := x.call(run.ExecutionID)
	if !ok {
		return dispatch.OutcomeFailure, nil
	}
	resp := call.resp
	start := time.Now()
	defer func() { resp.DurationMs = time.Since(start).Milliseconds() }()
	fail := func(class, detail string) (dispatch.Outcome, error) {
		resp.Class, resp.Detail = class, detail
		return dispatch.OutcomeFailure, nil
	}
	// The run comes from the claimed permit; the call's host and artifact
	// must still be the frozen member's.
	if len(run.Member.Request.ResolvedTargets) != 1 || run.Member.Request.ResolvedTargets[0].HostID != call.hostID ||
		run.Member.Request.ResolvedTargets[0].HostKeyFingerprint != call.fingerprint {
		return fail(classBatchNotExecuted, "not started: the member's target differs from the call")
	}
	if sum := sha256.Sum256(call.artifact); canonical.Digest(sum).String() != run.Member.Request.ArtifactSHA256 {
		return fail(classBatchNotExecuted, "not started: the artifact differs from the approved plan")
	}
	// The pin's credential is what connects: it must still be the one the
	// member binds (and whose version the dispatcher just checked).
	hk, pinned, err := s.db.HostKey(call.hostID)
	switch {
	case err != nil:
		return fail(classBatchNotExecuted, "not started: the host pin could not be read")
	case !pinned:
		return fail(classBatchNotExecuted, "not started: "+ErrHostNotPinned.Error())
	}
	if err := s.memberCredentialRef(run.Member, hk); err != nil {
		return fail(classBatchNotExecuted, "not started: "+status.Convert(err).Message())
	}
	c, err := s.Connect(ctx, call.hostID, call.fingerprint, call.eps)
	if err != nil {
		class, detail := connectClass(err)
		resp.Unreachable = class == classNetworkUnreachable
		return fail(class, detail)
	}
	defer c.Close()
	resp.Endpoint = c.Endpoint.String()
	// Marked running before the script is handed over: a crash from here
	// on is reconciled as unknown (no job directory), never as not run.
	if err := s.db.MarkRunRunning(run.ExecutionID, call.hostID, resp.Endpoint); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "mark_run_running", "execution", run.ExecutionID, "detail", err.Error())
		return fail(classBatchNotExecuted, "not started: the run could not be recorded as running")
	}
	res, err := x.attached(ctx, c.Client, run.ExecutionID, run.Parameters, call.artifact, call.timeout, call.secrets...)
	redact(&res, call.secrets)
	if err != nil {
		// hostrun.Attached returns errors only when nothing was started.
		return fail(hostrun.ClassPrecheckFailed, "not started: "+err.Error())
	}
	resp.Class, resp.Detail, resp.ExitCode = res.Class, res.Detail, int32(res.ExitCode)
	resp.Result, resp.Log, resp.LogTruncated = res.Result, res.Log, res.LogTruncated
	if res.Class == hostrun.ClassSuccess {
		return dispatch.OutcomeSuccess, nil
	}
	return dispatch.OutcomeFailure, nil
}

// batchRunRecorder is the production dispatch.Recorder: the executor's
// durable run table. The intent is a run in state dispatching, created
// before anything reaches the target; the outcome finishes it. An existing
// run for the execution ID (from this process or an earlier one) is
// dispatch.ErrIntentRecorded, so a member is never dispatched twice.
type batchRunRecorder struct {
	s *Service
	x *batchExec
}

// RecordIntent implements dispatch.Recorder.
func (r batchRunRecorder) RecordIntent(_ context.Context, run dispatch.Run) error {
	call, ok := r.x.call(run.ExecutionID)
	if !ok {
		return errors.New("batch: no call state for the run")
	}
	switch _, err := r.s.db.GetRun(run.ExecutionID, call.hostID); {
	case err == nil:
		return dispatch.ErrIntentRecorded
	case !errors.Is(err, executordb.ErrNoRun):
		return fmt.Errorf("batch: read run: %w", err)
	}
	if err := r.s.db.CreateRun(executordb.Run{ExecutionID: run.ExecutionID, HostID: call.hostID, Digest: run.ParentDigest,
		Endpoints: call.endpoints, Fingerprint: call.fingerprint, Timeout: call.timeout}); err != nil {
		if _, gerr := r.s.db.GetRun(run.ExecutionID, call.hostID); gerr == nil {
			return dispatch.ErrIntentRecorded
		}
		return fmt.Errorf("batch: record intent: %w", err)
	}
	r.s.log.Info("audit", "kind", "batch_member_dispatching", "batch", run.ParentDigest, "member", run.MemberID,
		"execution", run.ExecutionID, "host", call.hostID)
	return nil
}

// RecordOutcome implements dispatch.Recorder.
func (r batchRunRecorder) RecordOutcome(_ context.Context, run dispatch.Run, o dispatch.Outcome) error {
	call, ok := r.x.call(run.ExecutionID)
	if !ok {
		return errors.New("batch: no call state for the run")
	}
	resp := call.resp
	fin := executordb.Run{ExecutionID: run.ExecutionID, HostID: call.hostID, Class: resp.GetClass(), Detail: resp.GetDetail(),
		ExitCode: int(resp.GetExitCode()), Endpoint: resp.GetEndpoint(), Result: resp.GetResult(), Log: resp.GetLog(), LogTruncated: resp.GetLogTruncated()}
	switch o {
	case dispatch.OutcomeNotExecuted:
		fin.Class, fin.ExitCode = classBatchNotExecuted, -1
		if fin.Detail == "" {
			fin.Detail = "revoked before dispatch: nothing reached the host"
		}
	case dispatch.OutcomeUnknown:
		fin.Class = classUnknown
		if fin.Detail == "" {
			fin.Detail = "the outcome cannot be known; never rerun"
		}
	}
	if err := r.s.db.FinishRun(fin); err != nil {
		return fmt.Errorf("batch: record outcome: %w", err)
	}
	return nil
}
