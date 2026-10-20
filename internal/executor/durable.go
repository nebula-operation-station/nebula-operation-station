// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Durable runs (spec 07). Outcome classes besides hostrun's.
const (
	classNotExecuted = "not_executed"
	// stuckDispatched is how long a job may stay "dispatched" (stored,
	// wrapper not started) before it counts as never started.
	stuckDispatched = 5 * time.Minute
	defaultDurable  = time.Hour
)

// StartDurable authorizes one host run and starts it as a durable job.
func (s *Service) StartDurable(ctx context.Context, req *pb.StartDurableRequest) (*pb.StartDurableResponse, error) {
	r := req.GetRun()
	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout == 0 {
		timeout = defaultDurable
	}
	if timeout > hostrun.MaxDurableTimeout {
		return nil, status.Errorf(codes.InvalidArgument, "timeout above %s", hostrun.MaxDurableTimeout)
	}
	d, eps, err := s.prepareRun(r, req.GetEndpoints())
	if err != nil {
		return nil, err
	}
	secrets, err := s.runSecrets(r.GetParametersJson())
	if err != nil {
		return nil, err
	}
	refs, _ := permit.SecretRefs(r.GetParametersJson()) // checked by runSecrets
	grant, err := s.auth.AuthorizeGrant(d, authorizeRequest(r))
	if err != nil {
		return nil, toStatus(err)
	}
	// Recorded before anything goes to the host: a crash from here on is
	// reconciled, never dispatched again.
	if err := s.db.CreateRun(executordb.Run{ExecutionID: grant.ExecutionID, HostID: r.GetHostId(), Digest: d.String(),
		Endpoints: req.GetEndpoints(), Fingerprint: r.GetHostKeyFingerprint(), Timeout: timeout, SecretRefs: refs}); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "create_run", "digest", d.String(), "host", r.GetHostId(), "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: the run was authorized but could not be recorded; it was not started")
	}
	s.log.Info("audit", "kind", "run_dispatching", "digest", d.String(), "host", r.GetHostId(), "execution", grant.ExecutionID)
	key := grant.ExecutionID + "/" + r.GetHostId()
	s.setDispatching(key, true)
	defer s.setDispatching(key, false)

	c, err := s.Connect(ctx, r.GetHostId(), r.GetHostKeyFingerprint(), eps)
	if err != nil {
		class, detail := connectClass(err)
		s.finishRun(executordb.Run{ExecutionID: grant.ExecutionID, HostID: r.GetHostId(), Class: class, Detail: "not dispatched: " + detail, ExitCode: -1})
		return s.runResponse(grant.ExecutionID, r.GetHostId(), false)
	}
	defer c.Close()
	outcome, detail, err := hostrun.Dispatch(ctx, c.Client, s.jobs, grant.ExecutionID, grant.Parameters, r.GetArtifact(), timeout, secrets...)
	switch {
	case err != nil:
		// The connection broke during dispatch: the reconciler finds out
		// whether the job is on the host.
		s.log.Warn("audit", "kind", "run_dispatch_uncertain", "execution", grant.ExecutionID, "host", r.GetHostId(), "detail", err.Error())
	case outcome == hostrun.NotStarted:
		s.finishRun(executordb.Run{ExecutionID: grant.ExecutionID, HostID: r.GetHostId(), Class: hostrun.ClassPrecheckFailed,
			Detail: detail, ExitCode: -1, Endpoint: c.Endpoint.String()})
	default:
		if err := s.db.MarkRunRunning(grant.ExecutionID, r.GetHostId(), c.Endpoint.String()); err != nil {
			s.log.Error("audit", "kind", "store_error", "op", "mark_run_running", "execution", grant.ExecutionID, "detail", err.Error())
		}
		s.log.Info("audit", "kind", "run_dispatched", "digest", d.String(), "host", r.GetHostId(), "execution", grant.ExecutionID,
			"endpoint", c.Endpoint.String())
	}
	return s.runResponse(grant.ExecutionID, r.GetHostId(), false)
}

func (s *Service) runResponse(executionID, hostID string, release bool) (*pb.StartDurableResponse, error) {
	st, err := s.runStatus(executionID, hostID, release)
	if err != nil {
		return nil, err
	}
	return &pb.StartDurableResponse{Run: st}, nil
}

func (s *Service) runStatus(executionID, hostID string, release bool) (*pb.RunStatus, error) {
	run, err := s.db.GetRun(executionID, hostID)
	if errors.Is(err, executordb.ErrNoRun) {
		return nil, status.Error(codes.NotFound, "no such run")
	}
	if err != nil {
		return nil, s.adminStoreError("get_run", err)
	}
	st := &pb.RunStatus{ExecutionId: run.ExecutionID, HostId: run.HostID, State: run.State, Class: run.Class, Detail: run.Detail,
		ExitCode: int32(run.ExitCode), Result: run.Result, Log: run.Log, LogTruncated: run.LogTruncated, Endpoint: run.Endpoint,
		Released: run.Released}
	if !run.DispatchedAt.IsZero() {
		st.DispatchedAtUnix = run.DispatchedAt.Unix()
	}
	if !run.FinishedAt.IsZero() {
		st.FinishedAtUnix = run.FinishedAt.Unix()
	}
	if release && run.State == executordb.RunFinished && !run.Released {
		if err := s.db.ReleaseRun(executionID, hostID); err != nil {
			return nil, s.adminStoreError("release_run", err)
		}
	}
	return st, nil
}

// GetRun reports a durable run.
func (s *Service) GetRun(_ context.Context, req *pb.GetRunRequest) (*pb.GetRunResponse, error) {
	st, err := s.runStatus(req.GetExecutionId(), req.GetHostId(), req.GetRelease())
	if err != nil {
		return nil, err
	}
	return &pb.GetRunResponse{Run: st}, nil
}

func (s *Service) finishRun(r executordb.Run) {
	if err := s.db.FinishRun(r); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "finish_run", "execution", r.ExecutionID, "host", r.HostID, "detail", err.Error())
		return
	}
	s.log.Info("audit", "kind", "run_finished", "execution", r.ExecutionID, "host", r.HostID, "class", r.Class, "exit", r.ExitCode,
		"result_bytes", len(r.Result), "log_bytes", len(r.Log), "log_truncated", r.LogTruncated)
	// The stage engine decides on the executor's own record of the run.
	s.auth.RecordOutcome(r.ExecutionID, r.HostID, permit.OutcomeOfClass(r.Class))
}

// Reconcile runs reconciliation passes until ctx ends (spec 07). A pass
// needs the unlocked keyring; while locked, open runs wait.
func (s *Service) Reconcile(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.ReconcileOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ReconcileOnce checks every open run once.
func (s *Service) ReconcileOnce(ctx context.Context) {
	if !s.keys.Unlocked() {
		return
	}
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	runs, err := s.db.OpenRuns()
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "open_runs", "detail", err.Error())
		return
	}
	for _, run := range runs {
		if ctx.Err() != nil {
			return
		}
		if s.isDispatching(run.ExecutionID + "/" + run.HostID) {
			continue
		}
		s.reconcile(ctx, run)
	}
}

func (s *Service) setDispatching(key string, on bool) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if s.dispatching == nil {
		s.dispatching = map[string]bool{}
	}
	if on {
		s.dispatching[key] = true
	} else {
		delete(s.dispatching, key)
	}
}

func (s *Service) isDispatching(key string) bool {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	return s.dispatching[key]
}

func (s *Service) reconcile(ctx context.Context, run executordb.Run) {
	eps, err := parseEndpoints(run.Endpoints)
	if err != nil {
		s.finishRun(executordb.Run{ExecutionID: run.ExecutionID, HostID: run.HostID, Class: classUnknown, Detail: "stored endpoints unusable", ExitCode: -1})
		return
	}
	reboot, waiting, err := s.db.GetRunReboot(run.ExecutionID, run.HostID)
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "get_run_reboot", "detail", err.Error())
		return
	}
	c, err := s.Connect(ctx, run.HostID, run.Fingerprint, eps)
	if err != nil {
		_, detail := connectClass(err)
		if waiting && time.Now().After(reboot.Deadline) {
			s.finishReboot(run, reboot, classHostNotReturned, "the host did not come back from the reboot in time: "+detail, "")
			return
		}
		// Retried on the next pass; a blocked host waits for a re-pin.
		s.log.Warn("audit", "kind", "reconcile_unreachable", "execution", run.ExecutionID, "host", run.HostID, "detail", detail)
		return
	}
	defer c.Close()
	if waiting {
		id, err := hostrun.BootID(ctx, c.Client, s.jobs)
		switch {
		case err == nil && id != reboot.OldBootID:
			s.finishReboot(run, reboot, hostrun.ClassSuccess, "rebooted and back", c.Endpoint.String())
		case time.Now().After(reboot.Deadline):
			s.finishReboot(run, reboot, classHostNotReturned, "the host did not reboot in time", c.Endpoint.String())
		}
		return
	}
	st, err := hostrun.Check(ctx, c.Client, s.jobs, run.ExecutionID)
	if err != nil {
		s.log.Warn("audit", "kind", "reconcile_check_failed", "execution", run.ExecutionID, "host", run.HostID, "detail", err.Error())
		return
	}
	now := time.Now()
	since := run.DispatchedAt
	if since.IsZero() {
		since = run.CreatedAt
	}
	fin := executordb.Run{ExecutionID: run.ExecutionID, HostID: run.HostID, ExitCode: -1, Endpoint: c.Endpoint.String()}
	switch st.Phase {
	case "missing":
		if run.State == executordb.RunDispatching {
			fin.Class, fin.Detail = classNotExecuted, "the job never reached the host"
		} else {
			fin.Class, fin.Detail = classUnknown, "the job directory is gone; the outcome cannot be known (not re-run)"
		}
		s.finishRun(fin)
		// The run directory (with any secrets) may outlive the job
		// directory; remove both.
		_ = hostrun.Remove(ctx, c.Client, s.jobs, run.ExecutionID)
	case "incomplete":
		// The dispatch was cut off before the job was stored. Give a
		// dispatch in progress its time, then end the run and remove
		// what the cut-off dispatch left behind.
		if now.Sub(since) > stuckDispatched {
			fin.Class, fin.Detail = classNotExecuted, "the dispatch was cut off before the job was stored"
			s.finishRun(fin)
			_ = hostrun.Remove(ctx, c.Client, s.jobs, run.ExecutionID)
		}
	case "dispatched":
		if now.Sub(since) > stuckDispatched {
			fin.Class, fin.Detail = classNotExecuted, "the job was stored but never started"
			s.finishRun(fin)
			_ = hostrun.Remove(ctx, c.Client, s.jobs, run.ExecutionID)
		} else if run.State == executordb.RunDispatching {
			_ = s.db.MarkRunRunning(run.ExecutionID, run.HostID, c.Endpoint.String())
		}
	case "running":
		if run.State == executordb.RunDispatching {
			_ = s.db.MarkRunRunning(run.ExecutionID, run.HostID, c.Endpoint.String())
		}
	case "dead":
		fin.Class, fin.Detail = hostrun.ClassScriptInterrupted, "the job ended without a result (host reboot or kill)"
		if now.Sub(since) >= run.Timeout {
			fin.Class, fin.Detail = hostrun.ClassExecutionTimeout, "the job did not finish within its timeout"
		}
		s.finishRun(fin)
		// A killed job never ran its own cleanup: remove the job and run
		// directories (and any secrets) now.
		if err := hostrun.Remove(ctx, c.Client, s.jobs, run.ExecutionID); err != nil {
			s.log.Warn("audit", "kind", "job_cleanup_failed", "execution", run.ExecutionID, "host", run.HostID, "detail", err.Error())
		}
	case "finished":
		res, err := hostrun.Collect(ctx, c.Client, s.jobs, run.ExecutionID, st.ExitCode)
		if err != nil {
			s.log.Warn("audit", "kind", "reconcile_collect_failed", "execution", run.ExecutionID, "host", run.HostID, "detail", err.Error())
			return
		}
		// Secret values never leave the executor in a result or log.
		if err := s.redactDurable(run, &res); err != nil {
			s.log.Warn("audit", "kind", "reconcile_waits_for_vault", "execution", run.ExecutionID, "host", run.HostID)
			return
		}
		fin.Class, fin.Detail, fin.ExitCode = res.Class, res.Detail, res.ExitCode
		fin.Result, fin.Log, fin.LogTruncated = res.Result, res.Log, res.LogTruncated
		if old, ok := hostrun.AwaitReboot(res.Result); ok && res.Class == hostrun.ClassSuccess {
			// The job scheduled a reboot: the run ends when the host is
			// back with a new boot ID, or as host_not_returned.
			// The action's timeout covers the job and the reboot.
			deadline := since.Add(run.Timeout)
			if err := s.db.AddRunReboot(executordb.RunReboot{ExecutionID: run.ExecutionID, HostID: run.HostID, OldBootID: old,
				Deadline: deadline, ExitCode: res.ExitCode, Result: res.Result, Log: res.Log, LogTruncated: res.LogTruncated}); err != nil {
				s.log.Error("audit", "kind", "store_error", "op", "add_run_reboot", "detail", err.Error())
				return
			}
			s.log.Info("audit", "kind", "run_awaits_reboot", "execution", run.ExecutionID, "host", run.HostID, "deadline", deadline.UTC())
		} else {
			s.finishRun(fin)
		}
		// Stored: the job directory can go (the tmpfiles rule is the
		// fallback, spec 07).
		if err := hostrun.Remove(ctx, c.Client, s.jobs, run.ExecutionID); err != nil {
			s.log.Warn("audit", "kind", "job_cleanup_failed", "execution", run.ExecutionID, "host", run.HostID, "detail", err.Error())
		}
	}
}

// classHostNotReturned: a rebooted host did not come back (spec 07/11).
const classHostNotReturned = "host_not_returned"

func (s *Service) finishReboot(run executordb.Run, r executordb.RunReboot, class, detail, endpoint string) {
	s.finishRun(executordb.Run{ExecutionID: run.ExecutionID, HostID: run.HostID, Class: class, Detail: detail, ExitCode: r.ExitCode,
		Result: r.Result, Log: r.Log, LogTruncated: r.LogTruncated, Endpoint: endpoint})
	if err := s.db.DeleteRunReboot(run.ExecutionID, run.HostID); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "delete_run_reboot", "detail", err.Error())
	}
}
