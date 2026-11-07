// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Container update members (ADR 0006 P2-03, container update plan cu02).
//
// A container mutation runs only as a batch member, and the executor, not
// the server, decides how: the frozen action ID makes it a durable job
// (Decision 5) with the fixed containerMutationTimeout, whatever timeout the
// request names. What the job gets is exactly the parameter document
// rendered from the member's frozen binding (Decision 3): the executor
// re-renders it and refuses the member when the approved parameters are not
// those bytes. Nothing is read back from the host to reconstruct a
// container's configuration (no `docker inspect` definition): the binding
// and the approved, hash-checked artifact are the only inputs, and the
// artifact recreates exactly the bound targets from the operator's Compose
// files with the bound image digests.

// composeUpdateAction is the only container mutation that runs in cu02.
// Rollback (cu03), standalone definitions (cu05) and private registry
// transfer (cu06) are refused here until their executor-side checks exist.
const composeUpdateAction = "docker.compose_update"

const (
	// containerMutationTimeout bounds one container mutation job on the
	// host (systemd RuntimeMaxSec). The member's request cannot change it.
	containerMutationTimeout = 30 * time.Minute
	// containerWaitMargin is how long past the job timeout RunBatchMember
	// waits for the run to be reconciled before it answers unknown and
	// leaves the run to the background reconciler.
	containerWaitMargin = 5 * time.Minute
	// containerRunPoll is how often a dispatched container job is checked
	// while RunBatchMember waits for it.
	containerRunPoll = 10 * time.Second
)

var (
	// errContainerBinding: a container member without its update binding,
	// or with an inspect-derived container binding instead.
	errContainerBinding = errors.New("container member needs its frozen update binding and no inspect-derived binding")
	// errContainerUnsupported: rollback, standalone and private registry
	// members are not executed yet.
	errContainerUnsupported = errors.New("only public compose updates are executed (rollback: cu03, standalone: cu05, private registry: cu06)")
	// errContainerParameters: the approved parameters are not the
	// rendering of the frozen binding.
	errContainerParameters = errors.New("parameters are not the rendering of the frozen binding")
)

// isContainerMember reports whether m is a container mutation member: its
// frozen action ID is one of the container update actions, or it carries
// an update binding. Such a member always runs durable.
func isContainerMember(m canonical.BatchMember) bool {
	return canonical.IsContainerUpdateAction(m.Request.ActionID) || m.ContainerUpdate != nil
}

// checkContainerMember checks a container member and its approved
// parameters before anything is claimed, and again on the claimed permit
// immediately before the host: only a public compose update runs, and only
// with exactly the parameters rendered from its frozen binding.
func checkContainerMember(m canonical.BatchMember, params []byte) error {
	if m.ContainerUpdate == nil || m.Container != nil {
		return errContainerBinding
	}
	u := *m.ContainerUpdate
	if m.Request.ActionID != composeUpdateAction || u.Kind != canonical.ContainerUpdateKindUpdate ||
		u.Form != canonical.ContainerUpdateFormCompose || u.Registry != nil {
		return errContainerUnsupported
	}
	want, hash, err := canonical.ContainerUpdateParameters(u)
	if err != nil {
		return fmt.Errorf("%w: %w", errContainerParameters, err)
	}
	if !bytes.Equal(params, want) || hash != m.Request.ParametersHash {
		return errContainerParameters
	}
	return nil
}

// durableRunner stores and starts one durable job (hostrun.Dispatch; tests
// may replace it).
type durableRunner func(ctx context.Context, client *ssh.Client, cfg hostrun.JobConfig, executionID string, params, script []byte,
	timeout time.Duration, secrets ...hostrun.Secret) (hostrun.DispatchOutcome, string, error)

// durableJobOver reports whether a finished run's class proves that its
// job is over on the host: its result was read, or it never started. A run
// closed without a result (unknown, script_interrupted, execution_timeout)
// does not: the script's own processes may still run (Q15).
func durableJobOver(class string) bool {
	switch class {
	case classUnknown, hostrun.ClassScriptInterrupted, hostrun.ClassExecutionTimeout:
		return false
	}
	return true
}

// durableMemberTransport hands a claimed container member to its host as a
// durable job and waits, bounded, for the run's reconciled outcome. c is
// the open connection to the target; the run is already recorded as
// dispatching.
func (s *Service) durableMemberTransport(ctx context.Context, x *batchExec, call *batchMemberCall, run dispatch.Run, c *sshtransport.Client) (dispatch.Outcome, error) {
	resp := call.resp
	if err := checkContainerMember(run.Member, run.Parameters); err != nil {
		c.Close()
		resp.Class, resp.Detail = classBatchNotExecuted, "not started: "+err.Error()
		return dispatch.OutcomeFailure, nil
	}
	// From here the job may be on the host: the reconciler owns the run.
	call.dispatched = true
	outcome, detail, err := x.durable(ctx, c.Client, s.jobs, run.ExecutionID, run.Parameters, call.artifact, call.timeout)
	switch {
	case err != nil:
		// The connection broke during dispatch: the reconciler finds out
		// whether the job is on the host.
		s.log.Warn("audit", "kind", "batch_member_dispatch_uncertain", "execution", run.ExecutionID, "host", call.hostID, "detail", err.Error())
	case outcome == hostrun.NotStarted:
		call.dispatched = false
		c.Close()
		resp.Class, resp.Detail = hostrun.ClassPrecheckFailed, "not started: "+detail
		return dispatch.OutcomeFailure, nil
	default:
		if err := s.db.MarkRunRunning(run.ExecutionID, call.hostID, c.Endpoint.String()); err != nil {
			s.log.Error("audit", "kind", "store_error", "op", "mark_run_running", "execution", run.ExecutionID, "detail", err.Error())
		}
		s.log.Info("audit", "kind", "batch_member_dispatched", "batch", run.ParentDigest, "member", run.MemberID, "execution", run.ExecutionID,
			"host", call.hostID, "action", run.ActionID, "endpoint", c.Endpoint.String())
	}
	c.Close()
	return s.awaitDurableMember(ctx, x, call, run)
}

// awaitDurableMember reconciles the member's own run until it is finished,
// for at most the job timeout plus containerWaitMargin or until ctx ends.
// While it waits the background reconciler leaves the run alone (the
// dispatching mark); afterwards it takes over.
func (s *Service) awaitDurableMember(ctx context.Context, x *batchExec, call *batchMemberCall, run dispatch.Run) (dispatch.Outcome, error) {
	resp := call.resp
	wctx, cancel := context.WithTimeout(ctx, call.timeout+containerWaitMargin)
	defer cancel()
	for {
		r, err := s.db.GetRun(run.ExecutionID, call.hostID)
		if err == nil && r.State != executordb.RunFinished && s.keys.Unlocked() {
			s.reconcile(wctx, r)
			r, err = s.db.GetRun(run.ExecutionID, call.hostID)
		}
		if err == nil && r.State == executordb.RunFinished {
			resp.Class, resp.Detail, resp.ExitCode = r.Class, r.Detail, int32(r.ExitCode)
			resp.Result, resp.Log, resp.LogTruncated = r.Result, r.Log, r.LogTruncated
			if r.Endpoint != "" {
				resp.Endpoint = r.Endpoint
			}
			call.jobOver = durableJobOver(r.Class)
			switch {
			case r.Class == hostrun.ClassSuccess:
				return dispatch.OutcomeSuccess, nil
			case !call.jobOver:
				return dispatch.OutcomeUnknown, fmt.Errorf("%s: %s; the job may still run on the target", r.Class, r.Detail)
			}
			return dispatch.OutcomeFailure, nil
		}
		if err != nil {
			s.log.Error("audit", "kind", "store_error", "op", "get_run", "execution", run.ExecutionID, "detail", err.Error())
		}
		t := time.NewTimer(x.durablePoll)
		select {
		case <-wctx.Done():
			t.Stop()
			resp.Class = classUnknown
			resp.Detail = "the durable job has not been reconciled yet; the executor keeps reconciling it and never reruns it"
			return dispatch.OutcomeUnknown, errors.New(resp.Detail)
		case <-t.C:
		}
	}
}

// memberRunFinished is called for every finished durable run. A batch
// member's outcome goes to the live rollout (the rollout ignores an
// outcome it has already, or an unknown execution), and a durable hold on
// its target ends once the job is over.
func (s *Service) memberRunFinished(executionID, hostID, class string) {
	r, err := s.db.GetRun(executionID, hostID)
	if err != nil || r.MemberID == "" {
		return
	}
	if s.batchAuth != nil {
		s.batchAuth.RecordOutcome(executionID, r.MemberID, permit.OutcomeOfClass(class))
	}
	x := s.batchRun
	if x == nil || !durableJobOver(class) {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	h := x.held[hostID]
	if h == nil || !h.durable || h.running || h.executionID != executionID {
		return
	}
	delete(x.held, hostID)
	if x.hosts[hostID] == executionID {
		delete(x.hosts, hostID)
	}
	_ = s.saveHeldLocked(x)
	s.log.Info("audit", "kind", "batch_target_released", "execution", executionID, "host", hostID,
		"detail", "the durable job is over")
}

// BatchContainerMembersDurable reports whether batch execution is wired so
// that container members run as durable jobs through the production
// transport (hostrun.Dispatch) and are followed at containerRunPoll. It is
// for the wiring check of the shipped executor.
func (s *Service) BatchContainerMembersDurable() bool {
	x := s.batchRun
	return x != nil && x.durable != nil && x.durablePoll == containerRunPoll &&
		reflect.ValueOf(x.durable).Pointer() == reflect.ValueOf(hostrun.Dispatch).Pointer()
}

// durableHoldGone reports whether the durable job a hold waits for is over,
// from the executor's own run record: never from hostrun.RunVisible, which
// sees only the SSH user's processes while the job runs as root.
func (s *Service) durableHoldGone(hostID, executionID string) bool {
	r, err := s.db.GetRun(executionID, hostID)
	return err == nil && r.State == executordb.RunFinished && durableJobOver(r.Class)
}
