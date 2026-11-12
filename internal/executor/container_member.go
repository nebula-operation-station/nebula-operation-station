// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
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
// those bytes.
//
// The parameters only bind what runs if the script consumes them, so the
// executor also pins the script: a member runs only with the module version
// and the exact artifact digest the executor pins (composePins), never with
// some other artifact the operator happens to trust for the action ID. The
// inspect-based docker.compose_update 1.0.0, which reads the project's
// directory and Compose files from `docker inspect` labels and pulls
// floating tags, is therefore never a container member's artifact: only the
// 2.0.0 artifact that recreates the bound targets with the bound digests,
// whose digest is pinned here (composeUpdateArtifactSHA256), runs. A
// rollback member (cu03) runs only the pinned docker.compose_rollback 1.0.0
// artifact (composeRollbackArtifactSHA256), which recreates the bound
// earlier definition from the retained images and pulls nothing, and only
// after checkRollbackMember accepted it against the recorded update.
// A standalone member (cu05) runs only the pinned docker.update or
// docker.rollback 1.0.0 artifact, which recreates the container from the
// operator's stored definition; the executor adds that definition as the
// run secret "definition" (container_standalone.go).

// composeUpdateAction and composeRollbackAction are the container mutations
// that run: a public compose update (cu02) and its rollback (cu03).
// standaloneUpdateAction and standaloneRollbackAction are their standalone
// forms (cu05). Private registry transfer (cu06) is refused here until its
// executor-side checks exist.
const (
	composeUpdateAction      = "docker.compose_update"
	composeRollbackAction    = "docker.compose_rollback"
	standaloneUpdateAction   = "docker.update"
	standaloneRollbackAction = "docker.rollback"
)

const (
	// composeUpdateVersion is the docker.compose_update module version whose
	// artifact consumes the update binding (result compose-update-v2).
	composeUpdateVersion = "2.0.0"
	// composeUpdateArtifactSHA256 is the lowercase hex SHA-256 of that
	// artifact, internal/executions/actions/scripts/docker_compose_update_v2.sh
	// as embedded in the server's catalog (checked by
	// TestShippedComposeUpdatePinMatchesEmbeddedScript). Changing it is a
	// reviewed change of this protected package.
	composeUpdateArtifactSHA256 = "39ecf0be674988af9c3893ceb23b78f7e7bb18f9d1dff9b92d6ee746c3b7b9ae"

	// composeRollbackVersion is the docker.compose_rollback module version
	// whose artifact consumes the rollback binding (result
	// compose-rollback-v1).
	composeRollbackVersion = "1.0.0"
	// composeRollbackArtifactSHA256 is the lowercase hex SHA-256 of
	// internal/executions/actions/scripts/docker_compose_rollback.sh as
	// embedded in the server's catalog (checked by
	// TestShippedComposeRollbackPinMatchesEmbeddedScript). Changing it is a
	// reviewed change of this protected package.
	composeRollbackArtifactSHA256 = "ac628df0cf626e85ba01b89095bf8c8a51b0316af1ea90921f19d0b2a7a45d79"

	// standaloneUpdateVersion and standaloneRollbackVersion are the
	// docker.update and docker.rollback module versions whose artifacts
	// consume the standalone binding and the definition run secret (results
	// standalone-update-v1 and standalone-rollback-v1).
	standaloneUpdateVersion   = "1.0.0"
	standaloneRollbackVersion = "1.0.0"
	// standaloneUpdateArtifactSHA256 is the lowercase hex SHA-256 of
	// internal/executions/actions/scripts/docker_update.sh as embedded in
	// the server's catalog (checked by
	// TestShippedStandalonePinsMatchEmbeddedScripts). Changing it is a
	// reviewed change of this protected package.
	standaloneUpdateArtifactSHA256 = "735f8b078985c5b0edbc983c8e74a5e789067560d0f7af517e26cda0b1ead6a4"
	// standaloneRollbackArtifactSHA256 is the lowercase hex SHA-256 of
	// internal/executions/actions/scripts/docker_rollback.sh, checked the
	// same way.
	standaloneRollbackArtifactSHA256 = "9d21136b63488f5d6b855e76ea1dabc842f7cf232761515a0aced05a4a8e1c3b"
)

// containerArtifact pins the one action, module version and artifact
// digest a container member must name: a pin admits its artifact only for
// its own action, so an update member never runs the rollback script or
// the other way round.
type containerArtifact struct {
	ActionID      string
	ModuleVersion string
	SHA256        string
}

// shippedComposeUpdatePin is the binding-consuming docker.compose_update
// artifact of the shipped executor.
func shippedComposeUpdatePin() containerArtifact {
	return containerArtifact{ActionID: composeUpdateAction, ModuleVersion: composeUpdateVersion, SHA256: composeUpdateArtifactSHA256}
}

// shippedComposeRollbackPin is the binding-consuming docker.compose_rollback
// artifact of the shipped executor.
func shippedComposeRollbackPin() containerArtifact {
	return containerArtifact{ActionID: composeRollbackAction, ModuleVersion: composeRollbackVersion, SHA256: composeRollbackArtifactSHA256}
}

// shippedStandaloneUpdatePin is the docker.update artifact of the shipped
// executor.
func shippedStandaloneUpdatePin() containerArtifact {
	return containerArtifact{ActionID: standaloneUpdateAction, ModuleVersion: standaloneUpdateVersion, SHA256: standaloneUpdateArtifactSHA256}
}

// shippedStandaloneRollbackPin is the docker.rollback artifact of the
// shipped executor.
func shippedStandaloneRollbackPin() containerArtifact {
	return containerArtifact{ActionID: standaloneRollbackAction, ModuleVersion: standaloneRollbackVersion, SHA256: standaloneRollbackArtifactSHA256}
}

// shippedContainerPins are the pins of the shipped executor.
func shippedContainerPins() []containerArtifact {
	return []containerArtifact{shippedComposeUpdatePin(), shippedComposeRollbackPin(), shippedStandaloneUpdatePin(), shippedStandaloneRollbackPin()}
}

// containerMemberForm is the binding kind and form a container action must
// carry (always public).
type containerMemberForm struct{ kind, form string }

// containerMemberForms is what a container member may be, per action ID.
var containerMemberForms = map[string]containerMemberForm{
	composeUpdateAction:      {canonical.ContainerUpdateKindUpdate, canonical.ContainerUpdateFormCompose},
	composeRollbackAction:    {canonical.ContainerUpdateKindRollback, canonical.ContainerUpdateFormCompose},
	standaloneUpdateAction:   {canonical.ContainerUpdateKindUpdate, canonical.ContainerUpdateFormAlone},
	standaloneRollbackAction: {canonical.ContainerUpdateKindRollback, canonical.ContainerUpdateFormAlone},
}

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
	// containerDispatchTimeout bounds handing a container job to its host;
	// the handoff runs to this bound even when the request ends.
	containerDispatchTimeout = 2 * time.Minute
	// containerReconcileAttempt bounds one reconcile attempt of a waiting
	// container member (connect, check, collect).
	containerReconcileAttempt = 2 * time.Minute
)

var (
	// errContainerBinding: a container member without its update binding,
	// or with an inspect-derived container binding instead.
	errContainerBinding = errors.New("container member needs its frozen update binding and no inspect-derived binding")
	// errContainerUnsupported: private registry members are not executed
	// yet, and an action carries only its own binding kind and form.
	errContainerUnsupported = errors.New("only public compose and standalone updates and their rollbacks are executed, each with its own binding kind and form (private registry: cu06)")
	// errContainerParameters: the approved parameters are not the
	// rendering of the frozen binding.
	errContainerParameters = errors.New("parameters are not the rendering of the frozen binding")
	// errContainerArtifact: the member's module version and artifact are
	// not the pinned, binding-consuming ones of its action (or none is
	// pinned).
	errContainerArtifact = errors.New("module version and artifact are not the pinned binding-consuming artifact of the action")
)

// isContainerMember reports whether m is a container mutation member: its
// frozen action ID is one of the container update actions, or it carries
// an update binding. Such a member always runs durable.
func isContainerMember(m canonical.BatchMember) bool {
	return canonical.IsContainerUpdateAction(m.Request.ActionID) || m.ContainerUpdate != nil
}

// checkContainerMember checks a container member and its approved
// parameters before anything is claimed, and again on the claimed permit
// immediately before the host: only a public compose update or rollback
// runs, each with its own binding kind, only with an action, module version
// and artifact digest equal to one of pins (an entry with an empty action,
// version or digest pins nothing), and only with exactly the parameters
// rendered from its frozen binding. A rollback member is checked against
// its recorded update separately (checkRollbackMember).
func checkContainerMember(m canonical.BatchMember, params []byte, pins ...containerArtifact) error {
	if m.ContainerUpdate == nil || m.Container != nil {
		return errContainerBinding
	}
	u := *m.ContainerUpdate
	f, ok := containerMemberForms[m.Request.ActionID]
	if !ok || u.Kind != f.kind || u.Form != f.form || u.Registry != nil {
		return errContainerUnsupported
	}
	if !slices.ContainsFunc(pins, func(p containerArtifact) bool {
		return p.ActionID != "" && p.SHA256 != "" && p.ModuleVersion != "" && p.ActionID == m.Request.ActionID &&
			p.ModuleVersion == m.Request.ModuleVersion && p.SHA256 == m.Request.ArtifactSHA256
	}) {
		return errContainerArtifact
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
	err := s.checkRollbackMember(run.Member, call.hostID)
	if err == nil {
		err = checkContainerMember(run.Member, run.Parameters, x.composePins...)
	}
	if err == nil {
		// A standalone member's definition again, right before the host:
		// unchanged since the claim and still of an accepted shape.
		err = s.recheckStandaloneDefinition(run.Member.ContainerUpdate, call.hostID, call.secrets)
	}
	if err == nil {
		// The row that keeps the prior image and definition exists before
		// anything can change on the host (R9).
		err = s.recordRecreationIntent(run, call.hostID, call.fingerprint)
	}
	if err != nil {
		c.Close()
		resp.Class, resp.Detail = classBatchNotExecuted, "not started: "+err.Error()
		return dispatch.OutcomeFailure, nil
	}
	// From here the job may be on the host: the reconciler owns the run.
	call.dispatched = true
	// The handoff is not cut by the caller hanging up: a cut-off dispatch
	// leaves a half-stored job that only ends after stuckDispatched.
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), containerDispatchTimeout)
	outcome, detail, err := x.durable(dctx, c.Client, s.jobs, run.ExecutionID, run.Parameters, call.artifact, call.timeout, call.secrets...)
	cancel()
	// The definition was handed over (or not); the executor keeps no copy.
	for _, sec := range call.secrets {
		clear(sec.Value)
	}
	call.secrets = nil
	switch {
	case err != nil:
		// The connection broke during dispatch: the reconciler finds out
		// whether the job is on the host.
		s.log.Warn("audit", "kind", "batch_member_dispatch_uncertain", "execution", run.ExecutionID, "host", call.hostID, "detail", err.Error())
	case outcome == hostrun.NotStarted:
		call.dispatched = false
		s.completeNotStarted(run.ExecutionID, detail)
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
		if err == nil && r.State != executordb.RunFinished && s.keys.Unlocked() && wctx.Err() == nil {
			// One attempt runs to its own bound: a caller hanging up must not
			// read as an unreachable host (that would back the run off and
			// count toward its reconcile deadline).
			actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), containerReconcileAttempt)
			s.reconcile(actx, r)
			acancel()
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
				// Class success alone is not a succeeded member: the
				// executor's verdict on the completed row decides.
				row, _ := s.completeRecreation(r)
				if containerMemberOutcome(r.Class, row) != permit.OutcomeSucceeded {
					resp.Class = hostrun.ClassPostcheckFailed
					resp.Detail = "the executor's postcheck verdict did not pass (recreation " + row.State + ")"
					if len(row.Verdict.Findings) > 0 {
						resp.Detail += ": " + strings.Join(row.Verdict.Findings, "; ")
					}
					return dispatch.OutcomeFailure, nil
				}
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

// memberRunFinished is called for every finished durable run. A container
// member's run is judged and its recreation row completed first (cu03);
// then the member's outcome goes to the live rollout (the rollout ignores
// an outcome it has already, or an unknown execution): succeeded only with
// class success and a passing verdict, which also records the member's own
// postcheck. A durable hold on its target ends once the job is over.
func (s *Service) memberRunFinished(executionID, hostID, class string) {
	r, err := s.db.GetRun(executionID, hostID)
	if err != nil || r.MemberID == "" {
		return
	}
	outcome := permit.OutcomeOfClass(class)
	row, container := s.completeRecreation(r)
	if container {
		outcome = containerMemberOutcome(class, row)
	}
	if s.batchAuth != nil {
		if container && outcome == permit.OutcomeSucceeded {
			s.batchAuth.RecordPostcheck(executionID, r.MemberID, containerPostcheckHash(r.MemberID))
		}
		s.batchAuth.RecordOutcome(executionID, r.MemberID, outcome)
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
	if !s.endHoldLocked(x, hostID, executionID) {
		return // still held; a recheck frees it once the hold end is recorded
	}
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
