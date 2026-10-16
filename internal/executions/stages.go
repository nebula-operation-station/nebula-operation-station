// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

// Stages (spec 07, Milestone 6, server part). The server turns a preset
// into a stage plan, proposes it with the request (the executor hashes it
// into the approval and enforces it), runs the hosts of the open stages
// and waits at gates. The executor decides; the server follows its view
// (GetRollout) and never runs a host the executor has not opened.

// Server-side classes of hosts that did not run in a rollout.
const (
	classSkipped = "skipped"
	classNotRun  = "not_run"
)

// Presets.
const (
	PresetSingle       = "single"
	PresetCanary       = "canary"
	PresetWaves        = "waves"
	PresetEnvironments = "environments"
)

// Plan is how an execution is staged.
type Plan struct {
	// Preset is single (or empty), canary, waves or environments.
	Preset string
	// Size is the number of canary hosts, or the wave size.
	Size int
	// Continue is manual or auto: how the next stage opens once a stage
	// passed. The executor refuses auto for HIGH and CRITICAL.
	Continue string
	// MaxFailed is the number of failed (and of unreachable) hosts each
	// stage tolerates; the canary stage tolerates none.
	MaxFailed int
}

// Staged reports whether the plan has stages.
func (p Plan) Staged() bool { return p.Preset != "" && p.Preset != PresetSingle }

// PlanError is an unusable plan (it describes the input).
type PlanError struct{ Reason string }

func (e *PlanError) Error() string { return e.Reason }

// stageMargin is added to each stage's planned duration; permitMargin to
// the whole plan (time for the gates).
const (
	stageMargin  = 5 * time.Minute
	permitMargin = time.Hour
	// maxPermitLifetime stays below the executor's 24 h limit.
	maxPermitLifetime = 24*time.Hour - time.Minute
)

// stageTimeout is the planned duration of a stage of n hosts.
func stageTimeout(a actions.Action, n int) int {
	rounds := (n + parallelHosts - 1) / parallelHosts
	d := time.Duration(rounds)*a.Timeout + stageMargin
	s := int(d / time.Second)
	return min(max(s, stageplan.MinTimeout), stageplan.MaxTimeout)
}

// buildStages turns a preset into stages over targets (in request order).
func buildStages(p Plan, a actions.Action, targets []target, envOf map[string]inventory.Environment) ([]stageplan.Stage, error) {
	if p.Continue != stageplan.ContinueManual && p.Continue != stageplan.ContinueAuto {
		return nil, &PlanError{"continue must be manual or auto"}
	}
	if p.MaxFailed < 0 || p.MaxFailed > MaxHosts {
		return nil, &PlanError{"max failed hosts per stage must be 0 or more"}
	}
	hosts := make([]string, len(targets))
	for i, t := range targets {
		hosts[i] = t.host
	}
	stage := func(name string, hs []string, maxFailed int) stageplan.Stage {
		mf := min(maxFailed, len(hs))
		return stageplan.Stage{Name: name, Hosts: hs, MaxFailed: mf, MaxUnreachable: mf, Continue: p.Continue, TimeoutS: stageTimeout(a, len(hs))}
	}
	var out []stageplan.Stage
	switch p.Preset {
	case PresetCanary:
		if p.Size < 1 || p.Size >= len(hosts) {
			return nil, &PlanError{fmt.Sprintf("the canary must be 1 to %d hosts (fewer than the selected hosts)", len(hosts)-1)}
		}
		out = []stageplan.Stage{stage("canary", hosts[:p.Size], 0), stage("rest", hosts[p.Size:], p.MaxFailed)}
	case PresetWaves:
		if p.Size < 1 || p.Size > MaxHosts {
			return nil, &PlanError{"the wave size must be 1 or more"}
		}
		if (len(hosts)+p.Size-1)/p.Size > stageplan.MaxStages {
			return nil, &PlanError{fmt.Sprintf("at most %d waves; choose a larger wave size", stageplan.MaxStages)}
		}
		for i := 0; i < len(hosts); i += p.Size {
			out = append(out, stage(fmt.Sprintf("wave-%d", i/p.Size+1), hosts[i:min(i+p.Size, len(hosts))], p.MaxFailed))
		}
	case PresetEnvironments:
		by := map[inventory.Environment][]string{}
		for _, h := range hosts {
			env := envOf[h]
			if env != inventory.EnvDev && env != inventory.EnvQA && env != inventory.EnvProd {
				return nil, &PlanError{fmt.Sprintf("host %s has no environment (DEV, QA or PROD)", h)}
			}
			by[env] = append(by[env], h)
		}
		for _, env := range []inventory.Environment{inventory.EnvDev, inventory.EnvQA, inventory.EnvProd} {
			if len(by[env]) > 0 {
				out = append(out, stage(strings.ToLower(string(env)), by[env], p.MaxFailed))
			}
		}
	default:
		return nil, &PlanError{"unknown preset"}
	}
	if len(out) > 0 {
		out[len(out)-1].Continue = stageplan.ContinueManual // nothing follows the last stage
	}
	return out, nil
}

// planExpiry is the permit expiry of a staged execution: the planned
// duration plus margin, at most just under 24 hours (spec 07).
func planExpiry(now time.Time, stages []stageplan.Stage) time.Time {
	d := permitMargin
	for _, s := range stages {
		d += time.Duration(s.TimeoutS) * time.Second
	}
	return now.Add(min(d, maxPermitLifetime))
}

// rollout asks the executor for its view of a rollout.
func (s *Service) rollout(ctx context.Context, digest string) (*pb.Rollout, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := s.exec.GetRollout(cctx, &pb.GetRolloutRequest{ExecutionDigest: digest})
	if err != nil {
		return nil, err
	}
	return r.GetRollout(), nil
}

// Rollout returns the executor's view of an execution's rollout.
func (s *Service) Rollout(ctx context.Context, id string) (*pb.Rollout, error) {
	e, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if e.StagePlan == "" || e.Digest == "" {
		return nil, ErrNotStaged
	}
	return s.rollout(ctx, e.Digest)
}

// Errors of staged executions.
var (
	ErrNotStaged  = errors.New("the execution has no stages")
	ErrNotRunning = errors.New("the execution is not running")
	ErrNoRetry    = errors.New("only a host that was unreachable (nothing ran) in an attached operation can be retried")
)

// waitNote says what a rollout waits for.
func waitNote(ro *pb.Rollout) string {
	open := int(ro.GetOpenStage())
	if open < 1 || open > len(ro.GetStages()) {
		return ""
	}
	st := ro.GetStages()[open-1]
	if st.GetPassed() {
		if open == len(ro.GetStages()) {
			return ""
		}
		return fmt.Sprintf("stage %d (%s) passed; waiting for you to continue to stage %d", open, st.GetStage().GetName(), open+1)
	}
	return fmt.Sprintf("stage %d (%s) has not passed: retry or skip the unreachable hosts, or abort", open, st.GetStage().GetName())
}

// dispatchStaged runs a staged execution: the hosts of the open stages,
// then waits for the executor to open more (a gate, or automatically),
// until every host is finished or the rollout stopped, was aborted or its
// permit ended.
func (s *Service) dispatchStaged(ctx context.Context, id string, a actions.Action) {
	for ctx.Err() == nil {
		e, err := s.Get(ctx, id)
		if err != nil {
			s.log.Error("execution dispatch", "execution", id, "error", err.Error())
			return
		}
		ro, err := s.rollout(ctx, e.Digest)
		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound, codes.FailedPrecondition:
			s.endRollout(ctx, e, "not_executed", "the permit ended (expired, executor locked or restarted); this host did not run")
			return
		default:
			s.log.Warn("rollout", "execution", id, "error", err.Error())
			if !sleepCtx(ctx, pollInterval) {
				return
			}
			continue
		}
		outcome := map[string]string{}
		for _, st := range ro.GetStages() {
			for _, o := range st.GetOutcomes() {
				outcome[o.GetHostId()] = o.GetOutcome()
			}
		}
		for _, h := range e.Hosts {
			if outcome[h.HostID] != "skipped" {
				continue
			}
			switch {
			case h.State == "waiting":
				s.finishHost(e.ID, a.ID, h.HostID, classSkipped, "skipped at a gate", -1, nil, nil, false)
			case h.State == "finished" && h.Class == "network_unreachable":
				// Unreachable, then skipped: nothing ran, and it no longer
				// counts as a failure of the rollout.
				if _, err := s.db.ExecContext(ctx, `UPDATE execution_hosts SET class = ?, detail = 'unreachable; skipped at a gate'
					WHERE execution_id = ? AND host_id = ? AND state = 'finished' AND class = 'network_unreachable'`, classSkipped, e.ID, h.HostID); err != nil {
					s.log.Error("execution host skip", "execution", e.ID, "host", h.HostID, "error", err.Error())
				}
			}
		}
		if ro.GetAborted() || ro.GetStopped() != "" {
			why := "the rollout was aborted; this host did not run"
			if ro.GetStopped() != "" {
				why = "the rollout stopped (" + ro.GetStopped() + "); this host did not run"
			}
			s.endRollout(ctx, e, classNotRun, why)
			return
		}
		var runnable []Host
		pending := false
		for _, h := range e.Hosts {
			if h.State == "finished" || outcome[h.HostID] == "skipped" {
				continue
			}
			pending = true
			if h.Stage <= int(ro.GetOpenStage()) {
				runnable = append(runnable, h)
			}
		}
		if !pending {
			// Every host has an outcome, but the open stage may still not
			// have passed (an unreachable host over the threshold): the
			// rollout waits for a retry, a skip or an abort, or until its
			// permit ends (review m63 finding 1).
			if open := int(ro.GetOpenStage()); open >= 1 && open <= len(ro.GetStages()) && !ro.GetStages()[open-1].GetPassed() {
				s.setWaiting(ctx, e, waitNote(ro))
				if !sleepCtx(ctx, pollInterval) {
					return
				}
				continue
			}
			s.setWaiting(ctx, e, "")
			return
		}
		if len(runnable) > 0 {
			s.setWaiting(ctx, e, "")
			sem := make(chan struct{}, parallelHosts)
			var wg sync.WaitGroup
			for _, h := range runnable {
				wg.Add(1)
				sem <- struct{}{}
				go func(h Host) {
					defer wg.Done()
					defer func() { <-sem }()
					s.runHost(ctx, e, a, h)
				}(h)
			}
			wg.Wait()
			continue
		}
		s.setWaiting(ctx, e, waitNote(ro))
		if !sleepCtx(ctx, pollInterval) {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// setWaiting records what the rollout waits for and notifies a new wait
// once (spec 13: "stage gate waiting for manual continue").
func (s *Service) setWaiting(ctx context.Context, e Execution, note string) {
	res, err := s.db.ExecContext(ctx, `UPDATE executions SET waiting = ? WHERE id = ? AND waiting != ?`, note, e.ID, note)
	if err != nil {
		return
	}
	if n, _ := res.RowsAffected(); n == 1 && note != "" && s.notifier != nil {
		s.notifier.Notify(ctx, notify.Event{Kind: notify.KindExecution, State: "WAITING", ExecutionID: e.ID, Time: s.now(),
			Reason: e.ActionID + ": " + note})
	}
}

// endRollout finishes every host that did not run.
func (s *Service) endRollout(ctx context.Context, e Execution, class, why string) {
	for _, h := range e.Hosts {
		if h.State == "waiting" {
			s.finishHost(e.ID, e.ActionID, h.HostID, class, why, -1, nil, nil, false)
		}
	}
	s.setWaiting(ctx, e, "")
}

// GateResult is what a gate needs from the browser.
type GateResult struct {
	// Done: the gate was applied (the privileged session sufficed).
	Done bool
	// Options are the WebAuthn request options for the assertion.
	Options []byte
	// CLI: only `nebula approve` on the executor host can apply it.
	CLI bool
}

// Gate is a gate on a staged execution: open stage Stage, or skip Host.
type Gate struct {
	Kind  string // open or skip
	Stage int
	Host  string
}

func (g Gate) proto() (*pb.Gate, error) {
	switch g.Kind {
	case "open":
		if g.Stage < 2 || g.Stage > stageplan.MaxStages || g.Host != "" {
			return nil, &PlanError{"open names a stage from 2"}
		}
		return &pb.Gate{Kind: pb.GateKind_GATE_KIND_OPEN_STAGE, Stage: uint32(g.Stage)}, nil
	case "skip":
		if g.Host == "" || g.Stage != 0 {
			return nil, &PlanError{"skip names a host"}
		}
		return &pb.Gate{Kind: pb.GateKind_GATE_KIND_SKIP_HOST, HostId: g.Host}, nil
	}
	return nil, &PlanError{"unknown gate"}
}

// staged returns a running staged execution.
func (s *Service) staged(ctx context.Context, id string) (Execution, error) {
	e, err := s.Get(ctx, id)
	if err != nil {
		return Execution{}, err
	}
	if e.StagePlan == "" {
		return Execution{}, ErrNotStaged
	}
	if e.State != "running" && e.State != "approved" {
		return Execution{}, ErrNotRunning
	}
	return e, nil
}

// BeginGate asks the executor what a gate needs; when the privileged
// session is enough it applies the gate at once.
func (s *Service) BeginGate(ctx context.Context, user, id string, g Gate) (GateResult, error) {
	e, err := s.staged(ctx, id)
	if err != nil {
		return GateResult{}, err
	}
	pg, err := g.proto()
	if err != nil {
		return GateResult{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := s.exec.BeginGate(cctx, &pb.BeginGateRequest{ExecutionDigest: e.Digest, Gate: pg})
	if err != nil {
		return GateResult{}, err
	}
	switch r.GetApprovalRequirement() {
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_NONE:
		if _, err := s.exec.CommitGate(cctx, &pb.CommitGateRequest{ExecutionDigest: e.Digest, Gate: pg}); err != nil {
			return GateResult{}, err
		}
		s.log.Info("audit", "kind", "execution_gate", "execution", id, "gate", g.Kind, "stage", g.Stage, "host", g.Host, "user", user)
		return GateResult{Done: true}, nil
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY:
		return GateResult{CLI: true}, nil
	}
	return GateResult{Options: r.GetRequestOptionsJson()}, nil
}

// CommitGate relays the browser's assertion for a gate.
func (s *Service) CommitGate(ctx context.Context, user, id string, g Gate, assertion []byte) error {
	e, err := s.staged(ctx, id)
	if err != nil {
		return err
	}
	pg, err := g.proto()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := s.exec.CommitGate(cctx, &pb.CommitGateRequest{ExecutionDigest: e.Digest, Gate: pg, AssertionJson: assertion}); err != nil {
		return err
	}
	s.log.Info("audit", "kind", "execution_gate", "execution", id, "gate", g.Kind, "stage", g.Stage, "host", g.Host, "user", user)
	return nil
}

// Abort stops a staged execution: the executor refuses every host that
// has not run.
func (s *Service) Abort(ctx context.Context, user, id string) error {
	e, err := s.staged(ctx, id)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if _, err := s.exec.AbortRollout(cctx, &pb.AbortRolloutRequest{ExecutionDigest: e.Digest}); err != nil {
		return err
	}
	s.log.Info("audit", "kind", "execution_aborted", "execution", id, "user", user)
	return nil
}

// RetryHost runs an unreachable host of a staged, attached execution
// again. The executor decides whether the permit still covers it (only a
// run that never reached the host leaves it unused).
func (s *Service) RetryHost(ctx context.Context, user, id, host string) error {
	e, err := s.staged(ctx, id)
	if err != nil {
		return err
	}
	if e.Durable {
		return ErrNoRetry
	}
	// One statement against finishExecution's: either the retry lands while
	// the execution still runs, or the execution finished first and the
	// retry is refused.
	res, err := s.db.ExecContext(ctx, `UPDATE execution_hosts SET state = 'waiting', class = '', detail = 'retry', finished_at = NULL
		WHERE execution_id = ? AND host_id = ? AND state = 'finished' AND class = 'network_unreachable'
		AND EXISTS (SELECT 1 FROM executions WHERE id = ? AND state = 'running')`, id, host, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNoRetry
	}
	s.log.Info("audit", "kind", "execution_host_retry", "execution", id, "host", host, "user", user)
	s.start(id)
	return nil
}
