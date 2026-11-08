// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// Container recreation records, retention and the rollback window (ADR
// 0006 P2-04, R9 to R13, container update plan cu03).
//
// Before a container member's job is dispatched the executor writes the
// member's row in state intent: the bound images with the prior image ID,
// the retained tag the script will create and the retained reference, and
// the executor-owned recreation definition. When the run finishes the
// executor judges it (container_judge.go) and completes the row once,
// before the outcome reaches the rollout. Only a run with class success and
// a passing verdict is a succeeded member; everything else fails it. NOS
// never prunes: the retained image and the row last through the rollback
// window, and the row stays as history afterwards. Nothing here retries a
// run or starts a rollback; a rollback is a separately approved member.

// DefaultRollbackWindow is how long after an update its row allows a
// rollback (R9). The expiry is set once, when the row first leaves intent.
const DefaultRollbackWindow = 7 * 24 * time.Hour

var (
	// errRecreationIntent: the intent row could not be written, so the job
	// is not dispatched.
	errRecreationIntent = errors.New("the container recreation record could not be written")

	// Rollback source refusals (Evaluate's row, window and recovery plan
	// checks, executor side).
	errRollbackNoRow          = errors.New("rollback: no recorded update for rollback_of")
	errRollbackOfRollback     = errors.New("rollback: a rollback's own row is never a rollback source")
	errRollbackState          = errors.New("rollback: the recorded update is not recreated or partial")
	errRollbackNoBaseline     = errors.New("rollback: no_baseline")
	errRollbackWindow         = errors.New("rollback: the rollback window is over")
	errRollbackRecoveryPlan   = errors.New("rollback: no recovery plan with the bound digest")
	errRollbackBindingDiffers = errors.New("rollback: the binding does not equal the recorded update")
)

// recreationDefinition is the executor-owned definition a rollback
// recreates from (R9, Q16). It holds identities and digests only: no file
// content and no environment, so nothing secret.
type recreationDefinition struct {
	Form              string                                `json:"form"`
	Project           string                                `json:"project,omitempty"`
	SourceDigest      string                                `json:"source_digest,omitempty"`
	WorkingDirHash    string                                `json:"working_dir_hash,omitempty"`
	ConfigFilesHash   string                                `json:"config_files_hash,omitempty"`
	DefinitionID      string                                `json:"definition_id,omitempty"`
	DefinitionVersion uint64                                `json:"definition_version,omitempty"`
	Services          []definitionService                   `json:"services"`
	Dependencies      []canonical.ContainerUpdateDependency `json:"dependencies"`
}

// definitionService is one recreated service before the update.
type definitionService struct {
	Service string `json:"service"`
	// PriorReferences are the targets' running references, sorted and
	// distinct.
	PriorReferences []string `json:"prior_references"`
	// PriorOverrideEntry is the NOS override entry the service ran with
	// (a reference with a digest, which cu02's phase 1 accepts only as the
	// override's entry), or '' when it had none.
	PriorOverrideEntry string `json:"prior_override_entry"`
	// ReplicasBefore is the replica count a rollback restores.
	ReplicasBefore int `json:"replicas_before"`
}

// retainedTag is the tag phase 4 gives the prior image of entry index.
func retainedTag(executionID string, index int) string {
	return fmt.Sprintf("nos-retained:%s-%d", executionID, index)
}

// recreationIntent builds the intent row of an update member from its
// frozen binding.
func recreationIntent(run dispatch.Run, hostID, hostKey string) (executordb.ContainerRecreation, error) {
	if run.Member.ContainerUpdate == nil {
		return executordb.ContainerRecreation{}, errContainerBinding
	}
	u := *run.Member.ContainerUpdate
	binding, err := json.Marshal(u)
	if err != nil {
		return executordb.ContainerRecreation{}, fmt.Errorf("encode binding: %w", err)
	}
	def := recreationDefinition{Form: u.Form, Project: u.Project, SourceDigest: u.SourceDigest, WorkingDirHash: u.WorkingDirHash,
		ConfigFilesHash: u.ConfigFilesHash, DefinitionID: u.DefinitionID, DefinitionVersion: u.DefinitionVersion,
		Services: []definitionService{}, Dependencies: u.Dependencies}
	if def.Dependencies == nil {
		def.Dependencies = []canonical.ContainerUpdateDependency{}
	}
	images := make([]executordb.RecreationImage, 0, len(u.Images))
	for i, img := range u.Images {
		ds := definitionService{Service: img.Service, PriorReferences: []string{}}
		for _, t := range u.Targets {
			if t.Service != img.Service {
				continue
			}
			ds.ReplicasBefore++
			if !slices.Contains(ds.PriorReferences, t.RunningReference) {
				ds.PriorReferences = append(ds.PriorReferences, t.RunningReference)
			}
			if strings.Contains(t.RunningReference, "@sha256:") {
				ds.PriorOverrideEntry = t.RunningReference
			}
		}
		sort.Strings(ds.PriorReferences)
		def.Services = append(def.Services, ds)
		ri := executordb.RecreationImage{Service: img.Service, Repository: img.Repository, OldTag: img.OldTag, NewTag: img.NewTag,
			NewPlatformDigest: img.NewPlatformDigest, PriorImageID: img.OldImageID, RetainedTag: retainedTag(run.ExecutionID, i)}
		if len(img.OldDigests) > 0 {
			ri.RetainedReference = img.Repository + ":" + img.OldTag + "@" + img.OldDigests[0]
		}
		images = append(images, ri)
	}
	defJSON, err := json.Marshal(def)
	if err != nil {
		return executordb.ContainerRecreation{}, fmt.Errorf("encode definition: %w", err)
	}
	unit := u.Project
	if u.Form == canonical.ContainerUpdateFormAlone && len(u.Targets) == 1 {
		unit = u.Targets[0].ContainerName
	}
	return executordb.ContainerRecreation{
		ExecutionID: run.ExecutionID, BatchDigest: run.ParentDigest, MemberID: run.MemberID,
		Kind: u.Kind, RollbackOf: u.RollbackOf, HostID: hostID, HostKey: hostKey, Form: u.Form, Unit: unit,
		Binding: binding, Definition: defJSON, Images: images,
	}, nil
}

// recordRecreationIntent writes the intent row; the job must not be
// dispatched when it fails.
func (s *Service) recordRecreationIntent(run dispatch.Run, hostID, hostKey string) error {
	row, err := recreationIntent(run, hostID, hostKey)
	if err == nil {
		err = s.db.CreateContainerRecreation(row)
	}
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "create_container_recreation", "execution", run.ExecutionID, "detail", err.Error())
		return fmt.Errorf("%w: %w", errRecreationIntent, err)
	}
	s.log.Info("audit", "kind", "container_recreation_intent", "execution", run.ExecutionID, "batch", run.ParentDigest,
		"member", run.MemberID, "host", hostID, "unit", row.Unit)
	return nil
}

// recreationCompletion derives a row's completion from its finished run:
// class and result. A run closed without a result is uncertain; a stop in
// phases 1 to 4 is not_recreated; a reached recreate with an
// after-snapshot is recreated only with class success and a passing
// verdict, otherwise partial; without an after-snapshot it is uncertain.
func recreationCompletion(row executordb.ContainerRecreation, class string, result []byte) executordb.RecreationCompletion {
	c := executordb.RecreationCompletion{State: executordb.RecreationUncertain}
	if !durableJobOver(class) {
		c.Verdict.Findings = []string{"the run closed without a result (" + class + "); the recreation is uncertain"}
		return c
	}
	var u canonical.BatchContainerUpdate
	if err := json.Unmarshal(row.Binding, &u); err != nil {
		c.Verdict.Findings = []string{"the recorded binding cannot be read"}
		return c
	}
	res, err := parseComposeUpdateResult(result)
	if err != nil {
		if class == hostrun.ClassPrecheckFailed {
			// Exit 10 is the script's stop while nothing changed.
			c.State = executordb.RecreationNotRecreated
			c.Verdict.Findings = []string{"the run stopped before any recreate without a readable result"}
			return c
		}
		c.Verdict.Findings = []string{"the result cannot be read; the recreation is uncertain"}
		return c
	}
	if len(res.Baseline) > 0 {
		if b, err := json.Marshal(res.Baseline); err == nil {
			c.Baseline = b
		}
	}
	c.Images = slices.Clone(row.Images)
	for i := range c.Images {
		for _, p := range res.Pulled {
			if p.Service == c.Images[i].Service {
				c.Images[i].NewImageID = p.ImageID
			}
		}
	}
	switch {
	case res.stopped():
		c.State = executordb.RecreationNotRecreated
		c.Containers = recreationContainers(res.Baseline, res.Baseline)
		c.Verdict.Findings = []string{"stopped in phase " + res.Phase + " (" + reasonText(res.Reason) + "); nothing was recreated"}
		return c
	case res.After == nil:
		c.Verdict.Findings = []string{"no after-snapshot; the recreation is uncertain"}
		return c
	}
	v := judgeComposeUpdate(u, res)
	c.Verdict = executordb.RecreationVerdict{Judged: true, Passed: v.Passed, Findings: boundFindings(v.Findings)}
	c.Containers = recreationContainers(res.Baseline, res.After)
	c.State = executordb.RecreationPartial
	if v.Passed && class == hostrun.ClassSuccess {
		c.State = executordb.RecreationRecreated
	} else if v.Passed {
		c.Verdict.Passed = false
		c.Verdict.Findings = append(c.Verdict.Findings, "the run's class is "+class+", not success")
	}
	return c
}

// recreationContainers matches baseline and after-snapshot by service and
// replica number: a new ID is recreated, the same ID unchanged, no entry
// missing (R13: these are the incarnations for any later action). An
// after entry without a baseline replica is listed as recreated with no
// before values.
func recreationContainers(before, after []snapshotEntry) []executordb.RecreationContainer {
	afterBy := map[string]snapshotEntry{}
	for _, a := range after {
		if !a.Oversize {
			afterBy[replicaKey(a.Service, a.Replica)] = a
		}
	}
	seen := map[string]bool{}
	var out []executordb.RecreationContainer
	for _, b := range before {
		if b.Oversize {
			continue
		}
		k := replicaKey(b.Service, b.Replica)
		seen[k] = true
		c := executordb.RecreationContainer{Service: b.Service, Replica: b.Replica, Name: b.Name, IDBefore: b.ID,
			ReferenceBefore: b.RunningReference, ConfigBefore: b.ConfigurationDigest, ImageBefore: b.ImageID, Status: executordb.ContainerMissing}
		if a, ok := afterBy[k]; ok {
			c.IDAfter, c.ReferenceAfter, c.ConfigAfter, c.ImageAfter = a.ID, a.RunningReference, a.ConfigurationDigest, a.ImageID
			c.Status = executordb.ContainerRecreated
			if a.ID == b.ID {
				c.Status = executordb.ContainerUnchanged
			}
		}
		out = append(out, c)
	}
	for _, a := range after {
		k := replicaKey(a.Service, a.Replica)
		if a.Oversize || seen[k] {
			continue
		}
		out = append(out, executordb.RecreationContainer{Service: a.Service, Replica: a.Replica, Name: a.Name, IDAfter: a.ID,
			ReferenceAfter: a.RunningReference, ConfigAfter: a.ConfigurationDigest, ImageAfter: a.ImageID, Status: executordb.ContainerRecreated})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return out[i].Replica < out[j].Replica
	})
	return out
}

// completeRecreation completes the run's intent row, once, and returns
// the row; ok is false when the run has no row (not a container member).
// A row already completed is returned as it is.
func (s *Service) completeRecreation(r executordb.Run) (executordb.ContainerRecreation, bool) {
	row, err := s.db.GetContainerRecreation(r.ExecutionID)
	if errors.Is(err, executordb.ErrNoRecreation) {
		return executordb.ContainerRecreation{}, false
	}
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "get_container_recreation", "execution", r.ExecutionID, "detail", err.Error())
		return executordb.ContainerRecreation{ExecutionID: r.ExecutionID, State: executordb.RecreationIntent}, true
	}
	if row.State != executordb.RecreationIntent || r.State != executordb.RunFinished {
		return row, true
	}
	c := recreationCompletion(row, r.Class, r.Result)
	if err := s.db.CompleteContainerRecreation(r.ExecutionID, c, s.clock(), DefaultRollbackWindow); err != nil && !errors.Is(err, executordb.ErrRecreationState) {
		s.log.Error("audit", "kind", "store_error", "op", "complete_container_recreation", "execution", r.ExecutionID, "detail", err.Error())
		return row, true
	}
	if got, err := s.db.GetContainerRecreation(r.ExecutionID); err == nil {
		row = got
	}
	s.log.Info("audit", "kind", "container_recreation_judged", "execution", r.ExecutionID, "member", row.MemberID, "host", row.HostID,
		"state", row.State, "verdict_passed", row.Verdict.Passed, "findings", len(row.Verdict.Findings))
	return row, true
}

// completeNotStarted completes the row of a job that never started on the
// host: nothing was recreated.
func (s *Service) completeNotStarted(executionID, detail string) {
	c := executordb.RecreationCompletion{State: executordb.RecreationNotRecreated,
		Verdict: executordb.RecreationVerdict{Findings: []string{"the job never started: " + boundReason(detail)}}}
	if err := s.db.CompleteContainerRecreation(executionID, c, s.clock(), DefaultRollbackWindow); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "complete_container_recreation", "execution", executionID, "detail", err.Error())
	}
}

// containerMemberOutcome is the rollout outcome of a container member's
// finished run: succeeded only with class success and a passing verdict
// on a recreated row.
func containerMemberOutcome(class string, row executordb.ContainerRecreation) permit.Outcome {
	if class != hostrun.ClassSuccess {
		return permit.OutcomeOfClass(class)
	}
	if row.State == executordb.RecreationRecreated && row.Verdict.Judged && row.Verdict.Passed {
		return permit.OutcomeSucceeded
	}
	return permit.OutcomeFailed
}

// judgeFinishedIntents completes every intent row whose run has finished:
// a crash between finishing the run and completing its row is judged on
// the next reconcile pass, from the run's stored result.
func (s *Service) judgeFinishedIntents() {
	rows, err := s.db.ContainerRecreationsInIntent()
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "container_recreations_in_intent", "detail", err.Error())
		return
	}
	for _, row := range rows {
		r, err := s.db.GetRun(row.ExecutionID, row.HostID)
		if err != nil || r.State != executordb.RunFinished {
			continue
		}
		s.memberRunFinished(r.ExecutionID, r.HostID, r.Class)
	}
}

// ContainerRecreations lists the recreation rows of a host (all hosts for
// an empty hostID), newest first, without the recreation definition and
// the baseline: those stay in the executor.
func (s *Service) ContainerRecreations(hostID string) ([]executordb.ContainerRecreation, error) {
	rows, err := s.db.ListContainerRecreations(hostID)
	if err != nil {
		return nil, fmt.Errorf("list container recreations: %w", err)
	}
	for i := range rows {
		rows[i].Definition, rows[i].Baseline = nil, nil
	}
	return rows, nil
}

// checkRollbackSource is the executor's check of a rollback binding
// against the recorded update (R10, R12): the row exists and is an
// update's, it is recreated or partial and has a baseline, the window is
// open at now, a recovery plan with the bound digest exists, and the
// binding equals the row: the reversed images with their rollback blocks,
// the present containers as targets with their recorded after-values, the
// dependencies and the source digest. An image entry without a target is
// accepted only when the row records every container of that service as
// missing.
func checkRollbackSource(u canonical.BatchContainerUpdate, row executordb.ContainerRecreation, plan *executordb.RecoveryPlan, hostID string, now time.Time) error {
	switch {
	case row.ExecutionID == "" || row.ExecutionID != u.RollbackOf || row.HostID != hostID:
		return errRollbackNoRow
	case row.Kind != canonical.ContainerUpdateKindUpdate:
		return errRollbackOfRollback
	case row.State != executordb.RecreationRecreated && row.State != executordb.RecreationPartial:
		return errRollbackState
	case len(row.Baseline) == 0:
		return errRollbackNoBaseline
	case row.WindowExpiresAt.IsZero() || !now.Before(row.WindowExpiresAt):
		return errRollbackWindow
	case plan == nil || plan.Digest() != u.RecoveryPlanDigest:
		return errRollbackRecoveryPlan
	}
	var upd canonical.BatchContainerUpdate
	if err := json.Unmarshal(row.Binding, &upd); err != nil {
		return fmt.Errorf("%w: the recorded binding cannot be read", errRollbackBindingDiffers)
	}
	differs := func(what string) error { return fmt.Errorf("%w: %s", errRollbackBindingDiffers, what) }
	if u.Form != upd.Form || u.Project != upd.Project || u.SourceDigest != upd.SourceDigest ||
		u.WorkingDirHash != upd.WorkingDirHash || u.ConfigFilesHash != upd.ConfigFilesHash {
		return differs("unit or source")
	}
	if !jsonEqual(u.Dependencies, upd.Dependencies) {
		return differs("dependencies")
	}
	if len(u.Images) != len(row.Images) {
		return differs("images")
	}
	for i, img := range u.Images {
		ri := row.Images[i]
		if img.Rollback == nil || img.Service != ri.Service || img.Repository != ri.Repository ||
			img.OldTag != ri.NewTag || img.NewTag != ri.OldTag ||
			img.Rollback.PriorImageID != ri.PriorImageID || img.Rollback.RetainedTag != ri.RetainedTag ||
			img.Rollback.RetainedReference != ri.RetainedReference {
			return differs("image " + ri.Service)
		}
	}
	var want []canonical.ContainerUpdateTarget
	present := map[string]bool{}
	for _, c := range row.Containers {
		if c.Status == executordb.ContainerMissing || slices.IndexFunc(row.Images, func(ri executordb.RecreationImage) bool { return ri.Service == c.Service }) < 0 {
			continue
		}
		present[c.Service] = true
		want = append(want, canonical.ContainerUpdateTarget{Service: c.Service, ContainerID: c.IDAfter, ContainerName: c.Name,
			ImageID: c.ImageAfter, RunningReference: c.ReferenceAfter, ConfigurationDigest: c.ConfigAfter})
	}
	sortTargets := func(ts []canonical.ContainerUpdateTarget) {
		sort.Slice(ts, func(i, j int) bool {
			if ts[i].Service != ts[j].Service {
				return ts[i].Service < ts[j].Service
			}
			return ts[i].ContainerID < ts[j].ContainerID
		})
	}
	got := slices.Clone(u.Targets)
	sortTargets(got)
	sortTargets(want)
	if !jsonEqual(got, want) {
		return differs("targets")
	}
	for _, img := range u.Images {
		if !present[img.Service] {
			// No target left: every container of the service must be
			// recorded missing, and the row must have seen one.
			seen := slices.ContainsFunc(row.Containers, func(c executordb.RecreationContainer) bool { return c.Service == img.Service })
			if !seen {
				return differs("service " + img.Service + " without a recorded container")
			}
		}
	}
	return nil
}

func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// checkRollbackMember checks a rollback member against the executor's
// own row and recovery plan, at the executor's clock.
func (s *Service) checkRollbackMember(m canonical.BatchMember, hostID string) error {
	if m.ContainerUpdate == nil || m.ContainerUpdate.Kind != canonical.ContainerUpdateKindRollback {
		return nil
	}
	u := *m.ContainerUpdate
	row, err := s.db.GetContainerRecreation(u.RollbackOf)
	if err != nil {
		return errRollbackNoRow
	}
	var plan *executordb.RecoveryPlan
	if p, err := s.db.ContainerRecoveryPlan(row.HostID, row.Unit); err == nil {
		plan = &p
	}
	return checkRollbackSource(u, row, plan, hostID, s.clock())
}
