// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Container recreation RPCs (ADR 0006 P2-04/P2-05, container update plan
// cu03, R11 to R13, Q8, Q19).
//
//   - ListContainerRecreations (server, admin): sanitized rows. The
//     recreation definition, the baseline, the frozen binding as a whole
//     and the host key never leave the executor; only the values a
//     rollback binding must equal and the unit's current recovery plan.
//   - Set/ClearContainerRecoveryPlan (admin only): the recovery plan
//     record a rollback binds by digest.
//   - ResolveContainerRecreation (server, admin): a server call needs the
//     executor's privileged session. It reads its evidence from the
//     executor's own runs table, never from the request, and moves only an
//     uncertain row, never to recreated.

// Request limits of the recovery plan RPCs; executordb enforces the same
// limits again when it stores the record.
const (
	// maxRecoveryUnitBytes bounds a unit name (Compose project or
	// container name).
	maxRecoveryUnitBytes = 255
	// maxRecoveryReferenceBytes bounds a recovery plan's free-text
	// reference.
	maxRecoveryReferenceBytes = 2048
)

// Resolve refusals. Each leaves the row as it is.
var (
	errResolveSession   = status.Error(codes.FailedPrecondition, "resolve_refused: a privileged session is required")
	errResolveNotRow    = status.Error(codes.NotFound, "resolve_refused: no container recreation for the execution")
	errResolveState     = status.Error(codes.FailedPrecondition, "resolve_refused: only an uncertain row is resolved")
	errResolveRunOpen   = status.Error(codes.FailedPrecondition, "resolve_refused: the row's run is not finished or its target is still held")
	errResolveNoPreview = status.Error(codes.FailedPrecondition, "resolve_refused: no finished durable docker.update_preview run of the row's host with that execution ID")
	errResolveReleased  = status.Error(codes.FailedPrecondition, "resolve_refused: the preview's result was released or is empty")
	errResolveTooEarly  = status.Error(codes.FailedPrecondition, "resolve_refused: the preview did not start after the row's run finished")
	errResolveEvidence  = status.Error(codes.FailedPrecondition, "resolve_refused: the preview cannot resolve the row; it stays uncertain")
)

// ListContainerRecreations lists sanitized recreation rows of one host, or
// every host, newest first (server and admin role).
func (s *Service) ListContainerRecreations(_ context.Context, in *pb.ListContainerRecreationsRequest) (*pb.ListContainerRecreationsResponse, error) {
	host := in.GetHostId()
	if host != "" && !canonical.ValidHostID(host) {
		return nil, status.Error(codes.InvalidArgument, "invalid host ID")
	}
	// The full rows: recreationInfo reads only whether a baseline exists
	// and never renders the definition or the baseline.
	rows, err := s.db.ListContainerRecreations(host)
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "list_container_recreations", "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: container recreations unavailable")
	}
	plans := recoveryPlanCache{s: s, plans: map[[2]string]*executordb.RecoveryPlan{}}
	out := &pb.ListContainerRecreationsResponse{}
	for _, row := range rows {
		plan, err := plans.get(row.HostID, row.Unit)
		if err != nil {
			return nil, err
		}
		out.Recreations = append(out.Recreations, recreationInfo(row, plan))
	}
	return out, nil
}

// recoveryPlanCache reads each unit's recovery plan once per answer.
type recoveryPlanCache struct {
	s     *Service
	plans map[[2]string]*executordb.RecoveryPlan
}

func (c recoveryPlanCache) get(hostID, unit string) (*executordb.RecoveryPlan, error) {
	k := [2]string{hostID, unit}
	if p, ok := c.plans[k]; ok {
		return p, nil
	}
	p, err := c.s.recoveryPlan(hostID, unit)
	if err != nil {
		return nil, err
	}
	c.plans[k] = p
	return p, nil
}

// recoveryPlan returns the unit's current recovery plan, nil when none is
// recorded.
func (s *Service) recoveryPlan(hostID, unit string) (*executordb.RecoveryPlan, error) {
	p, err := s.db.ContainerRecoveryPlan(hostID, unit)
	if errors.Is(err, executordb.ErrNoRecoveryPlan) {
		return nil, nil
	}
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "container_recovery_plan", "host", hostID, "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: recovery plan unavailable")
	}
	return &p, nil
}

// recreationInfo renders a row for the socket: identity, state, window,
// verdict, the images and current incarnations a rollback binds, the
// binding's source values and dependencies, and the recovery plan. The
// recreation definition, the baseline (only whether one exists), the
// batch digest, the host key and the binding as a whole are left out.
func recreationInfo(row executordb.ContainerRecreation, plan *executordb.RecoveryPlan) *pb.ContainerRecreationInfo {
	info := &pb.ContainerRecreationInfo{
		ExecutionId: row.ExecutionID, MemberId: row.MemberID, Kind: row.Kind, RollbackOf: row.RollbackOf,
		HostId: row.HostID, Form: row.Form, Unit: row.Unit, State: row.State,
		WindowExpiresAtUnix: unixOrZero(row.WindowExpiresAt), CreatedAtUnix: unixOrZero(row.CreatedAt),
		UpdatedAtUnix: unixOrZero(row.UpdatedAt), HasBaseline: len(row.Baseline) > 0,
		Verdict: &pb.ContainerRecreationVerdict{Judged: row.Verdict.Judged, Passed: row.Verdict.Passed,
			Findings: append([]string{}, row.Verdict.Findings...)},
	}
	// The binding is the row's own frozen update binding; a row whose
	// binding cannot be read lists without its binding values.
	var u canonical.BatchContainerUpdate
	if json.Unmarshal(row.Binding, &u) != nil {
		u = canonical.BatchContainerUpdate{}
	}
	info.SourceDigest, info.WorkingDirHash, info.ConfigFilesHash = u.SourceDigest, u.WorkingDirHash, u.ConfigFilesHash
	for i, img := range row.Images {
		ri := &pb.ContainerRecreationImage{Service: img.Service, Repository: img.Repository, OldTag: img.OldTag, NewTag: img.NewTag,
			NewPlatformDigest: img.NewPlatformDigest, PriorImageId: img.PriorImageID,
			RetainedTag: strings.TrimPrefix(img.RetainedTag, retainedRepository+":"), RetainedReference: img.RetainedReference}
		if i < len(u.Images) && u.Images[i].Service == img.Service {
			b := u.Images[i]
			ri.Platform, ri.PolicyVersion, ri.PolicyDigest, ri.MajorChange = b.Platform, b.PolicyVersion, b.PolicyDigest, b.MajorChange
		}
		info.Images = append(info.Images, ri)
	}
	for _, c := range row.Containers {
		info.Targets = append(info.Targets, &pb.ContainerRecreationTarget{Service: c.Service, Replica: c.Replica,
			ContainerName: c.Name, Status: c.Status, ContainerId: c.IDAfter, ImageId: c.ImageAfter,
			RunningReference: c.ReferenceAfter, ConfigurationDigest: c.ConfigAfter})
	}
	for _, d := range u.Dependencies {
		pd := &pb.ContainerRecreationDependency{Service: d.Service, Relation: d.Relation, RestartOnUpdate: d.RestartOnUpdate}
		for _, m := range d.Containers {
			pd.Containers = append(pd.Containers, &pb.ContainerRecreationDependencyMember{ContainerId: m.ContainerID,
				ContainerName: m.ContainerName, ConfigurationDigest: m.ConfigurationDigest})
		}
		info.Dependencies = append(info.Dependencies, pd)
	}
	if plan != nil {
		info.RecoveryPlan = recoveryPlanInfo(*plan)
	}
	return info
}

func recoveryPlanInfo(p executordb.RecoveryPlan) *pb.ContainerRecoveryPlanInfo {
	return &pb.ContainerRecoveryPlanInfo{HostId: p.HostID, Unit: p.Unit, Kind: p.Kind, Reference: p.Reference, Actor: p.Actor,
		Version: p.Version, RecordedAtUnix: unixOrZero(p.RecordedAt), Digest: p.Digest()}
}

// recoveryPlanAdmin returns the local admin caller's name. It is defense
// in depth behind the role table: the handlers refuse every other role.
func recoveryPlanAdmin(ctx context.Context) (string, error) {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "recovery plan: no authenticated caller")
	}
	if c.Role != peercred.RoleAdmin {
		return "", status.Error(codes.PermissionDenied, "recovery plan: local admin only")
	}
	return callerName(ctx), nil
}

// validRecoveryField reports whether s is non-blank, within limit bytes,
// valid UTF-8 and free of control characters.
func validRecoveryField(s string, limit int) bool {
	if strings.TrimSpace(s) == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

// SetContainerRecoveryPlan records a unit's recovery plan with the next
// version (admin role): exactly one of a reference or the explicit
// no_persistent_data declaration. The reference is never logged.
func (s *Service) SetContainerRecoveryPlan(ctx context.Context, in *pb.SetContainerRecoveryPlanRequest) (*pb.SetContainerRecoveryPlanResponse, error) {
	who, err := recoveryPlanAdmin(ctx)
	if err != nil {
		return nil, err
	}
	host, unit := in.GetHostId(), in.GetUnit()
	if !canonical.ValidHostID(host) || !validRecoveryField(unit, maxRecoveryUnitBytes) {
		return nil, status.Error(codes.InvalidArgument, "invalid host ID or unit")
	}
	var kind, reference string
	switch p := in.GetPlan().(type) {
	case *pb.SetContainerRecoveryPlanRequest_Reference:
		if !validRecoveryField(p.Reference, maxRecoveryReferenceBytes) {
			return nil, status.Errorf(codes.InvalidArgument,
				"the reference must be printable text of 1 to %d bytes", maxRecoveryReferenceBytes)
		}
		kind, reference = executordb.RecoveryPlanReference, p.Reference
	case *pb.SetContainerRecoveryPlanRequest_NoPersistentData:
		if !p.NoPersistentData {
			return nil, status.Error(codes.InvalidArgument, "no_persistent_data must be declared explicitly")
		}
		kind = executordb.RecoveryNoData
	default:
		return nil, status.Error(codes.InvalidArgument, "a recovery plan needs either a reference or the explicit no_persistent_data declaration")
	}
	plan, err := s.db.SetContainerRecoveryPlan(host, unit, kind, reference, who)
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "set_container_recovery_plan", "host", host, "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: the recovery plan was not recorded")
	}
	s.log.Info("audit", "kind", "container_recovery_plan_set", "by", who, "host", host, "unit", unit,
		"plan_kind", kind, "version", plan.Version, "digest", plan.Digest())
	return &pb.SetContainerRecoveryPlanResponse{Plan: recoveryPlanInfo(plan)}, nil
}

// ClearContainerRecoveryPlan removes a unit's recovery plan (admin role);
// a rollback bound to it then fails revalidation.
func (s *Service) ClearContainerRecoveryPlan(ctx context.Context, in *pb.ClearContainerRecoveryPlanRequest) (*pb.ClearContainerRecoveryPlanResponse, error) {
	who, err := recoveryPlanAdmin(ctx)
	if err != nil {
		return nil, err
	}
	host, unit := in.GetHostId(), in.GetUnit()
	if !canonical.ValidHostID(host) || !validRecoveryField(unit, maxRecoveryUnitBytes) {
		return nil, status.Error(codes.InvalidArgument, "invalid host ID or unit")
	}
	if err := s.db.ClearContainerRecoveryPlan(host, unit); err != nil {
		if errors.Is(err, executordb.ErrNoRecoveryPlan) {
			return nil, status.Error(codes.NotFound, "no recovery plan recorded for the unit")
		}
		s.log.Error("audit", "kind", "store_error", "op", "clear_container_recovery_plan", "host", host, "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: the recovery plan was not cleared")
	}
	s.log.Info("audit", "kind", "container_recovery_plan_cleared", "by", who, "host", host, "unit", unit)
	return &pb.ClearContainerRecoveryPlanResponse{}, nil
}

// resolveCaller admits the local admin, and the server only while the
// executor's privileged session is active.
func (s *Service) resolveCaller(ctx context.Context) (string, error) {
	c, ok := peercred.CallerFrom(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "resolve: no authenticated caller")
	}
	switch c.Role {
	case peercred.RoleAdmin:
	case peercred.RoleServer:
		if active, _ := s.auth.Session(); !active {
			return "", errResolveSession
		}
	default:
		return "", status.Error(codes.PermissionDenied, "resolve: server or local admin only")
	}
	if err := s.checkNotRecovering(); err != nil {
		return "", err
	}
	return callerName(ctx), nil
}

// ResolveContainerRecreation resolves an uncertain row from a retained
// docker.update_preview run of its host (R11, Q19). The preview must be a
// finished durable classic run of that action whose result is still kept,
// started after the row's run finished and its hold ended. Every frozen
// container unchanged gives not_recreated; anything else that matches
// gives partial with the preview's incarnations. A unit the preview cannot
// match, or reports without complete facts, leaves the row uncertain.
// Nothing runs on the host and the window is not extended.
func (s *Service) ResolveContainerRecreation(ctx context.Context, in *pb.ResolveContainerRecreationRequest) (*pb.ResolveContainerRecreationResponse, error) {
	who, err := s.resolveCaller(ctx)
	if err != nil {
		return nil, err
	}
	exec, previewID := in.GetExecutionId(), in.GetPreviewExecutionId()
	if !validExecutionID(exec) || !validExecutionID(previewID) || exec == previewID {
		return nil, status.Error(codes.InvalidArgument, "resolve: malformed execution IDs")
	}
	row, err := s.db.GetContainerRecreation(exec)
	if errors.Is(err, executordb.ErrNoRecreation) {
		return nil, errResolveNotRow
	}
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "get_container_recreation", "execution", exec, "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: container recreation unavailable")
	}
	if row.State != executordb.RecreationUncertain {
		return nil, errResolveState
	}
	own, err := s.db.GetRun(row.ExecutionID, row.HostID)
	if err != nil || own.State != executordb.RunFinished || own.FinishedAt.IsZero() {
		return nil, errResolveRunOpen
	}
	for _, h := range s.HeldBatchTargets() {
		if h.HostID == row.HostID && h.ExecutionID == row.ExecutionID {
			return nil, errResolveRunOpen
		}
	}
	// The evidence comes from the runs table only: an attached run has no
	// row there, so it can never resolve.
	pv, err := s.db.GetRun(previewID, row.HostID)
	if err != nil || !isUpdatePreview(pv.ActionID) || pv.MemberID != "" || pv.State != executordb.RunFinished ||
		pv.Class != hostrun.ClassSuccess {
		return nil, errResolveNoPreview
	}
	if pv.Released || len(pv.Result) == 0 {
		return nil, errResolveReleased
	}
	if !pv.CreatedAt.After(own.FinishedAt) {
		return nil, errResolveTooEarly
	}
	var u canonical.BatchContainerUpdate
	if err := json.Unmarshal(row.Binding, &u); err != nil {
		return nil, errResolveEvidence
	}
	preview, err := dockerhost.ParseUpdatePreview(pv.Result)
	if err != nil || preview.Status != dockerhost.PreviewOK {
		return nil, errResolveEvidence
	}
	state, containers, ok := resolveFromPreview(row, u, preview)
	if !ok {
		s.log.Info("audit", "kind", "container_recreation_unresolved", "by", who, "execution", exec, "preview", previewID, "host", row.HostID)
		return nil, errResolveEvidence
	}
	v := executordb.RecreationVerdict{Findings: boundFindings(append(append([]string{}, row.Verdict.Findings...),
		fmt.Sprintf("resolved as %s from docker.update_preview %s; a preview gives no verdict", state, previewID)))}
	if err := s.db.ResolveContainerRecreation(exec, state, containers, v); err != nil {
		if errors.Is(err, executordb.ErrRecreationState) {
			return nil, status.Error(codes.Aborted, "resolve: the row changed concurrently")
		}
		s.log.Error("audit", "kind", "store_error", "op", "resolve_container_recreation", "execution", exec, "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error: the resolve was not recorded")
	}
	s.log.Info("audit", "kind", "container_recreation_resolved", "by", who, "execution", exec, "preview", previewID,
		"host", row.HostID, "unit", row.Unit, "state", state)
	got, err := s.db.GetContainerRecreation(exec)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "storage_error: container recreation unavailable")
	}
	plan, err := s.recoveryPlan(got.HostID, got.Unit)
	if err != nil {
		return nil, err
	}
	return &pb.ResolveContainerRecreationResponse{Recreation: recreationInfo(got, plan)}, nil
}

// resolveFromPreview matches the row's frozen containers (its binding's
// targets) against the preview's unit. ok is false when the preview has no
// unit with complete facts for the row. A frozen container the preview
// shows with the same ID and identical facts is unchanged; one with the
// same service and name but another ID is recreated; one not shown is
// missing; a preview container of a frozen service that matches none is a
// new incarnation. The state is not_recreated only when every frozen
// container is unchanged and nothing new exists, otherwise partial.
func resolveFromPreview(row executordb.ContainerRecreation, u canonical.BatchContainerUpdate, p dockerhost.UpdatePreview) (string, []executordb.RecreationContainer, bool) {
	if len(u.Targets) == 0 {
		return "", nil, false
	}
	var unit *dockerhost.PreviewUnit
	for i := range p.Units {
		pu := &p.Units[i]
		switch {
		case u.Form == canonical.ContainerUpdateFormCompose && pu.Form == "compose" && pu.Project == u.Project && u.Project != "":
			unit = pu
		case u.Form == canonical.ContainerUpdateFormAlone && pu.Form == "standalone" && pu.HasFacts() &&
			len(pu.Targets) == 1 && pu.Targets[0].ContainerName == u.Targets[0].ContainerName:
			unit = pu
		}
		if unit != nil {
			break
		}
	}
	if unit == nil || !unit.HasFacts() {
		return "", nil, false
	}
	// Replica numbers come from the baseline when the row has one.
	replicas := map[string]string{}
	var baseline []snapshotEntry
	if len(row.Baseline) > 0 && json.Unmarshal(row.Baseline, &baseline) == nil {
		for _, b := range baseline {
			replicas[b.ID] = b.Replica
		}
	}
	frozen := map[string]bool{}
	for _, t := range u.Targets {
		frozen[t.Service] = true
	}
	used := make([]bool, len(unit.Targets))
	find := func(match func(dockerhost.PreviewTarget) bool) (dockerhost.PreviewTarget, bool) {
		for i, pt := range unit.Targets {
			if !used[i] && match(pt) {
				used[i] = true
				return pt, true
			}
		}
		return dockerhost.PreviewTarget{}, false
	}
	state := executordb.RecreationNotRecreated
	out := make([]executordb.RecreationContainer, 0, len(u.Targets))
	for _, t := range u.Targets {
		c := executordb.RecreationContainer{Service: t.Service, Replica: replicas[t.ContainerID], Name: t.ContainerName,
			IDBefore: t.ContainerID, ReferenceBefore: t.RunningReference, ConfigBefore: t.ConfigurationDigest, ImageBefore: t.ImageID,
			Status: executordb.ContainerMissing}
		pt, found := find(func(pt dockerhost.PreviewTarget) bool { return pt.ContainerID == t.ContainerID })
		if found {
			c.Status = executordb.ContainerUnchanged
		} else {
			pt, found = find(func(pt dockerhost.PreviewTarget) bool {
				return pt.Service == t.Service && pt.ContainerName == t.ContainerName
			})
			if found {
				c.Status = executordb.ContainerRecreated
			}
		}
		if found {
			c.IDAfter, c.ReferenceAfter, c.ConfigAfter, c.ImageAfter = pt.ContainerID, pt.RunningReference, pt.ConfigurationDigest, pt.ImageID
		}
		if !found || pt.ContainerID != t.ContainerID || pt.Service != t.Service || pt.ImageID != t.ImageID ||
			pt.RunningReference != t.RunningReference || pt.ConfigurationDigest != t.ConfigurationDigest {
			state = executordb.RecreationPartial
		}
		out = append(out, c)
	}
	for i, pt := range unit.Targets {
		if used[i] || !frozen[pt.Service] {
			continue
		}
		state = executordb.RecreationPartial
		out = append(out, executordb.RecreationContainer{Service: pt.Service, Name: pt.ContainerName, IDAfter: pt.ContainerID,
			ReferenceAfter: pt.RunningReference, ConfigAfter: pt.ConfigurationDigest, ImageAfter: pt.ImageID,
			Status: executordb.ContainerRecreated})
	}
	return state, out, true
}
