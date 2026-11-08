// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Container update and rollback members (ADR 0006 P2-05, container update
// plan cu04). A docker.compose_update 2.0.0 member binds one Compose
// project with its frozen service set; a docker.compose_rollback 1.0.0
// member binds the rollback of one recorded update. Both bindings are
// built here, by the server, from one named docker.update_preview run of
// the member's host that is the newest finished preview of that host and
// at most maxPreviewBindingAge old. Nothing of the binding comes from the
// request except the selection (project, services, target tags and the
// tag policy the executor re-checks). The parameter document is the
// rendering of the binding (Decision 3); the executor renders it again and
// refuses a member whose parameters differ.

const (
	// composeUpdateAction and composeRollbackAction are the container
	// mutations a batch may carry, at exactly these module versions (the
	// ones the executor pins).
	composeUpdateAction    = "docker.compose_update"
	composeUpdateVersion   = "2.0.0"
	composeRollbackAction  = "docker.compose_rollback"
	composeRollbackVersion = "1.0.0"
	// updatePreviewAction is the read-only source of every binding.
	updatePreviewAction = "docker.update_preview"
	// maxPreviewBindingAge is how old the docker.update_preview run a
	// container update or rollback member is bound to may be, counted from
	// the run's start (container update plan cu02, UpdateBindings: "at most
	// maxContainerBindingAge old").
	maxPreviewBindingAge = maxContainerBindingAge
	// maxContainerServices bounds the services selected for one unit (the
	// canonical binding allows at most 20 image entries).
	maxContainerServices = 20
)

// Errors of container members. Each is wrapped in a BatchInputError that
// names the member, so callers can show the reason and branch on it.
var (
	// ErrBatchPreviewMissing: the named preview is not a successful,
	// finished docker.update_preview run of the member's host.
	ErrBatchPreviewMissing = errors.New("no finished docker.update_preview run of this host with that ID; run a preview first")
	// ErrBatchPreviewStale: the preview is older than the binding allows,
	// started in the future, or a newer preview of the host exists.
	ErrBatchPreviewStale = errors.New("the update preview is not fresh; run a new docker.update_preview and plan from it")
	// ErrBatchPreviewUnit: the preview does not offer the requested unit,
	// service or tag as an update or rollback.
	ErrBatchPreviewUnit = errors.New("the update preview does not offer this change")
	// ErrBatchRollbackSource: the recorded update cannot be rolled back
	// (no row, wrong host, state, window, baseline or recovery plan), or
	// the host no longer matches it.
	ErrBatchRollbackSource = errors.New("the recorded container update cannot be rolled back")
)

// ContainerUpdateSpec selects one Compose update unit of a
// docker.compose_update member.
type ContainerUpdateSpec struct {
	// PreviewExecutionID is the docker.update_preview run the binding is
	// built from. It must be the newest finished preview of the host.
	PreviewExecutionID string
	// Project is the Compose project.
	Project string
	// Services are the recreated services. Their dependencies are derived
	// from the preview, never requested.
	Services []ContainerServiceSpec
}

// ContainerServiceSpec is one recreated service and its target tag.
type ContainerServiceSpec struct {
	Service string
	// NewTag is the explicit target tag; empty keeps the running tag (a
	// same-tag digest refresh). The preview must have resolved it.
	NewTag string
	// MajorChange, PolicyVersion and PolicyDigest are required exactly
	// when the tag changes; the executor compares them with its own tag
	// policy and refuses a mismatch.
	MajorChange   bool
	PolicyVersion string
	PolicyDigest  string
}

// ContainerRollbackSpec selects the rollback of one recorded update.
type ContainerRollbackSpec struct {
	// PreviewExecutionID is the docker.update_preview run that shows the
	// host still matches the recorded update. It must be the newest
	// finished preview of the host.
	PreviewExecutionID string
	// RollbackOf is the execution ID of the recorded docker.compose_update.
	RollbackOf string
}

// RecreationLister lists the executor's container recreation rows (the
// server connection's ListContainerRecreations).
type RecreationLister interface {
	ListContainerRecreations(ctx context.Context, in *pb.ListContainerRecreationsRequest, opts ...grpc.CallOption) (*pb.ListContainerRecreationsResponse, error)
}

var executionIDRe = regexp.MustCompile(`^[0-9a-f-]{36}$`)

// containerInput is a BatchInputError for member n that unwraps to cause.
func containerInput(n int, cause error, format string, args ...any) error {
	return &BatchInputError{Reason: fmt.Sprintf("member %d: ", n) + fmt.Sprintf(format, args...), Err: cause}
}

// isContainerMutation reports whether actionID is a container update or
// rollback (the four canonical action IDs).
func isContainerMutation(actionID string) bool { return canonical.IsContainerUpdateAction(actionID) }

// planContainerMember builds the binding of a container mutation member.
// units counts container members per host and unit, so one batch never
// recreates the same unit twice.
func (b *Batches) planContainerMember(ctx context.Context, a actions.Action, spec BatchMemberSpec, units map[string]int, n int) (canonical.BatchContainerUpdate, error) {
	if len(spec.Params) > 0 {
		return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchPreviewUnit, "%s takes no parameters; a Compose update or rollback is bound from the update preview", a.ID)
	}
	var (
		u       canonical.BatchContainerUpdate
		err     error
		project string
	)
	switch {
	case a.ID == composeUpdateAction && a.Version == composeUpdateVersion:
		if spec.Update == nil || spec.Rollback != nil {
			return u, containerInput(n, ErrBatchPreviewUnit, "a Compose update needs the project and services to update, and nothing else")
		}
		project = spec.Update.Project
		u, err = b.updateBinding(ctx, spec.HostID, *spec.Update, n)
	case a.ID == composeRollbackAction && a.Version == composeRollbackVersion:
		if spec.Rollback == nil || spec.Update != nil {
			return u, containerInput(n, ErrBatchPreviewUnit, "a Compose rollback needs the recorded update to roll back, and nothing else")
		}
		u, err = b.rollbackBinding(ctx, spec.HostID, *spec.Rollback, n)
		project = u.Project
	default:
		// docker.update and docker.rollback (standalone, cu05) and any
		// other version have no executor that runs them.
		return u, containerInput(n, ErrBatchPreviewUnit, "%s %s is not available in a batch", a.ID, a.Version)
	}
	if err != nil {
		return canonical.BatchContainerUpdate{}, err
	}
	key := spec.HostID + "\x00" + project
	if first, dup := units[key]; dup {
		return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchPreviewUnit,
			"Compose project %q on %s is already recreated by member %d; one batch changes a unit once", project, spec.HostID, first)
	}
	units[key] = n
	return u, nil
}

// freshPreview loads the named preview of hostID and checks that it is the
// host's newest successful preview, of the shipped preview artifact, and
// started at most maxPreviewBindingAge before now.
func (b *Batches) freshPreview(ctx context.Context, hostID, id string, n int) (dockerhost.UpdatePreview, error) {
	if !executionIDRe.MatchString(id) {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewMissing, "name the docker.update_preview run to plan from")
	}
	pa, ok := actions.Lookup(updatePreviewAction)
	if !ok {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewMissing, "docker.update_preview is not in the catalog")
	}
	var (
		action, version, sha, state, class string
		result                             []byte
		started, finished                  sql.NullInt64
	)
	err := b.db.QueryRowContext(ctx, `SELECT e.action_id, e.module_version, e.artifact_sha256, h.state, h.class, h.result, h.started_at, h.finished_at
		FROM execution_hosts h JOIN executions e ON e.id = h.execution_id WHERE e.id = ? AND h.host_id = ?`, id, hostID).
		Scan(&action, &version, &sha, &state, &class, &result, &started, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewMissing, "%v", ErrBatchPreviewMissing)
	}
	if err != nil {
		return dockerhost.UpdatePreview{}, fmt.Errorf("member %d: load preview %s on %s: %w", n, id, hostID, err)
	}
	if action != pa.ID || version != pa.Version || sha != pa.SHA256() || state != "finished" || class != "success" || len(result) == 0 {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewMissing, "%v", ErrBatchPreviewMissing)
	}
	now := b.now()
	if !started.Valid || !finished.Valid {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewStale, "%v (no recorded start)", ErrBatchPreviewStale)
	}
	at := time.Unix(started.Int64, 0)
	if at.After(now) || now.Sub(at) > maxPreviewBindingAge {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewStale, "%v (it must have started at most %s ago)", ErrBatchPreviewStale, maxPreviewBindingAge)
	}
	// A newer successful preview of the host supersedes this one: the plan
	// shown from the older preview is not what the host looks like now.
	var newer int
	if err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
		WHERE e.action_id = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success' AND e.id <> ?
		AND (h.started_at > ? OR (h.started_at = ? AND h.finished_at > ?))`,
		updatePreviewAction, hostID, id, started.Int64, started.Int64, finished.Int64).Scan(&newer); err != nil {
		return dockerhost.UpdatePreview{}, fmt.Errorf("member %d: newer previews of %s: %w", n, hostID, err)
	}
	if newer > 0 {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewStale, "%v (a newer preview of %s exists)", ErrBatchPreviewStale, hostID)
	}
	p, err := dockerhost.ParseUpdatePreview(result)
	if err != nil {
		b.log.Warn("batch preview unreadable", "preview", id, "host", hostID)
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewMissing, "the update preview's result cannot be read")
	}
	if p.Status != dockerhost.PreviewOK {
		return dockerhost.UpdatePreview{}, containerInput(n, ErrBatchPreviewUnit, "the update preview of %s reports %s", hostID, p.Status)
	}
	return p, nil
}

// composeUnit returns the preview's complete Compose unit for project.
func composeUnit(p dockerhost.UpdatePreview, project string, n int) (dockerhost.PreviewUnit, error) {
	i := slices.IndexFunc(p.Units, func(u dockerhost.PreviewUnit) bool { return u.Form == "compose" && u.Project == project })
	if i < 0 {
		return dockerhost.PreviewUnit{}, containerInput(n, ErrBatchPreviewUnit, "the update preview has no Compose project %q", project)
	}
	u := p.Units[i]
	switch u.Reason {
	case "":
		return u, nil
	case dockerhost.PreviewTruncated:
		return u, containerInput(n, ErrBatchPreviewUnit, "Compose project %q was cut off by a preview limit", project)
	default:
		return u, containerInput(n, ErrBatchPreviewUnit, "Compose project %q is unavailable: %s", project, u.Reason)
	}
}

// updateBinding builds a docker.compose_update binding from the preview.
func (b *Batches) updateBinding(ctx context.Context, hostID string, spec ContainerUpdateSpec, n int) (canonical.BatchContainerUpdate, error) {
	p, err := b.freshPreview(ctx, hostID, spec.PreviewExecutionID, n)
	if err != nil {
		return canonical.BatchContainerUpdate{}, err
	}
	unit, err := composeUnit(p, spec.Project, n)
	if err != nil {
		return canonical.BatchContainerUpdate{}, err
	}
	if len(spec.Services) == 0 || len(spec.Services) > maxContainerServices {
		return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchPreviewUnit, "select 1 to %d services of %q", maxContainerServices, spec.Project)
	}
	sel := slices.Clone(spec.Services)
	slices.SortFunc(sel, func(x, y ContainerServiceSpec) int { return strings.Compare(x.Service, y.Service) })
	frozen := map[string]bool{}
	for i, s := range sel {
		if i > 0 && sel[i-1].Service == s.Service {
			return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchPreviewUnit, "service %q is selected twice", s.Service)
		}
		if !unit.Available(s.Service) {
			return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchPreviewUnit, "service %q of %q cannot be updated: %s",
				s.Service, spec.Project, serviceReasons(unit, s.Service))
		}
		frozen[s.Service] = true
	}
	// Namespace sharers are recreated together or not at all (Q12).
	for _, svc := range unit.Services {
		for _, other := range svc.Shares {
			if frozen[svc.Service] != frozen[other] {
				return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchPreviewUnit,
					"services %q and %q share a namespace; select both or neither", svc.Service, other)
			}
		}
	}
	u := canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormCompose,
		SourceDigest: unit.SourceDigest, Project: unit.Project, WorkingDirHash: unit.WorkingDirHash, ConfigFilesHash: unit.ConfigFilesHash,
		Images: []canonical.ContainerUpdateImage{}, Targets: []canonical.ContainerUpdateTarget{},
	}
	for _, s := range sel {
		img, targets, err := updateEntry(unit, s, n)
		if err != nil {
			return canonical.BatchContainerUpdate{}, err
		}
		u.Images = append(u.Images, img)
		u.Targets = append(u.Targets, targets...)
	}
	if u.Dependencies, err = dependencyClosure(unit, frozen, n); err != nil {
		return canonical.BatchContainerUpdate{}, err
	}
	return u, nil
}

// serviceReasons names why a service of the unit cannot get a binding.
func serviceReasons(unit dockerhost.PreviewUnit, svc string) string {
	i := slices.IndexFunc(unit.Services, func(s dockerhost.PreviewService) bool { return s.Service == svc })
	if i < 0 {
		return "no such service"
	}
	s := unit.Services[i]
	if s.Replicas == 0 {
		return "no containers"
	}
	if len(s.Reasons) > 0 {
		return strings.Join(s.Reasons, ", ")
	}
	var why []string
	for _, t := range unit.Targets {
		if t.Service != svc {
			continue
		}
		for _, im := range unit.Images {
			if im.ImageID == t.ImageID && im.RunningReference == t.RunningReference && im.Reason != "" && !slices.Contains(why, im.Reason) {
				why = append(why, im.Reason)
			}
		}
	}
	if len(why) == 0 {
		return "unavailable"
	}
	return strings.Join(why, ", ")
}

// updateEntry builds one service's image entry and targets.
func updateEntry(unit dockerhost.PreviewUnit, s ContainerServiceSpec, n int) (canonical.ContainerUpdateImage, []canonical.ContainerUpdateTarget, error) {
	var targets []canonical.ContainerUpdateTarget
	var imageID, ref string
	for _, t := range unit.Targets {
		if t.Service != s.Service {
			continue
		}
		if imageID == "" {
			imageID, ref = t.ImageID, t.RunningReference
		} else if t.ImageID != imageID || t.RunningReference != ref {
			return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit, "the containers of service %q run different images", s.Service)
		}
		targets = append(targets, canonical.ContainerUpdateTarget{Service: t.Service, ContainerID: t.ContainerID, ContainerName: t.ContainerName,
			ImageID: t.ImageID, RunningReference: t.RunningReference, ConfigurationDigest: t.ConfigurationDigest})
	}
	j := slices.IndexFunc(unit.Images, func(im dockerhost.PreviewImage) bool { return im.ImageID == imageID && im.RunningReference == ref })
	if len(targets) == 0 || j < 0 {
		return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit, "service %q has no container with image facts", s.Service)
	}
	im := unit.Images[j]
	newTag := s.NewTag
	if newTag == "" {
		newTag = im.Tag
	}
	k := slices.IndexFunc(im.Resolved, func(r dockerhost.PreviewResolution) bool { return r.Tag == newTag })
	if k < 0 {
		return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit,
			"the preview did not resolve tag %q of service %q; run a preview with that target tag", newTag, s.Service)
	}
	res := im.Resolved[k]
	if res.Reason != "" {
		return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit, "tag %q of service %q is unavailable: %s", newTag, s.Service, res.Reason)
	}
	img := canonical.ContainerUpdateImage{Service: s.Service, Repository: im.Repository, Platform: im.Platform, OldTag: im.Tag, NewTag: newTag,
		OldDigests: slices.Clone(im.OldDigests), NewIndexDigest: res.IndexDigest, NewPlatformDigest: res.PlatformDigest, OldImageID: im.ImageID}
	if newTag == im.Tag {
		if s.MajorChange || s.PolicyVersion != "" || s.PolicyDigest != "" {
			return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit, "service %q keeps its tag; a tag policy applies only to a tag change", s.Service)
		}
		if slices.Contains(im.OldDigests, res.PlatformDigest) || (res.IndexDigest != "" && slices.Contains(im.OldDigests, res.IndexDigest)) {
			return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit, "service %q is current: tag %q has no new digest", s.Service, newTag)
		}
		return img, targets, nil
	}
	if s.PolicyVersion == "" || s.PolicyDigest == "" {
		return canonical.ContainerUpdateImage{}, nil, containerInput(n, ErrBatchPreviewUnit, "the tag change of service %q needs its tag policy version and digest", s.Service)
	}
	img.PolicyVersion, img.PolicyDigest, img.MajorChange = s.PolicyVersion, s.PolicyDigest, s.MajorChange
	return img, targets, nil
}

// dependencyClosure derives the bound dependency set exactly as the
// docker.compose_update 2.0.0 script recomputes it: the transitive closure
// of depends_on, links and volumes_from in both directions, "requires"
// before "required_by", restart_on_update when a required_by service
// restarts on a frozen one. Every dependency must have containers.
func dependencyClosure(unit dockerhost.PreviewUnit, frozen map[string]bool, n int) ([]canonical.ContainerUpdateDependency, error) {
	graph := map[string][]string{}
	reverse := map[string][]string{}
	restarts := map[string]map[string]bool{}
	for _, s := range unit.Services {
		restarts[s.Service] = map[string]bool{}
		for _, d := range s.Depends {
			graph[s.Service] = append(graph[s.Service], d.Service)
			reverse[d.Service] = append(reverse[d.Service], s.Service)
			if d.Restart {
				restarts[s.Service][d.Service] = true
			}
		}
	}
	reach := func(edges map[string][]string) map[string]bool {
		seen := map[string]bool{}
		var todo []string
		for s := range frozen {
			todo = append(todo, s)
		}
		for len(todo) > 0 {
			x := todo[len(todo)-1]
			todo = todo[:len(todo)-1]
			for _, y := range edges[x] {
				if !seen[y] {
					seen[y] = true
					todo = append(todo, y)
				}
			}
		}
		return seen
	}
	requires, requiredBy := reach(graph), reach(reverse)
	var names []string
	for s := range requires {
		if !frozen[s] {
			names = append(names, s)
		}
	}
	for s := range requiredBy {
		if !frozen[s] && !requires[s] {
			names = append(names, s)
		}
	}
	slices.Sort(names)
	deps := []canonical.ContainerUpdateDependency{}
	for _, name := range names {
		d := canonical.ContainerUpdateDependency{Service: name, Relation: canonical.ContainerDependencyRequires}
		if !requires[name] {
			d.Relation = canonical.ContainerDependencyRequiredBy
			for f := range frozen {
				if restarts[name][f] {
					d.RestartOnUpdate = true
				}
			}
		}
		for _, t := range unit.Targets {
			if t.Service == name {
				d.Containers = append(d.Containers, canonical.ContainerDependencyMember{ContainerID: t.ContainerID,
					ContainerName: t.ContainerName, ConfigurationDigest: t.ConfigurationDigest})
			}
		}
		if len(d.Containers) == 0 {
			return nil, containerInput(n, ErrBatchPreviewUnit, "dependency %q has no container; it would be created outside the bound set", name)
		}
		slices.SortFunc(d.Containers, func(x, y canonical.ContainerDependencyMember) int {
			return strings.Compare(x.ContainerID, y.ContainerID)
		})
		deps = append(deps, d)
	}
	return deps, nil
}

// rollbackBinding builds a docker.compose_rollback binding from the
// executor's recreation row of the recorded update, after a fresh preview
// shows that the host still runs exactly what that update left.
func (b *Batches) rollbackBinding(ctx context.Context, hostID string, spec ContainerRollbackSpec, n int) (canonical.BatchContainerUpdate, error) {
	if b.recreations == nil {
		return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchRollbackSource, "container rollbacks are not available: the executor's recreation list is not connected")
	}
	if !executionIDRe.MatchString(spec.RollbackOf) {
		return canonical.BatchContainerUpdate{}, containerInput(n, ErrBatchRollbackSource, "name the recorded update to roll back")
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	list, err := b.recreations.ListContainerRecreations(cctx, &pb.ListContainerRecreationsRequest{HostId: hostID})
	if err != nil {
		return canonical.BatchContainerUpdate{}, fmt.Errorf("member %d: list container recreations of %s: %w", n, hostID, err)
	}
	var row *pb.ContainerRecreationInfo
	for _, r := range list.GetRecreations() {
		if r.GetExecutionId() == spec.RollbackOf {
			row = r
			break
		}
	}
	refuse := func(why string) error {
		return containerInput(n, ErrBatchRollbackSource, "%v: %s", ErrBatchRollbackSource, why)
	}
	now := b.now()
	switch {
	case row == nil || row.GetHostId() != hostID:
		return canonical.BatchContainerUpdate{}, refuse("no recorded update with that ID on " + hostID)
	case row.GetKind() != canonical.ContainerUpdateKindUpdate:
		return canonical.BatchContainerUpdate{}, refuse("a rollback is never rolled back")
	case row.GetForm() != canonical.ContainerUpdateFormCompose:
		return canonical.BatchContainerUpdate{}, refuse("only Compose updates are rolled back")
	case row.GetState() != "recreated" && row.GetState() != "partial":
		return canonical.BatchContainerUpdate{}, refuse("the update is " + row.GetState())
	case !row.GetHasBaseline():
		return canonical.BatchContainerUpdate{}, refuse("no baseline was recorded")
	case row.GetWindowExpiresAtUnix() <= now.Unix():
		return canonical.BatchContainerUpdate{}, refuse("the rollback window is over")
	case row.GetRecoveryPlan() == nil || row.GetRecoveryPlan().GetDigest() == "":
		return canonical.BatchContainerUpdate{}, refuse("no recovery plan is recorded for the unit")
	}
	u := canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindRollback, Form: canonical.ContainerUpdateFormCompose,
		SourceDigest: row.GetSourceDigest(), Project: row.GetUnit(), WorkingDirHash: row.GetWorkingDirHash(), ConfigFilesHash: row.GetConfigFilesHash(),
		RollbackOf: row.GetExecutionId(), RecoveryPlanDigest: row.GetRecoveryPlan().GetDigest(),
		Images: []canonical.ContainerUpdateImage{}, Targets: []canonical.ContainerUpdateTarget{}, Dependencies: []canonical.ContainerUpdateDependency{},
	}
	services := map[string]bool{}
	for _, ri := range row.GetImages() {
		services[ri.GetService()] = true
		u.Images = append(u.Images, canonical.ContainerUpdateImage{Service: ri.GetService(), Repository: ri.GetRepository(), Platform: ri.GetPlatform(),
			OldTag: ri.GetNewTag(), NewTag: ri.GetOldTag(), OldDigests: []string{ri.GetNewPlatformDigest()},
			PolicyVersion: ri.GetPolicyVersion(), PolicyDigest: ri.GetPolicyDigest(), MajorChange: ri.GetMajorChange(),
			Rollback: &canonical.ContainerRollbackImage{PriorImageID: ri.GetPriorImageId(), RetainedTag: ri.GetRetainedTag(), RetainedReference: ri.GetRetainedReference()}})
	}
	for _, t := range row.GetTargets() {
		if t.GetStatus() == "missing" || !services[t.GetService()] {
			continue
		}
		u.Targets = append(u.Targets, canonical.ContainerUpdateTarget{Service: t.GetService(), ContainerID: t.GetContainerId(), ContainerName: t.GetContainerName(),
			ImageID: t.GetImageId(), RunningReference: t.GetRunningReference(), ConfigurationDigest: t.GetConfigurationDigest()})
	}
	slices.SortFunc(u.Targets, func(x, y canonical.ContainerUpdateTarget) int {
		if c := strings.Compare(x.Service, y.Service); c != 0 {
			return c
		}
		return strings.Compare(x.ContainerID, y.ContainerID)
	})
	for _, d := range row.GetDependencies() {
		cd := canonical.ContainerUpdateDependency{Service: d.GetService(), Relation: d.GetRelation(), RestartOnUpdate: d.GetRestartOnUpdate()}
		for _, c := range d.GetContainers() {
			cd.Containers = append(cd.Containers, canonical.ContainerDependencyMember{ContainerID: c.GetContainerId(),
				ContainerName: c.GetContainerName(), ConfigurationDigest: c.GetConfigurationDigest()})
		}
		u.Dependencies = append(u.Dependencies, cd)
	}

	// The fresh preview must show the unit exactly as the update left it:
	// the same source, the same recreated containers and the same
	// dependency containers.
	p, err := b.freshPreview(ctx, hostID, spec.PreviewExecutionID, n)
	if err != nil {
		return canonical.BatchContainerUpdate{}, err
	}
	unit, err := composeUnit(p, u.Project, n)
	if err != nil {
		return canonical.BatchContainerUpdate{}, err
	}
	if unit.SourceDigest != u.SourceDigest || unit.WorkingDirHash != u.WorkingDirHash || unit.ConfigFilesHash != u.ConfigFilesHash {
		return canonical.BatchContainerUpdate{}, refuse("the project's files changed since the update")
	}
	var seen []canonical.ContainerUpdateTarget
	for _, t := range unit.Targets {
		if services[t.Service] {
			seen = append(seen, canonical.ContainerUpdateTarget{Service: t.Service, ContainerID: t.ContainerID, ContainerName: t.ContainerName,
				ImageID: t.ImageID, RunningReference: t.RunningReference, ConfigurationDigest: t.ConfigurationDigest})
		}
	}
	if !slices.Equal(seen, u.Targets) {
		return canonical.BatchContainerUpdate{}, refuse("the updated containers changed since the update")
	}
	for _, d := range u.Dependencies {
		for _, c := range d.Containers {
			i := slices.IndexFunc(unit.Targets, func(t dockerhost.PreviewTarget) bool { return t.ContainerID == c.ContainerID })
			if i < 0 || unit.Targets[i].Service != d.Service || unit.Targets[i].ContainerName != c.ContainerName ||
				unit.Targets[i].ConfigurationDigest != c.ConfigurationDigest {
				return canonical.BatchContainerUpdate{}, refuse("dependency " + d.Service + " changed since the update")
			}
		}
	}
	return u, nil
}

// sameContainerUpdate reports whether two bindings are equal field for
// field (both nil counts as equal).
func sameContainerUpdate(a, b *canonical.BatchContainerUpdate) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}
