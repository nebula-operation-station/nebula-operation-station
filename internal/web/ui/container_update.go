// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Container and Compose update and rollback from the tree (ADR 0006 P2-05,
// container update plan cu04).
//
// GET /inventory/containers shows, per enrolled host, the Compose projects
// of the host's newest usable docker.update_preview run as a tree: project,
// services, containers. Every service that can be updated has its own
// checkbox in a no-JavaScript form; a project has none, so selecting a
// parent never selects anything below it. Everything that cannot be updated
// shows its reason and no checkbox. Recorded updates of the executor's
// recreation list are offered for rollback the same way.
//
// POST /inventory/containers/plan answers the confirmation page: per unit
// and per image, current to approved (repository, tag, index and platform
// digest, platform, the tag policy of a tag change), the configuration and
// source digests, the exact services and containers, the dependencies that
// are affected but not recreated, the stage, the risk floor and the
// rollback state. The bindings shown are built by the planner from the
// shown preview, with the same code that builds the proposal. The confirmed
// POST (PostForm only) rebuilds them, compares the digest of the shown plan
// and proposes one batch: one stage per inventory environment (DEV, QA,
// PROD) with a manual gate between stages and no tolerated failure, so the
// first failed or regressed member stops all undispatched work. Approval
// happens on the batch page with the executor's risk.
//
// Every string from a host, the preview or the executor is untrusted and
// rendered by html/template as text only. The preview carries identities,
// digests and reasons, never an environment value or another secret.

// Limits of the container update controls.
const (
	// ctrMaxHosts bounds the hosts on one page and in one plan.
	ctrMaxHosts = 50
	// ctrMaxSelections bounds the selected services and rollbacks.
	ctrMaxSelections = 100
	// ctrMaxBody bounds the plan form body.
	ctrMaxBody = 64 << 10
	// ctrMaxFieldLen bounds one selection value.
	ctrMaxFieldLen = 300
)

// ContainerTagPolicy compares a running tag with a target tag under the
// executor's tag policy (registrymeta, Q13). CompareTags must fail for tags
// that cannot be compared and for a variant change; the UI then offers no
// tag change. Nil (Options.ContainerTagPolicy) offers same-tag digest
// refreshes only: a tag change needs the policy's version and digest.
type ContainerTagPolicy interface {
	CompareTags(ctx context.Context, repository, oldTag, newTag string) (ContainerTagComparison, error)
}

// ContainerTagComparison is the policy verdict on one tag change.
type ContainerTagComparison struct {
	PolicyVersion string
	PolicyDigest  string
	MajorChange   bool
}

// ctrReasonText explains every reason the preview, the planner or the
// recreation list can report (TestContainerUpdateNamesEveryReason).
var ctrReasonText = map[string]string{
	// Preview statuses.
	dockerhost.PreviewPrepareRequired: "the host is not prepared for container updates; propose docker.update_prepare once",
	"salt_unsafe":                     "the host's update salt is unsafe; repair it on the host and run docker.update_prepare again",
	"tooling_missing":                 "a required host tool is missing (root, docker compose, python3 and curl are needed)",
	"not_root":                        "the preview did not run as root",
	"params_invalid":                  "the preview's parameters were refused",
	"host_unreadable":                 "the host could not be read",
	"result_too_large":                "the preview's result exceeded its limit",
	"internal_error":                  "the preview failed on the host",
	// Unit reasons.
	dockerhost.PreviewTruncated:     "cut off by a preview limit (too many projects or containers)",
	dockerhost.PreviewOverrideDrift: "the running state no longer follows the NOS override (override_drift); bring the project back to its files on the host",
	"project_mismatch":              "the running containers do not match the project's files",
	"unsupported_files":             "the project's Compose files are not supported (too many, too large or unreadable)",
	"dependency_unsupported":        "a dependency of the project is not supported",
	// Service reasons.
	"build_unsupported":  "the service builds its image (build:); building is not supported",
	"config_not_applied": "the applied configuration differs from the files (pending edit, --env-file, --profile or a shell variable)",
	"digest_pinned":      "the image is pinned by digest; it stays pinned",
	"ephemeral_port":     "a published port uses a Docker-chosen host port",
	"mixed_images":       "the replicas of the service run different images",
	"scale_mismatch":     "the service runs another number of replicas than its files say (hand-scaled)",
	"target_not_running": "a replica is stopped or the service is a one-shot service",
	// Image reasons.
	"reference_unsupported": "the image reference is not supported (private registry images arrive with cu06)",
	"old_digest_unknown":    "the local image digest is unknown",
	"platform_unknown":      "the image platform is unknown",
	"tag_unresolved":        "the tag could not be resolved anonymously (private images arrive with cu06)",
	"snapshot_too_large":    "a container's snapshot entry exceeds its limit",
}

// ctrReason explains reason r; an unknown reason is shown as itself.
func ctrReason(r string) string {
	if t, ok := ctrReasonText[r]; ok {
		return t
	}
	return r
}

// Page data.

type containerUpdateData struct {
	// Hosts are the host sections, in inventory order.
	Hosts []ctrHostView
	// More is the number of hosts not shown (over ctrMaxHosts).
	More int
	// TagChanges is false when the server has no tag policy.
	TagChanges bool
	// Selectable is true when at least one checkbox is shown.
	Selectable bool
	// Error is a refusal shown above the tree.
	Error string
	// Confirm is the confirmation page; nil on the tree page.
	Confirm *ctrConfirm
}

type ctrHostView struct {
	ID, Name, Env string
	// Unavailable is why nothing on the host is offered.
	Unavailable string
	// PrepareURL proposes docker.update_prepare (prepare_required).
	PrepareURL string
	// PreviewURL proposes a fresh docker.update_preview.
	PreviewURL string
	// PreviewID and PreviewAge identify the shown preview.
	PreviewID  string
	PreviewAge string
	// PreviewNote is why the preview offers nothing.
	PreviewNote string
	Units       []ctrUnitView
	Rollbacks   []ctrRollbackView
	// RollbackNote is why no rollback list is shown.
	RollbackNote string
}

type ctrUnitView struct {
	// Label is the project name, or "standalone container <name>".
	Label       string
	Unavailable string
	Services    []ctrServiceView
}

type ctrServiceView struct {
	Key, Service string
	Containers   []string
	Image        string
	Unavailable  string
	// Shares are the services that must be selected together with it.
	Shares []string
	// Tags are the target tags the preview resolved, besides the
	// running one; a tag change is offered only with a tag policy.
	Tags []string
	// Refresh is true when the running tag has a new digest.
	Refresh bool
}

type ctrRollbackView struct {
	Key, Unit, State, Window, ExecutionID string
	Images                                []string
	Unavailable                           string
}

// ctrConfirm is the confirmation page.
type ctrConfirm struct {
	Stages []ctrStageView
	Hidden []ctrField
	Digest string
	Count  int
}

type ctrField struct{ Name, Value string }

type ctrStageView struct {
	Num        int
	Name       string
	GateManual bool
	Members    []ctrMemberView
}

type ctrMemberView struct {
	Kind, HostID, HostName, Project string
	PreviewID, PreviewAge           string
	Risk                            string
	TagChange                       bool
	SourceDigest, WorkingDirHash    string
	ConfigFilesHash                 string
	RollbackOf, RecoveryPlanDigest  string
	Images                          []canonical.ContainerUpdateImage
	Targets                         []canonical.ContainerUpdateTarget
	Dependencies                    []canonical.ContainerUpdateDependency
}

// handleContainerUpdates serves the tree page.
func (h *Handler) handleContainerUpdates(w http.ResponseWriter, r *http.Request) {
	if h.containerBatches == nil || h.hosts == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*operationsCallTimeout)
	defer cancel()
	hosts, err := h.hosts(ctx)
	if err != nil {
		h.log.Error("list hosts", "error", err)
		http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
		return
	}
	want := map[string]bool{}
	for _, id := range r.URL.Query()["host"] {
		if len(want) < ctrMaxHosts {
			want[id] = true
		}
	}
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	d := &containerUpdateData{TagChanges: h.containerTagPolicy != nil}
	for _, host := range hosts {
		if len(want) > 0 && !want[host.ID] {
			continue
		}
		if len(d.Hosts) == ctrMaxHosts {
			d.More++
			continue
		}
		v := h.ctrHost(ctx, host, hostKeyStatus(host.ID, pins, pinsUnavailable))
		for _, u := range v.Units {
			for _, s := range u.Services {
				if s.Unavailable == "" {
					d.Selectable = true
				}
			}
		}
		for _, rb := range v.Rollbacks {
			if rb.Unavailable == "" {
				d.Selectable = true
			}
		}
		d.Hosts = append(d.Hosts, v)
	}
	h.render(w, r, pageData{Title: "Container updates", Active: "chart", Content: "container_update", ContainerUpdate: d})
}

// ctrHostGate is why a host offers nothing ("" when it may).
func ctrHostGate(host inventory.Host, keyStatus string) string {
	switch {
	case keyStatus == "blocked":
		return "blocked: the host key changed; re-pin it first"
	case keyStatus == "unavailable":
		return "host enrollment unavailable (executor unreachable)"
	case keyStatus != "pinned":
		return "not enrolled"
	case !executions.HasStageEnvironment(host.Environment):
		return stagedNoEnvironment + "; set its environment in the inventory"
	case len(host.Endpoints) == 0:
		return stagedNoEndpoints
	}
	return ""
}

// ctrHost builds one host section of the tree.
func (h *Handler) ctrHost(ctx context.Context, host inventory.Host, keyStatus string) ctrHostView {
	id := url.QueryEscape(host.ID)
	v := ctrHostView{ID: host.ID, Name: inventoryShownName(host), Env: string(host.Environment),
		PreviewURL: "/operations/new?action=docker.update_preview&host=" + id}
	if v.Unavailable = ctrHostGate(host, keyStatus); v.Unavailable != "" {
		v.PreviewURL = ""
		return v
	}
	p, err := h.containerBatches.LatestContainerPreview(ctx, host.ID)
	switch {
	case err != nil:
		h.log.Error("latest update preview", "host", host.ID, "error", err)
		v.PreviewNote = "the update preview could not be loaded"
	case p.ID == "":
		v.PreviewNote = "no update preview yet; run one to see what can be updated"
	case p.Stale != "":
		v.PreviewID, v.PreviewAge, v.PreviewNote = p.ID, ageText(h.clockNow(), p.StartedAt), p.Stale
	case p.Status != dockerhost.PreviewOK:
		v.PreviewID, v.PreviewAge, v.PreviewNote = p.ID, ageText(h.clockNow(), p.StartedAt), ctrReason(p.Status)
		if p.Status == dockerhost.PreviewPrepareRequired {
			v.PrepareURL = "/operations/new?action=docker.update_prepare&host=" + id
		}
	default:
		v.PreviewID, v.PreviewAge = p.ID, ageText(h.clockNow(), p.StartedAt)
		for _, u := range p.Units {
			v.Units = append(v.Units, ctrUnit(host.ID, u, h.containerTagPolicy != nil))
		}
		if len(v.Units) == 0 {
			v.PreviewNote = "the preview found no Compose project or container"
		}
	}
	rows, err := h.containerBatches.ContainerRecreations(ctx, host.ID)
	if err != nil {
		h.log.Warn("container recreations", "host", host.ID, "error", err)
		v.RollbackNote = "the executor's recreation list could not be read; no rollback is offered"
		return v
	}
	now := h.clockNow()
	for _, row := range rows {
		if row.GetKind() != canonical.ContainerUpdateKindUpdate {
			continue
		}
		v.Rollbacks = append(v.Rollbacks, ctrRollback(host.ID, row, now, v.PreviewID != "" && v.PreviewNote == "" && len(v.Units) > 0))
	}
	return v
}

// ctrUnit builds one unit of the tree.
func ctrUnit(hostID string, u dockerhost.PreviewUnit, tagChanges bool) ctrUnitView {
	if u.Form != "compose" {
		return ctrUnitView{Label: "standalone container " + u.ContainerID,
			Unavailable: "standalone containers are not offered here yet (no batch planner for docker.update)"}
	}
	v := ctrUnitView{Label: u.Project}
	if u.Reason != "" {
		v.Unavailable = ctrReason(u.Reason)
		return v
	}
	for _, s := range u.Services {
		sv := ctrServiceView{Key: hostID + "/" + u.Project + "/" + s.Service, Service: s.Service, Shares: s.Shares}
		var img *dockerhost.PreviewImage
		for _, t := range u.Targets {
			if t.Service != s.Service {
				continue
			}
			sv.Containers = append(sv.Containers, t.ContainerName)
			if img == nil {
				if j := slices.IndexFunc(u.Images, func(im dockerhost.PreviewImage) bool {
					return im.ImageID == t.ImageID && im.RunningReference == t.RunningReference
				}); j >= 0 {
					img = &u.Images[j]
				}
			}
		}
		var reasons []string
		for _, r := range s.Reasons {
			reasons = append(reasons, ctrReason(r))
		}
		switch {
		case s.Replicas == 0:
			reasons = append(reasons, "no running container")
		case img == nil:
			reasons = append(reasons, "no image facts")
		case img.Reason != "":
			reasons = append(reasons, ctrReason(img.Reason))
		}
		if img != nil {
			sv.Image = img.Repository + ":" + img.Tag
			for _, res := range img.Resolved {
				switch {
				case res.Tag == img.Tag && res.Reason == "":
					sv.Refresh = !slices.Contains(img.OldDigests, res.PlatformDigest) && (res.IndexDigest == "" || !slices.Contains(img.OldDigests, res.IndexDigest))
				case res.Tag != img.Tag && res.Reason == "" && tagChanges:
					sv.Tags = append(sv.Tags, res.Tag)
				}
			}
		}
		if len(reasons) == 0 && !u.Available(s.Service) {
			reasons = append(reasons, "unavailable")
		}
		if len(reasons) == 0 && !sv.Refresh && len(sv.Tags) == 0 {
			if tagChanges {
				reasons = append(reasons, "up to date: no new digest for this tag; run a preview with a target tag to change tags")
			} else {
				reasons = append(reasons, "up to date: no new digest for this tag (tag changes need the executor's tag policy, which this server does not have)")
			}
		}
		sv.Unavailable = strings.Join(reasons, "; ")
		v.Services = append(v.Services, sv)
	}
	return v
}

// ctrRollback builds one rollback offer from a recreation row.
func ctrRollback(hostID string, row *pb.ContainerRecreationInfo, now time.Time, previewOK bool) ctrRollbackView {
	v := ctrRollbackView{Key: hostID + "/" + row.GetExecutionId(), Unit: row.GetUnit(), State: row.GetState(), ExecutionID: row.GetExecutionId()}
	for _, im := range row.GetImages() {
		v.Images = append(v.Images, fmt.Sprintf("%s: %s back to %s (retained %s)", im.GetService(), im.GetNewTag(), im.GetOldTag(), im.GetRetainedReference()))
	}
	exp := time.Unix(row.GetWindowExpiresAtUnix(), 0)
	if row.GetWindowExpiresAtUnix() > 0 {
		v.Window = exp.UTC().Format(time.RFC3339)
	}
	switch {
	case row.GetForm() != canonical.ContainerUpdateFormCompose:
		v.Unavailable = "standalone rollbacks are not offered here yet"
	case row.GetState() == "uncertain":
		v.Unavailable = "the outcome of this update is uncertain; an administrator must resolve the recreation first (admin guide 9.3)"
	case row.GetState() == "rolled_back":
		v.Unavailable = "already rolled back"
	case row.GetState() != "recreated" && row.GetState() != "partial":
		v.Unavailable = "nothing was recreated (" + row.GetState() + ")"
	case !row.GetHasBaseline():
		v.Unavailable = "no baseline was recorded"
	case row.GetWindowExpiresAtUnix() <= now.Unix():
		v.Unavailable = "the rollback window is over; the retained image may be gone"
	case row.GetRecoveryPlan() == nil || row.GetRecoveryPlan().GetDigest() == "":
		v.Unavailable = "no recovery plan is recorded for the unit"
	case !previewOK:
		v.Unavailable = "needs a fresh update preview that shows the unit as the update left it"
	}
	return v
}

// ctrSelection is one host's part of a submitted plan.
type ctrSelection struct {
	host      inventory.Host
	preview   executions.ContainerPreview
	projects  map[string][]executions.ContainerServiceSpec
	rollbacks []string
}

// ctrError is a refusal of the plan form with its HTTP status.
type ctrError struct {
	status int
	msg    string
}

func (e *ctrError) Error() string { return e.msg }

func ctrBad(format string, args ...any) error {
	return &ctrError{status: http.StatusBadRequest, msg: fmt.Sprintf(format, args...)}
}

// splitKey splits "<host>/<rest...>" keys from the right: n parts after
// the host. Host IDs never end in a segment the preview validates, so the
// rightmost segments are the project, service or execution ID.
func splitKey(key string, n int) (host string, parts []string, ok bool) {
	parts = make([]string, n)
	rest := key
	for i := n - 1; i >= 0; i-- {
		j := strings.LastIndex(rest, "/")
		if j <= 0 || j == len(rest)-1 {
			return "", nil, false
		}
		parts[i], rest = rest[j+1:], rest[:j]
	}
	return rest, parts, rest != ""
}

// ctrPlan reads the selection (PostForm only), checks every host against
// the inventory and builds the bindings from the shown previews.
func (h *Handler) ctrPlan(ctx context.Context, form url.Values) ([]ctrStageView, executions.BatchRequest, error) {
	hosts, err := h.hosts(ctx)
	if err != nil {
		return nil, executions.BatchRequest{}, &ctrError{status: http.StatusServiceUnavailable, msg: "inventory unavailable"}
	}
	byID := make(map[string]inventory.Host, len(hosts))
	for _, x := range hosts {
		byID[x.ID] = x
	}
	if len(form["unit"]) > 0 || len(form["project"]) > 0 {
		return nil, executions.BatchRequest{}, ctrBad("selecting a project selects none of its services; select the services to update")
	}
	svcs, rbs := form["svc"], form["rollback"]
	if len(svcs)+len(rbs) == 0 {
		return nil, executions.BatchRequest{}, ctrBad("select at least one service or rollback")
	}
	if len(svcs)+len(rbs) > ctrMaxSelections {
		return nil, executions.BatchRequest{}, ctrBad("at most %d selections", ctrMaxSelections)
	}
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	sel := map[string]*ctrSelection{}
	var order []string
	hostOf := func(id string) (*ctrSelection, error) {
		if s, ok := sel[id]; ok {
			return s, nil
		}
		host, ok := byID[id]
		if !ok {
			return nil, ctrBad("unknown host: %s", stagedEcho(id))
		}
		if why := ctrHostGate(host, hostKeyStatus(id, pins, pinsUnavailable)); why != "" {
			return nil, ctrBad("host %s cannot be updated: %s", stagedEcho(id), why)
		}
		if len(sel) == ctrMaxHosts {
			return nil, ctrBad("at most %d hosts", ctrMaxHosts)
		}
		shown := form.Get("preview:" + id)
		if shown == "" {
			return nil, ctrBad("host %s: the plan names no update preview; reload the tree", stagedEcho(id))
		}
		p, err := h.containerBatches.LatestContainerPreview(ctx, id)
		if err != nil {
			h.log.Error("latest update preview", "host", id, "error", err)
			return nil, &ctrError{status: http.StatusBadGateway, msg: "the update preview could not be loaded"}
		}
		if p.ID != shown || p.Stale != "" || p.Status != dockerhost.PreviewOK {
			return nil, ctrBad("host %s: the update preview you reviewed is no longer the newest fresh one; reload the tree", stagedEcho(id))
		}
		s := &ctrSelection{host: host, preview: p, projects: map[string][]executions.ContainerServiceSpec{}}
		sel[id] = s
		order = append(order, id)
		return s, nil
	}
	seen := map[string]bool{}
	for _, key := range svcs {
		if len(key) > ctrMaxFieldLen || seen[key] {
			return nil, executions.BatchRequest{}, ctrBad("invalid or repeated selection")
		}
		seen[key] = true
		id, parts, ok := splitKey(key, 2)
		if !ok {
			return nil, executions.BatchRequest{}, ctrBad("invalid selection %s", stagedEcho(key))
		}
		s, err := hostOf(id)
		if err != nil {
			return nil, executions.BatchRequest{}, err
		}
		spec, err := h.ctrServiceSpec(ctx, s.preview, parts[0], parts[1], form.Get("tag:"+key), form.Get("major:"+key) == "1")
		if err != nil {
			return nil, executions.BatchRequest{}, err
		}
		s.projects[parts[0]] = append(s.projects[parts[0]], spec)
	}
	for _, key := range rbs {
		if len(key) > ctrMaxFieldLen || seen[key] {
			return nil, executions.BatchRequest{}, ctrBad("invalid or repeated selection")
		}
		seen[key] = true
		id, parts, ok := splitKey(key, 1)
		if !ok {
			return nil, executions.BatchRequest{}, ctrBad("invalid rollback %s", stagedEcho(key))
		}
		s, err := hostOf(id)
		if err != nil {
			return nil, executions.BatchRequest{}, err
		}
		s.rollbacks = append(s.rollbacks, parts[0])
	}

	// Stages: the host stages of the staged OS update (DEV, QA, PROD,
	// manual gates, no tolerated failure).
	envOf := map[string]inventory.Environment{}
	for _, id := range order {
		envOf[id] = sel[id].host.Environment
	}
	stages, err := executions.PlanStages(stagedPlan, order, envOf)
	if err != nil {
		return nil, executions.BatchRequest{}, ctrBad("%v", err)
	}
	var req executions.BatchRequest
	var views []ctrStageView
	for i, st := range stages {
		spec := executions.BatchStageSpec{Gate: canonical.BatchGateManual}
		sv := ctrStageView{Num: i + 1, Name: st.Name, GateManual: i < len(stages)-1}
		for _, id := range st.Hosts {
			s := sel[id]
			projects := make([]string, 0, len(s.projects))
			for p := range s.projects {
				projects = append(projects, p)
			}
			slices.Sort(projects)
			for _, project := range projects {
				us := executions.ContainerUpdateSpec{PreviewExecutionID: s.preview.ID, Project: project, Services: s.projects[project]}
				b, err := h.containerBatches.PlanContainerUpdate(ctx, id, us)
				if err != nil {
					return nil, executions.BatchRequest{}, h.ctrPlanError(id, err)
				}
				spec.Members = append(spec.Members, executions.BatchMemberSpec{ActionID: "docker.compose_update", Version: "2.0.0", HostID: id, Update: &us})
				sv.Members = append(sv.Members, ctrMember("Update", s, b))
			}
			for _, rb := range s.rollbacks {
				rs := executions.ContainerRollbackSpec{PreviewExecutionID: s.preview.ID, RollbackOf: rb}
				b, err := h.containerBatches.PlanContainerRollback(ctx, id, rs)
				if err != nil {
					return nil, executions.BatchRequest{}, h.ctrPlanError(id, err)
				}
				// One batch changes a unit once (the planner refuses it
				// too); say so before the confirmation page.
				if _, updated := s.projects[b.Project]; updated {
					return nil, executions.BatchRequest{}, ctrBad("host %s: project %s is selected for an update and a rollback; one batch changes a project once",
						stagedEcho(id), stagedEcho(b.Project))
				}
				spec.Members = append(spec.Members, executions.BatchMemberSpec{ActionID: "docker.compose_rollback", Version: "1.0.0", HostID: id, Rollback: &rs})
				sv.Members = append(sv.Members, ctrMember("Rollback", s, b))
			}
		}
		req.Stages = append(req.Stages, spec)
		views = append(views, sv)
	}
	for i := range views {
		for j := range views[i].Members {
			views[i].Members[j].PreviewAge = ageText(h.clockNow(), sel[views[i].Members[j].HostID].preview.StartedAt)
		}
	}
	return views, req, nil
}

// ctrServiceSpec builds one service selection. A tag change needs the tag
// policy: a variant change or tags it cannot compare are refused, and a
// major change needs the second explicit choice.
func (h *Handler) ctrServiceSpec(ctx context.Context, p executions.ContainerPreview, project, service, tag string, major bool) (executions.ContainerServiceSpec, error) {
	spec := executions.ContainerServiceSpec{Service: service}
	i := slices.IndexFunc(p.Units, func(u dockerhost.PreviewUnit) bool { return u.Form == "compose" && u.Project == project })
	if i < 0 {
		return spec, ctrBad("project %s is not in the update preview", stagedEcho(project))
	}
	u := p.Units[i]
	var img *dockerhost.PreviewImage
	for _, t := range u.Targets {
		if t.Service == service {
			if j := slices.IndexFunc(u.Images, func(im dockerhost.PreviewImage) bool {
				return im.ImageID == t.ImageID && im.RunningReference == t.RunningReference
			}); j >= 0 {
				img = &u.Images[j]
			}
			break
		}
	}
	if img == nil || !u.Available(service) {
		return spec, ctrBad("service %s of %s cannot be updated", stagedEcho(service), stagedEcho(project))
	}
	if tag == "" || tag == img.Tag {
		return spec, nil
	}
	if h.containerTagPolicy == nil {
		return spec, ctrBad("service %s: tag changes need the executor's tag policy, which this server does not have", stagedEcho(service))
	}
	if !slices.ContainsFunc(img.Resolved, func(r dockerhost.PreviewResolution) bool { return r.Tag == tag && r.Reason == "" }) {
		return spec, ctrBad("service %s: the preview did not resolve tag %s; run a preview with that target tag", stagedEcho(service), stagedEcho(tag))
	}
	c, err := h.containerTagPolicy.CompareTags(ctx, img.Repository, img.Tag, tag)
	if err != nil {
		return spec, ctrBad("service %s: %s to %s is not offered: the tags cannot be compared or the variant changes", stagedEcho(service), stagedEcho(img.Tag), stagedEcho(tag))
	}
	if c.MajorChange && !major {
		return spec, ctrBad("service %s: %s to %s is a major version change; confirm it with the second choice", stagedEcho(service), stagedEcho(img.Tag), stagedEcho(tag))
	}
	spec.NewTag, spec.PolicyVersion, spec.PolicyDigest, spec.MajorChange = tag, c.PolicyVersion, c.PolicyDigest, c.MajorChange
	return spec, nil
}

// ctrPlanError maps a planner refusal: its reason names the member and is
// shown; anything else is logged.
func (h *Handler) ctrPlanError(hostID string, err error) error {
	var ie *executions.BatchInputError
	if errors.As(err, &ie) {
		return ctrBad("host %s: %s", stagedEcho(hostID), strings.TrimPrefix(ie.Reason, "member 1: "))
	}
	h.log.Error("plan container member", "host", hostID, "error", err)
	return &ctrError{status: http.StatusBadGateway, msg: "the container update could not be planned"}
}

// ctrMember is the confirmation view of one binding.
func ctrMember(kind string, s *ctrSelection, b canonical.BatchContainerUpdate) ctrMemberView {
	m := ctrMemberView{Kind: kind, HostID: s.host.ID, HostName: inventoryShownName(s.host), Project: b.Project, PreviewID: s.preview.ID,
		Risk: string(canonical.ContainerUpdateFloor(b)), SourceDigest: b.SourceDigest, WorkingDirHash: b.WorkingDirHash,
		ConfigFilesHash: b.ConfigFilesHash, RollbackOf: b.RollbackOf, RecoveryPlanDigest: b.RecoveryPlanDigest,
		Images: b.Images, Targets: b.Targets, Dependencies: b.Dependencies}
	for _, im := range b.Images {
		if im.OldTag != im.NewTag {
			m.TagChange = true
		}
	}
	return m
}

// ctrDigest digests the shown plan: the stages with their hosts and gates,
// and every member's kind, host, preview and complete binding.
func ctrDigest(views []ctrStageView) (string, error) {
	type member struct {
		Kind, Host, Preview string
		Binding             any
	}
	type stage struct {
		Name    string
		Gate    bool
		Members []member
	}
	var doc []stage
	for _, v := range views {
		st := stage{Name: v.Name, Gate: v.GateManual}
		for _, m := range v.Members {
			st.Members = append(st.Members, member{Kind: m.Kind, Host: m.HostID, Preview: m.PreviewID,
				Binding: []any{m.Project, m.SourceDigest, m.WorkingDirHash, m.ConfigFilesHash, m.RollbackOf, m.RecoveryPlanDigest, m.Images, m.Targets, m.Dependencies}})
		}
		doc = append(doc, st)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("digest container plan: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ctrHidden is the selection as the confirmation form carries it.
func ctrHidden(form url.Values) []ctrField {
	var out []ctrField
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "svc" || k == "rollback" || strings.HasPrefix(k, "preview:") || strings.HasPrefix(k, "tag:") || strings.HasPrefix(k, "major:") {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range form[k] {
			out = append(out, ctrField{Name: k, Value: v})
		}
	}
	return out
}

// handleContainerPlan answers the confirmation page and, confirmed,
// proposes the batch.
func (h *Handler) handleContainerPlan(w http.ResponseWriter, r *http.Request) {
	if h.containerBatches == nil || h.hosts == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, ctrMaxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	form := r.PostForm
	ctx, cancel := context.WithTimeout(r.Context(), 3*operationsCallTimeout)
	defer cancel()
	views, req, err := h.ctrPlan(ctx, form)
	if err != nil {
		var ce *ctrError
		if errors.As(err, &ce) {
			http.Error(w, ce.msg, ce.status)
			return
		}
		http.Error(w, "the container update could not be planned", http.StatusBadGateway)
		return
	}
	shown, err := ctrDigest(views)
	if err != nil {
		h.log.Error("container plan digest", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	digest := form.Get("plan_digest")
	if form.Get("confirm") != "1" || !stagedDigestOK(digest) {
		n := 0
		for _, v := range views {
			n += len(v.Members)
		}
		d := &containerUpdateData{Confirm: &ctrConfirm{Stages: views, Hidden: ctrHidden(form), Digest: shown, Count: n}}
		h.render(w, r, pageData{Title: "Confirm container updates", Active: "chart", Content: "container_update", ContainerUpdate: d})
		return
	}
	if digest != shown {
		http.Error(w, "the plan changed since you reviewed it; review it again", http.StatusBadRequest)
		return
	}
	created, err := h.containerBatches.ProposeBatch(ctx, webUser(r), req)
	if err == nil {
		http.Redirect(w, r, "/batches/"+url.PathEscape(created.ID), http.StatusSeeOther)
		return
	}
	var ce *executions.BatchCriticalError
	var ie *executions.BatchInputError
	switch {
	case errors.As(err, &ce):
		http.Error(w, "Refused: "+ce.Advice()+" Nothing was proposed.", http.StatusUnprocessableEntity)
	case errors.Is(err, executions.ErrBatchExecutionUnavailable):
		http.Error(w, "Refused: the executor does not run batches; nothing was proposed", http.StatusConflict)
	case errors.Is(err, executions.ErrBatchExecutionUnknown):
		http.Error(w, "Refused: the executor could not be asked whether it runs batches; nothing was proposed, try again", http.StatusServiceUnavailable)
	case errors.As(err, &ie):
		http.Error(w, ie.Reason, http.StatusBadRequest)
	case errors.Is(err, executions.ErrBatchContainer), errors.Is(err, executions.ErrBatchAnswer):
		http.Error(w, err.Error(), http.StatusBadGateway)
	default:
		h.log.Error("propose container batch", "error", err)
		http.Error(w, "the batch could not be proposed", http.StatusBadGateway)
	}
}
