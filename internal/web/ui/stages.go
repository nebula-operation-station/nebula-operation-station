// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/stageplan"
)

// Staged operations (Milestone 6): the operation page shows the stages
// with the executor's view of them, a gate button, skip and retry per
// host and an abort button. The executor decides; these handlers relay.

type stageView struct {
	Num                       int
	Name, Continue            string
	Hosts                     []string
	MaxFailed, MaxUnreachable int
	Open, Passed              bool
}

type rolloutView struct {
	Stages  []stageView
	Waiting string
	// Known: the executor's view could be read.
	Known            bool
	Stopped          string
	Aborted          bool
	OpenStage        int
	GateNext         int
	GateKey, GateCLI bool
	CanAbort         bool
}

// planDoc is the stored plan document (the server wrote it).
type planDoc struct {
	Stages []struct {
		Name           string   `json:"name"`
		Hosts          []string `json:"hosts"`
		MaxFailed      int      `json:"max_failed"`
		MaxUnreachable int      `json:"max_unreachable"`
		Continue       string   `json:"continue"`
	} `json:"stages"`
}

// rolloutFor builds the stage view of a staged execution and marks the
// hosts that can be skipped or retried.
func (h *Handler) rolloutFor(ctx context.Context, e executions.Execution, v *execView) {
	var doc planDoc
	if e.StagePlan == "" || json.Unmarshal([]byte(e.StagePlan), &doc) != nil {
		return
	}
	rv := &rolloutView{Waiting: e.Waiting}
	for i, st := range doc.Stages {
		rv.Stages = append(rv.Stages, stageView{Num: i + 1, Name: st.Name, Hosts: st.Hosts, MaxFailed: st.MaxFailed,
			MaxUnreachable: st.MaxUnreachable, Continue: st.Continue})
	}
	v.Rollout = rv
	running := e.State == "running" || e.State == "approved"
	if !running {
		return
	}
	ro, err := h.operations.Rollout(ctx, e.ID)
	if err != nil {
		h.log.Warn("rollout", "execution", e.ID, "error", err.Error())
		return
	}
	rv.Known, rv.Stopped, rv.Aborted, rv.OpenStage = true, ro.GetStopped(), ro.GetAborted(), int(ro.GetOpenStage())
	rv.CanAbort = !rv.Aborted && rv.Stopped == ""
	outcome := map[string]string{}
	for i, st := range ro.GetStages() {
		if i < len(rv.Stages) {
			rv.Stages[i].Open, rv.Stages[i].Passed = st.GetOpen(), st.GetPassed()
		}
		for _, o := range st.GetOutcomes() {
			outcome[o.GetHostId()] = o.GetOutcome()
		}
	}
	if open := rv.OpenStage; rv.CanAbort && open >= 1 && open < len(rv.Stages) && rv.Stages[open-1].Passed {
		rv.GateNext = open + 1
		switch ro.GetGateRequirement() {
		case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY:
			rv.GateCLI = true
		case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_NONE:
		default:
			rv.GateKey = true
		}
	}
	for i := range v.Hosts {
		hv := &v.Hosts[i]
		o := outcome[hv.ID]
		inOpen := hv.Stage <= rv.OpenStage
		hv.CanSkip = rv.CanAbort && inOpen && ((o == "" && hv.State == "waiting") || o == "unreachable")
		hv.CanRetry = rv.CanAbort && inOpen && !e.Durable && o == "unreachable" && hv.Class == "network_unreachable"
	}
}

type gateInput struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Stage     int             `json:"stage"`
	Host      string          `json:"host"`
	Assertion json.RawMessage `json:"assertion"`
}

func (in gateInput) gate() executions.Gate {
	return executions.Gate{Kind: in.Kind, Stage: in.Stage, Host: in.Host}
}

// stagedError answers errors of the staged-operation endpoints.
func (h *Handler) stagedError(w http.ResponseWriter, op string, err error) {
	var pe *executions.PlanError
	switch {
	case errors.Is(err, executions.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "operation not found")
	case errors.Is(err, executions.ErrNotStaged), errors.Is(err, executions.ErrNotRunning), errors.Is(err, executions.ErrNoRetry):
		writeJSONError(w, http.StatusConflict, err.Error())
	case errors.As(err, &pe):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		h.executorRefusal(w, op, err)
	}
}

func (h *Handler) handleOperationGate(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	var in gateInput
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	res, err := h.operations.BeginGate(ctx, webUser(r), in.ID, in.gate())
	switch {
	case err != nil:
		h.stagedError(w, "begin gate", err)
	case res.CLI:
		msg := "this gate needs the executor host: nebula approve "
		if in.Kind == "skip" {
			msg += "--skip " + in.Host
		} else {
			msg += "--stage " + strconv.Itoa(in.Stage)
		}
		writeJSONError(w, http.StatusConflict, msg+" <digest>")
	case res.Done:
		writeJSON(w, http.StatusOK, map[string]bool{"done": true})
	default:
		writeJSON(w, http.StatusOK, map[string]json.RawMessage{"options": res.Options})
	}
}

func (h *Handler) handleOperationGateCommit(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	var in gateInput
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.operations.CommitGate(ctx, webUser(r), in.ID, in.gate(), in.Assertion); err != nil {
		h.stagedError(w, "commit gate", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

func (h *Handler) handleOperationAbort(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.operations.Abort(ctx, webUser(r), in.ID); err != nil {
		h.stagedError(w, "abort rollout", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

func (h *Handler) handleOperationRetry(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	var in struct {
		ID   string `json:"id"`
		Host string `json:"host"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.operations.RetryHost(ctx, webUser(r), in.ID, in.Host); err != nil {
		h.stagedError(w, "retry host", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// Staged OS update from the inventory chart (ADR 0006, P2-02 part 2):
// a no-JavaScript form with one checkbox per enrolled (pinned, not
// blocked) managed host. Selecting or expanding a parent never
// authorizes its descendants: the form offers managed hosts only, and
// the frozen list is handed to the existing stage proposal
// (Operations.CreateStaged) with the DEV/QA/PROD preset and a manual
// gate after every stage. The confirmation page shows the stages that
// preset lays out (executions.PlanStages, the layout CreateStaged
// proposes), not just the host list.

const (
	// stagedMaxHosts bounds one staged update selection from the form.
	stagedMaxHosts = 1000
	// stagedMaxBody bounds the form body (1000 host ids and the rest
	// fit with room to spare).
	stagedMaxBody = 1 << 20
	// stagedMaxEcho bounds a client-supplied host id echoed in an
	// error.
	stagedMaxEcho = 64
	// stagedActionSecurity and stagedActionAll are the two update
	// actions of the form.
	stagedActionSecurity = "package.install_security"
	stagedActionAll      = "package.install_all"
	// stagedNoEnvironment is why an enrolled host without a DEV, QA or
	// PROD environment cannot be selected: the preset has no stage
	// for it.
	stagedNoEnvironment = "no environment (DEV, QA or PROD), so it fits no stage"
)

// stagedPlan is the plan of every staged update from the chart: the
// DEV/QA/PROD stages by the hosts' inventory environment, a manual
// gate after every stage, no failed host tolerated. The confirmation
// page and the proposal both use it.
var stagedPlan = executions.Plan{Preset: executions.PresetEnvironments, Continue: stageplan.ContinueManual, MaxFailed: 0}

var stagedUpdateActions = []stagedAction{
	{ID: stagedActionSecurity, Label: "Security updates"},
	{ID: stagedActionAll, Label: "All updates"},
}

// stagedAction is one selectable action of the staged update form.
type stagedAction struct {
	// ID is the action id passed to the stage proposal.
	ID string
	// Label is the option text.
	Label string
}

// stagedHost is one host of the staged update form.
type stagedHost struct {
	// ID is the inventory host id (the checkbox value).
	ID string
	// Name is the displayed host name.
	Name string
	// Unselectable is why the host cannot be selected (shown next to
	// its disabled checkbox); empty when it can.
	Unselectable string
}

// stagedFormData is the selection form on the chart page.
type stagedFormData struct {
	// Hosts are the enrolled managed hosts, in inventory order.
	Hosts []stagedHost
	// Actions are the selectable update actions.
	Actions []stagedAction
}

// stagedStageView is one stage of the plan on the confirmation page.
type stagedStageView struct {
	// Num is the stage number (from 1).
	Num int
	// Name is the stage name of the plan (dev, qa, prod).
	Name string
	// Hosts are the stage's hosts, in plan order.
	Hosts []stagedHost
	// MaxFailed is the number of failed (and of unreachable) hosts the
	// stage tolerates.
	MaxFailed int
	// GateManual: a manual gate follows the stage (the next stage opens
	// only when someone continues); false on the last stage and when
	// the next stage opens automatically.
	GateManual bool
	// GateAuto: the next stage opens automatically once this stage
	// passed.
	GateAuto bool
}

// stagedConfirmData is the frozen selection on the confirmation page.
type stagedConfirmData struct {
	// Hosts is the frozen selection, in submitted order (the hidden
	// inputs of the confirm form).
	Hosts []stagedHost
	// Stages is the staged plan that the confirm form proposes.
	Stages []stagedStageView
	// Action is the selected action id.
	Action string
	// ActionLabel is the selected action label.
	ActionLabel string
}

// stagedUpdateData is the staged update section of the chart page: the
// selection form (Form) on the chart, or the confirmation of the
// frozen list (Confirm) on the confirmation page.
type stagedUpdateData struct {
	// Form is the selection form; nil on the confirmation page.
	Form *stagedFormData
	// Confirm is the frozen list awaiting confirmation; nil on the
	// chart page.
	Confirm *stagedConfirmData
}

// stagedUpdateSection builds the staged update selection of the chart
// page: one checkbox per enrolled managed host, disabled with the
// reason for a host the plan has no stage for. PVE nodes, guests and
// containers are never offered. It returns nil (section hidden) when
// operations are off or the enrollment cannot be determined.
func (h *Handler) stagedUpdateSection(hosts []inventory.Host, pins map[string]*pb.HostKeyPin, pinsUnavailable bool) *stagedUpdateData {
	if h.operations == nil || pinsUnavailable {
		return nil
	}
	var enrolled []stagedHost
	for _, host := range hosts {
		if hostKeyStatus(host.ID, pins, pinsUnavailable) != "pinned" {
			continue
		}
		sh := stagedHost{ID: host.ID, Name: inventoryShownName(host)}
		if !executions.HasStageEnvironment(host.Environment) {
			sh.Unselectable = stagedNoEnvironment
		}
		enrolled = append(enrolled, sh)
	}
	if len(enrolled) == 0 {
		return nil
	}
	return &stagedUpdateData{Form: &stagedFormData{Hosts: enrolled, Actions: stagedUpdateActions}}
}

// stagedActionLabel is the label of a staged update action id.
func stagedActionLabel(id string) (string, bool) {
	for _, a := range stagedUpdateActions {
		if a.ID == id {
			return a.Label, true
		}
	}
	return "", false
}

// stagedEcho bounds a client-supplied id for an error message.
func stagedEcho(id string) string {
	if len(id) > stagedMaxEcho {
		return strconv.Quote(id[:stagedMaxEcho]) + "..."
	}
	return strconv.Quote(id)
}

// stagedStages lays out the stagedPlan stages over the frozen hosts
// with executions.PlanStages, the layout CreateStaged proposes for
// the same hosts and plan.
func stagedStages(frozen []stagedHost, envOf map[string]inventory.Environment) ([]stagedStageView, error) {
	ids := make([]string, len(frozen))
	byID := make(map[string]stagedHost, len(frozen))
	for i, host := range frozen {
		ids[i] = host.ID
		byID[host.ID] = host
	}
	stages, err := executions.PlanStages(stagedPlan, ids, envOf)
	if err != nil {
		return nil, err
	}
	out := make([]stagedStageView, len(stages))
	for i, st := range stages {
		v := stagedStageView{Num: i + 1, Name: st.Name, MaxFailed: st.MaxFailed}
		if i < len(stages)-1 {
			v.GateManual = st.Continue == stageplan.ContinueManual
			v.GateAuto = st.Continue == stageplan.ContinueAuto
		}
		for _, id := range st.Hosts {
			v.Hosts = append(v.Hosts, byID[id])
		}
		out[i] = v
	}
	return out, nil
}

// handleChartStaged is the staged OS update form of the inventory
// chart (ADR 0006, P2-02 part 2). The first POST validates the
// checkbox selection and answers the confirmation page, which shows
// the staged plan (stages in order, their hosts, the gates between
// them); the confirmed POST proposes the frozen list with the same
// plan and redirects to the operation page. Every host id is checked
// against the inventory: unknown or unenrolled hosts, and hosts
// without a DEV, QA or PROD environment, are refused before anything
// is proposed.
func (h *Handler) handleChartStaged(w http.ResponseWriter, r *http.Request) {
	if !h.operationsEnabled(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.hosts == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, stagedMaxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	hosts, err := h.hosts(ctx)
	if err != nil {
		http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
		return
	}
	byID := make(map[string]inventory.Host, len(hosts))
	for _, host := range hosts {
		byID[host.ID] = host
	}
	ids := r.Form["host"]
	if len(ids) == 0 {
		http.Error(w, "select at least one host", http.StatusBadRequest)
		return
	}
	if len(ids) > stagedMaxHosts {
		http.Error(w, "too many hosts selected", http.StatusBadRequest)
		return
	}
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	if pinsUnavailable {
		http.Error(w, "host enrollment unavailable (executor unreachable); nothing was proposed", http.StatusServiceUnavailable)
		return
	}
	frozen := make([]stagedHost, 0, len(ids))
	envOf := make(map[string]inventory.Environment, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		host, ok := byID[id]
		if !ok {
			http.Error(w, "unknown host: "+stagedEcho(id), http.StatusBadRequest)
			return
		}
		if hostKeyStatus(id, pins, false) != "pinned" {
			http.Error(w, "host not enrolled for updates: "+stagedEcho(id), http.StatusBadRequest)
			return
		}
		if !executions.HasStageEnvironment(host.Environment) {
			http.Error(w, "host "+stagedEcho(id)+" cannot be updated in stages: "+stagedNoEnvironment+"; set its environment in the inventory or leave it out", http.StatusBadRequest)
			return
		}
		envOf[id] = host.Environment
		frozen = append(frozen, stagedHost{ID: host.ID, Name: inventoryShownName(host)})
	}
	if len(frozen) == 0 {
		http.Error(w, "select at least one host", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	label, ok := stagedActionLabel(action)
	if !ok {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	// The plan shown and the plan proposed come from the same layout
	// (executions.PlanStages with stagedPlan).
	stages, err := stagedStages(frozen, envOf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.FormValue("confirm") != "1" {
		data := pageData{Title: "Confirm staged OS update", Active: "chart", Content: "chart"}
		data.Chart = &chartData{Staged: &stagedUpdateData{Confirm: &stagedConfirmData{
			Hosts: frozen, Stages: stages, Action: action, ActionLabel: label,
		}}}
		h.render(w, r, data)
		return
	}
	hostIDs := make([]string, len(frozen))
	for i, host := range frozen {
		hostIDs[i] = host.ID
	}
	cctx, cancel := context.WithTimeout(ctx, operationsCallTimeout)
	defer cancel()
	created, err := h.operations.CreateStaged(cctx, webUser(r), action, hostIDs, nil, stagedPlan)
	var he *executions.HostError
	var pe *executions.ParamError
	var ple *executions.PlanError
	switch {
	case err == nil:
		http.Redirect(w, r, "/operations/"+url.PathEscape(created.ID), http.StatusSeeOther)
	case errors.Is(err, executions.ErrUnknownAction), errors.Is(err, executions.ErrNoHosts), errors.Is(err, executions.ErrTooManyHosts), errors.As(err, &he), errors.As(err, &pe), errors.As(err, &ple):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		h.stagedFormRefusal(w, err)
	}
}

// stagedFormRefusal answers an executor error of the staged update
// form as a plain-text error page (the form posts without JavaScript,
// so no JSON): a refusal is 409 with the executor's reason, anything
// else 502 or 503 without detail.
func (h *Handler) stagedFormRefusal(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok || st.Code() == codes.Unknown {
		h.log.Error("create staged execution", "error", err)
		http.Error(w, "operations unavailable", http.StatusServiceUnavailable)
		return
	}
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound:
		msg := st.Message()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		http.Error(w, "the executor refused: "+msg, http.StatusConflict)
	default:
		h.log.Error("propose staged update", "error", err)
		http.Error(w, "executor unavailable", http.StatusBadGateway)
	}
}
