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
// gate after every stage.

const (
	// stagedMaxHosts bounds one staged update selection from the form.
	stagedMaxHosts = 1000
	// stagedActionSecurity and stagedActionAll are the two update
	// actions of the form.
	stagedActionSecurity = "package.install_security"
	stagedActionAll      = "package.install_all"
)

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

// stagedHost is one selectable host of the staged update form.
type stagedHost struct {
	// ID is the inventory host id (the checkbox value).
	ID string
	// Name is the displayed host name.
	Name string
}

// stagedFormData is the selection form on the chart page.
type stagedFormData struct {
	// Hosts are the enrolled managed hosts, in inventory order.
	Hosts []stagedHost
	// Actions are the selectable update actions.
	Actions []stagedAction
}

// stagedConfirmData is the frozen host list on the confirmation page.
type stagedConfirmData struct {
	// Hosts is the frozen selection, in submitted order.
	Hosts []stagedHost
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
// page: one checkbox per enrolled managed host. PVE nodes, guests and
// containers are never offered. It returns nil (section hidden) when
// operations are off or the enrollment cannot be determined.
func (h *Handler) stagedUpdateSection(hosts []inventory.Host, pins map[string]*pb.HostKeyPin, pinsUnavailable bool) *stagedUpdateData {
	if h.operations == nil || pinsUnavailable {
		return nil
	}
	var enrolled []stagedHost
	for _, host := range hosts {
		if hostKeyStatus(host.ID, pins, pinsUnavailable) == "pinned" {
			enrolled = append(enrolled, stagedHost{ID: host.ID, Name: inventoryShownName(host)})
		}
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

// handleChartStaged is the staged OS update form of the inventory
// chart (ADR 0006, P2-02 part 2). The first POST validates the
// checkbox selection and answers the confirmation page, which lists
// every frozen host; the confirmed POST proposes the frozen list to
// the existing stage proposal and redirects to the operation page.
// Every host id is checked against the inventory: unknown or
// unenrolled hosts are refused before anything is proposed.
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
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	ids := r.Form["host"]
	if len(ids) == 0 {
		http.Error(w, "select at least one host", http.StatusBadRequest)
		return
	}
	if len(ids) > stagedMaxHosts {
		http.Error(w, "too many hosts selected", http.StatusBadRequest)
		return
	}
	frozen := make([]stagedHost, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		host, ok := byID[id]
		if !ok {
			http.Error(w, "unknown host: "+id, http.StatusBadRequest)
			return
		}
		if hostKeyStatus(id, pins, pinsUnavailable) != "pinned" {
			http.Error(w, "host not enrolled for updates: "+id, http.StatusBadRequest)
			return
		}
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
	if r.FormValue("confirm") != "1" {
		data := pageData{Title: "Confirm staged OS update", Active: "chart", Content: "chart"}
		data.Chart = &chartData{Staged: &stagedUpdateData{Confirm: &stagedConfirmData{
			Hosts: frozen, Action: action, ActionLabel: label,
		}}}
		h.render(w, r, data)
		return
	}
	// The frozen list goes to the existing stage proposal: DEV/QA/
	// PROD by the hosts' inventory environment, a manual gate after
	// every stage, no failed host tolerated.
	plan := executions.Plan{Preset: executions.PresetEnvironments, Continue: stageplan.ContinueManual, MaxFailed: 0}
	hostIDs := make([]string, len(frozen))
	for i, host := range frozen {
		hostIDs[i] = host.ID
	}
	cctx, cancel := context.WithTimeout(ctx, operationsCallTimeout)
	defer cancel()
	created, err := h.operations.CreateStaged(cctx, webUser(r), action, hostIDs, nil, plan)
	var he *executions.HostError
	var pe *executions.ParamError
	var ple *executions.PlanError
	switch {
	case err == nil:
		http.Redirect(w, r, "/operations/"+url.PathEscape(created.ID), http.StatusSeeOther)
	case errors.Is(err, executions.ErrUnknownAction), errors.Is(err, executions.ErrNoHosts), errors.Is(err, executions.ErrTooManyHosts), errors.As(err, &he), errors.As(err, &pe), errors.As(err, &ple):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
			h.executorRefusal(w, "propose staged update", err)
			return
		}
		h.log.Error("create staged execution", "error", err)
		http.Error(w, "operations unavailable", http.StatusServiceUnavailable)
	}
}
