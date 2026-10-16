// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
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
