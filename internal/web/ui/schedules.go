// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// Scheduled read-only checks: a page to propose a schedule grant, approve
// it with the security key and revoke it. The executor decides what may
// be scheduled (only actions it rates LOW) and enforces every run.

// Schedules manages schedule grants (executions.Service).
type Schedules interface {
	CreateSchedule(ctx context.Context, user string, actionIDs, hostIDs []string, interval time.Duration, days int) (executions.ScheduleCreated, error)
	Schedules(ctx context.Context) ([]executions.Schedule, error)
	ApproveSchedule(ctx context.Context, user, id string, assertion []byte) error
	RevokeSchedule(ctx context.Context, user, id string) error
}

type scheduleRow struct {
	ID, Short, State, Actions, Hosts, Interval, Expires, CreatedBy, Options string
	Pending, Active                                                         bool
}

type schedulesData struct {
	Rows    []scheduleRow
	Actions []actionView
	Hosts   []opsHostOption
}

func (h *Handler) schedulesEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.schedules == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *Handler) handleSchedules(w http.ResponseWriter, r *http.Request) {
	if !h.schedulesEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	data := pageData{Title: "Scheduled checks", Active: "operations", Content: "schedules", Scripts: []string{"webauthn.js", "schedules.js"}}
	sd := &schedulesData{}
	list, err := h.schedules.Schedules(ctx)
	if err != nil {
		h.log.Error("list schedules", "error", err)
	}
	now := time.Now()
	for _, x := range list {
		state := x.State
		if state == "active" && !now.Before(x.ExpiresAt) {
			state = "expired"
		}
		row := scheduleRow{ID: x.ID, Short: x.ID[:8], State: state, Actions: strings.Join(x.Actions, ", "), Hosts: strings.Join(x.Hosts, ", "),
			Interval: x.Interval.String(), Expires: x.ExpiresAt.UTC().Format("2006-01-02 15:04 MST"), CreatedBy: x.CreatedBy,
			Pending: state == "pending", Active: state == "active"}
		if row.Pending && len(x.Options) > 0 && json.Valid(x.Options) {
			row.Options = string(x.Options)
		}
		sd.Rows = append(sd.Rows, row)
	}
	for _, a := range executions.SortedActions() {
		sd.Actions = append(sd.Actions, actionView{ID: a.ID, Title: a.Title, Description: a.Description, ReadOnly: true})
	}
	if h.hosts != nil && h.hostKeys != nil {
		hosts, err := h.hosts(ctx)
		if err != nil {
			h.log.Error("list hosts", "error", err)
		}
		usable := map[string]bool{}
		if pins, err := h.hostKeys(ctx); err == nil {
			for _, p := range pins {
				usable[p.GetHostId()] = !p.GetBlocked()
			}
		}
		for _, x := range hosts {
			if usable[x.ID] {
				name := x.DisplayName
				if name == "" {
					name = x.ID
				}
				sd.Hosts = append(sd.Hosts, opsHostOption{ID: x.ID, Name: name, Usable: true})
			}
		}
	}
	data.Schedules = sd
	h.render(w, data)
}

func (h *Handler) scheduleError(w http.ResponseWriter, op string, err error) {
	var se *executions.ScheduleError
	var he *executions.HostError
	switch {
	case errors.Is(err, executions.ErrScheduleNotFound):
		writeJSONError(w, http.StatusNotFound, "schedule not found")
	case errors.Is(err, executions.ErrScheduleState):
		writeJSONError(w, http.StatusConflict, err.Error())
	case errors.As(err, &se), errors.As(err, &he), errors.Is(err, executions.ErrUnknownAction):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		h.executorRefusal(w, op, err)
	}
}

func (h *Handler) handleScheduleCreate(w http.ResponseWriter, r *http.Request) {
	if !h.schedulesEnabled(w, r) {
		return
	}
	var in struct {
		Actions         []string `json:"actions"`
		Hosts           []string `json:"hosts"`
		IntervalMinutes int      `json:"interval_minutes"`
		Days            int      `json:"days"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	c, err := h.schedules.CreateSchedule(ctx, webUser(r), in.Actions, in.Hosts, time.Duration(in.IntervalMinutes)*time.Minute, in.Days)
	if err != nil {
		h.scheduleError(w, "create schedule", err)
		return
	}
	out := map[string]any{"id": c.ID, "cli": c.CLI}
	if len(c.Options) > 0 {
		out["options"] = json.RawMessage(c.Options)
	}
	if c.CLI {
		out["command"] = "nebula schedule approve " + c.Digest[:16]
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleScheduleApprove(w http.ResponseWriter, r *http.Request) {
	if !h.schedulesEnabled(w, r) {
		return
	}
	var in struct {
		ID        string          `json:"id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.schedules.ApproveSchedule(ctx, webUser(r), in.ID, in.Assertion); err != nil {
		h.scheduleError(w, "approve schedule", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

func (h *Handler) handleScheduleRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.schedulesEnabled(w, r) {
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
	if err := h.schedules.RevokeSchedule(ctx, webUser(r), in.ID); err != nil {
		h.scheduleError(w, "revoke schedule", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}
