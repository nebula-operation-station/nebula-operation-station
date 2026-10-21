// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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
	ID, Short, State, StateClass, Actions, Interval, CreatedBy, Options string
	HostCount                                                           int
	HostList                                                            []string
	Expires                                                             time.Time
	LastRun, NextDue                                                    time.Time
	LastRunSet, NextDueSet                                              bool
	Pending, Active                                                     bool
}

// scheduleIntervalOption is one interval the form offers.
type scheduleIntervalOption struct{ Value, Label string }

// scheduleIntervals are the intervals the form offers (minutes, as the
// create endpoint takes interval_minutes). The default is a day; the
// inventory's "Schedule refresh…" presets 6 hours.
var scheduleIntervals = []scheduleIntervalOption{
	{Value: "60", Label: "hour"},
	{Value: "360", Label: "6 hours"},
	{Value: "1440", Label: "day"},
	{Value: "10080", Label: "week"},
}

const defaultScheduleInterval = "1440"

type schedulesData struct {
	Rows    []scheduleRow
	Actions []actionView
	Hosts   []opsHostOption
	// Interval and Days preselect the form (query parameters); the
	// defaults are a day for 30 days.
	IntervalOptions []scheduleIntervalOption
	Interval, Days  string
}

// formatScheduleInterval renders an interval for the cards: "15 min",
// "6 h", "1 day", "3 days".
func formatScheduleInterval(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	}
	if d%time.Hour == 0 {
		n := int(d / time.Hour)
		if n == 1 {
			return "1 h"
		}
		return fmt.Sprintf("%d h", n)
	}
	n := int(d / time.Minute)
	if n == 1 {
		return "1 min"
	}
	return fmt.Sprintf("%d min", n)
}

// schedulePrefill reads the preselection from the query parameters
// (?action=, ?host=, ?all=1, ?interval=, ?days=, as /operations/new?host=
// does). Only values the form can hold are kept: actions the executor may
// schedule, hosts the form offers, one of the offered intervals, and a
// whole number of days 1 to 90. Everything else is ignored.
func schedulePrefill(r *http.Request, schedulable map[string]bool, offeredHosts map[string]bool) (actions, hosts map[string]bool, allHosts bool, interval, days string) {
	interval, days = defaultScheduleInterval, "30"
	actions, hosts = map[string]bool{}, map[string]bool{}
	q := r.URL.Query()
	for _, a := range q["action"] {
		if schedulable[a] {
			actions[a] = true
		}
	}
	for _, id := range q["host"] {
		if offeredHosts[id] {
			hosts[id] = true
		}
	}
	allHosts = q.Get("all") == "1"
	if v := q.Get("interval"); v != "" {
		for _, o := range scheduleIntervals {
			if o.Value == v {
				interval = v
				break
			}
		}
	}
	if v := q.Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= executions.MaxScheduleDays {
			days = strconv.Itoa(n)
		}
	}
	return
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
	sd := &schedulesData{IntervalOptions: scheduleIntervals, Interval: defaultScheduleInterval, Days: "30"}
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
		row := scheduleRow{ID: x.ID, Short: x.ID[:8], State: state, Actions: strings.Join(x.Actions, ", "),
			HostCount: len(x.Hosts), HostList: x.Hosts,
			Interval: formatScheduleInterval(x.Interval), Expires: x.ExpiresAt.UTC(), CreatedBy: x.CreatedBy,
			Pending: state == "pending", Active: state == "active"}
		switch state {
		case "pending":
			row.StateClass = "badge--pending"
		case "active":
			row.StateClass = "badge--ok"
		default:
			row.StateClass = "badge--unknown"
		}
		if !x.LastRun.IsZero() {
			row.LastRun, row.LastRunSet = x.LastRun.UTC(), true
		}
		if state == "active" && row.LastRunSet {
			row.NextDue, row.NextDueSet = x.LastRun.Add(x.Interval).UTC(), true
		}
		if row.Pending && len(x.Options) > 0 && json.Valid(x.Options) {
			row.Options = string(x.Options)
		}
		sd.Rows = append(sd.Rows, row)
	}
	schedulable := map[string]bool{}
	for _, a := range executions.SortedActions() {
		schedulable[a.ID] = true
		sd.Actions = append(sd.Actions, actionView{ID: a.ID, Title: a.Title, Description: a.Description, ReadOnly: true})
	}
	offered := map[string]bool{}
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
				offered[x.ID] = true
			}
		}
	}
	// Prefill from the query parameters (the inventory's "Schedule
	// refresh…" and "Keep all hosts fresh…"). It only checks boxes:
	// nothing is created without the normal approval flow.
	preActions, preHosts, preAll, interval, days := schedulePrefill(r, schedulable, offered)
	sd.Interval, sd.Days = interval, days
	for i := range sd.Actions {
		sd.Actions[i].Selected = preActions[sd.Actions[i].ID]
	}
	for i := range sd.Hosts {
		sd.Hosts[i].Checked = preHosts[sd.Hosts[i].ID] || preAll
	}
	data.Schedules = sd
	h.render(w, r, data)
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
