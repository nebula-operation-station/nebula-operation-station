// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
)

// Discovery pages (spec 12, M9-2): queue scans, review the staged results
// and import what you choose. Everything a scan saw is untrusted network
// data and is shown as text.

// DiscoveryStore queues scans and keeps their results
// (internal/discovery.Store).
type DiscoveryStore interface {
	Available() bool
	Submit(ctx context.Context, user string, req discovery.Request) (discovery.JobRow, error)
	Cancel(ctx context.Context, id string) error
	Jobs(ctx context.Context, limit int) ([]discovery.JobRow, error)
	Job(ctx context.Context, id string) (discovery.JobRow, []discovery.Row, error)
	Import(ctx context.Context, user, id string, addresses []string, all bool) (discovery.ImportReport, error)
	CreateSchedule(ctx context.Context, user, name string, req discovery.Request, interval time.Duration, first time.Time) (discovery.Schedule, error)
	DeleteSchedule(ctx context.Context, id string) error
	Schedules(ctx context.Context) ([]discovery.Schedule, error)
}

type discoveryJobView struct {
	ID, Created, Finished, Targets, Description, State, Error, CreatedBy string
	Hosts                                                                int
	Queued, Done                                                         bool
}

type discoveryRowView struct {
	Address, MAC, Vendor, Hostname, OS, Ports, Class, ClassKey, Reason, MatchAsset, MatchHost, Imported string
	Importable                                                                                          bool
}

type discoveryScheduleView struct {
	ID, Name, Description, Targets, When, Next, CreatedBy string
	Enabled                                               bool
}

type discoveryData struct {
	Available bool
	Networks  []networkRow
	Modes     []discoveryjob.Mode
	Jobs      []discoveryJobView
	Schedules []discoveryScheduleView
	Job       *discoveryJobView
	Rows      []discoveryRowView
	Counts    string
}

const timeFormat = "2006-01-02 15:04 MST"

func viewJob(j discovery.JobRow) discoveryJobView {
	v := discoveryJobView{ID: j.ID, Created: j.CreatedAt.UTC().Format(timeFormat), Targets: j.Targets, Description: j.Description, State: j.State,
		Error: j.Error, CreatedBy: j.CreatedBy, Hosts: j.Hosts, Queued: j.State == discovery.StateQueued, Done: j.State == discovery.StateDone}
	if !j.FinishedAt.IsZero() {
		v.Finished = j.FinishedAt.UTC().Format(timeFormat)
	}
	if j.ScheduleID != "" {
		v.CreatedBy += " (schedule)"
	}
	return v
}

func (h *Handler) handleDiscoveryPage(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil || h.network == nil {
		h.render(w, pageData{Title: "Discovery", Active: "network", Content: "empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	d := &discoveryData{Available: h.discovery.Available(), Modes: discoveryjob.Modes}
	nets, err := h.network.Networks(ctx)
	if err != nil {
		h.log.Error("list networks", "error", err)
		http.Error(w, "network data unavailable", http.StatusInternalServerError)
		return
	}
	for _, n := range nets {
		d.Networks = append(d.Networks, networkRow{ID: n.ID, Name: n.Name, Prefix: n.Prefix.String()})
	}
	jobs, err := h.discovery.Jobs(ctx, 50)
	if err != nil {
		h.log.Error("list discovery jobs", "error", err)
		http.Error(w, "discovery data unavailable", http.StatusInternalServerError)
		return
	}
	for _, j := range jobs {
		d.Jobs = append(d.Jobs, viewJob(j))
	}
	scheds, err := h.discovery.Schedules(ctx)
	if err != nil {
		h.log.Error("list discovery schedules", "error", err)
		http.Error(w, "discovery data unavailable", http.StatusInternalServerError)
		return
	}
	for _, sc := range scheds {
		v := discoveryScheduleView{ID: sc.ID, Name: sc.Name, Description: sc.Description, Targets: sc.Targets, CreatedBy: sc.CreatedBy, Enabled: sc.Enabled,
			Next: sc.NextAt.UTC().Format(timeFormat)}
		switch {
		case sc.Interval == 0 && sc.Enabled:
			v.When = "once"
		case sc.Interval == 0:
			v.When, v.Next = "once (done)", ""
		default:
			v.When = "every " + strconv.Itoa(int(sc.Interval/time.Hour)) + " h"
		}
		d.Schedules = append(d.Schedules, v)
	}
	h.render(w, pageData{Title: "Discovery", Active: "network", Content: "discovery", Scripts: []string{"webauthn.js", "discovery.js"}, Discovery: d})
}

func (h *Handler) handleDiscoveryJob(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	j, rows, err := h.discovery.Job(ctx, r.PathValue("id"))
	if errors.Is(err, discovery.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get discovery job", "error", err)
		http.Error(w, "discovery data unavailable", http.StatusInternalServerError)
		return
	}
	jv := viewJob(j)
	d := &discoveryData{Job: &jv}
	counts := map[discovery.Class]int{}
	for _, row := range rows {
		counts[row.Class]++
		var open []string
		for _, p := range row.Ports {
			if p.State == "open" {
				s := strconv.Itoa(p.Port) + "/" + p.Protocol
				if p.Service != "" {
					s += " " + p.Service
				}
				if p.Product != "" {
					s += " (" + strings.TrimSpace(p.Product+" "+p.Version) + ")"
				}
				open = append(open, s)
			}
		}
		rv := discoveryRowView{Address: row.Address, MAC: row.MAC, Vendor: row.Vendor, Hostname: row.Hostname, OS: row.OS, Ports: strings.Join(open, ", "),
			Class: string(row.Class), ClassKey: strings.ReplaceAll(string(row.Class), " ", "_"), Reason: row.Reason, MatchAsset: row.MatchAsset,
			MatchHost: row.MatchHost, Imported: row.ImportedAsset, Importable: row.Importable && j.State == discovery.StateDone}
		d.Rows = append(d.Rows, rv)
	}
	var parts []string
	for _, c := range []discovery.Class{discovery.ClassNew, discovery.ClassExisting, discovery.ClassPossible, discovery.ClassConflict} {
		if counts[c] > 0 {
			parts = append(parts, strconv.Itoa(counts[c])+" "+string(c))
		}
	}
	d.Counts = strings.Join(parts, ", ")
	h.render(w, pageData{Title: "Discovery scan", Active: "network", Content: "discovery_job", Scripts: []string{"webauthn.js", "discovery.js"}, Discovery: d})
}

// answerDiscoveryError maps a store error.
func (h *Handler) answerDiscoveryError(w http.ResponseWriter, op string, err error) {
	var ve *discovery.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSONError(w, http.StatusBadRequest, ve.Reason)
	case errors.Is(err, discovery.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "not found")
	case errors.Is(err, discovery.ErrUnavailable):
		writeJSONError(w, http.StatusConflict, "nebula-discovery is not installed on this machine")
	default:
		h.log.Error(op, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "discovery data unavailable")
	}
}

func (h *Handler) handleDiscoverySubmit(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		discovery.Request
		Schedule struct {
			Kind  string `json:"kind"` // now, once, interval
			Name  string `json:"name"`
			At    int64  `json:"at"` // unix seconds
			Hours int    `json:"hours"`
		} `json:"schedule"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	user := webUser(r)
	switch in.Schedule.Kind {
	case "", "now":
		j, err := h.discovery.Submit(ctx, user, in.Request)
		if err != nil {
			h.answerDiscoveryError(w, "submit discovery", err)
			return
		}
		h.log.Info("audit", "kind", "discovery_queued", "job", j.ID, "targets", j.Targets, "scan", j.Description, "user", user)
		writeJSON(w, http.StatusOK, map[string]string{"id": j.ID})
	case "once", "interval":
		var interval time.Duration
		first := time.Unix(in.Schedule.At, 0)
		if in.Schedule.Kind == "interval" {
			if in.Schedule.Hours < 1 || in.Schedule.Hours > 24*366 {
				writeJSONError(w, http.StatusBadRequest, "the interval must be 1 hour or more")
				return
			}
			interval = time.Duration(in.Schedule.Hours) * time.Hour
		}
		if in.Schedule.At <= 0 {
			first = time.Time{}
		}
		sc, err := h.discovery.CreateSchedule(ctx, user, in.Schedule.Name, in.Request, interval, first)
		if err != nil {
			h.answerDiscoveryError(w, "create discovery schedule", err)
			return
		}
		h.log.Info("audit", "kind", "discovery_scheduled", "schedule", sc.ID, "name", sc.Name, "targets", sc.Targets, "scan", sc.Description,
			"interval", sc.Interval.String(), "user", user)
		writeJSON(w, http.StatusOK, map[string]string{"schedule": sc.ID})
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown schedule kind")
	}
}

func (h *Handler) handleDiscoveryCancel(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.NotFound(w, r)
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
	if err := h.discovery.Cancel(ctx, in.ID); err != nil {
		h.answerDiscoveryError(w, "cancel discovery", err)
		return
	}
	h.log.Info("audit", "kind", "discovery_cancelled", "job", in.ID, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleDiscoveryImport(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		ID        string   `json:"id"`
		Addresses []string `json:"addresses"`
		All       bool     `json:"all"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if len(in.Addresses) > discoveryjob.MaxHosts {
		writeJSONError(w, http.StatusBadRequest, "too many addresses")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	rep, err := h.discovery.Import(ctx, webUser(r), in.ID, in.Addresses, in.All)
	if err != nil {
		h.answerDiscoveryError(w, "import discovery", err)
		return
	}
	h.log.Info("audit", "kind", "discovery_imported", "job", in.ID, "created", strings.Join(rep.Created, ","), "updated", strings.Join(rep.Updated, ","),
		"skipped", len(rep.Skipped), "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]any{"created": rep.Created, "updated": rep.Updated, "skipped": rep.Skipped})
}

func (h *Handler) handleDiscoveryScheduleDelete(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		http.NotFound(w, r)
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
	if err := h.discovery.DeleteSchedule(ctx, in.ID); err != nil {
		h.answerDiscoveryError(w, "delete discovery schedule", err)
		return
	}
	h.log.Info("audit", "kind", "discovery_schedule_deleted", "schedule", in.ID, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
