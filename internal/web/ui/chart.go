// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// chartContainer is one container box of the org chart, from the latest
// stored docker.list result.
type chartContainer struct {
	// Name is the container name.
	Name string
	// Image is the image:tag.
	Image string
	// State is the docker state (running, exited, ...).
	State string
	// StateClass is the badge CSS class for the state.
	StateClass string
	// Health is the docker health state (healthy, unhealthy, starting),
	// "" when the container has no health check.
	Health string
	// HealthClass is the badge CSS class for the health state.
	HealthClass string
	// Project is the Compose project name, "" for standalone.
	Project string
}

// chartGroup is one column of container boxes: a Compose project (Name
// set, in a light frame) or the standalone containers (Name empty).
type chartGroup struct {
	// Name is the Compose project name, "" for standalone.
	Name string
	// Containers are the group's containers, in stored order.
	Containers []chartContainer
}

// chartHost is one host column of the org chart.
type chartHost struct {
	// ID is the host ID.
	ID string
	// DisplayName is the host's display name.
	DisplayName string
	// OS is the PRETTY_NAME from the latest core.facts, "" if unknown.
	OS string
	// StateLabel is the ops state text, StateClass its dot CSS class.
	StateLabel string
	StateClass string
	// PatchText is the patch state ("⬆ n", "✓" or "unknown"),
	// PatchClass its badge CSS class.
	PatchText  string
	PatchClass string
	// ContainerCount is the number of stored containers.
	ContainerCount int
	// Groups are the container groups in first-seen order: Compose
	// projects (Name set) and, last, the standalone containers.
	Groups []chartGroup
	// Expanded opens the subtree by default (hosts with problems).
	Expanded bool
	// WorstClass is the border colour class: critical (unreachable),
	// warning (updates pending) or neutral.
	WorstClass string
}

// chartData is the /inventory/chart page data.
type chartData struct {
	// Unavailable is true when the host list could not be read.
	Unavailable bool
	// Hosts are the host columns, in inventory order.
	Hosts []chartHost
}

// chartHosts builds the org chart columns from the batch reads.
func (h *Handler) chartHosts(ctx context.Context, hosts []inventory.Host, pins map[string]*pb.HostKeyPin, pinsUnavailable bool, b batchData) []chartHost {
	out := make([]chartHost, 0, len(hosts))
	for _, host := range hosts {
		v := viewHost(host, pins, pinsUnavailable, b, time.Now())
		ch := chartHost{
			ID:             host.ID,
			DisplayName:    v.DisplayName,
			OS:             v.OS,
			StateLabel:     v.StateLabel,
			StateClass:     v.StateClass,
			ContainerCount: v.ContainersTotal,
		}
		switch {
		case v.UpdatesChecked.IsZero():
			ch.PatchText, ch.PatchClass = "unknown", "badge--unknown"
		case v.UpdatesTotal > 0:
			ch.PatchText = "⬆ " + strconv.Itoa(v.UpdatesTotal)
			ch.PatchClass = "badge--warning"
		default:
			ch.PatchText, ch.PatchClass = "✓", "badge--ok"
		}
		// Border colour = worst state: red unreachable, yellow
		// updates pending, grey otherwise.
		switch {
		case v.StateFilter == "critical":
			ch.WorstClass = "chart__node--critical"
		case v.UpdatesTotal > 0 || v.FailedServices > 0:
			ch.WorstClass = "chart__node--warning"
		default:
			ch.WorstClass = "chart__node--neutral"
		}
		// Problem hosts open by default, the rest collapsed.
		ch.Expanded = ch.WorstClass != "chart__node--neutral"
		if row, ok := b.docker[host.ID]; ok {
			if list, err := dockerhost.ParseList(row.Result); err == nil {
				// Compose projects keep first-seen order; the
				// standalone containers form the last group.
				index := map[string]int{}
				var standalone []chartContainer
				for _, c := range list.Containers {
					cv := chartContainer{Name: c.Name, Image: c.Image, State: c.State,
						StateClass: containerStateClass(c.State), Health: c.Health,
						HealthClass: containerHealthClass(c.Health), Project: c.Project}
					if c.Project == "" {
						standalone = append(standalone, cv)
						continue
					}
					if i, ok := index[c.Project]; ok {
						ch.Groups[i].Containers = append(ch.Groups[i].Containers, cv)
						continue
					}
					index[c.Project] = len(ch.Groups)
					ch.Groups = append(ch.Groups, chartGroup{Name: c.Project, Containers: []chartContainer{cv}})
				}
				if len(standalone) > 0 {
					ch.Groups = append(ch.Groups, chartGroup{Containers: standalone})
				}
			}
		}
		out = append(out, ch)
	}
	return out
}

// handleInventoryChart renders the read-only org chart (ADR 0006, P1-18):
// managed hosts left-to-right, each host's stored Docker containers in a
// column beside it. It only shows data NOS already has.
func (h *Handler) handleInventoryChart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	data := pageData{Title: "Inventory chart", Active: "chart", Content: "chart"}
	if h.hosts == nil {
		h.render(w, r, data)
		return
	}
	hosts, err := h.hosts(ctx)
	if err != nil {
		data.Chart = &chartData{Unavailable: true}
		h.render(w, r, data)
		return
	}
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	b := h.batchData(ctx)
	data.Chart = &chartData{Hosts: h.chartHosts(ctx, hosts, pins, pinsUnavailable, b)}
	h.render(w, r, data)
}
