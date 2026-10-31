// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
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
	// PVENodes are the PVE node columns with their guest and storage
	// (datastore) children, in tree order; empty when the PVE provider
	// is nil.
	PVENodes []pveNodeView
	// PVEUnavailable is true when the PVE tree could not be read.
	PVEUnavailable bool
}

// pveNodeView is one PVE node box in the org chart, with its guest and
// storage (datastore) children.
type pveNodeView struct {
	// Name is the node name (untrusted text; rendered as text only).
	Name string
	// State is the node's own state; StateClass is its dot CSS class.
	State      string
	StateClass string
	// StateReason explains the node state.
	StateReason string
	// WorstClass is the border colour class (chart__node--...).
	WorstClass string
	// Expanded opens the subtree by default (nodes with problems).
	Expanded bool
	// Stale marks a stale node observation.
	Stale bool
	// Guests are the guest boxes, in tree order.
	Guests []pveGuestView
	// Storages are the storage (datastore) boxes, sorted after the
	// guests.
	Storages []pveStorageView
}

// pveGuestView is one guest box under a PVE node.
type pveGuestView struct {
	// Name is the guest name (untrusted text; rendered as text only).
	Name string
	// VMID is the guest VMID.
	VMID uint64
	// State is the guest state; StateClass is its dot CSS class.
	State      string
	StateClass string
	// StateReason explains the guest state.
	StateReason string
	// Stale marks a stale guest observation.
	Stale bool
}

// pveStorageView is one storage (datastore) box under a PVE node.
type pveStorageView struct {
	// Name is the storage id (untrusted text; rendered as text only).
	Name string
	// TypeLabel is the type label: the storage type, or "backup
	// datastore" for Proxmox Backup Server storages.
	TypeLabel string
	// IconClass is the CSS class of the type icon.
	IconClass string
	// Shared marks a cluster-shared datastore.
	Shared bool
	// HasPercent is false when the fill level is unknown; the box then
	// shows "unknown", never 0 percent.
	HasPercent bool
	// UsedPercent is the used percentage, clamped to [0, 100].
	UsedPercent int
	// TotalText is the human-readable total capacity.
	TotalText string
	// State is the storage state (ok, warning, critical, unknown); it
	// drives the box border and bar colour.
	State string
	// StateReason explains the storage state.
	StateReason string
	// Stale marks a stale storage observation.
	Stale bool
}

// pveStateClass maps a PVE box state to its dot badge CSS class. "off"
// has no badge of its own and uses the unknown (grey) one.
func pveStateClass(state string) string {
	if state == string(pveinventory.StateOff) {
		return "badge--unknown"
	}
	return "badge--" + state
}

// storageTypeLabel is the type label of a storage box: the storage
// type, or "backup datastore" for Proxmox Backup Server storages.
func storageTypeLabel(backup bool, stype string) string {
	if backup {
		return "backup datastore"
	}
	return stype
}

// storageIconClass maps a storage type to the CSS class of its icon.
// The type is untrusted text; only this fixed set of suffixes ever
// reaches the class attribute, everything else uses the generic icon.
func storageIconClass(stype string) string {
	switch stype {
	case "dir", "lvm", "lvmthin", "zfspool", "nfs", "cifs", "pbs", "rbd", "iscsi", "vbds":
		return "chart__storage-icon--" + stype
	default:
		return "chart__storage-icon--other"
	}
}

// humanBytes renders a byte count as a compact display value
// ("512 GiB", "512 MiB", "123 B").
func humanBytes(b uint64) string {
	const gib = uint64(1024 * 1024 * 1024)
	const mib = uint64(1024 * 1024)
	switch {
	case b >= gib && b%gib == 0:
		return fmt.Sprintf("%d GiB", b/gib)
	case b >= gib:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(gib))
	case b >= mib && b%mib == 0:
		return fmt.Sprintf("%d MiB", b/mib)
	case b >= mib:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// pveTreeToView converts the PVE roots of the org-chart tree into
// chart views. Non-PVE roots (managed hosts) are skipped: the chart
// renders those from the inventory.
func pveTreeToView(tree pveinventory.Tree) []pveNodeView {
	out := make([]pveNodeView, 0, len(tree.Roots))
	for _, r := range tree.Roots {
		if r.Kind != pveinventory.KindPVENode {
			continue
		}
		n := pveNodeView{
			Name:        r.Name,
			State:       string(r.State),
			StateClass:  pveStateClass(string(r.State)),
			StateReason: r.StateReason,
			Stale:       r.Stale,
		}
		switch r.Worst {
		case pveinventory.StateCritical:
			n.WorstClass = "chart__node--critical"
		case pveinventory.StateWarning:
			n.WorstClass = "chart__node--warning"
		default:
			n.WorstClass = "chart__node--neutral"
		}
		n.Expanded = n.WorstClass != "chart__node--neutral"
		for _, c := range r.Children {
			switch c.Kind {
			case pveinventory.KindGuest:
				n.Guests = append(n.Guests, pveGuestView{
					Name:        c.Name,
					VMID:        c.VMID,
					State:       string(c.State),
					StateClass:  pveStateClass(string(c.State)),
					StateReason: c.StateReason,
					Stale:       c.Stale,
				})
			case pveinventory.KindStorage:
				n.Storages = append(n.Storages, pveStorageView{
					Name:        c.Name,
					TypeLabel:   storageTypeLabel(c.StorageBackup, c.StorageType),
					IconClass:   storageIconClass(c.StorageType),
					Shared:      c.StorageShared,
					HasPercent:  c.State != pveinventory.StateUnknown,
					UsedPercent: c.StorageFillPercent,
					TotalText:   humanBytes(c.StorageTotalBytes),
					State:       string(c.State),
					StateReason: c.StateReason,
					Stale:       c.Stale,
				})
			}
		}
		out = append(out, n)
	}
	return out
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
	// PVE section: node boxes with guest and storage (datastore)
	// children. A nil provider hides the section; an error shows
	// "PVE unavailable" (the detail goes to the log only).
	if h.pveChart != nil {
		tree, err := h.pveChart(ctx)
		if err != nil {
			h.log.Error("org chart: PVE tree failed", "error", err)
			data.Chart.PVEUnavailable = true
		} else {
			data.Chart.PVENodes = pveTreeToView(tree)
		}
	}
	h.render(w, r, data)
}
