// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
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
	// SameTagText/SameTagClass are the same-tag status (has the
	// registry's digest for the running tag changed?).
	SameTagText  string
	SameTagClass string
	// StableText/StableClass are the stable-version status (is a newer
	// stable version tag available?), kept distinct from the same-tag
	// status.
	StableText  string
	StableClass string
	// Note is the same-tag note from docker.check_updates, rendered
	// escaped.
	Note string
	// ReleaseNotes are the notes for the stable version, rendered
	// escaped.
	ReleaseNotes string
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
	// Patch is the full OS patch state (source, list age, counts),
	// shown in the details panel and the badge.
	Patch patchStateView
	// ContainerCount is the number of stored containers.
	ContainerCount int
	// Groups are the container groups in first-seen order: Compose
	// projects (Name set) and, last, the standalone containers.
	Groups []chartGroup
	// Details is the read-only details side panel (config, snapshots,
	// updates, backups). It has no controls that change anything.
	Details chartDetails
	// Expanded opens the subtree by default (hosts with problems).
	Expanded bool
	// WorstClass is the border colour class: critical (unreachable or a
	// critical indicator), warning (updates pending or a warning
	// indicator) or neutral.
	WorstClass string
	// Indicators are the CPU/RAM/disk rows (ADR 0006 P1-34).
	Indicators []chartIndicator
	// Filesystems are the per-filesystem details rows (all real mounts);
	// nil when the host reported none.
	Filesystems []chartFilesystem
}

// kv is one key/value row in a details panel section.
type kv struct {
	// K is the label, V the value; both are rendered escaped.
	K, V string
}

// chartDetails is the server-rendered details side panel of one box
// (ADR 0006 P1-33). It is read-only: it shows stored data and plain links
// to the normal detail pages, and it has no controls that change anything.
type chartDetails struct {
	// Config is the box configuration, in display order.
	Config []kv
	// Snapshots is the snapshot summary ("none collected" or a count).
	Snapshots string
	// Backups is the backup summary ("none collected" or a count).
	Backups string
	// DetailURL links to the normal detail page (no-JS navigation).
	DetailURL string
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
	now := h.pveNow()
	// Fetch the latest stored readings once per page, not once per host.
	// A nil operations service (or a read error) leaves the maps empty:
	// the indicators then render as unknown, never as zero.
	var hostMetrics, hostFilesystems map[string]executions.LastResultRow
	if h.operations != nil {
		hostMetrics, _ = h.operations.LastResults(ctx, "host.metrics")
		hostFilesystems, _ = h.operations.LastResults(ctx, "filesystem.list")
	}
	// Registry metadata (stable version + release notes) per host, from
	// the stored registry.tags result. Absent while the registry lookup
	// is not wired; the stable version then renders "unknown".
	var registryTags map[string]executions.LastResultRow
	if h.operations != nil {
		registryTags, _ = h.operations.LastResults(ctx, "registry.tags")
	}
	out := make([]chartHost, 0, len(hosts))
	for _, host := range hosts {
		v := viewHost(host, pins, pinsUnavailable, b, now)
		patch := newPatchStateView(b.updates[host.ID], now)
		ch := chartHost{
			ID:             host.ID,
			DisplayName:    v.DisplayName,
			OS:             v.OS,
			StateLabel:     v.StateLabel,
			StateClass:     v.StateClass,
			ContainerCount: v.ContainersTotal,
			Patch:          patch,
			PatchText:      patch.Text,
			PatchClass:     patch.Class,
		}
		// CPU/RAM/disk indicators (ADR 0006 P1-34): parse the stored
		// host.metrics and filesystem.list results. Missing or unreadable
		// readings are unknown, never zero; a reading older than
		// indicatorStaleAfter is stale.
		var m hostmetrics.Metrics
		var fs hostmetrics.Filesystems
		var observedAt time.Time
		if row, ok := hostMetrics[host.ID]; ok && len(row.Result) > 0 {
			observedAt = row.FinishedAt
			if parsed, err := hostmetrics.ParseMetrics(row.Result); err == nil {
				m = parsed
			}
		}
		if row, ok := hostFilesystems[host.ID]; ok && len(row.Result) > 0 {
			if parsed, err := hostmetrics.ParseFilesystems(row.Result); err == nil {
				fs = parsed
			}
		}
		// TODO(p134c): fill Avg24h from the P1-25 24-h buckets once the
		// managed hosts have them. The chart does not load 24-h buckets
		// for managed hosts yet (the P1-25 buckets are PVE-only), so
		// hostIndicators passes nil and the 24-h average renders a dash.
		// Do not invent a data source.
		indicators := hostIndicators(m, fs, observedAt, now, indicatorStaleAfter)
		ch.Indicators = summaryIndicatorRows(indicators)
		ch.Filesystems = filesystemRows(fs)
		// Border colour = worst state: red unreachable or a critical
		// indicator, yellow updates pending or a warning indicator, grey
		// otherwise.
		var hostState IndicatorState
		switch {
		case v.StateFilter == "critical":
			hostState = StateCrit
		case v.UpdatesTotal > 0 || v.FailedServices > 0:
			hostState = StateWarn
		default:
			hostState = StateOK
		}
		worst := hostState
		for _, ind := range indicators {
			worst = worstState(worst, ind.State)
		}
		switch {
		case worst == StateCrit:
			ch.WorstClass = "chart__node--critical"
		case worst == StateWarn:
			ch.WorstClass = "chart__node--warning"
		default:
			ch.WorstClass = "chart__node--neutral"
		}
		// Problem hosts open by default, the rest collapsed.
		ch.Expanded = ch.WorstClass != "chart__node--neutral"
		// Read-only details side panel: config, snapshots, updates,
		// backups. No controls that change anything.
		os := v.OS
		if os == "" {
			os = "unknown"
		}
		ch.Details = chartDetails{
			Config: []kv{
				{"State", v.StateLabel},
				{"OS", os},
				{"Containers", strconv.Itoa(v.ContainersTotal)},
			},
			Snapshots: "none collected",
			Backups:   "none collected",
			DetailURL: "/hosts/" + host.ID,
		}
		// Same-tag status per image, from the stored check_updates
		// result; registry metadata per image for the stable version.
		var ups dockerhost.ImageUpdates
		if upRow, ok := b.dockerUp[host.ID]; ok {
			ups, _ = dockerhost.ParseImageUpdates(upRow.Result)
		}
		upByImage := map[string]dockerhost.ImageUpdate{}
		for _, iu := range ups.Images {
			upByImage[iu.Image] = iu
		}
		regByImage := map[string]registryInfo{}
		if regRow, ok := registryTags[host.ID]; ok {
			regByImage = parseRegistryHostResult(regRow.Result)
		}
		if row, ok := b.docker[host.ID]; ok {
			if list, err := dockerhost.ParseList(row.Result); err == nil {
				// Compose projects keep first-seen order; the
				// standalone containers form the last group.
				index := map[string]int{}
				var standalone []chartContainer
				for _, c := range list.Containers {
					iu := upByImage[c.Image]
					cu := newContainerUpdateView(imageTag(c.Image), iu.Status, iu.Note, regByImage[c.Image])
					cv := chartContainer{Name: c.Name, Image: c.Image, State: c.State,
						StateClass: containerStateClass(c.State), Health: c.Health,
						HealthClass: containerHealthClass(c.Health), Project: c.Project,
						SameTagText: cu.SameTagText, SameTagClass: cu.SameTagClass,
						StableText: cu.StableText, StableClass: cu.StableClass,
						Note: cu.Note, ReleaseNotes: cu.ReleaseNotes}
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
