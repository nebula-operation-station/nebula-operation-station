// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/gpuhost"
)

// Extra line kinds of an org-chart box (ADR 0006 P1-34 part 3). Only this
// fixed set ever reaches a class attribute.
const (
	// LineGPU is one NVIDIA GPU of the box's machine (pci.inventory +
	// gpu.status).
	LineGPU = "gpu"
	// LineStats is the runtime stats line of a container box
	// (docker.stats).
	LineStats = "stats"
)

// chartLine is one optional extra line of an org-chart box (GPU, CVE,
// backup, service latency). A line exists only when its data source has a
// usable result; a missing source hides the line. Unknown and stale data
// carry an explicit word in Text, never a healthy-looking value.
type chartLine struct {
	// Kind is the line kind (one of the Line* constants); it is part of
	// the CSS class.
	Kind string
	// Label is the short line label ("GPU", "CVE", ...).
	Label string
	// Text is the line value (host text inside is rendered escaped).
	Text string
	// Title is the hover text with details (rendered escaped), "" for
	// none.
	Title string
	// State is the line state (ok, warn, crit, unknown, stale); it drives
	// the colour class and feeds the box's worst-state border.
	State IndicatorState
	// HasMeter shows a mini bar with MeterValue (0-100).
	HasMeter   bool
	MeterValue int
}

// chartResults are the stored action results the extra lines read, fetched
// once per page (never once per host). A nil map means the source is not
// available: its lines are hidden.
type chartResults struct {
	pci   map[string]executions.LastResultRow
	gpu   map[string]executions.LastResultRow
	stats map[string]executions.LastResultRow
}

// loadChartResults reads the extra-line sources. A nil operations service
// or a read error leaves the map nil, which hides the lines.
func (h *Handler) loadChartResults(ctx context.Context) chartResults {
	var r chartResults
	if h.operations == nil {
		return r
	}
	read := func(action string) map[string]executions.LastResultRow {
		m, err := h.operations.LastResults(ctx, action)
		if err != nil {
			h.log.Warn("org chart: stored results unavailable", "action", action, "error", err)
			return nil
		}
		return m
	}
	r.pci = read("pci.inventory")
	r.gpu = read("gpu.status")
	r.stats = read("docker.stats")
	return r
}

// clampPercent rounds a percentage to a whole meter value in [0, 100].
func clampPercent(v float64) int {
	p := int(v + 0.5)
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// lineStates collects the states of the lines, for worstState.
func lineStates(lines []chartLine) []IndicatorState {
	out := make([]IndicatorState, 0, len(lines))
	for _, l := range lines {
		out = append(out, l.State)
	}
	return out
}

// isStale reports whether an observation taken at observedAt is older
// than staleAfter at now. A zero observedAt is unobserved, hence stale.
func isStale(observedAt, now time.Time, staleAfter time.Duration) bool {
	return observedAt.IsZero() || now.Sub(observedAt) > staleAfter
}

// gpuMetricText formats one GPU's telemetry; missing metrics are "?",
// never zero.
func gpuMetricText(g gpuhost.GPU) string {
	util := "util ?"
	if g.UtilPercent != nil {
		util = fmt.Sprintf("util %d %%", *g.UtilPercent)
	}
	vram := "VRAM ?"
	if g.MemoryUsedMiB != nil && g.MemoryTotalMiB != nil {
		vram = fmt.Sprintf("VRAM %d/%d MiB", *g.MemoryUsedMiB, *g.MemoryTotalMiB)
	}
	temp := "? °C"
	if g.TemperatureC != nil {
		temp = fmt.Sprintf("%d °C", *g.TemperatureC)
	}
	power := "? W"
	if g.PowerW != nil {
		power = fmt.Sprintf("%.0f W", *g.PowerW)
	}
	return util + " · " + vram + " · " + temp + " · " + power
}

// gpuLines builds one line per NVIDIA GPU of a machine from its stored
// pci.inventory (the GPU identities) and gpu.status (the driver
// telemetry), matched by PCI bus ID (ADR 0006 P1-34). Without a usable
// pci.inventory there are no lines. A GPU without a matching gpu.status
// entry (passed through to a guest, no driver) says "no driver telemetry":
// host telemetry is never implied. Missing telemetry is "unknown", old
// readings "stale"; the level follows the current utilisation.
func gpuLines(pciRow, gpuRow *executions.LastResultRow, now time.Time, staleAfter time.Duration) []chartLine {
	if pciRow == nil || len(pciRow.Result) == 0 {
		return nil
	}
	inv, err := gpuhost.ParsePCIInventory(pciRow.Result)
	if err != nil || inv.Phase != "done" || !inv.Present || len(inv.Devices) == 0 {
		return nil
	}
	invStale := isStale(pciRow.FinishedAt, now, staleAfter)
	var st gpuhost.GPUStatus
	telemetry := false
	telemetryStale := false
	if gpuRow != nil && len(gpuRow.Result) > 0 {
		if parsed, err := gpuhost.ParseGPUStatus(gpuRow.Result); err == nil && parsed.Phase == "done" && parsed.Present {
			st = parsed
			telemetry = true
			telemetryStale = isStale(gpuRow.FinishedAt, now, staleAfter)
		}
	}
	lines := make([]chartLine, 0, len(inv.Devices))
	for _, d := range inv.Devices {
		l := chartLine{Kind: LineGPU, Label: "GPU", Title: "PCI " + d.Slot + " · " + d.Device}
		g, matched := gpuhost.GPU{}, false
		if telemetry {
			g, matched = st.GPUForSlot(d.Slot)
		}
		switch {
		case !telemetry:
			l.Text = d.Device + " · telemetry unknown"
			l.State = StateUnknown
		case !matched:
			l.Text = d.Device + " · no driver telemetry"
			l.State = StateUnknown
		case telemetryStale:
			l.Text = g.Name + " · stale"
			l.State = StateStale
		default:
			l.Text = g.Name + " · " + gpuMetricText(g)
			if g.UtilPercent != nil {
				l.State = levelOf(float64(*g.UtilPercent))
				l.HasMeter = true
				l.MeterValue = clampPercent(float64(*g.UtilPercent))
			} else {
				l.State = StateUnknown
			}
		}
		if invStale && l.State != StateStale {
			l.Text += " · inventory stale"
			l.State = StateStale
			l.HasMeter = false
		}
		lines = append(lines, l)
	}
	return lines
}

// containerStats is one host's parsed docker.stats snapshot, indexed by
// full container ID. ok is false when the host has no usable snapshot:
// the container stats lines are then hidden.
type containerStats struct {
	ok    bool
	stale bool
	byID  map[string]dockerhost.ContainerStats
}

// newContainerStats parses a host's stored docker.stats result.
func newContainerStats(r *executions.LastResultRow, now time.Time, staleAfter time.Duration) containerStats {
	if r == nil || len(r.Result) == 0 {
		return containerStats{}
	}
	s, err := dockerhost.ParseStats(r.Result)
	if err != nil || s.Phase != "done" || !s.Present {
		return containerStats{}
	}
	cs := containerStats{ok: true, stale: isStale(r.FinishedAt, now, staleAfter), byID: make(map[string]dockerhost.ContainerStats, len(s.Containers))}
	for _, c := range s.Containers {
		cs.byID[c.FullID] = c
	}
	return cs
}

// statsLine builds the runtime stats line of one container box (ADR 0006
// P1-34: CPU % and RAM usage as numbers). There is no line without a
// usable docker.stats snapshot, nor for a container that does not run
// (stopped containers have no stats, not zeros). A running container
// missing from the snapshot (or without a full ID to match it by) is
// "stats unknown"; an old snapshot "stale". The level follows the RAM
// share of the container's limit; CPU % is per core and carries none.
func statsLine(cs containerStats, c dockerhost.Container) []chartLine {
	if !cs.ok || !c.Running() {
		return nil
	}
	l := chartLine{Kind: LineStats, Label: "Stats"}
	st, found := cs.byID[c.FullID]
	switch {
	case c.FullID == "" || !found:
		l.Text = "stats unknown"
		l.State = StateUnknown
	case cs.stale:
		l.Text = "stats stale"
		l.State = StateStale
	default:
		cpu := "CPU ?"
		if st.CPUPercent != nil {
			cpu = "CPU " + indicatorText(*st.CPUPercent)
		}
		ram := "RAM ?"
		if st.MemUsedBytes != nil && st.MemLimitBytes != nil {
			ram = "RAM " + humanBytes(uint64(*st.MemUsedBytes)) + " / " + humanBytes(uint64(*st.MemLimitBytes))
		}
		l.Text = cpu + " · " + ram
		if st.MemPercent != nil {
			l.State = levelOf(*st.MemPercent)
			l.Title = "RAM " + indicatorText(*st.MemPercent) + " of limit"
		} else {
			l.State = StateUnknown
		}
	}
	return []chartLine{l}
}

// worstClass maps a worst state to the box border class: red for
// critical, yellow for warning, grey otherwise (unknown/stale are labelled
// on their lines and never turn the border healthy-green).
func worstClass(s IndicatorState) string {
	switch s {
	case StateCrit:
		return "chart__node--critical"
	case StateWarn:
		return "chart__node--warning"
	default:
		return "chart__node--neutral"
	}
}

// hostLines builds the extra lines of one managed host box, in display
// order: GPUs.
func hostLines(res chartResults, hostID string, now time.Time) []chartLine {
	var lines []chartLine
	lines = append(lines, gpuLines(rowFor(res.pci, hostID), rowFor(res.gpu, hostID), now, indicatorStaleAfter)...)
	return lines
}

// guestLines builds the extra lines of one PVE guest box. A guest linked
// to a managed host (reviewed link) shows that host's GPU lines: the
// guest's own driver telemetry, matched by its own PCI view.
func guestLines(res chartResults, g pveGuestView, now time.Time) []chartLine {
	var lines []chartLine
	if g.HostID != "" {
		lines = append(lines, gpuLines(rowFor(res.pci, g.HostID), rowFor(res.gpu, g.HostID), now, indicatorStaleAfter)...)
	}
	return lines
}

// addPVELines fills the guest extra lines and folds their states into
// each node's worst-state border.
func addPVELines(nodes []pveNodeView, res chartResults, now time.Time) {
	for i := range nodes {
		n := &nodes[i]
		worst := n.worst
		for j := range n.Guests {
			n.Guests[j].Lines = guestLines(res, n.Guests[j], now)
			worst = worstState(append(lineStates(n.Guests[j].Lines), worst)...)
		}
		n.worst = worst
		n.WorstClass = worstClass(worst)
		n.Expanded = n.WorstClass != "chart__node--neutral"
	}
}

// rowFor returns a pointer to host's row in m, nil when absent.
func rowFor(m map[string]executions.LastResultRow, hostID string) *executions.LastResultRow {
	row, ok := m[hostID]
	if !ok {
		return nil
	}
	return &row
}
