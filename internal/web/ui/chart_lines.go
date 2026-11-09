// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/gpuhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/servicecheck"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
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
	// LineCVE is the image-scan CVE count line of a host box
	// (image.vulnerabilities).
	LineCVE = "cve"
	// LineLatency is the service-check outcome and latency line of a host
	// box (service.check).
	LineLatency = "latency"
	// LineBackup is the backup freshness line of a PVE guest box (P1-29).
	LineBackup = "backup"
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
	// URL is an optional NOS-built link for the line (the
	// vulnerabilities page of a Hermes line, VU-12); "" for none.
	URL string
}

// chartResults are the stored action results the extra lines read, fetched
// once per page (never once per host). A nil map means the source is not
// available: its lines are hidden.
type chartResults struct {
	pci   map[string]executions.LastResultRow
	gpu   map[string]executions.LastResultRow
	stats map[string]executions.LastResultRow
	vulns map[string]executions.LastResultRow
	svc   map[string]executions.LastResultRow
	// hermes is the finding store view (VU-12); nil without a
	// vulnerabilities backend, which hides the Hermes lines.
	hermes *chartVulnIndex
}

// loadChartResults reads the extra-line sources. A nil operations service
// or a read error leaves the map nil, which hides the lines.
func (h *Handler) loadChartResults(ctx context.Context) chartResults {
	r := chartResults{hermes: h.loadChartVulns(ctx)}
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
	r.vulns = read("image.vulnerabilities")
	r.svc = read("service.check")
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

// shortImageRef shortens a digest reference ("repo@sha256:<64 hex>") to
// the repository and the first 12 digest digits.
func shortImageRef(ref string) string {
	repo, digest, ok := strings.Cut(ref, "@sha256:")
	if !ok || len(digest) < 12 {
		return ref
	}
	return repo + "@" + digest[:12]
}

// cveLine builds the image-scan line of a host box from its stored
// image.vulnerabilities result (ADR 0006 P1-30/P1-34): counts by severity
// of the scanned image. No result (or a malformed one) hides the line. A
// scan that did not complete (no Trivy, old database, failed, busy, ...)
// is "scan unknown" — never zero CVEs; an old result is "stale". Critical
// CVEs are critical, high ones a warning. Severity counts alone do not
// imply exploitability; the details (platform, database age, coverage)
// are in the title. It also returns the scanned image reference ("" when
// none), for the Hermes source selection of the CVE place (VU-12).
func cveLine(r *executions.LastResultRow, now time.Time, staleAfter time.Duration) ([]chartLine, string) {
	if r == nil || len(r.Result) == 0 {
		return nil, ""
	}
	v, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		return nil, ""
	}
	l := chartLine{Kind: LineCVE, Label: trivyLocalChartLabel}
	img := "image"
	if v.Image != "" {
		img = shortImageRef(v.Image)
		l.Title = v.Image
	}
	switch {
	case v.Phase != "done":
		l.Text = img + " · scan unknown (not run)"
		l.State = StateUnknown
	case v.Status == dockerhost.VulnsStale:
		l.Text = img + " · scan stale (database old)"
		l.State = StateStale
	case v.Status != dockerhost.VulnsOK:
		l.Text = img + " · scan unknown (" + v.Status + ")"
		l.State = StateUnknown
	case isStale(r.FinishedAt, now, staleAfter):
		l.Text = img + " · scan stale"
		l.State = StateStale
	default:
		crit, high := v.Severity["CRITICAL"], v.Severity["HIGH"]
		l.Text = fmt.Sprintf("%s · %d critical · %d high · %d medium · %d low", img,
			crit, high, v.Severity["MEDIUM"], v.Severity["LOW"])
		switch {
		case crit > 0:
			l.State = StateCrit
		case high > 0:
			l.State = StateWarn
		default:
			l.State = StateOK
		}
		details := []string{fmt.Sprintf("%d total", v.Total), fmt.Sprintf("%d targets", v.Targets)}
		if v.Platform != "" {
			details = append(details, v.Platform)
		}
		if v.DBAgeH != nil {
			details = append(details, fmt.Sprintf("database %d h old", *v.DBAgeH))
		}
		if v.Cached {
			details = append(details, "cached")
		}
		if l.Title != "" {
			details = append([]string{l.Title}, details...)
		}
		l.Title = strings.Join(details, " · ")
	}
	return []chartLine{l}, v.Image
}

// latencyLine builds the service-check line of a host box from its stored
// service.check result (ADR 0006 P1-27/P1-34): the probe outcome and its
// latency, distinct from systemd/Docker runtime state. No result (no
// check configured) or a result that is not the fixed contract hides the
// line. An old result is "stale". A redirect is a warning; an HTTP error
// or a failed probe (refused, timeout, ...) is critical. The result only
// carries the fixed status, latency and HTTP code — no host text.
func latencyLine(r *executions.LastResultRow, now time.Time, staleAfter time.Duration) []chartLine {
	if r == nil || len(r.Result) == 0 {
		return nil
	}
	res, err := servicecheck.ParseResult(r.Result)
	if err != nil {
		return nil
	}
	l := chartLine{Kind: LineLatency, Label: "Service", Title: "latest service check"}
	ms := fmt.Sprintf("%d ms", res.Latency.Milliseconds())
	switch res.Status {
	case servicecheck.StatusOK:
		l.Text = "ok · " + ms
		if res.HTTPStatus != 0 {
			l.Text = fmt.Sprintf("ok %d · %s", res.HTTPStatus, ms)
		}
		l.State = StateOK
	case servicecheck.StatusRedirect:
		l.Text = fmt.Sprintf("redirect %d · %s", res.HTTPStatus, ms)
		l.State = StateWarn
	case servicecheck.StatusHTTPError:
		l.Text = fmt.Sprintf("HTTP %d · %s", res.HTTPStatus, ms)
		l.State = StateCrit
	default:
		// refused, unresolved, timeout, tls-error, error: a fixed word,
		// no meaningful latency.
		l.Text = string(res.Status)
		l.State = StateCrit
	}
	if isStale(r.FinishedAt, now, staleAfter) {
		l.Text = string(res.Status) + " · stale"
		l.State = StateStale
	}
	return []chartLine{l}
}

// maxChartBackupReads bounds the per-guest backup freshness reads of one
// chart page (each is a few store queries). Guests beyond it show "backup
// unknown (not loaded)", never a healthy state.
const maxChartBackupReads = 200

// chartBackupReader is the optional backup freshness read of the PVE store
// (ADR 0006 P1-29). The chart uses it when the configured store provides
// it; otherwise the backup lines are hidden.
type chartBackupReader interface {
	GuestBackupFreshness(ctx context.Context, remoteID string, vmid, generation uint64, maxAge time.Duration) (pveinventory.Freshness, error)
}

// backupConfidenceText summarizes the three confidence channels, kept
// separate: a count alone never implies restore safety.
func backupConfidenceText(f pveinventory.Freshness) string {
	catalog := "absent"
	if f.Catalog.Present {
		catalog = "present"
	}
	verified := string(f.Verification.State)
	if verified == "" {
		verified = string(pvecontract.Unknown)
	}
	return fmt.Sprintf("tasks %d · catalog %s · verified %s", f.Task.Count, catalog, verified)
}

// backupLine builds the backup freshness line of a PVE guest box from the
// P1-29 verdict: ok, overdue and failed (both warnings), stale evidence,
// expected off, unknown. Unknown is never safe. The reason (which may
// carry stored PVE text) and the confidence channels are in the title.
func backupLine(f pveinventory.Freshness, now time.Time) chartLine {
	l := chartLine{Kind: LineBackup, Label: "Backup"}
	last := ""
	if f.LastSuccessUnix > 0 {
		last = ageText(now, time.Unix(f.LastSuccessUnix, 0))
	}
	switch f.State {
	case pveinventory.FreshnessOK:
		l.Text, l.State = "ok", StateOK
		if last != "" {
			l.Text = "ok · last " + last
		}
	case pveinventory.FreshnessOverdue:
		l.Text, l.State = "overdue · no successful backup", StateWarn
		if last != "" {
			l.Text = "overdue · last " + last
		}
	case pveinventory.FreshnessFailed:
		l.Text, l.State = "failed", StateWarn
		if last != "" {
			l.Text = "failed · last success " + last
		}
	case pveinventory.FreshnessStaleData:
		l.Text, l.State = "backup data stale", StateStale
	case pveinventory.FreshnessExpectedOff:
		l.Text, l.State = "expected off", StateOK
	default:
		l.Text, l.State = "backup unknown", StateUnknown
	}
	l.Title = backupConfidenceText(f)
	if f.Reason != "" {
		l.Title = f.Reason + " · " + l.Title
	}
	return l
}

// maxChartGuestConfigReads bounds the per-guest config reads of one chart
// page for the passthrough lines; guests beyond it get no passthrough
// line (the guest box itself is unaffected).
const maxChartGuestConfigReads = 200

// nvidiaVendor is NVIDIA's PCI vendor ID.
const nvidiaVendor = "10de"

// chartGuestConfigReader is the optional stored guest config read of the
// PVE store. The chart uses it for the hostpci passthrough lines when the
// configured store provides it; otherwise those lines are hidden.
type chartGuestConfigReader interface {
	GetGuestConfig(ctx context.Context, remoteID string, vmid, generation uint64) (pveinventory.GuestConfig, error)
}

// passthroughLines builds the node-box lines for a guest's NVIDIA hostpci
// passthrough devices (ADR 0006 P1-34: "GPU → guest (VMID)"). The device
// is named by its PCI vendor:device ID (the node's own pci.inventory is
// not linked to the PVE node); the node has no driver for a passed-through
// device, so the line says so and never implies host telemetry. Non-NVIDIA
// devices are left out; an old config is stale.
func passthroughLines(cfg pveinventory.GuestConfig, g pveGuestView, now time.Time, staleAfter time.Duration) []chartLine {
	var lines []chartLine
	for _, p := range cfg.HostPCI {
		// Device is validated on ingest as PCI-vvvv:dddd:bb:dd.f.
		rest, ok := strings.CutPrefix(p.Device, "PCI-")
		if !ok {
			continue
		}
		parts := strings.SplitN(rest, ":", 3)
		if len(parts) != 3 || parts[0] != nvidiaVendor {
			continue
		}
		l := chartLine{
			Kind:  LineGPU,
			Label: "GPU",
			Text:  fmt.Sprintf("NVIDIA %s:%s (%s) → %s (%d) · passthrough, no host telemetry", parts[0], parts[1], parts[2], g.Name, g.VMID),
			Title: p.ID + " " + p.Device,
			State: StateUnknown,
		}
		if isStale(cfg.ObservedAt, now, staleAfter) {
			l.Text = fmt.Sprintf("NVIDIA %s:%s (%s) → %s (%d) · config stale", parts[0], parts[1], parts[2], g.Name, g.VMID)
			l.State = StateStale
		}
		lines = append(lines, l)
	}
	return lines
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
// order: GPUs, image CVEs (P1-30 or Hermes, VU-12), Hermes host findings,
// service check.
func hostLines(res chartResults, hostID string, now time.Time) []chartLine {
	var lines []chartLine
	lines = append(lines, gpuLines(rowFor(res.pci, hostID), rowFor(res.gpu, hostID), now, indicatorStaleAfter)...)
	lines = append(lines, cvePlaceLines(res, hostID, now)...)
	lines = append(lines, res.hermes.hostLines(hostID)...)
	lines = append(lines, latencyLine(rowFor(res.svc, hostID), now, indicatorStaleAfter)...)
	return lines
}

// guestLines builds the extra lines of one PVE guest box. A guest linked
// to a managed host (reviewed link) shows that host's GPU lines: the
// guest's own driver telemetry, matched by its own PCI view, and that
// host's Hermes findings line (VU-12).
func guestLines(res chartResults, g pveGuestView, now time.Time) []chartLine {
	var lines []chartLine
	if g.HostID != "" {
		lines = append(lines, gpuLines(rowFor(res.pci, g.HostID), rowFor(res.gpu, g.HostID), now, indicatorStaleAfter)...)
		lines = append(lines, res.hermes.hostLines(g.HostID)...)
	}
	return lines
}

// addPVELines fills the guest extra lines (linked-host GPUs, backup
// freshness) and folds their states into each node's worst-state border.
// Backup lines need the optional store read; without it they are hidden.
func (h *Handler) addPVELines(ctx context.Context, nodes []pveNodeView, res chartResults, now time.Time) {
	backups, _ := h.pve.(chartBackupReader)
	configs, _ := h.pve.(chartGuestConfigReader)
	reads, configReads := 0, 0
	for i := range nodes {
		n := &nodes[i]
		worst := n.worst
		for j := range n.Guests {
			g := &n.Guests[j]
			g.Lines = guestLines(res, *g, now)
			if backups != nil {
				g.Lines = append(g.Lines, h.guestBackupLine(ctx, backups, n.remoteID, *g, now, &reads))
			}
			worst = worstState(append(lineStates(g.Lines), worst)...)
			if configs != nil && configReads < maxChartGuestConfigReads {
				configReads++
				cfg, err := configs.GetGuestConfig(ctx, n.remoteID, g.VMID, g.generation)
				if err != nil {
					// No stored config (e.g. LXC, not yet collected):
					// no passthrough line.
					continue
				}
				n.Lines = append(n.Lines, passthroughLines(cfg, *g, now, indicatorStaleAfter)...)
			}
		}
		worst = worstState(append(lineStates(n.Lines), worst)...)
		n.worst = worst
		n.WorstClass = worstClass(worst)
		n.Expanded = n.WorstClass != "chart__node--neutral"
	}
}

// guestBackupLine reads one guest's backup freshness, within the page's
// read budget. A failed read or an exhausted budget is "backup unknown";
// the error detail goes to the log only.
func (h *Handler) guestBackupLine(ctx context.Context, r chartBackupReader, remoteID string, g pveGuestView, now time.Time, reads *int) chartLine {
	unknown := func(text string) chartLine {
		return chartLine{Kind: LineBackup, Label: "Backup", Text: text, State: StateUnknown}
	}
	if *reads >= maxChartBackupReads {
		return unknown("backup unknown (not loaded)")
	}
	*reads++
	f, err := r.GuestBackupFreshness(ctx, remoteID, g.VMID, g.generation, 0)
	if err != nil {
		h.log.Warn("org chart: backup freshness read failed", "remote", remoteID, "vmid", g.VMID, "error", err)
		return unknown("backup unknown")
	}
	return backupLine(f, now)
}

// rowFor returns a pointer to host's row in m, nil when absent.
func rowFor(m map[string]executions.LastResultRow, hostID string) *executions.LastResultRow {
	row, ok := m[hostID]
	if !ok {
		return nil
	}
	return &row
}
