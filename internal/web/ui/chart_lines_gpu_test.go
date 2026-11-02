// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// linesNow is the fixed clock of the extra-line tests.
var linesNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// linesOptions builds handler options with one healthy host ("box") whose
// stored results per action are given in extra. The host has no updates
// and no indicators that warn, so its border is neutral unless an extra
// line raises it.
func linesOptions(t *testing.T, extra map[string]map[string]executions.LastResultRow) ui.Options {
	t.Helper()
	host := inventory.Host{ID: "box", DisplayName: "box", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states: map[string]executions.OpsState{
			"box": {State: "READY", Reason: "no pending work", ObservedAt: linesNow},
		},
		updates: map[string]executions.HostUpdates{},
		metrics: map[string]executions.LastResultRow{},
		filesys: map[string]executions.LastResultRow{},
		extra:   extra,
	}
	var log strings.Builder
	return ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return []inventory.Host{host}, nil },
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
		Now:          func() time.Time { return linesNow },
	}
}

// linesBody renders the chart for the given stored results.
func linesBody(t *testing.T, extra map[string]map[string]executions.LastResultRow) string {
	t.Helper()
	return getBody(t, newTestHandler(t, linesOptions(t, extra)).Handler(), "/inventory/chart")
}

// row is a stored result for one host, finished age before linesNow.
func row(result []byte, age time.Duration) executions.LastResultRow {
	return executions.LastResultRow{Result: result, FinishedAt: linesNow.Add(-age)}
}

// pciDoc builds a pci.inventory result (format pci-inventory-v1) from
// tab-separated "slot\tclass\tvendor\tdevice" lines.
func pciDoc(t *testing.T, lines ...string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"format": "pci-inventory-v1", "phase": "done", "reason": "", "present": true,
		"devices": b64(strings.Join(lines, "\n")),
	})
	if err != nil {
		t.Fatalf("marshal pci: %v", err)
	}
	return doc
}

// gpuDoc builds a gpu.status result (format gpu-status-v1) from
// nvidia-smi CSV lines.
func gpuDoc(t *testing.T, lines ...string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"format": "gpu-status-v1", "phase": "done", "reason": "", "present": true,
		"gpus": b64(strings.Join(lines, "\n")),
	})
	if err != nil {
		t.Fatalf("marshal gpu: %v", err)
	}
	return doc
}

const (
	pciA6000 = "0000:65:00.0\t3D controller\tNVIDIA Corporation [10de]\tGA102GL [RTX A6000] [10de:2230]"
	uuidA    = "GPU-12345678-1234-1234-1234-123456789abc"
)

// gpuLine is one nvidia-smi line for the A6000 at 65:00.0 with util %.
func gpuLine(util string) string {
	return "0, " + uuidA + ", 00000000:65:00.0, NVIDIA RTX A6000, " + util + ", 1024, 49140, 61, 120.5"
}

// hostNodeHas reports whether a chart node <li> carries the border class.
func hostNodeHas(body, class string) bool {
	return strings.Contains(body, `<li class="chart__node `+class+`">`)
}

func TestChartGPULineShowsTelemetryAndLevel(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"pci.inventory": {"box": row(pciDoc(t, pciA6000), time.Minute)},
		"gpu.status":    {"box": row(gpuDoc(t, gpuLine("95")), time.Minute)},
	})
	for _, want := range []string{
		`chart__line chart__line--gpu chart__line--crit`,
		`NVIDIA RTX A6000 · util 95 % · VRAM 1024/49140 MiB · 61 °C · 120 W`,
		`chart__ind-meter chart__ind-meter--crit`,
		`value="95"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing %q", want)
		}
	}
	if !hostNodeHas(body, "chart__node--critical") {
		t.Error("a GPU at 95 % util should make the box border critical")
	}
}

func TestChartGPULineWarnRaisesBorder(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"pci.inventory": {"box": row(pciDoc(t, pciA6000), time.Minute)},
		"gpu.status":    {"box": row(gpuDoc(t, gpuLine("75")), time.Minute)},
	})
	if !hostNodeHas(body, "chart__node--warning") {
		t.Error("a GPU at 75 % util should make the box border warning")
	}
}

func TestChartGPULineHiddenWithoutInventory(t *testing.T) {
	cases := map[string]map[string]map[string]executions.LastResultRow{
		"no sources": {},
		"telemetry only": {
			"gpu.status": {"box": row(gpuDoc(t, gpuLine("95")), time.Minute)},
		},
		"malformed inventory": {
			"pci.inventory": {"box": row([]byte(`{"format":"nope"}`), time.Minute)},
		},
		"no nvidia gpu": {
			"pci.inventory": {"box": row(pciDoc(t, "0000:00:02.0\tVGA compatible controller\tIntel Corporation [8086]\tUHD [8086:3e92]"), time.Minute)},
		},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			body := linesBody(t, extra)
			if strings.Contains(body, "chart__line--gpu") {
				t.Error("GPU line rendered without a usable pci.inventory")
			}
			if !hostNodeHas(body, "chart__node--neutral") {
				t.Error("border should stay neutral without GPU lines")
			}
		})
	}
}

func TestChartGPULineUnknownAndStaleLabels(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]map[string]executions.LastResultRow
		want  []string
	}{
		{"telemetry missing", map[string]map[string]executions.LastResultRow{
			"pci.inventory": {"box": row(pciDoc(t, pciA6000), time.Minute)},
		}, []string{`chart__line--gpu chart__line--unknown`, `· telemetry unknown`}},
		{"passed through, no driver", map[string]map[string]executions.LastResultRow{
			"pci.inventory": {"box": row(pciDoc(t, pciA6000), time.Minute)},
			"gpu.status":    {"box": row(gpuDoc(t), time.Minute)},
		}, []string{`chart__line--gpu chart__line--unknown`, `· no driver telemetry`}},
		{"telemetry stale", map[string]map[string]executions.LastResultRow{
			"pci.inventory": {"box": row(pciDoc(t, pciA6000), time.Minute)},
			"gpu.status":    {"box": row(gpuDoc(t, gpuLine("95")), 25*time.Hour)},
		}, []string{`chart__line--gpu chart__line--stale`, `NVIDIA RTX A6000 · stale`}},
		{"inventory stale", map[string]map[string]executions.LastResultRow{
			"pci.inventory": {"box": row(pciDoc(t, pciA6000), 25*time.Hour)},
			"gpu.status":    {"box": row(gpuDoc(t, gpuLine("95")), time.Minute)},
		}, []string{`chart__line--gpu chart__line--stale`, `· inventory stale`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := linesBody(t, tc.extra)
			for _, w := range tc.want {
				if !strings.Contains(body, w) {
					t.Errorf("chart body missing %q", w)
				}
			}
			if strings.Contains(body, `chart__ind-meter--crit`) {
				t.Error("unknown/stale GPU line must not render a level meter")
			}
			if !hostNodeHas(body, "chart__node--neutral") {
				t.Error("unknown/stale GPU line must not raise the border")
			}
		})
	}
}

func TestChartGPULineEscapesHostText(t *testing.T) {
	hostile := "0000:65:00.0\t3D controller\tNVIDIA Corporation [10de]\t<script>alert(1)</script>"
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"pci.inventory": {"box": row(pciDoc(t, hostile), time.Minute)},
		"gpu.status": {"box": row(gpuDoc(t,
			"0, "+uuidA+", 00000000:65:00.0, <img src=x onerror=alert(2)>, 10, 1, 2, 3, 4"), time.Minute)},
	})
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "<img src=x") {
		t.Error("host GPU text rendered as markup")
	}
	if !strings.Contains(body, "&lt;img src=x onerror=alert(2)&gt;") {
		t.Error("hostile GPU name not escaped in the line")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("hostile PCI device name not escaped in the title")
	}
}

// TestChartGPULineOnLinkedGuest: a PVE guest linked to a managed host
// shows that host's GPU telemetry, and the node border includes it; an
// unlinked guest shows none.
func TestChartGPULineOnLinkedGuest(t *testing.T) {
	tree := pveinventory.Tree{Roots: []pveinventory.Box{{
		Kind: pveinventory.KindPVENode, Name: "pve1", RemoteID: "lab",
		State: pveinventory.StateOK, Worst: pveinventory.StateOK,
		Children: []pveinventory.Box{
			{Kind: pveinventory.KindGuest, Name: "bigai", VMID: 101, Generation: 1, HostID: "bigai", State: pveinventory.StateOK, Worst: pveinventory.StateOK},
			{Kind: pveinventory.KindGuest, Name: "plain", VMID: 102, Generation: 1, State: pveinventory.StateOK, Worst: pveinventory.StateOK},
		},
	}}}
	o := linesOptions(t, map[string]map[string]executions.LastResultRow{
		"pci.inventory": {"bigai": row(pciDoc(t, pciA6000), time.Minute)},
		"gpu.status":    {"bigai": row(gpuDoc(t, gpuLine("80")), time.Minute)},
	})
	o.PVEChart = func(context.Context) (pveinventory.Tree, error) { return tree, nil }
	body := getBody(t, newTestHandler(t, o).Handler(), "/inventory/chart")
	if got := strings.Count(body, "chart__line--gpu"); got != 1 {
		t.Errorf("GPU lines = %d, want 1 (linked guest only)", got)
	}
	if !hostNodeHas(body, "chart__node--warning") {
		t.Error("node border should include the guest GPU warning")
	}
}
