// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// b64 base64-encodes a string for the host telemetry docs.
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// metricsDoc builds a host.metrics result (format host-metrics-v1). cpu,
// mem and disk are the decoded field values ("" means unavailable).
func metricsDoc(t *testing.T, cpu, mem, disk string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"format": "host-metrics-v1",
		"phase":  "done",
		"reason": "",
		"cpu":    b64(cpu),
		"load":   "",
		"mem":    b64(mem),
		"disk":   b64(disk),
	})
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	return doc
}

// fsListDoc builds a filesystem.list result (format fs-list-v1) from
// tab-separated "fstype\tmount\tsize\tused" lines.
func fsListDoc(t *testing.T, lines ...string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"format": "fs-list-v1",
		"phase":  "done",
		"reason": "",
		"mounts": b64(strings.Join(lines, "\n")),
	})
	if err != nil {
		t.Fatalf("marshal fs list: %v", err)
	}
	return doc
}

// indicatorHandler builds a chart handler with one host carrying the given
// metrics and filesystem docs, observed at a fixed time (so staleness is
// deterministic).
func indicatorHandler(t *testing.T, hostID string, metrics, fs []byte, observed time.Time) *ui.Handler {
	t.Helper()
	host := inventory.Host{ID: hostID, DisplayName: hostID, Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium}
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states: map[string]executions.OpsState{
			hostID: {State: "READY", Reason: "no pending work", ObservedAt: observed},
		},
		updates: map[string]executions.HostUpdates{},
		metrics: map[string]executions.LastResultRow{},
		filesys: map[string]executions.LastResultRow{},
	}
	if metrics != nil {
		ops.metrics[hostID] = executions.LastResultRow{Result: metrics, FinishedAt: observed}
	}
	if fs != nil {
		ops.filesys[hostID] = executions.LastResultRow{Result: fs, FinishedAt: observed}
	}
	var log strings.Builder
	return newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return []inventory.Host{host}, nil },
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
		Now:          func() time.Time { return observed },
	})
}

// TestChartIndicatorThresholdClasses: the meter colour class follows the
// ADR 0006 P1-34 thresholds (>=90 crit, >=70 warn, else ok).
func TestChartIndicatorThresholdClasses(t *testing.T) {
	observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	// CPU 10% (ok), RAM 75% (warn), disk 95% (crit).
	metrics := metricsDoc(t, "10", "750 1000", "/\t95\t100")
	fs := fsListDoc(t, "ext4\t/\t100\t95")
	body := getBody(t, indicatorHandler(t, "web", metrics, fs, observed).Handler(), "/inventory/chart")
	for _, want := range []string{
		`chart__ind-meter--ok`,   // CPU 10%
		`chart__ind-meter--warn`, // RAM 75%
		`chart__ind-meter--crit`, // disk 95%
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing meter class %q", want)
		}
	}
}

// TestChartIndicatorUnknownRendersWord: a host with no metrics renders the
// word "unknown" and no meter, never a 0 % fill (review focus).
func TestChartIndicatorUnknownRendersWord(t *testing.T) {
	observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	body := getBody(t, indicatorHandler(t, "web", nil, nil, observed).Handler(), "/inventory/chart")
	if !strings.Contains(body, `chart__ind-cur">unknown`) {
		t.Error("unknown indicator should render the word 'unknown'")
	}
	if strings.Contains(body, `chart__ind-meter`) {
		t.Error("unknown indicator should not render a meter")
	}
}

// TestChartIndicatorEscapesHostileMount: a mount point carrying a script
// tag is escaped in the filesystem details list (XSS-safe).
func TestChartIndicatorEscapesHostileMount(t *testing.T) {
	observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	metrics := metricsDoc(t, "10", "750 1000", "/\t95\t100")
	fs := fsListDoc(t, "ext4\t/<script>alert(1)</script>\t100\t95")
	body := getBody(t, indicatorHandler(t, "web", metrics, fs, observed).Handler(), "/inventory/chart")
	if !strings.Contains(body, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
		t.Error("hostile mount not escaped")
	}
	if strings.Contains(body, `<script>alert(1)`) {
		t.Error("hostile mount rendered as markup")
	}
}

// TestChartFilesystemListFocusable: the filesystem details list opens on
// hover AND keyboard focus (tabindex="0" trigger, role="list"), no JS.
func TestChartFilesystemListFocusable(t *testing.T) {
	observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	metrics := metricsDoc(t, "10", "750 1000", "/\t95\t100")
	fs := fsListDoc(t, "ext4\t/\t100\t95")
	body := getBody(t, indicatorHandler(t, "web", metrics, fs, observed).Handler(), "/inventory/chart")
	if !strings.Contains(body, `chart__fs__trigger" tabindex="0"`) {
		t.Error("filesystem trigger should be focusable (tabindex=0)")
	}
	if !strings.Contains(body, `role="list"`) {
		t.Error("filesystem list should have role=list")
	}
}

// TestChartIndicatorAvgDashWhenNil: managed hosts have no 24-h buckets, so
// the 24-h average renders the dash placeholder, never a number.
func TestChartIndicatorAvgDashWhenNil(t *testing.T) {
	observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	metrics := metricsDoc(t, "10", "750 1000", "/\t95\t100")
	fs := fsListDoc(t, "ext4\t/\t100\t95")
	body := getBody(t, indicatorHandler(t, "web", metrics, fs, observed).Handler(), "/inventory/chart")
	if !strings.Contains(body, `chart__ind-avg" title="24-h average">–`) {
		t.Error("24-h average should render the dash placeholder when nil")
	}
}
