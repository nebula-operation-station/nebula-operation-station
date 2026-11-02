// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
)

// TestIndicatorRowUnknownRendersWord pins the review focus: a missing
// reading renders the word "unknown", never a 0 % value (ADR 0006 P1-34).
func TestIndicatorRowUnknownRendersWord(t *testing.T) {
	ind := Indicator{Kind: IndicatorCPU, Label: "CPU", State: StateUnknown}
	row := indicatorRow(ind)
	if row.CurrentText != "unknown" {
		t.Errorf("current = %q, want \"unknown\"", row.CurrentText)
	}
	if row.HasValue {
		t.Error("unknown indicator must not carry a meter value")
	}
	if row.MeterValue != 0 {
		t.Errorf("meter value = %d, want 0 (no fill)", row.MeterValue)
	}
}

// TestIndicatorRowStaleKeepsMeterButShowsWord: a stale reading keeps its
// meter fill but shows the word "stale" instead of the number.
func TestIndicatorRowStaleKeepsMeterButShowsWord(t *testing.T) {
	v := 55.0
	ind := Indicator{Kind: IndicatorRAM, Label: "RAM", Current: &v, State: StateStale}
	row := indicatorRow(ind)
	if row.CurrentText != "stale" {
		t.Errorf("current = %q, want \"stale\"", row.CurrentText)
	}
	if !row.HasValue {
		t.Error("stale indicator must keep its meter value")
	}
	if row.MeterValue != 55 {
		t.Errorf("meter value = %d, want 55", row.MeterValue)
	}
}

// TestIndicatorRowAvgShownWhenPresent: a present 24-h average renders its
// value, not the dash placeholder.
func TestIndicatorRowAvgShownWhenPresent(t *testing.T) {
	v, avg := 82.0, 75.4
	ind := Indicator{Kind: IndicatorCPU, Label: "CPU", Current: &v, Avg24h: &avg, State: StateCrit}
	row := indicatorRow(ind)
	if row.AvgText != "75 %" {
		t.Errorf("avg = %q, want \"75 %%\"", row.AvgText)
	}
	if row.CurrentText != "82 %" {
		t.Errorf("current = %q, want \"82 %%\"", row.CurrentText)
	}
}

// TestIndicatorRowAvgDashWhenNil: a nil 24-h average renders the dash
// placeholder, never a number.
func TestIndicatorRowAvgDashWhenNil(t *testing.T) {
	v := 82.0
	ind := Indicator{Kind: IndicatorCPU, Label: "CPU", Current: &v, State: StateCrit}
	row := indicatorRow(ind)
	if row.AvgText != "–" {
		t.Errorf("avg = %q, want dash \"–\"", row.AvgText)
	}
}

// TestIndicatorRowMeterClamped: values outside [0,100] are clamped so the
// meter attribute stays valid.
func TestIndicatorRowMeterClamped(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want int
	}{
		{-5, 0},
		{0, 0},
		{100, 100},
		{150, 100},
	} {
		v := tc.in
		ind := Indicator{Kind: IndicatorCPU, Label: "CPU", Current: &v, State: StateOK}
		row := indicatorRow(ind)
		if row.MeterValue != tc.want {
			t.Errorf("meter(%v) = %d, want %d", tc.in, row.MeterValue, tc.want)
		}
	}
}

// TestSummaryIndicatorRowsSelectsThreeRows: the summary picks CPU, RAM and
// the fullest disk (Label "Disk"), skipping the per-filesystem rows.
func TestSummaryIndicatorRowsSelectsThreeRows(t *testing.T) {
	indicators := []Indicator{
		{Kind: IndicatorCPU, Label: "CPU", State: StateOK},
		{Kind: IndicatorRAM, Label: "RAM", State: StateOK},
		{Kind: IndicatorDisk, Label: "Disk", State: StateOK},
		{Kind: IndicatorDisk, Label: "Disk /var", State: StateOK},
		{Kind: IndicatorDisk, Label: "Disk /home", State: StateOK},
	}
	rows := summaryIndicatorRows(indicators)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3 (CPU, RAM, Disk)", len(rows))
	}
	for i, want := range []string{"CPU", "RAM", "Disk"} {
		if rows[i].Label != want {
			t.Errorf("row %d label = %q, want %q", i, rows[i].Label, want)
		}
	}
}

// TestFilesystemRowsBuildsOneRowPerMount: the details list has one row per
// real mount, in order, with the usage text.
func TestFilesystemRowsBuildsOneRowPerMount(t *testing.T) {
	fs := hostmetrics.Filesystems{
		Available: true,
		Mounts: []hostmetrics.Mount{
			{FSType: "ext4", Mount: "/var", SizeBytes: 200, UsedBytes: 100, Percent: 50},
			{FSType: "xfs", Mount: "/home", SizeBytes: 100, UsedBytes: 90, Percent: 90},
		},
	}
	rows := filesystemRows(fs)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Mount != "/var" || rows[0].PercentText != "50 %" {
		t.Errorf("row 0 = %q %q, want /var 50 %%", rows[0].Mount, rows[0].PercentText)
	}
	if rows[1].Mount != "/home" || rows[1].PercentText != "90 %" {
		t.Errorf("row 1 = %q %q, want /home 90 %%", rows[1].Mount, rows[1].PercentText)
	}
}
