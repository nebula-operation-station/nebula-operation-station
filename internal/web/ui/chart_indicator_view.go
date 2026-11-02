// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
)

// indicatorStaleAfter is how long a host.metrics read may be old before the
// chart marks the box indicators stale (ADR 0006 P1-34).
const indicatorStaleAfter = 24 * time.Hour

// chartIndicator is one CPU/RAM/DISK row of an org-chart host box,
// pre-formatted for display. The numeric value lives in the meter's value
// attribute (the CSP style-src 'self' forbids inline styles); CurrentText
// and AvgText are the display strings, "unknown"/"stale" instead of a number
// when applicable.
type chartIndicator struct {
	// Label is the row label (CPU, RAM, Disk).
	Label string
	// State is the indicator state (ok, warn, crit, unknown, stale); it
	// drives the meter colour class.
	State string
	// HasValue is true when the meter shows a fill.
	HasValue bool
	// MeterValue is the meter fill, 0-100, only used when HasValue.
	MeterValue int
	// CurrentText is the current value text ("unknown", "stale" or "82 %").
	CurrentText string
	// AvgText is the 24-h average text ("–" when unknown, "75 %" when known).
	AvgText string
}

// chartFilesystem is one row of the per-host filesystem details list.
type chartFilesystem struct {
	// Mount is the mount point (untrusted text; rendered escaped).
	Mount string
	// PercentText is the usage text ("–" when unknown, "75 %" when known).
	PercentText string
}

// indicatorText formats a percentage for display, rounded to a whole
// percent.
func indicatorText(v float64) string {
	return fmt.Sprintf("%d %%", int(v+0.5))
}

// indicatorRow builds one display row from an indicator. A nil current
// value is "unknown" (never 0 %); a stale value keeps its meter but shows
// the word "stale" instead of the number.
func indicatorRow(ind Indicator) chartIndicator {
	row := chartIndicator{
		Label:       ind.Label,
		State:       string(ind.State),
		CurrentText: "unknown",
		AvgText:     "–",
	}
	if ind.Current != nil {
		row.CurrentText = indicatorText(*ind.Current)
		row.HasValue = true
		row.MeterValue = int(*ind.Current + 0.5)
		if row.MeterValue < 0 {
			row.MeterValue = 0
		}
		if row.MeterValue > 100 {
			row.MeterValue = 100
		}
	}
	if ind.Avg24h != nil {
		row.AvgText = indicatorText(*ind.Avg24h)
	}
	if ind.State == StateStale {
		row.CurrentText = "stale"
	}
	return row
}

// summaryIndicatorRows selects the three summary rows (CPU, RAM, the
// fullest disk) from the full indicator list returned by hostIndicators.
func summaryIndicatorRows(indicators []Indicator) []chartIndicator {
	var rows []chartIndicator
	for _, ind := range indicators {
		switch {
		case ind.Kind == IndicatorCPU:
			rows = append(rows, indicatorRow(ind))
		case ind.Kind == IndicatorRAM:
			rows = append(rows, indicatorRow(ind))
		case ind.Kind == IndicatorDisk && ind.Label == "Disk":
			rows = append(rows, indicatorRow(ind))
		}
	}
	return rows
}

// filesystemRows builds the details-list rows from the filesystems result,
// in the order the host reported them.
func filesystemRows(fs hostmetrics.Filesystems) []chartFilesystem {
	if len(fs.Mounts) == 0 {
		return nil
	}
	rows := make([]chartFilesystem, 0, len(fs.Mounts))
	for _, m := range fs.Mounts {
		row := chartFilesystem{Mount: m.Mount, PercentText: "–"}
		if m.SizeBytes > 0 {
			row.PercentText = indicatorText(m.Percent)
		}
		rows = append(rows, row)
	}
	return rows
}
