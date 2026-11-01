// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
)

// Indicator kinds (ADR 0006 P1-34).
const (
	// IndicatorCPU is the CPU utilisation indicator.
	IndicatorCPU = "cpu"
	// IndicatorRAM is the RAM utilisation indicator.
	IndicatorRAM = "ram"
	// IndicatorDisk is a disk utilisation indicator: one per
	// filesystem, plus the fullest one as the summary.
	IndicatorDisk = "disk"
)

// IndicatorState is the state of one chart indicator.
type IndicatorState string

const (
	// StateOK is below the warning threshold.
	StateOK IndicatorState = "ok"
	// StateWarn is at or above the warning threshold.
	StateWarn IndicatorState = "warn"
	// StateCrit is at or above the critical threshold.
	StateCrit IndicatorState = "crit"
	// StateUnknown has no value; it is never rendered as zero.
	StateUnknown IndicatorState = "unknown"
	// StateStale has a value, but the observation is older than the
	// allowed age.
	StateStale IndicatorState = "stale"
)

// Thresholds for the chart indicators (ADR 0006 P1-34): a current value
// at or above warnThresholdPercent is warning, at or above
// critThresholdPercent critical.
const (
	warnThresholdPercent = 70.0
	critThresholdPercent = 90.0
)

// Indicator is one CPU/RAM/disk indicator of an org-chart box.
type Indicator struct {
	// Kind is the indicator kind (cpu, ram, disk).
	Kind string
	// Current is the current percentage, nil when unknown.
	Current *float64
	// Avg24h is the 24 h average percentage, nil when unknown.
	Avg24h *float64
	// State is the indicator state (ok, warn, crit, unknown, stale).
	State IndicatorState
	// Label is the display label.
	Label string
}

// levelOf maps a percentage to its indicator state: >=90 critical, >=70
// warning, otherwise ok.
func levelOf(v float64) IndicatorState {
	switch {
	case v >= critThresholdPercent:
		return StateCrit
	case v >= warnThresholdPercent:
		return StateWarn
	default:
		return StateOK
	}
}

// newIndicator builds one indicator. A nil current value is unknown,
// never zero; a value observed more than staleAfter before now is stale
// (a zero observedAt is treated as unobserved, hence stale).
func newIndicator(kind string, cur, avg *float64, observedAt, now time.Time, staleAfter time.Duration) Indicator {
	ind := Indicator{Kind: kind, Current: cur, Avg24h: avg, Label: indicatorLabel(kind)}
	switch {
	case cur == nil:
		ind.State = StateUnknown
	case now.Sub(observedAt) > staleAfter:
		ind.State = StateStale
	default:
		ind.State = levelOf(*cur)
	}
	return ind
}

// indicatorLabel is the display label of an indicator kind.
func indicatorLabel(kind string) string {
	switch kind {
	case IndicatorCPU:
		return "CPU"
	case IndicatorRAM:
		return "RAM"
	case IndicatorDisk:
		return "Disk"
	default:
		return kind
	}
}

// stateRank orders indicator states for the worst-state comparison:
// critical > warning > stale > unknown > ok.
func stateRank(s IndicatorState) int {
	switch s {
	case StateCrit:
		return 4
	case StateWarn:
		return 3
	case StateStale:
		return 2
	case StateUnknown:
		return 1
	default:
		return 0
	}
}

// worstState returns the worst of the given states for the box border:
// critical > warning > stale > unknown > ok. No states is ok.
func worstState(states ...IndicatorState) IndicatorState {
	worst := StateOK
	for _, s := range states {
		if stateRank(s) > stateRank(worst) {
			worst = s
		}
	}
	return worst
}

// hostIndicators builds the CPU, RAM and disk indicators for one host
// from the parsed host.metrics and filesystem.list results (ADR 0006
// P1-34). observedAt is when the readings were taken; values older than
// staleAfter are stale, missing readings unknown — never zero. The disk
// indicators are one per real filesystem (Label "Disk <mount>") plus the
// fullest one as the summary (Label "Disk").
func hostIndicators(m hostmetrics.Metrics, fs hostmetrics.Filesystems, observedAt, now time.Time, staleAfter time.Duration) []Indicator {
	out := make([]Indicator, 0, 3+len(fs.Mounts))
	var cpu *float64
	if m.CPU.Available {
		v := m.CPU.Percent
		cpu = &v
	}
	var ram *float64
	if m.Mem.Available && m.Mem.TotalBytes > 0 {
		v := m.Mem.Percent()
		ram = &v
	}
	out = append(out, newIndicator(IndicatorCPU, cpu, nil, observedAt, now, staleAfter))
	out = append(out, newIndicator(IndicatorRAM, ram, nil, observedAt, now, staleAfter))
	for _, mt := range fs.Mounts {
		v := mt.Percent
		ind := newIndicator(IndicatorDisk, &v, nil, observedAt, now, staleAfter)
		ind.Label = "Disk " + mt.Mount
		out = append(out, ind)
	}
	// Summary: the fullest filesystem. The host.metrics disk reading
	// is the action's own fullest computation; the filesystem list
	// covers hosts whose metrics disk reading is unavailable.
	if m.Disk.Available {
		v := m.Disk.Percent
		out = append(out, newIndicator(IndicatorDisk, &v, nil, observedAt, now, staleAfter))
	} else if best, ok := fs.Fullest(); ok {
		v := best.Percent
		out = append(out, newIndicator(IndicatorDisk, &v, nil, observedAt, now, staleAfter))
	} else {
		out = append(out, newIndicator(IndicatorDisk, nil, nil, observedAt, now, staleAfter))
	}
	return out
}
