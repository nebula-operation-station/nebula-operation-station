// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
)

// TestLevelOfThresholds pins the indicator thresholds: >=90 critical,
// >=70 warning, everything below ok (ADR 0006 P1-34).
func TestLevelOfThresholds(t *testing.T) {
	for _, tc := range []struct {
		v     float64
		state IndicatorState
	}{
		{0, StateOK},
		{50, StateOK},
		{69.9, StateOK},
		{70, StateWarn},
		{89.9, StateWarn},
		{90, StateCrit},
		{100, StateCrit},
	} {
		if got := levelOf(tc.v); got != tc.state {
			t.Errorf("levelOf(%v) = %s, want %s", tc.v, got, tc.state)
		}
	}
}

// TestNewIndicatorNilIsUnknown: a missing reading is unknown, never
// zero.
func TestNewIndicatorNilIsUnknown(t *testing.T) {
	now := time.Now()
	ind := newIndicator(IndicatorCPU, nil, nil, now, now, time.Hour)
	if ind.State != StateUnknown {
		t.Errorf("state = %s, want unknown", ind.State)
	}
	if ind.Current != nil {
		t.Errorf("current = %v, want nil (unknown is never zero)", *ind.Current)
	}
	if ind.Avg24h != nil {
		t.Errorf("avg24h = %v, want nil", *ind.Avg24h)
	}
	if ind.Kind != IndicatorCPU || ind.Label != "CPU" {
		t.Errorf("kind/label = %q/%q, want cpu/CPU", ind.Kind, ind.Label)
	}
}

// TestNewIndicatorStale: a value older than the allowed age is stale, a
// fresh value takes its level.
func TestNewIndicatorStale(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-time.Minute)
	old := now.Add(-2 * time.Hour)
	staleAfter := time.Hour

	v := 5.0
	ind := newIndicator(IndicatorRAM, &v, nil, old, now, staleAfter)
	if ind.State != StateStale {
		t.Errorf("stale value: state = %s, want stale", ind.State)
	}
	if ind.Current == nil || *ind.Current != 5 {
		t.Errorf("stale value must keep its value, got %v", ind.Current)
	}

	ind = newIndicator(IndicatorRAM, &v, nil, fresh, now, staleAfter)
	if ind.State != StateOK {
		t.Errorf("fresh value: state = %s, want ok", ind.State)
	}

	// Exactly at the threshold the value is still fresh.
	ind = newIndicator(IndicatorRAM, &v, nil, now.Add(-staleAfter), now, staleAfter)
	if ind.State != StateOK {
		t.Errorf("value at the exact age: state = %s, want ok", ind.State)
	}

	// A nil value is unknown even when the observation is old.
	ind = newIndicator(IndicatorRAM, nil, nil, old, now, staleAfter)
	if ind.State != StateUnknown {
		t.Errorf("nil value with old observation: state = %s, want unknown", ind.State)
	}

	// A zero observedAt is unobserved: stale, not fresh.
	ind = newIndicator(IndicatorRAM, &v, nil, time.Time{}, now, staleAfter)
	if ind.State != StateStale {
		t.Errorf("zero observedAt: state = %s, want stale", ind.State)
	}
}

// TestWorstStateOrder pins the box-border ordering: critical > warning >
// stale > unknown > ok.
func TestWorstStateOrder(t *testing.T) {
	for _, tc := range []struct {
		states []IndicatorState
		want   IndicatorState
	}{
		{nil, StateOK},
		{[]IndicatorState{StateOK}, StateOK},
		{[]IndicatorState{StateOK, StateUnknown}, StateUnknown},
		{[]IndicatorState{StateUnknown, StateStale}, StateStale},
		{[]IndicatorState{StateStale, StateWarn}, StateWarn},
		{[]IndicatorState{StateWarn, StateCrit}, StateCrit},
		{[]IndicatorState{StateOK, StateWarn, StateUnknown, StateStale, StateCrit}, StateCrit},
		{[]IndicatorState{StateCrit, StateOK, StateWarn, StateStale, StateUnknown}, StateCrit},
		{[]IndicatorState{StateStale, StateUnknown, StateOK}, StateStale},
	} {
		if got := worstState(tc.states...); got != tc.want {
			t.Errorf("worstState(%v) = %s, want %s", tc.states, got, tc.want)
		}
	}
}

// hostMetricsFixture is a complete host.metrics reading plus a
// filesystem.list with three real mounts, /data the fullest.
func hostMetricsFixture() (hostmetrics.Metrics, hostmetrics.Filesystems) {
	m := hostmetrics.Metrics{
		Phase: "done",
		CPU:   hostmetrics.CPUStat{Available: true, Percent: 82.5},
		Mem:   hostmetrics.MemStat{Available: true, UsedBytes: 12 * 1024, TotalBytes: 16 * 1024}, // 75%
		Disk:  hostmetrics.DiskStat{Available: true, Mount: "/data", UsedBytes: 9 * 100, TotalBytes: 10 * 100, Percent: 90},
	}
	fs := hostmetrics.Filesystems{
		Phase:     "done",
		Available: true,
		Mounts: []hostmetrics.Mount{
			{FSType: "ext4", Mount: "/", SizeBytes: 500, UsedBytes: 150, Percent: 30},
			{FSType: "ext4", Mount: "/var", SizeBytes: 200, UsedBytes: 160, Percent: 80},
			{FSType: "xfs", Mount: "/data", SizeBytes: 1000, UsedBytes: 900, Percent: 90},
		},
	}
	return m, fs
}

// TestHostIndicators builds the indicator set from a complete reading:
// CPU, RAM, one disk indicator per filesystem and the fullest one as
// the summary.
func TestHostIndicators(t *testing.T) {
	m, fs := hostMetricsFixture()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	inds := hostIndicators(m, fs, now.Add(-time.Minute), now, time.Hour)

	// CPU, RAM, 3 filesystems, 1 summary.
	if len(inds) != 6 {
		t.Fatalf("got %d indicators, want 6: %+v", len(inds), inds)
	}
	if inds[0].Kind != IndicatorCPU || inds[0].Label != "CPU" || inds[0].State != StateWarn || inds[0].Current == nil || *inds[0].Current != 82.5 {
		t.Errorf("cpu indicator = %+v, want warn at 82.5", inds[0])
	}
	if inds[1].Kind != IndicatorRAM || inds[1].State != StateWarn || inds[1].Current == nil || *inds[1].Current != 75 {
		t.Errorf("ram indicator = %+v, want warn at 75", inds[1])
	}
	for i, want := range []struct {
		label string
		pct   float64
		state IndicatorState
	}{
		{"Disk /", 30, StateOK},
		{"Disk /var", 80, StateWarn},
		{"Disk /data", 90, StateCrit},
	} {
		got := inds[2+i]
		if got.Kind != IndicatorDisk || got.Label != want.label || got.State != want.state || got.Current == nil || *got.Current != want.pct {
			t.Errorf("disk indicator %d = %+v, want %s at %v (%s)", i, got, want.label, want.pct, want.state)
		}
	}
	// Summary is the fullest filesystem: /data at 90, critical.
	sum := inds[5]
	if sum.Kind != IndicatorDisk || sum.Label != "Disk" || sum.State != StateCrit || sum.Current == nil || *sum.Current != 90 {
		t.Errorf("disk summary = %+v, want Disk at 90 (crit)", sum)
	}
}

// TestHostIndicatorsUnavailable: every missing reading is unknown,
// never zero, and the disk summary is unknown without any filesystem.
func TestHostIndicatorsUnavailable(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	inds := hostIndicators(hostmetrics.Metrics{Phase: "done"}, hostmetrics.Filesystems{Phase: "done", Available: true}, now.Add(-time.Minute), now, time.Hour)
	if len(inds) != 3 {
		t.Fatalf("got %d indicators, want 3: %+v", len(inds), inds)
	}
	for i, ind := range inds {
		if ind.State != StateUnknown {
			t.Errorf("indicator %d = %+v, want unknown", i, ind)
		}
		if ind.Current != nil {
			t.Errorf("indicator %d current = %v, want nil (unknown is never zero)", i, *ind.Current)
		}
	}
}

// TestHostIndicatorsStale: an old observation makes every available
// reading stale, keeping its value.
func TestHostIndicatorsStale(t *testing.T) {
	m, fs := hostMetricsFixture()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	inds := hostIndicators(m, fs, now.Add(-48*time.Hour), now, time.Hour)
	if len(inds) != 6 {
		t.Fatalf("got %d indicators, want 6", len(inds))
	}
	for i, ind := range inds {
		if ind.State != StateStale {
			t.Errorf("indicator %d = %+v, want stale", i, ind)
		}
		if ind.Current == nil {
			t.Errorf("indicator %d lost its value: %+v", i, ind)
		}
	}
}

// TestHostIndicatorsDiskSummaryFromFilesystemList: when the metrics disk
// reading is unavailable, the summary is the fullest listed filesystem.
func TestHostIndicatorsDiskSummaryFromFilesystemList(t *testing.T) {
	m, fs := hostMetricsFixture()
	m.Disk.Available = false
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	inds := hostIndicators(m, fs, now.Add(-time.Minute), now, time.Hour)
	sum := inds[len(inds)-1]
	if sum.Label != "Disk" || sum.Current == nil || *sum.Current != 90 || sum.State != StateCrit {
		t.Errorf("disk summary = %+v, want Disk at 90 (crit) from the fullest mount", sum)
	}
}
