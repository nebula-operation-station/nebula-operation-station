// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"testing"
	"time"
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
