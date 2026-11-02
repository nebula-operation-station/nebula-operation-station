// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// svcDoc builds a service.check result (format service-check-v1).
func svcDoc(status string, latencyMS, httpStatus int) []byte {
	return []byte(fmt.Sprintf(`{"format":"service-check-v1","phase":"done","status":%q,"latency_ms":%d,"http_status":%d}`,
		status, latencyMS, httpStatus))
}

func TestChartLatencyLineOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		doc    []byte
		state  string
		text   string
		border string
	}{
		{"http ok", svcDoc("ok", 12, 200), "ok", "ok 200 · 12 ms", "chart__node--neutral"},
		{"tcp ok", svcDoc("ok", 3, 0), "ok", "ok · 3 ms", "chart__node--neutral"},
		{"redirect", svcDoc("redirect", 20, 301), "warn", "redirect 301 · 20 ms", "chart__node--warning"},
		{"http error", svcDoc("http-error", 40, 503), "crit", "HTTP 503 · 40 ms", "chart__node--critical"},
		{"refused", svcDoc("refused", 1, 0), "crit", ">refused<", "chart__node--critical"},
		{"timeout", svcDoc("timeout", 5000, 0), "crit", ">timeout<", "chart__node--critical"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := linesBody(t, map[string]map[string]executions.LastResultRow{
				"service.check": {"box": row(tc.doc, time.Minute)},
			})
			if !strings.Contains(body, `chart__line chart__line--latency chart__line--`+tc.state) {
				t.Errorf("service line should be %s", tc.state)
			}
			if !strings.Contains(body, tc.text) {
				t.Errorf("chart body missing %q", tc.text)
			}
			if !hostNodeHas(body, tc.border) {
				t.Errorf("border should be %s", tc.border)
			}
		})
	}
}

func TestChartLatencyLineHiddenWithoutCheck(t *testing.T) {
	cases := map[string]map[string]map[string]executions.LastResultRow{
		"no check configured": {},
		"other host":          {"service.check": {"other": row(svcDoc("ok", 1, 200), time.Minute)}},
		"body smuggled": {"service.check": {"box": row([]byte(
			`{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":200,"body":"<script>x</script>"}`), time.Minute)}},
		"inconsistent": {"service.check": {"box": row(svcDoc("ok", 1, 503), time.Minute)}},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			body := linesBody(t, extra)
			if strings.Contains(body, "chart__line--latency") {
				t.Error("service line rendered without a valid service.check result")
			}
			if strings.Contains(body, "<script>x</script>") {
				t.Error("smuggled host text rendered")
			}
			if !hostNodeHas(body, "chart__node--neutral") {
				t.Error("a hidden service line must not raise the border")
			}
		})
	}
}

func TestChartLatencyLineStale(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"service.check": {"box": row(svcDoc("http-error", 40, 503), 25*time.Hour)},
	})
	if !strings.Contains(body, `chart__line--latency chart__line--stale`) {
		t.Error("an old service check should be stale")
	}
	if !strings.Contains(body, "http-error · stale") {
		t.Error("stale service line should say stale")
	}
	if strings.Contains(body, "40 ms") {
		t.Error("a stale latency must not be shown as current")
	}
	if !hostNodeHas(body, "chart__node--neutral") {
		t.Error("a stale service check must not raise the border")
	}
}
