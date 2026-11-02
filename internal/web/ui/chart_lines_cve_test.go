// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// scannedImage is the digest reference of the scanned image.
var scannedImage = "nginx@sha256:" + strings.Repeat("0123456789abcdef", 4)

// vulnsDoc builds an image.vulnerabilities result (format
// image-vulns-v1). sev holds CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN counts; a
// non-ok status carries no summary.
func vulnsDoc(t *testing.T, status string, sev map[string]int) []byte {
	t.Helper()
	doc := map[string]any{
		"format": "image-vulns-v1", "phase": "done", "reason": "", "present": true,
		"status": status, "trivy": b64("0.50.1"), "dbver": b64("2"), "dbage": 3,
		"image": scannedImage, "platform": b64("linux/amd64"), "cached": false,
	}
	if status == "ok" {
		total := 0
		for _, n := range sev {
			total += n
		}
		sum, err := json.Marshal(map[string]any{"severity": sev, "total": total, "targets": 2, "top": []any{}})
		if err != nil {
			t.Fatalf("marshal summary: %v", err)
		}
		doc["summary"] = b64(string(sum))
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal vulns: %v", err)
	}
	return b
}

// sevCounts builds a full severity map.
func sevCounts(crit, high, med, low int) map[string]int {
	return map[string]int{"CRITICAL": crit, "HIGH": high, "MEDIUM": med, "LOW": low, "UNKNOWN": 0}
}

func TestChartCVELineCountsAndLevel(t *testing.T) {
	cases := []struct {
		name   string
		sev    map[string]int
		state  string
		border string
	}{
		{"critical", sevCounts(2, 5, 10, 3), "crit", "chart__node--critical"},
		{"high only", sevCounts(0, 1, 0, 0), "warn", "chart__node--warning"},
		{"clean", sevCounts(0, 0, 4, 1), "ok", "chart__node--neutral"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := linesBody(t, map[string]map[string]executions.LastResultRow{
				"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", tc.sev), time.Hour)},
			})
			if !strings.Contains(body, `chart__line chart__line--cve chart__line--`+tc.state) {
				t.Errorf("CVE line should be %s", tc.state)
			}
			if !hostNodeHas(body, tc.border) {
				t.Errorf("border should be %s", tc.border)
			}
		})
	}
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(2, 5, 10, 3)), time.Hour)},
	})
	for _, want := range []string{
		"nginx@0123456789ab · 2 critical · 5 high · 10 medium · 3 low",
		"20 total · 2 targets · linux/amd64 · database 3 h old",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing %q", want)
		}
	}
}

func TestChartCVELineHiddenWithoutSource(t *testing.T) {
	cases := map[string]map[string]map[string]executions.LastResultRow{
		"no scan":        {},
		"malformed scan": {"image.vulnerabilities": {"box": row([]byte(`{"format":"image-vulns-v1","phase":"done","status":"bogus"}`), time.Hour)}},
		"other host":     {"image.vulnerabilities": {"other": row(vulnsDoc(t, "ok", sevCounts(1, 0, 0, 0)), time.Hour)}},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			if body := linesBody(t, extra); strings.Contains(body, "chart__line--cve") {
				t.Error("CVE line rendered without a usable scan")
			}
		})
	}
}

func TestChartCVELineUnknownAndStale(t *testing.T) {
	cases := []struct {
		name   string
		result executions.LastResultRow
		state  string
		want   string
	}{
		{"failed scan", row(vulnsDoc(t, "failed", nil), time.Hour), "unknown", "scan unknown (failed)"},
		{"no trivy", row(vulnsDoc(t, "absent", nil), time.Hour), "unknown", "scan unknown (absent)"},
		{"old database", row(vulnsDoc(t, "stale", nil), time.Hour), "stale", "scan stale (database old)"},
		{"old result", row(vulnsDoc(t, "ok", sevCounts(9, 9, 9, 9)), 25*time.Hour), "stale", "nginx@0123456789ab · scan stale"},
		{"precheck", row([]byte(`{"format":"image-vulns-v1","phase":"precheck","reason":"no docker"}`), time.Hour), "unknown", "scan unknown (not run)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := linesBody(t, map[string]map[string]executions.LastResultRow{
				"image.vulnerabilities": {"box": tc.result},
			})
			if !strings.Contains(body, `chart__line--cve chart__line--`+tc.state) {
				t.Errorf("CVE line should be %s", tc.state)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("chart body missing %q", tc.want)
			}
			if strings.Contains(body, "0 critical") {
				t.Error("an unknown scan must never render as zero CVEs")
			}
			if !hostNodeHas(body, "chart__node--neutral") {
				t.Error("unknown/stale scan must not raise the border")
			}
		})
	}
}

// TestChartCVELineEscaping: the only host text in the line is the
// validated digest reference and platform; markup in the image reference
// is rejected by the parser, which hides the line, and is never rendered.
func TestChartCVELineEscaping(t *testing.T) {
	hostile := strings.Replace(string(vulnsDoc(t, "ok", sevCounts(1, 0, 0, 0))), scannedImage, "<script>x</script>@sha256:"+strings.Repeat("0", 64), 1)
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row([]byte(hostile), time.Hour)},
	})
	if strings.Contains(body, "<script>x</script>") {
		t.Error("hostile image reference rendered as markup")
	}
	if strings.Contains(body, "chart__line--cve") {
		t.Error("a scan with an invalid image reference should be hidden")
	}
	// A valid scan carries its details (reference, counts) in the title.
	body = linesBody(t, map[string]map[string]executions.LastResultRow{
		"image.vulnerabilities": {"box": row(vulnsDoc(t, "ok", sevCounts(1, 0, 0, 0)), time.Hour)},
	})
	if !strings.Contains(body, `title="`+scannedImage+` · 1 total`) {
		t.Error("CVE details title missing")
	}
}
