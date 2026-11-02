// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// Full container IDs for the stats tests (docker.stats matches by full ID).
var (
	idRun   = strings.Repeat("a1", 32)
	idOther = strings.Repeat("b2", 32)
	idStop  = strings.Repeat("c3", 32)
)

// statsDoc builds a docker.stats result (format docker-stats-v1) from
// per-container JSON rows.
func statsDoc(t *testing.T, rows ...map[string]string) []byte {
	t.Helper()
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal stats row: %v", err)
		}
		lines = append(lines, string(b))
	}
	doc, err := json.Marshal(map[string]any{
		"format": "docker-stats-v1", "phase": "done", "reason": "", "present": true,
		"version": b64("26.1.4"), "stats": b64(strings.Join(lines, "\n")),
	})
	if err != nil {
		t.Fatalf("marshal stats: %v", err)
	}
	return doc
}

// statsList is a docker.list with one running and one exited container.
func statsList(t *testing.T) executions.LastResultRow {
	return row(dockerListDoc(t,
		idRun+"\tapp\tnginx:1.25\trunning\tUp 5 days\t\t\t\t",
		idStop+"\told\tbusybox:1\texited\tExited (0)\t\t\t\t"), time.Minute)
}

func TestChartContainerStatsLine(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"docker.list": {"box": statsList(t)},
		"docker.stats": {"box": row(statsDoc(t,
			map[string]string{"id": idRun, "name": "app", "cpu": "12.4%", "mem": "256MiB / 1GiB", "memp": "25.00%"}), time.Minute)},
	})
	if !strings.Contains(body, `chart__line chart__line--stats chart__line--ok`) {
		t.Error("running container should have an ok stats line")
	}
	if !strings.Contains(body, `CPU 12 % · RAM 256 MiB / 1 GiB`) {
		t.Error("stats line should show CPU % and RAM used/limit")
	}
	if got := strings.Count(body, "chart__line--stats"); got != 1 {
		t.Errorf("stats lines = %d, want 1 (the exited container has none)", got)
	}
	if !hostNodeHas(body, "chart__node--neutral") {
		t.Error("25 % RAM should keep the border neutral")
	}
}

func TestChartContainerStatsLevelRaisesBorder(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"docker.list": {"box": statsList(t)},
		"docker.stats": {"box": row(statsDoc(t,
			map[string]string{"id": idRun, "name": "app", "cpu": "300.0%", "mem": "950MiB / 1000MiB", "memp": "95.00%"}), time.Minute)},
	})
	if !strings.Contains(body, `chart__line--stats chart__line--crit`) {
		t.Error("95 % of the RAM limit should be critical")
	}
	if !hostNodeHas(body, "chart__node--critical") {
		t.Error("a critical container stats line should make the host border critical")
	}
}

func TestChartContainerStatsHiddenWithoutSource(t *testing.T) {
	cases := map[string]map[string]map[string]executions.LastResultRow{
		"no stats": {"docker.list": {"box": statsList(t)}},
		"malformed stats": {
			"docker.list":  {"box": statsList(t)},
			"docker.stats": {"box": row([]byte(`{"format":"docker-stats-v0"}`), time.Minute)},
		},
		"stats of another host": {
			"docker.list":  {"box": statsList(t)},
			"docker.stats": {"other": row(statsDoc(t), time.Minute)},
		},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			if body := linesBody(t, extra); strings.Contains(body, "chart__line--stats") {
				t.Error("stats line rendered without a usable docker.stats snapshot")
			}
		})
	}
}

func TestChartContainerStatsUnknownAndStale(t *testing.T) {
	cases := []struct {
		name  string
		stats executions.LastResultRow
		want  string
		state string
	}{
		{"not in snapshot", row(statsDoc(t,
			map[string]string{"id": idOther, "name": "x", "cpu": "1%", "mem": "1MiB / 1GiB", "memp": "1%"}), time.Minute),
			"stats unknown", "unknown"},
		{"metrics unparseable", row(statsDoc(t,
			map[string]string{"id": idRun, "name": "app", "cpu": "--", "mem": "--", "memp": "--"}), time.Minute),
			"CPU ? · RAM ?", "unknown"},
		{"stale snapshot", row(statsDoc(t,
			map[string]string{"id": idRun, "name": "app", "cpu": "99%", "mem": "1GiB / 1GiB", "memp": "99%"}), 25*time.Hour),
			"stats stale", "stale"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := linesBody(t, map[string]map[string]executions.LastResultRow{
				"docker.list":  {"box": statsList(t)},
				"docker.stats": {"box": tc.stats},
			})
			if !strings.Contains(body, `chart__line--stats chart__line--`+tc.state) {
				t.Errorf("stats line should be %s", tc.state)
			}
			if !strings.Contains(body, tc.want) {
				t.Errorf("chart body missing %q", tc.want)
			}
			if strings.Contains(body, "CPU 0 %") || strings.Contains(body, "RAM 0 B") {
				t.Error("unknown stats must never render as zero")
			}
			if !hostNodeHas(body, "chart__node--neutral") {
				t.Error("unknown/stale stats must not raise the border")
			}
		})
	}
}

// TestChartContainerStatsEscaping: the stats line carries no host text
// beyond validated numbers; a hostile container name in the snapshot is
// dropped by the parser and the box name stays escaped.
func TestChartContainerStatsEscaping(t *testing.T) {
	body := linesBody(t, map[string]map[string]executions.LastResultRow{
		"docker.list": {"box": statsList(t)},
		"docker.stats": {"box": row(statsDoc(t,
			map[string]string{"id": idRun, "name": "<script>alert(1)</script>", "cpu": "<b>1%</b>", "mem": "1MiB / 1GiB", "memp": "1%"}), time.Minute)},
	})
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "<b>1%") {
		t.Error("host stats text rendered as markup")
	}
	if !strings.Contains(body, "CPU ? · RAM 1 MiB / 1 GiB") {
		t.Error("an invalid CPU reading should render as ?, not as host text")
	}
}
