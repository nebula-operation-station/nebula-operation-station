// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

// chartOps overrides the batch reads fakeOps hardcodes, so the chart
// tests can drive ops states, update counts and docker lists per host.
type chartOps struct {
	*fakeOps
	states  map[string]executions.OpsState
	updates map[string]executions.HostUpdates
	docker  map[string]executions.LastResultRow
	facts   map[string]executions.LastResultRow
}

func (c *chartOps) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	return c.states, nil
}

func (c *chartOps) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	return c.updates, nil
}

func (c *chartOps) LastResults(_ context.Context, actionID string) (map[string]executions.LastResultRow, error) {
	switch actionID {
	case "docker.list":
		return c.docker, nil
	case "core.facts":
		return c.facts, nil
	}
	return map[string]executions.LastResultRow{}, nil
}

// factsDoc builds a core.facts result from an os-release body.
func factsDoc(t *testing.T, osRelease string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"os_release": base64.StdEncoding.EncodeToString([]byte(osRelease)),
	})
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	return doc
}

// dockerListDoc builds a docker.list result (format docker-ps-v1) from
// tab-separated container lines.
func dockerListDoc(t *testing.T, lines ...string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"format":     "docker-ps-v1",
		"phase":      "done",
		"present":    true,
		"version":    base64.StdEncoding.EncodeToString([]byte("26.1.4")),
		"containers": base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))),
	})
	if err != nil {
		t.Fatalf("marshal docker list: %v", err)
	}
	return doc
}

func chartHosts() []inventory.Host {
	return []inventory.Host{
		{ID: "web", DisplayName: "Web <server>", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium},
		{ID: "nas", DisplayName: "Storage", Environment: inventory.EnvProd, Criticality: inventory.CriticalityHigh},
		{ID: "ci", DisplayName: "CI runner", Environment: inventory.EnvDev, Criticality: inventory.CriticalityLow},
		{ID: "clean", DisplayName: "Clean host", Environment: inventory.EnvDev, Criticality: inventory.CriticalityLow},
	}
}

func chartHandler(t *testing.T) *ui.Handler {
	t.Helper()
	observed := time.Unix(1791960000, 0)
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states: map[string]executions.OpsState{
			"web":   {State: "READY", Reason: "no pending work", ObservedAt: observed},
			"nas":   {State: "WARNING", Reason: "3 updates", ObservedAt: observed},
			"ci":    {State: "UNREACHABLE", Reason: "no answer", ObservedAt: observed},
			"clean": {State: "READY", Reason: "no pending work", ObservedAt: observed},
		},
		updates: map[string]executions.HostUpdates{
			"nas":   {HostID: "nas", Total: 3, Security: 2, RebootRequired: true, ObservedAt: observed},
			"clean": {HostID: "clean", Total: 0, ObservedAt: observed},
		},
		docker: map[string]executions.LastResultRow{
			"web": {Result: dockerListDoc(t,
				"a1a1a1a1a1a1	web-nginx	nginx:1.25	running	Up 5 days	0.0.0.0:80->80/tcp	stack-a	web	/app",
				"a2a2a2a2a2a2	web-cache	redis:7	running	Up 5 days (healthy)		stack-a	cache	/app",
				"a3a3a3a3a3a3	loose	busybox:1	exited	Exited (0)				",
				"a4a4a4a4a4a4	inject	<img src=x onerror=alert(1)>	running	Up 1 hour				"),
				FinishedAt: observed},
			"clean": {Result: dockerListDoc(t,
				"b1b1b1b1b1b1	healthy-one	nginx:1.25	running	Up 5 days (healthy)				",
				"b2b2b2b2b2b2	starting-one	redis:7	running	Up 5 minutes (health: starting)				",
				"b3b3b3b3b3b3	unhealthy-one	nginx:1.25	running	Up 5 days (unhealthy)				"),
				FinishedAt: observed},
		},
		facts: map[string]executions.LastResultRow{
			"clean": {Result: factsDoc(t, `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`), FinishedAt: observed},
		},
	}
	var log strings.Builder
	return newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return chartHosts(), nil },
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
	})
}

func TestChartRendersHostsAndContainers(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	for _, want := range []string{
		"Web &lt;server&gt;", // hostile display name escaped
		"web-nginx", "nginx:1.25",
		"web-cache", "redis:7",
		"loose", "busybox:1",
		"stack-a", // compose project group
		"4 containers",
		"chart__box--container",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing %q", want)
		}
	}
}

func TestChartEscapesHostileContainerImage(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Error("hostile image not escaped")
	}
	if strings.Contains(body, "<img src=x") {
		t.Error("hostile image rendered as markup")
	}
}

func TestChartWorstStateBorderClass(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	// ci is unreachable: red border.
	if !strings.Contains(body, `chart__node--critical`) {
		t.Error("unreachable host missing critical border class")
	}
	// nas has pending updates: yellow border.
	if !strings.Contains(body, `chart__node--warning`) {
		t.Error("updates host missing warning border class")
	}
	// web and clean have no problem: neutral border.
	if !strings.Contains(body, `chart__node--neutral`) {
		t.Error("clean host missing neutral border class")
	}
}

func TestChartPatchState(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	if !strings.Contains(body, "⬆ 3") {
		t.Error("updates count patch state missing")
	}
	if !strings.Contains(body, "✓") {
		t.Error("up-to-date patch state missing")
	}
	if !strings.Contains(body, "unknown") {
		t.Error("never-checked patch state missing")
	}
}

func TestChartExpandedOnlyForProblemHosts(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	// The problem hosts (nas, ci) are open by default...
	opens := strings.Count(body, `<details class="chart__details" open`)
	if opens != 2 {
		t.Errorf("open details count = %d, want 2 (nas, ci)", opens)
	}
}

// TestChartBadgeClasses checks the badge colour classes of every state
// badge the chart renders: docker state (running green, exited red) and
// docker health (healthy green, starting yellow, unhealthy red).
func TestChartBadgeClasses(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	for _, want := range []string{
		`<span class="badge badge--ok">running</span>`,
		`<span class="badge badge--critical">exited</span>`,
		`<span class="badge badge--ok">healthy</span>`,
		`<span class="badge badge--warning">starting</span>`,
		`<span class="badge badge--critical">unhealthy</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing %q", want)
		}
	}
	if strings.Contains(body, `badge--critical">healthy`) {
		t.Error("healthy badge styled critical")
	}
	if strings.Contains(body, `badge--critical">starting`) {
		t.Error("starting badge styled critical")
	}
}

// TestChartTruncationTooltips checks that the values that can be cut by
// the ellipsis (image names, the OS line, container names) carry the full
// value in a title attribute.
func TestChartTruncationTooltips(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	for _, want := range []string{
		`title="nginx:1.25"`,
		`title="web-nginx"`,
		`title="OK · Debian GNU/Linux 12 (bookworm)"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart body missing tooltip %q", want)
		}
	}
}

// TestChartCSSHasNoInnerScroll checks that no chart rule creates a scroll
// area of its own: the columns grow with their content and the page
// scrolls.
func TestChartCSSHasNoInnerScroll(t *testing.T) {
	b, err := static.FS.ReadFile("app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		sel := strings.TrimSpace(line)
		if !strings.HasPrefix(sel, ".chart") {
			continue
		}
		for _, bad := range []string{"overflow: auto", "overflow-x: auto", "overflow-y: auto", "overflow: scroll"} {
			if strings.Contains(sel, bad) {
				t.Errorf("chart CSS keeps an inner scroll area: %s", sel)
			}
		}
	}
}

func TestChartEmptyInventory(t *testing.T) {
	var log strings.Builder
	h := newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, nil },
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
	})
	body := getBody(t, h.Handler(), "/inventory/chart")
	if !strings.Contains(body, "No managed hosts yet") {
		t.Error("empty inventory message missing")
	}
}

func TestChartUnavailableInventory(t *testing.T) {
	var log strings.Builder
	h := newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return nil, errors.New("inventory down") },
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
	})
	body := getBody(t, h.Handler(), "/inventory/chart")
	if !strings.Contains(body, "Inventory unavailable") {
		t.Error("unavailable message missing")
	}
}
