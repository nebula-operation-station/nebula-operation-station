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
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"github.com/nebula-operation-station/nebula-operation-station/web/static"
)

// chartOps overrides the batch reads fakeOps hardcodes, so the chart
// tests can drive ops states, update counts and docker lists per host.
type chartOps struct {
	*fakeOps
	states   map[string]executions.OpsState
	updates  map[string]executions.HostUpdates
	docker   map[string]executions.LastResultRow
	facts    map[string]executions.LastResultRow
	dockerUp map[string]executions.LastResultRow
	registry map[string]executions.LastResultRow
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
	case "docker.check_updates":
		return c.dockerUp, nil
	case "registry.tags":
		return c.registry, nil
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

// gib is one GiB in bytes.
const gib = 1024 * 1024 * 1024

// pveChartTree builds an org-chart tree from one PVE remote with the
// given storages, for the PVE chart render tests.
func pveChartTree(t *testing.T, storages ...pveinventory.StorageInput) pveinventory.Tree {
	t.Helper()
	now := time.Unix(1791960000, 0)
	tree, err := pveinventory.BuildTree(pveinventory.TreeInput{
		Now: now,
		Remotes: []pveinventory.RemoteInput{{
			RemoteID: "pve-lab",
			Name:     "PVE lab",
			Nodes: []pveinventory.NodeInput{{
				Node:       "pve1",
				Status:     "online",
				ObservedAt: now,
			}},
			Guests: []pveinventory.GuestInput{{
				VMID:       100,
				Generation: 1,
				Kind:       "qemu",
				Node:       "pve1",
				Name:       "web-vm",
				Status:     "running",
				ObservedAt: now,
			}},
			Storages: storages,
		}},
	})
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	return tree
}

// pveChartHandler builds a handler with the given PVE tree provider.
func pveChartHandler(t *testing.T, tree pveinventory.Tree) *ui.Handler {
	t.Helper()
	var log strings.Builder
	return newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return chartHosts(), nil },
		PVEChart:     func(context.Context) (pveinventory.Tree, error) { return tree, nil },
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
	})
}

func TestChartPVEStorageBoxes(t *testing.T) {
	tree := pveChartTree(t,
		pveinventory.StorageInput{
			Node: "pve1", ID: "local", Type: "dir", Active: true,
			UsedBytes: 256 * gib, TotalBytes: 512 * gib, CapacityKnown: true,
		},
		pveinventory.StorageInput{
			Node: "pve1", ID: "local-lvm", Type: "lvmthin", Active: true, Shared: true,
			UsedBytes: 384 * gib, TotalBytes: 480 * gib, CapacityKnown: true,
		},
		pveinventory.StorageInput{
			Node: "pve1", ID: "backup", Type: "pbs", Active: true,
			UsedBytes: 475 * gib, TotalBytes: 500 * gib, CapacityKnown: true,
		},
	)
	body := getBody(t, pveChartHandler(t, tree).Handler(), "/inventory/chart")

	for label, want := range map[string]string{
		"PVE node box":           "chart__box--node",
		"node name":              "pve1",
		"guest box":              "chart__box--guest",
		"guest name":             "web-vm",
		"guest vmid":             "VM 100",
		"storage box":            "chart__box--storage",
		"dir icon":               "chart__storage-icon--dir",
		"lvmthin icon":           "chart__storage-icon--lvmthin",
		"pbs icon":               "chart__storage-icon--pbs",
		"pbs label":              "backup datastore",
		"shared mark":            "shared",
		"local fill":             "50 % von 512 GiB",
		"lvm fill":               "80 % von 480 GiB",
		"backup fill":            "95 % von 500 GiB",
		"local bar":              `<meter class="chart__storage-meter" min="0" max="100" low="70" high="90" optimum="0" value="50">50%</meter>`,
		"lvm bar":                `<meter class="chart__storage-meter" min="0" max="100" low="70" high="90" optimum="0" value="80">80%</meter>`,
		"backup bar":             `<meter class="chart__storage-meter" min="0" max="100" low="70" high="90" optimum="0" value="95">95%</meter>`,
		"warning storage class":  "chart__storage--warning",
		"critical storage class": "chart__storage--critical",
		"node worst state":       "chart__node--critical",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("chart page missing %s (%q)", label, want)
		}
	}
	// Storages render after the guest boxes.
	if i, j := strings.Index(body, "chart__box--guest"), strings.Index(body, "chart__box--storage"); i < 0 || j < 0 || i > j {
		t.Errorf("storage boxes must render after guest boxes (guest at %d, storage at %d)", i, j)
	}
}

func TestChartPVEStorageEscaping(t *testing.T) {
	evil := `"><script>alert(1)</script>`
	tree := pveChartTree(t,
		pveinventory.StorageInput{
			Node: "pve1", ID: evil, Type: "dir", Active: true,
			UsedBytes: gib, TotalBytes: 2 * gib, CapacityKnown: true,
		},
	)
	body := getBody(t, pveChartHandler(t, tree).Handler(), "/inventory/chart")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("raw script tag from storage id reached the page")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped storage id missing")
	}
}

func TestChartPVEStorageUnknown(t *testing.T) {
	tree := pveChartTree(t,
		pveinventory.StorageInput{
			Node: "pve1", ID: "off", Type: "nfs", Active: false,
			UsedBytes: 0, TotalBytes: 0, CapacityKnown: false,
		},
	)
	body := getBody(t, pveChartHandler(t, tree).Handler(), "/inventory/chart")
	if !strings.Contains(body, "chart__storage-fill--unknown") {
		t.Error("unknown fill marker missing")
	}
	if !strings.Contains(body, ">unknown<") {
		t.Error("unknown text missing")
	}
	if strings.Contains(body, "width:0%") {
		t.Error("unknown storage must not render a 0 % bar")
	}
}

// TestChartPVEStorageBarsCSPCompatible guards finding 6: a strict CSP blocks
// inline width styles, which left the storage fills at zero width. The fill
// must be carried by a CSP-compatible construct (a native meter element), not
// an inline style attribute.
func TestChartPVEStorageBarsCSPCompatible(t *testing.T) {
	tree := pveChartTree(t,
		pveinventory.StorageInput{
			Node: "pve1", ID: "local", Type: "dir", Active: true,
			UsedBytes: 384 * gib, TotalBytes: 480 * gib, CapacityKnown: true,
		},
	)
	body := getBody(t, pveChartHandler(t, tree).Handler(), "/inventory/chart")
	// No inline width style anywhere in the storage markup: a strict CSP
	// (style-src without 'unsafe-inline') drops it and the fill stays at 0.
	if strings.Contains(body, `style="width:`) {
		t.Error("storage fill uses an inline width style; strict CSP blocks it")
	}
	// The fill level is carried by the meter element's value attribute.
	if !strings.Contains(body, `<meter class="chart__storage-meter"`) {
		t.Error("storage fill must use a CSP-compatible meter element")
	}
	if !strings.Contains(body, `value="80">80%</meter>`) {
		t.Error("meter must carry the used percentage in its value attribute")
	}
}

func TestChartPVEUnavailable(t *testing.T) {
	var log strings.Builder
	h := newTestHandler(t, ui.Options{
		Hosts:        func(context.Context) ([]inventory.Host, error) { return chartHosts(), nil },
		PVEChart:     func(context.Context) (pveinventory.Tree, error) { return pveinventory.Tree{}, errors.New("pve down") },
		Log:          slog.New(slog.NewTextHandler(&log, nil)),
		PublicOrigin: "https://nebula.example",
	})
	body := getBody(t, h.Handler(), "/inventory/chart")
	if !strings.Contains(body, "PVE unavailable") {
		t.Error("PVE unavailable message missing")
	}
	if !strings.Contains(body, "chart__box--host") {
		t.Error("managed hosts must still render when PVE is unavailable")
	}
}

func TestChartPVENilProvider(t *testing.T) {
	body := getBody(t, chartHandler(t).Handler(), "/inventory/chart")
	if strings.Contains(body, "chart__box--node") {
		t.Error("PVE node box without provider")
	}
	if strings.Contains(body, "PVE unavailable") {
		t.Error("PVE unavailable message without provider")
	}
}

func TestChartPVENodesBeforeHosts(t *testing.T) {
	tree := pveChartTree(t,
		pveinventory.StorageInput{
			Node: "pve1", ID: "local", Type: "dir", Active: true,
			UsedBytes: gib, TotalBytes: 4 * gib, CapacityKnown: true,
		},
	)
	body := getBody(t, pveChartHandler(t, tree).Handler(), "/inventory/chart")
	i, j := strings.Index(body, "chart__box--node"), strings.Index(body, "chart__box--host")
	if i < 0 || j < 0 || i > j {
		t.Errorf("PVE nodes must render before managed hosts (pve at %d, host at %d)", i, j)
	}
}
