// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// testDigest is a syntactically valid sha256 digest so docker.check_updates
// lines with status current/update are kept (the parser drops them otherwise).
var testDigest = "sha256:" + strings.Repeat("a", 64)

// listLine joins docker.list fields (ID, name, image, state, status, ports,
// project, service, workdir) into one tab-separated line.
func listLine(fields ...string) string { return strings.Join(fields, "\t") }

// updateLine joins docker.check_updates fields (image, status, remote, note)
// into one tab-separated line.
func updateLine(img, status, remote, note string) string {
	return strings.Join([]string{img, status, remote, note}, "\t")
}

// checkUpdatesDoc builds a docker.check_updates result (format
// docker-updates-v1) from tab-separated image lines.
func checkUpdatesDoc(t *testing.T, lines ...string) []byte {
	t.Helper()
	doc, err := json.Marshal(map[string]any{
		"format": "docker-updates-v1",
		"phase":  "done",
		"lines":  base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))),
	})
	if err != nil {
		t.Fatalf("marshal check updates: %v", err)
	}
	return doc
}

// registryTagsDoc builds a registry.tags result: a JSON object mapping an
// image reference to {"tags": [...], "releaseNotes": {tag: note}}.
func registryTagsDoc(t *testing.T, m map[string]any) []byte {
	t.Helper()
	doc, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal registry tags: %v", err)
	}
	return doc
}

// patchChartHandler builds a chart handler with one host ("web") that has a
// stored container list, a same-tag check and registry metadata, plus a
// second host ("ghost") with no update data at all (the "unknown" case).
//
// web containers:
//   - web-nginx  nginx:1.25     same-tag current, newer stable 1.26.3
//   - web-redis  redis:7        same-tag update,    newer stable 7.2.4
//   - web-pg     postgres:16.4  same-tag current,   up-to-date stable 16.4
//   - web-evil   <evil img>     hostile image, no update/registry data
func patchChartHandler(t *testing.T) *ui.Handler {
	t.Helper()
	observed := time.Unix(1791960000, 0)
	// ListsUpdated a bit older than observed so the list age is non-zero.
	listsUpdated := observed.Add(-3 * time.Hour)
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states: map[string]executions.OpsState{
			"web":   {State: "READY", Reason: "no pending work", ObservedAt: observed},
			"ghost": {State: "READY", Reason: "no pending work", ObservedAt: observed},
		},
		updates: map[string]executions.HostUpdates{
			// "web" has a known list age and a pending security update.
			"web": {HostID: "web", Total: 1, Security: 1, Kernel: 0,
				RebootRequired: false, ListsUpdated: listsUpdated, ObservedAt: observed},
			// "ghost" has no HostUpdates entry at all -> unknown.
		},
		docker: map[string]executions.LastResultRow{
			"web": {Result: dockerListDoc(t,
				listLine("a1a1a1a1a1a1", "web-nginx", "nginx:1.25", "running", "Up 5 days", "0.0.0.0:80->80/tcp", "stack-a", "web", "/app"),
				listLine("a2a2a2a2a2a2", "web-redis", "redis:7", "running", "Up 5 days", "", "stack-a", "cache", "/app"),
				listLine("a3a3a3a3a3a3", "web-pg", "postgres:16.4", "running", "Up 5 days", "", "stack-a", "db", "/app"),
				listLine("a4a4a4a4a4a4", "web-evil", "<evil img src=x>", "running", "Up 5 days", "", "", "", ""),
			), FinishedAt: observed},
		},
		dockerUp: map[string]executions.LastResultRow{
			"web": {Result: checkUpdatesDoc(t,
				updateLine("nginx:1.25", "current", testDigest, ""),
				updateLine("redis:7", "update", testDigest, "redis 7.2 available"),
				updateLine("postgres:16.4", "current", testDigest, ""),
			), FinishedAt: observed},
		},
		registry: map[string]executions.LastResultRow{
			"web": {Result: registryTagsDoc(t, map[string]any{
				"nginx:1.25": map[string]any{
					"tags":         []string{"1.25", "1.25.4", "1.26", "1.26.3", "stable"},
					"releaseNotes": map[string]string{"1.26.3": "<b>nginx 1.26.3</b> security fixes"},
				},
				"redis:7":       map[string]any{"tags": []string{"7", "7.2", "7.2.4"}},
				"postgres:16.4": map[string]any{"tags": []string{"15", "16", "16.4"}},
			}), FinishedAt: observed},
		},
	}
	return newTestHandler(t, ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{
				{ID: "web", DisplayName: "Web <host>", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium},
				{ID: "ghost", DisplayName: "Ghost", Environment: inventory.EnvProd, Criticality: inventory.CriticalityLow},
			}, nil
		},
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	})
}

// chartSection extracts the chart <section>…</section> element so the
// mutation-control and template-directive assertions are scoped to the chart,
// not the page chrome (toolbar links, layout nav, etc.).
func chartSection(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<section class="panel chart"`)
	if start < 0 {
		t.Fatalf("chart section not found in body")
	}
	rest := body[start:]
	end := strings.Index(rest, "</section>")
	if end < 0 {
		t.Fatalf("chart section end not found")
	}
	return rest[:end+len("</section>")]
}

func TestChartShowsPatchListAgeAndUnknown(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	// The host with a stored list age shows it next to the patch badge.
	if !strings.Contains(body, `class="chart__listage"`) || !strings.Contains(body, "list ") {
		t.Errorf("list age not shown in chart")
	}
	// The host with no update data shows the unknown state.
	if !strings.Contains(body, "list unknown") {
		t.Errorf("unknown patch state not shown")
	}
	if !strings.Contains(body, "unknown — never checked") {
		t.Errorf("details panel should say unknown (never checked)")
	}
	// The known host shows its source in the details panel.
	if !strings.Contains(body, "source: package list") {
		t.Errorf("patch source not shown in details panel")
	}
}

func TestChartDetailsPanelIsServerRendered(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	for _, want := range []string{
		`<aside class="chart__dpanel"`,
		">Config<",
		">Updates<",
		">Snapshots<",
		">Backups<",
		"none collected", // snapshots and backups are not stored yet
	} {
		if !strings.Contains(body, want) {
			t.Errorf("details panel missing %q", want)
		}
	}
}

func TestChartHasNoMutationControls(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	section := chartSection(t, body)
	for _, bad := range []string{"<form", "<button", "onsubmit", "onclick", "method="} {
		if strings.Contains(strings.ToLower(section), bad) {
			t.Errorf("chart section contains a mutation control %q", bad)
		}
	}
}

func TestChartEscapesHostileNamesAndReleaseNotes(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	// A hostile image reference must be escaped, never rendered as markup.
	if strings.Contains(body, "<evil img src=x>") {
		t.Errorf("hostile image rendered unescaped")
	}
	if !strings.Contains(body, "&lt;evil img src=x&gt;") {
		t.Errorf("hostile image not escaped")
	}
	// A hostile release note must be escaped, never rendered as markup.
	if strings.Contains(body, "<b>nginx 1.26.3</b>") {
		t.Errorf("hostile release note rendered unescaped")
	}
	if !strings.Contains(body, "&lt;b&gt;nginx 1.26.3&lt;/b&gt;") {
		t.Errorf("hostile release note not escaped")
	}
}

func TestChartDistinguishesSameTagFromStable(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	// Same-tag badges (from docker.check_updates statuses).
	for _, want := range []string{
		`badge--ok">up to date`,            // nginx:1.25, postgres:16.4 (current)
		`badge--warning">same tag updated`, // redis:7 (update)
		`badge--unknown">unknown`,          // hostile image (no check data)
	} {
		if !strings.Contains(body, want) {
			t.Errorf("same-tag badge missing %q", want)
		}
	}
	// Stable-version badges (from registrymeta), kept distinct from same-tag.
	for _, want := range []string{
		`badge--warning">stable 1.26.3`,  // nginx:1.25 -> newer stable
		`badge--warning">stable 7.2.4`,   // redis:7 -> newer stable
		`badge--ok">stable 16.4`,         // postgres:16.4 -> up-to-date stable
		`badge--unknown">stable unknown`, // hostile image -> no tag list
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stable badge missing %q", want)
		}
	}
}

func TestChartShowsReleaseNotes(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	if !strings.Contains(body, `chart__note--release`) {
		t.Errorf("release note not shown")
	}
	if !strings.Contains(body, "security fixes") {
		t.Errorf("release note text not present")
	}
}

// TestChartContainerNoteEscaped guards the check_updates note field, a
// separate untrusted string from the release note.
func TestChartContainerNoteEscaped(t *testing.T) {
	observed := time.Unix(1791960000, 0)
	ops := &chartOps{
		fakeOps: &fakeOps{},
		states:  map[string]executions.OpsState{"web": {State: "READY", ObservedAt: observed}},
		docker: map[string]executions.LastResultRow{
			"web": {Result: dockerListDoc(t,
				listLine("a1a1a1a1a1a1", "web-nginx", "nginx:1.25", "running", "Up 5 days", "", "", "", ""),
			), FinishedAt: observed},
		},
		dockerUp: map[string]executions.LastResultRow{
			"web": {Result: checkUpdatesDoc(t,
				updateLine("nginx:1.25", "update", testDigest, "<script>alert(1)</script>"),
			), FinishedAt: observed},
		},
	}
	h := newTestHandler(t, ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web", Environment: inventory.EnvProd}}, nil
		},
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	})
	body := getBody(t, h.Handler(), "/inventory/chart")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("hostile container note rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("escaped container note not shown")
	}
}

// TestChartHasNoUnrenderedDirectives guards against an unbalanced
// {{if}}/{{end}} in the chart template. A broken template would surface a
// literal directive (or panic); checking the rendered output keeps the
// failure message clear.
func TestChartHasNoUnrenderedDirectives(t *testing.T) {
	body := getBody(t, patchChartHandler(t).Handler(), "/inventory/chart")
	section := chartSection(t, body)
	if strings.Contains(section, "{{") {
		t.Errorf("unrendered template directive present in chart output")
	}
}
