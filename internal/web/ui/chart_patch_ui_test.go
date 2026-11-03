// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
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

// chartNode is one element of the rendered chart region: its tag, its
// attributes in source order, and its place in the element tree.
type chartNode struct {
	tag    string
	attrs  [][2]string
	parent *chartNode
	kids   []*chartNode
}

// attr returns the value of the named attribute and whether it is present.
func (n *chartNode) attr(name string) (string, bool) {
	for _, a := range n.attrs {
		if a[0] == name {
			return a[1], true
		}
	}
	return "", false
}

// hasClass reports whether the class attribute lists c.
func (n *chartNode) hasClass(c string) bool {
	v, _ := n.attr("class")
	for _, f := range strings.Fields(v) {
		if f == c {
			return true
		}
	}
	return false
}

// ancestor returns the closest ancestor with the tag.
func (n *chartNode) ancestor(tag string) *chartNode {
	for p := n.parent; p != nil; p = p.parent {
		if p.tag == tag {
			return p
		}
	}
	return nil
}

// walk calls fn for n and every descendant, depth first.
func (n *chartNode) walk(fn func(*chartNode)) {
	fn(n)
	for _, k := range n.kids {
		k.walk(fn)
	}
}

var (
	// chartTagRe matches one opening or closing tag. html/template escapes
	// '<' and '>' in text and attribute values, so a tag never contains '>'.
	chartTagRe = regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9-]*)(\s[^>]*)?>`)
	// chartAttrRe matches one attribute: a bare name or name="value".
	chartAttrRe = regexp.MustCompile(`([^\s="'>/]+)(?:\s*=\s*"([^"]*)")?`)
	// chartVoid lists the void elements (no closing tag).
	chartVoid = map[string]bool{"area": true, "base": true, "br": true, "col": true,
		"embed": true, "hr": true, "img": true, "input": true, "link": true,
		"meta": true, "source": true, "track": true, "wbr": true}
	// buttonTextRe captures the content of each button, in source order.
	buttonTextRe = regexp.MustCompile(`(?s)<button\b[^>]*>(.*?)</button>`)
)

// chartRegion parses the whole chart <section> — every nested element up
// to its matching </section>, not the first nested one — into an element
// tree and returns the tree and the raw markup. Unbalanced or mismatched
// tags fail the test, so a broken template cannot hide markup from a scan.
func chartRegion(t *testing.T, body string) (*chartNode, string) {
	t.Helper()
	start := strings.Index(body, `<section class="panel chart"`)
	if start < 0 {
		t.Fatalf("chart section not found in body")
	}
	var root *chartNode
	var stack []*chartNode
	for _, m := range chartTagRe.FindAllStringSubmatchIndex(body[start:], -1) {
		tag := strings.ToLower(body[start+m[4] : start+m[5]])
		if m[3] > m[2] { // closing tag
			if len(stack) == 0 || stack[len(stack)-1].tag != tag {
				t.Fatalf("chart markup: unexpected </%s> at %d", tag, start+m[0])
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return root, body[start : start+m[1]]
			}
			continue
		}
		n := &chartNode{tag: tag}
		if m[6] >= 0 {
			for _, a := range chartAttrRe.FindAllStringSubmatch(body[start+m[6]:start+m[7]], -1) {
				n.attrs = append(n.attrs, [2]string{strings.ToLower(a[1]), a[2]})
			}
		}
		if root == nil {
			root = n
		} else {
			n.parent = stack[len(stack)-1]
			n.parent.kids = append(n.parent.kids, n)
		}
		if !chartVoid[tag] {
			stack = append(stack, n)
		}
	}
	t.Fatalf("chart section end not found")
	return nil, ""
}

// detailsButtonShape checks a button against the one shape allowed in the
// chart: exactly type="button", class="chart__dpanel-btn", hidden and a
// non-empty data-nos-dpanel-btn — nothing else (no form, formaction, name,
// value, extra class, data attribute or handler) — and the text "Details".
func detailsButtonShape(n *chartNode, text string) error {
	if n.tag != "button" {
		return fmt.Errorf("not a button: <%s>", n.tag)
	}
	want := map[string]string{"type": "button", "class": "chart__dpanel-btn", "hidden": ""}
	seen := map[string]bool{}
	for _, a := range n.attrs {
		if seen[a[0]] {
			return fmt.Errorf("duplicate attribute %s", a[0])
		}
		seen[a[0]] = true
		if a[0] == "data-nos-dpanel-btn" {
			if a[1] == "" {
				return fmt.Errorf("empty data-nos-dpanel-btn")
			}
			continue
		}
		v, ok := want[a[0]]
		if !ok {
			return fmt.Errorf("attribute %s not allowed", a[0])
		}
		if a[1] != v {
			return fmt.Errorf("attribute %s=%q, want %q", a[0], a[1], v)
		}
	}
	for _, k := range []string{"type", "class", "hidden", "data-nos-dpanel-btn"} {
		if !seen[k] {
			return fmt.Errorf("missing attribute %s", k)
		}
	}
	if len(n.kids) != 0 || text != "Details" {
		return fmt.Errorf("button content %q, want plain text Details", text)
	}
	return nil
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

// The chart has no mutation controls before phase 2: no forms, no inputs,
// no inline handlers, no method or formaction attributes, and "<button" is
// banned except the read-only Details button in its one exact shape. The
// scan covers the whole chart region: every host, every details panel
// (whose sections are nested <section> elements) and the sheet. The Fit
// button is page chrome outside the chart and is not allowed in here.
func TestChartHasNoMutationControls(t *testing.T) {
	for name, h := range map[string]*ui.Handler{"patch": patchChartHandler(t), "pve": chartHandler(t)} {
		t.Run(name, func(t *testing.T) {
			body := getBody(t, h.Handler(), "/inventory/chart")
			root, raw := chartRegion(t, body)
			lower := strings.ToLower(raw)
			for _, bad := range []string{"<form", "<input", "<select", "<textarea",
				"onsubmit", "onclick", "method=", "formaction", "formmethod"} {
				if strings.Contains(lower, bad) {
					t.Errorf("chart region contains a mutation control %q", bad)
				}
			}
			// The scan reaches past the nested panel sections: the sheet
			// closes the chart region.
			if !strings.Contains(raw, `id="chart-sheet"`) {
				t.Fatalf("chart region scan stops before the sheet")
			}
			var buttons []*chartNode
			root.walk(func(n *chartNode) {
				for _, a := range n.attrs {
					if strings.HasPrefix(a[0], "on") || a[0] == "form" || a[0] == "formaction" {
						t.Errorf("attribute %s on <%s> in the chart region", a[0], n.tag)
					}
				}
				if n.tag == "button" {
					buttons = append(buttons, n)
				}
			})
			texts := buttonTextRe.FindAllStringSubmatch(raw, -1)
			if got := strings.Count(lower, "<button"); got != len(buttons) || len(texts) != len(buttons) {
				t.Fatalf("button count mismatch: raw %d, parsed %d, texts %d", got, len(buttons), len(texts))
			}
			if len(buttons) == 0 {
				t.Fatal("no details buttons found in the chart region")
			}
			for i, b := range buttons {
				if err := detailsButtonShape(b, texts[i][1]); err != nil {
					t.Errorf("chart region has a non-navigation button: %v (%s)", err, texts[i][0])
				}
			}
		})
	}
}

// The allowed-button check is exact: a button that could submit, carry
// data or act differently is rejected, not only the obvious ones.
func TestChartDetailsButtonShapeRejectsLookalikes(t *testing.T) {
	const ok = `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web">Details</button>`
	for _, tc := range []struct{ name, tag string }{
		{"submit", `<button type="submit" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web">Details</button>`},
		{"no type", `<button class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web">Details</button>`},
		{"formaction", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web" formaction="/x">Details</button>`},
		{"form", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web" form="f">Details</button>`},
		{"name", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web" name="n">Details</button>`},
		{"value", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web" value="v">Details</button>`},
		{"extra class", `<button type="button" class="chart__dpanel-btn danger" hidden data-nos-dpanel-btn="web">Details</button>`},
		{"other data", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web" data-action="reboot">Details</button>`},
		{"empty id", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="">Details</button>`},
		{"no id", `<button type="button" class="chart__dpanel-btn" hidden>Details</button>`},
		{"not hidden", `<button type="button" class="chart__dpanel-btn" data-nos-dpanel-btn="web">Details</button>`},
		{"duplicate type", `<button type="button" type="submit" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web">Details</button>`},
		{"handler", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web" onclick="x()">Details</button>`},
		{"other text", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web">Reboot</button>`},
		{"markup", `<button type="button" class="chart__dpanel-btn" hidden data-nos-dpanel-btn="web"><span>Details</span></button>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := chartRegion(t, `<section class="panel chart">`+tc.tag+`</section>`)
			text := buttonTextRe.FindStringSubmatch(tc.tag)[1]
			if err := detailsButtonShape(root.kids[0], text); err == nil {
				t.Errorf("lookalike button accepted: %s", tc.tag)
			}
		})
	}
	root, _ := chartRegion(t, `<section class="panel chart">`+ok+`</section>`)
	if err := detailsButtonShape(root.kids[0], "Details"); err != nil {
		t.Errorf("allowed shape rejected: %v", err)
	}
}

// Review of PR #165: the Details button is a direct child of its host
// node, never inside the <summary> (a button there is invalid interactive
// content and toggles the host) nor inside <details> (hidden while the
// host is collapsed), and it sits next to its own host's panel.
func TestChartDetailsButtonOutsideSummary(t *testing.T) {
	for name, h := range map[string]*ui.Handler{"patch": patchChartHandler(t), "pve": chartHandler(t)} {
		t.Run(name, func(t *testing.T) {
			root, _ := chartRegion(t, getBody(t, h.Handler(), "/inventory/chart"))
			n := 0
			root.walk(func(b *chartNode) {
				if b.tag != "button" {
					return
				}
				n++
				id, _ := b.attr("data-nos-dpanel-btn")
				if b.ancestor("summary") != nil {
					t.Errorf("details button %q is inside a <summary>", id)
				}
				if b.ancestor("details") != nil {
					t.Errorf("details button %q is inside <details>", id)
				}
				node := b.parent
				if node == nil || node.tag != "li" || !node.hasClass("chart__node") {
					t.Errorf("details button %q is not a direct child of its host node", id)
					return
				}
				panels := 0
				node.walk(func(p *chartNode) {
					if v, ok := p.attr("data-nos-dpanel"); ok {
						panels++
						if v != id {
							t.Errorf("button %q sits next to the panel of %q", id, v)
						}
					}
				})
				if panels != 1 {
					t.Errorf("host node of button %q has %d panels, want 1", id, panels)
				}
			})
			if n == 0 {
				t.Fatal("no details buttons rendered")
			}
		})
	}
}

// The details sheet comes with a backdrop that closes it; both are hidden
// without JS, and the backdrop is an empty element.
func TestChartSheetHasHiddenBackdrop(t *testing.T) {
	root, _ := chartRegion(t, getBody(t, patchChartHandler(t).Handler(), "/inventory/chart"))
	var sheet, backdrop *chartNode
	root.walk(func(n *chartNode) {
		switch id, _ := n.attr("id"); id {
		case "chart-sheet":
			sheet = n
		case "chart-sheet-backdrop":
			backdrop = n
		}
	})
	if sheet == nil || backdrop == nil {
		t.Fatalf("sheet found %v, backdrop found %v", sheet != nil, backdrop != nil)
	}
	for _, n := range []*chartNode{sheet, backdrop} {
		if _, ok := n.attr("hidden"); !ok {
			t.Errorf("<%s> must be hidden without JS", n.tag)
		}
	}
	if v, _ := sheet.attr("aria-modal"); v != "true" {
		t.Errorf("sheet aria-modal = %q, want true", v)
	}
	if !backdrop.hasClass("dpanel-backdrop") || len(backdrop.kids) != 0 {
		t.Errorf("backdrop must be an empty .dpanel-backdrop element")
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
	_, section := chartRegion(t, body)
	if strings.Contains(section, "{{") {
		t.Errorf("unrendered template directive present in chart output")
	}
}
