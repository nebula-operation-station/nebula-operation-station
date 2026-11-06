// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chartHarnessTimeout bounds one run of the Node.js chart harness.
const chartHarnessTimeout = 30 * time.Second

// runChartHarness runs testdata/chart_client.js on the given script. As for
// the other JavaScript harnesses, a missing Node.js fails the test: CI has
// it, and a skip would turn the behaviour checks silently green.
func runChartHarness(t *testing.T, script, scenario string) (string, error) {
	t.Helper()
	var node string
	for _, name := range []string{"node", "nodejs"} {
		if p, err := exec.LookPath(name); err == nil {
			node = p
			break
		}
	}
	if node == "" {
		t.Fatal("Node.js (node) is not on PATH; it is needed to run the chart harness")
	}
	harness, err := filepath.Abs(filepath.Join("testdata", "chart_client.js"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), chartHarnessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, harness, scenario)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS="}
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// The chart code runs against a fake DOM with a real geometry model: a wrong
// zoom direction, Fit formula, wheel sign, key mapping or pan bound fails
// here, not only a changed string.
func TestChartInteractionBehaviour(t *testing.T) {
	script := inventoryJS(t)
	for _, scenario := range []string{
		"zoommath",       // zoomAt: direction, fixed point, both caps
		"fitmath",        // fitTransform: known box sizes
		"wheelmath",      // wheelDelta: signs, units, pinch cap, Shift
		"keymath",        // keyAction: mapping, browser shortcuts
		"panmath",        // clampPan and wheelPan
		"buttons",        // toolbar buttons drive the real handlers
		"hundredhosts",   // Fit shows 100 hosts on the smallest canvas
		"wheelpan",       // scroll pans, in the right direction
		"wheelrelease",   // at the edge the page scrolls
		"wheelzoom",      // Ctrl/Meta+scroll and pinch zoom around the pointer
		"wheelnocancel",  // a wheel event that cannot be cancelled stays with the page
		"gesture",        // Safari gesture events
		"touchswipe",     // one finger: the chart while it can follow, then the page
		"touchlandscape", // a landscape phone reaches the form below the canvas
		"touchcontrol",   // a swipe from a control is the page's
		"touchnocancel",  // an uncancelable touchmove is left alone
		"pinch",          // two fingers zoom and move, on boxes too
		"pinchfingers",   // fingers landing and lifting during a pinch
		"pinchsafari",    // gesture and pointer events do not zoom twice
		"touchlist",      // list mode and a rotation into it
		"mousedrag",      // a mouse drag is not a swipe
		"clicktoggle",    // a click on a box toggles it, a shaky one too
		"dragnotoggle",   // a drag from a box pans and leaves it as it was
		"dragcontrol",    // links and buttons stay clickable
		"dragslop",       // the drag threshold, a press lost outside the canvas
		"touchbox",       // a tap on a box toggles, a swipe from it pans
		"focusreveal",    // a mouse focus does not move the box from under the pointer
		"expandall",      // Expand all and Collapse all, on the canvas and in the list
		"expandkept",     // pan, zoom and mode changes keep the boxes as they are
		"keys",           // keys through the real handler
		"panbounds",      // part of the chart stays visible
		"listmode",       // the plain list leaves every default alone
	} {
		t.Run(scenario, func(t *testing.T) {
			out, err := runChartHarness(t, script, scenario)
			if err != nil {
				t.Fatalf("harness %s: %v\n%s", scenario, err, out)
			}
			if out != "ok "+scenario {
				t.Fatalf("harness %s output = %q", scenario, out)
			}
		})
	}
}

// The harness has to notice the breakages it exists for: each change below
// is a bug, and the harness must fail on it. A replaced line that no longer
// exists fails too, so this list cannot go stale unnoticed.
func TestChartHarnessCatchesBrokenBehaviour(t *testing.T) {
	script := inventoryJS(t)
	for _, tc := range []struct{ name, from, to string }{
		{"swapped Zoom in button", "zoomInBtn.addEventListener('click', () => zoomBy(zoomStep))", "zoomInBtn.addEventListener('click', () => zoomBy(1 / zoomStep))"},
		{"swapped Zoom out button", "zoomOutBtn.addEventListener('click', () => zoomBy(1 / zoomStep))", "zoomOutBtn.addEventListener('click', () => zoomBy(zoomStep))"},
		{"zoom ignores the fixed point", "tx: mx - (mx - t.tx) * f", "tx: t.tx"},
		{"no upper zoom limit", "Math.min(maxScale, Math.max(minScale, s))", "Math.max(minScale, s)"},
		{"no lower zoom limit", "Math.min(maxScale, Math.max(minScale, s))", "Math.min(maxScale, s)"},
		{"flipped zoom wheel sign", "Math.exp(-d * 0.01)", "Math.exp(d * 0.01)"},
		{"flipped pan wheel sign", "clamp(t - d,", "clamp(t + d,"},
		{"no pinch cap", "const d = clamp(dy, -wheelZoomCap, wheelZoomCap);", "const d = dy;"},
		{"plus key zooms out", "case '=': return { zoom: zoomStep };", "case '=': return { zoom: 1 / zoomStep };"},
		{"minus key zooms in", "case '-': return { zoom: 1 / zoomStep };", "case '-': return { zoom: zoomStep };"},
		{"zero key does not fit", "case '0': return { fit: true };", "case '0': return null;"},
		{"arrow keys swapped", "case 'ArrowDown': return { dx: 0, dy: keyStep };", "case 'ArrowDown': return { dx: 0, dy: -keyStep };"},
		{"browser shortcuts taken", "if (e.ctrlKey || e.metaKey || e.altKey) return null;", ""},
		{"Fit ignores the height", "Math.min(1, b.w / b.chartW, b.h / b.chartH)", "Math.min(1, b.w / b.chartW)"},
		{"Fit enlarges", "Math.min(1, b.w / b.chartW, b.h / b.chartH)", "Math.min(b.w / b.chartW, b.h / b.chartH)"},
		{"Fit does not centre", "tx: Math.max(0, (b.w - b.chartW * scale) / 2)", "tx: 0"},
		{"min scale too large for 100 hosts", "const minScale = 0.015;", "const minScale = 0.02;"},
		{"pan without bounds", "const place = (x, y, s) => {\n    const b = box();", "const place = (x, y, s) => {\n    const b = { w: 1e9, h: 1e9, chartW: 1e9, chartH: 1e9 };"},
		{"wheel never releases", "if (panBy(d.dx, d.dy)) e.preventDefault();", "panBy(d.dx, d.dy); e.preventDefault();"},
		{"wheel pans without being cancelable", "if (!panning() || !e.cancelable) return;\n    const d = M.wheelDelta", "if (!panning()) return;\n    const d = M.wheelDelta"},
		{"Fit of a very wide chart starts off-screen", "tx: Math.max(0, (b.w - b.chartW * scale) / 2)", "tx: (b.w - b.chartW * scale) / 2"},
		{"swipe never releases at the edge", "drag.held = Math.abs(dx) > Math.abs(dy) || M.wheelPan(ty, -dy, b.h, b.chartH * scale) !== ty;", "drag.held = true;"},
		{"vertical swipe always leaves the chart", "drag.held = Math.abs(dx) > Math.abs(dy) || M.wheelPan(ty, -dy, b.h, b.chartH * scale) !== ty;", "drag.held = Math.abs(dx) > Math.abs(dy);"},
		{"held swipe is not cancelled", "if (pinch || (drag && holdSwipe(t.clientX, t.clientY))) e.preventDefault();", "if (pinch) e.preventDefault();"},
		{"pinch is not cancelled", "if (pinch || (drag && holdSwipe(t.clientX, t.clientY))) e.preventDefault();", "if (drag && holdSwipe(t.clientX, t.clientY)) e.preventDefault();"},
		{"uncancelable touchmove cancelled", "if (!panning() || !e.cancelable) return;\n    const t = e.targetTouches[0];", "if (!panning()) return;\n    const t = e.targetTouches[0];"},
		{"pinch only from free space", "if (touch) {\n      if (e.isPrimary)", "if (touch && !e.target.closest('a, button, summary')) {\n      if (e.isPrimary)"},
		{"pinch ignores the midpoint", "place(tx + p.x - pinch.x, ty + p.y - pinch.y, scale);\n      ", ""},
		{"pinch zooms before it moves", "place(tx + p.x - pinch.x, ty + p.y - pinch.y, scale);\n      zoomAt(pinch.scale * p.dist / pinch.dist, p.x, p.y);", "zoomAt(pinch.scale * p.dist / pinch.dist, p.x, p.y);\n      place(tx + p.x - pinch.x, ty + p.y - pinch.y, scale);"},
		{"pinch distance can be zero", "dist: Math.max(1, Math.hypot(a.x - b.x, a.y - b.y))", "dist: Math.hypot(a.x - b.x, a.y - b.y)"},
		{"lost finger stays tracked", "if (e.isPrimary) { fingers.clear(); pinch = null; }", ""},
		{"last finger of a pinch stops", "drag = { x: f.x, y: f.y, tx, ty, held: true };", ""},
		{"gesture events zoom on top of the pinch", "if (!pinch) zoomAt(gestureBase * e.scale, e.clientX, e.clientY);", "zoomAt(gestureBase * e.scale * 2, e.clientX, e.clientY);"},
		{"pointer moves ignore list mode", "chartSection.addEventListener('pointermove', (e) => {\n    if (!panning()) return;", "chartSection.addEventListener('pointermove', (e) => {"},
		{"touchmove is taken in list mode", "if (!panning() || !e.cancelable) return;\n    const t = e.targetTouches[0];", "if (!e.cancelable) return;\n    const t = e.targetTouches[0];"},
		{"toggle listener misses the capture phase", "if (panning()) place(tx, ty, scale);\n  }, true);", "if (panning()) place(tx, ty, scale);\n  });"},
		{"zoom wheel reaches the browser", "e.preventDefault();\n      zoomAt(scale * d.zoom, e.clientX, e.clientY);", "zoomAt(scale * d.zoom, e.clientX, e.clientY);"},
		{"drag does not start on a box", "e.target.closest('a, button, input,", "e.target.closest('a, button, summary, input,"},
		{"drag starts on a link", "e.target.closest('a, button, input,", "e.target.closest('input,"},
		{"no drag threshold", "if (Math.hypot(dx, dy) < dragSlop) return;\n", ""},
		{"pointer captured on press", "drag = { x: e.clientX, y: e.clientY, tx, ty, held: !touch };", "drag = { x: e.clientX, y: e.clientY, tx, ty, held: !touch };\n    chartSection.setPointerCapture(e.pointerId);"},
		{"pointer not captured for a drag", "drag.moved = true;\n        chartSection.setPointerCapture(e.pointerId);", "drag.moved = true;"},
		{"drag toggles the box", "if (dragged && e.detail) e.preventDefault();", ""},
		{"a drag swallows the keyboard", "if (dragged && e.detail) e.preventDefault();", "if (dragged) e.preventDefault();"},
		{"a drag swallows every later click", "dragged = !!drag?.moved;", "dragged ||= !!drag?.moved;"},
		{"press lost outside the canvas drags on", "if (e.buttons === 0) drag = null;", ""},
		{"mouse focus pans the chart", "if (e.target.matches(':focus-visible')) revealFocus(e.target);", "revealFocus(e.target);"},
		{"keyboard focus does not pan", "if (e.target.matches(':focus-visible')) revealFocus(e.target);", ""},
		{"Collapse all opens", "['chart-collapse-all', false]", "['chart-collapse-all', true]"},
		{"Expand all closes", "['chart-expand-all', true]", "['chart-expand-all', false]"},
		{"buttons shown without boxes", "btn.hidden = !boxes.length;", "btn.hidden = false;"},
		{"Expand all hidden in the list", "for (const el of panOnly) if (el) el.hidden = !pan;", "for (const el of panOnly) if (el) el.hidden = !pan;\n    document.getElementById('chart-expand-all').hidden = !pan;"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(script, tc.from) {
				t.Fatalf("inventory.js no longer contains %q", tc.from)
			}
			broken := strings.Replace(script, tc.from, tc.to, 1)
			out, err := runChartHarness(t, broken, "all")
			if err == nil {
				t.Fatalf("harness passes with this bug: %s", out)
			}
			if !strings.HasPrefix(out, "FAIL: ") {
				t.Fatalf("harness broke instead of reporting the bug: %s", out)
			}
		})
	}
}
