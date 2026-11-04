// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Run with: node --test web/static/trafficmap/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { acceptMessage, send, OUT } from "./bridge.js";
import { createBackend } from "./main.js";
import { validateModel, MSG_ICONS } from "./model.js";
import { computeLayout } from "./layout.js";
import { buildScene, ZOOM } from "./scene.js";
import { createCamera, pick, worldToScreen, screenToWorld, zoomAt, relativeZoom, MAX_RELATIVE_ZOOM } from "./camera.js";

const ORIGIN = "https://nos.example";

function fakeWindow() {
  const sent = [];
  const parent = { postMessage: (data, origin) => sent.push({ data, origin }) };
  return { parent, location: { origin: ORIGIN }, sent };
}

function modelMessage() {
  return JSON.parse(readFileSync(new URL("./testdata/model-valid.json", import.meta.url), "utf8"));
}

test("AcceptsModelOnlyFromParentWithOwnOrigin", () => {
  const win = fakeWindow();
  const ok = acceptMessage({ source: win.parent, origin: ORIGIN, data: modelMessage() }, win, () => false);
  assert.equal(ok.kind, "model");
  assert.equal(acceptMessage({ source: {}, origin: ORIGIN, data: modelMessage() }, win, () => false), null);
  assert.equal(acceptMessage({ source: win.parent, origin: "https://evil.example", data: modelMessage() }, win, () => false), null);
  assert.equal(acceptMessage({ source: win.parent, origin: "null", data: modelMessage() }, win, () => false), null);
});

test("RejectsUnknownAndInvalidMessages", () => {
  const win = fakeWindow();
  const ev = (data) => ({ source: win.parent, origin: ORIGIN, data });
  assert.equal(acceptMessage(ev({ type: "nos.trafficmap.fetch", url: "https://x" }), win, () => false).kind, "error");
  assert.equal(acceptMessage(ev("string"), win, () => false).kind, "error");
  assert.equal(acceptMessage(ev(null), win, () => false).kind, "error");
  const bad = modelMessage();
  bad.nodes[1].label = "\u202e";
  const r = acceptMessage(ev(bad), win, () => false);
  assert.equal(r.kind, "error");
  assert.ok(r.errors.length > 0);
});

function fakeBitmap(width = 16, height = 16) {
  const b = { width, height, closed: false, close() { this.closed = true; } };
  return b;
}

test("RejectedIconMessagesCloseTheirBitmaps", () => {
  const win = fakeWindow();
  const isBitmap = (v) => v !== null && typeof v === "object" && "close" in v;
  const ev = (data) => ({ source: win.parent, origin: ORIGIN, data });

  const badKey = fakeBitmap();
  const r1 = acceptMessage(ev({ type: MSG_ICONS, icons: { "Bad Key": badKey } }), win, isBitmap);
  assert.equal(r1.kind, "error", "a bad catalog key is rejected");
  assert.ok(badKey.closed, "the bitmap of a bad key is closed");

  const big = fakeBitmap(1000, 16);
  const r2 = acceptMessage(ev({ type: MSG_ICONS, icons: { docker: big } }), win, isBitmap);
  assert.equal(r2.kind, "error", "an oversized bitmap is rejected");
  assert.ok(big.closed, "the oversized bitmap is closed");

  const many = {};
  for (let i = 0; i < 513; i++) many["k" + i] = fakeBitmap();
  const r3 = acceptMessage(ev({ type: MSG_ICONS, icons: many }), win, isBitmap);
  assert.equal(r3.kind, "error", "too many entries is rejected");
  assert.ok(Object.values(many).every((b) => b.closed), "all bitmaps of a rejected message are closed");

  const good = fakeBitmap();
  const r4 = acceptMessage(ev({ type: MSG_ICONS, icons: { docker: good } }), win, isBitmap);
  assert.equal(r4.kind, "icons", "a valid message is accepted");
  assert.ok(!good.closed, "accepted bitmaps stay open");
});

test("SendTargetsOwnOriginNeverWildcard", () => {
  const win = fakeWindow();
  send(win, OUT.select, { id: "vm101" });
  assert.deepEqual(win.sent, [{ data: { type: OUT.select, id: "vm101" }, origin: ORIGIN }]);
  const top = { location: { origin: ORIGIN } };
  top.parent = top;
  send(top, OUT.ready, {});
});

test("FallsBackToCanvas2DWhenWebGL2Missing", () => {
  const made = [];
  const makeCanvas = () => {
    const c = { n: made.length };
    made.push(c);
    return c;
  };
  const r = createBackend(makeCanvas, { webgl2: () => null, canvas2d: (c) => ({ name: "canvas2d", c }) }, true, () => {});
  assert.equal(r.backend.name, "canvas2d");
  assert.ok(r.fallback);
  assert.equal(made.length, 2, "Canvas 2D gets a fresh canvas");
  assert.equal(r.canvas, made[1]);
});

test("FallsBackToCanvas2DWhenWebGL2Throws", () => {
  const r = createBackend(() => ({}), { webgl2: () => { throw new Error("compile shader"); }, canvas2d: () => ({ name: "canvas2d" }) }, true, () => {});
  assert.equal(r.backend.name, "canvas2d");
  assert.ok(r.fallback);
});

test("UsesWebGL2WhenAvailable", () => {
  let lostCb = null;
  const r = createBackend(() => ({}), { webgl2: (c, onLost) => { lostCb = onLost; return { name: "webgl2" }; }, canvas2d: () => assert.fail("not used") }, true, () => "lost");
  assert.equal(r.backend.name, "webgl2");
  assert.equal(r.fallback, false);
  assert.equal(lostCb(), "lost", "context-loss callback is wired through");
});

test("ForcedCanvas2DSkipsWebGL2", () => {
  const r = createBackend(() => ({}), { webgl2: () => assert.fail("not used"), canvas2d: () => ({ name: "canvas2d" }) }, false, () => {});
  assert.equal(r.backend.name, "canvas2d");
});

test("NoBackendAtAll", () => {
  const r = createBackend(() => ({}), { webgl2: () => null, canvas2d: () => null }, true, () => {});
  assert.equal(r.backend, null);
});

test("CameraRoundTripAndBounds", () => {
  const cam = createCamera(500, 800, 600);
  const [sx, sy] = worldToScreen(cam, 120, -40);
  const [wx, wy] = screenToWorld(cam, sx, sy);
  assert.ok(Math.abs(wx - 120) < 1e-9 && Math.abs(wy + 40) < 1e-9);
  for (let i = 0; i < 100; i++) zoomAt(cam, 400, 300, 2);
  assert.ok(Math.abs(relativeZoom(cam) - MAX_RELATIVE_ZOOM) < 1e-9);
});

test("PickFindsStarUnderPointer", () => {
  const m = validateModel(modelMessage());
  const l = computeLayout(m);
  const s = buildScene(m, l, { level: ZOOM.zone, focus: null });
  const cam = createCamera(l.extent, 1000, 800);
  const p = l.nodes.get("vm101");
  const [sx, sy] = worldToScreen(cam, p.x, p.y);
  assert.equal(pick(s, cam, sx, sy), "vm101");
  assert.equal(pick(s, cam, 1, 1), null);
});
