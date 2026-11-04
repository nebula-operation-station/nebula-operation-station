// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Behaviour of startTrafficMap against a fake DOM: backend selection,
// context loss, throwing backends and the frame loop's error handling.
// The real WebGL2 and Canvas 2D backends run against fake contexts.
// Run with: node --test web/static/trafficmap/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { startTrafficMap, STATUS, MAX_FRAME_FAILURES, REBUILD_BACKOFF_BASE_MS, REBUILD_BACKOFF_MAX_MS, rebuildBackoffMs } from "./main.js";
import { OUT } from "./bridge.js";
import { segmentVisible } from "./canvas2d.js";
import { buildScene } from "./scene.js";

const ORIGIN = "https://nos.example";

function modelMessage() {
  return JSON.parse(readFileSync(new URL("./testdata/model-valid.json", import.meta.url), "utf8"));
}

class FakeTarget {
  constructor() {
    this.listeners = new Map();
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
  }
  removeEventListener(type, fn) {
    if (this.listeners.has(type)) this.listeners.get(type).delete(fn);
  }
  dispatch(type, ev = {}) {
    const e = { type, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...ev };
    for (const fn of [...(this.listeners.get(type) || [])]) fn(e);
    return e;
  }
}

// fake2d is a 2D context that accepts every call; fail.d2 makes the next
// fillRect (the first call of a Canvas 2D render) throw.
function fake2d(fail) {
  const gradient = { addColorStop() {} };
  const target = {
    createRadialGradient: () => gradient,
    createLinearGradient: () => gradient,
    measureText: () => ({ width: 0 }),
    fillRect() {
      if (fail.d2) throw new Error("fake 2d failure");
    },
    drawImage() {
      if (fail.drawImage) throw new Error("fake drawImage failure");
    },
  };
  return new Proxy(target, {
    get(t, k) {
      if (k in t) return t[k];
      return () => {};
    },
    set(t, k, v) {
      t[k] = v;
      return true;
    },
  });
}

// fakeGL is a WebGL2 context good enough for createWebGL2Backend: shaders
// compile, there is no float colour buffer (no bloom), and fail.gl makes
// draw calls throw. Enum constants are their own names.
function fakeGL(state, fail) {
  const target = {
    drawingBufferWidth: 800,
    drawingBufferHeight: 600,
    isContextLost: () => state.lost,
    getExtension: (name) => (name === "WEBGL_lose_context" ? { loseContext: () => (state.released = true) } : null),
    getShaderParameter: () => true,
    getProgramParameter: (p, k) => (k === "ACTIVE_UNIFORMS" ? 0 : true),
    getUniformLocation: () => null,
    drawArraysInstanced() {
      if (fail.gl) throw new Error("fake GL failure");
    },
    bufferData() {
      state.bufferDataCalls++;
      const up = fail.upload;
      if (up && (typeof up !== "function" || up(state.bufferDataCalls))) throw new Error("fake upload failure");
    },
    createShader() {
      if (fail.compile) throw new Error("fake compile failure");
      return {};
    },
  };
  return new Proxy(target, {
    get(t, k) {
      if (k in t) return t[k];
      if (typeof k === "string" && /^[A-Z0-9_]+$/.test(k)) return k;
      return () => ({});
    },
  });
}

class FakeElement extends FakeTarget {
  constructor(doc, tag) {
    super();
    this.ownerDocument = doc;
    this.tagName = tag;
    this.style = {};
    this.attrs = {};
    this.children = [];
    this.textContent = "";
  }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
  }
  append(...els) {
    this.children.push(...els);
  }
  insertBefore(el, ref) {
    const i = this.children.indexOf(ref);
    this.children.splice(i < 0 ? this.children.length : i, 0, el);
  }
  replaceChild(el, old) {
    this.children[this.children.indexOf(old)] = el;
  }
  getBoundingClientRect() {
    return { left: 0, top: 0, width: 800, height: 600 };
  }
  setPointerCapture() {}
  focus() {}
}

class FakeCanvas extends FakeElement {
  constructor(doc, env) {
    super(doc, "canvas");
    this.env = env;
    this.kind = null;
    this.glState = { lost: false, released: false, bufferDataCalls: 0 };
  }
  getContext(type) {
    if (this.kind !== null && this.kind !== type) return null;
    if (type === "webgl2") {
      if (!this.env.webgl) return null;
      this.kind = type;
      return fakeGL(this.glState, this.env.fail);
    }
    if (type === "2d") {
      this.kind = type;
      return (this.ctx2d ??= fake2d(this.env.fail));
    }
    return null;
  }
  loseContext() {
    this.glState.lost = true;
    this.dispatch("webglcontextlost");
  }
}

class FakeBitmap {
  constructor() {
    this.width = 16;
    this.height = 16;
    this.closed = false;
  }
  close() {
    this.closed = true;
  }
}

// flakyBuild wraps buildScene: it throws while broken() is true for the
// call number, and counts every call.
function flakyBuild(broken) {
  const b = {
    calls: 0,
    build(...args) {
      b.calls++;
      if (broken(b.calls)) throw new Error("fake buildScene failure");
      return buildScene(...args);
    },
  };
  return b;
}

// setup starts the map against a fake window. prepare may arm failures
// before startTrafficMap runs; build replaces buildScene and reducedMotion
// makes prefers-reduced-motion match.
function setup({ webgl = true, prepare = () => {}, build = undefined, reducedMotion = false } = {}) {
  const env = { webgl, fail: {}, canvases: [] };
  prepare(env);
  const sent = [];
  const frames = [];
  const win = new FakeTarget();
  win.parent = { postMessage: (data, origin) => sent.push({ data, origin }) };
  win.location = { origin: ORIGIN };
  win.devicePixelRatio = 1;
  win.ImageBitmap = FakeBitmap;
  win.requestAnimationFrame = (fn) => frames.push(fn);
  win.matchMedia = () => ({ matches: reducedMotion });
  const doc = {
    defaultView: win,
    createElement(tag) {
      if (tag === "canvas") {
        const c = new FakeCanvas(doc, env);
        env.canvases.push(c);
        return c;
      }
      return new FakeElement(doc, tag);
    },
  };
  const root = new FakeElement(doc, "div");
  const map = startTrafficMap(root, build ? { buildScene: build } : {});
  let now = 0;
  const post = (data) => win.dispatch("message", { source: win.parent, origin: ORIGIN, data });
  return {
    env,
    sent,
    root,
    map,
    // tick runs the pending animation frame n times. It fails if the loop
    // was not re-armed, which is exactly the freeze the frame loop must avoid.
    tick(n = 1) {
      for (let i = 0; i < n; i++) {
        assert.equal(frames.length, 1, "exactly one animation frame is pending");
        now += 16;
        frames.pop()(now);
      }
    },
    // advance runs animation frames until at least ms have passed and
    // calls each(status) after every frame.
    advance(ms, each = () => {}) {
      const until = now + ms;
      while (now < until) {
        this.tick(1);
        each(this.status());
      }
    },
    status: () => root.children.find((c) => c.tagName === "p").textContent,
    backendMessages: () => sent.filter((m) => m.data.type === OUT.backend).map((m) => m.data),
    errorMessages: () => sent.filter((m) => m.data.type === OUT.error),
    webglCanvas: () => env.canvases.find((c) => c.kind === "webgl2"),
    // The overlay canvas is the first canvas startTrafficMap creates.
    overlay: () => env.canvases[0],
    sendModel: () => post(modelMessage()),
    sendFocus: (id) => post({ type: "nos.trafficmap.focus", id }),
    sendIcons: (icons) => post({ type: "nos.trafficmap.icons", icons }),
  };
}

test("StartsWithWebGL2AndDrawsFrames", () => {
  const h = setup();
  h.sendModel();
  h.tick(3);
  assert.deepEqual(h.backendMessages(), [{ type: OUT.backend, backend: "webgl2 (no bloom)", fallback: false }]);
  assert.equal(h.status(), STATUS.webgl);
  assert.equal(h.errorMessages().length, 0);
  h.map.stop();
});

test("WithoutWebGL2UsesCanvas2D", () => {
  const h = setup({ webgl: false });
  h.sendModel();
  h.tick(2);
  assert.deepEqual(h.backendMessages(), [{ type: OUT.backend, backend: "canvas2d", fallback: true }]);
  assert.equal(h.status(), STATUS.fallback);
  h.map.stop();
});

test("ContextLostEventSwitchesToCanvas2D", () => {
  const h = setup();
  h.sendModel();
  h.tick(2);
  const gl = h.webglCanvas();
  gl.glState.lost = true;
  const ev = gl.dispatch("webglcontextlost");
  assert.ok(ev.defaultPrevented, "the loss event is handled");
  h.tick(2);
  assert.equal(h.backendMessages().length, 2);
  assert.deepEqual(h.backendMessages()[1], { type: OUT.backend, backend: "canvas2d", fallback: true });
  assert.equal(h.status(), STATUS.lost);
  const fresh = h.env.canvases.at(-1);
  assert.equal(fresh.kind, "2d", "Canvas 2D runs on a fresh canvas");
  assert.ok(h.root.children.includes(fresh), "the fresh canvas is in the page");
  assert.ok(!h.root.children.includes(gl), "the lost canvas is gone");
  assert.equal(gl.listeners.get("webglcontextlost").size, 0, "the old backend's listener is removed");
  h.map.stop();
});

test("ContextLossWithoutEventIsDetected", () => {
  const h = setup();
  h.sendModel();
  h.tick(1);
  h.webglCanvas().glState.lost = true;
  h.tick(2);
  assert.equal(h.backendMessages().at(-1).backend, "canvas2d");
  assert.equal(h.status(), STATUS.lost);
  h.map.stop();
});

test("ThrowingWebGL2RenderSwitchesToCanvas2D", () => {
  const h = setup();
  h.sendModel();
  h.tick(1);
  h.env.fail.gl = true;
  h.tick(3);
  assert.equal(h.backendMessages().at(-1).backend, "canvas2d");
  assert.equal(h.status(), STATUS.failed);
  h.map.stop();
});

test("FailingShaderBuildFallsBackAndReleasesContext", () => {
  const h = setup({ prepare: (env) => (env.fail.compile = true) });
  assert.deepEqual(h.backendMessages(), [{ type: OUT.backend, backend: "canvas2d", fallback: true }]);
  const gl = h.webglCanvas();
  assert.ok(gl.glState.released, "the half-built context is released");
  assert.equal(gl.listeners.get("webglcontextlost")?.size ?? 0, 0, "the discarded canvas has no loss listener");
  // A late loss of the discarded context must not reinstall the backend.
  gl.dispatch("webglcontextlost");
  h.sendModel();
  h.tick(2);
  assert.equal(h.backendMessages().length, 1);
  assert.equal(h.status(), STATUS.fallback);
  h.map.stop();
});

test("RepeatedSetSceneFailuresKeepLoopAliveAndSwitchToCanvas2D", () => {
  const h = setup();
  h.env.fail.upload = true;
  h.sendModel();
  h.tick(1);
  assert.equal(h.status(), STATUS.frameError, "a failing frame is shown");
  assert.equal(h.errorMessages().length, 1, "the parent is told once");
  h.advance(backoffUntilDegrade() + 32);
  assert.equal(h.errorMessages().length, 1, "no message per failed frame");
  assert.equal(h.backendMessages().at(-1).backend, "canvas2d");
  h.tick(2);
  assert.equal(h.status(), STATUS.failed, "the status recovers once frames draw again");
  h.map.stop();
});

test("FailingCanvas2DFramesDoNotFreezeAndRecover", () => {
  const h = setup({ webgl: false });
  h.sendModel();
  h.tick(1);
  h.env.fail.d2 = true;
  h.tick(MAX_FRAME_FAILURES * 3);
  assert.equal(h.status(), STATUS.frameError);
  assert.equal(h.errorMessages().length, 1);
  assert.equal(h.backendMessages().length, 1, "Canvas 2D is not reinstalled");
  h.env.fail.d2 = false;
  h.tick(1);
  assert.equal(h.status(), STATUS.fallback);
  h.map.stop();
});

// backoffUntilDegrade is the time the backoffs of the failed rebuilds
// before the degrade take.
function backoffUntilDegrade() {
  let ms = 0;
  for (let i = 1; i < MAX_FRAME_FAILURES; i++) ms += rebuildBackoffMs(i);
  return ms;
}

test("RebuildBackoffIsExponentialWithACap", () => {
  assert.equal(rebuildBackoffMs(1), REBUILD_BACKOFF_BASE_MS);
  assert.equal(rebuildBackoffMs(2), REBUILD_BACKOFF_BASE_MS * 2);
  assert.equal(rebuildBackoffMs(3), REBUILD_BACKOFF_BASE_MS * 4);
  assert.equal(rebuildBackoffMs(4), REBUILD_BACKOFF_BASE_MS * 8);
  assert.equal(rebuildBackoffMs(5), REBUILD_BACKOFF_BASE_MS * 16);
  assert.equal(rebuildBackoffMs(6), REBUILD_BACKOFF_BASE_MS * 32);
  assert.equal(rebuildBackoffMs(7), REBUILD_BACKOFF_MAX_MS, "the delay is capped");
  assert.equal(rebuildBackoffMs(100), REBUILD_BACKOFF_MAX_MS, "the delay stays capped");
});

test("FailingRebuildsAreBackedOffInsteadOfRetriedEveryFrame", () => {
  const h = setup();
  h.env.fail.upload = true;
  h.sendModel();
  h.tick(1);
  const gl = h.webglCanvas();
  assert.equal(gl.glState.bufferDataCalls, 1, "the first frame uploads the scene");
  h.tick(6);
  assert.equal(gl.glState.bufferDataCalls, 1, "the backoff suppresses scene rebuilds while failures persist");
  assert.equal(h.backendMessages().length, 1, "backed-off frames are not failures");
  h.advance(REBUILD_BACKOFF_BASE_MS);
  assert.equal(gl.glState.bufferDataCalls, 2, "the rebuild is retried once the backoff has passed");
  h.advance(backoffUntilDegrade());
  assert.equal(h.backendMessages().at(-1).backend, "canvas2d", "the degrade still switches backends");
  assert.equal(h.errorMessages().length, 1);
  h.map.stop();
});

test("FailedFirstRebuildIsRetriedAfterTheBackoff", () => {
  const b = flakyBuild((n) => n === 1);
  const h = setup({ webgl: false, build: b.build });
  h.sendModel();
  h.tick(1);
  assert.equal(b.calls, 1);
  assert.equal(h.status(), STATUS.frameError);
  h.advance(REBUILD_BACKOFF_BASE_MS / 2);
  assert.equal(b.calls, 1, "the rebuild is backed off");
  h.advance(REBUILD_BACKOFF_BASE_MS);
  assert.equal(b.calls, 2, "the rebuild is retried after the backoff");
  assert.equal(h.status(), STATUS.fallback, "the map draws again");
  assert.equal(h.errorMessages().length, 1);
  h.map.stop();
});

// overlayCounts wraps the overlay's 2D context and counts the calls that
// draw text or wipe the canvas, so a test can tell whether the overlay
// drew labels or was cleared.
function overlayCounts(h) {
  const octx = h.overlay().ctx2d;
  const counts = { fillText: 0, clearRect: 0 };
  octx.fillText = () => counts.fillText++;
  octx.clearRect = () => counts.clearRect++;
  return counts;
}

test("HalfUploadedWebGL2SceneDrawsNoOverlay", () => {
  const h = setup();
  h.sendModel();
  h.tick(1);
  const gl = h.webglCanvas();
  assert.equal(gl.glState.bufferDataCalls, 4, "the first scene is fully uploaded");
  // From the next setScene on, the second upload fails: the buffers hold
  // a mix of the new and the old scene.
  h.env.fail.upload = (n) => n > 4 && n % 4 === 2;
  const counts = overlayCounts(h);
  h.sendModel();
  h.tick(1);
  assert.equal(gl.glState.bufferDataCalls, 6, "the upload fails halfway through the scene");
  assert.equal(h.status(), STATUS.frameError);
  h.tick(1);
  assert.ok(counts.clearRect > 0, "the overlay is cleared over the mixed base");
  assert.equal(counts.fillText, 0, "no labels are drawn over the mixed base");
  h.map.stop();
});

test("OverlayIsClearedOverAnEmptyFallbackBase", () => {
  const b = flakyBuild((n) => n >= 2);
  const h = setup({ build: b.build });
  h.sendModel();
  h.tick(1);
  assert.equal(h.status(), STATUS.webgl, "the first scene draws");
  const counts = overlayCounts(h);
  h.sendModel();
  h.tick(1);
  let reset = false;
  h.advance(1000, () => {
    // Reset once, right after the frame that installs the fallback, so
    // only the frames drawn on the new (empty) base are counted.
    if (!reset && h.backendMessages().at(-1).backend === "canvas2d") {
      reset = true;
      counts.clearRect = 0;
      counts.fillText = 0;
    }
  });
  assert.equal(h.backendMessages().at(-1).backend, "canvas2d", "the degrade installs the fallback");
  assert.ok(counts.clearRect > 0, "the overlay is cleared over the empty base");
  assert.equal(counts.fillText, 0, "no stale labels are drawn after the fallback install");
  h.map.stop();
});

test("FastModelUpdatesCannotPostponeTheDegrade", () => {
  const b = flakyBuild(() => true);
  const h = setup({ webgl: false, build: b.build });
  const bmp = new FakeBitmap();
  h.sendIcons({ docker: bmp });
  // Models arrive faster than the failure streak can reset: every rebuild
  // fails, yet the degrade must still be reached. MAX_FRAME_FAILURES is 3
  // in main.js; two extra models must not postpone the degrade.
  for (let i = 0; i < 5; i++) {
    h.sendModel();
    h.tick(1);
  }
  assert.ok(bmp.closed, "the degrade is reached despite the new models");
  assert.equal(h.status(), STATUS.frameError);
  assert.equal(h.errorMessages().length, 1, "the parent is told once per failure streak");
  h.map.stop();
});

test("SuccessfulRebuildEndsTheFailureStreak", () => {
  let broken = (n) => n <= 2;
  const b = flakyBuild((n) => broken(n));
  const h = setup({ webgl: false, build: b.build });
  h.sendModel();
  h.tick(1);
  h.advance(rebuildBackoffMs(1) + rebuildBackoffMs(2) + 16);
  assert.equal(b.calls, 3, "two backed-off retries");
  assert.equal(h.status(), STATUS.fallback, "a successful rebuild restores the status");
  assert.equal(h.errorMessages().length, 1);
  // A later failure starts a new streak: the parent is told again and the
  // backoff starts over at its base delay.
  const before = b.calls;
  broken = (n) => n === before + 1;
  h.sendFocus("pve1");
  h.tick(1);
  assert.equal(b.calls, before + 1);
  assert.equal(h.status(), STATUS.frameError);
  assert.equal(h.errorMessages().length, 2, "a new failure streak is reported");
  h.advance(REBUILD_BACKOFF_BASE_MS + 16);
  assert.equal(b.calls, before + 2, "the backoff was reset by the success");
  assert.equal(h.status(), STATUS.fallback);
  h.map.stop();
});

test("RebuildFailingWithAnOldSceneBacksOffAndDegrades", () => {
  let broken = false;
  const b = flakyBuild(() => broken);
  const h = setup({ webgl: false, build: b.build });
  h.sendModel();
  const bmp = new FakeBitmap();
  h.sendIcons({ docker: bmp });
  h.tick(2);
  assert.equal(h.status(), STATUS.fallback);
  broken = true;
  const before = b.calls;
  h.sendModel();
  h.tick(1);
  assert.equal(b.calls, before + 1);
  const seen = new Set();
  h.advance(1000, (s) => seen.add(s));
  assert.deepEqual([...seen], [STATUS.frameError], "drawing the old scene does not end the failure streak");
  const attempts = b.calls - before;
  assert.ok(attempts >= MAX_FRAME_FAILURES && attempts <= 5, "rebuilds are retried with a growing backoff, got " + attempts);
  assert.ok(bmp.closed, "the degrade is reached");
  h.advance(10 * REBUILD_BACKOFF_MAX_MS);
  assert.ok(b.calls - before <= attempts + 11, "the backoff is capped, not reset: " + (b.calls - before));
  assert.equal(h.errorMessages().length, 1, "the parent is told once per failure streak");
  h.map.stop();
});

test("NewModelClearsTheRebuildBackoff", () => {
  let broken = true;
  const b = flakyBuild(() => broken);
  const h = setup({ webgl: false, build: b.build });
  h.sendModel();
  h.tick(1);
  h.advance(3000);
  assert.ok(b.calls >= 3, "the rebuild was retried");
  broken = false;
  const before = b.calls;
  h.sendModel();
  h.tick(1);
  assert.equal(b.calls, before + 1, "a new model is built at once");
  assert.equal(h.status(), STATUS.fallback);
  h.map.stop();
});

test("BackedOffFramesUnderReducedMotionAreNotFailures", () => {
  const h = setup({ reducedMotion: true });
  h.env.fail.upload = true;
  h.sendModel();
  h.tick(1);
  h.env.fail.upload = false;
  assert.equal(h.status(), STATUS.frameError);
  h.advance(REBUILD_BACKOFF_BASE_MS / 2);
  assert.equal(h.backendMessages().length, 1, "frames that attempt nothing do not degrade the renderer");
  h.advance(REBUILD_BACKOFF_BASE_MS);
  assert.equal(h.backendMessages().length, 1);
  assert.equal(h.status(), STATUS.webgl, "the retried rebuild recovers on WebGL2");
  assert.equal(h.errorMessages().length, 1);
  h.map.stop();
});

test("FailingOverlayDropsIconsAndRecovers", () => {
  const h = setup({ webgl: false });
  h.sendModel();
  h.tick(1);
  const bmp = new FakeBitmap();
  h.sendIcons({ docker: bmp });
  h.env.fail.drawImage = true;
  h.tick(1);
  assert.equal(h.status(), STATUS.frameError, "a throwing drawImage is caught");
  h.tick(MAX_FRAME_FAILURES);
  assert.equal(h.status(), STATUS.fallback, "without icons the overlay draws again");
  assert.ok(bmp.closed, "dropped icons are released");
  h.map.stop();
});

test("ReplacedIconsAreClosed", () => {
  const h = setup({ webgl: false });
  const a = new FakeBitmap();
  const b = new FakeBitmap();
  const c = new FakeBitmap();
  h.sendIcons({ docker: a, debian: b });
  h.sendIcons({ docker: a, ubuntu: c });
  assert.ok(!a.closed, "a reused bitmap stays open");
  assert.ok(b.closed, "a replaced bitmap is closed");
  h.map.stop();
  assert.ok(a.closed && c.closed, "stop releases the remaining bitmaps");
});

test("Canvas2DCullsOffscreenBeams", () => {
  assert.ok(segmentVisible(10, 10, 20, 20, 100, 100, 0));
  assert.ok(segmentVisible(-50, 50, 150, 50, 100, 100, 0), "a beam crossing the viewport is drawn");
  assert.ok(!segmentVisible(-50, -50, -10, -10, 100, 100, 5));
  assert.ok(!segmentVisible(120, 0, 200, 100, 100, 100, 5));
  assert.ok(segmentVisible(103, 0, 200, 100, 100, 100, 5), "the margin counts");
});
