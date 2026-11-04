// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Behaviour of startTrafficMap against a fake DOM: backend selection,
// context loss, throwing backends and the frame loop's error handling.
// The real WebGL2 and Canvas 2D backends run against fake contexts.
// Run with: node --test web/static/trafficmap/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { startTrafficMap, STATUS, MAX_FRAME_FAILURES } from "./main.js";
import { OUT } from "./bridge.js";
import { segmentVisible } from "./canvas2d.js";

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
      if (fail.upload) throw new Error("fake upload failure");
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
    this.glState = { lost: false, released: false };
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
      return fake2d(this.env.fail);
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

// setup starts the map against a fake window. prepare may arm failures
// before startTrafficMap runs.
function setup({ webgl = true, prepare = () => {} } = {}) {
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
  const map = startTrafficMap(root);
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
    status: () => root.children.find((c) => c.tagName === "p").textContent,
    backendMessages: () => sent.filter((m) => m.data.type === OUT.backend).map((m) => m.data),
    errorMessages: () => sent.filter((m) => m.data.type === OUT.error),
    webglCanvas: () => env.canvases.find((c) => c.kind === "webgl2"),
    sendModel: () => post(modelMessage()),
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
  h.tick(MAX_FRAME_FAILURES);
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
