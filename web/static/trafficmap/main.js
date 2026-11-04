// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Traffic map renderer entry point (ADR 0009 D4, TM18). Data model in
// (postMessage only, see bridge.js), pixels out. Chooses WebGL2 and falls
// back to Canvas 2D when WebGL2 is missing, fails, or loses its context.
// The DOM is touched only through createElement, textContent and CSSOM
// style properties; there is no innerHTML anywhere.

import { acceptMessage, send, OUT } from "./bridge.js";
import { computeLayout } from "./layout.js";
import { buildScene, ZOOM, ZOOM_THRESHOLDS } from "./scene.js";
import { createCamera, resizeCamera, fitCamera, zoomAt, panBy, centreOn, pick, cameraLevel, relativeZoom } from "./camera.js";
import { createWebGL2Backend } from "./webgl2.js";
import { createCanvas2DBackend } from "./canvas2d.js";
import { drawOverlay } from "./overlay.js";
import { PAINTERS } from "./symbols.js";

/** Upper bound of the device pixel ratio used for the backing stores. */
export const MAX_DPR = 2;
/** Pointer travel in CSS pixels after which a press is a drag, not a click. */
export const DRAG_THRESHOLD_PX = 4;
/**
 * Consecutive failed frames after which the renderer degrades: WebGL2 is
 * replaced by Canvas 2D, and on Canvas 2D the icons are dropped. A frame
 * fails when a scene rebuild or a draw it attempted throws; a frame whose
 * rebuild is backed off only fails if its draw throws.
 */
export const MAX_FRAME_FAILURES = 3;

/**
 * REBUILD_BACKOFF_BASE_MS is the delay before a scene rebuild is retried
 * after one failed rebuild; it doubles with every further failed rebuild.
 * REBUILD_BACKOFF_MAX_MS caps that delay, so a persistently failing rebuild
 * is not retried on every frame.
 */
export const REBUILD_BACKOFF_BASE_MS = 100;
export const REBUILD_BACKOFF_MAX_MS = 4000;

/**
 * rebuildBackoffMs is the delay in ms before the next scene rebuild attempt
 * after the failures-th consecutive failed rebuild: exponential from
 * REBUILD_BACKOFF_BASE_MS up to REBUILD_BACKOFF_MAX_MS.
 */
export function rebuildBackoffMs(failures) {
  return Math.min(REBUILD_BACKOFF_BASE_MS * 2 ** (failures - 1), REBUILD_BACKOFF_MAX_MS);
}

/** User-facing status texts (English UI strings). */
export const STATUS = Object.freeze({
  waiting: "Waiting for map data.",
  webgl: "Rendering with WebGL2.",
  fallback: "Rendering with Canvas 2D (fallback).",
  lost: "The graphics context was lost; switched to Canvas 2D.",
  failed: "WebGL2 stopped working; switched to Canvas 2D.",
  none: "This browser cannot draw the traffic map.",
  rejected: "Map data was rejected; showing the last valid data.",
  frameError: "Drawing the traffic map failed; retrying.",
});

/**
 * createBackend picks a backend. With preferWebGL it tries WebGL2 first;
 * otherwise, or if WebGL2 is unavailable or throws, it uses Canvas 2D on a
 * fresh canvas (a canvas that once had a WebGL context cannot give a 2D
 * one). Returns { backend, canvas, fallback } where backend may be null.
 */
export function createBackend(makeCanvas, factories, preferWebGL, onLost) {
  if (preferWebGL) {
    const canvas = makeCanvas();
    try {
      const backend = factories.webgl2(canvas, onLost);
      if (backend) return { backend, canvas, fallback: false };
    } catch {
      // Fall through to Canvas 2D; the reason is reported as a status.
    }
  }
  const canvas = makeCanvas();
  const backend = factories.canvas2d(canvas);
  return { backend, canvas, fallback: true };
}

function cover(el) {
  el.style.position = "absolute";
  el.style.left = "0";
  el.style.top = "0";
  el.style.width = "100%";
  el.style.height = "100%";
  el.style.display = "block";
}

/**
 * startTrafficMap renders the map into root and returns { stop }.
 * opts.symbols selects the node symbol painter (default "star-core");
 * opts.preferWebGL = false forces the Canvas 2D backend.
 */
export function startTrafficMap(root, opts = {}) {
  const win = root.ownerDocument.defaultView;
  const doc = root.ownerDocument;
  const painter = (PAINTERS[opts.symbols] || PAINTERS["star-core"])();
  const motion = win.matchMedia ? win.matchMedia("(prefers-reduced-motion: reduce)") : null;
  const isBitmap = (b) => typeof win.ImageBitmap === "function" && b instanceof win.ImageBitmap;
  // opts.buildScene replaces buildScene; the behaviour tests use it to make
  // rebuilds fail.
  const build = typeof opts.buildScene === "function" ? opts.buildScene : buildScene;

  let base = null;
  let backend = null;
  let model = null;
  let layout = null;
  let scene = null;
  let nodeById = new Map();
  // sceneNodeById is the nodeById of the model the installed scene was
  // built from. The overlay uses it, not nodeById: while a rebuild for a
  // newer model fails, the old scene keeps rendering and must not be
  // paired with the newer model's nodes.
  let sceneNodeById = new Map();
  let icons = new Map();
  let cam = null;
  let focus = null;
  let level = ZOOM.overview;
  let dpr = 1;
  let dirty = true;
  let redraw = true;
  let switchToFallback = null;
  let backendStatus = STATUS.waiting;
  let stopped = false;
  let generation = 0;
  // failures counts consecutive failed frames and drives the status, the
  // error report and the degrade; rebuildFailures counts consecutive failed
  // scene rebuilds and drives the rebuild backoff. A failed rebuild sets
  // nextRebuildAt once; frames before it neither retry nor fail.
  let failures = 0;
  let degradeAt = MAX_FRAME_FAILURES;
  let rebuildFailures = 0;
  let nextRebuildAt = 0;

  root.style.position = "relative";
  root.style.overflow = "hidden";
  root.tabIndex = 0;
  root.setAttribute("role", "application");
  root.setAttribute("aria-label", "Traffic map");

  const overlay = doc.createElement("canvas");
  cover(overlay);
  overlay.style.pointerEvents = "none";
  const octx = overlay.getContext("2d");

  const status = doc.createElement("p");
  status.setAttribute("role", "status");
  status.style.position = "absolute";
  status.style.right = "12px";
  status.style.bottom = "4px";
  status.style.margin = "0";
  status.style.font = "11px sans-serif";
  status.style.color = "#8c9199";
  status.style.pointerEvents = "none";
  root.append(overlay, status);

  function setStatus(text) {
    status.textContent = text;
  }

  function makeCanvas() {
    const c = doc.createElement("canvas");
    cover(c);
    return c;
  }

  function install(preferWebGL, reasonText) {
    if (backend) backend.dispose();
    // A loss reported by an earlier, already replaced backend is ignored.
    const gen = ++generation;
    const r = createBackend(makeCanvas, { webgl2: createWebGL2Backend, canvas2d: createCanvas2DBackend }, preferWebGL, () => {
      if (gen === generation) switchToFallback = STATUS.lost;
    });
    if (base) {
      root.replaceChild(r.canvas, base);
    } else {
      root.insertBefore(r.canvas, overlay);
    }
    base = r.canvas;
    backend = r.backend;
    resize();
    dirty = true;
    resetFailures();
    if (!backend) {
      setStatus(STATUS.none);
      send(win, OUT.backend, { backend: "none", fallback: true });
      return;
    }
    backendStatus = reasonText || (r.fallback ? STATUS.fallback : STATUS.webgl);
    setStatus(model ? backendStatus : STATUS.waiting);
    send(win, OUT.backend, { backend: backend.name, fallback: r.fallback });
  }

  function size() {
    const rect = root.getBoundingClientRect();
    return [Math.max(1, Math.floor(rect.width)), Math.max(1, Math.floor(rect.height))];
  }

  function resize() {
    const [w, h] = size();
    dpr = Math.min(MAX_DPR, Math.max(1, win.devicePixelRatio || 1));
    for (const c of [base, overlay]) {
      if (!c) continue;
      c.width = Math.round(w * dpr);
      c.height = Math.round(h * dpr);
    }
    if (cam && layout) resizeCamera(cam, layout.extent, w, h);
    redraw = true;
  }

  function setFocus(id, notify) {
    focus = id !== null && nodeById.has(id) ? id : null;
    if (focus !== null && cam) {
      const p = layout.nodes.get(focus);
      centreOn(cam, p.x, p.y);
      if (relativeZoom(cam) < ZOOM_THRESHOLDS.zone) {
        zoomAt(cam, cam.width / 2, cam.height / 2, ZOOM_THRESHOLDS.zone / relativeZoom(cam));
      }
    }
    dirty = true;
    if (notify) send(win, OUT.select, { id: focus });
  }

  function onMessage(ev) {
    const r = acceptMessage(ev, win, isBitmap);
    if (r === null) return;
    switch (r.kind) {
      case "model": {
        model = r.value;
        layout = computeLayout(model);
        nodeById = new Map(model.nodes.map((n) => [n.id, n]));
        const [w, h] = size();
        if (cam === null) {
          cam = createCamera(layout.extent, w, h);
        } else {
          resizeCamera(cam, layout.extent, w, h);
        }
        if (focus !== null && !nodeById.has(focus)) focus = null;
        dirty = true;
        // A new model gets a fresh rebuild right away; the failure streak is
        // kept (see resetRebuildBackoff).
        resetRebuildBackoff();
        if (backend) setStatus(backendStatus);
        break;
      }
      case "icons":
        releaseIcons(r.value);
        icons = r.value;
        redraw = true;
        break;
      case "focus":
        setFocus(r.value, false);
        break;
      default:
        setStatus(STATUS.rejected);
        send(win, OUT.error, { errors: r.errors });
    }
  }

  // releaseIcons closes the bitmaps of the current icon map that are not
  // reused by next, so replaced icon sets do not hold bitmap memory.
  function releaseIcons(next) {
    const keep = new Set(next.values());
    for (const bmp of icons.values()) {
      if (keep.has(bmp)) continue;
      if (typeof bmp.close === "function") bmp.close();
    }
  }

  // clearOverlay wipes the overlay canvas when the base drew no scene (none
  // yet, or a half-finished upload), so it is not covered by labels of an
  // earlier, different scene.
  function clearOverlay() {
    octx.setTransform(1, 0, 0, 1, 0, 0);
    octx.clearRect(0, 0, overlay.width, overlay.height);
  }

  function local(ev) {
    const rect = root.getBoundingClientRect();
    return [ev.clientX - rect.left, ev.clientY - rect.top];
  }

  let press = null;
  function onPointerDown(ev) {
    if (ev.button !== 0) return;
    const [x, y] = local(ev);
    press = { id: ev.pointerId, x, y, lastX: x, lastY: y, drag: false };
    root.setPointerCapture(ev.pointerId);
    root.focus();
  }
  function onPointerMove(ev) {
    if (!press || ev.pointerId !== press.id || !cam) return;
    const [x, y] = local(ev);
    if (!press.drag && Math.hypot(x - press.x, y - press.y) > DRAG_THRESHOLD_PX) press.drag = true;
    if (press.drag) {
      panBy(cam, x - press.lastX, y - press.lastY);
      redraw = true;
    }
    press.lastX = x;
    press.lastY = y;
  }
  function onPointerUp(ev) {
    if (!press || ev.pointerId !== press.id) return;
    const wasDrag = press.drag;
    press = null;
    if (wasDrag || !cam || !scene) return;
    const [x, y] = local(ev);
    setFocus(pick(scene, cam, x, y), true);
  }
  function onDoubleClick(ev) {
    if (!cam || !scene) return;
    const [x, y] = local(ev);
    const id = pick(scene, cam, x, y);
    if (id !== null) send(win, OUT.open, { id });
  }
  function onWheel(ev) {
    if (!cam) return;
    ev.preventDefault();
    const [x, y] = local(ev);
    zoomAt(cam, x, y, Math.exp(-Math.max(-300, Math.min(300, ev.deltaY)) * 0.0015));
    redraw = true;
  }
  function onKey(ev) {
    if (!cam) return;
    const step = 60;
    switch (ev.key) {
      case "Escape":
        setFocus(null, true);
        break;
      case "+":
      case "=":
        zoomAt(cam, cam.width / 2, cam.height / 2, 1.25);
        break;
      case "-":
        zoomAt(cam, cam.width / 2, cam.height / 2, 0.8);
        break;
      case "0":
        fitCamera(cam, layout.extent, cam.width, cam.height);
        break;
      case "ArrowLeft":
        panBy(cam, step, 0);
        break;
      case "ArrowRight":
        panBy(cam, -step, 0);
        break;
      case "ArrowUp":
        panBy(cam, 0, step);
        break;
      case "ArrowDown":
        panBy(cam, 0, -step);
        break;
      case "Enter":
        if (focus !== null) send(win, OUT.open, { id: focus });
        return;
      default:
        return;
    }
    ev.preventDefault();
    redraw = true;
  }

  function step(ts) {
    if (switchToFallback === null && backend && backend.name !== "canvas2d" && backend.isLost()) {
      switchToFallback = STATUS.lost;
    }
    if (switchToFallback !== null) {
      // Cleared only after a successful install, so a throwing install is
      // retried on the next frame.
      install(false, switchToFallback);
      switchToFallback = null;
    }
    if (!backend || !cam || !model) return;
    const lvl = cameraLevel(cam);
    if (lvl !== level) {
      level = lvl;
      dirty = true;
    }
    if (dirty) {
      if (rebuildFailures > 0 && ts < nextRebuildAt) {
        // The rebuild is backed off: the last scene keeps rendering, and
        // without one there is nothing to draw yet.
        if (scene === null) return;
      } else {
        try {
          const next = build(model, layout, { level, focus });
          backend.setScene(next);
          scene = next;
          sceneNodeById = nodeById;
        } catch (err) {
          // The deadline is set only here, by an attempt that failed, so
          // backed-off frames cannot push it further out.
          rebuildFailures++;
          nextRebuildAt = ts + rebuildBackoffMs(rebuildFailures);
          // Nothing is drawn in this frame, so base and overlay keep showing
          // the same last frame. Whether the overlay is drawn is decided only
          // by render's completeness below, on every backend alike.
          throw err;
        }
        rebuildFailures = 0;
        nextRebuildAt = 0;
        dirty = false;
        redraw = true;
      }
    }
    const reduced = motion !== null && motion.matches;
    if (redraw || !reduced) {
      const time = reduced ? 0 : ts / 1000;
      try {
        // render reports whether it drew a complete scene. Without one
        // (no scene yet, or a half-finished WebGL2 upload) it draws no
        // scene at all and only clears the base to the background.
        const complete = backend.render(cam, dpr, time);
        if (complete) {
          drawOverlay(octx, scene, cam, dpr, time, painter, icons, sceneNodeById);
          redraw = false;
        } else {
          // Empty base: clear the overlay too, so no labels of an earlier
          // scene are left over it.
          clearOverlay();
        }
      } catch (err) {
        if (backend.name === "canvas2d") throw err;
        // A failing WebGL2 draw is not retried: switch on the next frame.
        switchToFallback = STATUS.failed;
        redraw = true;
        return;
      }
    }
  }

  // frame re-arms itself first, so no exception can stop the loop. A frame
  // that throws is a failure; failed rebuilds are retried with a growing
  // backoff, and repeated failures degrade the renderer. The streak ends
  // only with a frame that throws nothing while no rebuild is failing, so
  // drawing an outdated scene does not count as recovery.
  function frame(ts) {
    if (stopped) return;
    win.requestAnimationFrame(frame);
    try {
      step(ts);
    } catch {
      failures++;
      redraw = true;
      if (failures === 1) {
        // Reported once per streak, not per failed frame.
        setStatus(STATUS.frameError);
        send(win, OUT.error, { errors: ["render: drawing a frame failed"] });
      }
      degrade();
      return;
    }
    if (failures > 0 && rebuildFailures === 0) {
      resetFailures();
      setStatus(!backend ? STATUS.none : model ? backendStatus : STATUS.waiting);
    }
  }

  // resetFailures ends a failure streak and clears the rebuild backoff.
  function resetFailures() {
    failures = 0;
    degradeAt = MAX_FRAME_FAILURES;
    rebuildFailures = 0;
    nextRebuildAt = 0;
  }

  // resetRebuildBackoff lets a new model be rebuilt right away. It must not
  // touch the failure streak, which ends only with a successful frame (or
  // an install): with models arriving faster than the degrade window,
  // resetting the streak on every model would postpone the degrade forever.
  function resetRebuildBackoff() {
    rebuildFailures = 0;
    nextRebuildAt = 0;
  }

  // degrade applies the stepwise degradation for a persistent failure
  // streak: WebGL2 is replaced by Canvas 2D, and on Canvas 2D the icons
  // are dropped.
  function degrade() {
    if (failures >= degradeAt) {
      degradeAt += MAX_FRAME_FAILURES;
      if (backend && backend.name !== "canvas2d") {
        switchToFallback = STATUS.failed;
      } else if (icons.size > 0) {
        releaseIcons(new Map());
        icons = new Map();
      }
    }
  }

  const observer = typeof win.ResizeObserver === "function" ? new win.ResizeObserver(resize) : null;
  if (observer) {
    observer.observe(root);
  } else {
    win.addEventListener("resize", resize);
  }
  win.addEventListener("message", onMessage);
  root.addEventListener("pointerdown", onPointerDown);
  root.addEventListener("pointermove", onPointerMove);
  root.addEventListener("pointerup", onPointerUp);
  root.addEventListener("pointercancel", onPointerUp);
  root.addEventListener("dblclick", onDoubleClick);
  root.addEventListener("wheel", onWheel, { passive: false });
  root.addEventListener("keydown", onKey);

  install(opts.preferWebGL !== false, null);
  send(win, OUT.ready, {});
  win.requestAnimationFrame(frame);

  return {
    stop() {
      stopped = true;
      if (observer) observer.disconnect();
      win.removeEventListener("resize", resize);
      win.removeEventListener("message", onMessage);
      root.removeEventListener("pointerdown", onPointerDown);
      root.removeEventListener("pointermove", onPointerMove);
      root.removeEventListener("pointerup", onPointerUp);
      root.removeEventListener("pointercancel", onPointerUp);
      root.removeEventListener("dblclick", onDoubleClick);
      root.removeEventListener("wheel", onWheel);
      root.removeEventListener("keydown", onKey);
      if (backend) backend.dispose();
      releaseIcons(new Map());
      icons = new Map();
    },
  };
}
