// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Camera: world <-> screen transform, zoom and picking. Screen units are CSS
// pixels; backends multiply by devicePixelRatio themselves. Picking works on
// the scene's stars only and never depends on how symbols are drawn.

import { zoomLevel } from "./scene.js";

/** Zoom bounds relative to the "fit all" scale. */
export const MIN_RELATIVE_ZOOM = 0.5;
export const MAX_RELATIVE_ZOOM = 40;
/** Minimum pick radius in CSS pixels, so tiny stars stay clickable. */
export const PICK_MIN_PX = 6;
/** Margin around the layout extent when fitting. */
const FIT_MARGIN = 1.08;

/** createCamera returns a camera fitted to a layout extent and viewport. */
export function createCamera(extent, width, height) {
  const cam = { cx: 0, cy: 0, scale: 1, fitScale: 1, width, height };
  fitCamera(cam, extent, width, height);
  return cam;
}

/** fitCamera centres the camera and makes the whole extent visible. */
export function fitCamera(cam, extent, width, height) {
  cam.width = width;
  cam.height = height;
  const e = Math.max(extent, 1) * FIT_MARGIN;
  cam.fitScale = Math.max(1e-6, Math.min(width, height) / (2 * e));
  cam.scale = cam.fitScale;
  cam.cx = 0;
  cam.cy = 0;
}

/** resizeCamera keeps the centre and relative zoom on viewport changes. */
export function resizeCamera(cam, extent, width, height) {
  const rel = cam.scale / cam.fitScale;
  const cx = cam.cx;
  const cy = cam.cy;
  fitCamera(cam, extent, width, height);
  cam.scale = cam.fitScale * rel;
  cam.cx = cx;
  cam.cy = cy;
}

/** worldToScreen converts world coordinates to CSS pixels. */
export function worldToScreen(cam, x, y) {
  return [(x - cam.cx) * cam.scale + cam.width / 2, (y - cam.cy) * cam.scale + cam.height / 2];
}

/** screenToWorld converts CSS pixels to world coordinates. */
export function screenToWorld(cam, sx, sy) {
  return [(sx - cam.width / 2) / cam.scale + cam.cx, (sy - cam.height / 2) / cam.scale + cam.cy];
}

/** relativeZoom is the camera scale relative to "fit all". */
export function relativeZoom(cam) {
  return cam.scale / cam.fitScale;
}

/** cameraLevel is the semantic zoom level for the current camera. */
export function cameraLevel(cam) {
  return zoomLevel(relativeZoom(cam));
}

/** zoomAt zooms by factor while keeping the world point under (sx, sy). */
export function zoomAt(cam, sx, sy, factor) {
  const [wx, wy] = screenToWorld(cam, sx, sy);
  const min = cam.fitScale * MIN_RELATIVE_ZOOM;
  const max = cam.fitScale * MAX_RELATIVE_ZOOM;
  cam.scale = Math.min(max, Math.max(min, cam.scale * factor));
  cam.cx = wx - (sx - cam.width / 2) / cam.scale;
  cam.cy = wy - (sy - cam.height / 2) / cam.scale;
}

/** panBy moves the camera by a screen-space delta in CSS pixels. */
export function panBy(cam, dx, dy) {
  cam.cx -= dx / cam.scale;
  cam.cy -= dy / cam.scale;
}

/** centreOn moves the camera centre to a world point. */
export function centreOn(cam, x, y) {
  cam.cx = x;
  cam.cy = y;
}

/**
 * pick returns the id of the star under (sx, sy), or null. The nearest star
 * wins; ties are broken by id so picking is deterministic.
 */
export function pick(scene, cam, sx, sy) {
  const [wx, wy] = screenToWorld(cam, sx, sy);
  let best = null;
  let bestD = Infinity;
  for (const s of scene.stars) {
    const d = Math.hypot(s.x - wx, s.y - wy);
    const reach = Math.max(s.r, PICK_MIN_PX / cam.scale);
    if (d <= reach && (d < bestD || (d === bestD && s.id < best))) {
      best = s.id;
      bestD = d;
    }
  }
  return best;
}
