// SPDX-License-Identifier: AGPL-3.0-or-later
//
// 2D overlay drawn on top of either backend: health spikes, focus and
// host-key rings, labels, software symbols and the truncation notice. All
// text is drawn with fillText; nothing here touches the DOM.

import { worldToScreen } from "./camera.js";
import { ZOOM } from "./scene.js";
import { STATE_COLORS } from "./health.js";

/** Label fonts in CSS pixels. */
const ZONE_FONT = "600 14px sans-serif";
const NODE_FONT = "11px sans-serif";
/** Software symbol size in CSS pixels per zoom level. */
const SOFTWARE_PX = Object.freeze([10, 13, 16]);
/** Labels and symbols outside the viewport plus this margin are skipped. */
const CULL_MARGIN = 80;

function visible(sx, sy, w, h) {
  return sx > -CULL_MARGIN && sy > -CULL_MARGIN && sx < w + CULL_MARGIN && sy < h + CULL_MARGIN;
}

/**
 * drawOverlay draws the overlay for one frame. time is in seconds; when
 * motion is reduced the caller passes a constant time. nodeById maps node
 * ids to validated model nodes for the symbol painter.
 */
export function drawOverlay(ctx, scene, cam, dpr, time, painter, icons, nodeById) {
  const w = cam.width;
  const h = cam.height;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  // Health spikes and markers.
  ctx.lineCap = "round";
  for (const hs of scene.health) {
    const [sx, sy] = worldToScreen(cam, hs.x, hs.y);
    if (!visible(sx, sy, w, h)) continue;
    const rp = Math.max(2, hs.r * cam.scale);
    for (const s of hs.spikes) {
      const len = rp * s.length;
      let alpha = 0.95;
      if (s.pulse) alpha = 0.55 + 0.45 * Math.abs(Math.sin(time * 3));
      ctx.globalAlpha = alpha;
      ctx.strokeStyle = s.css;
      ctx.lineWidth = Math.max(1.5, rp * 0.22);
      ctx.beginPath();
      ctx.moveTo(sx + s.dir[0] * rp, sy + s.dir[1] * rp);
      ctx.lineTo(sx + s.dir[0] * (rp + len), sy + s.dir[1] * (rp + len));
      ctx.stroke();
      if (s.pulse && scene.level === ZOOM.overview) {
        ctx.beginPath();
        ctx.arc(sx, sy, rp + len * (0.5 + 0.5 * Math.abs(Math.sin(time * 3))), 0, Math.PI * 2);
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }
    if (hs.flicker) {
      // Grey flicker: unreachable.
      ctx.globalAlpha = 0.35 + 0.35 * Math.abs(Math.sin(time * 11 + hs.x));
      ctx.fillStyle = STATE_COLORS.unknown.css;
      ctx.beginPath();
      ctx.arc(sx, sy, rp * 1.15, 0, Math.PI * 2);
      ctx.fill();
    }
    if (hs.ring) {
      // Red ring: host-key mismatch.
      ctx.globalAlpha = 1;
      ctx.strokeStyle = STATE_COLORS.crit.css;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(sx, sy, rp * 1.6 + 3, 0, Math.PI * 2);
      ctx.stroke();
    }
  }
  ctx.globalAlpha = 1;

  // Symbol inside the star core (painter decides) and focus ring.
  for (const s of scene.stars) {
    const [sx, sy] = worldToScreen(cam, s.x, s.y);
    if (!visible(sx, sy, w, h)) continue;
    const rp = s.r * cam.scale;
    if (scene.level === ZOOM.close) {
      const node = nodeById.get(s.id);
      if (node) painter.drawCore(ctx, node, sx, sy, rp, scene.level, icons);
    }
    if (s.id === scene.focus) {
      ctx.strokeStyle = "#ffffff";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 3]);
      ctx.beginPath();
      ctx.arc(sx, sy, Math.max(rp, 4) * 2 + 6, 0, Math.PI * 2);
      ctx.stroke();
      ctx.setLineDash([]);
    }
  }

  // Software symbols: under the node, nested containers one row lower.
  const size = SOFTWARE_PX[scene.level] || SOFTWARE_PX[0];
  for (const sw of scene.software) {
    const [sx, sy] = worldToScreen(cam, sw.x, sw.y);
    if (!visible(sx, sy, w, h)) continue;
    const row = sw.nested ? 2 : 1;
    painter.drawSoftware(ctx, sw.entries, sx - size, sy + 14 + row * (size + 4), size, icons);
  }

  // Labels.
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  for (const l of scene.labels) {
    const [sx, sy] = worldToScreen(cam, l.x, l.y);
    if (!visible(sx, sy, w, h)) continue;
    ctx.font = l.kind === "zone" ? ZONE_FONT : NODE_FONT;
    ctx.fillStyle = "rgba(4, 6, 12, 0.7)";
    ctx.fillText(l.text, sx + 1, sy + 1);
    ctx.fillStyle = l.kind === "zone" ? "#dfe6f5" : "#c3cbdb";
    ctx.fillText(l.text, sx, sy);
  }

  if (scene.notice) {
    ctx.font = NODE_FONT;
    ctx.textAlign = "left";
    ctx.textBaseline = "top";
    ctx.fillStyle = STATE_COLORS.warn.css;
    ctx.fillText(scene.notice, 12, 12);
  }
}
