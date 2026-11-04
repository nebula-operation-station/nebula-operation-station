// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Node symbol painters. Open question Q1 of ADR 0009 is not decided; this
// implements the recommended variant: the node stays a star (size, VLAN
// colour and health encoding come from the backend), and the OS symbol is
// drawn inside the star core when zoomed in close.
//
// A painter is the only place that knows how a node's symbol looks. Layout,
// picking and the backends never depend on it, so a switchable OS-symbol
// mode can be added later as another painter.
//
// Painter interface:
//   name: string
//   drawCore(ctx, node, sx, sy, radiusPx, level, icons) draws into a
//     CanvasRenderingContext2D overlay at screen position (sx, sy).
//   drawSoftware(ctx, entries, sx, sy, sizePx, icons) draws a row of
//     software symbols (catalog key + count) starting at (sx, sy).
// Text is drawn with fillText only; icons are validated ImageBitmaps.

import { ZOOM } from "./scene.js";

/** Minimum on-screen star radius before the OS symbol is drawn. */
export const CORE_SYMBOL_MIN_PX = 9;

function glyph(key) {
  // Generic symbol: first character of the catalog key. Keys are validated
  // against [a-z0-9][a-z0-9._-]{0,63}, so this is always plain ASCII.
  return key.charAt(0).toUpperCase();
}

function drawBadge(ctx, key, cx, cy, size, icons) {
  const icon = icons ? icons.get(key) : undefined;
  if (icon) {
    ctx.drawImage(icon, cx - size / 2, cy - size / 2, size, size);
    return;
  }
  ctx.fillStyle = "rgba(10, 14, 24, 0.85)";
  ctx.beginPath();
  ctx.arc(cx, cy, size / 2, 0, Math.PI * 2);
  ctx.fill();
  ctx.fillStyle = "#e8ecf4";
  ctx.font = Math.round(size * 0.62) + "px sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(glyph(key), cx, cy + 0.5);
}

/** starCorePainter returns the default painter (ADR 0009 Q1 recommendation). */
export function starCorePainter() {
  return Object.freeze({
    name: "star-core",
    drawCore(ctx, node, sx, sy, radiusPx, level, icons) {
      if (level < ZOOM.close || !node.os || radiusPx < CORE_SYMBOL_MIN_PX) return;
      drawBadge(ctx, node.os, sx, sy, radiusPx * 1.2, icons);
    },
    drawSoftware(ctx, entries, sx, sy, sizePx, icons) {
      let x = sx;
      for (const e of entries) {
        drawBadge(ctx, e.key, x + sizePx / 2, sy, sizePx, icons);
        if (e.count > 1) {
          ctx.fillStyle = "#c8d0e0";
          ctx.font = Math.round(sizePx * 0.5) + "px sans-serif";
          ctx.textAlign = "left";
          ctx.textBaseline = "middle";
          const t = "\u00d7" + (e.count > 999 ? "999+" : String(e.count));
          ctx.fillText(t, x + sizePx + 1, sy);
          x += sizePx + ctx.measureText(t).width + 4;
        } else {
          x += sizePx + 3;
        }
      }
    },
  });
}

/** PAINTERS lists the available symbol modes by name. */
export const PAINTERS = Object.freeze({ "star-core": starCorePainter });
