// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Canvas 2D backend: the fallback when WebGL2 is missing, fails to
// initialise or loses its context (ADR 0009 D4). It draws the same scene
// lists as the WebGL2 backend with additive blending instead of HDR bloom.

import { worldToScreen } from "./camera.js";

const BACKGROUND = "#05070d";
/** Beams thinner than this on screen are skipped in the fallback. */
const MIN_BEAM_PX = 0.2;

function rgba(rgb, a) {
  return "rgba(" + Math.round(rgb[0] * 255) + "," + Math.round(rgb[1] * 255) + "," + Math.round(rgb[2] * 255) + "," + a.toFixed(3) + ")";
}

/** particleT returns the position (0..1 from a to b) of a particle at time. */
export function particleT(p, time) {
  const t = (p.phase + time * p.speed) % 1;
  return p.dir > 0 ? t : 1 - t;
}

/**
 * segmentVisible reports whether the bounding box of the segment, grown by
 * margin, intersects the w x h viewport.
 */
export function segmentVisible(ax, ay, bx, by, w, h, margin) {
  return Math.max(ax, bx) >= -margin && Math.min(ax, bx) <= w + margin && Math.max(ay, by) >= -margin && Math.min(ay, by) <= h + margin;
}

/**
 * createCanvas2DBackend returns a backend drawing into canvas, or null if
 * no 2D context can be created. Backend interface (shared with WebGL2):
 *   name, setScene(scene), render(cam, dpr, time) -> bool, isLost(),
 *   dispose(). render returns whether a scene was actually drawn (false
 *   before the first scene, or after a failed upload on WebGL2).
 */
export function createCanvas2DBackend(canvas) {
  const ctx = canvas.getContext("2d", { alpha: false });
  if (!ctx) return null;
  let scene = null;

  return {
    name: "canvas2d",
    setScene(s) {
      scene = s;
    },
    isLost() {
      return false;
    },
    render(cam, dpr, time) {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.globalCompositeOperation = "source-over";
      ctx.globalAlpha = 1;
      ctx.fillStyle = BACKGROUND;
      ctx.fillRect(0, 0, cam.width, cam.height);
      if (!scene) return false;
      ctx.globalCompositeOperation = "lighter";

      for (const n of scene.nebulae) {
        const [x, y] = worldToScreen(cam, n.x, n.y);
        const r = n.r * cam.scale;
        if (r < 1) continue;
        const g = ctx.createRadialGradient(x, y, 0, x, y, r);
        g.addColorStop(0, rgba(n.rgb, 0.18));
        g.addColorStop(0.55, rgba(n.rgb, 0.07));
        g.addColorStop(1, rgba(n.rgb, 0));
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.lineCap = "round";
      // Beams that are too thin or whose bounding box lies outside the
      // viewport are culled; their particles are skipped too.
      const screen = scene.beams.map((b) => {
        if (b.width < MIN_BEAM_PX) return null;
        const [ax, ay] = worldToScreen(cam, b.ax, b.ay);
        const [bx, by] = worldToScreen(cam, b.bx, b.by);
        return segmentVisible(ax, ay, bx, by, cam.width, cam.height, b.width * 3) ? [ax, ay, bx, by] : null;
      });
      scene.beams.forEach((b, i) => {
        if (screen[i] === null) return;
        const [ax, ay, bx, by] = screen[i];
        ctx.strokeStyle = rgba(b.rgb, 0.12 * b.brightness);
        ctx.lineWidth = b.width * 3;
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(bx, by);
        ctx.stroke();
        ctx.strokeStyle = rgba(b.rgb, 0.55 * b.brightness);
        ctx.lineWidth = b.width;
        ctx.stroke();
      });

      for (const p of scene.particles) {
        const seg = screen[p.beam];
        if (!seg) continue;
        const b = scene.beams[p.beam];
        const [ax, ay, bx, by] = seg;
        const t = particleT(p, time);
        const x = ax + (bx - ax) * t;
        const y = ay + (by - ay) * t;
        ctx.fillStyle = rgba(b.rgb, 0.9);
        ctx.beginPath();
        ctx.arc(x, y, 1.2 + b.width * 0.35, 0, Math.PI * 2);
        ctx.fill();
      }

      for (const s of scene.stars) {
        const [x, y] = worldToScreen(cam, s.x, s.y);
        const core = Math.max(1.2, s.r * cam.scale);
        const glow = core * 3.2;
        if (x < -glow || y < -glow || x > cam.width + glow || y > cam.height + glow) continue;
        const g = ctx.createRadialGradient(x, y, 0, x, y, glow);
        g.addColorStop(0, rgba([1, 1, 1], 0.9 * s.brightness));
        g.addColorStop(0.2, rgba(s.rgb, 0.8 * s.brightness));
        g.addColorStop(0.45, rgba(s.rgb, 0.18 * s.brightness));
        g.addColorStop(1, rgba(s.rgb, 0));
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(x, y, glow, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalCompositeOperation = "source-over";
      return true;
    },
    dispose() {
      scene = null;
    },
  };
}
