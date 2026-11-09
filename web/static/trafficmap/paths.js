// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Attack-path overlay of the traffic map (ADR 0011 D10, VU-24). The overlay
// is served only inside the admin-only renderer document of the attack-path
// pages, which carries it in the data-paths attribute of the map root; the
// normal traffic map document has no such attribute and never draws it.
// It holds traffic map node IDs, ranks and flags only: no labels, no
// findings, no links. The data is validated like the model (exact shape,
// explicit limits, unknown keys rejected, values never echoed) and drawn
// with canvas primitives only; nothing here touches the DOM beyond reading
// the attribute.

import { worldToScreen } from "./camera.js";

/** Supported overlay schema version. */
export const PATHS_VERSION = 1;

/** Limits enforced by validatePaths; beams and marks equal the Go side. */
export const PATHS_LIMITS = Object.freeze({
  bytes: 262144,
  beams: 1000,
  marks: 1000,
  idLength: 128,
  rank: 20,
  errors: 20,
});

/** Roles of a marked node. */
export const MARK_ROLES = Object.freeze(["target", "step"]);

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;

/** Colours: rank 1 red, later ranks amber; targets keep the red ring. */
export const PATH_COLORS = Object.freeze({
  top: "#ff4d4d",
  other: "#ffa94d",
  target: "#ff4d4d",
  step: "#ffd43b",
  notice: "#ffa94d",
});

/** PathsError carries the list of problems found in the overlay data. */
export class PathsError extends Error {
  constructor(errors) {
    super("invalid attack-path overlay: " + errors.join("; "));
    this.name = "PathsError";
    this.errors = errors;
  }
}

function fail(errors, path, msg) {
  // Only the path and a fixed message: never echo untrusted values.
  if (errors.length < PATHS_LIMITS.errors) errors.push(path + ": " + msg);
}

function plainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function exactKeys(errors, v, path, keys) {
  if (!plainObject(v)) {
    fail(errors, path, "is not an object");
    return false;
  }
  for (const k of Object.keys(v)) {
    if (!keys.includes(k)) fail(errors, path, "has an unknown key");
  }
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(v, k)) fail(errors, path + "." + k, "is missing");
  }
  return true;
}

function id(errors, v, path) {
  if (typeof v !== "string" || v.length === 0 || v.length > PATHS_LIMITS.idLength || !ID_RE.test(v)) {
    fail(errors, path, "is not a valid identifier");
    return undefined;
  }
  return v;
}

function bool(errors, v, path) {
  if (typeof v !== "boolean") {
    fail(errors, path, "is not a boolean");
    return false;
  }
  return v;
}

/**
 * validatePaths checks a parsed overlay and returns a fresh frozen copy with
 * only the known fields. It throws PathsError on any problem.
 */
export function validatePaths(raw) {
  const errors = [];
  if (!exactKeys(errors, raw, "paths", ["version", "beams", "marks", "truncated"])) throw new PathsError(errors);
  if (raw.version !== PATHS_VERSION) fail(errors, "paths.version", "is not supported");
  const truncated = bool(errors, raw.truncated, "paths.truncated");
  const beams = [];
  if (!Array.isArray(raw.beams) || raw.beams.length > PATHS_LIMITS.beams) {
    fail(errors, "paths.beams", "is not a list within the limit");
  } else {
    raw.beams.forEach((b, i) => {
      const p = "paths.beams[" + i + "]";
      if (!exactKeys(errors, b, p, ["from", "to", "rank", "assumed", "possible"])) return;
      const from = id(errors, b.from, p + ".from");
      const to = id(errors, b.to, p + ".to");
      if (from !== undefined && from === to) fail(errors, p, "is a self loop");
      if (!Number.isInteger(b.rank) || b.rank < 1 || b.rank > PATHS_LIMITS.rank) fail(errors, p + ".rank", "is out of range");
      const assumed = bool(errors, b.assumed, p + ".assumed");
      const possible = bool(errors, b.possible, p + ".possible");
      beams.push(Object.freeze({ from, to, rank: b.rank, assumed, possible }));
    });
  }
  const marks = [];
  if (!Array.isArray(raw.marks) || raw.marks.length > PATHS_LIMITS.marks) {
    fail(errors, "paths.marks", "is not a list within the limit");
  } else {
    const seen = new Set();
    raw.marks.forEach((m, i) => {
      const p = "paths.marks[" + i + "]";
      if (!exactKeys(errors, m, p, ["id", "role"])) return;
      const mid = id(errors, m.id, p + ".id");
      if (mid !== undefined && seen.has(mid)) fail(errors, p + ".id", "is repeated");
      seen.add(mid);
      if (!MARK_ROLES.includes(m.role)) fail(errors, p + ".role", "has an unsupported value");
      marks.push(Object.freeze({ id: mid, role: m.role }));
    });
  }
  if (errors.length > 0) throw new PathsError(errors);
  return Object.freeze({ rejected: false, truncated, beams: Object.freeze(beams), marks: Object.freeze(marks) });
}

/** REJECTED is the overlay used when the data is invalid: nothing to draw, a notice instead. */
export const REJECTED = Object.freeze({ rejected: true, truncated: false, beams: Object.freeze([]), marks: Object.freeze([]) });

/**
 * readPaths reads the overlay from root's data-paths attribute. It returns
 * null when the attribute is absent (the normal traffic map), the validated
 * overlay, or REJECTED when the data is oversized or invalid.
 */
export function readPaths(root) {
  if (!root || typeof root.getAttribute !== "function") return null;
  const text = root.getAttribute("data-paths");
  if (text === null) return null;
  if (typeof text !== "string" || text.length > PATHS_LIMITS.bytes) return REJECTED;
  try {
    return validatePaths(JSON.parse(text));
  } catch {
    return REJECTED;
  }
}

/**
 * drawPaths draws the overlay over the current overlay canvas in CSS
 * pixels (drawOverlay has set the transform). positions maps traffic map
 * node IDs to world positions ({x, y}). It returns how many beams were
 * drawn and how many were skipped because an end is not on the map.
 */
export function drawPaths(ctx, cam, paths, positions) {
  const out = { drawn: 0, skipped: 0 };
  if (!paths) return out;
  ctx.globalAlpha = 1;
  if (paths.rejected || paths.truncated) {
    ctx.font = "11px sans-serif";
    ctx.textAlign = "left";
    ctx.textBaseline = "bottom";
    ctx.fillStyle = PATH_COLORS.notice;
    ctx.fillText(paths.rejected ? "Attack-path overlay rejected: invalid data" : "Attack-path overlay truncated", 12, cam.height - 8);
  }
  // Later ranks first, so rank 1 is drawn on top.
  const beams = [...paths.beams].sort((a, b) => b.rank - a.rank);
  for (const b of beams) {
    const p = positions.get(b.from);
    const q = positions.get(b.to);
    if (!p || !q) {
      out.skipped++;
      continue;
    }
    const [x1, y1] = worldToScreen(cam, p.x, p.y);
    const [x2, y2] = worldToScreen(cam, q.x, q.y);
    const top = b.rank === 1;
    ctx.strokeStyle = top ? PATH_COLORS.top : PATH_COLORS.other;
    ctx.fillStyle = ctx.strokeStyle;
    ctx.globalAlpha = top ? 0.95 : Math.max(0.35, 0.85 - 0.03 * b.rank);
    ctx.lineWidth = top ? 3 : 2;
    ctx.setLineDash(b.assumed || b.possible ? [6, 4] : []);
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();
    ctx.setLineDash([]);
    // Arrow head at the step's target.
    const ang = Math.atan2(y2 - y1, x2 - x1);
    const len = 9;
    ctx.beginPath();
    ctx.moveTo(x2, y2);
    ctx.lineTo(x2 - len * Math.cos(ang - 0.4), y2 - len * Math.sin(ang - 0.4));
    ctx.lineTo(x2 - len * Math.cos(ang + 0.4), y2 - len * Math.sin(ang + 0.4));
    ctx.closePath();
    ctx.fill();
    out.drawn++;
  }
  ctx.globalAlpha = 1;
  for (const m of paths.marks) {
    const p = positions.get(m.id);
    if (!p) continue;
    const [sx, sy] = worldToScreen(cam, p.x, p.y);
    ctx.strokeStyle = m.role === "target" ? PATH_COLORS.target : PATH_COLORS.step;
    ctx.lineWidth = m.role === "target" ? 2.5 : 1.5;
    ctx.beginPath();
    ctx.arc(sx, sy, m.role === "target" ? 16 : 11, 0, Math.PI * 2);
    ctx.stroke();
  }
  return out;
}
