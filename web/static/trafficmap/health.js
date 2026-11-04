// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Health spikes (ADR 0009 D4). Each managed node gets four spikes: top =
// patches, left = general health, bottom = disk, right = load. Spike length
// encodes severity as well as colour, so colour is never the only cue. A
// value that is not known is drawn grey and short, never green.

/** Spike directions as unit vectors in screen space (y grows downwards). */
export const SPIKE_DIRECTIONS = Object.freeze({
  patches: Object.freeze([0, -1]),
  general: Object.freeze([-1, 0]),
  disk: Object.freeze([0, 1]),
  load: Object.freeze([1, 0]),
});

/** Colours per state, as [r, g, b] in 0..1 and as CSS strings. */
export const STATE_COLORS = Object.freeze({
  ok: Object.freeze({ rgb: Object.freeze([0.3, 0.85, 0.45]), css: "#4dd973" }),
  warn: Object.freeze({ rgb: Object.freeze([1.0, 0.72, 0.2]), css: "#ffb833" }),
  crit: Object.freeze({ rgb: Object.freeze([1.0, 0.25, 0.25]), css: "#ff4040" }),
  unknown: Object.freeze({ rgb: Object.freeze([0.55, 0.57, 0.6]), css: "#8c9199" }),
});

/** Spike length as a multiple of the star radius, per state. */
export const SPIKE_LENGTH = Object.freeze({ unknown: 0.6, ok: 0.9, warn: 1.6, crit: 2.4 });

/**
 * spikesFor returns the spikes and markers of a node's health, or null for
 * nodes without health (unmanaged). Each spike is
 * { key, state, dir: [dx, dy], length, rgb, css, pulse }.
 * pulse is true for critical patches (they pulse in the overview).
 * flicker marks an unreachable host (grey flicker); ring marks a host-key
 * mismatch (red ring).
 */
export function spikesFor(node) {
  const h = node.health;
  if (!h) return null;
  const spikes = [];
  for (const key of ["patches", "general", "disk", "load"]) {
    // Defensive: anything that is not a known state is treated as unknown.
    const state = Object.prototype.hasOwnProperty.call(STATE_COLORS, h[key]) ? h[key] : "unknown";
    const color = STATE_COLORS[state];
    spikes.push({
      key,
      state,
      dir: SPIKE_DIRECTIONS[key],
      length: SPIKE_LENGTH[state],
      rgb: color.rgb,
      css: color.css,
      pulse: key === "patches" && state === "crit",
    });
  }
  return { spikes, flicker: h.unreachable === true, ring: h.hostKeyMismatch === true };
}
