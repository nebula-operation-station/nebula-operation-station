// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Deterministic layout (ADR 0009 D4): zones on a ring around the router,
// nodes per zone on a sunflower (phyllotaxis) spiral ordered by resources.
// O(n log n) for the sort, no randomness, no force simulation; the result
// depends only on the model's content, never on input order.

import { resourceWeight } from "./model.js";

/** Golden angle in radians, the phyllotaxis step. */
export const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
/** Distance between neighbouring stars on the spiral, in world units. */
export const SPIRAL_STEP = 14;
/** Minimum gap between two zone discs on the ring, in world units. */
export const ZONE_GAP = 60;
/** Minimum ring radius (distance of zone centres from the router). */
export const MIN_RING = 220;
/** Base star radius and growth per unit of resource weight. */
export const STAR_BASE = 3;
export const STAR_GROWTH = 0.9;
/** Upper bound of the star radius in world units. */
export const STAR_MAX = 16;

function compareStrings(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** starRadius maps a node's resources to its star radius in world units. */
export function starRadius(node) {
  return Math.min(STAR_MAX, STAR_BASE + STAR_GROWTH * resourceWeight(node.resources));
}

/** zoneRadius is the radius of the disc holding n stars on the spiral. */
export function zoneRadius(n) {
  return SPIRAL_STEP * Math.sqrt(Math.max(n, 1)) + STAR_MAX;
}

/**
 * computeLayout returns { zones: Map(zoneId -> {x, y, r}),
 * nodes: Map(nodeId -> {x, y, r}), extent } for a validated model.
 * The router sits at the origin.
 */
export function computeLayout(model) {
  const zoneList = [...model.zones].sort((a, b) => compareStrings(a.id, b.id));
  const members = new Map(zoneList.map((z) => [z.id, []]));
  const nodes = new Map();
  for (const n of model.nodes) {
    if (n.kind === "router") {
      nodes.set(n.id, { x: 0, y: 0, r: Math.max(starRadius(n), 8) });
    } else {
      members.get(n.zone).push(n);
    }
  }

  // Ring radius: large enough that neighbouring zone discs do not overlap
  // (chord between neighbours >= sum of their radii + gap).
  const radii = zoneList.map((z) => zoneRadius(members.get(z.id).length));
  const count = zoneList.length;
  let ring = MIN_RING;
  if (count > 1) {
    const half = Math.sin(Math.PI / count);
    for (let i = 0; i < count; i++) {
      const need = (radii[i] + radii[(i + 1) % count] + ZONE_GAP) / (2 * half);
      ring = Math.max(ring, need);
    }
  }
  ring = Math.max(ring, Math.max(0, ...radii) + MIN_RING / 2);

  const zones = new Map();
  let extent = ring;
  zoneList.forEach((z, i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(count, 1);
    const cx = ring * Math.cos(angle);
    const cy = ring * Math.sin(angle);
    zones.set(z.id, { x: cx, y: cy, r: radii[i] });
    extent = Math.max(extent, ring + radii[i]);

    // Largest first so the brightest stars sit in the zone centre; ties are
    // broken by id so the order is total.
    const list = members.get(z.id);
    const weights = new Map(list.map((n) => [n.id, resourceWeight(n.resources)]));
    list.sort((a, b) => weights.get(b.id) - weights.get(a.id) || compareStrings(a.id, b.id));
    list.forEach((n, k) => {
      const rr = k === 0 ? 0 : SPIRAL_STEP * Math.sqrt(k + 0.5);
      const th = k * GOLDEN_ANGLE + angle;
      nodes.set(n.id, { x: cx + rr * Math.cos(th), y: cy + rr * Math.sin(th), r: starRadius(n) });
    });
  });

  return { zones, nodes, extent };
}
