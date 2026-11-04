// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Scene builder: turns a validated model, its layout and the view state
// (semantic zoom level, focus) into backend-neutral draw lists. Pure and
// deterministic; both the WebGL2 and the Canvas 2D backend draw exactly
// these lists, and the overlay draws its labels and symbols from them.

import { resourceWeight } from "./model.js";
import { spikesFor } from "./health.js";

/** Semantic zoom levels (ADR 0009 D4). */
export const ZOOM = Object.freeze({ overview: 0, zone: 1, close: 2 });
/** Camera scale (relative to "fit all") at which each level begins. */
export const ZOOM_THRESHOLDS = Object.freeze({ zone: 1.8, close: 4.5 });
/** A focused node shows exactly this many top connections. */
export const TOP_N = 5;
/** Particles per beam are bounded so the frame cost stays predictable. */
export const MAX_PARTICLES_PER_BEAM = 6;

const ROUTER_RGB = Object.freeze([0.92, 0.94, 1.0]);

/** zoomLevel maps a relative camera scale to a semantic zoom level. */
export function zoomLevel(relativeScale) {
  if (relativeScale >= ZOOM_THRESHOLDS.close) return ZOOM.close;
  if (relativeScale >= ZOOM_THRESHOLDS.zone) return ZOOM.zone;
  return ZOOM.overview;
}

/** hexToRgb converts a validated "#rrggbb" colour into [r, g, b] in 0..1. */
export function hexToRgb(hex) {
  const v = parseInt(hex.slice(1), 16);
  return [((v >> 16) & 255) / 255, ((v >> 8) & 255) / 255, (v & 255) / 255];
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function total(l) {
  return l.bytesAB + l.bytesBA;
}

/**
 * topLinks returns the n largest links of node id by inbound plus outbound
 * bytes, ties broken by the peer id so the result is deterministic.
 */
export function topLinks(model, id, n = TOP_N) {
  const peer = (l) => (l.a === id ? l.b : l.a);
  return model.links
    .filter((l) => l.a === id || l.b === id)
    .sort((x, y) => total(y) - total(x) || cmp(peer(x), peer(y)) || x.port - y.port)
    .slice(0, n);
}

function beamStyle(volume) {
  return {
    width: Math.min(6, 0.6 + 0.35 * volume),
    brightness: Math.min(1, 0.25 + 0.075 * volume),
  };
}

function mix(a, b) {
  return [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2, (a[2] + b[2]) / 2];
}

// hash01 is a small deterministic hash used for particle phases, so the
// animation does not depend on Math.random.
function hash01(i, j) {
  let h = (Math.imul(i + 1, 0x9e3779b1) ^ Math.imul(j + 1, 0x85ebca77)) >>> 0;
  h = Math.imul(h ^ (h >>> 15), 0x2c1b3c6d) >>> 0;
  return (h ^ (h >>> 13)) / 4294967296;
}

function addBeam(out, ax, ay, bx, by, bytesAB, bytesBA, rgb, key) {
  const volume = Math.log10(1 + bytesAB + bytesBA);
  const s = beamStyle(volume);
  const sum = bytesAB + bytesBA;
  const index = out.beams.length;
  out.beams.push({ key, ax, ay, bx, by, width: s.width, brightness: s.brightness, rgb, forward: sum > 0 ? bytesAB / sum : 0.5 });
  // Particles show the direction split: a share proportional to bytesAB
  // travels a -> b, the rest b -> a.
  const n = Math.max(1, Math.min(MAX_PARTICLES_PER_BEAM, Math.ceil(volume / 2)));
  const forwardCount = Math.round(n * (sum > 0 ? bytesAB / sum : 0.5));
  for (let k = 0; k < n; k++) {
    out.particles.push({
      beam: index,
      phase: hash01(index, k),
      dir: k < forwardCount ? 1 : -1,
      speed: 0.08 + 0.04 * hash01(k, index),
    });
  }
}

/**
 * buildScene returns { level, focus, stars, beams, particles, nebulae,
 * labels, health, software, notice }. Coordinates are in world units.
 * view = { level, focus } where focus is a node id or null.
 */
export function buildScene(model, layout, view) {
  const level = view.level;
  const byId = new Map(model.nodes.map((n) => [n.id, n]));
  const focus = view.focus !== null && byId.has(view.focus) ? view.focus : null;
  const zoneRgb = new Map(model.zones.map((z) => [z.id, hexToRgb(z.color)]));
  const rgbOf = (n) => (n.kind === "router" ? ROUTER_RGB : zoneRgb.get(n.zone));
  const out = { level, focus, stars: [], beams: [], particles: [], nebulae: [], labels: [], health: [], software: [], notice: null };

  if (model.truncated) {
    out.notice = "The server truncated this model; not every connection is shown.";
  }

  // Focus: exactly the node's top connections; peers stay highlighted.
  let focusLinks = null;
  const highlighted = new Set();
  if (focus !== null) {
    focusLinks = topLinks(model, focus);
    highlighted.add(focus);
    for (const l of focusLinks) {
      highlighted.add(l.a);
      highlighted.add(l.b);
      if (l.via !== null) highlighted.add(l.via);
    }
  }

  const zonesSorted = [...model.zones].sort((a, b) => cmp(a.id, b.id));
  for (const z of zonesSorted) {
    const p = layout.zones.get(z.id);
    out.nebulae.push({ id: z.id, x: p.x, y: p.y, r: p.r * 1.35, rgb: zoneRgb.get(z.id), seed: hash01(out.nebulae.length, 7) });
    if (level === ZOOM.overview || focus === null) {
      out.labels.push({ kind: "zone", x: p.x, y: p.y - p.r * 1.1, text: z.name });
    }
  }

  const nodesSorted = [...model.nodes].sort((a, b) => cmp(a.id, b.id));
  for (const n of nodesSorted) {
    const p = layout.nodes.get(n.id);
    const dim = focus !== null && !highlighted.has(n.id);
    const brightness = (n.kind === "observed" ? 0.45 : 0.55) + Math.min(0.45, 0.05 * resourceWeight(n.resources));
    out.stars.push({ id: n.id, x: p.x, y: p.y, r: p.r, rgb: rgbOf(n), brightness: dim ? brightness * 0.25 : brightness, kind: n.kind });

    const showLabel =
      n.kind === "router" ||
      (focus !== null && highlighted.has(n.id)) ||
      (focus === null && level === ZOOM.close) ||
      (focus === null && level === ZOOM.zone && (n.kind === "managed" || n.kind === "guest"));
    if (showLabel) {
      const text = n.kind === "observed" && level === ZOOM.close ? n.label + " (unknown device)" : n.label;
      out.labels.push({ kind: "node", id: n.id, x: p.x, y: p.y + p.r + 4, text });
    }

    const h = spikesFor(n);
    if (h && (!dim || h.ring || h.flicker)) {
      // Overview: only the markers that must stand out (critical patches
      // pulse, unreachable flicker, host-key mismatch ring). Dimmed nodes
      // lose their spikes but keep the host-key ring and the unreachable
      // flicker: those warnings must stay visible while a node is focused.
      let spikes = level === ZOOM.overview ? h.spikes.filter((s) => s.pulse) : h.spikes;
      if (dim) spikes = [];
      out.health.push({ id: n.id, x: p.x, y: p.y, r: p.r, spikes, flicker: h.flicker, ring: h.ring });
    }
  }

  // Software symbols: aggregated on the Proxmox host in the overview, per
  // node when closer, with Docker containers nested at the closest level.
  if (focus === null || level !== ZOOM.overview) {
    const perNode = new Map();
    for (const n of nodesSorted) {
      if (n.software.length === 0) continue;
      const target = level === ZOOM.overview && n.host !== null ? n.host : n.id;
      if (!perNode.has(target)) perNode.set(target, new Map());
      const agg = perNode.get(target);
      for (const s of n.software) {
        agg.set(s.key, (agg.get(s.key) || 0) + s.count);
      }
      if (level === ZOOM.close) {
        for (const s of n.software) {
          if (s.children.length === 0) continue;
          const nested = s.children.map((c) => ({ key: c.key, count: c.count }));
          out.software.push({ id: n.id, parent: s.key, nested: true, x: layout.nodes.get(n.id).x, y: layout.nodes.get(n.id).y, entries: nested });
        }
      }
    }
    for (const [id, agg] of [...perNode].sort((a, b) => cmp(a[0], b[0]))) {
      if (focus !== null && !highlighted.has(id)) continue;
      const p = layout.nodes.get(id);
      const entries = [...agg].sort((a, b) => cmp(a[0], b[0])).map(([key, count]) => ({ key, count }));
      out.software.push({ id, parent: null, nested: false, x: p.x, y: p.y, entries });
    }
  }

  const router = model.nodes.find((n) => n.kind === "router");
  const hub = router ? layout.nodes.get(router.id) : { x: 0, y: 0 };

  if (focus === null && level === ZOOM.overview) {
    // Per-VLAN bundles through the hop: one beam per zone to the router,
    // carrying all traffic that leaves or enters the zone.
    const outBytes = new Map();
    const inBytes = new Map();
    const add = (m, k, v) => m.set(k, (m.get(k) || 0) + v);
    for (const l of model.links) {
      const za = byId.get(l.a).zone;
      const zb = byId.get(l.b).zone;
      if (za === zb) continue;
      if (za !== null) {
        add(outBytes, za, l.bytesAB);
        add(inBytes, za, l.bytesBA);
      }
      if (zb !== null) {
        add(outBytes, zb, l.bytesBA);
        add(inBytes, zb, l.bytesAB);
      }
    }
    for (const z of zonesSorted) {
      const o = outBytes.get(z.id) || 0;
      const i = inBytes.get(z.id) || 0;
      if (o + i === 0) continue;
      const p = layout.zones.get(z.id);
      addBeam(out, p.x, p.y, hub.x, hub.y, o, i, mix(zoneRgb.get(z.id), ROUTER_RGB), "zone:" + z.id);
    }
    return out;
  }

  const links = focusLinks !== null ? focusLinks : model.links;
  links.forEach((l, idx) => {
    const a = layout.nodes.get(l.a);
    const b = layout.nodes.get(l.b);
    const rgb = mix(rgbOf(byId.get(l.a)), rgbOf(byId.get(l.b)));
    const key = "link:" + idx;
    if (l.via !== null && l.via !== l.a && l.via !== l.b) {
      // Routed traffic is drawn A -> hop -> B.
      const v = layout.nodes.get(l.via);
      addBeam(out, a.x, a.y, v.x, v.y, l.bytesAB, l.bytesBA, rgb, key + ":1");
      addBeam(out, v.x, v.y, b.x, b.y, l.bytesAB, l.bytesBA, rgb, key + ":2");
    } else {
      addBeam(out, a.x, a.y, b.x, b.y, l.bytesAB, l.bytesBA, rgb, key);
    }
  });
  return out;
}
