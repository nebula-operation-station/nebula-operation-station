// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Run with: node --test web/static/trafficmap/

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validateModel } from "./model.js";
import { computeLayout, starRadius, STAR_MAX } from "./layout.js";
import { buildScene, topLinks, zoomLevel, ZOOM, TOP_N, ZOOM_THRESHOLDS } from "./scene.js";
import { spikesFor, STATE_COLORS, SPIKE_LENGTH } from "./health.js";

function raw() {
  return JSON.parse(readFileSync(new URL("./testdata/model-valid.json", import.meta.url), "utf8"));
}

function shuffled(arr, seed) {
  const a = [...arr];
  let s = seed;
  for (let i = a.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) % 2147483648;
    const j = s % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function asObject(layout) {
  return {
    zones: Object.fromEntries([...layout.zones].sort()),
    nodes: Object.fromEntries([...layout.nodes].sort()),
    extent: layout.extent,
  };
}

function big(nZones, nPerZone) {
  const zones = Array.from({ length: nZones }, (_, i) => ({ id: "z" + i, name: "zone " + i, color: "#336699" }));
  const nodes = [{ id: "gw", label: "gw", kind: "router", zone: null }];
  for (let z = 0; z < nZones; z++) {
    for (let k = 0; k < nPerZone; k++) {
      nodes.push({ id: `n${z}-${k}`, label: `n${z}-${k}`, kind: "managed", zone: "z" + z, resources: { vcpu: (k * 7) % 16, ramMiB: 1024 * ((k * 3) % 64) } });
    }
  }
  return validateModel({ type: "nos.trafficmap.model", version: 1, window: "1h", truncated: false, zones, nodes, links: [] });
}

test("LayoutIsDeterministicAcrossRuns", () => {
  const m = validateModel(raw());
  assert.deepEqual(asObject(computeLayout(m)), asObject(computeLayout(m)));
});

test("LayoutDoesNotDependOnInputOrder", () => {
  const base = raw();
  const want = asObject(computeLayout(validateModel(base)));
  for (const seed of [1, 2, 3, 42]) {
    const r = raw();
    r.nodes = shuffled(r.nodes, seed);
    r.zones = shuffled(r.zones, seed + 100);
    r.links = shuffled(r.links, seed + 200);
    assert.deepEqual(asObject(computeLayout(validateModel(r))), want);
  }
});

test("RouterSitsAtOriginAndEveryNodeIsPlaced", () => {
  const m = validateModel(raw());
  const l = computeLayout(m);
  assert.deepEqual([l.nodes.get("gw").x, l.nodes.get("gw").y], [0, 0]);
  for (const n of m.nodes) {
    const p = l.nodes.get(n.id);
    assert.ok(p && Number.isFinite(p.x) && Number.isFinite(p.y), n.id);
  }
});

test("LargestNodeSitsInZoneCentre", () => {
  const m = validateModel(raw());
  const l = computeLayout(m);
  const z = l.zones.get("vlan20");
  const db = l.nodes.get("vm101");
  assert.ok(Math.hypot(db.x - z.x, db.y - z.y) < 1e-9);
});

test("ZoneDiscsDoNotOverlapAndHoldTheirNodes", () => {
  const m = big(12, 120);
  const l = computeLayout(m);
  const zs = [...l.zones.values()];
  for (let i = 0; i < zs.length; i++) {
    for (let j = i + 1; j < zs.length; j++) {
      assert.ok(Math.hypot(zs[i].x - zs[j].x, zs[i].y - zs[j].y) >= zs[i].r + zs[j].r, `zones ${i} ${j} overlap`);
    }
  }
  for (const n of m.nodes) {
    if (n.kind === "router") continue;
    const p = l.nodes.get(n.id);
    const z = l.zones.get(n.zone);
    assert.ok(Math.hypot(p.x - z.x, p.y - z.y) <= z.r, n.id + " outside its zone");
  }
});

test("StarRadiusGrowsLogarithmicallyAndIsBounded", () => {
  const r = (vcpu, ramMiB, gpus) => starRadius({ resources: { vcpu, ramMiB, gpus } });
  assert.ok(r(1, 1024, 0) < r(8, 16384, 0));
  assert.ok(r(8, 16384, 0) < r(8, 16384, 1));
  assert.ok(r(4096, 64 * 1024 * 1024, 64) <= STAR_MAX);
});

test("LayoutHandles4000NodesQuickly", () => {
  const m = big(40, 99);
  const t0 = performance.now();
  computeLayout(m);
  assert.ok(performance.now() - t0 < 500);
});

test("ZoomLevelsFollowThresholds", () => {
  assert.equal(zoomLevel(1), ZOOM.overview);
  assert.equal(zoomLevel(ZOOM_THRESHOLDS.zone), ZOOM.zone);
  assert.equal(zoomLevel(ZOOM_THRESHOLDS.close + 1), ZOOM.close);
});

test("OverviewShowsPerZoneBundlesThroughTheHop", () => {
  const m = validateModel(raw());
  const s = buildScene(m, computeLayout(m), { level: ZOOM.overview, focus: null });
  assert.deepEqual(s.beams.map((b) => b.key).sort(), ["zone:vlan10", "zone:vlan20", "zone:vlan30"]);
  for (const b of s.beams) assert.deepEqual([b.bx, b.by], [0, 0]);
  assert.equal(s.labels.filter((l) => l.kind === "zone").length, 3);
});

test("CloserZoomShowsIndividualLinksViaHop", () => {
  const m = validateModel(raw());
  const s = buildScene(m, computeLayout(m), { level: ZOOM.zone, focus: null });
  const direct = m.links.filter((l) => l.via === null).length;
  const routed = m.links.length - direct;
  assert.equal(s.beams.length, direct + 2 * routed);
});

test("FocusShowsExactlyTopFiveConnections", () => {
  const m = validateModel(raw());
  const top = topLinks(m, "vm101");
  assert.equal(top.length, TOP_N);
  assert.ok(!top.some((l) => l.b === "gw" && l.a === "vm101"), "smallest link is excluded");
  const s = buildScene(m, computeLayout(m), { level: ZOOM.zone, focus: "vm101" });
  const segments = top.reduce((n, l) => n + (l.via !== null ? 2 : 1), 0);
  assert.equal(s.beams.length, segments);
  const peerStar = s.stars.find((x) => x.id === "plug");
  const focusStar = s.stars.find((x) => x.id === "vm101");
  const otherStar = s.stars.find((x) => x.id === "vm102");
  const outsider = s.stars.find((x) => x.id === "nas");
  assert.ok(focusStar.brightness > 0.5);
  assert.ok(peerStar.brightness >= 0.45, "peer stays highlighted");
  assert.ok(otherStar.brightness > 0.45, "top peer stays highlighted");
  assert.ok(outsider.brightness >= 0.45, "routed peer stays highlighted");
  const s2 = buildScene(m, computeLayout(m), { level: ZOOM.zone, focus: "cam1" });
  assert.ok(s2.stars.find((x) => x.id === "pve1").brightness <= 0.25, "unrelated node is dimmed");
});

test("FocusOnUnknownNodeIsIgnored", () => {
  const m = validateModel(raw());
  const s = buildScene(m, computeLayout(m), { level: ZOOM.zone, focus: "ghost" });
  assert.equal(s.focus, null);
});

test("ParticlesFollowDirectionSplit", () => {
  const m = validateModel(raw());
  const s = buildScene(m, computeLayout(m), { level: ZOOM.zone, focus: null });
  const camBeam = s.beams.findIndex((b) => b.key === "link:1:1");
  const parts = s.particles.filter((p) => p.beam === camBeam);
  assert.ok(parts.length > 1);
  assert.ok(parts.every((p) => p.dir === 1), "camera traffic flows one way");
  const again = buildScene(m, computeLayout(m), { level: ZOOM.zone, focus: null });
  assert.deepEqual(again.particles, s.particles);
});

test("UnknownHealthIsGreyNeverGreen", () => {
  const n = { health: { patches: "unknown", general: "unknown", disk: "unknown", load: "unknown", unreachable: false, hostKeyMismatch: false } };
  for (const s of spikesFor(n).spikes) {
    assert.equal(s.css, STATE_COLORS.unknown.css);
    assert.notEqual(s.css, STATE_COLORS.ok.css);
  }
  const bogus = spikesFor({ health: { patches: "green", general: undefined, disk: "ok", load: "ok" } });
  assert.equal(bogus.spikes[0].state, "unknown");
  assert.equal(bogus.spikes[1].state, "unknown");
  assert.equal(spikesFor({ health: null }), null);
});

test("SpikeLengthEncodesSeverity", () => {
  assert.ok(SPIKE_LENGTH.unknown < SPIKE_LENGTH.ok);
  assert.ok(SPIKE_LENGTH.ok < SPIKE_LENGTH.warn);
  assert.ok(SPIKE_LENGTH.warn < SPIKE_LENGTH.crit);
});

test("HealthMarkersInScene", () => {
  const r = raw();
  r.nodes[1].health = { patches: "crit", hostKeyMismatch: true };
  const m = validateModel(r);
  const l = computeLayout(m);
  const over = buildScene(m, l, { level: ZOOM.overview, focus: null });
  const pve = over.health.find((h) => h.id === "pve1");
  assert.equal(pve.spikes.length, 1);
  assert.ok(pve.spikes[0].pulse);
  assert.ok(pve.ring);
  const web = over.health.find((h) => h.id === "vm102");
  assert.ok(web.flicker);
  assert.equal(over.health.find((h) => h.id === "nas"), undefined, "unmanaged nodes have no spikes");
  const close = buildScene(m, l, { level: ZOOM.close, focus: null });
  assert.equal(close.health.find((h) => h.id === "pve1").spikes.length, 4);
});

test("SoftwareAggregatesOnProxmoxHostInOverview", () => {
  const r = raw();
  r.nodes[2].software = [{ key: "postgres", count: 1 }];
  r.nodes[3].software = [{ key: "nginx", count: 1 }, { key: "postgres", count: 1 }];
  const m = validateModel(r);
  const l = computeLayout(m);
  const over = buildScene(m, l, { level: ZOOM.overview, focus: null });
  assert.deepEqual(over.software.map((s) => s.id), ["pve1"]);
  assert.deepEqual(over.software[0].entries, [
    { key: "docker", count: 1 },
    { key: "nginx", count: 1 },
    { key: "postgres", count: 2 },
  ]);
  const close = buildScene(m, l, { level: ZOOM.close, focus: null });
  assert.ok(close.software.some((s) => s.nested && s.parent === "docker" && s.entries[0].key === "postgres"));
  assert.deepEqual(close.software.filter((s) => !s.nested).map((s) => s.id), ["pve1", "vm101", "vm102"]);
});

test("TruncatedModelShowsNotice", () => {
  const r = raw();
  r.truncated = true;
  const m = validateModel(r);
  assert.match(buildScene(m, computeLayout(m), { level: 0, focus: null }).notice, /truncated/);
});
