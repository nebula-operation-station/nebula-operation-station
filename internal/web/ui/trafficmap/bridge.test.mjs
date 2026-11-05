// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Behaviour tests of the parent bridge web/static/trafficmap-bridge.js
// (ADR 0009 D4, TM19), run by TestBridgeJavaScriptBehaviour under
// node --test. The converted model is checked with the renderer's own
// validator (web/static/trafficmap/model.js), so the bridge cannot drift
// from the renderer's message schema.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { validateModel } from "../../../../web/static/trafficmap/model.js";

const src = readFileSync(new URL("../../../../web/static/trafficmap-bridge.js", import.meta.url), "utf8");
// Run in this realm so objects built here are plain objects for the bridge.
const B = vm.runInThisContext(src + "\nNOSTrafficMapBridge;");

const SHA = "a".repeat(64);

function apiModel(over = {}) {
  return {
    window: "24h",
    from: "2026-11-04T00:00:00Z",
    to: "2026-11-05T00:00:00Z",
    zones: [
      { id: "lan", name: "LAN", vlan: 10, nodes: 3 },
      { id: "iot", name: "IoT", vlan: 30, nodes: 1 },
    ],
    nodes: [
      { id: "gw", label: "router", kind: "router", zone: "lan", vlan: 10, resources: {}, health: {}, software: [] },
      { id: "gw2", label: "second hop", kind: "router", zone: "iot", vlan: 30, resources: {}, health: {}, software: [] },
      { id: "h1", label: "pve1", kind: "host", zone: "lan", vlan: 10,
        resources: { vcpu: 8, ram_mib: 32768, gpus: 1 },
        health: { patches: "critical", reachable: true, host_key_mismatch: false, backup_fresh: true, failed_units: 0, disk_used_pct: 95, load: 4 },
        software: [{ key: "docker", count: 1, icon: SHA }, { key: "postgres", count: 2, icon: "not-a-hash" }] },
      { id: "vm101", label: "db01", kind: "guest", zone: "lan", vlan: 10, resources: { vcpu: 2 }, health: {}, software: [] },
      { id: "nas", label: "nas", kind: "asset", zone: "lan", vlan: null, resources: {}, health: {}, software: [] },
      { id: "cam", label: "camera", kind: "endpoint", zone: "", vlan: null, resources: {}, health: {}, software: [] },
    ],
    edges: [
      { a: "h1", b: "nas", bytes_ab: 100, bytes_ba: 200, connections: 3, via: [], services: [{ proto: "tcp", port: 2049 }], lower_bound: false, confirmed: true },
      { a: "cam", b: "nas", bytes_ab: 5, bytes_ba: 6, connections: 1, via: ["gw2"], services: [{ proto: "sctp", port: 9 }], lower_bound: true, confirmed: false },
      { a: "h1", b: "ghost", bytes_ab: 1, bytes_ba: 1, connections: 1, via: [], services: [] },
    ],
    zone_links: [],
    lower_bound: true,
    truncated: false,
    omitted: { zones: 0, nodes: 0, edges: 0, zone_links: 0, software: 0, addresses: 0, flows: 0 },
    unmapped_flows: 7,
    ...over,
  };
}

test("converted model passes the renderer's validator", () => {
  const r = B.convertModel(apiModel());
  const m = validateModel(r.message);
  assert.equal(m.window, "24h");
  const kinds = Object.fromEntries(m.nodes.map((n) => [n.id, n.kind]));
  assert.deepEqual(kinds, { gw: "router", gw2: "asset", h1: "managed", vm101: "guest", nas: "asset", cam: "observed" });
  assert.equal(m.nodes.find((n) => n.id === "gw").zone, null);
  // A node without a zone goes into the synthetic zone.
  const cam = m.nodes.find((n) => n.id === "cam");
  assert.ok(m.zones.some((z) => z.id === cam.zone && z.name === "No zone"));
  // The dangling edge is dropped; an unknown protocol becomes "other".
  assert.equal(m.links.length, 2);
  const camLink = m.links.find((l) => l.a === "cam");
  assert.equal(camLink.proto, "other");
  assert.equal(camLink.via, "gw2");
  assert.equal(r.facts.dropped, 1);
  assert.equal(r.message.truncated, true);
});

test("health that is not known is never drawn as healthy", () => {
  const m = validateModel(B.convertModel(apiModel()).message);
  const vm101 = m.nodes.find((n) => n.id === "vm101");
  for (const k of ["patches", "general", "disk", "load"]) assert.equal(vm101.health[k], "unknown", k);
  assert.equal(vm101.health.unreachable, false);
  const h1 = m.nodes.find((n) => n.id === "h1");
  assert.equal(h1.health.patches, "crit");
  assert.equal(h1.health.general, "ok");
  assert.equal(h1.health.disk, "crit");
  assert.equal(h1.health.load, "ok");

  const bad = apiModel();
  bad.nodes[2].health = { reachable: false, host_key_mismatch: true };
  const h = validateModel(B.convertModel(bad).message).nodes.find((n) => n.id === "h1").health;
  assert.equal(h.general, "crit");
  assert.equal(h.unreachable, true);
  assert.equal(h.hostKeyMismatch, true);
});

test("hostile text is cleaned and bounded", () => {
  const a = apiModel();
  a.nodes[2].label = "evil\u202egnp.exe\u200b<img src=x onerror=alert(1)>\u0000" + "x".repeat(400);
  a.zones[0].name = "\u2066\u2069";
  const m = validateModel(B.convertModel(a).message);
  const label = m.nodes.find((n) => n.id === "h1").label;
  assert.ok(label.length <= 128);
  assert.ok(label.endsWith("…"));
  assert.ok(!/[\u202e\u200b\u0000]/.test(label));
  // Empty after cleaning: the id stands in.
  assert.equal(m.zones.find((z) => z.id === "lan").name, "lan");
  // Exactly at the limit: no ellipsis.
  const b = apiModel();
  b.nodes[2].label = "y".repeat(128);
  assert.equal(validateModel(B.convertModel(b).message).nodes.find((n) => n.id === "h1").label, "y".repeat(128));
});

test("duplicate and invalid ids are dropped, not passed on", () => {
  const a = apiModel();
  a.nodes.push({ id: "h1", label: "twin", kind: "host", zone: "lan" });
  a.nodes.push({ id: "../etc", label: "x", kind: "host", zone: "lan" });
  a.nodes.push({ id: "a".repeat(129), label: "x", kind: "host", zone: "lan" });
  a.zones.push({ id: "lan", name: "dup" });
  const r = B.convertModel(a);
  const m = validateModel(r.message);
  assert.ok(!m.nodes.some((n) => n.id === "h1"));
  assert.equal(r.index.has("h1"), false);
  assert.ok(r.facts.dropped >= 4);
});

test("no room for the synthetic zone leaves the unzoned nodes out", () => {
  const a = apiModel();
  a.zones = Array.from({ length: 256 }, (_, i) => ({ id: "z" + i, name: "Z" + i }));
  a.nodes = [{ id: "n1", label: "n1", kind: "host", zone: "z1" }, { id: "n2", label: "n2", kind: "host", zone: "" }];
  a.edges = [{ a: "n1", b: "n2", bytes_ab: 1, bytes_ba: 1 }];
  const m = validateModel(B.convertModel(a).message);
  assert.deepEqual(m.nodes.map((n) => n.id), ["n1"]);
  assert.equal(m.links.length, 0);
});

test("a malformed model is rejected", () => {
  for (const bad of [null, [], "x", { window: "30d" }, { window: "1h<script>" }]) {
    assert.throws(() => B.convertModel(bad));
  }
  // Missing arrays give an empty but valid model.
  validateModel(B.convertModel({ window: "1h" }).message);
});

test("unmapped flows are a neutral note, not truncation", () => {
  const r = B.convertModel(apiModel({ edges: [] }));
  const t = B.summaryTexts(r.facts);
  assert.match(t.unmapped, /^7 flows go to peers outside the inventory and are not drawn\.$/);
  assert.equal(t.truncated, "");
  assert.equal(r.message.truncated, false);

  const tr = B.convertModel(apiModel({ edges: [], unmapped_flows: 0, truncated: true, omitted: { nodes: 3, edges: 5, flows: 0 } }));
  const tt = B.summaryTexts(tr.facts);
  assert.equal(tt.unmapped, "");
  assert.equal(tt.truncated, "The map is incomplete: left out 3 nodes, 5 edges.");
  assert.equal(tr.message.truncated, true);
});

test("icons: only valid hashes, one per key", () => {
  const r = B.convertModel(apiModel());
  assert.deepEqual([...B.iconRefs(r.index).entries()], [["docker", SHA]]);
});

const frameWin = { postMessage() {} };
const index = B.convertModel(apiModel()).index;
const ev = (data, over = {}) => ({ source: frameWin, origin: "null", data, ...over });

test("frame messages: only the current iframe with the opaque origin", () => {
  const ok = { type: "nos.trafficmap.open", id: "h1" };
  assert.deepEqual(B.acceptFrameMessage(ev(ok), frameWin, index), ok);
  assert.equal(B.acceptFrameMessage(ev(ok, { source: {} }), frameWin, index), null);
  assert.equal(B.acceptFrameMessage(ev(ok, { source: null }), frameWin, index), null);
  for (const origin of ["https://nebula.example.org", "https://evil.example", "", undefined, "null "]) {
    assert.equal(B.acceptFrameMessage(ev(ok, { origin }), frameWin, index), null, String(origin));
  }
  assert.equal(B.acceptFrameMessage(ev(ok), null, index), null);
});

test("frame messages: strict shapes and known node ids", () => {
  const rejects = [
    null, "nos.trafficmap.open", [], { type: 1 },
    { type: "nos.trafficmap.open", id: "ghost" },
    { type: "nos.trafficmap.open", id: "h1", href: "https://evil.example" },
    { type: "nos.trafficmap.open", id: "../hosts" },
    { type: "nos.trafficmap.open", id: null },
    { type: "nos.trafficmap.select", id: "x/y" },
    { type: "nos.trafficmap.ready", extra: 1 },
    { type: "nos.trafficmap.backend", backend: "<b>", fallback: false },
    { type: "nos.trafficmap.backend", backend: "webgl2", fallback: "no" },
    { type: "nos.trafficmap.error", errors: new Array(21).fill("x") },
    { type: "nos.trafficmap.navigate", url: "/hosts/h1" },
    Object.assign(Object.create({ inherited: 1 }), { type: "nos.trafficmap.ready" }),
  ];
  for (const d of rejects) assert.equal(B.acceptFrameMessage(ev(d), frameWin, index), null, JSON.stringify(d));
  assert.deepEqual(B.acceptFrameMessage(ev({ type: "nos.trafficmap.select", id: null }), frameWin, index), { type: "nos.trafficmap.select", id: null });
  assert.deepEqual(B.acceptFrameMessage(ev({ type: "nos.trafficmap.ready" }), frameWin, index), { type: "nos.trafficmap.ready" });
  assert.deepEqual(B.acceptFrameMessage(ev({ type: "nos.trafficmap.backend", backend: "webgl2 (no bloom)", fallback: true }), frameWin, index),
    { type: "nos.trafficmap.backend", backend: "webgl2 (no bloom)", fallback: true });
  assert.deepEqual(B.acceptFrameMessage(ev({ type: "nos.trafficmap.error", errors: ["a", "b"] }), frameWin, index), { type: "nos.trafficmap.error", count: 2 });
  // Before a model is loaded no node id is accepted.
  assert.equal(B.acceptFrameMessage(ev({ type: "nos.trafficmap.open", id: "h1" }), frameWin, null), null);
});

test("navigation targets: host page, asset page, else the focus view", () => {
  assert.equal(B.openTarget(index, "24h", "h1"), "/hosts/h1");
  assert.equal(B.openTarget(index, "24h", "nas"), "/network/a/nas");
  assert.equal(B.openTarget(index, "24h", "vm101"), "/traffic?window=24h&focus=vm101");
  assert.equal(B.openTarget(index, "24h", "gw"), "/traffic?window=24h&focus=gw");
  assert.equal(B.openTarget(index, "24h", "ghost"), null);
  assert.equal(B.openTarget(index, "30d", "h1"), null);
  assert.deepEqual(B.pageFor("host", "a:b"), { href: "/hosts/a%3Ab", text: "Open host page" });
  for (const id of ["/evil.example", "//evil.example", "javascript:alert(1)", "", "a b"]) {
    assert.equal(B.pageFor("host", id), null, id);
  }
});

// --- start(): the wiring with a fake DOM, fetch and iframe ---------------

class FakeEl {
  constructor(id, attrs = {}) {
    this.id = id;
    this.attrs = { ...attrs };
    this.textContent = "";
    this.hidden = false;
    this.listeners = {};
  }
  getAttribute(k) { return Object.hasOwn(this.attrs, k) ? this.attrs[k] : null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
}

function fakeResponse(status, ctype, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => (k === "Content-Type" ? ctype : k === "Content-Length" ? String(body.length) : null) },
    text: async () => body,
    blob: async () => ({ size: body.length, body }),
  };
}

function setup({ window = "24h", focus = "", api = apiModel(), apiStatus = 200 } = {}) {
  const posts = [];
  const contentWindow = { postMessage: (msg, origin) => posts.push({ msg, origin }) };
  const els = {};
  for (const id of ["trafficmap-status", "trafficmap-summary", "trafficmap-unmapped", "trafficmap-truncated", "trafficmap-selection",
    "trafficmap-selection-label", "trafficmap-selection-kind", "trafficmap-selection-open", "trafficmap-selection-focus"]) els[id] = new FakeEl(id);
  els["trafficmap-page"] = new FakeEl("trafficmap-page", { "data-window": window, "data-focus": focus });
  els["trafficmap-frame"] = Object.assign(new FakeEl("trafficmap-frame"), { contentWindow });
  const winListeners = {};
  const fetched = [];
  const navigated = [];
  const env = {
    document: { getElementById: (id) => els[id] || null },
    window: { addEventListener: (t, f) => (winListeners[t] ||= []).push(f) },
    fetch: async (url, opts) => {
      fetched.push({ url, opts });
      if (url.startsWith("/api/v1/trafficmap")) return fakeResponse(apiStatus, "application/json; charset=utf-8", JSON.stringify(api));
      if (url === "/icons/" + SHA + ".png") return fakeResponse(200, "image/png", "png");
      return fakeResponse(404, "text/plain", "");
    },
    createImageBitmap: async () => ({ width: 32, height: 32, close() {} }),
    navigate: (href) => navigated.push(href),
  };
  const s = B.start(env);
  const deliver = (data, over = {}) => winListeners.message.forEach((f) => f({ source: contentWindow, origin: "null", data, ...over }));
  return { s, els, posts, fetched, navigated, deliver, contentWindow };
}

test("start: fetches the model of the page's window and focus", async () => {
  const t = setup({ window: "7d", focus: "h1" });
  await t.s.loaded;
  assert.equal(t.fetched[0].url, "/api/v1/trafficmap?window=7d&focus=h1");
  assert.equal(t.fetched[0].opts.credentials, "same-origin");
  assert.ok(t.fetched.some((f) => f.url === "/icons/" + SHA + ".png"));
  assert.ok(!t.fetched.some((f) => f.url.includes("not-a-hash")));
  assert.equal(t.els["trafficmap-unmapped"].textContent, "7 flows go to peers outside the inventory and are not drawn.");
  assert.equal(t.els["trafficmap-unmapped"].hidden, false);
});

test("start: nothing is posted before the iframe is ready; then model, focus and icons", async () => {
  const t = setup({ focus: "h1", api: apiModel({ focus: "h1" }) });
  await t.s.loaded;
  assert.equal(t.posts.length, 0);
  // A ready from another source or origin does not count.
  t.deliver({ type: "nos.trafficmap.ready" }, { source: {} });
  t.deliver({ type: "nos.trafficmap.ready" }, { origin: "https://evil.example" });
  assert.equal(t.posts.length, 0);
  t.deliver({ type: "nos.trafficmap.ready" });
  const types = t.posts.map((p) => p.msg.type);
  assert.deepEqual(types, ["nos.trafficmap.model", "nos.trafficmap.icons", "nos.trafficmap.focus"]);
  for (const p of t.posts) assert.equal(p.origin, "*");
  validateModel(t.posts[0].msg);
  assert.deepEqual(Object.keys(t.posts[1].msg.icons), ["docker"]);
  assert.deepEqual(t.posts[2].msg, { type: "nos.trafficmap.focus", id: "h1" });
});

test("start: a reloaded iframe gets nothing until it is ready again", async () => {
  const t = setup();
  await t.s.loaded;
  t.deliver({ type: "nos.trafficmap.ready" });
  const n = t.posts.length;
  t.els["trafficmap-frame"].listeners.load.forEach((f) => f());
  await t.s.loaded;
  assert.equal(t.posts.length, n);
  t.deliver({ type: "nos.trafficmap.ready" });
  assert.ok(t.posts.length > n);
});

test("start: open navigates to the node's page, only for valid messages", async () => {
  const t = setup();
  await t.s.loaded;
  t.deliver({ type: "nos.trafficmap.open", id: "h1" }, { source: {} });
  t.deliver({ type: "nos.trafficmap.open", id: "h1" }, { origin: "https://nebula.example.org" });
  t.deliver({ type: "nos.trafficmap.open", id: "ghost" });
  t.deliver({ type: "nos.trafficmap.open", id: "h1", url: "https://evil.example" });
  assert.deepEqual(t.navigated, []);
  t.deliver({ type: "nos.trafficmap.open", id: "h1" });
  t.deliver({ type: "nos.trafficmap.open", id: "nas" });
  t.deliver({ type: "nos.trafficmap.open", id: "vm101" });
  assert.deepEqual(t.navigated, ["/hosts/h1", "/network/a/nas", "/traffic?window=24h&focus=vm101"]);
});

test("start: select shows the node as text with same-origin links", async () => {
  const t = setup();
  const hostile = apiModel();
  hostile.nodes[2].label = "<img src=x onerror=alert(1)>";
  const u = setup({ api: hostile });
  await Promise.all([t.s.loaded, u.s.loaded]);
  u.deliver({ type: "nos.trafficmap.select", id: "h1" });
  assert.equal(u.els["trafficmap-selection"].hidden, false);
  assert.equal(u.els["trafficmap-selection-label"].textContent, "<img src=x onerror=alert(1)>");
  assert.equal(u.els["trafficmap-selection-open"].attrs.href, "/hosts/h1");
  assert.equal(u.els["trafficmap-selection-focus"].attrs.href, "/traffic?window=24h&focus=h1");
  u.deliver({ type: "nos.trafficmap.select", id: "vm101" });
  assert.equal(u.els["trafficmap-selection-open"].hidden, true);
  assert.equal(u.els["trafficmap-selection-open"].attrs.href, undefined);
  u.deliver({ type: "nos.trafficmap.select", id: null });
  assert.equal(u.els["trafficmap-selection"].hidden, true);
});

test("start: API errors and renderer rejections are reported as text", async () => {
  const t = setup({ apiStatus: 403 });
  await t.s.loaded;
  assert.match(t.els["trafficmap-status"].textContent, /could not be loaded: the server answered 403/);
  const u = setup();
  await u.s.loaded;
  u.deliver({ type: "nos.trafficmap.error", errors: ["model.nodes[0].id: is not a valid identifier"] });
  assert.equal(u.els["trafficmap-status"].textContent, "The renderer rejected the map data (1 problem).");
});

test("start: invalid page parameters stop before any request", () => {
  for (const [window, focus] of [["30d", ""], ["24h", "../x"]]) {
    const t = setup({ window, focus });
    assert.equal(t.s, null);
    assert.equal(t.fetched.length, 0);
  }
});
