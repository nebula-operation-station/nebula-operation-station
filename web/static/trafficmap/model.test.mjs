// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Run with: node --test web/static/trafficmap/

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  validateModel,
  validateIcons,
  validateFocus,
  ValidationError,
  LIMITS,
  MSG_ICONS,
  MSG_FOCUS,
} from "./model.js";

function loadValid() {
  return JSON.parse(readFileSync(new URL("./testdata/model-valid.json", import.meta.url), "utf8"));
}

function rejects(mutate, pathPart) {
  const m = loadValid();
  mutate(m);
  assert.throws(
    () => validateModel(m),
    (err) => {
      assert.ok(err instanceof ValidationError, "ValidationError expected");
      if (pathPart) {
        assert.ok(err.errors.some((e) => e.includes(pathPart)), `error mentions ${pathPart}: ${err.errors.join(" | ")}`);
      }
      return true;
    },
  );
}

test("ValidModelIsAcceptedAndFrozen", () => {
  const m = validateModel(loadValid());
  assert.equal(m.nodes.length, 7);
  assert.equal(m.links.length, 10);
  assert.ok(Object.isFrozen(m));
  assert.ok(Object.isFrozen(m.nodes[1].health));
  assert.throws(() => {
    m.nodes.push({});
  });
});

test("MissingHealthOnManagedNodeIsUnknownNeverOk", () => {
  const raw = loadValid();
  delete raw.nodes[1].health;
  raw.nodes[2].health = { patches: "ok" };
  const m = validateModel(raw);
  const pve = m.nodes.find((n) => n.id === "pve1");
  for (const k of ["patches", "general", "disk", "load"]) assert.equal(pve.health[k], "unknown");
  const vm = m.nodes.find((n) => n.id === "vm101");
  assert.equal(vm.health.patches, "ok");
  assert.equal(vm.health.disk, "unknown");
});

test("HealthOnUnmanagedNodesIsDropped", () => {
  const raw = loadValid();
  raw.nodes[4].health = { patches: "ok" };
  const m = validateModel(raw);
  assert.equal(m.nodes[4].health, null);
});

test("OutputContainsOnlyKnownFields", () => {
  const m = validateModel(loadValid());
  assert.deepEqual(Object.keys(m).sort(), ["links", "nodes", "truncated", "window", "zones"]);
  assert.deepEqual(Object.keys(m.nodes[0]).sort(), ["health", "host", "id", "kind", "label", "os", "resources", "software", "zone"]);
});

const rejections = [
  ["not an object", (m) => Object.assign(m, { nodes: "x" }), "model.nodes"],
  ["wrong type", (m) => (m.type = "other"), "model.type"],
  ["wrong version", (m) => (m.version = 2), "model.version"],
  ["unknown window", (m) => (m.window = "1y"), "model.window"],
  ["unknown top-level field", (m) => (m.extra = 1), "model"],
  ["unknown node field", (m) => (m.nodes[1].html = "<b>"), "model.nodes[1]"],
  ["prototype key", (m) => Object.defineProperty(m.nodes[1], "__proto__", { value: {}, enumerable: true }), "model.nodes[1]"],
  ["control character in label", (m) => (m.nodes[1].label = "a\u0007b"), "label"],
  ["newline in label", (m) => (m.nodes[1].label = "a\nb"), "label"],
  ["bidi override in label", (m) => (m.nodes[1].label = "abc‮def"), "label"],
  ["zero-width in label", (m) => (m.nodes[1].label = "a​b"), "label"],
  ["lone surrogate in label", (m) => (m.nodes[1].label = "a\ud800b"), "label"],
  ["empty label", (m) => (m.nodes[1].label = ""), "label"],
  ["label too long", (m) => (m.nodes[1].label = "x".repeat(LIMITS.labelLength + 1)), "label"],
  ["label not a string", (m) => (m.nodes[1].label = 5), "label"],
  ["invalid id", (m) => (m.nodes[1].id = "a b"), "id"],
  ["id too long", (m) => (m.nodes[1].id = "a".repeat(LIMITS.idLength + 1)), "id"],
  ["duplicate node", (m) => m.nodes.push({ ...m.nodes[5] }), "duplicate"],
  ["duplicate zone", (m) => m.zones.push({ ...m.zones[0] }), "duplicate"],
  ["unknown zone", (m) => (m.nodes[1].zone = "vlan99"), "zone"],
  ["router with zone", (m) => (m.nodes[0].zone = "vlan10"), "zone"],
  ["node without zone", (m) => (m.nodes[1].zone = null), "zone"],
  ["two routers", (m) => m.nodes.push({ id: "gw2", label: "gw2", kind: "router", zone: null }), "router"],
  ["unknown kind", (m) => (m.nodes[1].kind = "server"), "kind"],
  ["bad color", (m) => (m.zones[0].color = "red; background:url(x)"), "color"],
  ["upper-case color", (m) => (m.zones[0].color = "#ABCDEF"), "color"],
  ["bad health state", (m) => (m.nodes[1].health.patches = "green"), "patches"],
  ["bad health flag", (m) => (m.nodes[1].health.unreachable = "yes"), "unreachable"],
  ["negative vcpu", (m) => (m.nodes[1].resources.vcpu = -1), "vcpu"],
  ["NaN ram", (m) => (m.nodes[1].resources.ramMiB = NaN), "ramMiB"],
  ["fractional gpus", (m) => (m.nodes[1].resources.gpus = 0.5), "gpus"],
  ["huge vcpu", (m) => (m.nodes[1].resources.vcpu = LIMITS.vcpu + 1), "vcpu"],
  ["unknown host", (m) => (m.nodes[2].host = "pve9"), "host"],
  ["self host", (m) => (m.nodes[2].host = "vm101"), "host"],
  ["bad os key", (m) => (m.nodes[1].os = "Debian Linux"), "os"],
  ["bad software key", (m) => (m.nodes[1].software[0].key = "../x"), "key"],
  ["nested children too deep", (m) => (m.nodes[1].software[0].children[0].children = []), "children"],
  ["too much software", (m) => (m.nodes[1].software = Array.from({ length: LIMITS.softwarePerNode + 1 }, () => ({ key: "x", count: 1 }))), "software"],
  ["link to unknown node", (m) => (m.links[0].b = "ghost"), "model.links[0].b"],
  ["link to itself", (m) => (m.links[0].b = m.links[0].a), "model.links[0]"],
  ["unknown via", (m) => (m.links[1].via = "ghost"), "via"],
  ["negative bytes", (m) => (m.links[0].bytesAB = -5), "bytesAB"],
  ["infinite bytes", (m) => (m.links[0].bytesBA = Infinity), "bytesBA"],
  ["port out of range", (m) => (m.links[0].port = 70000), "port"],
  ["unknown protocol", (m) => (m.links[0].proto = "sctp"), "proto"],
  ["truncated not bool", (m) => (m.truncated = "no"), "truncated"],
  ["too many zones", (m) => (m.zones = Array.from({ length: LIMITS.zones + 1 }, (_, i) => ({ id: "z" + i, name: "z", color: "#000000" }))), "zones"],
  ["too many links", (m) => (m.links = new Array(LIMITS.links + 1).fill(m.links[0])), "links"],
];

for (const [name, mutate, path] of rejections) {
  test("RejectsModel: " + name, () => rejects(mutate, path));
}

test("RejectsNonObjects", () => {
  for (const v of [null, undefined, 1, "x", [], new Date()]) {
    assert.throws(() => validateModel(v), ValidationError);
  }
});

test("ErrorsNeverEchoInputValues", () => {
  const m = loadValid();
  m.nodes[1].label = "<img src=x onerror=alert(1)>\u0007";
  m.nodes[2].os = "SECRET-VALUE";
  try {
    validateModel(m);
    assert.fail("expected rejection");
  } catch (err) {
    assert.ok(err instanceof ValidationError);
    assert.ok(!err.message.includes("onerror"));
    assert.ok(!err.message.includes("SECRET-VALUE"));
  }
});

test("ErrorListIsBounded", () => {
  const m = loadValid();
  m.links = m.links.map((l) => ({ ...l, b: "ghost" }));
  m.links = m.links.concat(m.links, m.links, m.links);
  try {
    validateModel(m);
    assert.fail("expected rejection");
  } catch (err) {
    assert.ok(err.errors.length <= LIMITS.errors);
  }
});

test("ValidatesIcons", () => {
  class FakeBitmap {
    constructor(w, h) {
      this.width = w;
      this.height = h;
    }
  }
  const isBitmap = (b) => b instanceof FakeBitmap;
  const icons = validateIcons({ type: MSG_ICONS, icons: { debian: new FakeBitmap(64, 64) } }, isBitmap);
  assert.equal(icons.get("debian").width, 64);
  assert.throws(() => validateIcons({ type: MSG_ICONS, icons: { debian: "https://example.org/x.png" } }, isBitmap), ValidationError);
  assert.throws(() => validateIcons({ type: MSG_ICONS, icons: { "Bad Key": new FakeBitmap(64, 64) } }, isBitmap), ValidationError);
  assert.throws(() => validateIcons({ type: MSG_ICONS, icons: { big: new FakeBitmap(4096, 64) } }, isBitmap), ValidationError);
  assert.throws(() => validateIcons({ type: "x", icons: {} }, isBitmap), ValidationError);
  assert.throws(() => validateIcons({ type: MSG_ICONS, icons: [] }, isBitmap), ValidationError);
});

test("ValidatesFocus", () => {
  assert.equal(validateFocus({ type: MSG_FOCUS, id: "vm101" }), "vm101");
  assert.equal(validateFocus({ type: MSG_FOCUS, id: null }), null);
  assert.throws(() => validateFocus({ type: MSG_FOCUS, id: "a b" }), ValidationError);
  assert.throws(() => validateFocus({ type: MSG_FOCUS }), ValidationError);
});
