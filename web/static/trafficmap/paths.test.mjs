// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Run with: node --test web/static/trafficmap/*.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validatePaths, readPaths, drawPaths, PathsError, PATHS_LIMITS, REJECTED } from "./paths.js";

function valid() {
  return {
    version: 1,
    truncated: false,
    beams: [
      { from: "m-web", to: "m-exec", rank: 1, assumed: false, possible: false },
      { from: "m-nas", to: "m-exec", rank: 2, assumed: true, possible: true },
    ],
    marks: [
      { id: "m-exec", role: "target" },
      { id: "m-web", role: "step" },
    ],
  };
}

function rootWith(attr) {
  return { getAttribute: (k) => (k === "data-paths" ? attr : null) };
}

// recorder is a 2D context that records calls by name.
function recorder() {
  const calls = [];
  const target = { calls };
  return new Proxy(target, {
    get(t, k) {
      if (k in t) return t[k];
      return (...args) => calls.push([k, ...args]);
    },
    set() {
      return true;
    },
  });
}

// World (x, y) is drawn at (x + 100, y + 50) by this camera.
const cam = { cx: 0, cy: 0, scale: 1, fitScale: 1, width: 200, height: 100 };

test("ValidOverlayIsCopiedAndFrozen", () => {
  const raw = valid();
  const v = validatePaths(raw);
  assert.equal(v.beams.length, 2);
  assert.equal(v.rejected, false);
  assert.ok(Object.isFrozen(v) && Object.isFrozen(v.beams) && Object.isFrozen(v.beams[0]));
  raw.beams[0].from = "changed";
  assert.equal(v.beams[0].from, "m-web", "the copy is independent of the input");
});

test("MalformedOverlaysAreRejectedWithoutEchoingValues", () => {
  const cases = {
    "unknown top key": (o) => (o.labels = { x: "<script>" }),
    "unknown beam key": (o) => (o.beams[0].label = "secret"),
    "missing key": (o) => delete o.truncated,
    "bad version": (o) => (o.version = 2),
    "hostile id": (o) => (o.beams[0].from = "<img src=x onerror=alert(1)>"),
    "bidi id": (o) => (o.marks[0].id = "m" + String.fromCharCode(0x202e) + "exec"),
    "long id": (o) => (o.beams[0].to = "a".repeat(PATHS_LIMITS.idLength + 1)),
    "self loop": (o) => (o.beams[0].to = "m-web"),
    "rank zero": (o) => (o.beams[0].rank = 0),
    "rank too big": (o) => (o.beams[0].rank = PATHS_LIMITS.rank + 1),
    "rank fraction": (o) => (o.beams[0].rank = 1.5),
    "flag not bool": (o) => (o.beams[0].assumed = "yes"),
    "bad role": (o) => (o.marks[0].role = "entry"),
    "repeated mark": (o) => o.marks.push({ id: "m-exec", role: "step" }),
    "too many beams": (o) => (o.beams = Array.from({ length: PATHS_LIMITS.beams + 1 }, (_, i) => ({ from: "a" + i, to: "b", rank: 1, assumed: false, possible: false }))),
    "beams not list": (o) => (o.beams = {}),
    "proto pollution": (o) => (o.beams[0] = JSON.parse('{"__proto__":{"x":1},"from":"a","to":"b","rank":1,"assumed":false,"possible":false}')),
  };
  for (const [name, edit] of Object.entries(cases)) {
    const o = valid();
    edit(o);
    assert.throws(() => validatePaths(o), (err) => {
      assert.ok(err instanceof PathsError, name);
      assert.ok(err.errors.length > 0 && err.errors.length <= PATHS_LIMITS.errors, name);
      for (const e of err.errors) assert.ok(!/script|secret|onerror|<|aaaa/.test(e), name + " echoes input: " + e);
      return true;
    }, name);
  }
  assert.throws(() => validatePaths(null), PathsError);
  assert.throws(() => validatePaths([]), PathsError);
});

test("ReadPathsDistinguishesAbsentFromInvalid", () => {
  assert.equal(readPaths(rootWith(null)), null, "the normal map has no overlay");
  assert.equal(readPaths(null), null);
  assert.equal(readPaths(rootWith("{not json")), REJECTED);
  assert.equal(readPaths(rootWith(JSON.stringify({ ...valid(), version: 9 }))), REJECTED);
  assert.equal(readPaths(rootWith(" ".repeat(PATHS_LIMITS.bytes + 1))), REJECTED, "oversized data is not parsed");
  const v = readPaths(rootWith(JSON.stringify(valid())));
  assert.equal(v.beams.length, 2);
});

test("DrawPathsDrawsMappedBeamsTopRankLast", () => {
  const ctx = recorder();
  const pos = new Map([
    ["m-web", { x: 10, y: 10 }],
    ["m-exec", { x: 50, y: 50 }],
    ["m-nas", { x: 90, y: 10 }],
  ]);
  const out = drawPaths(ctx, cam, validatePaths(valid()), pos);
  assert.deepEqual(out, { drawn: 2, skipped: 0 });
  const moves = ctx.calls.filter((c) => c[0] === "moveTo");
  // rank 2 (from m-nas) first, rank 1 (from m-web) last, so it is on top.
  assert.deepEqual(moves[0].slice(1), [190, 60]);
  const lineStarts = moves.filter((c) => c[1] === 110 && c[2] === 60);
  assert.equal(lineStarts.length, 1, "the rank 1 beam starts at m-web");
  assert.ok(moves.indexOf(lineStarts[0]) > 0, "rank 1 is drawn after rank 2");
  assert.ok(!ctx.calls.some((c) => c[0] === "fillText"), "no text for a valid overlay");
  const dashes = ctx.calls.filter((c) => c[0] === "setLineDash").map((c) => c[1].length);
  assert.ok(dashes.includes(2), "assumed or possible beams are dashed");
});

test("DrawPathsSkipsNodesNotOnTheMap", () => {
  const ctx = recorder();
  const out = drawPaths(ctx, cam, validatePaths(valid()), new Map([["m-exec", { x: 0, y: 0 }]]));
  assert.deepEqual(out, { drawn: 0, skipped: 2 });
});

test("RejectedOverlaySaysSoWithAFixedText", () => {
  const ctx = recorder();
  drawPaths(ctx, cam, REJECTED, new Map());
  const texts = ctx.calls.filter((c) => c[0] === "fillText").map((c) => c[1]);
  assert.deepEqual(texts, ["Attack-path overlay rejected: invalid data"]);
  assert.deepEqual(drawPaths(recorder(), cam, null, new Map()), { drawn: 0, skipped: 0 });
});

test("NormalBootNeverLoadsTheOverlay", () => {
  const boot = readFileSync(new URL("./boot.js", import.meta.url), "utf8");
  assert.ok(!/paths/.test(boot), "boot.js must not read or pass an attack-path overlay");
  const pboot = readFileSync(new URL("./paths-boot.js", import.meta.url), "utf8");
  assert.ok(/readPaths\(root\) \|\| REJECTED/.test(pboot), "the overlay document never falls back to a plain map silently");
});
