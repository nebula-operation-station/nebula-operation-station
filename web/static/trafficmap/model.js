// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Traffic map data model and its validator (ADR 0009 D4, TM18).
//
// The renderer receives its model only through postMessage from the parent
// page. Everything in it originates from managed hosts or observed devices
// and is untrusted (spec 09): the validator accepts exactly the documented
// shape, enforces explicit limits, rejects unknown keys, malformed or
// non-printable text and dangling references, and returns a fresh, frozen
// copy that contains only known fields. Callers never use the raw input.

/** Message type of a model update sent by the parent page. */
export const MSG_MODEL = "nos.trafficmap.model";
/** Message type of an icon update (decoded ImageBitmaps) from the parent. */
export const MSG_ICONS = "nos.trafficmap.icons";
/** Message type that focuses a node (or clears focus with id null). */
export const MSG_FOCUS = "nos.trafficmap.focus";

/** Supported model schema version. */
export const MODEL_VERSION = 1;

/** Limits enforced by validateModel. */
export const LIMITS = Object.freeze({
  zones: 256,
  nodes: 4000,
  links: 20000,
  idLength: 128,
  labelLength: 128,
  softwarePerNode: 32,
  softwareChildren: 64,
  icons: 512,
  iconPixels: 256,
  vcpu: 4096,
  ramMiB: 64 * 1024 * 1024,
  gpus: 64,
  bytes: Number.MAX_SAFE_INTEGER,
  count: 1e12,
  port: 65535,
  errors: 20,
});

/** Time windows the server may report (ADR 0009 D3). */
export const WINDOWS = Object.freeze(["1h", "24h", "7d", "21d"]);
/** Node kinds. "router" marks the hop drawn at the centre. */
export const NODE_KINDS = Object.freeze(["router", "managed", "guest", "asset", "observed"]);
/** Health indicator states; "unknown" is never drawn as healthy. */
export const HEALTH_STATES = Object.freeze(["ok", "warn", "crit", "unknown"]);
/** Health indicators, one spike each (top, left, bottom, right). */
export const HEALTH_KEYS = Object.freeze(["patches", "general", "disk", "load"]);
/** Transport protocols of a link. */
export const PROTOCOLS = Object.freeze(["tcp", "udp", "icmp", "other"]);

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const KEY_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const COLOR_RE = /^#[0-9a-f]{6}$/;
// C0 and C1 controls, DEL, line/paragraph separators, bidi embeddings,
// overrides and isolates, zero-width and BOM characters.
const UNPRINTABLE_RE = /[\u0000-\u001f\u007f-\u009f  ‪-‮⁦-⁩​-‏﻿]/;

/** ValidationError carries the list of problems found in a message. */
export class ValidationError extends Error {
  constructor(errors) {
    super("invalid traffic map model: " + errors.join("; "));
    this.name = "ValidationError";
    this.errors = errors;
  }
}

class Checker {
  constructor() {
    this.errors = [];
  }

  fail(path, msg) {
    if (this.errors.length < LIMITS.errors) {
      // Only the path and a fixed message: never echo untrusted values.
      this.errors.push(path + ": " + msg);
    }
    return undefined;
  }

  object(v, path, required, optional = []) {
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      return this.fail(path, "must be an object");
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) {
      return this.fail(path, "must be a plain object");
    }
    const keys = Object.keys(v);
    for (const k of keys) {
      if (!required.includes(k) && !optional.includes(k)) {
        this.fail(path, "unknown field");
        return undefined;
      }
    }
    for (const k of required) {
      if (!Object.prototype.hasOwnProperty.call(v, k)) {
        this.fail(path + "." + k, "is required");
        return undefined;
      }
    }
    return v;
  }

  has(v, k) {
    return Object.prototype.hasOwnProperty.call(v, k);
  }

  array(v, path, max) {
    if (!Array.isArray(v)) return this.fail(path, "must be an array");
    if (v.length > max) return this.fail(path, "too many entries");
    return v;
  }

  text(v, path, max) {
    if (typeof v !== "string") return this.fail(path, "must be a string");
    if (v.length === 0) return this.fail(path, "must not be empty");
    if (v.length > max) return this.fail(path, "too long");
    if (!isWellFormed(v)) return this.fail(path, "is not valid UTF-16/UTF-8 text");
    if (UNPRINTABLE_RE.test(v)) return this.fail(path, "contains unprintable characters");
    return v;
  }

  id(v, path) {
    const s = this.text(v, path, LIMITS.idLength);
    if (s === undefined) return undefined;
    if (!ID_RE.test(s)) return this.fail(path, "is not a valid identifier");
    return s;
  }

  key(v, path) {
    if (typeof v !== "string" || !KEY_RE.test(v)) return this.fail(path, "is not a valid catalog key");
    return v;
  }

  oneOf(v, path, allowed) {
    if (typeof v !== "string" || !allowed.includes(v)) return this.fail(path, "has an unsupported value");
    return v;
  }

  number(v, path, max, integer = true) {
    if (typeof v !== "number" || !Number.isFinite(v)) return this.fail(path, "must be a finite number");
    if (integer && !Number.isInteger(v)) return this.fail(path, "must be an integer");
    if (v < 0 || v > max) return this.fail(path, "is out of range");
    return v;
  }

  bool(v, path) {
    if (typeof v !== "boolean") return this.fail(path, "must be a boolean");
    return v;
  }
}

function isWellFormed(s) {
  if (typeof s.isWellFormed === "function") return s.isWellFormed();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function deepFreeze(o) {
  if (o && typeof o === "object" && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

function checkZone(c, raw, path) {
  const z = c.object(raw, path, ["id", "name", "color"]);
  if (!z) return undefined;
  const id = c.id(z.id, path + ".id");
  const name = c.text(z.name, path + ".name", LIMITS.labelLength);
  let color;
  if (typeof z.color !== "string" || !COLOR_RE.test(z.color)) {
    c.fail(path + ".color", "must be #rrggbb in lower case");
  } else {
    color = z.color;
  }
  if (id === undefined || name === undefined || color === undefined) return undefined;
  return { id, name, color };
}

function checkResources(c, raw, path) {
  const r = c.object(raw, path, [], ["vcpu", "ramMiB", "gpus"]);
  if (!r) return undefined;
  const out = { vcpu: 0, ramMiB: 0, gpus: 0 };
  if (c.has(r, "vcpu")) out.vcpu = c.number(r.vcpu, path + ".vcpu", LIMITS.vcpu);
  if (c.has(r, "ramMiB")) out.ramMiB = c.number(r.ramMiB, path + ".ramMiB", LIMITS.ramMiB);
  if (c.has(r, "gpus")) out.gpus = c.number(r.gpus, path + ".gpus", LIMITS.gpus);
  if (out.vcpu === undefined || out.ramMiB === undefined || out.gpus === undefined) return undefined;
  return out;
}

function unknownHealth() {
  const h = { unreachable: false, hostKeyMismatch: false };
  for (const k of HEALTH_KEYS) h[k] = "unknown";
  return h;
}

function checkHealth(c, raw, path) {
  const h = c.object(raw, path, [], [...HEALTH_KEYS, "unreachable", "hostKeyMismatch"]);
  if (!h) return undefined;
  const out = unknownHealth();
  let ok = true;
  for (const k of HEALTH_KEYS) {
    if (c.has(h, k)) {
      out[k] = c.oneOf(h[k], path + "." + k, HEALTH_STATES);
      if (out[k] === undefined) ok = false;
    }
  }
  for (const k of ["unreachable", "hostKeyMismatch"]) {
    if (c.has(h, k)) {
      out[k] = c.bool(h[k], path + "." + k);
      if (out[k] === undefined) ok = false;
    }
  }
  return ok ? out : undefined;
}

function checkSoftware(c, raw, path, max, allowChildren) {
  const list = c.array(raw, path, max);
  if (!list) return undefined;
  const out = [];
  for (let i = 0; i < list.length; i++) {
    const p = path + "[" + i + "]";
    const s = c.object(list[i], p, ["key", "count"], allowChildren ? ["children"] : []);
    if (!s) return undefined;
    const key = c.key(s.key, p + ".key");
    const count = c.number(s.count, p + ".count", LIMITS.count);
    let children = [];
    if (allowChildren && c.has(s, "children")) {
      children = checkSoftware(c, s.children, p + ".children", LIMITS.softwareChildren, false);
    }
    if (key === undefined || count === undefined || children === undefined) return undefined;
    out.push(allowChildren ? { key, count, children } : { key, count });
  }
  return out;
}

function checkNode(c, raw, path) {
  const n = c.object(raw, path, ["id", "label", "kind", "zone"], ["resources", "os", "host", "health", "software"]);
  if (!n) return undefined;
  const id = c.id(n.id, path + ".id");
  const label = c.text(n.label, path + ".label", LIMITS.labelLength);
  const kind = c.oneOf(n.kind, path + ".kind", NODE_KINDS);
  const zone = n.zone === null ? null : c.id(n.zone, path + ".zone");
  const resources = c.has(n, "resources") ? checkResources(c, n.resources, path + ".resources") : { vcpu: 0, ramMiB: 0, gpus: 0 };
  const os = c.has(n, "os") ? c.key(n.os, path + ".os") : null;
  const host = c.has(n, "host") ? c.id(n.host, path + ".host") : null;
  const health = c.has(n, "health") ? checkHealth(c, n.health, path + ".health") : null;
  const software = c.has(n, "software") ? checkSoftware(c, n.software, path + ".software", LIMITS.softwarePerNode, true) : [];
  if ([id, label, kind, zone, resources, os, host, health, software].includes(undefined)) return undefined;
  if (kind === "router" && zone !== null) return c.fail(path + ".zone", "must be null for the router");
  if (kind !== "router" && zone === null) return c.fail(path + ".zone", "is required");
  // Health is only meaningful for managed nodes and guests; for every other
  // kind it is dropped rather than drawn.
  const managed = kind === "managed" || kind === "guest";
  return { id, label, kind, zone, resources, os, host, health: managed ? health || unknownHealth() : null, software };
}

function checkLink(c, raw, path) {
  const l = c.object(raw, path, ["a", "b", "bytesAB", "bytesBA"], ["proto", "port", "count", "via"]);
  if (!l) return undefined;
  const a = c.id(l.a, path + ".a");
  const b = c.id(l.b, path + ".b");
  const bytesAB = c.number(l.bytesAB, path + ".bytesAB", LIMITS.bytes);
  const bytesBA = c.number(l.bytesBA, path + ".bytesBA", LIMITS.bytes);
  const proto = c.has(l, "proto") ? c.oneOf(l.proto, path + ".proto", PROTOCOLS) : "other";
  const port = c.has(l, "port") ? c.number(l.port, path + ".port", LIMITS.port) : 0;
  const count = c.has(l, "count") ? c.number(l.count, path + ".count", LIMITS.count) : 0;
  const via = c.has(l, "via") ? c.id(l.via, path + ".via") : null;
  if ([a, b, bytesAB, bytesBA, proto, port, count, via].includes(undefined)) return undefined;
  if (a === b) return c.fail(path, "must connect two different nodes");
  return { a, b, bytesAB, bytesBA, proto, port, count, via };
}

/**
 * validateModel checks a model message and returns a frozen copy that holds
 * only known fields. It throws ValidationError listing at most LIMITS.errors
 * problems; messages contain field paths only, never input values.
 */
export function validateModel(raw) {
  const c = new Checker();
  const m = c.object(raw, "model", ["type", "version", "window", "truncated", "zones", "nodes", "links"]);
  if (!m) throw new ValidationError(c.errors);
  if (m.type !== MSG_MODEL) c.fail("model.type", "has an unsupported value");
  if (m.version !== MODEL_VERSION) c.fail("model.version", "is not supported");
  const window = c.oneOf(m.window, "model.window", WINDOWS);
  const truncated = c.bool(m.truncated, "model.truncated");
  const zonesRaw = c.array(m.zones, "model.zones", LIMITS.zones);
  const nodesRaw = c.array(m.nodes, "model.nodes", LIMITS.nodes);
  const linksRaw = c.array(m.links, "model.links", LIMITS.links);
  if (c.errors.length > 0) throw new ValidationError(c.errors);

  const zones = [];
  const zoneIds = new Set();
  zonesRaw.forEach((z, i) => {
    const v = checkZone(c, z, "model.zones[" + i + "]");
    if (!v) return;
    if (zoneIds.has(v.id)) {
      c.fail("model.zones[" + i + "].id", "is a duplicate");
      return;
    }
    zoneIds.add(v.id);
    zones.push(v);
  });

  const nodes = [];
  const nodeIds = new Set();
  let routers = 0;
  nodesRaw.forEach((n, i) => {
    const p = "model.nodes[" + i + "]";
    const v = checkNode(c, n, p);
    if (!v) return;
    if (nodeIds.has(v.id)) {
      c.fail(p + ".id", "is a duplicate");
      return;
    }
    if (v.zone !== null && !zoneIds.has(v.zone)) c.fail(p + ".zone", "references an unknown zone");
    if (v.kind === "router") routers++;
    nodeIds.add(v.id);
    nodes.push(v);
  });
  if (routers > 1) c.fail("model.nodes", "must contain at most one router");
  nodes.forEach((n, i) => {
    if (n.host !== null && (!nodeIds.has(n.host) || n.host === n.id)) {
      c.fail("model.nodes[" + i + "].host", "references an unknown node");
    }
  });

  const links = [];
  linksRaw.forEach((l, i) => {
    const p = "model.links[" + i + "]";
    const v = checkLink(c, l, p);
    if (!v) return;
    if (!nodeIds.has(v.a)) c.fail(p + ".a", "references an unknown node");
    if (!nodeIds.has(v.b)) c.fail(p + ".b", "references an unknown node");
    if (v.via !== null && !nodeIds.has(v.via)) c.fail(p + ".via", "references an unknown node");
    links.push(v);
  });

  if (c.errors.length > 0) throw new ValidationError(c.errors);
  return deepFreeze({ window, truncated, zones, nodes, links });
}

/**
 * validateIcons checks an icon message: a map from catalog key to a decoded
 * bitmap. The bitmap check is injected (isBitmap) so the browser can use
 * instanceof ImageBitmap and tests can use a stub. Returns a frozen Map.
 */
export function validateIcons(raw, isBitmap) {
  const c = new Checker();
  const m = c.object(raw, "icons", ["type", "icons"]);
  if (!m) throw new ValidationError(c.errors);
  if (m.type !== MSG_ICONS) c.fail("icons.type", "has an unsupported value");
  const icons = c.object(m.icons, "icons.icons", Object.keys(m.icons || {}));
  if (c.errors.length > 0) throw new ValidationError(c.errors);
  const keys = Object.keys(icons);
  if (keys.length > LIMITS.icons) throw new ValidationError(["icons.icons: too many entries"]);
  const out = new Map();
  for (const k of keys) {
    const p = "icons.icons[" + out.size + "]";
    if (c.key(k, p) === undefined) continue;
    const bmp = icons[k];
    if (!isBitmap(bmp)) {
      c.fail(p, "must be an ImageBitmap");
      continue;
    }
    if (!(bmp.width > 0 && bmp.height > 0 && bmp.width <= LIMITS.iconPixels && bmp.height <= LIMITS.iconPixels)) {
      c.fail(p, "has unsupported dimensions");
      continue;
    }
    out.set(k, bmp);
  }
  if (c.errors.length > 0) throw new ValidationError(c.errors);
  return out;
}

/** validateFocus checks a focus message and returns the node id or null. */
export function validateFocus(raw) {
  const c = new Checker();
  const m = c.object(raw, "focus", ["type", "id"]);
  if (!m) throw new ValidationError(c.errors);
  if (m.type !== MSG_FOCUS) c.fail("focus.type", "has an unsupported value");
  const id = m.id === null ? null : c.id(m.id, "focus.id");
  if (c.errors.length > 0) throw new ValidationError(c.errors);
  return id;
}

/**
 * resourceWeight is the logarithmic size measure used for star size,
 * brightness and the layout order (ADR 0009 D4).
 */
export function resourceWeight(r) {
  return Math.log2(1 + r.vcpu) + Math.log2(1 + r.ramMiB / 1024) + 2 * Math.log2(1 + r.gpus);
}

/** linkVolume is the logarithmic traffic measure for beam width. */
export function linkVolume(l) {
  return Math.log10(1 + l.bytesAB + l.bytesBA);
}
