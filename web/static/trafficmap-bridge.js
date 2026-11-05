// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Parent side of the traffic map (ADR 0009 D4, TM19), loaded by the page
// GET /traffic (internal/web/ui/trafficmap).
//
// It fetches the bounded model from /api/v1/trafficmap and the icons from
// /icons/<sha256>.png, decodes the icons to ImageBitmaps, converts the
// model to the renderer's message schema (web/static/trafficmap/model.js)
// and posts both to the renderer iframe. Everything in the model comes
// from managed hosts or observed devices and is untrusted: it is checked
// and bounded here, checked again by the renderer, and only ever set with
// textContent. There is no innerHTML anywhere.
//
// Messaging. The iframe is sandboxed with allow-scripts only, so its
// origin is opaque and serializes as "null":
//   - incoming messages are accepted only when ev.source is the iframe's
//     current window AND ev.origin is "null"; then the shape is checked
//     strictly (type, exact keys, node id syntax, id in the current model);
//   - outgoing messages go only to the iframe's window. The target origin
//     must be "*" because an opaque origin cannot be named. Nothing is sent
//     before the renderer in that window announced "ready" (with origin
//     "null"). The window cannot hold a foreign document: the page's CSP
//     (frame-src via default-src 'self') blocks cross-origin navigations
//     of the iframe, and the iframe has no allow-top-navigation or popups.
//
// Navigation. A node id coming back from the iframe is looked up in the
// parent's own copy of the model; the target is built from a fixed path
// and the encoded id: host nodes open /hosts/<id>, asset nodes
// /network/a/<id>, other nodes the focus view /traffic?window=..&focus=<id>.
// Nothing from a message is ever used as a URL.
"use strict";

const NOSTrafficMapBridge = (() => {
  /** Message types (web/static/trafficmap/model.js and bridge.js). */
  const MSG = Object.freeze({
    model: "nos.trafficmap.model",
    icons: "nos.trafficmap.icons",
    focus: "nos.trafficmap.focus",
    ready: "nos.trafficmap.ready",
    backend: "nos.trafficmap.backend",
    select: "nos.trafficmap.select",
    open: "nos.trafficmap.open",
    error: "nos.trafficmap.error",
  });

  /** Limits; the renderer's LIMITS are the upper bound of each. */
  const LIMITS = Object.freeze({
    modelBytes: 4 << 20, // the API's MaxResponseBytes
    zones: 256,
    nodes: 4000,
    links: 20000,
    idLength: 128,
    labelLength: 128,
    softwarePerNode: 32,
    icons: 512,
    iconBytes: 512 << 10,
    iconPixels: 256,
    iconFetches: 4,
    vcpu: 4096,
    ramMiB: 64 * 1024 * 1024,
    gpus: 64,
    count: 1e12,
    errors: 20,
    backendName: 32,
  });

  const WINDOWS = Object.freeze(["1h", "24h", "7d", "21d"]);
  const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
  const KEY_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
  const SHA_RE = /^[0-9a-f]{64}$/;
  const BACKEND_RE = /^[a-z0-9 ()]+$/;
  // Same set as the renderer's UNPRINTABLE_RE: controls, line/paragraph
  // separators, bidi embeddings/overrides/isolates, zero-width and BOM.
  const UNPRINTABLE_RE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]/g;
  const PROTOCOLS = ["tcp", "udp", "icmp"];
  const ZONE_COLORS = ["#4fa3ff", "#ffb347", "#9b6bff", "#4fd1a5", "#ff6b8b", "#f2d95c", "#5ce1f2", "#c48bff", "#8fd16a", "#ff8f5c", "#6b8bff", "#e07bd8"];
  /** API node kind → renderer kind. */
  const KINDS = Object.freeze({ router: "router", host: "managed", guest: "guest", container: "guest", asset: "asset", endpoint: "observed", unknown: "observed" });
  const KIND_TEXT = Object.freeze({ router: "Router", host: "Managed host", guest: "Guest", container: "Container", asset: "Asset", endpoint: "Observed endpoint", unknown: "Unknown node" });
  const UNZONED = "unzoned";

  const isPlain = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
  const isID = (v) => typeof v === "string" && v.length > 0 && v.length <= LIMITS.idLength && ID_RE.test(v);
  const isCount = (v, max) => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max;
  const arr = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);

  /** cleanText returns printable, well-formed text of at most max UTF-16 units, or fallback. */
  function cleanText(v, max, fallback) {
    if (typeof v !== "string") return fallback;
    // Bound the work on hostile input before looking at characters.
    const chars = [];
    let len = 0;
    for (const ch of v.slice(0, 4 * max).replace(UNPRINTABLE_RE, "")) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xd800 && cp <= 0xdfff) continue; // lone surrogate
      chars.push(ch);
      len += ch.length;
    }
    let cut = v.length > 4 * max;
    while (len > max || (cut && len > max - 1)) {
      len -= chars.pop().length;
      cut = true;
    }
    const s = (chars.join("") + (cut ? "…" : "")).trim();
    return s === "" || s === "…" ? fallback : s;
  }

  // zoneColor picks a stable color per zone id (FNV-1a), so colors do not
  // move between visits or windows.
  function zoneColor(id) {
    let h = 0x811c9dc5;
    for (let i = 0; i < id.length; i++) {
      h ^= id.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ZONE_COLORS[h % ZONE_COLORS.length];
  }

  const known = (v) => v !== null && v !== undefined;

  function level(v, warn, crit) {
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0) return "unknown";
    if (v >= crit) return "crit";
    if (v >= warn) return "warn";
    return "ok";
  }

  // health maps the API's values to the renderer's spikes. A value that is
  // not known stays "unknown"; it is never drawn as healthy.
  function health(h, vcpu) {
    h = isPlain(h) ? h : {};
    const patches = { current: "ok", pending: "warn", critical: "crit" }[h.patches] || "unknown";
    let general = "unknown";
    const bad = h.reachable === false || h.host_key_mismatch === true;
    const warn = (isCount(h.failed_units, 1e9) && h.failed_units > 0) || h.backup_fresh === false;
    if (bad) general = "crit";
    else if (warn) general = "warn";
    else if (h.reachable === true && h.failed_units === 0 && h.backup_fresh === true) general = "ok";
    const disk = level(h.disk_used_pct, 80, 90);
    const load = known(vcpu) && vcpu > 0 && typeof h.load === "number" ? level(h.load / vcpu, 0.7, 1.0) : "unknown";
    return { patches, general, disk, load, unreachable: h.reachable === false, hostKeyMismatch: h.host_key_mismatch === true };
  }

  /**
   * convertModel turns an API model (internal/web/api/trafficmap.Model)
   * into the renderer's model message. It never throws on hostile input:
   * invalid entries are dropped and counted in result.dropped. The result
   * also returns the facts the page shows and the parent's node index.
   */
  function convertModel(api) {
    if (!isPlain(api)) throw new Error("model: not an object");
    if (!WINDOWS.includes(api.window)) throw new Error("model: unsupported window");
    let dropped = 0;

    const zones = [];
    const zoneIDs = new Set();
    for (const z of arr(api.zones, LIMITS.zones)) {
      if (!isPlain(z) || !isID(z.id) || zoneIDs.has(z.id)) {
        dropped++;
        continue;
      }
      zoneIDs.add(z.id);
      zones.push({ id: z.id, name: cleanText(z.name, LIMITS.labelLength, z.id), color: zoneColor(z.id) });
    }
    if (Array.isArray(api.zones) && api.zones.length > LIMITS.zones) dropped += api.zones.length - LIMITS.zones;

    // A synthetic zone holds nodes the API placed in no zone (the renderer
    // requires one for every node but the router).
    let unzoned = UNZONED;
    for (let i = 2; zoneIDs.has(unzoned); i++) unzoned = UNZONED + "-" + i;

    const nodes = [];
    const index = new Map(); // id → { kind (API), label }
    const seen = new Set();
    const dup = new Set();
    const rawNodes = arr(api.nodes, LIMITS.nodes);
    for (const n of rawNodes) {
      if (isPlain(n) && isID(n.id)) {
        if (seen.has(n.id)) dup.add(n.id);
        seen.add(n.id);
      }
    }
    let router = false;
    let needUnzoned = false;
    for (const n of rawNodes) {
      if (!isPlain(n) || !isID(n.id) || dup.has(n.id)) {
        dropped++;
        continue;
      }
      const apiKind = Object.prototype.hasOwnProperty.call(KINDS, n.kind) ? n.kind : "unknown";
      let kind = KINDS[apiKind];
      if (kind === "router") {
        // The renderer draws one router at the centre; further hops are
        // drawn as assets in their zone.
        if (router) kind = "asset";
        router = true;
      }
      let zone = null;
      if (kind !== "router") {
        if (isID(n.zone) && zoneIDs.has(n.zone)) {
          zone = n.zone;
        } else {
          zone = unzoned;
          needUnzoned = true;
        }
      }
      const label = cleanText(n.label, LIMITS.labelLength, n.id);
      const out = { id: n.id, label, kind, zone };
      const r = isPlain(n.resources) ? n.resources : {};
      const res = {};
      if (isCount(r.vcpu, LIMITS.vcpu)) res.vcpu = r.vcpu;
      if (isCount(r.ram_mib, LIMITS.ramMiB)) res.ramMiB = r.ram_mib;
      if (isCount(r.gpus, LIMITS.gpus)) res.gpus = r.gpus;
      if (Object.keys(res).length > 0) out.resources = res;
      if (kind === "managed" || kind === "guest") out.health = health(n.health, res.vcpu);
      const software = [];
      const keys = new Set();
      for (const s of arr(n.software, LIMITS.softwarePerNode)) {
        if (!isPlain(s) || typeof s.key !== "string" || !KEY_RE.test(s.key) || keys.has(s.key) || !isCount(s.count, LIMITS.count)) continue;
        keys.add(s.key);
        software.push({ key: s.key, count: s.count });
      }
      if (software.length > 0) out.software = software;
      nodes.push(out);
      index.set(n.id, { kind: apiKind, label, software: arr(n.software, LIMITS.softwarePerNode) });
    }
    if (Array.isArray(api.nodes) && api.nodes.length > LIMITS.nodes) dropped += api.nodes.length - LIMITS.nodes;
    if (needUnzoned) {
      if (zones.length >= LIMITS.zones) {
        // No room for the synthetic zone: leave the unzoned nodes out.
        for (let i = nodes.length - 1; i >= 0; i--) {
          if (nodes[i].zone === unzoned) {
            index.delete(nodes[i].id);
            nodes.splice(i, 1);
            dropped++;
          }
        }
      } else {
        zones.push({ id: unzoned, name: "No zone", color: "#8a8f98" });
      }
    }

    const links = [];
    for (const e of arr(api.edges, LIMITS.links)) {
      if (!isPlain(e) || !index.has(e.a) || !index.has(e.b) || e.a === e.b ||
        !isCount(e.bytes_ab, Number.MAX_SAFE_INTEGER) || !isCount(e.bytes_ba, Number.MAX_SAFE_INTEGER)) {
        dropped++;
        continue;
      }
      const l = { a: e.a, b: e.b, bytesAB: e.bytes_ab, bytesBA: e.bytes_ba };
      const svc = Array.isArray(e.services) && isPlain(e.services[0]) ? e.services[0] : null;
      if (svc) {
        l.proto = PROTOCOLS.includes(svc.proto) ? svc.proto : "other";
        if (isCount(svc.port, 65535)) l.port = svc.port;
      }
      if (isCount(e.connections, Number.MAX_SAFE_INTEGER)) l.count = Math.min(e.connections, LIMITS.count);
      const via = Array.isArray(e.via) ? e.via.find((v) => index.has(v)) : undefined;
      if (via !== undefined) l.via = via;
      links.push(l);
    }
    if (Array.isArray(api.edges) && api.edges.length > LIMITS.links) dropped += api.edges.length - LIMITS.links;

    const omitted = {};
    if (isPlain(api.omitted)) {
      for (const k of ["zones", "nodes", "edges", "zone_links", "software", "addresses", "flows"]) {
        if (isCount(api.omitted[k], Number.MAX_SAFE_INTEGER) && api.omitted[k] > 0) omitted[k] = api.omitted[k];
      }
    }
    return {
      message: { type: MSG.model, version: 1, window: api.window, truncated: api.truncated === true || dropped > 0, zones, nodes, links },
      index,
      facts: {
        window: api.window,
        focus: isID(api.focus) ? api.focus : "",
        truncated: api.truncated === true,
        omitted,
        dropped,
        unmapped: isCount(api.unmapped_flows, Number.MAX_SAFE_INTEGER) ? api.unmapped_flows : 0,
        lowerBound: api.lower_bound === true,
        nodes: nodes.length,
        links: links.length,
      },
    };
  }

  /**
   * iconRefs lists the icons to load: catalog key → icon hash, first
   * valid hash per key, at most LIMITS.icons.
   */
  function iconRefs(index) {
    const out = new Map();
    for (const n of index.values()) {
      for (const s of n.software) {
        if (out.size >= LIMITS.icons) return out;
        if (!isPlain(s) || typeof s.key !== "string" || !KEY_RE.test(s.key) || out.has(s.key)) continue;
        if (typeof s.icon === "string" && SHA_RE.test(s.icon)) out.set(s.key, s.icon);
      }
    }
    return out;
  }

  /**
   * acceptFrameMessage checks one MessageEvent from the renderer. It
   * returns null for anything that is not a valid message of the current
   * iframe, else { type, ...fields }. index is the current node index;
   * select and open must name a node in it.
   */
  function acceptFrameMessage(ev, frameWin, index) {
    if (!ev || !frameWin || ev.source !== frameWin || ev.origin !== "null") return null;
    const d = ev.data;
    if (!isPlain(d) || typeof d.type !== "string") return null;
    const keys = Object.keys(d).sort().join(",");
    switch (d.type) {
      case MSG.ready:
        return keys === "type" ? { type: d.type } : null;
      case MSG.backend:
        if (keys !== "backend,fallback,type" || typeof d.fallback !== "boolean") return null;
        if (typeof d.backend !== "string" || d.backend.length === 0 || d.backend.length > LIMITS.backendName || !BACKEND_RE.test(d.backend)) return null;
        return { type: d.type, backend: d.backend, fallback: d.fallback };
      case MSG.select:
        if (keys !== "id,type") return null;
        if (d.id === null) return { type: d.type, id: null };
        return isID(d.id) && index && index.has(d.id) ? { type: d.type, id: d.id } : null;
      case MSG.open:
        if (keys !== "id,type") return null;
        return isID(d.id) && index && index.has(d.id) ? { type: d.type, id: d.id } : null;
      case MSG.error:
        if (keys !== "errors,type" || !Array.isArray(d.errors) || d.errors.length > LIMITS.errors) return null;
        return { type: d.type, count: d.errors.length };
      default:
        return null;
    }
  }

  /** focusHref is the focus view of a node in a window. */
  function focusHref(span, id) {
    return "/traffic?window=" + encodeURIComponent(span) + "&focus=" + encodeURIComponent(id);
  }

  /**
   * pageFor returns the page a node opens, { href, text }, or null when the
   * node has no page of its own. href is always a same-origin path.
   */
  function pageFor(kind, id) {
    if (!isID(id)) return null;
    if (kind === "host") return { href: "/hosts/" + encodeURIComponent(id), text: "Open host page" };
    if (kind === "asset") return { href: "/network/a/" + encodeURIComponent(id), text: "Open asset page" };
    return null;
  }

  /** openTarget is where double-clicking a node goes. */
  function openTarget(index, span, id) {
    const n = isID(id) && index ? index.get(id) : undefined;
    if (!n || !WINDOWS.includes(span)) return null;
    const p = pageFor(n.kind, id);
    return p ? p.href : focusHref(span, id);
  }

  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);

  /** summaryTexts returns the texts of the page's info lines. */
  function summaryTexts(facts) {
    const out = {
      summary: plural(facts.nodes, "node", "nodes") + " and " + plural(facts.links, "connection", "connections") + " in the last " + facts.window +
        (facts.focus ? " (top connections of one node)" : "") + (facts.lowerBound ? "; byte counts are lower bounds" : "") + ".",
      unmapped: "",
      truncated: "",
    };
    // Flows to peers outside the inventory are not a cap: a neutral note.
    if (facts.unmapped > 0) out.unmapped = plural(facts.unmapped, "flow goes", "flows go") + " to peers outside the inventory and " + (facts.unmapped === 1 ? "is" : "are") + " not drawn.";
    if (facts.truncated || facts.dropped > 0) {
      const parts = Object.entries(facts.omitted).map(([k, v]) => v + " " + k.replace("_", " "));
      if (facts.dropped > 0) parts.push(facts.dropped + " invalid entries");
      out.truncated = "The map is incomplete" + (parts.length > 0 ? ": left out " + parts.join(", ") : "") + ".";
    }
    return out;
  }

  function setText(el, text) {
    if (!el) return;
    el.textContent = text;
    el.hidden = text === "";
  }

  async function fetchModel(fetchFn, span, focus) {
    let url = "/api/v1/trafficmap?window=" + encodeURIComponent(span);
    if (focus) url += "&focus=" + encodeURIComponent(focus);
    const res = await fetchFn(url, { credentials: "same-origin", headers: { Accept: "application/json" }, redirect: "error", cache: "no-store" });
    if (!res.ok) throw new Error("the server answered " + res.status);
    const ct = (res.headers.get("Content-Type") || "").split(";")[0].trim();
    if (ct !== "application/json") throw new Error("unexpected content type");
    const len = Number(res.headers.get("Content-Length"));
    if (len > LIMITS.modelBytes) throw new Error("model too large");
    const text = await res.text();
    if (text.length > LIMITS.modelBytes) throw new Error("model too large");
    return JSON.parse(text);
  }

  // loadIcon fetches and decodes one icon; it resolves to null on any
  // problem (the renderer then draws the generic symbol).
  async function loadIcon(env, sha) {
    try {
      const res = await env.fetch("/icons/" + sha + ".png", { credentials: "same-origin", redirect: "error" });
      if (!res.ok) return null;
      if ((res.headers.get("Content-Type") || "").split(";")[0].trim() !== "image/png") return null;
      if (Number(res.headers.get("Content-Length")) > LIMITS.iconBytes) return null;
      const blob = await res.blob();
      if (blob.size > LIMITS.iconBytes) return null;
      let bmp = await env.createImageBitmap(blob);
      if (bmp.width > LIMITS.iconPixels || bmp.height > LIMITS.iconPixels) {
        const scale = LIMITS.iconPixels / Math.max(bmp.width, bmp.height);
        const small = await env.createImageBitmap(bmp, {
          resizeWidth: Math.max(1, Math.floor(bmp.width * scale)),
          resizeHeight: Math.max(1, Math.floor(bmp.height * scale)),
          resizeQuality: "high",
        });
        bmp.close();
        bmp = small;
      }
      if (!(bmp.width > 0 && bmp.height > 0)) {
        bmp.close();
        return null;
      }
      return bmp;
    } catch {
      return null;
    }
  }

  /** loadIcons decodes the referenced icons with bounded concurrency. */
  async function loadIcons(env, refs) {
    const out = {};
    const queue = [...refs.entries()];
    const worker = async () => {
      for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
        const bmp = await loadIcon(env, next[1]);
        if (bmp) out[next[0]] = bmp;
      }
    };
    await Promise.all(Array.from({ length: Math.min(LIMITS.iconFetches, queue.length) }, worker));
    return out;
  }

  /**
   * start wires the page. env supplies document, window, fetch,
   * createImageBitmap and navigate (location.assign) so tests can fake them.
   */
  function start(env) {
    const doc = env.document;
    const root = doc.getElementById("trafficmap-page");
    const frame = doc.getElementById("trafficmap-frame");
    if (!root || !frame) return null;
    const span = root.getAttribute("data-window");
    const focusAttr = root.getAttribute("data-focus") || "";
    const status = doc.getElementById("trafficmap-status");
    if (!WINDOWS.includes(span) || (focusAttr !== "" && !isID(focusAttr))) {
      setText(status, "The traffic map could not be loaded: invalid page parameters.");
      return null;
    }
    const focus = focusAttr;
    const el = (id) => doc.getElementById(id);

    let ready = false;
    let model = null; // converted model
    let icons = null; // key → ImageBitmap
    let backendText = "";

    const post = (msg) => {
      // Only the iframe's window, only after its renderer announced ready;
      // "*" because its sandboxed origin is opaque.
      if (ready && frame.contentWindow) frame.contentWindow.postMessage(msg, "*");
    };
    const sendAll = () => {
      if (!ready || !model) return;
      post(model.message);
      if (icons) post({ type: MSG.icons, icons });
      if (model.facts.focus) post({ type: MSG.focus, id: model.facts.focus });
    };

    const showSelection = (id) => {
      const box = el("trafficmap-selection");
      if (!box) return;
      const n = id !== null && model ? model.index.get(id) : undefined;
      if (!n) {
        box.hidden = true;
        return;
      }
      setText(el("trafficmap-selection-label"), n.label);
      setText(el("trafficmap-selection-kind"), KIND_TEXT[n.kind] || KIND_TEXT.unknown);
      const open = el("trafficmap-selection-open");
      const p = pageFor(n.kind, id);
      if (open) {
        open.hidden = !p;
        if (p) {
          open.setAttribute("href", p.href);
          open.textContent = p.text;
        } else {
          open.removeAttribute("href");
        }
      }
      const fl = el("trafficmap-selection-focus");
      if (fl) {
        fl.hidden = id === model.facts.focus;
        fl.setAttribute("href", focusHref(span, id));
      }
      box.hidden = false;
    };

    const onMessage = (ev) => {
      const m = acceptFrameMessage(ev, frame.contentWindow, model ? model.index : null);
      if (m === null) return;
      switch (m.type) {
        case MSG.ready:
          ready = true;
          sendAll();
          break;
        case MSG.backend:
          backendText = m.backend === "none" ? "This browser can draw neither WebGL2 nor Canvas 2D; the map is not shown." : "Drawn with " + m.backend + (m.fallback ? " (fallback)" : "") + ".";
          if (model) setText(status, backendText);
          break;
        case MSG.select:
          showSelection(m.id);
          break;
        case MSG.open: {
          const href = openTarget(model ? model.index : null, span, m.id);
          if (href) env.navigate(href);
          break;
        }
        case MSG.error:
          setText(status, "The renderer rejected the map data (" + plural(m.count, "problem", "problems") + ").");
          break;
      }
    };
    // There is deliberately no reset on the iframe's load event: the
    // renderer announces "ready" while its module runs, before that event
    // fires, so a reset there would drop the only "ready". A reloaded
    // renderer announces "ready" again and gets everything again.
    env.window.addEventListener("message", onMessage);

    const loaded = (async () => {
      try {
        model = convertModel(await fetchModel(env.fetch, span, focus));
      } catch (err) {
        setText(status, "The traffic map could not be loaded: " + (err && typeof err.message === "string" ? cleanText(err.message, 120, "error") : "error") + ".");
        return;
      }
      const t = summaryTexts(model.facts);
      setText(el("trafficmap-summary"), t.summary);
      setText(el("trafficmap-unmapped"), t.unmapped);
      setText(el("trafficmap-truncated"), t.truncated);
      setText(status, backendText || "Map loaded.");
      sendAll();
      icons = await loadIcons(env, iconRefs(model.index));
      if (ready && Object.keys(icons).length > 0) post({ type: MSG.icons, icons });
    })();
    return { loaded, onMessage };
  }

  return { MSG, LIMITS, convertModel, iconRefs, acceptFrameMessage, pageFor, openTarget, focusHref, summaryTexts, cleanText, start };
})();

if (typeof document !== "undefined" && typeof window !== "undefined" && typeof fetch === "function") {
  NOSTrafficMapBridge.start({
    document,
    window,
    fetch: (u, o) => fetch(u, o),
    createImageBitmap: (b, o) => (o ? createImageBitmap(b, o) : createImageBitmap(b)),
    navigate: (href) => window.location.assign(href),
  });
}
