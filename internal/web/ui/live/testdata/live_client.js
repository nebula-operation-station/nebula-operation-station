// SPDX-License-Identifier: AGPL-3.0-or-later
// Behavioural harness for the live block of web/static/inventory.js.
// Reads the block on stdin, runs it in a fresh vm context against a fake
// DOM, EventSource, IntersectionObserver, fetch and clock, and runs the
// scenario named in argv[2]. Exits 1 with a message on the first failed
// expectation. No network: fetch is a local fake.
'use strict';
const vm = require('vm');

const fail = (msg) => { process.stderr.write('FAIL: ' + msg + '\n'); process.exit(1); };
const expect = (cond, msg) => { if (!cond) fail(msg); };

// Fake element: just enough of the DOM the live block touches.
class El {
  constructor(className, extra) {
    this.className = className || '';
    this.children = [];
    this.parentNode = null;
    this.dataset = {};
    this.textContent = '';
    this.title = '';
    this.attrs = {};
    this.q = {};  // selector -> element (querySelector)
    this.up = {}; // selector -> element (closest)
    Object.assign(this, extra);
  }
  get classList() {
    const names = () => new Set(this.className.split(/\s+/).filter(Boolean));
    return {
      contains: (c) => names().has(c),
      toggle: (c, on) => { const s = names(); if (on) s.add(c); else s.delete(c); this.className = [...s].join(' '); },
    };
  }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter((x) => x !== this);
    this.parentNode = null;
  }
  getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; }
  querySelector(sel) { return this.q[sel] || null; }
  closest(sel) { return this.up[sel] || null; }
}

// Chart: node pve1, an unlinked guest VM 101 on it, and host web01.
const buildChart = () => {
  const nodeName = new El('chart__name', { title: 'pve1' });
  const nodeBox = new El('chart__box chart__box--node', { q: { 'a.chart__name': nodeName } });
  const nodeWrap = new El('chart__node', { q: { '.chart__box--node .chart__name': nodeName } });
  nodeBox.up['.chart__node'] = nodeWrap;
  const guestBox = new El('chart__box chart__box--guest', {
    q: { '.chart__vmid': new El('chart__vmid', { textContent: 'VM 101' }) },
    up: { '.chart__node': nodeWrap },
  });
  const hostLink = new El('chart__name', { attrs: { href: '/hosts/web01' } });
  const hostBox = new El('chart__box chart__box--host', { q: { 'a.chart__name': hostLink } });
  const boxes = [nodeBox, guestBox, hostBox];
  const chart = new El('chart');
  chart.querySelectorAll = () => boxes;
  return { chart, byId: { 'node:pve1': nodeBox, 'guest:pve1:101': guestBox, 'host:web01': hostBox } };
};

// Starts the live block in a fresh context and returns its controls.
const start = (src) => {
  let now = 1e6, seq = 0;
  const timers = new Map();
  const addTimer = (fn, ms, every) => { const id = ++seq; timers.set(id, { fn, at: now + Math.max(0, ms || 0), every }); return id; };
  const clearTimer = (id) => { timers.delete(id); };
  const { chart, byId } = buildChart();
  const listeners = {};
  const document = {
    hidden: false,
    querySelector: (sel) => (sel === '.chart' ? chart : null),
    createElement: () => new El(),
    addEventListener: (name, f) => { (listeners[name] = listeners[name] || []).push(f); },
  };
  const streams = [];
  class EventSource {
    constructor(url) { this.url = url; this.on = {}; this.closed = false; streams.push(this); }
    addEventListener(name, f) { this.on[name] = f; }
    close() { this.closed = true; }
    emit(name, data) { if (!this.closed && this.on[name]) this.on[name]({ data: JSON.stringify(data) }); }
  }
  let observe = null;
  class IntersectionObserver {
    constructor(cb) { observe = cb; this.els = []; }
    observe(el) { this.els.push(el); }
  }
  const posts = [];
  let reply = () => ({ status: 200, body: { granted: [] } });
  const fetch = async (url, init) => {
    const req = { url, body: JSON.parse(init.body) };
    posts.push(req);
    const r = reply(req);
    return { status: r.status, ok: r.status >= 200 && r.status < 300, json: async () => r.body };
  };
  const RealDate = Date;
  const FakeDate = class extends RealDate {};
  FakeDate.now = () => now;
  const window = { EventSource, IntersectionObserver, addEventListener: () => {} };
  const ctx = vm.createContext({
    document, window, EventSource, IntersectionObserver, fetch, Date: FakeDate, JSON, Math, Map, Set,
    Number, String, Object, Promise,
    setTimeout: (fn, ms) => addTimer(fn, ms, 0), clearTimeout: clearTimer,
    setInterval: (fn, ms) => addTimer(fn, ms, Math.max(1, ms || 0)), clearInterval: clearTimer,
  });
  vm.runInContext(src, ctx, { filename: 'inventory.js(live block)' });

  const flush = () => new Promise((r) => setImmediate(r));
  // advance runs every timer due within ms, in time order, settling the
  // promises each one starts.
  const advance = async (ms) => {
    const end = now + ms;
    await flush();
    for (;;) {
      let next = null;
      for (const [id, t] of timers) if (t.at <= end && (!next || t.at < next[1].at)) next = [id, t];
      if (!next) break;
      const [id, t] = next;
      now = t.at;
      if (t.every) t.at += t.every; else timers.delete(id);
      t.fn();
      for (let i = 0; i < 5; i++) await flush();
    }
    now = end;
    for (let i = 0; i < 5; i++) await flush();
  };
  const live = (id) => byId[id].children.find((c) => c.classList.contains('chart__line--live')) || null;
  const text = (id) => { const l = live(id); return l ? l.children[1].textContent : null; };
  return {
    document, streams, posts, byId, live, text, advance,
    stream: () => streams[streams.length - 1],
    reply: (f) => { reply = f; },
    see: (...ids) => observe(ids.map((id) => ({ isIntersecting: true, target: byId[id] }))),
    visibility: () => (listeners.visibilitychange || []).forEach((f) => f()),
  };
};

const ALL = ['node:pve1', 'guest:pve1:101', 'host:web01'];

// hello opens a viewer and the visible boxes are posted.
const hello = async (h, viewer) => {
  h.stream().emit('hello', { viewer, renew: 10 });
  await h.advance(0);
};

const scenarios = {
  // Node, guest and host boxes are all requested; values are rendered.
  async boxes(h) {
    expect(h.streams.length === 1 && h.stream().url === '/chart/live/events', 'one stream to /chart/live/events');
    h.see(...ALL);
    await hello(h, 'v1');
    const last = h.posts[h.posts.length - 1];
    expect(last && last.url === '/chart/live/targets', 'targets posted');
    const kinds = last.body.boxes.map((b) => b.kind).sort().join(',');
    expect(kinds === 'guest,host,node', 'posted kinds = ' + kinds + ', want guest,host,node');
    expect(last.body.viewer === 'v1', 'posted viewer = ' + last.body.viewer);
    h.stream().emit('value', { id: 'node:pve1', metric: 'cpu', value: 0.5 });
    h.stream().emit('value', { id: 'node:pve1', metric: 'ram', value: 0.25 });
    expect(h.text('node:pve1') === 'CPU 50 % · RAM 25 %', 'node text = ' + h.text('node:pve1'));
    h.stream().emit('value', { id: 'host:web01', metric: 'evil', value: 0.5 });
    expect(h.live('host:web01') === null, 'unknown metric must not render');
  },

  // A box the server did not grant loses its live line; granted ones keep it.
  async drop(h) {
    h.see(...ALL);
    h.reply(() => ({ status: 200, body: { granted: ALL } }));
    await hello(h, 'v1');
    for (const id of ALL) h.stream().emit('value', { id, metric: 'cpu', value: 0.1 });
    for (const id of ALL) expect(h.live(id), id + ' has a live line');
    h.reply(() => ({ status: 200, body: { granted: ['host:web01'] } }));
    await h.advance(10e3); // renewal
    expect(h.live('node:pve1') === null, 'denied node keeps its live line');
    expect(h.live('guest:pve1:101') === null, 'denied guest keeps its live line');
    expect(h.live('host:web01') !== null, 'granted host lost its live line');
    // A dropped box shows nothing old when a value comes back.
    h.stream().emit('value', { id: 'node:pve1', metric: 'ram', value: 0.3 });
    expect(h.text('node:pve1') === 'RAM 30 %', 'node text after drop = ' + h.text('node:pve1'));
  },

  // No value for more than 15 s shows the age, without any event or POST.
  async stale(h) {
    h.see('host:web01');
    h.reply(() => ({ status: 200, body: { granted: ['host:web01'] } }));
    await hello(h, 'v1');
    h.stream().emit('value', { id: 'host:web01', metric: 'cpu', value: 0.4 });
    await h.advance(14e3);
    expect(!h.live('host:web01').classList.contains('chart__line--stale'), 'stale before 15 s');
    await h.advance(6e3);
    const l = h.live('host:web01');
    expect(l.classList.contains('chart__line--stale'), 'not stale after 20 s: ' + h.text('host:web01'));
    expect(/last observed \d+ s ago$/.test(h.text('host:web01')), 'no age: ' + h.text('host:web01'));
  },

  // After a 410 the stream is reopened; if it never says hello the old
  // value must still turn stale.
  async stale410(h) {
    h.see('host:web01');
    h.reply(() => ({ status: 200, body: { granted: ['host:web01'] } }));
    await hello(h, 'v1');
    h.stream().emit('value', { id: 'host:web01', metric: 'cpu', value: 0.4 });
    h.reply(() => ({ status: 410, body: {} }));
    await h.advance(10e3); // renewal answers 410
    expect(h.streams.length === 2 && h.streams[0].closed, 'stream not reopened after 410');
    const posts = h.posts.length;
    await h.advance(30e3); // the new stream never sends hello
    expect(h.posts.length === posts, 'posted without a viewer');
    const l = h.live('host:web01');
    expect(l && l.classList.contains('chart__line--stale'), 'old value looks fresh after a 410: ' + h.text('host:web01'));
  },

  // A hidden page releases every box (empty list).
  async hidden(h) {
    h.see(...ALL);
    await hello(h, 'v1');
    h.document.hidden = true;
    h.visibility();
    await h.advance(1e3);
    const last = h.posts[h.posts.length - 1];
    expect(last.body.boxes.length === 0, 'hidden page posted ' + last.body.boxes.length + ' boxes');
  },
};

const main = async () => {
  const name = process.argv[2];
  if (!scenarios[name]) fail('unknown scenario ' + name);
  let src = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) src += chunk;
  await scenarios[name](start(src));
  process.stdout.write('ok ' + name + '\n');
};
main().catch((e) => fail(e && e.stack || String(e)));
