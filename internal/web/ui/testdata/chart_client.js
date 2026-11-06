// SPDX-License-Identifier: AGPL-3.0-or-later
// Behavioural harness for the org chart in web/static/inventory.js. Reads the
// whole script on stdin, runs it in a fresh vm context against a fake DOM with
// a real geometry model and runs the scenario named in argv[2] ("all" runs
// every scenario). Exits 1 with a message on the first failed expectation.
// No network. The pure functions are read from the script's nosChartMath
// binding, so the page needs no test hook.
'use strict';
const vm = require('vm');

const fail = (msg) => { process.stderr.write('FAIL: ' + msg + '\n'); process.exit(1); };
const expect = (cond, msg) => { if (!cond) fail(msg); };
const near = (got, want, msg) => expect(Math.abs(got - want) < 1e-6, msg + ': got ' + got + ', want ' + want);

const source = require('fs').readFileSync(0, 'utf8');

class El {
  constructor(hidden) {
    this.hidden = !!hidden;
    this.style = { transform: '' };
    this.listeners = {};
    this.names = new Set();
    this.children = [];
    this.scrollLeft = 0;
    this.scrollTop = 0;
  }
  get classList() {
    return {
      contains: (c) => this.names.has(c),
      toggle: (c, on) => { if (on) this.names.add(c); else this.names.delete(c); },
    };
  }
  addEventListener(name, fn, opts) { (this.listeners[name] ||= []).push({ fn, opts }); }
  dispatch(name, init) {
    const e = {
      type: name, target: this, button: 0, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false,
      deltaX: 0, deltaY: 0, deltaMode: 0, cancelable: true, defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; }, ...init,
    };
    for (const l of this.listeners[name] || []) l.fn(e);
    return e;
  }
  removeAttribute() {}
  contains() { return true; }
  closest() { return null; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  setPointerCapture() {}
}

// A 1000x600 canvas at (100,200) with a 1px border and 16px padding: the chart
// lays out at (117,217) and the area Fit may use is 968x568.
const page = (opts) => {
  const o = { clientW: 1000, clientH: 600, chartW: 968, chartH: 2000, narrow: false, ...opts };
  const section = new El();
  const hosts = new El();
  const layout = { x: 117, y: 217 };
  Object.assign(section, {
    clientWidth: o.clientW, clientHeight: o.clientH, clientLeft: 1, clientTop: 1,
    getBoundingClientRect: () => ({ left: 100, top: 200, width: o.clientW + 2, height: o.clientH + 2 }),
    querySelector: (sel) => (sel === '.chart__hosts' ? hosts : null),
  });
  hosts.children = [new El()];
  hosts.scrollWidth = o.chartW;
  hosts.scrollHeight = o.chartH;
  const state = () => {
    const m = /^translate\((.+)px,(.+)px\) scale\((.+)\)$/.exec(hosts.style.transform);
    return m ? { tx: +m[1], ty: +m[2], scale: +m[3] } : { tx: 0, ty: 0, scale: 1 };
  };
  hosts.getBoundingClientRect = () => {
    const s = state();
    return { left: layout.x + s.tx - section.scrollLeft, top: layout.y + s.ty - section.scrollTop };
  };
  const byID = {};
  for (const id of ['chart-fit', 'chart-zoom-out', 'chart-zoom-in', 'chart-zoom-100', 'chart-hint']) byID[id] = new El(true);
  const document = {
    querySelector: (sel) => (sel === '.chart' ? section : null),
    querySelectorAll: () => [],
    getElementById: (id) => byID[id] || null,
    addEventListener() {},
    body: { children: [], appendChild() {} },
  };
  const window = { matchMedia: () => ({ matches: o.narrow, addEventListener() {} }) };
  const ctx = vm.createContext({ document, window, CSS: { escape: (s) => s } });
  vm.runInContext(source, ctx);
  // Visible part of the chart inside the canvas, in px per axis.
  const visible = () => {
    const s = state(), r = hosts.getBoundingClientRect();
    const w = hosts.scrollWidth * s.scale, h = hosts.scrollHeight * s.scale;
    return {
      x: Math.min(r.left + w, 101 + o.clientW) - Math.max(r.left, 101),
      y: Math.min(r.top + h, 201 + o.clientH) - Math.max(r.top, 201),
    };
  };
  return {
    section, hosts, state, visible, math: vm.runInContext('nosChartMath', ctx),
    click: (id) => byID[id].dispatch('click'),
    wheel: (init) => section.dispatch('wheel', init),
    key: (key, init) => section.dispatch('keydown', { key, ...init }),
    controlHidden: (id) => byID[id].hidden,
  };
};
const math = () => page().math;

const scenarios = {
  // Pure zoom: the direction follows the requested scale, the point (mx, my)
  // stays where it is, and the scale is capped at both ends.
  zoommath() {
    const M = math();
    const t = M.zoomAt({ tx: 10, ty: 20, scale: 1 }, 2, 110, 220);
    near(t.scale, 2, 'zoom in scale');
    near(t.tx, -90, 'zoom in tx');
    near(t.ty, -180, 'zoom in ty');
    near((110 - t.tx) / t.scale, 100, 'point under the pointer');
    const out = M.zoomAt({ tx: 0, ty: 0, scale: 2 }, 1, 100, 100);
    near(out.scale, 1, 'zoom out scale');
    near(out.tx, 50, 'zoom out tx');
    near(M.zoomAt({ tx: 0, ty: 0, scale: 1 }, 1000, 0, 0).scale, M.maxScale, 'max cap');
    near(M.zoomAt({ tx: 0, ty: 0, scale: 1 }, 0.0001, 0, 0).scale, M.minScale, 'min cap');
    near(M.maxScale, 3, 'maxScale');
    near(M.zoomStep, 1.25, 'zoomStep');
  },

  // Pure Fit: known box sizes give known transforms.
  fitmath() {
    const M = math();
    const check = (box, scale, tx, msg) => {
      const t = M.fitTransform(box);
      near(t.scale, scale, msg + ' scale');
      near(t.tx, tx, msg + ' tx');
      near(t.ty, 0, msg + ' ty');
    };
    check({ w: 968, h: 568, chartW: 968, chartH: 1136 }, 0.5, 242, 'height bound');
    check({ w: 500, h: 568, chartW: 1000, chartH: 200 }, 0.5, 0, 'width bound');
    check({ w: 968, h: 568, chartW: 484, chartH: 100 }, 1, 242, 'never enlarges');
    check({ w: 968, h: 568, chartW: 968, chartH: 1e7 }, M.minScale, (968 - 968 * M.minScale) / 2, 'floor at minScale');
    check({ w: 0, h: 0, chartW: 0, chartH: 0 }, 1, 0, 'empty box stays a number');
  },

  // Pure wheel mapping: signs, units, the pinch cap, Shift.
  wheelmath() {
    const M = math();
    const d = (e, h) => M.wheelDelta({ deltaX: 0, deltaY: 0, deltaMode: 0, ...e }, h);
    near(d({ deltaY: 100 }).dy, 100, 'plain wheel dy');
    near(d({ deltaX: -40 }).dx, -40, 'plain wheel dx');
    expect(d({ deltaY: 100 }).zoom === undefined, 'plain wheel must pan');
    near(d({ deltaY: 3, deltaMode: 1 }).dy, 48, 'line mode');
    near(d({ deltaY: 2, deltaMode: 2 }, 500).dy, 1000, 'page mode');
    const shifted = d({ deltaY: 30, shiftKey: true });
    near(shifted.dx, 30, 'shift moves sideways');
    near(shifted.dy, 0, 'shift leaves dy');
    near(d({ deltaX: 7, deltaY: 30, shiftKey: true }).dy, 30, 'shift with own dx');
    near(d({ deltaY: -10, ctrlKey: true }).zoom, Math.exp(0.1), 'pinch out zooms in');
    near(d({ deltaY: 10, ctrlKey: true }).zoom, Math.exp(-0.1), 'pinch in zooms out');
    near(d({ deltaY: -10, metaKey: true }).zoom, Math.exp(0.1), 'meta zooms');
    near(d({ deltaY: -100, ctrlKey: true }).zoom, Math.exp(0.22), 'mouse notch up capped');
    near(d({ deltaY: 100, ctrlKey: true }).zoom, Math.exp(-0.22), 'mouse notch down capped');
  },

  // Pure key mapping, and browser shortcuts stay with the browser.
  keymath() {
    const M = math();
    const k = (key, mods) => M.keyAction({ key, ...mods });
    near(k('+').zoom, 1.25, '+ zooms in');
    near(k('=').zoom, 1.25, '= zooms in');
    near(k('-').zoom, 0.8, '- zooms out');
    expect(k('0')?.fit === true, '0 fits');
    near(k('ArrowDown').dy, 48, 'ArrowDown');
    near(k('ArrowUp').dy, -48, 'ArrowUp');
    near(k('ArrowRight').dx, 48, 'ArrowRight');
    near(k('ArrowLeft').dx, -48, 'ArrowLeft');
    expect(k('x') === null, 'other keys are not taken');
    for (const mod of ['ctrlKey', 'metaKey', 'altKey']) {
      for (const key of ['+', '-', '0', 'ArrowDown']) expect(k(key, { [mod]: true }) === null, mod + '+' + key + ' is the browser');
    }
  },

  // Pure pan bounds.
  panmath() {
    const M = math();
    near(M.clampPan(-1e6, 568, 2000), 48 - 2000, 'keeps the end of the chart in view');
    near(M.clampPan(1e6, 568, 2000), 568 - 48, 'keeps the start of the chart in view');
    near(M.clampPan(-1e6, 568, 10), -10 + 10, 'a chart under the margin stays whole');
    near(M.clampPan(-300, 568, 2000), -300, 'inside the bounds nothing changes');
    near(M.wheelPan(-100, 50, 568, 2000), -150, 'wheel moves the chart against the delta');
    near(M.wheelPan(0, -50, 568, 2000), 0, 'stops at the start');
    near(M.wheelPan(-1432, 50, 568, 2000), -1432, 'stops at the end');
    near(M.wheelPan(30, 50, 568, 100), 30, 'a chart in view does not move');
    near(M.wheelPan(100, 50, 568, 2000), 50, 'dragged past the start: moves back');
    near(M.wheelPan(100, -50, 568, 2000), 100, 'dragged past the start: not further out');
  },

  // The toolbar drives the real handlers: Zoom in zooms in, Zoom out out,
  // both around the canvas centre; 100% resets; Fit shows the whole chart.
  buttons() {
    const p = page();
    expect(!p.controlHidden('chart-zoom-in') && !p.controlHidden('chart-hint'), 'pan controls are shown');
    p.click('chart-zoom-in');
    near(p.state().scale, 1.25, 'Zoom in');
    // The centre of the 1002x602 border box is (484, 284) from the chart.
    near(p.state().tx, 484 - 484 * 1.25, 'Zoom in keeps the centre');
    near(p.state().ty, 284 - 284 * 1.25, 'Zoom in keeps the centre');
    p.click('chart-zoom-out');
    near(p.state().scale, 1, 'Zoom out');
    near(p.state().tx, 0, 'Zoom out keeps the centre');
    p.click('chart-zoom-out');
    near(p.state().scale, 0.8, 'Zoom out below 100%');
    p.click('chart-zoom-100');
    const s = p.state();
    expect(s.scale === 1 && s.tx === 0 && s.ty === 0, '100% resets: ' + p.hosts.style.transform);
    p.section.scrollTop = 40;
    p.click('chart-fit');
    near(p.state().scale, 0.284, 'Fit scale');
    near(p.state().tx, (968 - 968 * 0.284) / 2, 'Fit centres');
    near(p.state().ty, 0, 'Fit starts at the top');
    expect(p.section.scrollTop === 0, 'Fit drops the native scroll offset');
    near(p.visible().y, 2000 * 0.284, 'Fit shows the whole height');
    near(p.visible().x, 968 * 0.284, 'Fit shows the whole width');
  },

  // Fit shows 100 real hosts on the smallest canvas without hitting minScale.
  hundredhosts() {
    const p = page({ clientH: 420, chartH: 100 * 200 });
    p.click('chart-fit');
    near(p.state().scale, 388 / 20000, 'Fit scale');
    expect(p.state().scale > p.math.minScale, 'minScale must not cut Fit short');
    near(p.visible().y, 388, 'all 100 hosts are visible');
  },

  // Scroll down moves the chart up, and each event that moves is consumed.
  wheelpan() {
    const p = page({ chartW: 2000 });
    expect(p.section.listeners.wheel[0].opts.passive === false, 'the wheel listener must be able to cancel');
    expect(p.wheel({ deltaY: 100 }).defaultPrevented, 'wheel that pans is consumed');
    near(p.state().ty, -100, 'scroll down moves the chart up');
    p.wheel({ deltaY: -60 });
    near(p.state().ty, -40, 'scroll up moves the chart down');
    p.wheel({ deltaX: 30 });
    near(p.state().tx, -30, 'scroll right moves the chart left');
    p.wheel({ deltaY: 25, shiftKey: true });
    near(p.state().tx, -55, 'Shift+scroll goes sideways');
    near(p.state().ty, -40, 'Shift+scroll stays on the row');
    p.wheel({ deltaY: 1, deltaMode: 1 });
    near(p.state().ty, -56, 'line deltas are converted');
  },

  // At the edge in the scroll direction the wheel event stays with the page,
  // so the staged update form below the canvas is reachable.
  wheelrelease() {
    const p = page();
    const top = p.wheel({ deltaY: -100 });
    expect(!top.defaultPrevented, 'at the top, scrolling up belongs to the page');
    p.wheel({ deltaY: 1e6 });
    near(p.state().ty, 568 - 2000, 'an inertial swipe stops at the end of the chart');
    expect(!p.wheel({ deltaY: 100 }).defaultPrevented, 'at the bottom, scrolling down belongs to the page');
    expect(p.wheel({ deltaY: -100 }).defaultPrevented, 'and scrolling back up pans again');

    const small = page({ chartH: 300 });
    expect(!small.wheel({ deltaY: 100 }).defaultPrevented, 'a chart that fits never holds the wheel');
    near(small.state().ty, 0, 'a chart that fits does not move');

    const fitted = page();
    fitted.click('chart-fit');
    expect(!fitted.wheel({ deltaY: 100 }).defaultPrevented, 'a fitted chart never holds the wheel');
    expect(!fitted.wheel({ deltaX: 3 }).defaultPrevented, 'not sideways either');
  },

  // Ctrl/Meta+wheel and pinch zoom around the pointer, and never reach the
  // browser's page zoom, not even at the limit.
  wheelzoom() {
    const p = page();
    const e = p.wheel({ deltaY: -100, ctrlKey: true, clientX: 300, clientY: 400 });
    expect(e.defaultPrevented, 'zoom is consumed');
    near(p.state().scale, Math.exp(0.22), 'scroll up zooms in, capped to one step');
    const f = Math.exp(0.22);
    near(p.state().tx, 183 - 183 * f, 'zoom keeps the pointer x');
    near(p.state().ty, 183 - 183 * f, 'zoom keeps the pointer y');
    p.wheel({ deltaY: 100, ctrlKey: true, clientX: 300, clientY: 400 });
    near(p.state().scale, 1, 'scroll down zooms out');
    for (let i = 0; i < 40; i++) p.wheel({ deltaY: -100, ctrlKey: true, clientX: 300, clientY: 400 });
    near(p.state().scale, p.math.maxScale, 'stops at maxScale');
    expect(p.wheel({ deltaY: -100, ctrlKey: true }).defaultPrevented, 'at maxScale the browser still does not zoom');
    for (let i = 0; i < 80; i++) p.wheel({ deltaY: 100, metaKey: true, clientX: 300, clientY: 400 });
    near(p.state().scale, p.math.minScale, 'stops at minScale');
  },

  // Safari's gesture events scale from the start of the gesture.
  gesture() {
    const p = page();
    p.click('chart-zoom-in');
    p.section.dispatch('gesturestart', {});
    p.section.dispatch('gesturechange', { scale: 2, clientX: 300, clientY: 400 });
    near(p.state().scale, 2.5, 'pinch multiplies the starting scale');
    p.section.dispatch('gesturechange', { scale: 0.5, clientX: 300, clientY: 400 });
    near(p.state().scale, 0.625, 'pinch in zooms out');
  },

  // Keys on the focused canvas, through the real handler.
  keys() {
    const p = page();
    expect(p.key('+').defaultPrevented, '+ is consumed');
    near(p.state().scale, 1.25, '+ zooms in');
    p.key('-');
    near(p.state().scale, 1, '- zooms out');
    p.key('=');
    near(p.state().scale, 1.25, '= zooms in');
    p.key('-');
    near(p.key('ArrowDown') && p.state().ty, -48, 'ArrowDown moves the chart up');
    near(p.key('ArrowUp') && p.state().ty, 0, 'ArrowUp moves the chart down');
    expect(!p.key('ArrowUp').defaultPrevented, 'ArrowUp at the top belongs to the page');
    p.key('0');
    near(p.state().scale, 0.284, '0 fits');
    p.click('chart-zoom-100');
    const before = p.hosts.style.transform;
    expect(!p.key('0', { ctrlKey: true }).defaultPrevented, 'Ctrl+0 is the browser');
    expect(!p.key('+', { metaKey: true }).defaultPrevented, 'Cmd++ is the browser');
    expect(!p.key('x').defaultPrevented, 'other keys pass');
    expect(!p.key('+', { target: new El() }).defaultPrevented, 'keys inside the chart stay with their element');
    expect(p.hosts.style.transform === before, 'ignored keys do not move the chart');
  },

  // However the chart is moved, a part of it stays in the canvas.
  panbounds() {
    const drag = (p, x, y) => {
      p.section.dispatch('pointerdown', { clientX: 300, clientY: 300, pointerId: 1 });
      p.section.dispatch('pointermove', { clientX: 300 + x, clientY: 300 + y });
      p.section.dispatch('pointerup', {});
    };
    const p = page();
    drag(p, 40, 30);
    near(p.state().tx, 40, 'a plain drag follows the pointer');
    near(p.state().ty, 30, 'a plain drag follows the pointer');
    for (const [x, y] of [[1e6, 1e6], [-1e6, -1e6], [1e6, -1e6], [-1e6, 1e6]]) {
      drag(p, x, y);
      const v = p.visible();
      expect(v.x >= 48 && v.y >= 48, 'drag left ' + JSON.stringify(v) + ' visible');
    }
    for (let i = 0; i < 40; i++) p.click('chart-zoom-out');
    expect(p.visible().x > 0 && p.visible().y > 0, 'zoom out keeps the chart in view');
    for (let i = 0; i < 40; i++) p.wheel({ deltaY: 100, ctrlKey: true, clientX: 2000, clientY: 2000 });
    expect(p.visible().x > 0 && p.visible().y > 0, 'zoom at a far point keeps the chart in view');

    // A chart that collapses under a panned view comes back.
    const q = page();
    q.wheel({ deltaY: 1400 });
    q.hosts.scrollHeight = 300;
    q.section.dispatch('toggle', { target: new El() });
    expect(q.visible().y >= 48, 'collapsing details keeps the chart in view');
  },

  // Below 600px the chart is a plain list: nothing is touched or cancelled.
  listmode() {
    const p = page({ narrow: true });
    expect(!p.section.classList.contains('chart--pan'), 'list mode has no pan class');
    expect(p.controlHidden('chart-zoom-in') && p.controlHidden('chart-fit'), 'list mode hides the controls');
    expect(!p.wheel({ deltaY: 100 }).defaultPrevented, 'wheel stays with the page');
    expect(!p.wheel({ deltaY: 100, ctrlKey: true }).defaultPrevented, 'browser zoom stays with the browser');
    expect(!p.key('+').defaultPrevented, 'keys stay with the page');
    p.section.dispatch('toggle', { target: new El() });
    expect(p.hosts.style.transform === '', 'list mode sets no transform');
  },
};

const name = process.argv[2];
if (name === 'all') {
  for (const f of Object.values(scenarios)) f();
} else {
  if (!scenarios[name]) fail('unknown scenario ' + name);
  scenarios[name]();
}
process.stdout.write('ok ' + name + '\n');
