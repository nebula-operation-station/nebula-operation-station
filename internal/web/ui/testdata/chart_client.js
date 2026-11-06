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
      preventDefault() { this.tried = true; if (this.cancelable) this.defaultPrevented = true; }, ...init,
    };
    for (const l of this.listeners[name] || []) l.fn(e);
    return e;
  }
  // An event from a child that does not bubble (toggle): only the capture
  // phase reaches this element.
  dispatchCaptured(name, init) {
    const listeners = this.listeners[name] || [];
    this.listeners[name] = listeners.filter((l) => l.opts === true || l.opts?.capture === true);
    const e = this.dispatch(name, init);
    this.listeners[name] = listeners;
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
  const media = { matches: o.narrow, change() {}, addEventListener(_, fn) { this.change = fn; } };
  const window = { matchMedia: () => media };
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
    setNarrow: (on) => { media.matches = on; media.change(); },
    touch: (opts) => touchScreen(section, opts),
  };
};
const math = () => page().math;

// A box, link or button inside the chart: the mouse leaves those alone.
const control = () => {
  const el = new El();
  el.closest = () => el;
  return el;
};

// A touch screen on a canvas with touch-action: pan-y. As in Chrome, a move
// sends pointermove, then touchmove (touchFirst swaps them for browsers with
// the other order). A vertical move or a two-finger move whose touchmove is
// not cancelled starts the browser's own pan: every finger gets pointercancel,
// the page scrolls and the chart hears no more of it. pageY is the page scroll.
const touchScreen = (section, opts) => {
  const fingers = new Map();
  const t = { pageY: 0, panning: false };
  const lift = (name, id) => {
    fingers.delete(id);
    section.dispatch(name, { pointerType: 'touch', pointerId: id });
  };
  t.down = (id, x, y, target) => {
    const f = { clientX: x, clientY: y, target: target || section };
    const isPrimary = fingers.size === 0;
    fingers.set(id, f);
    t.panning = t.panning && !isPrimary;
    return section.dispatch('pointerdown', { pointerType: 'touch', pointerId: id, isPrimary, ...f });
  };
  // Returns the touchmove event.
  t.move = (id, x, y, init) => {
    const f = fingers.get(id);
    const dx = x - f.clientX, dy = y - f.clientY;
    f.clientX = x; f.clientY = y;
    const pointer = () => section.dispatch('pointermove', { pointerType: 'touch', pointerId: id, ...f });
    const touch = () => section.dispatch('touchmove', {
      target: f.target, targetTouches: [...fingers.values()].filter((g) => g.target === f.target), ...init,
    });
    let e;
    if (opts?.touchFirst) { e = touch(); pointer(); } else { pointer(); e = touch(); }
    if (!e.defaultPrevented && (fingers.size > 1 || Math.abs(dy) >= Math.abs(dx))) {
      t.panning = true;
      t.pageY -= dy;
      for (const fid of [...fingers.keys()]) lift('pointercancel', fid);
    }
    return e;
  };
  t.up = (id) => lift('pointerup', id);
  // One finger in steps of 10px, as a real swipe arrives.
  t.swipe = (x0, y0, x1, y1, target) => {
    t.down(1, x0, y0, target);
    const n = Math.ceil(Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0)) / 10);
    for (let i = 1; i <= n; i++) {
      if (t.panning) t.pageY -= (y1 - y0) / n;
      else t.move(1, x0 + (x1 - x0) * i / n, y0 + (y1 - y0) * i / n);
    }
    if (fingers.has(1)) t.up(1);
  };
  return t;
};

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
    check({ w: 100, h: 568, chartW: 1e5, chartH: 100 }, M.minScale, 0, 'wider than the area at minScale starts at the left');
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

  // A wheel event the browser will not cancel scrolls the page anyway, so the
  // chart must not move or zoom along with it.
  wheelnocancel() {
    const p = page({ chartW: 2000 });
    for (const init of [{ deltaY: 100 }, { deltaX: 30 }, { deltaY: -100, ctrlKey: true, clientX: 300, clientY: 400 }]) {
      const e = p.wheel({ ...init, cancelable: false });
      expect(!e.defaultPrevented, 'nothing to cancel');
      const s = p.state();
      expect(s.tx === 0 && s.ty === 0 && s.scale === 1, 'the chart stays put: ' + p.hosts.style.transform);
    }
    p.wheel({ deltaY: 100 });
    near(p.state().ty, -100, 'the next cancelable event pans again');
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

  // One finger: the chart follows while it can, the swipe goes to the page
  // where it cannot, as with the wheel. In both browser event orders.
  touchswipe() {
    for (const opts of [{}, { touchFirst: true }]) {
      const p = page({ chartW: 2000 });
      const t = p.touch(opts);
      t.swipe(500, 300, 500, 100);
      near(p.state().ty, -200, 'a swipe up moves the chart up');
      near(t.pageY, 0, 'while the chart moves the page stays');
      t.swipe(500, 300, 200, 300);
      near(p.state().tx, -300, 'a swipe left moves the chart left');
      t.swipe(500, 100, 500, 200);
      near(p.state().ty, -100, 'a swipe down moves the chart back');
      t.down(1, 500, 300);
      t.move(1, 500, 280);
      expect(t.move(1, 500, 320).defaultPrevented, 'a held swipe stays held when it turns');
      near(p.state().ty, -80, 'and follows the finger');
      t.up(1);

      // At the top a swipe down is the page's, and the chart does not twitch.
      const q = page();
      const u = q.touch(opts);
      u.swipe(500, 100, 500, 300);
      expect(q.state().ty === 0 && q.state().tx === 0, 'released swipe moved the chart: ' + q.hosts.style.transform);
      near(u.pageY, -200, 'the page scrolls instead');
      u.swipe(500, 300, 500, 100);
      near(q.state().ty, -200, 'the next swipe the chart can follow is its own again');

      for (const prepared of [page({ chartH: 300 }), page()]) {
        if (prepared.hosts.scrollHeight === 2000) prepared.click('chart-fit');
        const before = prepared.hosts.style.transform;
        const v = prepared.touch(opts);
        v.swipe(500, 300, 500, 100);
        near(v.pageY, 200, 'a chart that fits never holds a swipe');
        expect(prepared.hosts.style.transform === before, 'and does not move');
      }
    }
  },

  // A landscape phone: the 420px canvas fills the 390px viewport, and the form
  // below it must be reachable by swiping on the canvas alone.
  touchlandscape() {
    const p = page({ clientW: 844, clientH: 420, chartW: 1600, chartH: 2000 });
    const t = p.touch();
    let swipes = 0;
    while (t.pageY === 0 && swipes < 40) { t.swipe(400, 360, 400, 60); swipes++; }
    expect(t.pageY > 0, 'no swipe reached the page in ' + swipes + ' swipes');
    near(p.visible().y >= 48 ? 1 : 0, 1, 'the chart stays in view');
    const scrolled = t.pageY;
    t.swipe(400, 360, 400, 60);
    near(t.pageY, scrolled + 300, 'further swipes keep scrolling the page');
    // Back up: the chart first, then the page above it.
    swipes = 0;
    while (t.pageY === scrolled + 300 && swipes < 40) { t.swipe(400, 60, 400, 360); swipes++; }
    expect(t.pageY < scrolled + 300, 'no swipe reached the page on the way back');
  },

  // A swipe that starts on a link or button is the page's; the tap stays a tap.
  touchcontrol() {
    const p = page();
    const t = p.touch();
    t.swipe(500, 300, 500, 100, control());
    near(t.pageY, 200, 'the page scrolls');
    near(p.state().ty, 0, 'the chart stays');
    const e = t.down(1, 500, 300, control());
    expect(!e.defaultPrevented, 'a tap is not cancelled');
    t.up(1);
  },

  // A touchmove the browser will not cancel (it is scrolling already) is left
  // alone: calling preventDefault on one only logs an intervention warning.
  touchnocancel() {
    const p = page();
    const t = p.touch();
    t.down(1, 500, 300);
    t.move(1, 500, 280);
    const e = t.move(1, 500, 260, { cancelable: false });
    expect(!e.tried, 'preventDefault on an uncancelable touchmove');
  },

  // Two fingers pinch on Chrome Android (pointer events only), wherever they
  // land: the chart is mostly boxes and links. The midpoint carries the chart.
  pinch() {
    for (const opts of [{}, { touchFirst: true }]) {
      const p = page();
      const t = p.touch(opts);
      t.down(1, 300, 400, control());
      t.down(2, 400, 400, control());
      near(p.state().scale, 1, 'landing does not zoom');
      expect(t.move(2, 500, 400).defaultPrevented, 'a pinch is cancelled: the browser must not scroll');
      near(p.state().scale, 2, 'twice the distance is twice the size');
      // The point under the first midpoint (350,400) follows it to (400,400).
      near(p.state().tx, 283 - 233 * 2, 'the point between the fingers stays there');
      near(p.state().ty, 183 - 183 * 2, 'the point between the fingers stays there');
      near(t.pageY, 0, 'the page stays');
      t.move(2, 350, 400);
      near(p.state().scale, 0.5, 'half the distance is half the size');
      t.move(1, 300, 300);
      t.move(2, 350, 300);
      near(p.state().scale, 0.5, 'two fingers moving together keep the scale');
      near(p.state().ty, 183 - 183 * 0.5 - 100, 'and move the chart');
      t.move(2, 1e5, 300);
      near(p.state().scale, p.math.maxScale, 'a pinch stops at maxScale');
      t.up(2);
      t.up(1);
    }
  },

  // Fingers that land or lift during a pinch do not make the chart jump, and
  // the last finger carries on as a drag.
  pinchfingers() {
    const p = page();
    const t = p.touch();
    t.down(1, 300, 400);
    t.move(1, 300, 380);
    near(p.state().ty, -20, 'one finger drags');
    t.down(2, 400, 380);
    near(p.state().ty, -20, 'the second finger does not move the chart');
    t.move(2, 500, 380);
    near(p.state().scale, 2, 'a drag turns into a pinch');
    const s = p.hosts.style.transform;
    t.down(3, 600, 600);
    t.move(3, 700, 700);
    expect(p.hosts.style.transform === s, 'a third finger changes nothing: ' + p.hosts.style.transform);
    t.up(3);
    expect(p.hosts.style.transform === s, 'nor does lifting it');
    t.up(2);
    expect(p.hosts.style.transform === s, 'lifting a pinch finger does not jump');
    const before = p.state();
    expect(t.move(1, 280, 370).defaultPrevented, 'the last finger still holds the gesture');
    near(p.state().tx, before.tx - 20, 'and drags sideways');
    near(p.state().ty, before.ty - 10, 'and up');
    near(p.state().scale, 2, 'at the pinched scale');
    t.up(1);
    t.swipe(500, 300, 500, 200);
    near(p.state().ty, before.ty - 110, 'afterwards one finger drags as before');

    // Two fingers in one spot: the distance must not divide by zero.
    const q = page();
    const u = q.touch();
    u.down(1, 300, 400);
    u.down(2, 300, 400);
    u.move(2, 310, 400);
    near(q.state().scale, q.math.maxScale, 'zero distance stays a number');

    // A finger whose pointerup never came (its element left the page) must
    // not turn the next touch into a pinch.
    const r = page();
    const pointer = (name, id, isPrimary, clientY) => r.section.dispatch(name, { pointerType: 'touch', pointerId: id, isPrimary, clientX: 500, clientY });
    pointer('pointerdown', 7, true, 400);
    pointer('pointerdown', 8, false, 500);
    pointer('pointerdown', 9, true, 300);
    pointer('pointermove', 9, true, 200);
    near(r.state().scale, 1, 'a new touch starts clean');
    near(r.state().ty, -100, 'and drags');

    // pure helper
    const M = p.math;
    const m = M.pinchOf({ x: 0, y: 0 }, { x: 30, y: 40 });
    near(m.dist, 50, 'distance');
    near(m.x, 15, 'midpoint x');
    near(m.y, 20, 'midpoint y');
    near(M.pinchOf({ x: 5, y: 5 }, { x: 5, y: 5 }).dist, 1, 'distance floor');
  },

  // iOS sends gesture and pointer events for one pinch: only one of them may
  // zoom. preventDefault stays, or the page itself would zoom.
  pinchsafari() {
    const p = page();
    const t = p.touch();
    t.down(1, 300, 400);
    t.down(2, 400, 400);
    p.section.dispatch('gesturestart', {});
    t.move(2, 500, 400);
    const s = p.hosts.style.transform;
    const e = p.section.dispatch('gesturechange', { scale: 3, clientX: 400, clientY: 400 });
    expect(e.defaultPrevented, 'the page must not zoom');
    expect(p.hosts.style.transform === s, 'the pointer pinch owns the zoom: ' + p.hosts.style.transform);
  },

  // Below 600px nothing touch is touched, and a rotation into list mode in the
  // middle of a gesture leaves the list alone.
  touchlist() {
    const p = page({ narrow: true });
    const t = p.touch();
    t.swipe(500, 300, 500, 100);
    near(t.pageY, 200, 'the page scrolls');
    t.down(1, 300, 400);
    t.down(2, 400, 400);
    expect(t.move(2, 500, 400).defaultPrevented === false, 'two fingers stay with the browser');
    expect(p.hosts.style.transform === '', 'list mode sets no transform');

    const q = page();
    const u = q.touch();
    u.down(1, 300, 400);
    u.down(2, 400, 400);
    u.move(2, 500, 400);
    q.setNarrow(true);
    expect(!u.move(2, 600, 400).defaultPrevented, 'the list scrolls again at once');
    expect(q.hosts.style.transform === '', 'a pinch does not survive the rotation');
  },

  // A mouse drag is not a swipe: it does not ask the page first.
  mousedrag() {
    const p = page();
    p.section.dispatch('pointerdown', { pointerType: 'mouse', pointerId: 1, clientX: 300, clientY: 300 });
    p.section.dispatch('pointermove', { pointerType: 'mouse', pointerId: 1, clientX: 300, clientY: 330 });
    near(p.state().ty, 30, 'a mouse may drag past the top');
    p.section.dispatch('pointerup', { pointerType: 'mouse', pointerId: 1 });
    p.section.dispatch('pointermove', { pointerType: 'mouse', pointerId: 1, clientX: 300, clientY: 400 });
    near(p.state().ty, 30, 'a released mouse drags nothing');
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
    q.section.dispatchCaptured('toggle', { target: new El() });
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
    p.section.dispatchCaptured('toggle', { target: new El() });
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
