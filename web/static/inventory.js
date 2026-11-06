// SPDX-License-Identifier: AGPL-3.0-or-later
// Inventory page and org chart. The add-host dialog posts JSON to
// /inventory/hosts (real Origin, decision 36). Server text is shown with
// textContent only, never innerHTML.
'use strict';

// Org chart geometry: pure functions, no DOM, tested by testdata/chart_client.js
// in internal/web/ui. Offsets: the chart's top-left corner relative to its
// layout position. dx, dy > 0 move the view right and down.
const nosChartMath = (() => {
  // Fit must reach 100 hosts of about 200px on the 420px minimum canvas.
  const minScale = 0.015;
  const maxScale = 3;
  const zoomStep = 1.25;
  // A trackpad pinch is ctrl+wheel with small deltas; a mouse notch (about
  // 100) is capped to one zoom step.
  const wheelZoomCap = 22;
  const keyStep = 48;
  // Part of the chart that stays in the canvas, per axis.
  const keepVisible = 48;

  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const clampScale = (s) => (Number.isFinite(s) ? Math.min(maxScale, Math.max(minScale, s)) : 1);
  return {
    minScale, maxScale, zoomStep,
    // Transform for scale `next` that keeps the point (mx, my) in place.
    zoomAt(t, next, mx, my) {
      const scale = clampScale(next);
      const f = scale / t.scale;
      return { tx: mx - (mx - t.tx) * f, ty: my - (my - t.ty) * f, scale };
    },
    // Transform that shows a chart of chartW x chartH in w x h; never enlarges.
    fitTransform(b) {
      const scale = clampScale(Math.min(1, b.w / b.chartW, b.h / b.chartH));
      return { tx: Math.max(0, (b.w - b.chartW * scale) / 2), ty: 0, scale };
    },
    // A wheel event as { zoom } or a pan in px { dx, dy }. Deltas may count
    // lines or pages (Firefox with a mouse).
    wheelDelta(e, pageHeight) {
      const px = (d) => (e.deltaMode === 1 ? d * 16 : e.deltaMode === 2 ? d * pageHeight : d);
      const dx = px(e.deltaX), dy = px(e.deltaY);
      if (e.ctrlKey || e.metaKey) {
        const d = clamp(dy, -wheelZoomCap, wheelZoomCap);
        return { zoom: Math.exp(-d * 0.01) };
      }
      return e.shiftKey && !dx ? { dx: dy, dy: 0 } : { dx, dy };
    },
    // A key as { zoom }, { fit } or a pan { dx, dy }; null leaves it alone,
    // browser shortcuts (Ctrl+0, Cmd++) too.
    keyAction(e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return null;
      switch (e.key) {
        case 'ArrowLeft': return { dx: -keyStep, dy: 0 };
        case 'ArrowRight': return { dx: keyStep, dy: 0 };
        case 'ArrowUp': return { dx: 0, dy: -keyStep };
        case 'ArrowDown': return { dx: 0, dy: keyStep };
        case '+':
        case '=': return { zoom: zoomStep };
        case '-': return { zoom: 1 / zoomStep };
        case '0': return { fit: true };
        default: return null;
      }
    },
    // Distance (never 0, it divides) and midpoint of two fingers.
    pinchOf(a, b) {
      return { dist: Math.max(1, Math.hypot(a.x - b.x, a.y - b.y)), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    },
    // Offset t on one axis with part of the chart kept visible.
    clampPan(t, view, size) {
      const keep = Math.min(keepVisible, size);
      return clamp(t, keep - size, view - keep);
    },
    // Offset after scrolling by d on one axis: ends at the chart's edges, a
    // chart dragged past them only comes back. Same offset: the page scrolls.
    wheelPan(t, d, view, size) {
      const lo = Math.min(0, view - size), hi = Math.max(0, view - size);
      if (size <= view && t >= lo && t <= hi) return t;
      return clamp(t - d, Math.min(t, lo), Math.max(t, hi));
    },
  };
})();

// Org chart interaction (ADR 0006 P1-35): drag and scroll pan; pinch,
// Ctrl+scroll, buttons and keys zoom; fit, list mode, details panel/sheet.
// Runs first and on its own; the chart is never re-rendered. Moves are
// instant, so reduced motion needs no extra case.
(() => {
  const chartSection = document.querySelector('.chart');
  if (!chartSection) return;
  const chartHosts = chartSection.querySelector('.chart__hosts');
  if (!chartHosts) return;
  const fitBtn = document.getElementById('chart-fit');
  const zoomOutBtn = document.getElementById('chart-zoom-out');
  const zoomInBtn = document.getElementById('chart-zoom-in');
  const actualBtn = document.getElementById('chart-zoom-100');
  const panOnly = [fitBtn, zoomOutBtn, zoomInBtn, actualBtn, document.getElementById('chart-hint')];
  const sheet = document.getElementById('chart-sheet');
  const narrow = window.matchMedia('(max-width: 600px)');
  const M = nosChartMath;
  const { zoomStep } = M;
  let tx = 0, ty = 0, scale = 1;

  const panning = () => chartSection.classList.contains('chart--pan');
  const applyTransform = () => {
    chartHosts.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
  };
  // Layout position of the chart's top-left corner (the transform origin).
  const origin = () => {
    const r = chartHosts.getBoundingClientRect();
    return { x: r.left - tx + chartSection.scrollLeft, y: r.top - ty + chartSection.scrollTop };
  };
  // The area the chart can use (padding kept on all sides) and its size at
  // 100%. Reads the layout: tx and ty must match the page.
  const box = () => {
    const view = chartSection.getBoundingClientRect();
    const o = origin();
    const left = o.x - view.left - chartSection.clientLeft;
    const top = o.y - view.top - chartSection.clientTop;
    return {
      w: chartSection.clientWidth - 2 * left,
      h: chartSection.clientHeight - top - left,
      chartW: chartHosts.scrollWidth,
      chartH: chartHosts.scrollHeight,
    };
  };
  // Every move ends here, so no path can lose the chart.
  const place = (x, y, s) => {
    const b = box();
    tx = M.clampPan(x, b.w, b.chartW * s);
    ty = M.clampPan(y, b.h, b.chartH * s);
    scale = s;
    applyTransform();
  };
  // Scroll-style pan; false at the chart's edge.
  const panBy = (dx, dy) => {
    unscroll();
    const b = box();
    const x = M.wheelPan(tx, dx, b.w, b.chartW * scale);
    const y = M.wheelPan(ty, dy, b.h, b.chartH * scale);
    if (x === tx && y === ty) return false;
    place(x, y, scale);
    return true;
  };
  // The clipped canvas can still scroll natively (focus, find): fit() drops
  // that offset, unscroll() folds it into the transform.
  const fit = () => {
    chartSection.scrollTop = 0;
    chartSection.scrollLeft = 0;
    ({ tx, ty, scale } = M.fitTransform(box()));
    applyTransform();
  };
  const unscroll = () => {
    if (!chartSection.scrollLeft && !chartSection.scrollTop) return;
    tx -= chartSection.scrollLeft;
    ty -= chartSection.scrollTop;
    chartSection.scrollLeft = 0;
    chartSection.scrollTop = 0;
    applyTransform();
  };
  const actualSize = () => {
    unscroll();
    tx = 0; ty = 0; scale = 1;
    applyTransform();
  };
  // Zoom keeping the point under (x, y) in place; default the canvas centre.
  const zoomAt = (next, x, y) => {
    unscroll();
    const view = chartSection.getBoundingClientRect();
    const o = origin();
    const mx = (x ?? view.left + view.width / 2) - o.x;
    const my = (y ?? view.top + view.height / 2) - o.y;
    const t = M.zoomAt({ tx, ty, scale }, next, mx, my);
    place(t.tx, t.ty, t.scale);
  };
  const zoomBy = (factor) => zoomAt(scale * factor);

  // Pan canvas on wide screens (a tab stop), plain list below 600px.
  const setMode = () => {
    const pan = !narrow.matches && chartHosts.children.length > 0;
    chartSection.classList.toggle('chart--pan', pan);
    if (pan) chartSection.tabIndex = 0;
    else chartSection.removeAttribute('tabindex');
    for (const el of panOnly) if (el) el.hidden = !pan;
    if (!pan) { tx = 0; ty = 0; scale = 1; chartHosts.style.transform = ''; }
  };

  // Scroll pans (Shift+wheel sideways); Ctrl/Meta+scroll and pinch zoom around
  // the pointer, never the page. A scroll the chart cannot follow or cancel
  // stays with the page, so nothing below is out of reach.
  chartSection.addEventListener('wheel', (e) => {
    if (!panning() || !e.cancelable) return;
    const d = M.wheelDelta(e, chartSection.clientHeight);
    if (d.zoom) {
      e.preventDefault();
      zoomAt(scale * d.zoom, e.clientX, e.clientY);
      return;
    }
    if (panBy(d.dx, d.dy)) e.preventDefault();
  }, { passive: false });

  // Safari's trackpad pinch: gesture events, e.scale counts from their start.
  let gestureBase = 1;
  chartSection.addEventListener('gesturestart', (e) => {
    if (!panning()) return;
    e.preventDefault();
    gestureBase = scale;
  }, { passive: false });
  chartSection.addEventListener('gesturechange', (e) => {
    if (!panning()) return;
    e.preventDefault();
    if (!pinch) zoomAt(gestureBase * e.scale, e.clientX, e.clientY);
  }, { passive: false });
  chartSection.addEventListener('gestureend', (e) => {
    if (!panning()) return;
    e.preventDefault();
  }, { passive: false });

  // Drag pans the canvas; interactive elements keep their behaviour. A swipe
  // (touch-action: pan-y) is decided once, like the wheel: the chart cancels
  // the first touchmove if it can follow, else the page scrolls. Two fingers
  // pinch from anywhere (Chrome has no gesture events) and carry the chart
  // with their midpoint; the last one left drags on.
  let drag = null, pinch = null;
  const fingers = new Map();
  const startPinch = () => {
    const [a, b] = fingers.values();
    unscroll();
    drag = null;
    pinch = { ...M.pinchOf(a, b), scale };
  };
  const holdSwipe = (x, y) => {
    const dx = x - drag.x, dy = y - drag.y;
    if (!drag.held && (dx || dy)) {
      const b = box();
      drag.held = Math.abs(dx) > Math.abs(dy) || M.wheelPan(ty, -dy, b.h, b.chartH * scale) !== ty;
      if (!drag.held) drag = null;
    }
    return drag?.held;
  };
  chartSection.addEventListener('pointerdown', (e) => {
    if (!panning() || e.button !== 0) return;
    const touch = e.pointerType === 'touch';
    if (touch) {
      if (e.isPrimary) { fingers.clear(); pinch = null; } // a lost pointerup
      fingers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (fingers.size > 1) return startPinch();
    }
    if (e.target.closest('a, button, summary, input, select, textarea, meter')) return;
    unscroll();
    drag = { x: e.clientX, y: e.clientY, tx, ty, held: !touch };
    chartSection.setPointerCapture(e.pointerId);
  });
  chartSection.addEventListener('pointermove', (e) => {
    if (!panning()) return;
    const f = fingers.get(e.pointerId);
    if (f) { f.x = e.clientX; f.y = e.clientY; }
    if (pinch) {
      const [a, b] = fingers.values(), p = M.pinchOf(a, b);
      place(tx + p.x - pinch.x, ty + p.y - pinch.y, scale);
      zoomAt(pinch.scale * p.dist / pinch.dist, p.x, p.y);
      pinch.x = p.x; pinch.y = p.y;
    } else if (drag && holdSwipe(e.clientX, e.clientY)) {
      place(drag.tx + (e.clientX - drag.x), drag.ty + (e.clientY - drag.y), scale);
    }
  });
  chartSection.addEventListener('touchmove', (e) => {
    if (!panning() || !e.cancelable) return;
    const t = e.targetTouches[0];
    if (pinch || (drag && holdSwipe(t.clientX, t.clientY))) e.preventDefault();
  }, { passive: false });
  const endDrag = (e) => {
    fingers.delete(e.pointerId);
    if (fingers.size > 1) return startPinch();
    const [f] = fingers.values();
    drag = null;
    if (f && pinch) drag = { x: f.x, y: f.y, tx, ty, held: true };
    pinch = null;
  };
  chartSection.addEventListener('pointerup', endDrag);
  chartSection.addEventListener('pointercancel', endDrag);

  // Keys on the focused canvas; arrows behave like the wheel.
  chartSection.addEventListener('keydown', (e) => {
    if (!panning() || e.target !== chartSection) return;
    const a = M.keyAction(e);
    if (!a) return;
    if (a.zoom) zoomBy(a.zoom);
    else if (a.fit) fit();
    else if (!panBy(a.dx, a.dy)) return;
    e.preventDefault();
  });

  // Collapsing details shortens the chart; toggle does not bubble, hence the
  // capture phase.
  chartSection.addEventListener('toggle', () => {
    if (panning()) place(tx, ty, scale);
  }, true);

  // Pan-to-focus: a focused element outside the clipped view moves into it.
  const margin = 16;
  const shift = (lo, hi, min, max) => (lo < min ? min - lo : hi > max ? Math.max(min - lo, max - hi) : 0);
  const revealFocus = (el) => {
    if (!panning() || !chartHosts.contains(el)) return;
    unscroll();
    const view = chartSection.getBoundingClientRect();
    const r = el.getBoundingClientRect();
    const dx = shift(r.left, r.right, view.left + margin, view.right - margin);
    const dy = shift(r.top, r.bottom, view.top + margin, view.bottom - margin);
    if (dx || dy) place(tx + dx, ty + dy, scale);
  };
  chartSection.addEventListener('focusin', (e) => revealFocus(e.target));

  if (fitBtn) fitBtn.addEventListener('click', fit);
  if (actualBtn) actualBtn.addEventListener('click', actualSize);
  if (zoomOutBtn) zoomOutBtn.addEventListener('click', () => zoomBy(1 / zoomStep));
  if (zoomInBtn) zoomInBtn.addEventListener('click', () => zoomBy(zoomStep));

  // Details: wide screens focus the side panel; narrow ones show a clone in
  // a modal bottom sheet (the rest of the page inert).
  const backdrop = document.getElementById('chart-sheet-backdrop');
  let lastOpener = null;
  let closeBtn = null;
  let madeInert = [];
  const setInert = (on) => {
    if (!on) {
      for (const el of madeInert) el.inert = false;
      madeInert = [];
      return;
    }
    for (const el of Array.from(document.body.children)) {
      if (el === sheet || el === backdrop || el.tagName === 'SCRIPT' || el.inert) continue;
      el.inert = on;
      madeInert.push(el);
    }
  };
  const openSheet = (clone) => {
    sheet.appendChild(clone);
    sheet.hidden = false;
    backdrop.hidden = false;
    setInert(true);
    closeBtn.focus({ preventScroll: true });
  };
  const closeSheet = () => {
    if (!sheet || sheet.hidden) return;
    for (const node of Array.from(sheet.children)) {
      if (node !== closeBtn) node.remove();
    }
    sheet.hidden = true;
    backdrop.hidden = true;
    setInert(false);
    if (lastOpener && document.contains(lastOpener)) lastOpener.focus({ preventScroll: true });
  };
  if (sheet && backdrop) {
    document.body.appendChild(backdrop);
    document.body.appendChild(sheet);
    closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'dpanel-sheet__close';
    closeBtn.textContent = 'Close';
    sheet.appendChild(closeBtn);
    closeBtn.addEventListener('click', closeSheet);
    backdrop.addEventListener('click', closeSheet);
    document.addEventListener('keydown', (e) => {
      if (sheet.hidden) return;
      if (e.key === 'Escape') { e.preventDefault(); closeSheet(); return; }
      if (e.key !== 'Tab') return;
      // Focus loop; the close button is always the first stop.
      const stops = [closeBtn, ...Array.from(sheet.querySelectorAll(
        'a[href], button, summary, input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )).filter((el) => el !== closeBtn && !el.hidden)];
      const first = stops[0], last = stops[stops.length - 1];
      const to = !sheet.contains(document.activeElement) ? first
        : e.shiftKey && document.activeElement === first ? last
          : !e.shiftKey && document.activeElement === last ? first : null;
      if (to) { e.preventDefault(); to.focus({ preventScroll: true }); }
    });
  }

  // The Details button sits beside the host's <summary>, never in it.
  for (const btn of chartSection.querySelectorAll('.chart__dpanel-btn')) {
    btn.hidden = false;
    btn.addEventListener('click', () => {
      const id = btn.dataset.nosDpanelBtn;
      if (!id) return;
      const panel = chartSection.querySelector('.chart__dpanel[data-nos-dpanel="' + CSS.escape(id) + '"]');
      if (!panel) return;
      lastOpener = btn;
      if (narrow.matches && closeBtn) {
        closeSheet();
        const clone = panel.cloneNode(true);
        clone.removeAttribute('tabindex');
        clone.removeAttribute('data-nos-dpanel');
        openSheet(clone);
        return;
      }
      const host = panel.closest('details');
      if (host && !host.open) host.open = true;
      // No native scrolling: the canvas pans to it.
      panel.focus({ preventScroll: true });
      revealFocus(panel);
    });
  }

  setMode();
  narrow.addEventListener('change', () => { closeSheet(); setMode(); });
})();

// Live chart values (ADR 0006 P1-37): one SSE stream; visible boxes are
// posted on change and every `renew` s, none while hidden, one POST at a
// time. Values: textContent only. A box not granted loses its live line;
// one without a value for 15 s shows its age (never a fresh look).
(() => {
  const chart = document.querySelector('.chart');
  if (!chart || !window.EventSource || !window.IntersectionObserver) return;
  const els = new Map(), seen = new Set();
  for (const el of chart.querySelectorAll('.chart__box--node,.chart__box--guest,.chart__box--host')) {
    const is = (k) => el.classList.contains('chart__box--' + k), a = el.querySelector('a.chart__name');
    const node = el.closest('.chart__node')?.querySelector('.chart__box--node .chart__name')?.title || '';
    const m = is('guest') && /^VM (\d+)$/.exec(el.querySelector('.chart__vmid')?.textContent);
    const h = a && /^\/hosts\/([a-z0-9._-]+)$/.exec(a.getAttribute('href'));
    const ref = is('node') ? { kind: 'node', name: node } : m ? { kind: 'guest', node, vmid: +m[1] }
      : !is('guest') && h ? { kind: 'host', id: h[1] } : null;
    const id = ref && Object.values(ref).join(':');
    if (ref && !els.has(id)) els.set(el.dataset.nosLive = id, { el, ref, v: {} });
  }
  if (!els.size) return;
  let viewer = '', renew = 10, timer = 0, es = null, busy = 0, again = 0;
  // Own clock: runs whatever the stream does (410, no hello, offline).
  setInterval(() => {
    for (const b of els.values()) if (b.t && Date.now() - b.at > 15e3) show(b, Math.round((Date.now() - b.at) / 1e3));
  }, 1e3);
  const send = async () => {
    clearTimeout(timer);
    const v = viewer;
    if (busy || !v) { again = busy; return; }
    busy = 1; again = 0;
    let gone = 0;
    const ids = document.hidden ? [] : [...seen].slice(0, 32);
    try {
      const res = await fetch('/chart/live/targets', {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ viewer: v, boxes: ids.map((id) => els.get(id).ref) }),
      });
      gone = res.status === 410;
      const g = res.ok && new Set((await res.json()).granted);
      // Denied (or over budget): drop the live line, the server value stays.
      for (const id of g ? ids : []) if (!g.has(id)) drop(els.get(id));
    } catch (_) { /* next renewal retries */ }
    busy = 0;
    if (gone && v === viewer) return open();
    if (again || v !== viewer) return send();
    timer = setTimeout(send, renew * 1000);
  };
  const mk = (p, c, t) => p.appendChild(Object.assign(document.createElement('span'), { className: c, textContent: t }));
  const drop = (b) => { if (b.t) { b.t.parentNode.remove(); b.t = null; b.v = {}; } };
  const show = (b, age) => {
    if (!b.t) {
      const l = mk(b.el, 'chart__line chart__line--live', '');
      mk(l, 'chart__line-name', 'Live');
      b.t = mk(l, 'chart__line-text', '');
    }
    const p = [['cpu', 'CPU'], ['ram', 'RAM'], ['disk', 'Disk']].filter(([k]) => typeof b.v[k] === 'number')
      .map(([k, l]) => l + ' ' + Math.round(b.v[k] * 100) + ' %');
    if (age) p.push('last observed ' + age + ' s ago');
    b.t.parentNode.classList.toggle('chart__line--stale', !!age);
    b.t.textContent = p.join(' · ');
  };
  const on = (name, f) => es.addEventListener(name, (e) => {
    try { const d = JSON.parse(e.data); if (d) f(d, els.get(d.id)); } catch (_) { /* ignored */ }
  });
  const open = () => {
    if (es) es.close();
    viewer = '';
    es = new EventSource('/chart/live/events');
    on('hello', (d) => { viewer = String(d.viewer || ''); if (d.renew > 0) renew = d.renew; send(); });
    on('value', (d, b) => {
      if (!b || typeof d.value !== 'number' || !['cpu', 'ram', 'disk'].includes(d.metric)) return;
      b.v[d.metric] = d.value;
      b.at = Date.now();
      show(b, 0);
    });
    on('age', (d, b) => { if (b && Number.isInteger(d.age)) show(b, d.age); });
  };
  const soon = () => { clearTimeout(timer); timer = setTimeout(send, 300); };
  const io = new IntersectionObserver((list) => {
    for (const en of list) seen[en.isIntersecting ? 'add' : 'delete'](en.target.dataset.nosLive);
    soon();
  });
  for (const b of els.values()) io.observe(b.el);
  document.addEventListener('visibilitychange', soon);
  window.addEventListener('pagehide', () => es && es.close());
  open();
})();

(() => {
  // webauthn.js is loaded only on pages with the add-host dialog (not on
  // the chart page); the dialog code below stops early without it.
  const w = typeof nebulaWebAuthn === 'undefined' ? null : nebulaWebAuthn;

  // Client-side text filter: the row's search text (id, name, endpoint,
  // OS) is built server side and lowercased there.
  const filter = document.getElementById('inventory-filter');
  if (filter) {
    filter.addEventListener('input', () => {
      const q = filter.value.trim().toLowerCase();
      for (const row of document.querySelectorAll('tbody tr[data-search]')) {
        row.hidden = q !== '' && !row.dataset.search.includes(q);
      }
    });
  }

  // A row click goes to the host page; the links inside the row keep
  // their own behaviour.
  for (const row of document.querySelectorAll('tbody tr[data-id]')) {
    row.addEventListener('click', (e) => {
      if (e.target.closest('a, button, input, select, textarea, td.select')) return;
      window.location.assign('/hosts/' + encodeURIComponent(row.dataset.id));
    });
  }

  // IP-aware natural comparison, a port of internal/web/ui/invsort:
  // IPs numerically (v4 before v6, IPs first), else case-insensitive
  // with digit runs as numbers ("node2" < "node10").
  const v4Re = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const v6GroupRe = /^[0-9a-f]{1,4}$/;
  const parseIPv6 = (s) => {
    let addr = s.toLowerCase();
    const v4 = addr.match(/:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      const o = v4.slice(1).map(Number);
      if (o.some((p) => p > 255)) return null;
      addr = addr.slice(0, -v4[0].length) +
        ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
    }
    const halves = addr.split('::');
    if (halves.length > 2) return null;
    const groups = (half) => {
      if (half === '') return [];
      const g = half.split(':');
      if (g.length > 8) return null;
      const out = [];
      for (const x of g) {
        if (!v6GroupRe.test(x)) return null;
        out.push(parseInt(x, 16));
      }
      return out;
    };
    if (halves.length === 2) {
      const head = groups(halves[0]);
      const tail = groups(halves[1]);
      if (!head || !tail || head.length + tail.length > 7) return null;
      return head.concat(new Array(8 - head.length - tail.length).fill(0), tail);
    }
    const full = groups(addr);
    return full && full.length === 8 ? full : null;
  };
  const parseIP = (s) => {
    const t = (s || '').trim();
    const m = t.match(v4Re);
    if (m) {
      const parts = m.slice(1).map(Number);
      if (parts.some((p) => p > 255)) return null;
      return { kind: 0, parts };
    }
    const v6 = parseIPv6(t);
    return v6 ? { kind: 1, parts: v6 } : null;
  };
  const ipCompare = (a, b) => {
    const pa = parseIP(a);
    const pb = parseIP(b);
    if (pa && pb) {
      if (pa.kind !== pb.kind) return pa.kind - pb.kind;
      for (let i = 0; i < pa.parts.length; i++) {
        if (pa.parts[i] !== pb.parts[i]) return pa.parts[i] - pb.parts[i];
      }
      return 0;
    }
    if (pa) return -1;
    if (pb) return 1;
    return naturalCompare(a, b);
  };
  const digitRun = (chars, i) => {
    let j = i;
    while (j < chars.length && chars[j] >= '0' && chars[j] <= '9') j++;
    let k = i;
    while (k < j && chars[k] === '0') k++;
    return { text: chars.slice(k, j).join(''), next: j };
  };
  const naturalCompare = (a, b) => {
    const ra = Array.from(a || '');
    const rb = Array.from(b || '');
    let i = 0;
    let j = 0;
    while (i < ra.length && j < rb.length) {
      const da = ra[i] >= '0' && ra[i] <= '9';
      const db = rb[j] >= '0' && rb[j] <= '9';
      if (da && db) {
        const na = digitRun(ra, i);
        const nb = digitRun(rb, j);
        let c = 0;
        if (na.text.length !== nb.text.length) c = na.text.length - nb.text.length;
        else if (na.text !== nb.text) c = na.text < nb.text ? -1 : 1;
        if (c !== 0) return c;
        i = na.next;
        j = nb.next;
        continue;
      }
      const la = ra[i].toLowerCase();
      const lb = rb[j].toLowerCase();
      if (la !== lb) return la < lb ? -1 : 1;
      i++;
      j++;
    }
    return ra.length - rb.length;
  };

  // Sortable columns: a header button toggles the order and sets
  // aria-sort. Host uses the IP-aware order, Last seen the row's data-ts
  // (ms, empty when never seen). Re-appending rows keeps the filter.
  const table = document.querySelector('table.inventory');
  if (table) {
    const tbody = table.querySelector('tbody');
    const sortDefs = {
      host: {
        value: (row) => {
          const name = row.querySelector('.host-name');
          return name ? name.textContent : (row.dataset.id || '');
        },
        compare: ipCompare,
      },
      os: { value: (row) => row.dataset.os || '', compare: naturalCompare },
      status: { value: (row) => row.dataset.status || '', compare: naturalCompare },
      updates: { value: (row) => Number(row.dataset.updates || '0'), compare: (a, b) => a - b },
      lastseen: {
        value: (row, dir) => {
          const ts = row.dataset.ts;
          if (ts === undefined || ts === '') return dir === 'ascending' ? Infinity : -Infinity;
          return Number(ts);
        },
        compare: (a, b) => a - b,
      },
    };
    let sortKey = null;
    let sortDir = 'ascending';
    const applySort = (key, dir) => {
      sortKey = key;
      sortDir = dir;
      for (const th of table.querySelectorAll('th[aria-sort]')) {
        const btn = th.querySelector('button[data-sort]');
        th.setAttribute('aria-sort', btn && btn.dataset.sort === key ? dir : 'none');
      }
      const def = sortDefs[key];
      const rows = Array.from(tbody.querySelectorAll('tr[data-id]'));
      rows.sort((a, b) => def.compare(def.value(a, dir), def.value(b, dir)));
      if (dir === 'descending') rows.reverse();
      for (const row of rows) tbody.appendChild(row);
    };
    for (const btn of table.querySelectorAll('th button[data-sort]')) {
      btn.addEventListener('click', () => {
        const key = btn.dataset.sort;
        if (sortKey === key) {
          applySort(key, sortDir === 'ascending' ? 'descending' : 'ascending');
        } else {
          applySort(key, 'ascending');
        }
      });
    }
  }

  // Selection and bulk actions: bulkbar.js.

  const dialog = document.getElementById('add-host-dialog');
  const form = document.getElementById('host-form');
  if (!dialog || !form || !w) return; // read-only page: no inventory store configured

  const idInput = document.getElementById('host-id');
  const nameInput = document.getElementById('host-display-name');
  const envSelect = document.getElementById('host-environment');
  const critSelect = document.getElementById('host-criticality');
  const endpointsInput = document.getElementById('host-endpoints');
  const tagsInput = document.getElementById('host-tags');
  const submit = document.getElementById('host-submit');
  const cancel = document.getElementById('host-cancel');

  // "Add to managed hosts" from a network asset: prefill the dialog, and
  // link the asset to the host once it exists.
  let prefillAsset = null;
  if (form.dataset.prefill) {
    try {
      const p = JSON.parse(form.dataset.prefill);
      prefillAsset = p.asset;
      idInput.value = p.id || '';
      nameInput.value = p.display_name || '';
      endpointsInput.value = (p.endpoints || []).join('\n');
    } catch (_) { /* no prefill */ }
  }

  const open = () => {
    w.show('', false);
    dialog.showModal();
    idInput.focus();
  };
  for (const b of document.querySelectorAll('.add-host')) {
    b.addEventListener('click', (e) => {
      e.preventDefault();
      open();
    });
  }
  cancel.addEventListener('click', () => dialog.close());
  // Coming from "Add to managed hosts": show the prefilled dialog right away.
  if (prefillAsset && !dialog.open) open();
  dialog.addEventListener('cancel', () => w.show('', false));

  function readForm() {
    const endpoints = endpointsInput.value
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s !== '');
    const tags = {};
    for (const line of tagsInput.value.split('\n')) {
      const t = line.trim();
      if (t === '') continue;
      const i = t.indexOf('=');
      if (i <= 0 || i === t.length - 1) throw new Error('Tags must be one key=value per line.');
      tags[t.slice(0, i).trim()] = t.slice(i + 1).trim();
    }
    return {
      id: idInput.value.trim(),
      display_name: nameInput.value.trim(),
      environment: envSelect.value,
      criticality: critSelect.value,
      endpoints,
      tags,
    };
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let body;
    try {
      body = readForm();
    } catch (err) {
      w.show(err.message, true);
      return;
    }
    submit.disabled = true;
    try {
      try {
        await w.post('/inventory/hosts', body);
      } catch (err) {
        if (err.data && err.data.duplicate_endpoint) {
          // Warn, do not block: ask for the "Add anyway" confirmation
          // and retry with the confirmation set.
          if (!confirm(err.message + '\n\nAdd anyway?')) return;
          await w.post('/inventory/hosts', Object.assign({}, body, { confirm_duplicate: true }));
        } else {
          throw err;
        }
      }
      if (prefillAsset) {
        await w.post('/network/a/link', { asset: prefillAsset, host: body.id });
        window.location.assign('/network/a/' + encodeURIComponent(prefillAsset));
        return;
      }
      window.location.assign('/hosts/' + encodeURIComponent(body.id));
    } catch (err) {
      w.show(err.message || 'The change failed.', true);
    } finally {
      submit.disabled = false;
    }
  });
})();
