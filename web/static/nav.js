// SPDX-License-Identifier: AGPL-3.0-or-later
// Navigation actions. POSTs go through fetch: a plain form would send
// "Origin: null" (Referrer-Policy no-referrer) and be rejected.
'use strict';

(() => {
  // The drawer styles below only apply to html.js: without JavaScript the
  // sidebar stays a static top bar on phones, so the navigation remains
  // reachable.
  document.documentElement.classList.add('js');

  const app = document.querySelector('.app');

  const logout = document.getElementById('logout');
  if (logout) {
    logout.addEventListener('click', async () => {
      logout.disabled = true;
      try {
        await fetch('/logout', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      } finally {
        window.location.assign('/login');
      }
    });
  }

  // Desktop: the toggle collapses the sidebar to icons only. The state is
  // remembered in the nebula_nav cookie (POST /ui/nav) so the server
  // renders the right state on the next load; the DOM class is updated
  // here for the current one and rolled back if the request fails.
  const collapse = document.getElementById('nav-collapse');
  if (collapse && app) {
    const setIcon = (collapsed) => {
      const use = collapse.querySelector('use');
      if (use) {
        use.setAttribute('href', '/static/icons.svg#i-panel-left-' + (collapsed ? 'open' : 'close'));
      }
    };
    const apply = (collapsed) => {
      app.classList.toggle('app--nav-collapsed', collapsed);
      collapse.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      collapse.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
      setIcon(collapsed);
    };
    collapse.addEventListener('click', () => {
      const collapsed = !app.classList.contains('app--nav-collapsed');
      apply(collapsed);
      fetch('/ui/nav', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ collapsed }) })
        .then((r) => {
          if (!r.ok) {
            throw new Error('status ' + r.status);
          }
        })
        .catch(() => apply(!collapsed));
    });
  }

  // Phones: the sidebar is an off-canvas drawer opened by the menu button
  // in the top bar. Escape closes it and focus returns to the button.
  const menu = document.getElementById('nav-menu');
  const close = document.getElementById('nav-close');
  const backdrop = document.getElementById('nav-backdrop');
  if (menu && app && backdrop) {
    const openDrawer = () => {
      app.classList.add('app--drawer-open');
      menu.setAttribute('aria-expanded', 'true');
      menu.setAttribute('aria-label', 'Close navigation');
      if (close) {
        close.focus();
      }
    };
    const closeDrawer = () => {
      app.classList.remove('app--drawer-open');
      menu.setAttribute('aria-expanded', 'false');
      menu.setAttribute('aria-label', 'Open navigation');
      menu.focus();
    };
    menu.addEventListener('click', () => {
      if (app.classList.contains('app--drawer-open')) {
        closeDrawer();
      } else {
        openDrawer();
      }
    });
    if (close) {
      close.addEventListener('click', closeDrawer);
    }
    backdrop.addEventListener('click', closeDrawer);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && app.classList.contains('app--drawer-open')) {
        closeDrawer();
      }
    });
  }

  // On narrow screens the full placeholder is clipped inside the search
  // field, so swap in a shorter one; the long text stays on wide screens.
  const search = document.querySelector('.topbar__search input');
  if (search) {
    const long = search.getAttribute('placeholder') || '';
    const short = 'Search hosts…';
    const narrow = window.matchMedia('(max-width: 600px)');
    const apply = () => {
      search.placeholder = narrow.matches ? short : long;
    };
    apply();
    narrow.addEventListener('change', apply);
  }
})();

// --- Topbar privileged-session display (ADR 0007 E20) ----------------
//
// It lives in nav.js because nav.js is the one script every non-bare page
// loads; pages whose own scripts do not include webauthn.js still get the
// display, and the assertion helpers are loaded on the first Extend click.
//
// The server is the source of truth: GET /privileged/session answers with
// the display it computed (internal/web/ui/session.View: state, label,
// remaining_seconds, extendable, low_threshold_seconds). This file only
// renders that view, counts the reported remaining seconds down and polls
// again; it derives no session state of its own. It sends the state it
// shows as ?prev= so the server can tell "expired" from "never opened".
//
// Polls are read-only and marked passive (X-Nebula-Passive, see
// internal/web/auth.PassiveHeader), so an open tab is not user activity
// and cannot keep the web login alive. Polling pauses while the tab is
// hidden and refreshes when it becomes visible.
//
// The only state-changing call is the explicit Extend click, which runs
// one fresh WebAuthn assertion (begin -> credentials.get -> finish). At
// most one flow runs at a time, so one click extends the session exactly
// once. Every poll carries a sequence number; an answer that is not for
// the latest poll is dropped, so a stale answer can never overwrite the
// state after an extend.
(() => {
  const el = document.getElementById('session-display');
  if (!el) return; // bare pages (login, setup): no session display
  const stateEl = document.getElementById('session-state');
  const timeEl = document.getElementById('session-time');
  const errEl = document.getElementById('session-error');
  const btn = document.getElementById('session-extend');
  if (!stateEl || !timeEl || !errEl || !btn) return;

  const POLL_MS = 30000;            // background refresh of the state
  const PASSIVE_HEADER = 'X-Nebula-Passive';
  const STATES = ['unknown', 'none', 'active', 'expired'];
  const MAX_SECONDS = 7 * 24 * 3600; // sanity bound for any duration
  const MAX_LABEL = 64;
  // Fail closed: anything unexpected is shown as unknown, without action.
  const UNKNOWN = Object.freeze({
    state: 'unknown', label: 'Session unavailable', remaining: 0, extendable: false, low: 0,
  });

  let view = UNKNOWN;
  let deadline = 0;        // Date.now() at which the remaining time hits 0
  let expiryPolled = false; // the poll at zero was sent for this view
  let inFlight = false;    // at most one assertion flow (extend once)
  let seq = 0;             // sequence number of the latest poll
  let pollTimer = 0;
  let tickTimer = 0;

  // parseView validates the poll answer field by field and returns the
  // unknown view on anything malformed.
  function parseView(p) {
    if (!p || typeof p !== 'object') return UNKNOWN;
    const s = p.state;
    const l = p.label;
    const r = p.remaining_seconds;
    const x = p.extendable;
    const t = p.low_threshold_seconds;
    if (typeof s !== 'string' || STATES.indexOf(s) < 0) return UNKNOWN;
    if (typeof l !== 'string' || l.length === 0 || l.length > MAX_LABEL) return UNKNOWN;
    if (!Number.isInteger(r) || r < 0 || r > MAX_SECONDS) return UNKNOWN;
    if (!Number.isInteger(t) || t < 0 || t > MAX_SECONDS) return UNKNOWN;
    if (typeof x !== 'boolean') return UNKNOWN;
    return { state: s, label: l, remaining: r, extendable: x, low: t };
  }

  // formatRemaining renders seconds as "1h 04m", "12m 09s" or "45s".
  function formatRemaining(sec) {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
    if (m > 0) return m + 'm ' + String(s).padStart(2, '0') + 's';
    return s + 's';
  }

  // loadWebAuthn returns the assertion helpers of webauthn.js, loading
  // that file (same origin, allowed by script-src 'self') on pages that do
  // not include it. The global must not be declared twice, so the file is
  // only added when it is not there yet.
  function loadWebAuthn() {
    if (typeof nebulaWebAuthn !== 'undefined') return Promise.resolve(nebulaWebAuthn);
    return new Promise((resolve, reject) => {
      const fail = () => reject(new Error('Could not load the security key helper.'));
      const s = document.createElement('script');
      s.src = '/static/webauthn.js';
      s.addEventListener('load', () => {
        if (typeof nebulaWebAuthn !== 'undefined') resolve(nebulaWebAuthn); else fail();
      });
      s.addEventListener('error', fail);
      document.head.appendChild(s);
    });
  }

  function stopTick() {
    if (tickTimer) { clearInterval(tickTimer); tickTimer = 0; }
  }

  // tick counts the server-reported remaining time down. At zero it asks
  // the server once; the server decides whether the session expired.
  function tick() {
    const rem = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    timeEl.textContent = formatRemaining(rem);
    el.classList.toggle('session-display--low', rem <= view.low);
    if (rem === 0 && !expiryPolled && !document.hidden && !inFlight) {
      expiryPolled = true;
      poll();
    }
  }

  function render() {
    el.hidden = false;
    el.dataset.state = view.state;
    stateEl.textContent = view.label; // text only
    btn.hidden = !view.extendable && !inFlight;
    btn.disabled = inFlight;
    btn.textContent = inFlight ? 'Verifying…' : 'Extend session';
    if (view.state === 'active') {
      tick();
      if (!tickTimer) tickTimer = setInterval(tick, 1000);
    } else {
      stopTick();
      timeEl.textContent = '';
      el.classList.remove('session-display--low');
    }
  }

  function showError(text) {
    errEl.textContent = text; // text only
    errEl.hidden = false;
  }

  function clearError() {
    errEl.textContent = '';
    errEl.hidden = true;
  }

  function apply(next) {
    view = next;
    deadline = Date.now() + next.remaining * 1000;
    expiryPolled = false;
    if (next.state !== 'unknown') clearError();
    render();
  }

  async function poll() {
    const mine = ++seq;
    let next;
    try {
      const res = await fetch('/privileged/session?prev=' + encodeURIComponent(view.state), {
        credentials: 'same-origin',
        headers: { [PASSIVE_HEADER]: '1' },
      });
      if (!res.ok) throw new Error(String(res.status));
      next = parseView(await res.json());
    } catch (_) {
      next = UNKNOWN; // fail closed
    }
    if (mine !== seq) return; // a newer poll or an extend superseded this one
    apply(next);
  }

  // backgroundPoll is the interval and visibility refresh. It does not run
  // while the tab is hidden or an assertion flow is in progress.
  function backgroundPoll() {
    if (document.hidden || inFlight) return;
    poll();
  }

  function startPolling() {
    if (!pollTimer) pollTimer = setInterval(backgroundPoll, POLL_MS);
  }

  function stopPolling() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = 0; }
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopPolling();
      stopTick();
    } else {
      backgroundPoll();
      startPolling();
    }
  });

  btn.addEventListener('click', async () => {
    // One assertion flow at a time: one click extends exactly once.
    if (inFlight) return;
    inFlight = true;
    seq++; // drop the answer of any poll that is still under way
    clearError();
    render();
    let ok = false;
    try {
      const w = await loadWebAuthn();
      const begin = await w.post('/privileged/begin');
      const cred = await navigator.credentials.get(w.requestOptions(begin.options));
      await w.post('/privileged/finish', { assertion: w.assertionJSON(cred) });
      ok = true;
    } catch (e) {
      showError(e && e.name === 'NotAllowedError'
        ? 'Verification cancelled.'
        : ((e && e.message) || 'Could not extend the session.'));
    } finally {
      inFlight = false;
      render();
    }
    if (ok) await poll(); // the server now reports the new expiry
  });

  if (!document.hidden) {
    poll();
    startPolling();
  }
})();
