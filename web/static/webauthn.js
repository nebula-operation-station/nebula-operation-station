// SPDX-License-Identifier: AGPL-3.0-or-later
// WebAuthn helpers for the login and setup pages. The executor produces
// the options and verifies the responses; this file only converts between
// base64url JSON and the browser's ArrayBuffers.
'use strict';

const nebulaWebAuthn = (() => {
  function decode(s) {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function encode(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function requestOptions(o) {
    const p = Object.assign({}, o.publicKey);
    p.challenge = decode(p.challenge);
    p.allowCredentials = (p.allowCredentials || []).map((c) => Object.assign({}, c, { id: decode(c.id) }));
    return { publicKey: p };
  }

  function creationOptions(o) {
    const p = Object.assign({}, o.publicKey);
    p.challenge = decode(p.challenge);
    p.user = Object.assign({}, p.user, { id: decode(p.user.id) });
    p.excludeCredentials = (p.excludeCredentials || []).map((c) => Object.assign({}, c, { id: decode(c.id) }));
    return { publicKey: p };
  }

  function assertionJSON(c) {
    return {
      id: c.id,
      rawId: encode(c.rawId),
      type: c.type,
      response: {
        clientDataJSON: encode(c.response.clientDataJSON),
        authenticatorData: encode(c.response.authenticatorData),
        signature: encode(c.response.signature),
        userHandle: c.response.userHandle ? encode(c.response.userHandle) : null,
      },
      clientExtensionResults: c.getClientExtensionResults(),
    };
  }

  function attestationJSON(c) {
    const r = {
      clientDataJSON: encode(c.response.clientDataJSON),
      attestationObject: encode(c.response.attestationObject),
    };
    if (typeof c.response.getTransports === 'function') r.transports = c.response.getTransports();
    return { id: c.id, rawId: encode(c.rawId), type: c.type, response: r, clientExtensionResults: c.getClientExtensionResults() };
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    if (!res.ok) {
      const err = new Error(data.error || ('request failed (' + res.status + ')'));
      err.data = data;
      throw err;
    }
    return data;
  }

  function show(text, isError) {
    const m = document.getElementById('message');
    m.textContent = text; // never innerHTML: messages may echo server text
    m.classList.toggle('message--error', !!isError);
  }

  // register runs the full registration flow against the existing /setup
  // endpoints: the one-time code, the new key, and — when keys are
  // registered already — a confirming key. statusEl receives the current
  // step; the promise resolves with the /setup/finish answer.
  async function register(code, statusEl) {
    const status = (text) => {
      statusEl.textContent = text; // never innerHTML
      statusEl.classList.remove('message--error');
    };
    const begin = await post('/setup/begin', { code });
    status('Touch the new security key…');
    const created = await navigator.credentials.create(creationOptions(begin.creation_options));
    const body = { registration_id: begin.registration_id, attestation: attestationJSON(created) };
    if (begin.authorization_options) {
      status('Now confirm with a security key that is already registered…');
      const confirm = await navigator.credentials.get(requestOptions(begin.authorization_options));
      body.assertion = assertionJSON(confirm);
    }
    return post('/setup/finish', body);
  }

  // --- Privileged session display (ADR 0007 E20) -------------------
  //
  // The topbar shows the executor-reported session state. Polling is
  // read-only (GET /privileged/session); the only state-changing call is
  // the explicit Extend click, which runs one fresh WebAuthn assertion
  // (begin -> credentials.get -> finish). At most one flow runs at a
  // time, so one click extends the session exactly once and extensions
  // never accumulate. Nothing here renews the session on activity.
  //
  // The state machine mirrors internal/web/ui/session one-to-one
  // (Next, FormatRemaining, CanExtend, Extending, StateLabel).

  const SESSION_POLL_SECONDS = 30; // read-only refresh of the state
  const SESSION_LOW_SECONDS = 60;  // session.LowThreshold

  function sessionStateLabel(s) { // session.StateLabel
    switch (s) {
      case 'active': return 'Session';
      case 'expired': return 'Session expired';
      case 'none': return 'No session';
      default: return 'Session unavailable';
    }
  }

  function sessionFormatRemaining(sec) { // session.FormatRemaining
    if (sec < 0) sec = 0;
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
    if (m > 0) return m + 'm ' + String(s).padStart(2, '0') + 's';
    return s + 's';
  }

  // sessionNext mirrors session.Next: pure, derived from the poll and
  // the clock only — repeated polls (browsing activity) can never renew
  // a session or move it back from expired to active.
  function sessionNext(prev, p, nowSec) {
    if (!p.available) return 'unknown';
    if (p.active) {
      if (!p.expiry_unix || nowSec >= p.expiry_unix) return 'expired';
      return 'active';
    }
    return (prev === 'active' || prev === 'expired') ? 'expired' : 'none';
  }

  function initSessionDisplay() {
    const el = document.getElementById('session-display');
    if (!el) return; // bare pages (login, setup): no session display
    const stateEl = document.getElementById('session-state');
    const timeEl = document.getElementById('session-time');
    const errEl = document.getElementById('session-error');
    const btn = document.getElementById('session-extend');

    let state = 'unknown';  // previously displayed state
    let expiry = 0;         // executor-reported expiry, unix seconds
    let inFlight = false;   // at most one assertion flow (extend once)
    let tickTimer = 0;
    let firstPoll = true;

    function stopTick() {
      if (tickTimer) { clearInterval(tickTimer); tickTimer = 0; }
    }

    function manageTick() {
      if (state === 'active') {
        if (!tickTimer) tickTimer = setInterval(tick, 1000);
      } else {
        stopTick();
      }
    }

    function tick() {
      const rem = expiry - Math.floor(Date.now() / 1000);
      if (rem <= 0) {
        // The executor-reported expiry has passed: show the expired
        // state locally; the next poll confirms it.
        state = 'expired';
        render();
        return;
      }
      timeEl.textContent = sessionFormatRemaining(rem);
      el.classList.toggle('session-display--low', rem <= SESSION_LOW_SECONDS);
    }

    function render() {
      el.hidden = false;
      el.dataset.state = state;
      stateEl.textContent = sessionStateLabel(state);
      // session.CanExtend: active and expired offer the Extend action.
      const extendable = state === 'active' || state === 'expired';
      btn.hidden = !extendable || inFlight;
      btn.disabled = inFlight;
      btn.textContent = inFlight ? 'Verifying…' : 'Extend session';
      if (state !== 'active') {
        timeEl.textContent = '';
        el.classList.remove('session-display--low');
      }
      manageTick();
    }

    function showError(text) {
      errEl.textContent = text; // never innerHTML
      errEl.hidden = false;
    }

    function clearError() {
      errEl.textContent = '';
      errEl.hidden = true;
    }

    async function poll() {
      let p;
      try {
        const res = await fetch('/privileged/session', { credentials: 'same-origin' });
        if (!res.ok) throw new Error(String(res.status));
        p = await res.json();
      } catch (_) {
        p = { active: false, available: false }; // fail closed to unknown
      }
      const prev = state;
      state = sessionNext(state, p, Math.floor(Date.now() / 1000));
      if (p.active && p.expiry_unix) expiry = p.expiry_unix;
      if (state === 'active') tick(); // show the time immediately
      if (firstPoll || state !== prev || state === 'active') {
        firstPoll = false;
        render();
      }
      if (p.available) clearError();
    }

    btn.addEventListener('click', async () => {
      // session.Extending: one assertion flow at a time, so one click
      // extends the session exactly once.
      if (inFlight) return;
      inFlight = true;
      clearError();
      render();
      try {
        const begin = await post('/privileged/begin');
        const cred = await navigator.credentials.get(requestOptions(begin.options));
        await post('/privileged/finish', { assertion: assertionJSON(cred) });
        await poll(); // the executor now reports the new expiry
      } catch (e) {
        showError(e.name === 'NotAllowedError'
          ? 'Verification cancelled.'
          : (e.message || 'Could not extend the session.'));
      } finally {
        inFlight = false;
        render();
      }
    });

    poll();
    setInterval(poll, SESSION_POLL_SECONDS * 1000);
  }

  initSessionDisplay();

  return { requestOptions, creationOptions, assertionJSON, attestationJSON, post, show, register };
})();
