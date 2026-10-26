// SPDX-License-Identifier: AGPL-3.0-or-later
// In-place run helper (job ui5), shared by the inventory bulk bar and
// the host page quick-action bar.
//
// ensureSession() asks the server whether a privileged session is open
// (GET /privileged/session) and, if not, opens it with one key tap —
// the same POST /privileged/begin + /privileged/finish as the
// dashboard.
//
// runOperation({action, hosts, params}) creates the operation through
// the normal create path (POST /operations/create) and, while it is
// pending, approves it in place: the WebAuthn assertion over the
// options the create response carries, and the typed host count for
// CRITICAL operations (asked inline, no browser dialog). It returns
// the operation ID.
//
// followStatus(container, ids) shows the progress of the operations in
// container and polls the read-only GET /operations/{id}/status until
// they finish, with a link to each operation page.
//
// All text is set with textContent; server text is never parsed as
// HTML.
'use strict';

const nebulaRunOp = (() => {
  const w = nebulaWebAuthn;

  const TERMINAL = new Set(['finished', 'failed', 'aborted']);

  // setMsg writes the status line (a <p class="message">).
  function setMsg(el, text, isError) {
    if (!el) return;
    el.textContent = text;
    el.classList.toggle('message--error', !!isError);
  }

  // ensureSession opens the privileged session while it is not open.
  async function ensureSession(statusEl) {
    let st;
    try {
      const res = await fetch('/privileged/session', { credentials: 'same-origin' });
      if (!res.ok) throw new Error(String(res.status));
      st = await res.json();
    } catch (_) {
      throw new Error('Could not check the privileged session.');
    }
    if (!st.available) {
      throw new Error('The executor is unavailable; open the session from the dashboard.');
    }
    if (st.active) return;
    setMsg(statusEl, 'Touch your security key to open the privileged session…');
    const begin = await w.post('/privileged/begin');
    const cred = await navigator.credentials.get(w.requestOptions(begin.options));
    await w.post('/privileged/finish', { assertion: w.assertionJSON(cred) });
  }

  // askTypedCount asks for the host count inline (no browser dialog)
  // and resolves with the typed number, or null when cancelled.
  function askTypedCount(container, n) {
    return new Promise((resolve) => {
      const box = document.createElement('div');
      box.className = 'inline-confirm';
      const label = document.createElement('label');
      label.textContent = 'Number of hosts (type it to confirm a CRITICAL operation) ';
      const input = document.createElement('input');
      input.type = 'text';
      input.inputMode = 'numeric';
      input.autocomplete = 'off';
      label.appendChild(input);
      const ok = document.createElement('button');
      ok.type = 'button';
      ok.className = 'button';
      ok.textContent = 'Confirm';
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'button button--secondary';
      cancel.textContent = 'Cancel';
      const done = (v) => {
        box.remove();
        resolve(v);
      };
      ok.addEventListener('click', () => {
        const v = parseInt(input.value, 10);
        if (v === n) done(v);
        else input.value = '';
      });
      cancel.addEventListener('click', () => done(null));
      box.appendChild(label);
      box.appendChild(ok);
      box.appendChild(cancel);
      container.appendChild(box);
      input.focus();
    });
  }

  // approveInPlace approves one pending operation in place: the typed
  // host count (CRITICAL) and the security key over its own options.
  async function approveInPlace(op, hosts, statusEl, container) {
    let typed = 0;
    if (op.requirement === 'assertion_verified_typed_count') {
      const v = await askTypedCount(container, hosts.length);
      if (v === null) throw new Error('Approval cancelled; the operation stays pending.');
      typed = v;
    }
    setMsg(statusEl, 'Touch your security key…');
    const cred = await navigator.credentials.get(w.requestOptions(op.options));
    await w.post('/operations/approve', {
      id: op.id,
      assertion: w.assertionJSON(cred),
      typed_count: typed,
    });
  }

  // runOperation creates the operation and, while pending, approves it
  // in place. Returns the operation ID.
  async function runOperation(spec, statusEl, container) {
    const created = await w.post('/operations/create', {
      action: spec.action,
      hosts: spec.hosts,
      params: spec.params || {},
    });
    if (created.state !== 'pending') return created.id;
    if (!created.options) {
      throw new Error('This operation needs approval on the executor host: run `nebula pending` and `nebula approve` there.');
    }
    await approveInPlace(created, spec.hosts, statusEl, container);
    return created.id;
  }

  // followStatus shows the progress of the operations in container and
  // polls until they finish. With reloadWhenDone the page reloads once
  // every operation is in a terminal state (simple table refresh).
  function followStatus(container, ids, opts) {
    opts = opts || {};
    const line = document.createElement('p');
    line.className = 'message';
    line.setAttribute('role', 'status');
    line.setAttribute('aria-live', 'polite');
    const links = document.createElement('p');
    links.className = 'runop-links';
    container.appendChild(line);
    container.appendChild(links);
    const stateOf = {};
    const done = new Set();
    const label = (id) => {
      const st = stateOf[id];
      if (!st) return id + ': …';
      const parts = Object.keys(st.hosts && st.hosts.by_state || {}).sort().map((k) => st.hosts.by_state[k] + ' ' + k);
      return id + ': ' + st.state + (parts.length ? ' (' + parts.join(', ') + ')' : '');
    };
    const render = (prefix) => {
      line.textContent = (prefix ? prefix + ' ' : '') + ids.map(label).join('  ·  ');
      links.textContent = '';
      for (const id of ids) {
        if (!done.has(id)) continue;
        const a = document.createElement('a');
        a.href = '/operations/' + encodeURIComponent(id);
        a.textContent = id;
        links.appendChild(a);
        links.appendChild(document.createTextNode(' '));
      }
    };
    render();
    let timer = null;
    const tick = async () => {
      let allDone = true;
      for (const id of ids) {
        if (done.has(id)) continue;
        let st;
        try {
          const res = await fetch('/operations/' + encodeURIComponent(id) + '/status', { credentials: 'same-origin' });
          if (!res.ok) throw new Error(String(res.status));
          st = await res.json();
        } catch (_) {
          allDone = false;
          continue;
        }
        stateOf[id] = st;
        if (TERMINAL.has(st.state)) done.add(id);
        else allDone = false;
      }
      render();
      if (allDone) {
        clearInterval(timer);
        if (opts.reloadWhenDone) {
          line.textContent = 'All operations finished; reloading…';
          setTimeout(() => window.location.reload(), 1500);
        }
      }
    };
    timer = setInterval(tick, 2000);
    tick();
  }

  return { ensureSession, runOperation, approveInPlace, askTypedCount, followStatus, setMsg };
})();
