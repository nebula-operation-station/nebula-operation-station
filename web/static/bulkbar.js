// SPDX-License-Identifier: AGPL-3.0-or-later
// Inventory bulk action bar (job ux01): selection state, the one-click
// refresh, the inline confirms and the clearance that keeps the last
// rows and focused controls out from under the fixed bar.
(() => {
  'use strict';
  // Selection and bulk actions on the selected hosts.
  const bulkbar = document.getElementById('bulkbar');
  if (!bulkbar) return;
  const filter = document.getElementById('inventory-filter');
  const boxes = () => Array.from(document.querySelectorAll('input.host-select'));
  const selected = () => boxes().filter((b) => b.checked).map((b) => b.value);
  const all = document.getElementById('select-all');
  const count = document.getElementById('bulk-count');
  const msg = document.getElementById('bulk-message');
  const toggle = document.getElementById('bulkbar-toggle');
  // A fresh selection starts collapsed (phones: table stays visible).
  const setCollapsed = () => {
    bulkbar.classList.remove('bulkbar--expanded');
    if (toggle) toggle.setAttribute('aria-expanded', 'false');
  };
  const update = () => {
    const n = selected().length;
    const wasHidden = bulkbar.hidden;
    bulkbar.hidden = n === 0;
    count.textContent = n + ' selected';
    if (n > 0 && wasHidden) setCollapsed();
    const shown = boxes().filter((b) => !b.closest('tr').hidden);
    all.checked = shown.length > 0 && shown.every((b) => b.checked);
    clearFocus();
  };
  if (toggle) {
    toggle.addEventListener('click', () => {
      const expanded = bulkbar.classList.toggle('bulkbar--expanded');
      toggle.setAttribute('aria-expanded', String(expanded));
    });
  }
  // scroll-padding-bottom only applies when a scroll happens, so a
  // focused control can still sit under the fixed bar (Space on a row
  // checkbox near the viewport bottom, the sheet expanding, tabbing to
  // a covered control). Move a covered focused element above the bar.
  const clearFocus = () => {
    const el = document.activeElement;
    if (!el || el === document.body || el === document.documentElement || bulkbar.hidden || bulkbar.contains(el)) return;
    const r = el.getBoundingClientRect();
    const top = bulkbar.getBoundingClientRect().top;
    if (r.bottom > top) window.scrollBy(0, r.bottom - top + 8);
  };
  // The bar is fixed at every width, so it would cover the last rows.
  // Measure the distance from the bar's top to the bottom of the
  // viewport into --bulkbar-h; app.css uses it as bottom padding of
  // .main and scroll-padding-bottom of the scroll container. The
  // ResizeObserver catches height changes (toggle, inline confirms,
  // text wrap, hidden); resize catches viewport changes.
  const setBarClearance = () => {
    const r = bulkbar.getBoundingClientRect();
    let h = 0;
    if (!bulkbar.hidden) {
      if (r.top <= 0) {
        // The sheet is at least as tall as the viewport (high browser
        // zoom): it covers the visible bottom area, so clear up to its
        // bottom edge instead of 0.
        h = Math.max(0, Math.ceil(Math.min(r.bottom, innerHeight)));
      } else {
        h = Math.max(0, Math.ceil(innerHeight - r.top));
      }
    }
    document.documentElement.style.setProperty('--bulkbar-h', h + 'px');
    clearFocus();
  };
  setBarClearance();
  new ResizeObserver(setBarClearance).observe(bulkbar);
  window.addEventListener('resize', setBarClearance);
  document.addEventListener('focusin', clearFocus);
  for (const b of boxes()) b.addEventListener('change', update);
  all.addEventListener('change', () => {
    for (const b of boxes()) {
      if (!b.closest('tr').hidden) b.checked = all.checked; // only what the filter shows
    }
    update();
  });
  // Rows the filter hides are unselected: no action on unseen hosts.
  if (filter) {
    filter.addEventListener('input', () => {
      for (const b of boxes()) {
        if (b.closest('tr').hidden) b.checked = false;
      }
      update();
    });
  }
  // One-click refresh: open the privileged session, create the reads,
  // approve in place, follow the status, reload when done.
  document.getElementById('bulk-refresh').addEventListener('click', async (e) => {
    const hosts = selected();
    if (hosts.length === 0) return;
    e.target.disabled = true;
    msg.textContent = '';
    msg.classList.remove('message--error');
    try {
      await nebulaRunOp.ensureSession(msg);
      msg.textContent = 'Refreshing ' + hosts.length + ' hosts…';
      const body = new URLSearchParams();
      for (const h of hosts) body.append('host', h);
      const res = await fetch('/inventory/refresh', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      const text = await res.text(); // text only; server text is never HTML
      let data = null;
      try { data = JSON.parse(text); } catch (_) { /* not JSON */ }
      if (!res.ok || !data) {
        throw new Error((data && data.error) || text.trim() || ('Request failed (' + res.status + ')'));
      }
      if (data.operations.length === 0) {
        throw new Error('No operation could be created for the selected hosts.');
      }
      for (const op of data.operations) {
        if (op.state !== 'pending' || !op.options) continue;
        await nebulaRunOp.approveInPlace(op, hosts, msg, bulkbar);
      }
      nebulaRunOp.followStatus(bulkbar, data.operations.map((o) => o.id), { reloadWhenDone: true });
    } catch (err) {
      msg.textContent = err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not refresh.');
      msg.classList.add('message--error');
      e.target.disabled = false;
    }
  });
  // "Schedule refresh…": the schedules page with the read actions and
  // hosts prefilled (6 h / 30 days); approval happens there.
  document.getElementById('bulk-schedule').addEventListener('click', () => {
    const hosts = selected();
    if (hosts.length === 0) return;
    const q = new URLSearchParams();
    for (const a of ['core.facts', 'package.list_updates', 'docker.list', 'service.list']) q.append('action', a);
    for (const h of hosts) q.append('host', h);
    q.set('interval', '360');
    q.set('days', '30');
    window.location.assign('/schedules?' + q.toString());
  });
  // "Reboot…" confirms inline, creates one system.reboot operation and
  // approves it in place. "Plan in the form" links carry the action
  // and selection to the operation form (canary, waves).
  const planHref = (action, hosts) => {
    const q = new URLSearchParams({ action });
    for (const h of hosts) q.append('host', h);
    return '/operations/new?' + q.toString();
  };
  const rebootConfirm = document.getElementById('bulk-reboot-confirm');
  const rebootGo = document.getElementById('bulk-reboot-go');
  const rebootCancel = document.getElementById('bulk-reboot-cancel');
  document.getElementById('bulk-reboot').addEventListener('click', () => {
    const hosts = selected();
    if (hosts.length === 0) return;
    updateConfirm.hidden = true;
    rebootConfirm.hidden = false;
    rebootConfirm.querySelector('.bulk-reboot-confirm__count').textContent = String(hosts.length);
    document.getElementById('bulk-reboot-plan').href = planHref('system.reboot', hosts);
    rebootGo.disabled = false;
  });

  // "Install updates…": security or all updates, like reboot.
  const updateConfirm = document.getElementById('bulk-update-confirm');
  const updateGo = document.getElementById('bulk-update-go');
  const updateKind = () => updateConfirm.querySelector('input[name="bulk-update-kind"]:checked').value;
  const updatePlan = () => { document.getElementById('bulk-update-plan').href = planHref(updateKind(), selected()); };
  for (const r of updateConfirm.querySelectorAll('input[name="bulk-update-kind"]')) r.addEventListener('change', updatePlan);
  document.getElementById('bulk-update').addEventListener('click', () => {
    const hosts = selected();
    if (hosts.length === 0) return;
    rebootConfirm.hidden = true;
    updateConfirm.hidden = false;
    updateConfirm.querySelector('.bulk-update-confirm__count').textContent = String(hosts.length);
    updatePlan();
    updateGo.disabled = false;
  });
  document.getElementById('bulk-update-cancel').addEventListener('click', () => {
    updateConfirm.hidden = true;
  });
  rebootCancel.addEventListener('click', () => {
    rebootConfirm.hidden = true;
  });
  // Run the confirmed operation and approve it in place.
  const runInPlace = (go, box, action, opts, fail) => go.addEventListener('click', async () => {
    const hosts = selected();
    if (hosts.length === 0) return;
    go.disabled = true;
    msg.textContent = '';
    msg.classList.remove('message--error');
    try {
      await nebulaRunOp.ensureSession(msg);
      const id = await nebulaRunOp.runOperation({ action: action(), hosts }, msg, box.parentElement);
      nebulaRunOp.followStatus(box.parentElement, [id], opts);
    } catch (err) {
      msg.textContent = err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || fail);
      msg.classList.add('message--error');
      go.disabled = false;
    }
  });
  runInPlace(updateGo, updateConfirm, updateKind, { reloadWhenDone: true }, 'Could not install the updates.');
  runInPlace(rebootGo, rebootConfirm, () => 'system.reboot', undefined, 'Could not reboot.');
  update();
})();
