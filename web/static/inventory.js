// SPDX-License-Identifier: AGPL-3.0-or-later
// Inventory page: client-side text filter, row navigation to the host
// page, and the add-host dialog. The dialog posts JSON to
// /inventory/hosts (fetch with a real Origin, decision 36); without
// JavaScript the same form posts as a plain form to /inventory. Server
// text is shown with textContent only, never innerHTML.
'use strict';

(() => {
  const w = nebulaWebAuthn;

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

  // Selection and bulk actions: refresh the reads behind the columns for
  // the selected hosts, or open the reboot form with them preselected.
  const bulkbar = document.getElementById('bulkbar');
  if (bulkbar) {
    const boxes = () => Array.from(document.querySelectorAll('input.host-select'));
    const selected = () => boxes().filter((b) => b.checked).map((b) => b.value);
    const all = document.getElementById('select-all');
    const count = document.getElementById('bulk-count');
    const msg = document.getElementById('bulk-message');
    const update = () => {
      const n = selected().length;
      bulkbar.hidden = n === 0;
      count.textContent = n + ' selected';
      const shown = boxes().filter((b) => !b.closest('tr').hidden);
      all.checked = shown.length > 0 && shown.every((b) => b.checked);
    };
    for (const b of boxes()) b.addEventListener('change', update);
    all.addEventListener('change', () => {
      for (const b of boxes()) {
        if (!b.closest('tr').hidden) b.checked = all.checked; // only what the filter shows
      }
      update();
    });
    // The selection is what is shown: rows the text filter hides are
    // unselected, so a bulk action never reaches a host you cannot see.
    if (filter) {
      filter.addEventListener('input', () => {
        for (const b of boxes()) {
          if (b.closest('tr').hidden) b.checked = false;
        }
        update();
      });
    }
    // One-click refresh: make sure the privileged session is open (one
    // key tap while it is not), create the reads for the selection,
    // approve what waits for a tap in place, one after the other, and
    // follow the rest by status; the page reloads when all are done.
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
    // "Schedule refresh…" opens the schedules page with the four read
    // actions and the selected hosts preselected (6 h / 30 days).
    // Prefill only checks boxes; the schedule is created through the
    // normal approval flow on that page.
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
    // "Reboot…" confirms inline in the bulk bar (no browser dialog),
    // then creates one system.reboot operation for the whole selection
    // and approves it in place with the key; the status follows in the
    // bar. The link keeps the operation form for canary and waves.
    const rebootConfirm = document.getElementById('bulk-reboot-confirm');
    const rebootGo = document.getElementById('bulk-reboot-go');
    const rebootCancel = document.getElementById('bulk-reboot-cancel');
    document.getElementById('bulk-reboot').addEventListener('click', () => {
      const hosts = selected();
      if (hosts.length === 0) return;
      rebootConfirm.hidden = false;
      rebootConfirm.querySelector('.bulk-reboot-confirm__count').textContent = String(hosts.length);
      rebootGo.disabled = false;
    });
    rebootCancel.addEventListener('click', () => {
      rebootConfirm.hidden = true;
    });
    rebootGo.addEventListener('click', async () => {
      const hosts = selected();
      if (hosts.length === 0) return;
      rebootGo.disabled = true;
      msg.textContent = '';
      msg.classList.remove('message--error');
      try {
        await nebulaRunOp.ensureSession(msg);
        const id = await nebulaRunOp.runOperation({ action: 'system.reboot', hosts }, msg, rebootConfirm.parentElement);
        nebulaRunOp.followStatus(rebootConfirm.parentElement, [id]);
      } catch (err) {
        msg.textContent = err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not reboot.');
        msg.classList.add('message--error');
        rebootGo.disabled = false;
      }
    });
    update();
  }

  const dialog = document.getElementById('add-host-dialog');
  const form = document.getElementById('host-form');
  if (!dialog || !form) return; // read-only page: no inventory store configured

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
