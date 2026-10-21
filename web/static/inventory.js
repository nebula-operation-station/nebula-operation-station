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
    document.getElementById('bulk-refresh').addEventListener('click', async (e) => {
      const hosts = selected();
      if (hosts.length === 0) return;
      e.target.disabled = true;
      msg.textContent = '';
      try {
        const body = new URLSearchParams();
        for (const h of hosts) body.append('host', h);
        const res = await fetch('/inventory/refresh', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        if (res.ok) {
          window.location.assign(res.url);
          return;
        }
        msg.textContent = (await res.text()).trim() || ('Request failed (' + res.status + ')'); // text only
        msg.classList.add('message--error');
      } catch (err) {
        msg.textContent = String(err);
      }
      e.target.disabled = false;
    });
    document.getElementById('bulk-reboot').addEventListener('click', () => {
      const hosts = selected();
      if (hosts.length === 0) return;
      const q = new URLSearchParams({ action: 'system.reboot' });
      for (const h of hosts) q.append('host', h);
      window.location.assign('/operations/new?' + q.toString());
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
