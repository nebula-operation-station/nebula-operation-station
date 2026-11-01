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

  // IP-aware natural comparison — a port of internal/web/ui/invsort.
  // IPs compare numerically (IPv4 before IPv6, IPs before non-IPs);
  // everything else compares case-insensitively with digit runs as
  // numbers, so "node2" < "node10" and "192.168.0.25" < "192.168.0.221".
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

  // Sortable columns: the Host, OS, Status, Updates and Last seen
  // headers hold a button; clicking it (or Enter/Space, since it is a
  // real button) toggles ascending/descending and sets aria-sort on the
  // column. The Host column uses the same IP-aware natural order as the
  // server default (internal/web/ui/invsort); Last seen sorts by the
  // row's data-ts (milliseconds, empty when never seen). Re-appending
  // rows keeps the text filter's hidden state, so both keep working.
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

  // Selection and bulk actions: refresh the reads behind the columns for
  // the selected hosts, or open the reboot form with them preselected.
  const bulkbar = document.getElementById('bulkbar');
  if (bulkbar) {
    const boxes = () => Array.from(document.querySelectorAll('input.host-select'));
    const selected = () => boxes().filter((b) => b.checked).map((b) => b.value);
    const all = document.getElementById('select-all');
    const count = document.getElementById('bulk-count');
    const msg = document.getElementById('bulk-message');
    const toggle = document.getElementById('bulkbar-toggle');
    // A fresh selection starts collapsed on phones, so the sheet does not
    // cover the table; the count and refresh stay reachable.
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
    };
    if (toggle) {
      toggle.addEventListener('click', () => {
        const expanded = bulkbar.classList.toggle('bulkbar--expanded');
        toggle.setAttribute('aria-expanded', String(expanded));
      });
    }
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
    // The "plan in the form" links carry the action and the selection, so
    // the operation form opens with the same hosts checked.
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

    // "Install updates…": security or all updates for the selection,
    // confirmed inline and approved in place with the key, like reboot.
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
    updateGo.addEventListener('click', async () => {
      const hosts = selected();
      if (hosts.length === 0) return;
      updateGo.disabled = true;
      msg.textContent = '';
      msg.classList.remove('message--error');
      try {
        await nebulaRunOp.ensureSession(msg);
        const id = await nebulaRunOp.runOperation({ action: updateKind(), hosts }, msg, updateConfirm.parentElement);
        nebulaRunOp.followStatus(updateConfirm.parentElement, [id], { reloadWhenDone: true });
      } catch (err) {
        msg.textContent = err.name === 'NotAllowedError' ? 'Cancelled or timed out.' : (err.message || 'Could not install the updates.');
        msg.classList.add('message--error');
        updateGo.disabled = false;
      }
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
